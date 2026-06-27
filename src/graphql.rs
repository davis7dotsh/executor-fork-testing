use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::catalog::ToolMode;

const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_TYPES: usize = 4_096;
const MAX_TOTAL_FIELDS: usize = 100_000;
const MAX_ROOT_FIELDS: usize = 2_048;
const MAX_ARGUMENTS: usize = 128;
const MAX_INPUT_FIELDS: usize = 1_024;
pub(crate) const MAX_INPUT_OBJECT_DEPTH: usize = 64;
const MAX_ENUM_VALUES: usize = 4_096;
const MAX_NAME_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 16 * 1024;
const MAX_TYPE_DEPTH: usize = 8;
const MAX_SELECTION_DEPTH: usize = 2;
const MAX_SELECTION_FIELDS: usize = 16;
const MAX_GENERATED_DOCUMENT_BYTES: usize = 64 * 1024;
const MAX_GENERATED_CATALOG_BYTES: usize = 32 * 1024 * 1024;

pub const INTROSPECTION_QUERY: &str = r#"query ExecutorIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        args {
          name
          description
          defaultValue
          type { ...ExecutorTypeRef }
        }
        type { ...ExecutorTypeRef }
      }
      inputFields {
        name
        description
        defaultValue
        type { ...ExecutorTypeRef }
      }
      enumValues(includeDeprecated: true) { name isDeprecated }
    }
  }
}

fragment ExecutorTypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType { kind name }
              }
            }
          }
        }
      }
    }
  }
}"#;

#[derive(Clone, Debug)]
pub struct CompiledGraphql {
    pub document: Value,
    pub query_type: String,
    pub mutation_type: Option<String>,
    pub tools: Vec<CompiledGraphqlTool>,
}

#[derive(Clone, Debug)]
pub struct CompiledGraphqlTool {
    pub stable_key: String,
    pub preferred_name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub intrinsic_mode: ToolMode,
    pub binding: GraphqlBindingV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphqlOperation {
    Query,
    Mutation,
}

impl GraphqlOperation {
    pub const fn is_mutation(self) -> bool {
        matches!(self, Self::Mutation)
    }

    fn keyword(self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Mutation => "mutation",
        }
    }

    fn stable_component(self) -> &'static str {
        self.keyword()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphqlTypeRef {
    Named { name: String },
    List { of_type: Box<GraphqlTypeRef> },
    NonNull { of_type: Box<GraphqlTypeRef> },
}

impl GraphqlTypeRef {
    pub fn graphql_type(&self) -> String {
        match self {
            Self::Named { name } => name.clone(),
            Self::List { of_type } => format!("[{}]", of_type.graphql_type()),
            Self::NonNull { of_type } => format!("{}!", of_type.graphql_type()),
        }
    }

    fn named_type(&self) -> &str {
        match self {
            Self::Named { name } => name,
            Self::List { of_type } | Self::NonNull { of_type } => of_type.named_type(),
        }
    }

    fn is_non_null(&self) -> bool {
        matches!(self, Self::NonNull { .. })
    }

    fn validate(&self, depth: usize) -> Result<(), GraphqlBindingError> {
        if depth > MAX_TYPE_DEPTH {
            return Err(GraphqlBindingError::LimitExceeded("type_depth"));
        }
        match self {
            Self::Named { name } => validate_binding_name(name),
            Self::List { of_type } => of_type.validate(depth + 1),
            Self::NonNull { of_type } => {
                if matches!(of_type.as_ref(), Self::NonNull { .. }) {
                    return Err(GraphqlBindingError::InvalidType);
                }
                of_type.validate(depth + 1)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphqlVariableBinding {
    pub name: String,
    pub type_ref: GraphqlTypeRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphqlSelectionField {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<GraphqlSelectionField>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphqlBindingV1 {
    pub version: u32,
    pub operation: GraphqlOperation,
    pub field_name: String,
    pub operation_name: String,
    pub variables: Vec<GraphqlVariableBinding>,
    pub selection: Vec<GraphqlSelectionField>,
    pub document: String,
}

impl GraphqlBindingV1 {
    pub fn canonical_document(&self) -> Result<String, GraphqlBindingError> {
        validate_binding_name(&self.field_name)?;
        validate_binding_name(&self.operation_name)?;
        if self.variables.len() > MAX_ARGUMENTS {
            return Err(GraphqlBindingError::LimitExceeded("variables"));
        }
        let mut previous = None;
        for variable in &self.variables {
            validate_binding_name(&variable.name)?;
            variable.type_ref.validate(0)?;
            if previous.is_some_and(|previous| previous >= variable.name.as_str()) {
                return Err(GraphqlBindingError::NonCanonicalOrder);
            }
            previous = Some(variable.name.as_str());
        }
        validate_selection(&self.selection, 0)?;
        canonical_document(
            self.operation,
            &self.operation_name,
            &self.field_name,
            &self.variables,
            &self.selection,
        )
    }

    pub fn validate(&self) -> Result<(), GraphqlBindingError> {
        if self.version != 1 {
            return Err(GraphqlBindingError::UnsupportedVersion);
        }
        let canonical = self.canonical_document()?;
        if canonical != self.document {
            return Err(GraphqlBindingError::NonCanonicalDocument);
        }
        Ok(())
    }

    pub fn stable_key(&self) -> Result<String, GraphqlBindingError> {
        self.validate()?;
        Ok(format!(
            "graphql:v1:{}:{}",
            self.operation.stable_component(),
            self.field_name
        ))
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GraphqlBindingError {
    #[error("the GraphQL binding version is not supported")]
    UnsupportedVersion,
    #[error("the GraphQL binding contains an invalid name")]
    InvalidName,
    #[error("the GraphQL binding contains an invalid type")]
    InvalidType,
    #[error("the GraphQL binding is not in canonical order")]
    NonCanonicalOrder,
    #[error("the GraphQL binding document is not canonical")]
    NonCanonicalDocument,
    #[error("the GraphQL binding exceeds limit {0}")]
    LimitExceeded(&'static str),
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GraphqlError {
    #[error("the GraphQL introspection response is invalid: {0}")]
    InvalidDocument(&'static str),
    #[error("the GraphQL introspection response contains an unsupported type: {0}")]
    UnsupportedType(String),
    #[error("the GraphQL introspection response exceeds compiler limit {code}")]
    LimitExceeded { code: &'static str },
    #[error("a generated GraphQL binding is invalid")]
    InvalidBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TypeKind {
    Scalar,
    Object,
    Interface,
    Union,
    Enum,
    InputObject,
}

#[derive(Clone, Debug)]
struct TypeDefinition {
    kind: TypeKind,
    fields: Vec<FieldDefinition>,
    input_fields: Vec<InputValueDefinition>,
    enum_values: Vec<String>,
}

#[derive(Clone, Debug)]
struct FieldDefinition {
    name: String,
    description: Option<String>,
    deprecated: bool,
    arguments: Vec<InputValueDefinition>,
    type_ref: GraphqlTypeRef,
}

#[derive(Clone, Debug)]
struct InputValueDefinition {
    name: String,
    description: Option<String>,
    has_default: bool,
    type_ref: GraphqlTypeRef,
}

pub fn compile_introspection(document: Value) -> Result<CompiledGraphql, GraphqlError> {
    if serde_json::to_vec(&document)
        .map_err(|_| invalid("the response cannot be encoded"))?
        .len()
        > MAX_DOCUMENT_BYTES
    {
        return Err(limit("document_bytes"));
    }
    let response = document
        .as_object()
        .ok_or_else(|| invalid("the response must be an object"))?;
    if response
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(|errors| !errors.is_empty())
    {
        return Err(invalid("the response contains GraphQL errors"));
    }
    let schema = response
        .get("data")
        .unwrap_or(&document)
        .get("__schema")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("the response is missing data.__schema"))?;
    let query_type = root_type_name(schema, "queryType")?
        .ok_or_else(|| invalid("the schema has no query root"))?;
    let mutation_type = root_type_name(schema, "mutationType")?;
    let types = parse_types(schema)?;
    let input_object_depths = InputObjectDepthIndex::new(&types);
    require_root(&types, &query_type)?;
    if let Some(name) = &mutation_type {
        require_root(&types, name)?;
    }

    let mut generated_bytes = 0_usize;
    let mut tools = compile_root(
        &types,
        &query_type,
        GraphqlOperation::Query,
        &input_object_depths,
        &mut generated_bytes,
        MAX_GENERATED_CATALOG_BYTES,
    )?;
    if let Some(name) = &mutation_type {
        tools.extend(compile_root(
            &types,
            name,
            GraphqlOperation::Mutation,
            &input_object_depths,
            &mut generated_bytes,
            MAX_GENERATED_CATALOG_BYTES,
        )?);
    }
    Ok(CompiledGraphql {
        document,
        query_type,
        mutation_type,
        tools,
    })
}

fn parse_types(
    schema: &Map<String, Value>,
) -> Result<BTreeMap<String, TypeDefinition>, GraphqlError> {
    let values = schema
        .get("types")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("the schema types must be an array"))?;
    if values.len() > MAX_TYPES {
        return Err(limit("types"));
    }
    let mut types = BTreeMap::new();
    let mut total_fields = 0_usize;
    for value in values {
        let value = value
            .as_object()
            .ok_or_else(|| invalid("a schema type must be an object"))?;
        let name = required_name(value, "name")?;
        let kind = parse_named_kind(required_string(value, "kind")?)?;
        validate_optional_description(value.get("description"))?;
        let fields = parse_fields(value.get("fields"))?;
        let input_fields = parse_input_values(value.get("inputFields"), MAX_INPUT_FIELDS)?;
        let enum_values = parse_enum_values(value.get("enumValues"))?;
        total_fields = total_fields
            .checked_add(fields.len())
            .and_then(|count| count.checked_add(input_fields.len()))
            .ok_or_else(|| limit("total_fields"))?;
        if total_fields > MAX_TOTAL_FIELDS {
            return Err(limit("total_fields"));
        }
        validate_type_shape(kind, &fields, &input_fields, &enum_values)?;
        let definition = TypeDefinition {
            kind,
            fields,
            input_fields,
            enum_values,
        };
        if types.insert(name, definition).is_some() {
            return Err(invalid("type names must be unique"));
        }
    }
    Ok(types)
}

fn parse_fields(value: Option<&Value>) -> Result<Vec<FieldDefinition>, GraphqlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let fields = value
        .as_array()
        .ok_or_else(|| invalid("type fields must be an array or null"))?;
    let mut parsed = Vec::with_capacity(fields.len());
    let mut names = BTreeSet::new();
    for field in fields {
        let field = field
            .as_object()
            .ok_or_else(|| invalid("a field must be an object"))?;
        let name = required_name(field, "name")?;
        if !names.insert(name.clone()) {
            return Err(invalid("field names must be unique"));
        }
        let description = optional_description(field.get("description"))?;
        let deprecated = field
            .get("isDeprecated")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("field deprecation must be a boolean"))?;
        let arguments = parse_input_values(field.get("args"), MAX_ARGUMENTS)?;
        let type_ref = parse_type_ref(
            field
                .get("type")
                .ok_or_else(|| invalid("a field is missing its type"))?,
            0,
        )?;
        parsed.push(FieldDefinition {
            name,
            description,
            deprecated,
            arguments,
            type_ref,
        });
    }
    parsed.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(parsed)
}

fn parse_input_values(
    value: Option<&Value>,
    maximum: usize,
) -> Result<Vec<InputValueDefinition>, GraphqlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = value
        .as_array()
        .ok_or_else(|| invalid("input values must be an array or null"))?;
    if values.len() > maximum {
        return Err(limit("input_values"));
    }
    let mut parsed = Vec::with_capacity(values.len());
    let mut names = BTreeSet::new();
    for value in values {
        let value = value
            .as_object()
            .ok_or_else(|| invalid("an input value must be an object"))?;
        let name = required_name(value, "name")?;
        if !names.insert(name.clone()) {
            return Err(invalid("input value names must be unique"));
        }
        let description = optional_description(value.get("description"))?;
        let has_default = match value.get("defaultValue") {
            None | Some(Value::Null) => false,
            Some(Value::String(default)) => {
                if default.len() > MAX_DESCRIPTION_BYTES {
                    return Err(limit("default_value_bytes"));
                }
                true
            }
            Some(_) => return Err(invalid("an input default value must be a string or null")),
        };
        let type_ref = parse_type_ref(
            value
                .get("type")
                .ok_or_else(|| invalid("an input value is missing its type"))?,
            0,
        )?;
        parsed.push(InputValueDefinition {
            name,
            description,
            has_default,
            type_ref,
        });
    }
    parsed.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(parsed)
}

fn parse_enum_values(value: Option<&Value>) -> Result<Vec<String>, GraphqlError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let values = value
        .as_array()
        .ok_or_else(|| invalid("enum values must be an array or null"))?;
    if values.len() > MAX_ENUM_VALUES {
        return Err(limit("enum_values"));
    }
    let mut parsed = BTreeSet::new();
    for value in values {
        let value = value
            .as_object()
            .ok_or_else(|| invalid("an enum value must be an object"))?;
        let name = required_name(value, "name")?;
        if !parsed.insert(name) {
            return Err(invalid("enum value names must be unique"));
        }
    }
    Ok(parsed.into_iter().collect())
}

fn parse_type_ref(value: &Value, depth: usize) -> Result<GraphqlTypeRef, GraphqlError> {
    if depth > MAX_TYPE_DEPTH {
        return Err(limit("type_depth"));
    }
    let value = value
        .as_object()
        .ok_or_else(|| invalid("a type reference must be an object"))?;
    let kind = required_string(value, "kind")?;
    match kind {
        "NON_NULL" => {
            if depth >= MAX_TYPE_DEPTH {
                return Err(limit("type_depth"));
            }
            let of_type = parse_type_ref(
                value
                    .get("ofType")
                    .ok_or_else(|| invalid("a wrapping type is missing ofType"))?,
                depth + 1,
            )?;
            if matches!(of_type, GraphqlTypeRef::NonNull { .. }) {
                return Err(invalid("NON_NULL cannot wrap NON_NULL"));
            }
            Ok(GraphqlTypeRef::NonNull {
                of_type: Box::new(of_type),
            })
        }
        "LIST" => {
            if depth >= MAX_TYPE_DEPTH {
                return Err(limit("type_depth"));
            }
            Ok(GraphqlTypeRef::List {
                of_type: Box::new(parse_type_ref(
                    value
                        .get("ofType")
                        .ok_or_else(|| invalid("a wrapping type is missing ofType"))?,
                    depth + 1,
                )?),
            })
        }
        "SCALAR" | "OBJECT" | "INTERFACE" | "UNION" | "ENUM" | "INPUT_OBJECT" => {
            Ok(GraphqlTypeRef::Named {
                name: required_name(value, "name")?,
            })
        }
        _ => Err(invalid("a type reference kind is invalid")),
    }
}

fn compile_root(
    types: &BTreeMap<String, TypeDefinition>,
    root_name: &str,
    operation: GraphqlOperation,
    input_object_depths: &InputObjectDepthIndex,
    generated_bytes: &mut usize,
    max_generated_bytes: usize,
) -> Result<Vec<CompiledGraphqlTool>, GraphqlError> {
    let root = types
        .get(root_name)
        .ok_or_else(|| invalid("a root type does not exist"))?;
    if root.fields.len() > MAX_ROOT_FIELDS {
        return Err(limit("root_fields"));
    }
    let mut tools = Vec::with_capacity(root.fields.len());
    for field in &root.fields {
        let tool = compile_tool(types, field, operation, input_object_depths)?;
        *generated_bytes = generated_bytes
            .checked_add(generated_tool_bytes(&tool)?)
            .ok_or_else(|| limit("generated_catalog_bytes"))?;
        if *generated_bytes > max_generated_bytes {
            return Err(limit("generated_catalog_bytes"));
        }
        tools.push(tool);
    }
    Ok(tools)
}

fn generated_tool_bytes(tool: &CompiledGraphqlTool) -> Result<usize, GraphqlError> {
    let binding = serde_json::to_vec(&tool.binding)
        .map_err(|_| invalid("a generated binding cannot be encoded"))?;
    [
        &tool.input_schema,
        tool.output_schema.as_ref().unwrap_or(&Value::Null),
    ]
    .into_iter()
    .try_fold(binding.len(), |total, value| {
        let encoded = serde_json::to_vec(value)
            .map_err(|_| invalid("a generated schema cannot be encoded"))?;
        total
            .checked_add(encoded.len())
            .ok_or_else(|| limit("generated_catalog_bytes"))
    })
}

fn compile_tool(
    types: &BTreeMap<String, TypeDefinition>,
    field: &FieldDefinition,
    operation: GraphqlOperation,
    input_object_depths: &InputObjectDepthIndex,
) -> Result<CompiledGraphqlTool, GraphqlError> {
    for argument in &field.arguments {
        require_input_type(types, &argument.type_ref)?;
    }
    require_output_type(types, &field.type_ref)?;
    let variables = field
        .arguments
        .iter()
        .map(|argument| GraphqlVariableBinding {
            name: argument.name.clone(),
            type_ref: argument.type_ref.clone(),
        })
        .collect::<Vec<_>>();
    let selection = build_selection(types, &field.type_ref, 0, &mut Vec::new())?;
    let operation_name = "ExecutorOperation".to_owned();
    let document = canonical_document(
        operation,
        &operation_name,
        &field.name,
        &variables,
        &selection,
    )
    .map_err(|_| GraphqlError::InvalidBinding)?;
    let binding = GraphqlBindingV1 {
        version: 1,
        operation,
        field_name: field.name.clone(),
        operation_name,
        variables,
        selection,
        document,
    };
    binding
        .validate()
        .map_err(|_| GraphqlError::InvalidBinding)?;
    Ok(CompiledGraphqlTool {
        stable_key: format!("graphql:v1:{}:{}", operation.stable_component(), field.name),
        preferred_name: field.name.clone(),
        display_name: field.name.clone(),
        description: field.description.clone(),
        input_schema: build_input_schema(types, &field.arguments, input_object_depths)?,
        output_schema: Some(build_output_schema(
            types,
            &field.type_ref,
            &binding.selection,
        )?),
        intrinsic_mode: if field.deprecated {
            ToolMode::Disabled
        } else if operation == GraphqlOperation::Mutation {
            ToolMode::Ask
        } else {
            ToolMode::Enabled
        },
        binding,
    })
}

fn build_input_schema(
    types: &BTreeMap<String, TypeDefinition>,
    arguments: &[InputValueDefinition],
    input_object_depths: &InputObjectDepthIndex,
) -> Result<Value, GraphqlError> {
    input_object_depths.validate(arguments)?;
    let mut definitions = BTreeMap::new();
    let mut active = BTreeSet::new();
    let mut properties = Map::new();
    let mut required = Vec::new();
    for argument in arguments {
        let mut schema =
            input_schema_for_type(types, &argument.type_ref, &mut definitions, &mut active)?;
        if let Some(description) = &argument.description
            && let Some(object) = schema.as_object_mut()
        {
            object.insert("description".to_owned(), Value::String(description.clone()));
        }
        properties.insert(argument.name.clone(), schema);
        if argument.type_ref.is_non_null() && !argument.has_default {
            required.push(Value::String(argument.name.clone()));
        }
    }
    let mut schema = Map::from_iter([
        (
            "$schema".to_owned(),
            Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
        ),
        ("type".to_owned(), Value::String("object".to_owned())),
        ("properties".to_owned(), Value::Object(properties)),
        ("additionalProperties".to_owned(), Value::Bool(false)),
    ]);
    if !required.is_empty() {
        schema.insert("required".to_owned(), Value::Array(required));
    }
    if !definitions.is_empty() {
        schema.insert(
            "$defs".to_owned(),
            Value::Object(definitions.into_iter().collect()),
        );
    }
    Ok(Value::Object(schema))
}

struct InputObjectDepthIndex {
    component_by_name: BTreeMap<String, usize>,
    depth_by_component: Vec<usize>,
}

impl InputObjectDepthIndex {
    fn new(types: &BTreeMap<String, TypeDefinition>) -> Self {
        let names = types
            .iter()
            .filter_map(|(name, definition)| {
                (definition.kind == TypeKind::InputObject).then_some(name.as_str())
            })
            .collect::<Vec<_>>();
        let indices = names
            .iter()
            .enumerate()
            .map(|(index, name)| (*name, index))
            .collect::<BTreeMap<_, _>>();
        let mut adjacency = vec![Vec::new(); names.len()];
        for (index, name) in names.iter().enumerate() {
            let definition = types
                .get(*name)
                .expect("input object names come from the type map");
            for field in &definition.input_fields {
                if let Some(target) = indices.get(field.type_ref.named_type()) {
                    adjacency[index].push(*target);
                }
            }
            adjacency[index].sort_unstable();
            adjacency[index].dedup();
        }

        let mut visited = vec![false; names.len()];
        let mut finish_order = Vec::with_capacity(names.len());
        for root in 0..names.len() {
            if visited[root] {
                continue;
            }
            visited[root] = true;
            let mut stack = vec![(root, 0_usize)];
            while let Some((node, next_edge)) = stack.last_mut() {
                if let Some(next) = adjacency[*node].get(*next_edge).copied() {
                    *next_edge += 1;
                    if !visited[next] {
                        visited[next] = true;
                        stack.push((next, 0));
                    }
                } else {
                    finish_order.push(*node);
                    stack.pop();
                }
            }
        }

        let mut reverse = vec![Vec::new(); names.len()];
        for (source, targets) in adjacency.iter().enumerate() {
            for target in targets {
                reverse[*target].push(source);
            }
        }
        let mut component_for = vec![usize::MAX; names.len()];
        let mut component_sizes = Vec::new();
        for root in finish_order.into_iter().rev() {
            if component_for[root] != usize::MAX {
                continue;
            }
            let component = component_sizes.len();
            component_for[root] = component;
            let mut size = 0_usize;
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                size = size.saturating_add(1);
                for previous in &reverse[node] {
                    if component_for[*previous] == usize::MAX {
                        component_for[*previous] = component;
                        stack.push(*previous);
                    }
                }
            }
            component_sizes.push(size.min(MAX_INPUT_OBJECT_DEPTH + 1));
        }

        let mut component_edges = vec![BTreeSet::new(); component_sizes.len()];
        let mut indegree = vec![0_usize; component_sizes.len()];
        for (source, targets) in adjacency.iter().enumerate() {
            let source_component = component_for[source];
            for target in targets {
                let target_component = component_for[*target];
                if source_component != target_component
                    && component_edges[source_component].insert(target_component)
                {
                    indegree[target_component] += 1;
                }
            }
        }
        let mut ready = indegree
            .iter()
            .enumerate()
            .filter_map(|(component, indegree)| (*indegree == 0).then_some(component))
            .collect::<Vec<_>>();
        let mut topological = Vec::with_capacity(component_sizes.len());
        while let Some(component) = ready.pop() {
            topological.push(component);
            for target in &component_edges[component] {
                indegree[*target] -= 1;
                if indegree[*target] == 0 {
                    ready.push(*target);
                }
            }
        }
        let mut depth_by_component = component_sizes.clone();
        for component in topological.into_iter().rev() {
            for target in &component_edges[component] {
                let candidate = component_sizes[component]
                    .saturating_add(depth_by_component[*target])
                    .min(MAX_INPUT_OBJECT_DEPTH + 1);
                depth_by_component[component] = depth_by_component[component].max(candidate);
            }
        }
        let component_by_name = names
            .into_iter()
            .enumerate()
            .map(|(index, name)| (name.to_owned(), component_for[index]))
            .collect();
        Self {
            component_by_name,
            depth_by_component,
        }
    }

    fn validate(&self, arguments: &[InputValueDefinition]) -> Result<(), GraphqlError> {
        let over_limit = arguments.iter().any(|argument| {
            self.component_by_name
                .get(argument.type_ref.named_type())
                .is_some_and(|component| {
                    self.depth_by_component[*component] > MAX_INPUT_OBJECT_DEPTH
                })
        });
        if over_limit {
            Err(limit("input_object_depth"))
        } else {
            Ok(())
        }
    }
}

fn input_schema_for_type(
    types: &BTreeMap<String, TypeDefinition>,
    type_ref: &GraphqlTypeRef,
    definitions: &mut BTreeMap<String, Value>,
    active: &mut BTreeSet<String>,
) -> Result<Value, GraphqlError> {
    match type_ref {
        GraphqlTypeRef::NonNull { of_type } => Ok(non_null_schema(input_schema_for_type(
            types,
            of_type,
            definitions,
            active,
        )?)),
        GraphqlTypeRef::List { of_type } => Ok(json!({
            "type": ["array", "null"],
            "items": input_schema_for_type(types, of_type, definitions, active)?
        })),
        GraphqlTypeRef::Named { name } => {
            let definition = types
                .get(name)
                .ok_or_else(|| GraphqlError::UnsupportedType(name.clone()))?;
            let base = match definition.kind {
                TypeKind::Scalar => input_scalar_schema(name),
                TypeKind::Enum => {
                    json!({ "type": ["string", "null"], "enum": nullable_enum(&definition.enum_values) })
                }
                TypeKind::InputObject => {
                    ensure_input_definition(types, name, definitions, active)?;
                    json!({ "anyOf": [{ "$ref": format!("#/$defs/{name}") }, { "type": "null" }] })
                }
                _ => return Err(GraphqlError::UnsupportedType(name.clone())),
            };
            Ok(base)
        }
    }
}

fn ensure_input_definition(
    types: &BTreeMap<String, TypeDefinition>,
    name: &str,
    definitions: &mut BTreeMap<String, Value>,
    active: &mut BTreeSet<String>,
) -> Result<(), GraphqlError> {
    if definitions.contains_key(name) || active.contains(name) {
        return Ok(());
    }
    if definitions.len() >= MAX_TYPES {
        return Err(limit("input_definitions"));
    }
    let definition = types
        .get(name)
        .filter(|definition| definition.kind == TypeKind::InputObject)
        .ok_or_else(|| GraphqlError::UnsupportedType(name.to_owned()))?;
    active.insert(name.to_owned());
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &definition.input_fields {
        let mut schema = input_schema_for_type(types, &field.type_ref, definitions, active)?;
        if let Some(description) = &field.description
            && let Some(object) = schema.as_object_mut()
        {
            object.insert("description".to_owned(), Value::String(description.clone()));
        }
        properties.insert(field.name.clone(), schema);
        if field.type_ref.is_non_null() && !field.has_default {
            required.push(Value::String(field.name.clone()));
        }
    }
    active.remove(name);
    let mut schema = Map::from_iter([
        ("type".to_owned(), Value::String("object".to_owned())),
        ("properties".to_owned(), Value::Object(properties)),
        ("additionalProperties".to_owned(), Value::Bool(false)),
    ]);
    if !required.is_empty() {
        schema.insert("required".to_owned(), Value::Array(required));
    }
    definitions.insert(name.to_owned(), Value::Object(schema));
    Ok(())
}

fn build_selection(
    types: &BTreeMap<String, TypeDefinition>,
    type_ref: &GraphqlTypeRef,
    depth: usize,
    stack: &mut Vec<String>,
) -> Result<Vec<GraphqlSelectionField>, GraphqlError> {
    let name = type_ref.named_type();
    let definition = types
        .get(name)
        .ok_or_else(|| GraphqlError::UnsupportedType(name.to_owned()))?;
    match definition.kind {
        TypeKind::Scalar | TypeKind::Enum => Ok(Vec::new()),
        TypeKind::Union => Ok(vec![GraphqlSelectionField {
            name: "__typename".to_owned(),
            fields: Vec::new(),
        }]),
        TypeKind::Object | TypeKind::Interface => {
            let mut selection = vec![GraphqlSelectionField {
                name: "__typename".to_owned(),
                fields: Vec::new(),
            }];
            if depth >= MAX_SELECTION_DEPTH || stack.iter().any(|item| item == name) {
                return Ok(selection);
            }
            stack.push(name.to_owned());
            for field in &definition.fields {
                if selection.len() >= MAX_SELECTION_FIELDS
                    || field
                        .arguments
                        .iter()
                        .any(|argument| argument.type_ref.is_non_null() && !argument.has_default)
                {
                    continue;
                }
                let field_type = types.get(field.type_ref.named_type()).ok_or_else(|| {
                    GraphqlError::UnsupportedType(field.type_ref.named_type().to_owned())
                })?;
                let fields = match field_type.kind {
                    TypeKind::Scalar | TypeKind::Enum => Vec::new(),
                    TypeKind::Object | TypeKind::Interface | TypeKind::Union => {
                        build_selection(types, &field.type_ref, depth + 1, stack)?
                    }
                    TypeKind::InputObject => continue,
                };
                selection.push(GraphqlSelectionField {
                    name: field.name.clone(),
                    fields,
                });
            }
            stack.pop();
            selection.sort_by(|left, right| left.name.cmp(&right.name));
            Ok(selection)
        }
        TypeKind::InputObject => Err(GraphqlError::UnsupportedType(name.to_owned())),
    }
}

fn build_output_schema(
    types: &BTreeMap<String, TypeDefinition>,
    type_ref: &GraphqlTypeRef,
    selection: &[GraphqlSelectionField],
) -> Result<Value, GraphqlError> {
    match type_ref {
        GraphqlTypeRef::NonNull { of_type } => Ok(non_null_schema(build_output_schema(
            types, of_type, selection,
        )?)),
        GraphqlTypeRef::List { of_type } => Ok(json!({
            "type": ["array", "null"],
            "items": build_output_schema(types, of_type, selection)?
        })),
        GraphqlTypeRef::Named { name } => {
            let definition = types
                .get(name)
                .ok_or_else(|| GraphqlError::UnsupportedType(name.clone()))?;
            match definition.kind {
                TypeKind::Scalar => Ok(scalar_schema(name)),
                TypeKind::Enum => Ok(
                    json!({ "type": ["string", "null"], "enum": nullable_enum(&definition.enum_values) }),
                ),
                TypeKind::Object | TypeKind::Interface | TypeKind::Union => {
                    let mut properties = Map::new();
                    for selected in selection {
                        if selected.name == "__typename" {
                            properties.insert(selected.name.clone(), json!({ "type": "string" }));
                            continue;
                        }
                        let field = definition
                            .fields
                            .iter()
                            .find(|field| field.name == selected.name)
                            .ok_or_else(|| invalid("a generated selection field is missing"))?;
                        properties.insert(
                            selected.name.clone(),
                            build_output_schema(types, &field.type_ref, &selected.fields)?,
                        );
                    }
                    Ok(json!({
                        "type": ["object", "null"],
                        "properties": properties,
                        "additionalProperties": false
                    }))
                }
                TypeKind::InputObject => Err(GraphqlError::UnsupportedType(name.clone())),
            }
        }
    }
}

fn scalar_schema(name: &str) -> Value {
    match name {
        "String" | "ID" => json!({ "type": ["string", "null"] }),
        "Boolean" => json!({ "type": ["boolean", "null"] }),
        "Int" => {
            json!({ "type": ["integer", "null"], "minimum": -2147483648_i64, "maximum": 2147483647_i64 })
        }
        "Float" => json!({ "type": ["number", "null"] }),
        _ => json!({ "type": ["string", "number", "boolean", "object", "array", "null"] }),
    }
}

fn input_scalar_schema(name: &str) -> Value {
    if name == "ID" {
        json!({ "type": ["string", "integer", "null"] })
    } else {
        scalar_schema(name)
    }
}

fn nullable_enum(values: &[String]) -> Vec<Value> {
    values
        .iter()
        .cloned()
        .map(Value::String)
        .chain(std::iter::once(Value::Null))
        .collect()
}

fn non_null_schema(mut schema: Value) -> Value {
    let Some(object) = schema.as_object_mut() else {
        return schema;
    };
    let singular_type = if let Some(Value::Array(types)) = object.get_mut("type") {
        types.retain(|value| value != "null");
        (types.len() == 1).then(|| types[0].clone())
    } else {
        None
    };
    if let Some(singular_type) = singular_type {
        object.insert("type".to_owned(), singular_type);
    }
    if let Some(Value::Array(values)) = object.get_mut("enum") {
        values.retain(|value| !value.is_null());
    }
    if let Some(Value::Array(alternatives)) = object.get_mut("anyOf") {
        alternatives.retain(|alternative| alternative.get("type") != Some(&json!("null")));
    }
    schema
}

fn canonical_document(
    operation: GraphqlOperation,
    operation_name: &str,
    field_name: &str,
    variables: &[GraphqlVariableBinding],
    selection: &[GraphqlSelectionField],
) -> Result<String, GraphqlBindingError> {
    let definitions = variables
        .iter()
        .map(|variable| format!("${}: {}", variable.name, variable.type_ref.graphql_type()))
        .collect::<Vec<_>>();
    let arguments = variables
        .iter()
        .map(|variable| format!("{}: ${}", variable.name, variable.name))
        .collect::<Vec<_>>();
    let mut document = format!("{} {}", operation.keyword(), operation_name);
    if !definitions.is_empty() {
        document.push('(');
        document.push_str(&definitions.join(", "));
        document.push(')');
    }
    document.push_str(" { result: ");
    document.push_str(field_name);
    if !arguments.is_empty() {
        document.push('(');
        document.push_str(&arguments.join(", "));
        document.push(')');
    }
    render_selection(&mut document, selection);
    document.push_str(" }");
    if document.len() > MAX_GENERATED_DOCUMENT_BYTES {
        return Err(GraphqlBindingError::LimitExceeded("document_bytes"));
    }
    Ok(document)
}

fn render_selection(document: &mut String, selection: &[GraphqlSelectionField]) {
    if selection.is_empty() {
        return;
    }
    document.push_str(" { ");
    for (index, field) in selection.iter().enumerate() {
        if index != 0 {
            document.push(' ');
        }
        document.push_str(&field.name);
        render_selection(document, &field.fields);
    }
    document.push_str(" }");
}

fn validate_selection(
    selection: &[GraphqlSelectionField],
    depth: usize,
) -> Result<(), GraphqlBindingError> {
    if depth > MAX_SELECTION_DEPTH + 1 {
        return Err(GraphqlBindingError::LimitExceeded("selection_depth"));
    }
    if selection.len() > MAX_SELECTION_FIELDS {
        return Err(GraphqlBindingError::LimitExceeded("selection_fields"));
    }
    let mut previous = None;
    for field in selection {
        validate_binding_name(&field.name)?;
        if previous.is_some_and(|previous| previous >= field.name.as_str()) {
            return Err(GraphqlBindingError::NonCanonicalOrder);
        }
        previous = Some(field.name.as_str());
        validate_selection(&field.fields, depth + 1)?;
    }
    Ok(())
}

fn validate_binding_name(name: &str) -> Result<(), GraphqlBindingError> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(GraphqlBindingError::InvalidName)
    }
}

fn require_root(types: &BTreeMap<String, TypeDefinition>, name: &str) -> Result<(), GraphqlError> {
    if types
        .get(name)
        .is_some_and(|root| root.kind == TypeKind::Object)
    {
        Ok(())
    } else {
        Err(invalid("a root type must be an object"))
    }
}

fn require_input_type(
    types: &BTreeMap<String, TypeDefinition>,
    type_ref: &GraphqlTypeRef,
) -> Result<(), GraphqlError> {
    let name = type_ref.named_type();
    if types.get(name).is_some_and(|definition| {
        matches!(
            definition.kind,
            TypeKind::Scalar | TypeKind::Enum | TypeKind::InputObject
        )
    }) {
        Ok(())
    } else {
        Err(GraphqlError::UnsupportedType(name.to_owned()))
    }
}

fn require_output_type(
    types: &BTreeMap<String, TypeDefinition>,
    type_ref: &GraphqlTypeRef,
) -> Result<(), GraphqlError> {
    let name = type_ref.named_type();
    if types.get(name).is_some_and(|definition| {
        matches!(
            definition.kind,
            TypeKind::Scalar
                | TypeKind::Enum
                | TypeKind::Object
                | TypeKind::Interface
                | TypeKind::Union
        )
    }) {
        Ok(())
    } else {
        Err(GraphqlError::UnsupportedType(name.to_owned()))
    }
}

fn validate_type_shape(
    kind: TypeKind,
    fields: &[FieldDefinition],
    input_fields: &[InputValueDefinition],
    enum_values: &[String],
) -> Result<(), GraphqlError> {
    let valid = match kind {
        TypeKind::Scalar => fields.is_empty() && input_fields.is_empty() && enum_values.is_empty(),
        TypeKind::Object | TypeKind::Interface => input_fields.is_empty() && enum_values.is_empty(),
        TypeKind::Union => fields.is_empty() && input_fields.is_empty() && enum_values.is_empty(),
        TypeKind::Enum => fields.is_empty() && input_fields.is_empty(),
        TypeKind::InputObject => fields.is_empty() && enum_values.is_empty(),
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(
            "a named type has fields that do not match its kind",
        ))
    }
}

fn parse_named_kind(kind: &str) -> Result<TypeKind, GraphqlError> {
    match kind {
        "SCALAR" => Ok(TypeKind::Scalar),
        "OBJECT" => Ok(TypeKind::Object),
        "INTERFACE" => Ok(TypeKind::Interface),
        "UNION" => Ok(TypeKind::Union),
        "ENUM" => Ok(TypeKind::Enum),
        "INPUT_OBJECT" => Ok(TypeKind::InputObject),
        _ => Err(invalid("a named type kind is invalid")),
    }
}

fn root_type_name(
    schema: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, GraphqlError> {
    match schema.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(root)) => Ok(Some(required_name(root, "name")?)),
        Some(_) => Err(invalid("a root type reference must be an object or null")),
    }
}

fn required_name(object: &Map<String, Value>, field: &'static str) -> Result<String, GraphqlError> {
    let name = required_string(object, field)?;
    if valid_name(name) {
        Ok(name.to_owned())
    } else {
        Err(invalid("a GraphQL name is invalid"))
    }
}

fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return false;
    }
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, GraphqlError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("a required string field is missing"))
}

fn optional_description(value: Option<&Value>) -> Result<Option<String>, GraphqlError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.len() <= MAX_DESCRIPTION_BYTES => {
            Ok(Some(value.clone()))
        }
        Some(Value::String(_)) => Err(limit("description_bytes")),
        Some(_) => Err(invalid("a description must be a string or null")),
    }
}

fn validate_optional_description(value: Option<&Value>) -> Result<(), GraphqlError> {
    optional_description(value).map(|_| ())
}

fn invalid(message: &'static str) -> GraphqlError {
    GraphqlError::InvalidDocument(message)
}

fn limit(code: &'static str) -> GraphqlError {
    GraphqlError::LimitExceeded { code }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        GraphqlBindingError, GraphqlError, GraphqlOperation, ToolMode, compile_introspection,
        compile_root, parse_type_ref, parse_types,
    };

    fn named(kind: &str, name: &str) -> Value {
        json!({ "kind": kind, "name": name, "ofType": null })
    }

    fn non_null(inner: Value) -> Value {
        json!({ "kind": "NON_NULL", "name": null, "ofType": inner })
    }

    fn list(inner: Value) -> Value {
        json!({ "kind": "LIST", "name": null, "ofType": inner })
    }

    fn schema() -> Value {
        json!({
            "data": {
                "__schema": {
                    "queryType": { "name": "Query" },
                    "mutationType": { "name": "Mutation" },
                    "subscriptionType": { "name": "Subscription" },
                    "types": [
                        { "kind": "SCALAR", "name": "String", "description": null, "fields": null, "inputFields": null, "enumValues": null },
                        { "kind": "SCALAR", "name": "ID", "description": null, "fields": null, "inputFields": null, "enumValues": null },
                        { "kind": "OBJECT", "name": "User", "description": null, "inputFields": null, "enumValues": null, "fields": [
                            { "name": "name", "description": null, "isDeprecated": false, "args": [], "type": named("SCALAR", "String") }
                        ] },
                        { "kind": "OBJECT", "name": "Query", "description": null, "inputFields": null, "enumValues": null, "fields": [
                            { "name": "user", "description": "Fetch user", "isDeprecated": false, "args": [
                                { "name": "id", "description": null, "defaultValue": null, "type": non_null(named("SCALAR", "ID")) }
                            ], "type": named("OBJECT", "User") }
                        ] },
                        { "kind": "OBJECT", "name": "Mutation", "description": null, "inputFields": null, "enumValues": null, "fields": [
                            { "name": "removeUser", "description": null, "isDeprecated": true, "args": [], "type": named("SCALAR", "String") }
                        ] }
                    ]
                }
            }
        })
    }

    fn input_object(name: &str, fields: Vec<Value>) -> Value {
        json!({
            "kind": "INPUT_OBJECT",
            "name": name,
            "description": null,
            "fields": null,
            "inputFields": fields,
            "enumValues": null
        })
    }

    fn input_field(name: &str, type_name: &str) -> Value {
        json!({
            "name": name,
            "description": null,
            "defaultValue": null,
            "type": named("INPUT_OBJECT", type_name)
        })
    }

    fn set_query_arguments(document: &mut Value, arguments: Vec<Value>) {
        let query = document["data"]["__schema"]["types"]
            .as_array_mut()
            .expect("schema types are an array")
            .iter_mut()
            .find(|definition| definition["name"] == "Query")
            .expect("query type exists");
        query["fields"][0]["args"] = Value::Array(arguments);
    }

    fn push_schema_types(document: &mut Value, definitions: impl IntoIterator<Item = Value>) {
        document["data"]["__schema"]["types"]
            .as_array_mut()
            .expect("schema types are an array")
            .extend(definitions);
    }

    #[test]
    fn compiles_root_fields_with_stable_modes_and_fixed_documents() {
        let compiled = compile_introspection(schema()).expect("schema compiles");
        assert_eq!(compiled.tools.len(), 2);
        let query = &compiled.tools[0];
        assert_eq!(query.stable_key, "graphql:v1:query:user");
        assert_eq!(query.intrinsic_mode, ToolMode::Enabled);
        assert_eq!(query.binding.operation, GraphqlOperation::Query);
        assert_eq!(
            query.binding.document,
            "query ExecutorOperation($id: ID!) { result: user(id: $id) { __typename name } }"
        );
        assert_eq!(query.input_schema["required"], json!(["id"]));
        assert_eq!(
            query.input_schema["properties"]["id"]["type"],
            json!(["string", "integer"])
        );
        let validator =
            jsonschema::validator_for(&query.input_schema).expect("compiled input schema is valid");
        assert!(validator.is_valid(&json!({ "id": 42 })));

        let mutation = &compiled.tools[1];
        assert_eq!(mutation.stable_key, "graphql:v1:mutation:removeUser");
        assert_eq!(mutation.intrinsic_mode, ToolMode::Disabled);
        assert_eq!(mutation.binding.operation, GraphqlOperation::Mutation);
    }

    #[test]
    fn persisted_document_must_exactly_match_typed_metadata() {
        let mut compiled = compile_introspection(schema()).expect("schema compiles");
        compiled.tools[0].binding.document = "query Evil { result: adminSecrets }".to_owned();
        assert_eq!(
            compiled.tools[0].binding.validate(),
            Err(GraphqlBindingError::NonCanonicalDocument)
        );
    }

    #[test]
    fn binding_identity_changes_when_a_field_is_coherently_rewritten() {
        let compiled = compile_introspection(schema()).expect("schema compiles");
        let original = &compiled.tools[0].binding;
        let mut rewritten = original.clone();
        rewritten.field_name = "otherUser".to_owned();
        rewritten.document = rewritten
            .canonical_document()
            .expect("rewritten binding is canonical");

        assert_ne!(
            original.stable_key().expect("original binding is valid"),
            rewritten.stable_key().expect("rewritten binding is valid")
        );
    }

    #[test]
    fn non_null_arguments_reject_null_at_every_required_layer() {
        let mut document = schema();
        document["data"]["__schema"]["types"][3]["fields"][0]["args"]
            .as_array_mut()
            .expect("query arguments are an array")
            .push(json!({
                "name": "tags",
                "description": null,
                "defaultValue": null,
                "type": non_null(list(non_null(named("SCALAR", "String"))))
            }));
        let compiled = compile_introspection(document).expect("schema compiles");
        let validator = jsonschema::validator_for(&compiled.tools[0].input_schema)
            .expect("compiled input schema is valid");

        assert!(validator.is_valid(&json!({ "id": "1", "tags": ["one"] })));
        assert!(!validator.is_valid(&json!({ "id": null, "tags": ["one"] })));
        assert!(!validator.is_valid(&json!({ "id": "1", "tags": null })));
        assert!(!validator.is_valid(&json!({ "id": "1", "tags": [null] })));
    }

    #[test]
    fn subscriptions_are_not_compiled() {
        let compiled = compile_introspection(schema()).expect("schema compiles");
        assert!(
            compiled
                .tools
                .iter()
                .all(|tool| !tool.stable_key.contains("subscription"))
        );
    }

    #[test]
    fn partial_introspection_errors_are_rejected() {
        let mut document = schema();
        document["errors"] = json!([{ "message": "partial" }]);
        assert!(compile_introspection(document).is_err());
    }

    #[test]
    fn aggregate_generated_catalog_budget_stops_schema_amplification() {
        let document = schema();
        let schema = document["data"]["__schema"]
            .as_object()
            .expect("test schema is an object");
        let types = parse_types(schema).expect("test types parse");
        let input_object_depths = super::InputObjectDepthIndex::new(&types);
        let mut generated_bytes = 0;
        let error = compile_root(
            &types,
            "Query",
            GraphqlOperation::Query,
            &input_object_depths,
            &mut generated_bytes,
            1,
        )
        .expect_err("generated output exceeding the aggregate budget is rejected");
        assert_eq!(
            error,
            GraphqlError::LimitExceeded {
                code: "generated_catalog_bytes"
            }
        );
    }

    #[test]
    fn input_object_dependency_depth_is_bounded_independent_of_root_order() {
        let mut document = schema();
        let definitions = (0..=super::MAX_INPUT_OBJECT_DEPTH)
            .map(|index| {
                let name = format!("Input{index}");
                let fields = if index == super::MAX_INPUT_OBJECT_DEPTH {
                    vec![json!({
                        "name": "value",
                        "description": null,
                        "defaultValue": null,
                        "type": named("SCALAR", "String")
                    })]
                } else {
                    vec![input_field("next", &format!("Input{}", index + 1))]
                };
                input_object(&name, fields)
            })
            .collect::<Vec<_>>();
        push_schema_types(&mut document, definitions);
        set_query_arguments(
            &mut document,
            vec![
                input_field("aTail", &format!("Input{}", super::MAX_INPUT_OBJECT_DEPTH)),
                input_field("zHead", "Input0"),
            ],
        );

        assert_eq!(
            compile_introspection(document).expect_err("deep input graph is rejected"),
            GraphqlError::LimitExceeded {
                code: "input_object_depth"
            }
        );
    }

    #[test]
    fn maximum_input_object_dependency_depth_is_supported() {
        let mut document = schema();
        let definitions = (0..super::MAX_INPUT_OBJECT_DEPTH)
            .map(|index| {
                let name = format!("Input{index}");
                let fields = if index + 1 == super::MAX_INPUT_OBJECT_DEPTH {
                    vec![json!({
                        "name": "value",
                        "description": null,
                        "defaultValue": null,
                        "type": named("SCALAR", "String")
                    })]
                } else {
                    vec![input_field("next", &format!("Input{}", index + 1))]
                };
                input_object(&name, fields)
            })
            .collect::<Vec<_>>();
        push_schema_types(&mut document, definitions);
        set_query_arguments(&mut document, vec![input_field("input", "Input0")]);

        compile_introspection(document).expect("the maximum input depth compiles");
    }

    #[test]
    fn bounded_recursive_input_objects_are_supported() {
        let mut document = schema();
        push_schema_types(
            &mut document,
            [
                input_object("RecursiveA", vec![input_field("b", "RecursiveB")]),
                input_object("RecursiveB", vec![input_field("a", "RecursiveA")]),
            ],
        );
        set_query_arguments(&mut document, vec![input_field("recursive", "RecursiveA")]);

        let compiled = compile_introspection(document).expect("bounded cycle compiles");
        assert!(compiled.tools[0].input_schema["$defs"]["RecursiveA"].is_object());
        assert!(compiled.tools[0].input_schema["$defs"]["RecursiveB"].is_object());
    }

    #[test]
    fn wide_shallow_input_object_graphs_do_not_consume_the_depth_budget() {
        let mut document = schema();
        let leaf_count = super::MAX_INPUT_OBJECT_DEPTH + 1;
        let root_fields = (0..leaf_count)
            .map(|index| input_field(&format!("field{index}"), &format!("Leaf{index}")))
            .collect::<Vec<_>>();
        let definitions = std::iter::once(input_object("WideInput", root_fields))
            .chain((0..leaf_count).map(|index| input_object(&format!("Leaf{index}"), Vec::new())));
        push_schema_types(&mut document, definitions);
        set_query_arguments(&mut document, vec![input_field("wide", "WideInput")]);

        let compiled = compile_introspection(document).expect("wide shallow graph compiles");
        assert_eq!(
            compiled.tools[0].input_schema["$defs"]
                .as_object()
                .expect("input definitions exist")
                .len(),
            leaf_count + 1
        );
    }

    #[test]
    fn wrapper_depth_beyond_the_introspection_query_is_a_declared_limit() {
        let mut type_ref = named("SCALAR", "String");
        for _ in 0..=super::MAX_TYPE_DEPTH {
            type_ref = list(type_ref);
        }
        assert_eq!(
            parse_type_ref(&type_ref, 0),
            Err(GraphqlError::LimitExceeded { code: "type_depth" })
        );
    }
}
