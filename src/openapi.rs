use std::{collections::BTreeMap, fmt};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::catalog::ToolMode;

const MAX_REFERENCE_DEPTH: usize = 64;
const MAX_RESOLVED_NODES: usize = 250_000;
const MAX_RESOLVED_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMPILED_OPERATIONS: usize = 100_000;
const MAX_PARAMETERS_PER_OPERATION: usize = 1_024;
const MAX_SECURITY_ALTERNATIVES: usize = 256;
const MAX_SECURITY_REQUIREMENTS_PER_ALTERNATIVE: usize = 64;
const HTTP_METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

#[derive(Clone, Copy)]
enum OpenApiSchemaDialect {
    OpenApi30,
    JsonSchema202012,
}

const OAS31_BASE_DIALECT: &str = "https://spec.openapis.org/oas/3.1/dialect/base";
const JSON_SCHEMA_2020_12_DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

#[derive(Clone, Debug)]
pub struct CompiledOpenApi {
    pub document: Value,
    pub title: String,
    pub description: Option<String>,
    pub tools: Vec<CompiledOpenApiTool>,
}

#[derive(Clone, Debug)]
pub struct CompiledOpenApiTool {
    pub stable_key: String,
    pub preferred_name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub intrinsic_mode: ToolMode,
    pub binding: OpenApiBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenApiBinding {
    pub version: u32,
    pub method: String,
    pub path_template: String,
    pub server_url: String,
    pub parameters: Vec<OpenApiParameterBinding>,
    pub request_body: Option<OpenApiRequestBodyBinding>,
    pub security: Vec<OpenApiSecurityAlternative>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenApiParameterBinding {
    pub name: String,
    pub location: OpenApiParameterLocation,
    pub required: bool,
    pub style: String,
    pub explode: bool,
    pub allow_reserved: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenApiParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
}

impl OpenApiParameterLocation {
    fn input_key(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "headers",
            Self::Cookie => "cookies",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenApiRequestBodyBinding {
    pub required: bool,
    pub default_media_type: String,
    pub media_types: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenApiSecurityAlternative {
    pub requirements: Vec<OpenApiSecurityRequirement>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenApiSecurityRequirement {
    pub scheme_name: String,
    pub scopes: Vec<String>,
    pub scheme: OpenApiSecurityScheme,
    pub oauth_flows: Option<OpenApiOAuthFlows>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OpenApiSecurityScheme {
    ApiKey {
        name: String,
        location: OpenApiParameterLocation,
    },
    Http {
        scheme: String,
        bearer_format: Option<String>,
    },
    OAuth2,
    OpenIdConnect {
        url: String,
    },
    MutualTls,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenApiOAuthFlows {
    pub implicit: Option<OpenApiOAuthFlow>,
    pub password: Option<OpenApiOAuthFlow>,
    pub client_credentials: Option<OpenApiOAuthFlow>,
    pub authorization_code: Option<OpenApiOAuthFlow>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenApiOAuthFlow {
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub refresh_url: Option<String>,
    pub scopes: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum OpenApiError {
    #[error("the OpenAPI document is not valid JSON or YAML")]
    Parse,
    #[error("only OpenAPI 3.0 and 3.1 documents are supported")]
    UnsupportedVersion,
    #[error("the OpenAPI document is invalid: {0}")]
    InvalidDocument(&'static str),
    #[error("external references are not supported: {0}")]
    ExternalReference(String),
    #[error("a local reference does not exist: {0}")]
    ReferenceNotFound(String),
    #[error("a local reference cycle was found: {0}")]
    ReferenceCycle(String),
    #[error("local reference resolution exceeded the depth limit")]
    ReferenceDepth,
    #[error("the OpenAPI document exceeds compiler limit {code}")]
    LimitExceeded { code: &'static str },
    #[error("operation {method} {path} is invalid: {message}")]
    InvalidOperation {
        method: String,
        path: String,
        message: &'static str,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenApiCredentialSet {
    pub schemes: BTreeMap<String, OpenApiCredential>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OpenApiCredential {
    ApiKey {
        value: String,
    },
    Bearer {
        token: String,
    },
    Basic {
        username: String,
        password: String,
    },
    #[serde(rename = "oauth_access_token")]
    OAuthAccessToken {
        #[serde(rename = "access_token")]
        access_token: String,
    },
}

pub type StaticCredentialSet = OpenApiCredentialSet;
pub type StaticCredentialScheme = OpenApiCredential;

impl OpenApiCredentialSet {
    pub fn validate(&self) -> Result<(), OpenApiCredentialError> {
        if self.schemes.len() > 64 {
            return Err(OpenApiCredentialError::TooManySchemes);
        }
        for (name, credential) in &self.schemes {
            if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
                return Err(OpenApiCredentialError::InvalidSchemeName);
            }
            credential.validate()?;
        }
        Ok(())
    }
}

impl OpenApiCredential {
    pub const fn credential_type(&self) -> &'static str {
        match self {
            Self::ApiKey { .. } => "api_key",
            Self::Bearer { .. } => "bearer",
            Self::Basic { .. } => "basic",
            Self::OAuthAccessToken { .. } => "manual_oauth_access_token",
        }
    }

    fn validate(&self) -> Result<(), OpenApiCredentialError> {
        if let Self::Basic { username, .. } = self
            && username.contains(':')
        {
            return Err(OpenApiCredentialError::InvalidBasicUsername);
        }
        if let Self::Basic { username, password } = self
            && (username.chars().any(char::is_control) || password.chars().any(char::is_control))
        {
            return Err(OpenApiCredentialError::InvalidBasicValue);
        }
        let valid = match self {
            Self::ApiKey { value } => !value.is_empty() && value.len() <= 16_384,
            Self::Bearer { token } => !token.is_empty() && token.len() <= 16_384,
            Self::Basic { username, password } => {
                username.len() <= 4_096 && password.len() <= 16_384
            }
            Self::OAuthAccessToken { access_token } => {
                !access_token.is_empty() && access_token.len() <= 16_384
            }
        };
        if valid {
            Ok(())
        } else {
            Err(OpenApiCredentialError::InvalidValue)
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum OpenApiCredentialError {
    #[error("at most 64 OpenAPI security schemes may be configured")]
    TooManySchemes,
    #[error("an OpenAPI security scheme name is invalid")]
    InvalidSchemeName,
    #[error("an OpenAPI credential value is invalid")]
    InvalidValue,
    #[error("an HTTP Basic username must not contain a colon")]
    InvalidBasicUsername,
    #[error("an HTTP Basic username or password must not contain control characters")]
    InvalidBasicValue,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenApiProtocolRequest {
    pub method: String,
    pub url: Url,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub selected_security_schemes: Vec<String>,
}

type CookieParameters = BTreeMap<String, Vec<(String, String)>>;

#[derive(Debug, Error)]
pub enum OpenApiInvocationError {
    #[error("tool arguments must be an object")]
    InvalidArguments,
    #[error("a required tool argument is missing: {0}")]
    MissingArgument(String),
    #[error("the tool arguments contain an invalid value: {0}")]
    InvalidArgument(String),
    #[error("no configured credential satisfies the operation security requirements")]
    UnsatisfiedSecurity,
    #[error("the configured credential does not match security scheme {0}")]
    InvalidCredential(String),
    #[error("the configured OpenAPI credentials are invalid")]
    InvalidCredentialConfiguration,
    #[error("an unsafe HTTP header was rejected: {0}")]
    InvalidHeader(String),
    #[error("the compiled operation URL is invalid")]
    InvalidUrl,
}

pub fn build_protocol_request(
    binding: &OpenApiBinding,
    arguments: &Value,
    credentials: &OpenApiCredentialSet,
) -> Result<OpenApiProtocolRequest, OpenApiInvocationError> {
    build_protocol_request_with_base(binding, arguments, credentials, None)
}

pub fn build_protocol_request_with_base(
    binding: &OpenApiBinding,
    arguments: &Value,
    credentials: &OpenApiCredentialSet,
    document_base_url: Option<&Url>,
) -> Result<OpenApiProtocolRequest, OpenApiInvocationError> {
    credentials
        .validate()
        .map_err(|_| OpenApiInvocationError::InvalidCredentialConfiguration)?;
    let method = validate_method(&binding.method)?;
    let arguments = arguments
        .as_object()
        .ok_or(OpenApiInvocationError::InvalidArguments)?;
    validate_argument_members(binding, arguments)?;
    let mut path = binding.path_template.clone();
    let mut query = Vec::new();
    let mut headers = BTreeMap::new();
    let mut cookies = BTreeMap::new();

    for parameter in &binding.parameters {
        validate_parameter_serialization(parameter)?;
        let carrier = arguments
            .get(parameter.location.input_key())
            .and_then(Value::as_object);
        let value = carrier.and_then(|carrier| carrier.get(&parameter.name));
        let Some(value) = value else {
            if parameter.required {
                return Err(OpenApiInvocationError::MissingArgument(format!(
                    "{}.{}",
                    parameter.location.input_key(),
                    parameter.name
                )));
            }
            continue;
        };
        match parameter.location {
            OpenApiParameterLocation::Path => {
                let serialized = serialize_parameter(value, parameter, false)?;
                let encoded = encode_path_value(&serialized);
                let marker = format!("{{{}}}", parameter.name);
                if !path.contains(&marker) {
                    return Err(OpenApiInvocationError::InvalidArgument(format!(
                        "path.{}",
                        parameter.name
                    )));
                }
                path = path.replace(&marker, &encoded);
            }
            OpenApiParameterLocation::Query => {
                append_query_parameter(&mut query, value, parameter)?;
            }
            OpenApiParameterLocation::Header => {
                validate_user_header_name(&parameter.name)?;
                let serialized = serialize_parameter(value, parameter, false)?;
                validate_header_value(&parameter.name, &serialized)?;
                headers.insert(parameter.name.to_ascii_lowercase(), serialized);
            }
            OpenApiParameterLocation::Cookie => {
                validate_cookie_name(&parameter.name)?;
                append_cookie_parameter(&mut cookies, value, parameter)?;
            }
        }
    }
    if path.contains('{') || path.contains('}') {
        return Err(OpenApiInvocationError::InvalidArgument("path".to_owned()));
    }

    let mut first_security_error = None;
    let mut selected = None;
    for alternative in &binding.security {
        if security_alternative_has_carrier_conflict(alternative)
            || !alternative.requirements.iter().all(|requirement| {
                credentials
                    .schemes
                    .get(&requirement.scheme_name)
                    .is_some_and(|credential| credential_matches(&requirement.scheme, credential))
            })
        {
            continue;
        }
        let mut candidate_query = query.clone();
        let mut candidate_headers = headers.clone();
        let mut candidate_cookies = cookies.clone();
        let applied = alternative.requirements.iter().try_for_each(|requirement| {
            let credential = credentials
                .schemes
                .get(&requirement.scheme_name)
                .ok_or(OpenApiInvocationError::UnsatisfiedSecurity)?;
            apply_credential(
                requirement,
                credential,
                &mut candidate_query,
                &mut candidate_headers,
                &mut candidate_cookies,
            )
        });
        match applied {
            Ok(()) => {
                selected = Some((
                    candidate_query,
                    candidate_headers,
                    candidate_cookies,
                    alternative
                        .requirements
                        .iter()
                        .map(|requirement| requirement.scheme_name.clone())
                        .collect::<Vec<_>>(),
                ));
                break;
            }
            Err(error) => {
                first_security_error.get_or_insert(error);
            }
        };
    }
    let (selected_query, selected_headers, selected_cookies, selected_security_schemes) = selected
        .ok_or_else(|| {
            first_security_error.unwrap_or(OpenApiInvocationError::UnsatisfiedSecurity)
        })?;
    query = selected_query;
    headers = selected_headers;
    cookies = selected_cookies;

    if !cookies.is_empty() {
        let cookie = cookies
            .into_values()
            .filter_map(|pairs| {
                (!pairs.is_empty()).then(|| {
                    pairs
                        .into_iter()
                        .map(|(name, value)| format!("{name}={}", encode_cookie_value(&value)))
                        .collect::<Vec<_>>()
                        .join("&")
                })
            })
            .collect::<Vec<_>>()
            .join("; ");
        headers.insert("cookie".to_owned(), cookie);
    }
    let mut url = operation_url(&binding.server_url, &path, document_base_url)?;
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (name, value) in query {
            pairs.append_pair(&name, &value);
        }
    }

    let body = if let Some(body_binding) = &binding.request_body {
        let body = arguments.get("body").cloned();
        if body_binding.required && body.is_none() {
            return Err(OpenApiInvocationError::MissingArgument("body".to_owned()));
        }
        let requested = match arguments.get("contentType") {
            Some(Value::String(requested)) => requested.as_str(),
            Some(_) => {
                return Err(OpenApiInvocationError::InvalidArgument(
                    "contentType".to_owned(),
                ));
            }
            None => &body_binding.default_media_type,
        };
        if !body_binding
            .media_types
            .iter()
            .any(|media| media == requested)
        {
            return Err(OpenApiInvocationError::InvalidArgument(
                "contentType".to_owned(),
            ));
        }
        if let Some(body) = &body {
            validate_request_body_value(requested, body)?;
        }
        if body.is_some() {
            headers.insert("content-type".to_owned(), requested.to_owned());
        } else if arguments.contains_key("contentType") {
            return Err(OpenApiInvocationError::InvalidArgument(
                "contentType".to_owned(),
            ));
        }
        body.map_or_else(
            || Ok(Vec::new()),
            |body| encode_request_body(requested, &body),
        )?
    } else {
        if arguments.contains_key("body") || arguments.contains_key("contentType") {
            return Err(OpenApiInvocationError::InvalidArgument("body".to_owned()));
        }
        Vec::new()
    };
    Ok(OpenApiProtocolRequest {
        method,
        url,
        headers,
        body,
        selected_security_schemes,
    })
}

fn validate_parameter_serialization(
    parameter: &OpenApiParameterBinding,
) -> Result<(), OpenApiInvocationError> {
    let supported = !parameter.allow_reserved
        && match parameter.location {
            OpenApiParameterLocation::Query => matches!(
                parameter.style.as_str(),
                "form" | "spaceDelimited" | "pipeDelimited" | "deepObject"
            ),
            OpenApiParameterLocation::Path | OpenApiParameterLocation::Header => {
                parameter.style == "simple"
            }
            OpenApiParameterLocation::Cookie => parameter.style == "form",
        };
    if supported {
        Ok(())
    } else {
        Err(OpenApiInvocationError::InvalidArgument(format!(
            "{}.{}",
            parameter.location.input_key(),
            parameter.name
        )))
    }
}

fn validate_method(method: &str) -> Result<String, OpenApiInvocationError> {
    let method = method.to_ascii_uppercase();
    if matches!(
        method.as_str(),
        "GET" | "PUT" | "POST" | "DELETE" | "OPTIONS" | "HEAD" | "PATCH"
    ) {
        Ok(method)
    } else {
        Err(OpenApiInvocationError::InvalidArgument("method".to_owned()))
    }
}

fn encode_request_body(media_type: &str, body: &Value) -> Result<Vec<u8>, OpenApiInvocationError> {
    let base = media_type
        .split_once(';')
        .map_or(media_type, |(base, _)| base)
        .trim();
    match base {
        "application/json" => serde_json::to_vec(body)
            .map_err(|_| OpenApiInvocationError::InvalidArgument("body".to_owned())),
        value if value.ends_with("+json") => serde_json::to_vec(body)
            .map_err(|_| OpenApiInvocationError::InvalidArgument("body".to_owned())),
        "text/plain" => Ok(body
            .as_str()
            .ok_or_else(|| OpenApiInvocationError::InvalidArgument("body".to_owned()))?
            .as_bytes()
            .to_vec()),
        "application/x-www-form-urlencoded" => {
            let object = body
                .as_object()
                .ok_or_else(|| OpenApiInvocationError::InvalidArgument("body".to_owned()))?;
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in object {
                serializer.append_pair(name, &scalar(value, "body")?);
            }
            Ok(serializer.finish().into_bytes())
        }
        _ => Err(OpenApiInvocationError::InvalidArgument("body".to_owned())),
    }
}

fn validate_request_body_value(
    media_type: &str,
    body: &Value,
) -> Result<(), OpenApiInvocationError> {
    let base = media_type
        .split_once(';')
        .map_or(media_type, |(base, _)| base)
        .trim();
    if base == "text/plain" && !body.is_string() {
        return Err(OpenApiInvocationError::InvalidArgument("body".to_owned()));
    }
    if base == "application/x-www-form-urlencoded" {
        let object = body
            .as_object()
            .ok_or_else(|| OpenApiInvocationError::InvalidArgument("body".to_owned()))?;
        if object
            .values()
            .any(|value| !matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_)))
        {
            return Err(OpenApiInvocationError::InvalidArgument("body".to_owned()));
        }
    }
    Ok(())
}

fn operation_url(
    server_url: &str,
    path: &str,
    document_base_url: Option<&Url>,
) -> Result<Url, OpenApiInvocationError> {
    let server = Url::parse(server_url)
        .or_else(|_| {
            document_base_url
                .ok_or(url::ParseError::RelativeUrlWithoutBase)?
                .join(server_url)
        })
        .map_err(|_| OpenApiInvocationError::InvalidUrl)?;
    if !matches!(server.scheme(), "http" | "https")
        || server.host().is_none()
        || !server.username().is_empty()
        || server.password().is_some()
        || server.query().is_some()
        || server.fragment().is_some()
    {
        return Err(OpenApiInvocationError::InvalidUrl);
    }
    let base_path = server.path().trim_end_matches('/');
    let combined = format!("{base_path}/{}", path.trim_start_matches('/'));
    let mut url = server;
    url.set_path(&combined);
    Ok(url)
}

fn validate_argument_members(
    binding: &OpenApiBinding,
    arguments: &Map<String, Value>,
) -> Result<(), OpenApiInvocationError> {
    let mut allowed_root = std::collections::BTreeSet::new();
    let mut carrier_members = BTreeMap::<&str, std::collections::BTreeSet<&str>>::new();
    for parameter in &binding.parameters {
        let carrier = parameter.location.input_key();
        allowed_root.insert(carrier);
        carrier_members
            .entry(carrier)
            .or_default()
            .insert(&parameter.name);
    }
    if binding.request_body.is_some() {
        allowed_root.insert("body");
        allowed_root.insert("contentType");
    }
    for (key, value) in arguments {
        if !allowed_root.contains(key.as_str()) {
            return Err(OpenApiInvocationError::InvalidArgument(key.clone()));
        }
        let Some(allowed_members) = carrier_members.get(key.as_str()) else {
            continue;
        };
        let members = value
            .as_object()
            .ok_or_else(|| OpenApiInvocationError::InvalidArgument(key.clone()))?;
        if let Some(unknown) = members
            .keys()
            .find(|member| !allowed_members.contains(member.as_str()))
        {
            return Err(OpenApiInvocationError::InvalidArgument(format!(
                "{key}.{unknown}"
            )));
        }
    }
    Ok(())
}

fn credential_matches(scheme: &OpenApiSecurityScheme, credential: &OpenApiCredential) -> bool {
    match (scheme, credential) {
        (OpenApiSecurityScheme::ApiKey { .. }, OpenApiCredential::ApiKey { .. }) => true,
        (OpenApiSecurityScheme::Http { scheme, .. }, OpenApiCredential::Basic { .. }) => {
            scheme == "basic"
        }
        (
            OpenApiSecurityScheme::Http { scheme, .. },
            OpenApiCredential::Bearer { .. } | OpenApiCredential::OAuthAccessToken { .. },
        ) => scheme == "bearer",
        (
            OpenApiSecurityScheme::OAuth2 | OpenApiSecurityScheme::OpenIdConnect { .. },
            OpenApiCredential::OAuthAccessToken { .. },
        ) => true,
        _ => false,
    }
}

fn apply_credential(
    requirement: &OpenApiSecurityRequirement,
    credential: &OpenApiCredential,
    query: &mut Vec<(String, String)>,
    headers: &mut BTreeMap<String, String>,
    cookies: &mut CookieParameters,
) -> Result<(), OpenApiInvocationError> {
    match (&requirement.scheme, credential) {
        (OpenApiSecurityScheme::ApiKey { name, location }, OpenApiCredential::ApiKey { value }) => {
            reject_control_characters(name, value)?;
            match location {
                OpenApiParameterLocation::Query => {
                    query.retain(|(existing, _)| existing != name);
                    query.push((name.clone(), value.clone()));
                }
                OpenApiParameterLocation::Header => {
                    validate_auth_header_name(name)?;
                    validate_header_value(name, value)?;
                    headers.insert(name.to_ascii_lowercase(), value.clone());
                }
                OpenApiParameterLocation::Cookie => {
                    validate_cookie_name(name)?;
                    for pairs in cookies.values_mut() {
                        pairs.retain(|(existing, _)| existing != name);
                    }
                    cookies.retain(|_, pairs| !pairs.is_empty());
                    cookies.insert(name.clone(), vec![(name.clone(), value.clone())]);
                }
                OpenApiParameterLocation::Path => {
                    return Err(OpenApiInvocationError::InvalidCredential(
                        requirement.scheme_name.clone(),
                    ));
                }
            }
        }
        (
            OpenApiSecurityScheme::Http { scheme, .. },
            OpenApiCredential::Basic { username, password },
        ) if scheme == "basic" => {
            reject_control_characters("username", username)?;
            reject_control_characters("password", password)?;
            use base64::Engine as _;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            let value = format!("Basic {encoded}");
            validate_header_value("authorization", &value)?;
            headers.insert("authorization".to_owned(), value);
        }
        (OpenApiSecurityScheme::Http { scheme, .. }, OpenApiCredential::Bearer { token })
            if scheme == "bearer" =>
        {
            reject_control_characters("token", token)?;
            let value = format!("Bearer {token}");
            validate_header_value("authorization", &value)?;
            headers.insert("authorization".to_owned(), value);
        }
        (
            OpenApiSecurityScheme::Http { scheme, .. },
            OpenApiCredential::OAuthAccessToken { access_token },
        ) if scheme == "bearer" => {
            reject_control_characters("access token", access_token)?;
            let value = format!("Bearer {access_token}");
            validate_header_value("authorization", &value)?;
            headers.insert("authorization".to_owned(), value);
        }
        (
            OpenApiSecurityScheme::OAuth2 | OpenApiSecurityScheme::OpenIdConnect { .. },
            OpenApiCredential::OAuthAccessToken { access_token },
        ) => {
            reject_control_characters("access token", access_token)?;
            let value = format!("Bearer {access_token}");
            validate_header_value("authorization", &value)?;
            headers.insert("authorization".to_owned(), value);
        }
        _ => {
            return Err(OpenApiInvocationError::InvalidCredential(
                requirement.scheme_name.clone(),
            ));
        }
    }
    Ok(())
}

fn append_query_parameter(
    output: &mut Vec<(String, String)>,
    value: &Value,
    parameter: &OpenApiParameterBinding,
) -> Result<(), OpenApiInvocationError> {
    if parameter.style == "deepObject" {
        let object = value.as_object().ok_or_else(|| {
            OpenApiInvocationError::InvalidArgument(format!("query.{}", parameter.name))
        })?;
        for (key, value) in object {
            output.push((
                format!("{}[{key}]", parameter.name),
                scalar(value, &format!("query.{}", parameter.name))?,
            ));
        }
        return Ok(());
    }
    if parameter.explode
        && let Some(values) = value.as_array()
    {
        for value in values {
            output.push((
                parameter.name.clone(),
                scalar(value, &format!("query.{}", parameter.name))?,
            ));
        }
        return Ok(());
    }
    if parameter.explode
        && let Some(object) = value.as_object()
    {
        for (key, value) in object {
            output.push((
                key.clone(),
                scalar(value, &format!("query.{}", parameter.name))?,
            ));
        }
        return Ok(());
    }
    output.push((
        parameter.name.clone(),
        serialize_parameter(value, parameter, true)?,
    ));
    Ok(())
}

fn append_cookie_parameter(
    output: &mut CookieParameters,
    value: &Value,
    parameter: &OpenApiParameterBinding,
) -> Result<(), OpenApiInvocationError> {
    let label = format!("cookies.{}", parameter.name);
    let pairs = if let Some(values) = value.as_array() {
        if parameter.explode {
            values
                .iter()
                .map(|value| Ok((parameter.name.clone(), scalar(value, &label)?)))
                .collect::<Result<Vec<_>, OpenApiInvocationError>>()?
        } else {
            vec![(
                parameter.name.clone(),
                values
                    .iter()
                    .map(|value| scalar(value, &label))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(","),
            )]
        }
    } else if let Some(object) = value.as_object() {
        if parameter.explode {
            object
                .iter()
                .map(|(name, value)| {
                    validate_cookie_name(name)?;
                    Ok((name.clone(), scalar(value, &label)?))
                })
                .collect::<Result<Vec<_>, OpenApiInvocationError>>()?
        } else {
            let mut flattened = Vec::with_capacity(object.len() * 2);
            for (name, value) in object {
                flattened.push(name.clone());
                flattened.push(scalar(value, &label)?);
            }
            vec![(parameter.name.clone(), flattened.join(","))]
        }
    } else {
        vec![(parameter.name.clone(), scalar(value, &label)?)]
    };
    for (name, value) in &pairs {
        validate_cookie_name(name)?;
        reject_control_characters(name, value)?;
    }
    output.insert(parameter.name.clone(), pairs);
    Ok(())
}

fn serialize_parameter(
    value: &Value,
    parameter: &OpenApiParameterBinding,
    query: bool,
) -> Result<String, OpenApiInvocationError> {
    let label = format!("{}.{}", parameter.location.input_key(), parameter.name);
    if let Some(values) = value.as_array() {
        let delimiter = match parameter.style.as_str() {
            "spaceDelimited" if query => " ",
            "pipeDelimited" if query => "|",
            _ => ",",
        };
        return values
            .iter()
            .map(|value| scalar(value, &label))
            .collect::<Result<Vec<_>, _>>()
            .map(|values| values.join(delimiter));
    }
    if let Some(object) = value.as_object() {
        let mut values = Vec::with_capacity(object.len() * 2);
        for (key, value) in object {
            let value = scalar(value, &label)?;
            if parameter.explode {
                values.push(format!("{key}={value}"));
            } else {
                values.push(key.clone());
                values.push(value);
            }
        }
        return Ok(values.join(","));
    }
    scalar(value, &label)
}

fn scalar(value: &Value, label: &str) -> Result<String, OpenApiInvocationError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err(OpenApiInvocationError::InvalidArgument(label.to_owned())),
    }
}

fn validate_user_header_name(name: &str) -> Result<(), OpenApiInvocationError> {
    let normalized = name.to_ascii_lowercase();
    if protected_header(&normalized, false) {
        return Err(OpenApiInvocationError::InvalidHeader(name.to_owned()));
    }
    validate_header_token(name)
}

fn validate_auth_header_name(name: &str) -> Result<(), OpenApiInvocationError> {
    let normalized = name.to_ascii_lowercase();
    if protected_header(&normalized, true) {
        return Err(OpenApiInvocationError::InvalidHeader(name.to_owned()));
    }
    validate_header_token(name)
}

fn validate_header_token(name: &str) -> Result<(), OpenApiInvocationError> {
    if is_http_token(name) {
        Ok(())
    } else {
        Err(OpenApiInvocationError::InvalidHeader(name.to_owned()))
    }
}

fn validate_cookie_name(name: &str) -> Result<(), OpenApiInvocationError> {
    validate_header_token(name)
}

fn protected_header(normalized: &str, allow_authorization: bool) -> bool {
    (!allow_authorization && normalized == "authorization")
        || normalized.starts_with("proxy-")
        || normalized.starts_with("x-forwarded-")
        || matches!(
            normalized,
            "host"
                | "content-length"
                | "transfer-encoding"
                | "connection"
                | "cookie"
                | "proxy-connection"
                | "upgrade"
                | "te"
                | "trailer"
                | "forwarded"
                | "via"
                | "referer"
                | "x-forwarded"
                | "x-real-ip"
                | "x-original-url"
                | "x-rewrite-url"
                | "x-original-host"
                | "x-http-method-override"
                | "x-http-method"
                | "x-method-override"
                | "x-original-method"
        )
}

fn is_http_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn validate_header_value(name: &str, value: &str) -> Result<(), OpenApiInvocationError> {
    if value
        .bytes()
        .any(|byte| byte != b'\t' && !(b' '..=b'~').contains(&byte))
    {
        Err(OpenApiInvocationError::InvalidHeader(name.to_owned()))
    } else {
        Ok(())
    }
}

fn reject_control_characters(name: &str, value: &str) -> Result<(), OpenApiInvocationError> {
    if value.chars().any(char::is_control) {
        Err(OpenApiInvocationError::InvalidArgument(name.to_owned()))
    } else {
        Ok(())
    }
}

fn encode_path_value(value: &str) -> String {
    percent_encode(value, false)
}

fn encode_cookie_value(value: &str) -> String {
    percent_encode(value, true)
}

fn percent_encode(value: &str, cookie: bool) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        let safe = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || (cookie && matches!(byte, b':' | b'@'));
        if safe {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

pub fn compile_document(bytes: &[u8]) -> Result<CompiledOpenApi, OpenApiError> {
    let document = parse_document(bytes)?;
    compile_value(document)
}

pub fn compile_value(document: Value) -> Result<CompiledOpenApi, OpenApiError> {
    let document_bytes = serde_json::to_vec(&document)
        .map_err(|_| OpenApiError::InvalidDocument("the document cannot be serialized"))?
        .len();
    if document_bytes > MAX_RESOLVED_BYTES {
        return Err(limit("document_bytes"));
    }
    let root = document
        .as_object()
        .ok_or(OpenApiError::InvalidDocument("the root must be an object"))?;
    let schema_dialect = validate_version(root)?;
    reject_external_references(&document)?;
    if matches!(schema_dialect, OpenApiSchemaDialect::OpenApi30) {
        reject_openapi30_reference_siblings(&document)?;
    }

    let info = object_field(root, "info")?;
    let title = string_field(info, "title")?.to_owned();
    let description = optional_string(info, "description")?.map(str::to_owned);
    let paths = object_field(root, "paths")?;
    let root_servers = root.get("servers");
    let root_security = root.get("security");
    let security_schemes = root
        .get("components")
        .and_then(Value::as_object)
        .and_then(|components| components.get("securitySchemes"))
        .and_then(Value::as_object);
    let mut tools = Vec::new();
    let mut budget = CompileBudget {
        resolved_nodes: 0,
        resolved_bytes: document_bytes,
    };
    if root_servers.is_some() {
        select_server(root_servers, &document, "ROOT", "/", &mut budget)?;
    }

    for (path, raw_path_item) in paths {
        if !path.starts_with('/') {
            continue;
        }
        let mut stack = Vec::new();
        let path_item = resolve_value(raw_path_item, &document, &mut stack, 0, &mut budget)?;
        let path_item = path_item
            .as_object()
            .ok_or_else(|| invalid_operation("PATH", path, "the path item must be an object"))?;
        if path_item.get("servers").is_some() {
            select_server(
                path_item.get("servers"),
                &document,
                "PATH",
                path,
                &mut budget,
            )?;
        }
        let path_parameters =
            parse_parameters(path_item.get("parameters"), &document, path, &mut budget)?;

        for method in HTTP_METHODS {
            let Some(raw_operation) = path_item.get(method) else {
                continue;
            };
            if method == "trace" {
                return Err(invalid_operation(
                    method,
                    path,
                    "TRACE operations are not supported",
                ));
            }
            if tools.len() >= MAX_COMPILED_OPERATIONS {
                return Err(limit("too_many_operations"));
            }
            let mut stack = Vec::new();
            let operation = resolve_value(raw_operation, &document, &mut stack, 0, &mut budget)?;
            let operation = operation.as_object().ok_or_else(|| {
                invalid_operation(method, path, "the operation must be an object")
            })?;
            if operation.get("servers").is_some() {
                select_server(
                    operation.get("servers"),
                    &document,
                    method,
                    path,
                    &mut budget,
                )?;
            }
            let operation_parameters =
                parse_parameters(operation.get("parameters"), &document, path, &mut budget)?;
            let parameters = merge_parameters(path_parameters.clone(), operation_parameters);
            if parameters.len() > MAX_PARAMETERS_PER_OPERATION {
                return Err(limit("too_many_parameters"));
            }
            validate_path_parameters(method, path, &parameters)?;
            let server_url = select_server(
                operation
                    .get("servers")
                    .or_else(|| path_item.get("servers"))
                    .or(root_servers),
                &document,
                method,
                path,
                &mut budget,
            )?;
            let request_body = parse_request_body(
                operation.get("requestBody"),
                &document,
                method,
                path,
                &mut budget,
            )?;
            let security = parse_security(
                operation.get("security").or(root_security),
                security_schemes,
                &document,
                method,
                path,
                &mut budget,
            )?;
            let preferred_name = operation
                .get("x-executor-toolPath")
                .and_then(Value::as_str)
                .or_else(|| operation.get("operationId").and_then(Value::as_str))
                .map(str::to_owned)
                .unwrap_or_else(|| fallback_name(method, path));
            let display_name = operation
                .get("summary")
                .and_then(Value::as_str)
                .or_else(|| operation.get("operationId").and_then(Value::as_str))
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{} {path}", method.to_ascii_uppercase()));
            let description = operation
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let input_schema =
                build_input_schema(&parameters, request_body.as_ref(), schema_dialect)?;
            let output_schema = parse_output_schema(
                operation.get("responses"),
                &document,
                method,
                path,
                &mut budget,
            )?;
            let binding = OpenApiBinding {
                version: 1,
                method: method.to_ascii_uppercase(),
                path_template: path.clone(),
                server_url,
                parameters: parameters
                    .iter()
                    .map(|parameter| parameter.binding.clone())
                    .collect(),
                request_body: request_body.as_ref().map(|body| body.binding.clone()),
                security,
            };
            budget.charge_serialized(&input_schema)?;
            if let Some(output_schema) = &output_schema {
                budget.charge_serialized(output_schema)?;
            }
            budget.charge_serialized(&binding)?;
            tools.push(CompiledOpenApiTool {
                stable_key: stable_key(method, path),
                preferred_name,
                display_name,
                description,
                input_schema,
                output_schema,
                intrinsic_mode: intrinsic_mode(method),
                binding,
            });
        }
    }
    tools.sort_by(|left, right| left.stable_key.cmp(&right.stable_key));
    Ok(CompiledOpenApi {
        document,
        title,
        description,
        tools,
    })
}

fn parse_document(bytes: &[u8]) -> Result<Value, OpenApiError> {
    let mut json = serde_json::Deserializer::from_slice(bytes);
    if let Ok(value) = UniqueValue::deserialize(&mut json)
        && json.end().is_ok()
    {
        return Ok(value.0);
    }
    serde_yaml::from_slice::<UniqueValue>(bytes)
        .map(|value| value.0)
        .map_err(|_| OpenApiError::Parse)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON-compatible value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite numbers are not supported"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some((key, value)) = entries.next_entry::<String, UniqueValue>()? {
            if object.insert(key.clone(), value.0).is_some() {
                return Err(de::Error::custom(format!("duplicate object key: {key}")));
            }
        }
        Ok(UniqueValue(Value::Object(object)))
    }
}

fn validate_version(root: &Map<String, Value>) -> Result<OpenApiSchemaDialect, OpenApiError> {
    if root.contains_key("swagger") {
        return Err(OpenApiError::UnsupportedVersion);
    }
    let version = root
        .get("openapi")
        .and_then(Value::as_str)
        .ok_or(OpenApiError::UnsupportedVersion)?;
    if version.starts_with("3.0.") {
        Ok(OpenApiSchemaDialect::OpenApi30)
    } else if version.starts_with("3.1.") {
        validate_openapi31_schema_dialect(root)?;
        Ok(OpenApiSchemaDialect::JsonSchema202012)
    } else {
        Err(OpenApiError::UnsupportedVersion)
    }
}

fn validate_openapi31_schema_dialect(root: &Map<String, Value>) -> Result<(), OpenApiError> {
    let Some(dialect) = root.get("jsonSchemaDialect") else {
        return Ok(());
    };
    let dialect = dialect.as_str().ok_or(OpenApiError::InvalidDocument(
        "jsonSchemaDialect must be a URI string",
    ))?;
    let dialect = dialect.strip_suffix('#').unwrap_or(dialect);
    if matches!(dialect, OAS31_BASE_DIALECT | JSON_SCHEMA_2020_12_DIALECT) {
        Ok(())
    } else {
        Err(OpenApiError::InvalidDocument(
            "the OpenAPI 3.1 JSON Schema dialect is not supported",
        ))
    }
}

fn reject_external_references(value: &Value) -> Result<(), OpenApiError> {
    match value {
        Value::Array(values) => {
            for value in values {
                reject_external_references(value)?;
            }
        }
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str)
                && !reference.starts_with('#')
            {
                return Err(OpenApiError::ExternalReference(reference.to_owned()));
            }
            for value in object.values() {
                reject_external_references(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_openapi30_reference_siblings(value: &Value) -> Result<(), OpenApiError> {
    match value {
        Value::Array(values) => {
            for value in values {
                reject_openapi30_reference_siblings(value)?;
            }
        }
        Value::Object(object) => {
            if object.contains_key("$ref") && object.len() > 1 {
                return Err(OpenApiError::InvalidDocument(
                    "OpenAPI 3.0 reference objects cannot have sibling fields",
                ));
            }
            for value in object.values() {
                reject_openapi30_reference_siblings(value)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

#[derive(Default)]
struct CompileBudget {
    resolved_nodes: usize,
    resolved_bytes: usize,
}

impl CompileBudget {
    fn charge(&mut self, value: &Value) -> Result<(), OpenApiError> {
        self.resolved_nodes = self
            .resolved_nodes
            .checked_add(1)
            .ok_or_else(|| limit("resolved_nodes"))?;
        if self.resolved_nodes > MAX_RESOLVED_NODES {
            return Err(limit("resolved_nodes"));
        }
        let shallow_bytes = match value {
            Value::Null | Value::Bool(_) => 8,
            Value::Number(number) => number.to_string().len() + 8,
            Value::String(value) => value.len() + 8,
            Value::Array(values) => values.len().saturating_mul(2) + 8,
            Value::Object(object) => object.keys().fold(8usize, |bytes, key| {
                bytes.saturating_add(key.len()).saturating_add(4)
            }),
        };
        self.charge_bytes(shallow_bytes)?;
        Ok(())
    }

    fn charge_serialized<T: Serialize>(&mut self, value: &T) -> Result<(), OpenApiError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|_| OpenApiError::InvalidDocument("compiled data cannot be serialized"))?
            .len();
        self.charge_bytes(bytes)
    }

    fn charge_bytes(&mut self, bytes: usize) -> Result<(), OpenApiError> {
        self.resolved_bytes = self
            .resolved_bytes
            .checked_add(bytes)
            .ok_or_else(|| limit("resolved_bytes"))?;
        if self.resolved_bytes > MAX_RESOLVED_BYTES {
            return Err(limit("resolved_bytes"));
        }
        Ok(())
    }
}

fn resolve_value(
    value: &Value,
    root: &Value,
    stack: &mut Vec<String>,
    depth: usize,
    budget: &mut CompileBudget,
) -> Result<Value, OpenApiError> {
    if depth > MAX_REFERENCE_DEPTH {
        return Err(OpenApiError::ReferenceDepth);
    }
    budget.charge(value)?;
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| resolve_value(value, root, stack, depth + 1, budget))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref") {
                let reference = reference
                    .as_str()
                    .ok_or(OpenApiError::InvalidDocument("$ref must be a string"))?;
                if !reference.starts_with('#') {
                    return Err(OpenApiError::ExternalReference(reference.to_owned()));
                }
                let pointer = local_pointer(reference)?;
                if stack.iter().any(|entry| entry == reference) {
                    return Err(OpenApiError::ReferenceCycle(reference.to_owned()));
                }
                let target = root
                    .pointer(&pointer)
                    .ok_or_else(|| OpenApiError::ReferenceNotFound(reference.to_owned()))?;
                stack.push(reference.to_owned());
                let resolved = resolve_value(target, root, stack, depth + 1, budget)?;
                stack.pop();
                if object.len() == 1 {
                    return Ok(resolved);
                }
                let mut resolved =
                    resolved
                        .as_object()
                        .cloned()
                        .ok_or(OpenApiError::InvalidDocument(
                            "a referenced value with siblings must be an object",
                        ))?;
                for (key, sibling) in object {
                    if key != "$ref" {
                        resolved.insert(
                            key.clone(),
                            resolve_value(sibling, root, stack, depth + 1, budget)?,
                        );
                    }
                }
                Ok(Value::Object(resolved))
            } else {
                object
                    .iter()
                    .map(|(key, value)| {
                        Ok((
                            key.clone(),
                            resolve_value(value, root, stack, depth + 1, budget)?,
                        ))
                    })
                    .collect::<Result<Map<_, _>, _>>()
                    .map(Value::Object)
            }
        }
        _ => Ok(value.clone()),
    }
}

fn local_pointer(reference: &str) -> Result<String, OpenApiError> {
    let fragment = reference
        .strip_prefix('#')
        .expect("local references start with a fragment marker");
    percent_decode(fragment).ok_or_else(|| OpenApiError::ReferenceNotFound(reference.to_owned()))
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push(hex(high)? * 16 + hex(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone)]
struct ParsedParameter {
    binding: OpenApiParameterBinding,
    schema: Value,
}

fn parse_parameters(
    value: Option<&Value>,
    root: &Value,
    path: &str,
    budget: &mut CompileBudget,
) -> Result<Vec<ParsedParameter>, OpenApiError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid_operation("PATH", path, "parameters must be an array"))?;
    if values.len() > MAX_PARAMETERS_PER_OPERATION {
        return Err(limit("too_many_parameters"));
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let mut stack = Vec::new();
        let value = resolve_value(value, root, &mut stack, 0, budget)?;
        let parameter = value
            .as_object()
            .ok_or_else(|| invalid_operation("PATH", path, "a parameter must be an object"))?;
        let name = string_field(parameter, "name")?.to_owned();
        let location = match string_field(parameter, "in")? {
            "path" => OpenApiParameterLocation::Path,
            "query" => OpenApiParameterLocation::Query,
            "header" => OpenApiParameterLocation::Header,
            "cookie" => OpenApiParameterLocation::Cookie,
            _ => {
                return Err(invalid_operation(
                    "PATH",
                    path,
                    "a parameter location is invalid",
                ));
            }
        };
        let required = location == OpenApiParameterLocation::Path
            || parameter
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let style = parameter
            .get("style")
            .and_then(Value::as_str)
            .unwrap_or_else(|| default_style(location))
            .to_owned();
        let explode = parameter
            .get("explode")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| style == "form");
        let allow_reserved = parameter
            .get("allowReserved")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if allow_reserved {
            return Err(invalid_operation(
                "PATH",
                path,
                "allowReserved parameters are not supported",
            ));
        }
        let supported_style = match location {
            OpenApiParameterLocation::Path | OpenApiParameterLocation::Header => style == "simple",
            OpenApiParameterLocation::Query => matches!(
                style.as_str(),
                "form" | "spaceDelimited" | "pipeDelimited" | "deepObject"
            ),
            OpenApiParameterLocation::Cookie => style == "form",
        };
        if !supported_style {
            return Err(invalid_operation(
                "PATH",
                path,
                "the parameter serialization style is not supported",
            ));
        }
        if parameter.contains_key("content") {
            return Err(invalid_operation(
                "PATH",
                path,
                "content-based parameters are not supported",
            ));
        }
        let schema = if let Some(schema) = parameter.get("schema") {
            schema.clone()
        } else {
            json!({})
        };
        parsed.push(ParsedParameter {
            binding: OpenApiParameterBinding {
                name,
                location,
                required,
                style,
                explode,
                allow_reserved,
            },
            schema,
        });
    }
    Ok(parsed)
}

fn merge_parameters(
    path_parameters: Vec<ParsedParameter>,
    operation_parameters: Vec<ParsedParameter>,
) -> Vec<ParsedParameter> {
    let mut parameters = BTreeMap::new();
    for parameter in path_parameters.into_iter().chain(operation_parameters) {
        parameters.insert(
            (parameter.binding.location, parameter.binding.name.clone()),
            parameter,
        );
    }
    parameters.into_values().collect()
}

fn default_style(location: OpenApiParameterLocation) -> &'static str {
    match location {
        OpenApiParameterLocation::Path | OpenApiParameterLocation::Header => "simple",
        OpenApiParameterLocation::Query | OpenApiParameterLocation::Cookie => "form",
    }
}

fn validate_path_parameters(
    method: &str,
    path: &str,
    parameters: &[ParsedParameter],
) -> Result<(), OpenApiError> {
    let mut template_names = Vec::new();
    let mut remainder = path;
    while let Some(open) = remainder.find('{') {
        let after_open = &remainder[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(invalid_operation(
                method,
                path,
                "the path template has an unclosed variable",
            ));
        };
        let name = &after_open[..close];
        if name.is_empty() || name.contains('{') {
            return Err(invalid_operation(
                method,
                path,
                "the path template has an invalid variable",
            ));
        }
        template_names.push(name);
        remainder = &after_open[close + 1..];
    }
    if remainder.contains('}') {
        return Err(invalid_operation(
            method,
            path,
            "the path template has an unmatched closing brace",
        ));
    }
    let path_parameters = parameters
        .iter()
        .filter(|parameter| parameter.binding.location == OpenApiParameterLocation::Path)
        .map(|parameter| parameter.binding.name.as_str())
        .collect::<Vec<_>>();
    let same_members = template_names.len() == path_parameters.len()
        && template_names
            .iter()
            .all(|name| path_parameters.iter().any(|parameter| parameter == name));
    if same_members {
        Ok(())
    } else {
        Err(invalid_operation(
            method,
            path,
            "path template variables and path parameters must match",
        ))
    }
}

fn select_server(
    value: Option<&Value>,
    root: &Value,
    method: &str,
    path: &str,
    budget: &mut CompileBudget,
) -> Result<String, OpenApiError> {
    let Some(value) = value else {
        return Ok("/".to_owned());
    };
    let servers = value
        .as_array()
        .ok_or_else(|| invalid_operation(method, path, "servers must be an array"))?;
    if servers.is_empty() {
        return Ok("/".to_owned());
    }
    let mut selected = None;
    for server in servers {
        let mut stack = Vec::new();
        let server = resolve_value(server, root, &mut stack, 0, budget)?;
        let url = parse_server_url(&server, method, path)?;
        if selected.is_none() {
            selected = Some(url);
        }
    }
    Ok(selected.expect("a non-empty server list selects its first server"))
}

fn parse_server_url(server: &Value, method: &str, path: &str) -> Result<String, OpenApiError> {
    let server = server
        .as_object()
        .ok_or_else(|| invalid_operation(method, path, "a server must be an object"))?;
    let mut url = string_field(server, "url")?.to_owned();
    if let Some(variables) = server.get("variables").and_then(Value::as_object) {
        for (name, variable) in variables {
            let default = variable
                .get("default")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    invalid_operation(method, path, "a server variable needs a default")
                })?;
            url = url.replace(&format!("{{{name}}}"), default);
        }
    }
    validate_server_url(&url, method, path)?;
    Ok(url)
}

fn validate_server_url(url: &str, method: &str, path: &str) -> Result<(), OpenApiError> {
    let base = Url::parse("https://executor.invalid/")
        .expect("the fixed OpenAPI server validation base is valid");
    let parsed = Url::options()
        .base_url(Some(&base))
        .parse(url)
        .map_err(|_| invalid_operation(method, path, "the server URL is invalid"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(invalid_operation(
            method,
            path,
            "the server URL scheme is not supported",
        ));
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid_operation(
            method,
            path,
            "server URLs cannot contain userinfo, query parameters, or fragments",
        ));
    }
    Ok(())
}

struct ParsedRequestBody {
    binding: OpenApiRequestBodyBinding,
    schemas: Vec<Value>,
}

fn parse_request_body(
    value: Option<&Value>,
    root: &Value,
    method: &str,
    path: &str,
    budget: &mut CompileBudget,
) -> Result<Option<ParsedRequestBody>, OpenApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut stack = Vec::new();
    let body = resolve_value(value, root, &mut stack, 0, budget)?;
    let body = body
        .as_object()
        .ok_or_else(|| invalid_operation(method, path, "requestBody must be an object"))?;
    let content = object_field(body, "content")?;
    let mut media_types = content.keys().cloned().collect::<Vec<_>>();
    if media_types.iter().any(|media_type| {
        let base = media_type
            .split_once(';')
            .map_or(media_type.as_str(), |(base, _)| base)
            .trim();
        !(base == "application/json"
            || base.ends_with("+json")
            || base == "text/plain"
            || base == "application/x-www-form-urlencoded")
    }) {
        return Err(invalid_operation(
            method,
            path,
            "the request body media type is not supported",
        ));
    }
    media_types.sort_by(|left, right| {
        media_rank(left)
            .cmp(&media_rank(right))
            .then_with(|| left.cmp(right))
    });
    let Some(default_media_type) = media_types.first().cloned() else {
        return Err(invalid_operation(
            method,
            path,
            "requestBody content cannot be empty",
        ));
    };
    let schemas = media_types
        .iter()
        .map(|media_type| {
            content
                .get(media_type)
                .and_then(Value::as_object)
                .and_then(|media| media.get("schema"))
                .cloned()
                .unwrap_or_else(|| json!({}))
        })
        .collect::<Vec<_>>();
    for (media_type, schema) in media_types.iter().zip(&schemas) {
        validate_request_body_schema(media_type, schema, method, path)?;
    }
    Ok(Some(ParsedRequestBody {
        binding: OpenApiRequestBodyBinding {
            required: body
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            default_media_type,
            media_types,
        },
        schemas,
    }))
}

fn validate_request_body_schema(
    media_type: &str,
    schema: &Value,
    method: &str,
    path: &str,
) -> Result<(), OpenApiError> {
    let base = media_type
        .split_once(';')
        .map_or(media_type, |(base, _)| base)
        .trim();
    if base == "text/plain" {
        if schema.get("type").and_then(Value::as_str) != Some("string") {
            return Err(invalid_operation(
                method,
                path,
                "text/plain request bodies require a string schema",
            ));
        }
    } else if base == "application/x-www-form-urlencoded" {
        let schema = schema.as_object().ok_or_else(|| {
            invalid_operation(method, path, "form request bodies require an object schema")
        })?;
        if schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err(invalid_operation(
                method,
                path,
                "form request bodies require an object schema",
            ));
        }
        if schema.get("additionalProperties") != Some(&Value::Bool(false)) {
            return Err(invalid_operation(
                method,
                path,
                "form request body properties must be declared scalar values",
            ));
        }
        if let Some(properties) = schema.get("properties") {
            let properties = properties.as_object().ok_or_else(|| {
                invalid_operation(method, path, "form schema properties must be an object")
            })?;
            for property in properties.values() {
                let scalar = property
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| {
                        matches!(kind, "string" | "number" | "integer" | "boolean")
                    });
                if !scalar {
                    return Err(invalid_operation(
                        method,
                        path,
                        "form request body properties must be scalar values",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn select_media(content: &Map<String, Value>) -> Option<(&String, &Map<String, Value>)> {
    content
        .iter()
        .filter_map(|(kind, value)| value.as_object().map(|value| (kind, value)))
        .min_by(|(left, _), (right, _)| {
            media_rank(left)
                .cmp(&media_rank(right))
                .then_with(|| left.cmp(right))
        })
}

fn media_rank(media_type: &str) -> u8 {
    let media_type = media_type
        .split_once(';')
        .map_or(media_type, |(essence, _)| essence)
        .trim();
    match media_type {
        "application/json" => 0,
        value if value.ends_with("+json") => 1,
        "application/x-www-form-urlencoded" => 2,
        "multipart/form-data" => 3,
        value if value.starts_with("text/") => 4,
        _ => 5,
    }
}

fn parse_security(
    value: Option<&Value>,
    schemes: Option<&Map<String, Value>>,
    root: &Value,
    method: &str,
    path: &str,
    budget: &mut CompileBudget,
) -> Result<Vec<OpenApiSecurityAlternative>, OpenApiError> {
    let Some(value) = value else {
        return Ok(vec![OpenApiSecurityAlternative {
            requirements: Vec::new(),
        }]);
    };
    let alternatives = value
        .as_array()
        .ok_or_else(|| invalid_operation(method, path, "security must be an array"))?;
    if alternatives.len() > MAX_SECURITY_ALTERNATIVES {
        return Err(limit("too_many_security_alternatives"));
    }
    if alternatives.is_empty() {
        return Ok(vec![OpenApiSecurityAlternative {
            requirements: Vec::new(),
        }]);
    }
    let mut parsed = Vec::with_capacity(alternatives.len());
    for alternative in alternatives {
        let alternative = alternative.as_object().ok_or_else(|| {
            invalid_operation(method, path, "a security alternative must be an object")
        })?;
        if alternative.len() > MAX_SECURITY_REQUIREMENTS_PER_ALTERNATIVE {
            return Err(limit("too_many_security_requirements"));
        }
        let mut requirements = Vec::with_capacity(alternative.len());
        for (scheme_name, scopes) in alternative {
            let scheme_value = schemes
                .and_then(|schemes| schemes.get(scheme_name))
                .ok_or_else(|| invalid_operation(method, path, "a security scheme is missing"))?;
            let mut stack = Vec::new();
            let scheme_value = resolve_value(scheme_value, root, &mut stack, 0, budget)?;
            let (scheme, oauth_flows) = parse_security_scheme(
                scheme_value.as_object().ok_or_else(|| {
                    invalid_operation(method, path, "a security scheme must be an object")
                })?,
                method,
                path,
            )?;
            let scopes = scopes
                .as_array()
                .ok_or_else(|| invalid_operation(method, path, "security scopes must be an array"))?
                .iter()
                .map(|scope| {
                    scope.as_str().map(str::to_owned).ok_or_else(|| {
                        invalid_operation(method, path, "a security scope must be a string")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            requirements.push(OpenApiSecurityRequirement {
                scheme_name: scheme_name.clone(),
                scopes,
                scheme,
                oauth_flows,
            });
        }
        requirements.sort_by(|left, right| left.scheme_name.cmp(&right.scheme_name));
        let alternative = OpenApiSecurityAlternative { requirements };
        if security_alternative_has_carrier_conflict(&alternative) {
            return Err(invalid_operation(
                method,
                path,
                "security requirements in an AND alternative target the same carrier",
            ));
        }
        parsed.push(alternative);
    }
    Ok(parsed)
}

fn security_alternative_has_carrier_conflict(alternative: &OpenApiSecurityAlternative) -> bool {
    let mut carriers = std::collections::BTreeSet::new();
    alternative
        .requirements
        .iter()
        .filter_map(security_carrier)
        .any(|carrier| !carriers.insert(carrier))
}

fn security_carrier(requirement: &OpenApiSecurityRequirement) -> Option<String> {
    match &requirement.scheme {
        OpenApiSecurityScheme::ApiKey { name, location } => Some(match location {
            OpenApiParameterLocation::Header => format!("header:{}", name.to_ascii_lowercase()),
            OpenApiParameterLocation::Query => format!("query:{name}"),
            OpenApiParameterLocation::Cookie => format!("cookie:{name}"),
            OpenApiParameterLocation::Path => return None,
        }),
        OpenApiSecurityScheme::Http { .. }
        | OpenApiSecurityScheme::OAuth2
        | OpenApiSecurityScheme::OpenIdConnect { .. } => Some("header:authorization".to_owned()),
        OpenApiSecurityScheme::MutualTls => Some("tls:client_certificate".to_owned()),
    }
}

fn parse_security_scheme(
    scheme: &Map<String, Value>,
    method: &str,
    path: &str,
) -> Result<(OpenApiSecurityScheme, Option<OpenApiOAuthFlows>), OpenApiError> {
    match string_field(scheme, "type")? {
        "apiKey" => {
            let location = match string_field(scheme, "in")? {
                "header" => OpenApiParameterLocation::Header,
                "query" => OpenApiParameterLocation::Query,
                "cookie" => OpenApiParameterLocation::Cookie,
                _ => {
                    return Err(invalid_operation(
                        method,
                        path,
                        "an API key location is invalid",
                    ));
                }
            };
            Ok((
                OpenApiSecurityScheme::ApiKey {
                    name: string_field(scheme, "name")?.to_owned(),
                    location,
                },
                None,
            ))
        }
        "http" => {
            let http_scheme = string_field(scheme, "scheme")?.to_ascii_lowercase();
            if !matches!(http_scheme.as_str(), "basic" | "bearer") {
                return Err(invalid_operation(
                    method,
                    path,
                    "the HTTP authentication scheme is not supported",
                ));
            }
            Ok((
                OpenApiSecurityScheme::Http {
                    scheme: http_scheme,
                    bearer_format: optional_string(scheme, "bearerFormat")?.map(str::to_owned),
                },
                None,
            ))
        }
        "oauth2" => Ok((
            OpenApiSecurityScheme::OAuth2,
            Some(parse_oauth_flows(object_field(scheme, "flows")?)?),
        )),
        "openIdConnect" => Ok((
            OpenApiSecurityScheme::OpenIdConnect {
                url: string_field(scheme, "openIdConnectUrl")?.to_owned(),
            },
            None,
        )),
        "mutualTLS" => Err(invalid_operation(
            method,
            path,
            "mutual TLS authentication is not supported",
        )),
        _ => Err(invalid_operation(
            method,
            path,
            "a security scheme type is unsupported",
        )),
    }
}

fn parse_oauth_flows(flows: &Map<String, Value>) -> Result<OpenApiOAuthFlows, OpenApiError> {
    Ok(OpenApiOAuthFlows {
        implicit: flows
            .get("implicit")
            .map(|flow| parse_oauth_flow(flow, true, false))
            .transpose()?,
        password: flows
            .get("password")
            .map(|flow| parse_oauth_flow(flow, false, true))
            .transpose()?,
        client_credentials: flows
            .get("clientCredentials")
            .map(|flow| parse_oauth_flow(flow, false, true))
            .transpose()?,
        authorization_code: flows
            .get("authorizationCode")
            .map(|flow| parse_oauth_flow(flow, true, true))
            .transpose()?,
    })
}

fn parse_oauth_flow(
    flow: &Value,
    needs_authorization_url: bool,
    needs_token_url: bool,
) -> Result<OpenApiOAuthFlow, OpenApiError> {
    let flow = flow.as_object().ok_or(OpenApiError::InvalidDocument(
        "an OAuth flow must be an object",
    ))?;
    let authorization_url = optional_string(flow, "authorizationUrl")?.map(str::to_owned);
    let token_url = optional_string(flow, "tokenUrl")?.map(str::to_owned);
    if needs_authorization_url && authorization_url.is_none() {
        return Err(OpenApiError::InvalidDocument(
            "an OAuth flow is missing authorizationUrl",
        ));
    }
    if needs_token_url && token_url.is_none() {
        return Err(OpenApiError::InvalidDocument(
            "an OAuth flow is missing tokenUrl",
        ));
    }
    let scopes = object_field(flow, "scopes")?
        .iter()
        .map(|(scope, description)| {
            description
                .as_str()
                .map(|description| (scope.clone(), description.to_owned()))
                .ok_or(OpenApiError::InvalidDocument(
                    "an OAuth scope description must be a string",
                ))
        })
        .collect::<Result<_, _>>()?;
    Ok(OpenApiOAuthFlow {
        authorization_url,
        token_url,
        refresh_url: optional_string(flow, "refreshUrl")?.map(str::to_owned),
        scopes,
    })
}

fn build_input_schema(
    parameters: &[ParsedParameter],
    body: Option<&ParsedRequestBody>,
    dialect: OpenApiSchemaDialect,
) -> Result<Value, OpenApiError> {
    let mut root_properties = Map::new();
    let mut root_required = Vec::new();
    let mut media_branches = None;
    for location in [
        OpenApiParameterLocation::Path,
        OpenApiParameterLocation::Query,
        OpenApiParameterLocation::Header,
        OpenApiParameterLocation::Cookie,
    ] {
        let matching = parameters
            .iter()
            .filter(|parameter| parameter.binding.location == location)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        let mut properties = Map::new();
        let mut required = Vec::new();
        for parameter in matching {
            properties.insert(
                parameter.binding.name.clone(),
                normalized_input_schema(&parameter.schema, dialect)?,
            );
            if parameter.binding.required {
                required.push(Value::String(parameter.binding.name.clone()));
            }
        }
        let mut schema = Map::from_iter([
            ("type".to_owned(), Value::String("object".to_owned())),
            ("properties".to_owned(), Value::Object(properties)),
            ("additionalProperties".to_owned(), Value::Bool(false)),
        ]);
        if !required.is_empty() {
            schema.insert("required".to_owned(), Value::Array(required));
            root_required.push(Value::String(location.input_key().to_owned()));
        }
        root_properties.insert(location.input_key().to_owned(), Value::Object(schema));
    }
    if let Some(body) = body {
        let normalized_schemas = body
            .schemas
            .iter()
            .map(|schema| normalized_input_schema(schema, dialect))
            .collect::<Result<Vec<_>, _>>()?;
        let schema = if normalized_schemas.len() == 1 {
            normalized_schemas[0].clone()
        } else {
            media_branches = Some(
                body.binding
                    .media_types
                    .iter()
                    .zip(&normalized_schemas)
                    .map(|(media_type, schema)| {
                        let mut required = Vec::new();
                        if body.binding.required {
                            required.push(Value::String("body".to_owned()));
                        }
                        if media_type != &body.binding.default_media_type {
                            required.push(Value::String("contentType".to_owned()));
                        }
                        let mut branch = Map::from_iter([
                            ("type".to_owned(), Value::String("object".to_owned())),
                            (
                                "properties".to_owned(),
                                json!({
                                    "body": schema,
                                    "contentType": { "const": media_type }
                                }),
                            ),
                        ]);
                        if !required.is_empty() {
                            branch.insert("required".to_owned(), Value::Array(required));
                        }
                        Value::Object(branch)
                    })
                    .collect::<Vec<_>>(),
            );
            Value::Bool(true)
        };
        root_properties.insert("body".to_owned(), schema);
        root_properties.insert(
            "contentType".to_owned(),
            json!({
                "type": "string",
                "enum": body.binding.media_types,
                "default": body.binding.default_media_type
            }),
        );
        if body.binding.required {
            root_required.push(Value::String("body".to_owned()));
        }
    }
    let mut schema = Map::from_iter([
        (
            "$schema".to_owned(),
            Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
        ),
        ("type".to_owned(), Value::String("object".to_owned())),
        ("properties".to_owned(), Value::Object(root_properties)),
        ("additionalProperties".to_owned(), Value::Bool(false)),
    ]);
    if !root_required.is_empty() {
        schema.insert("required".to_owned(), Value::Array(root_required));
    }
    if let Some(media_branches) = media_branches {
        schema.insert("oneOf".to_owned(), Value::Array(media_branches));
    }
    Ok(Value::Object(schema))
}

fn normalized_input_schema(
    schema: &Value,
    dialect: OpenApiSchemaDialect,
) -> Result<Value, OpenApiError> {
    let mut schema = schema.clone();
    validate_schema_dialect_declarations(&schema, dialect)?;
    normalize_request_schema(&mut schema);
    if matches!(dialect, OpenApiSchemaDialect::OpenApi30) {
        normalize_openapi30_schema(&mut schema);
    }
    Ok(schema)
}

fn validate_schema_dialect_declarations(
    value: &Value,
    dialect: OpenApiSchemaDialect,
) -> Result<(), OpenApiError> {
    let Value::Object(schema) = value else {
        return Ok(());
    };
    if let Some(declared) = schema.get("$schema") {
        let declared = declared.as_str().ok_or(OpenApiError::InvalidDocument(
            "a Schema Object $schema declaration must be a URI string",
        ))?;
        let declared = declared.strip_suffix('#').unwrap_or(declared);
        if matches!(dialect, OpenApiSchemaDialect::OpenApi30)
            || !matches!(declared, OAS31_BASE_DIALECT | JSON_SCHEMA_2020_12_DIALECT)
        {
            return Err(OpenApiError::InvalidDocument(
                "a Schema Object uses an unsupported JSON Schema dialect",
            ));
        }
    }
    for keyword in [
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    ] {
        if let Some(child) = schema.get(keyword) {
            validate_schema_dialect_declarations(child, dialect)?;
        }
    }
    for keyword in [
        "$defs",
        "definitions",
        "dependentSchemas",
        "patternProperties",
        "properties",
    ] {
        if let Some(children) = schema.get(keyword).and_then(Value::as_object) {
            for child in children.values() {
                validate_schema_dialect_declarations(child, dialect)?;
            }
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = schema.get(keyword).and_then(Value::as_array) {
            for child in children {
                validate_schema_dialect_declarations(child, dialect)?;
            }
        }
    }
    Ok(())
}

fn normalize_request_schema(value: &mut Value) {
    let Value::Object(schema) = value else {
        return;
    };
    for keyword in [
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    ] {
        if let Some(child) = schema.get_mut(keyword) {
            normalize_request_schema(child);
        }
    }
    for keyword in [
        "$defs",
        "definitions",
        "dependentSchemas",
        "patternProperties",
        "properties",
    ] {
        if let Some(children) = schema.get_mut(keyword).and_then(Value::as_object_mut) {
            children.values_mut().for_each(normalize_request_schema);
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = schema.get_mut(keyword).and_then(Value::as_array_mut) {
            children.iter_mut().for_each(normalize_request_schema);
        }
    }
    let read_only = schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| {
            properties
                .iter()
                .filter(|(_, property)| property.get("readOnly") == Some(&Value::Bool(true)))
                .map(|(name, _)| name.clone())
                .collect::<std::collections::HashSet<_>>()
        })
        .unwrap_or_default();
    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|name| name.as_str().is_none_or(|name| !read_only.contains(name)));
    }
}

fn normalize_openapi30_schema(value: &mut Value) {
    let Value::Object(schema) = value else {
        return;
    };
    for keyword in [
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    ] {
        if let Some(child) = schema.get_mut(keyword) {
            normalize_openapi30_schema(child);
        }
    }
    for keyword in [
        "$defs",
        "definitions",
        "dependentSchemas",
        "patternProperties",
        "properties",
    ] {
        if let Some(children) = schema.get_mut(keyword).and_then(Value::as_object_mut) {
            children.values_mut().for_each(normalize_openapi30_schema);
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(children) = schema.get_mut(keyword).and_then(Value::as_array_mut) {
            children.iter_mut().for_each(normalize_openapi30_schema);
        }
    }
    normalize_openapi30_exclusive_bound(schema, "minimum", "exclusiveMinimum");
    normalize_openapi30_exclusive_bound(schema, "maximum", "exclusiveMaximum");
    if schema.remove("nullable") == Some(Value::Bool(true)) {
        match schema.remove("type") {
            Some(Value::String(schema_type)) => {
                schema.insert(
                    "type".to_owned(),
                    Value::Array(vec![
                        Value::String(schema_type),
                        Value::String("null".to_owned()),
                    ]),
                );
            }
            Some(Value::Array(mut schema_types)) => {
                if !schema_types.iter().any(|schema_type| schema_type == "null") {
                    schema_types.push(Value::String("null".to_owned()));
                }
                schema.insert("type".to_owned(), Value::Array(schema_types));
            }
            Some(schema_type) => {
                schema.insert("type".to_owned(), schema_type);
            }
            None => {}
        }
    }
}

fn normalize_openapi30_exclusive_bound(
    schema: &mut Map<String, Value>,
    inclusive_name: &str,
    exclusive_name: &str,
) {
    match schema.remove(exclusive_name) {
        Some(Value::Bool(true)) => {
            if let Some(bound) = schema.remove(inclusive_name) {
                schema.insert(exclusive_name.to_owned(), bound);
            }
        }
        Some(Value::Bool(false)) | None => {}
        Some(value) => {
            schema.insert(exclusive_name.to_owned(), value);
        }
    }
}

fn parse_output_schema(
    value: Option<&Value>,
    root: &Value,
    method: &str,
    path: &str,
    budget: &mut CompileBudget,
) -> Result<Option<Value>, OpenApiError> {
    let Some(responses) = value else {
        return Ok(None);
    };
    let responses = responses
        .as_object()
        .ok_or_else(|| invalid_operation(method, path, "responses must be an object"))?;
    let response = responses
        .iter()
        .filter(|(status, _)| {
            status.len() == 3
                && status.starts_with('2')
                && status[1..]
                    .chars()
                    .all(|character| character.is_ascii_digit())
        })
        .min_by_key(|(status, _)| *status)
        .map(|(_, response)| response)
        .or_else(|| responses.get("2XX"))
        .or_else(|| responses.get("default"));
    let Some(response) = response else {
        return Ok(None);
    };
    let mut stack = Vec::new();
    let response = resolve_value(response, root, &mut stack, 0, budget)?;
    let content = response
        .as_object()
        .and_then(|response| response.get("content"))
        .and_then(Value::as_object);
    Ok(content
        .and_then(select_media)
        .and_then(|(_, media)| media.get("schema"))
        .cloned())
}

fn stable_key(method: &str, path: &str) -> String {
    let digest = Sha256::digest(format!("{}\n{path}", method.to_ascii_uppercase()));
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("openapi:v1:{digest}")
}

fn fallback_name(method: &str, path: &str) -> String {
    let mut name = method.to_owned();
    for segment in path.split('/') {
        let segment = segment.trim_matches(['{', '}']);
        if !segment.is_empty() {
            name.push('_');
            name.push_str(segment);
        }
    }
    name
}

fn intrinsic_mode(method: &str) -> ToolMode {
    match method {
        "get" | "head" | "options" => ToolMode::Enabled,
        "post" | "put" | "patch" | "delete" => ToolMode::Ask,
        _ => ToolMode::Disabled,
    }
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Map<String, Value>, OpenApiError> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or(OpenApiError::InvalidDocument(
            "a required object field is missing",
        ))
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, OpenApiError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(OpenApiError::InvalidDocument(
            "a required string field is missing",
        ))
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, OpenApiError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(OpenApiError::InvalidDocument(
            "an optional string field is invalid",
        )),
    }
}

fn invalid_operation(method: &str, path: &str, message: &'static str) -> OpenApiError {
    OpenApiError::InvalidOperation {
        method: method.to_ascii_uppercase(),
        path: path.to_owned(),
        message,
    }
}

fn limit(code: &'static str) -> OpenApiError {
    OpenApiError::LimitExceeded { code }
}

#[cfg(test)]
mod tests {
    use super::{percent_decode, stable_key};

    #[test]
    fn percent_decoding_handles_local_pointer_fragments() {
        assert_eq!(percent_decode("/a%20b"), Some("/a b".to_owned()));
        assert_eq!(percent_decode("/%GG"), None);
    }

    #[test]
    fn stable_keys_are_case_normalized_and_path_sensitive() {
        assert_eq!(stable_key("get", "/pets"), stable_key("GET", "/pets"));
        assert_ne!(stable_key("get", "/pets"), stable_key("get", "/pets/"));
    }
}
