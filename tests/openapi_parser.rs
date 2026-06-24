use executor::{
    catalog::ToolMode,
    openapi::{
        OpenApiCredential, OpenApiCredentialError, OpenApiCredentialSet, OpenApiError,
        OpenApiInvocationError, OpenApiParameterLocation, OpenApiSecurityScheme,
        build_protocol_request, build_protocol_request_with_base, compile_document,
    },
};
use serde_json::json;
use url::Url;

type StaticCredentialSet = OpenApiCredentialSet;
type StaticCredentialScheme = OpenApiCredential;

#[test]
fn compiles_yaml_with_parameter_server_media_and_security_precedence() {
    let document = br#"
openapi: 3.1.0
info:
  title: Pet Service
  description: Pet operations
servers:
  - url: https://root.example.test/{version}
    variables:
      version:
        default: v1
security:
  - rootKey: []
paths:
  /pets/{pet_id}:
    servers:
      - url: https://path.example.test
    parameters:
      - $ref: '#/components/parameters/PetId'
      - name: view
        in: query
        schema:
          type: string
    get:
      operationId: getPet
      summary: Get a pet
      servers:
        - url: https://operation.example.test
      parameters:
        - name: view
          in: query
          required: true
          schema:
            enum: [summary, full]
      security:
        - bearerAuth: []
          rootKey: []
        - {}
      responses:
        '200':
          description: ok
          content:
            application/problem+json:
              schema:
                type: object
            application/json:
              schema:
                $ref: '#/components/schemas/Pet'
  /pets:
    post:
      operationId: createPet
      requestBody:
        required: true
        content:
          text/plain:
            schema: { type: string }
          application/json:
            schema:
              $ref: '#/components/schemas/PetInput'
      responses:
        default:
          description: response
components:
  parameters:
    PetId:
      name: pet_id
      in: path
      required: true
      schema: { type: string }
  schemas:
    Pet:
      type: object
      properties:
        id: { type: string }
    PetInput:
      type: object
      properties:
        name: { type: string }
      required: [name]
  securitySchemes:
    rootKey:
      type: apiKey
      in: header
      name: X-Root-Key
    bearerAuth:
      type: http
      scheme: bearer
    oauth:
      type: oauth2
      flows: {}
"#;
    let compiled = compile_document(document).expect("valid YAML should compile");
    assert_eq!(compiled.title, "Pet Service");
    assert_eq!(compiled.tools.len(), 2);

    let get = compiled
        .tools
        .iter()
        .find(|tool| tool.preferred_name == "getPet")
        .expect("GET operation should exist");
    assert_eq!(get.intrinsic_mode, ToolMode::Enabled);
    assert_eq!(get.binding.server_url, "https://operation.example.test");
    assert_eq!(get.binding.parameters.len(), 2);
    let view = get
        .binding
        .parameters
        .iter()
        .find(|parameter| parameter.name == "view")
        .expect("operation query parameter should replace the path parameter");
    assert!(view.required);
    assert_eq!(view.location, OpenApiParameterLocation::Query);
    assert_eq!(get.binding.security.len(), 2);
    assert_eq!(get.binding.security[0].requirements.len(), 2);
    assert!(get.binding.security[1].requirements.is_empty());
    assert!(matches!(
        get.binding.security[0].requirements[0].scheme,
        OpenApiSecurityScheme::Http { .. }
    ));
    assert_eq!(
        get.output_schema,
        Some(json!({
            "type": "object",
            "properties": { "id": { "type": "string" } }
        }))
    );

    let post = compiled
        .tools
        .iter()
        .find(|tool| tool.preferred_name == "createPet")
        .expect("POST operation should exist");
    assert_eq!(post.intrinsic_mode, ToolMode::Ask);
    let body = post
        .binding
        .request_body
        .as_ref()
        .expect("request body should compile");
    assert_eq!(body.default_media_type, "application/json");
    assert_eq!(
        body.media_types,
        vec!["application/json".to_owned(), "text/plain".to_owned()]
    );
    assert_eq!(
        post.binding.security[0].requirements[0].scheme_name,
        "rootKey"
    );
}

#[test]
fn openapi_30_input_schemas_normalize_nullable_and_exclusive_bounds_to_2020_12() {
    let compiled = compile_document(
        serde_json::to_string(&json!({
            "openapi": "3.0.3",
            "info": { "title": "OpenAPI 3.0 schema normalization", "version": "1" },
            "servers": [{ "url": "https://api.example.test" }],
            "paths": {
                "/items": {
                    "get": {
                        "operationId": "listItems",
                        "parameters": [{
                            "name": "limit",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "nullable": true,
                                "minimum": 5,
                                "exclusiveMinimum": true
                            }
                        }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }))
        .expect("specification should serialize")
        .as_bytes(),
    )
    .expect("OpenAPI 3.0 specification should compile");
    let schema = &compiled.tools[0].input_schema;
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    let limit = &schema["properties"]["query"]["properties"]["limit"];
    let types = limit["type"]
        .as_array()
        .expect("nullable schema should become a type union");
    assert_eq!(types, &[json!("integer"), json!("null")]);
    assert_eq!(limit["exclusiveMinimum"], 5);
    assert!(limit.get("minimum").is_none());
}

#[test]
fn openapi_30_rejects_reference_siblings_instead_of_overriding_constraints() {
    let error = compile_document(
        serde_json::to_string(&json!({
            "openapi": "3.0.3",
            "info": { "title": "Reference sibling", "version": "1" },
            "paths": {
                "/items": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/Input",
                                        "additionalProperties": true
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Input": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": { "name": { "type": "string" } }
                    }
                }
            }
        }))
        .expect("specification should serialize")
        .as_bytes(),
    )
    .expect_err("OpenAPI 3.0 reference siblings should be rejected");
    assert!(matches!(error, OpenApiError::InvalidDocument(_)));
}

#[test]
fn request_projection_does_not_require_read_only_properties() {
    let compiled = compile_document(
        serde_json::to_string(&json!({
            "openapi": "3.1.0",
            "info": { "title": "Read-only request projection", "version": "1" },
            "paths": {
                "/items": {
                    "post": {
                        "operationId": "createItem",
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["id", "name"],
                                        "properties": {
                                            "id": { "type": "string", "readOnly": true },
                                            "name": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        }))
        .expect("specification should serialize")
        .as_bytes(),
    )
    .expect("OpenAPI specification should compile");
    assert_eq!(
        compiled.tools[0].input_schema["properties"]["body"]["required"],
        json!(["name"])
    );
}

#[test]
fn openapi_31_accepts_only_implemented_json_schema_dialects() {
    let make_document = |dialect: Option<&str>| {
        let mut document = json!({
            "openapi": "3.1.0",
            "info": { "title": "Dialect", "version": "1" },
            "paths": {
                "/items": {
                    "get": {
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        });
        if let Some(dialect) = dialect {
            document["jsonSchemaDialect"] = json!(dialect);
        }
        document
    };

    for dialect in [
        None,
        Some("https://spec.openapis.org/oas/3.1/dialect/base"),
        Some("https://json-schema.org/draft/2020-12/schema"),
        Some("https://json-schema.org/draft/2020-12/schema#"),
    ] {
        let document = make_document(dialect);
        compile_document(&serde_json::to_vec(&document).unwrap_or_default()).unwrap_or_else(
            |error| panic!("supported dialect {dialect:?} should compile: {error}"),
        );
    }

    for dialect in [
        "https://example.test/custom-dialect",
        "https://json-schema.org/draft/2019-09/schema",
    ] {
        let document = make_document(Some(dialect));
        assert!(matches!(
            compile_document(&serde_json::to_vec(&document).unwrap_or_default()),
            Err(OpenApiError::InvalidDocument(
                "the OpenAPI 3.1 JSON Schema dialect is not supported"
            ))
        ));
    }

    let mut non_string = make_document(None);
    non_string["jsonSchemaDialect"] = json!({ "uri": "not a string" });
    assert!(matches!(
        compile_document(&serde_json::to_vec(&non_string).unwrap_or_default()),
        Err(OpenApiError::InvalidDocument(
            "jsonSchemaDialect must be a URI string"
        ))
    ));

    let mut schema_override = make_document(None);
    schema_override["paths"]["/items"]["get"]["parameters"] = json!([{
        "name": "query",
        "in": "query",
        "schema": {
            "$schema": "https://example.test/custom-dialect",
            "type": "string",
            "x-custom-assertion": true
        }
    }]);
    assert!(matches!(
        compile_document(&serde_json::to_vec(&schema_override).unwrap_or_default()),
        Err(OpenApiError::InvalidDocument(
            "a Schema Object uses an unsupported JSON Schema dialect"
        ))
    ));

    let mut nested_override = make_document(None);
    nested_override["paths"]["/items"]["get"]["parameters"] = json!([{
        "name": "query",
        "in": "query",
        "schema": {
            "type": "array",
            "unevaluatedItems": {
                "$schema": "https://example.test/custom-dialect",
                "x-custom-assertion": true
            }
        }
    }]);
    assert!(matches!(
        compile_document(&serde_json::to_vec(&nested_override).unwrap_or_default()),
        Err(OpenApiError::InvalidDocument(
            "a Schema Object uses an unsupported JSON Schema dialect"
        ))
    ));
}

#[test]
fn local_pointer_decoding_and_ref_siblings_are_supported() {
    let document = json!({
        "openapi": "3.1.0",
        "info": { "title": "Refs" },
        "paths": {
            "/things": {
                "get": {
                    "parameters": [{
                        "name": "filter",
                        "in": "query",
                        "schema": {
                            "$ref": "#/components/schemas/Encoded%20Name",
                            "description": "override"
                        }
                    }],
                    "responses": { "204": { "description": "none" } }
                }
            }
        },
        "components": {
            "schemas": {
                "Encoded Name": { "type": "string" }
            }
        }
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        compiled.tools[0].input_schema["properties"]["query"]["properties"]["filter"],
        json!({ "type": "string", "description": "override" })
    );
}

#[test]
fn rejects_swagger_external_refs_missing_refs_and_cycles() {
    let swagger = br#"{"swagger":"2.0","info":{"title":"old"},"paths":{}}"#;
    assert!(matches!(
        compile_document(swagger),
        Err(OpenApiError::UnsupportedVersion)
    ));

    let external = br#"{
      "openapi":"3.0.3","info":{"title":"external"},
      "paths":{"/x":{"get":{"responses":{"200":{"$ref":"https://example.test/r"}}}}}
    }"#;
    assert!(matches!(
        compile_document(external),
        Err(OpenApiError::ExternalReference(_))
    ));

    let missing = br##"{
      "openapi":"3.0.3","info":{"title":"missing"},
      "paths":{"/x":{"get":{"parameters":[{"$ref":"#/components/parameters/nope"}],"responses":{}}}}
    }"##;
    assert!(matches!(
        compile_document(missing),
        Err(OpenApiError::ReferenceNotFound(_))
    ));

    let cycle = br##"{
      "openapi":"3.0.3","info":{"title":"cycle"},
      "paths":{"/x":{"get":{"parameters":[{"$ref":"#/components/parameters/a"}],"responses":{}}}},
      "components":{"parameters":{
        "a":{"$ref":"#/components/parameters/b"},
        "b":{"$ref":"#/components/parameters/a"}
      }}
    }"##;
    assert!(matches!(
        compile_document(cycle),
        Err(OpenApiError::ReferenceCycle(_))
    ));

    let duplicate_yaml = br#"
openapi: 3.0.3
info: { title: Duplicate }
paths: {}
paths: {}
"#;
    assert!(matches!(
        compile_document(duplicate_yaml),
        Err(OpenApiError::Parse)
    ));
}

#[test]
fn rejects_path_parameters_that_do_not_match_the_template() {
    let document = br#"{
      "openapi":"3.0.3","info":{"title":"paths"},
      "paths":{"/items/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}}
    }"#;
    assert!(matches!(
        compile_document(document),
        Err(OpenApiError::InvalidOperation { .. })
    ));
}

#[test]
fn stable_identity_does_not_depend_on_operation_id_and_trace_is_disabled() {
    let make = |operation_id: &str| {
        json!({
            "openapi": "3.0.3",
            "info": { "title": "Identity" },
            "paths": {
                "/items/{id}": {
                    "parameters": [{
                        "name": "id",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "string" }
                    }],
                    "trace": {
                        "operationId": operation_id,
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }
        })
    };
    let first = compile_document(&serde_json::to_vec(&make("firstName")).unwrap()).unwrap();
    let second = compile_document(&serde_json::to_vec(&make("secondName")).unwrap()).unwrap();
    assert_eq!(first.tools[0].stable_key, second.tools[0].stable_key);
    assert_ne!(
        first.tools[0].preferred_name,
        second.tools[0].preferred_name
    );
    assert_eq!(first.tools[0].intrinsic_mode, ToolMode::Disabled);
}

#[test]
fn request_credentials_override_user_carriers() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Invoke" },
        "servers": [{ "url": "https://api.example.test/v1" }],
        "components": { "securitySchemes": {
            "key": { "type": "apiKey", "in": "query", "name": "api_key" },
            "bearer": { "type": "http", "scheme": "bearer" }
        }},
        "paths": { "/items/{id}": { "post": {
            "parameters": [
                { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                { "name": "api_key", "in": "query", "schema": { "type": "string" } },
                { "name": "Api_Key", "in": "query", "schema": { "type": "string" } },
                { "name": "tags", "in": "query", "explode": true, "schema": { "type": "array" } },
                { "name": "X-Trace", "in": "header", "schema": { "type": "string" } }
            ],
            "security": [{ "key": [], "bearer": [] }],
            "requestBody": { "required": true, "content": {
                "application/json": { "schema": { "type": "object" } }
            }},
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    let credentials = StaticCredentialSet {
        schemes: [
            (
                "key".to_owned(),
                StaticCredentialScheme::ApiKey {
                    value: "secret-key".to_owned(),
                },
            ),
            (
                "bearer".to_owned(),
                StaticCredentialScheme::Bearer {
                    token: "secret-token".to_owned(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    let request = build_protocol_request(
        &compiled.tools[0].binding,
        &json!({
            "path": { "id": "a/b" },
            "query": { "api_key": "attacker", "Api_Key": "case-sensitive", "tags": ["one", "two"] },
            "headers": { "X-Trace": "trace-1" },
            "body": { "name": "item" }
        }),
        &credentials,
    )
    .unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.url.path(), "/v1/items/a%2Fb");
    let query = request.url.query_pairs().collect::<Vec<_>>();
    assert_eq!(
        query
            .iter()
            .filter(|(name, _)| name == "api_key")
            .map(|(_, value)| value.as_ref())
            .collect::<Vec<_>>(),
        vec!["secret-key"]
    );
    assert_eq!(
        query
            .iter()
            .filter(|(name, _)| name == "Api_Key")
            .map(|(_, value)| value.as_ref())
            .collect::<Vec<_>>(),
        vec!["case-sensitive"]
    );
    assert_eq!(
        query
            .iter()
            .filter(|(name, _)| name == "tags")
            .map(|(_, value)| value.as_ref())
            .collect::<Vec<_>>(),
        vec!["one", "two"]
    );
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer secret-token")
    );
    assert_eq!(
        request.headers.get("x-trace").map(String::as_str),
        Some("trace-1")
    );
    assert_eq!(
        request.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(request.body, br#"{"name":"item"}"#);
}

#[test]
fn request_construction_rejects_protected_headers_and_crlf_credentials() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Safety" },
        "servers": [{ "url": "https://api.example.test" }],
        "components": { "securitySchemes": {
            "key": { "type": "apiKey", "in": "header", "name": "X-Api-Key" }
        }},
        "paths": { "/safe": { "get": {
            "parameters": [{ "name": "Authorization", "in": "header", "schema": { "type": "string" } }],
            "security": [{ "key": [] }],
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    let credentials = |value: &str| StaticCredentialSet {
        schemes: [(
            "key".to_owned(),
            StaticCredentialScheme::ApiKey {
                value: value.to_owned(),
            },
        )]
        .into_iter()
        .collect(),
    };
    assert!(matches!(
        build_protocol_request(
            &compiled.tools[0].binding,
            &json!({ "headers": { "Authorization": "user" } }),
            &credentials("secret")
        ),
        Err(OpenApiInvocationError::InvalidHeader(_))
    ));
    assert!(
        build_protocol_request(
            &compiled.tools[0].binding,
            &json!({}),
            &credentials("secret\r\nX-Evil: yes")
        )
        .is_err()
    );
}

#[test]
fn tiny_exponential_reference_dag_hits_the_global_resolution_budget() {
    let mut schemas = serde_json::Map::new();
    schemas.insert("Node0".to_owned(), json!({ "type": "string" }));
    for index in 1..=18 {
        let reference = format!("#/components/schemas/Node{}", index - 1);
        schemas.insert(
            format!("Node{index}"),
            json!([{ "$ref": reference }, { "$ref": reference }]),
        );
    }
    let document = json!({
        "openapi": "3.1.0",
        "info": { "title": "Expansion budget" },
        "components": { "schemas": schemas },
        "paths": { "/expand": { "get": {
            "parameters": [{
                "name": "value", "in": "query",
                "schema": { "$ref": "#/components/schemas/Node18" }
            }],
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let result = compile_document(&serde_json::to_vec(&document).unwrap());
    assert!(
        matches!(
            &result,
            Err(OpenApiError::LimitExceeded {
                code: "resolved_nodes"
            })
        ),
        "unexpected expansion result: {result:?}"
    );
}

#[test]
fn rejects_parameter_serializations_the_invoker_cannot_execute() {
    let cases = [
        ("path", "label", false),
        ("header", "form", false),
        ("query", "matrix", false),
        ("cookie", "simple", false),
        ("query", "form", true),
    ];
    for (location, style, allow_reserved) in cases {
        let path = if location == "path" {
            "/items/{value}"
        } else {
            "/items"
        };
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "Unsupported parameter" },
            "paths": { path: { "get": {
                "parameters": [{
                    "name": "value", "in": location,
                    "required": location == "path", "style": style,
                    "allowReserved": allow_reserved,
                    "schema": { "type": "string" }
                }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        assert!(matches!(
            compile_document(&serde_json::to_vec(&document).unwrap()),
            Err(OpenApiError::InvalidOperation { .. })
        ));
    }
}

#[test]
fn rejects_content_based_parameters_the_invoker_cannot_serialize() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Content parameter" },
        "paths": { "/items": { "get": {
            "parameters": [{
                "name": "filter",
                "in": "query",
                "content": {
                    "application/json": {
                        "schema": { "type": "object" }
                    }
                }
            }],
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    assert!(matches!(
        compile_document(&serde_json::to_vec(&document).unwrap()),
        Err(OpenApiError::InvalidOperation { .. })
    ));
}

#[test]
fn rejects_request_body_media_the_invoker_cannot_encode() {
    for media_type in ["multipart/form-data", "application/octet-stream"] {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "Unsupported body" },
            "paths": { "/upload": { "post": {
                "requestBody": { "content": {
                    media_type: { "schema": { "type": "object" } }
                }},
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        assert!(matches!(
            compile_document(&serde_json::to_vec(&document).unwrap()),
            Err(OpenApiError::InvalidOperation { .. })
        ));
    }
}

#[test]
fn request_body_schemas_match_the_production_encoders() {
    let cases = [
        ("text/plain", json!({ "type": "object", "properties": {} })),
        (
            "application/x-www-form-urlencoded",
            json!({
                "type": "object",
                "properties": { "tags": { "type": "array" } },
                "additionalProperties": false
            }),
        ),
        (
            "application/x-www-form-urlencoded",
            json!({ "type": "object", "additionalProperties": true }),
        ),
        (
            "application/x-www-form-urlencoded",
            json!({
                "type": "object",
                "properties": { "name": { "type": "string" } }
            }),
        ),
    ];
    for (media_type, schema) in cases {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "Body schema" },
            "paths": { "/submit": { "post": {
                "requestBody": { "content": { media_type: { "schema": schema } } },
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        assert!(matches!(
            compile_document(&serde_json::to_vec(&document).unwrap()),
            Err(OpenApiError::InvalidOperation { .. })
        ));
    }

    let valid_form = json!({
        "openapi": "3.0.3",
        "info": { "title": "Form body" },
        "servers": [{ "url": "https://api.example.test" }],
        "paths": { "/submit": { "post": {
            "requestBody": { "content": {
                "application/x-www-form-urlencoded": { "schema": {
                    "type": "object",
                    "properties": { "name": { "type": "string" } },
                    "additionalProperties": false
                }}
            }},
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&valid_form).unwrap()).unwrap();
    assert!(matches!(
        build_protocol_request(
            &compiled.tools[0].binding,
            &json!({ "body": { "name": { "nested": true } } }),
            &StaticCredentialSet::default()
        ),
        Err(OpenApiInvocationError::InvalidArgument(_))
    ));
}

#[test]
fn parameterized_json_is_preferred_over_text_request_media() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Media preference" },
        "paths": { "/submit": { "post": {
            "requestBody": { "content": {
                "text/plain": { "schema": { "type": "string" } },
                "application/json; charset=utf-8": { "schema": { "type": "object" } }
            }},
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(
        compiled.tools[0]
            .binding
            .request_body
            .as_ref()
            .map(|body| body.default_media_type.as_str()),
        Some("application/json; charset=utf-8")
    );
}

#[test]
fn rejects_server_urls_with_plaintext_secret_or_ambient_components() {
    for server_url in [
        "https://user:password@api.example.test/v1",
        "https://api.example.test/v1?api_key=secret",
        "https://api.example.test/v1#fragment",
        "ftp://api.example.test/v1",
        "//user:password@api.example.test/v1",
    ] {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "Unsafe server" },
            "servers": [{ "url": server_url }],
            "paths": { "/items": { "get": {
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        assert!(matches!(
            compile_document(&serde_json::to_vec(&document).unwrap()),
            Err(OpenApiError::InvalidOperation { .. })
        ));
    }

    for server_url in ["https://api.example.test/v1", "/relative/v1"] {
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "Safe server" },
            "servers": [{ "url": server_url }],
            "paths": { "/items": { "get": {
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        assert!(compile_document(&serde_json::to_vec(&document).unwrap()).is_ok());
    }

    let hidden_in_fallback = json!({
        "openapi": "3.0.3",
        "info": { "title": "Unsafe fallback" },
        "servers": [
            { "url": "https://api.example.test" },
            { "url": "https://api.example.test?secret=value" }
        ],
        "paths": {}
    });
    assert!(matches!(
        compile_document(&serde_json::to_vec(&hidden_in_fallback).unwrap()),
        Err(OpenApiError::InvalidOperation { .. })
    ));
}

#[test]
fn rejects_and_security_requirements_that_overwrite_the_same_carrier() {
    let document = |security: serde_json::Value| {
        json!({
            "openapi": "3.0.3",
            "info": { "title": "Carrier conflict" },
            "servers": [{ "url": "https://api.example.test" }],
            "components": { "securitySchemes": {
                "basic": { "type": "http", "scheme": "basic" },
                "bearer": { "type": "http", "scheme": "bearer" }
            }},
            "paths": { "/items": { "get": {
                "security": security,
                "responses": { "200": { "description": "ok" } }
            }}}
        })
    };
    let conflicting = document(json!([{ "basic": [], "bearer": [] }]));
    assert!(matches!(
        compile_document(&serde_json::to_vec(&conflicting).unwrap()),
        Err(OpenApiError::InvalidOperation { .. })
    ));

    let alternatives = document(json!([{ "basic": [] }, { "bearer": [] }]));
    let compiled = compile_document(&serde_json::to_vec(&alternatives).unwrap()).unwrap();
    let mut binding = compiled.tools[0].binding.clone();
    let bearer = binding.security[1].requirements[0].clone();
    binding.security[0].requirements.push(bearer);
    binding.security.truncate(1);
    let credentials = StaticCredentialSet {
        schemes: [
            (
                "basic".to_owned(),
                StaticCredentialScheme::Basic {
                    username: "user".to_owned(),
                    password: "password".to_owned(),
                },
            ),
            (
                "bearer".to_owned(),
                StaticCredentialScheme::Bearer {
                    token: "token".to_owned(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    assert!(matches!(
        build_protocol_request(&binding, &json!({}), &credentials),
        Err(OpenApiInvocationError::UnsatisfiedSecurity)
    ));
}

#[test]
fn public_request_builder_rejects_cookie_name_injection() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Cookie safety" },
        "servers": [{ "url": "https://api.example.test" }],
        "components": { "securitySchemes": {
            "cookie": { "type": "apiKey", "in": "cookie", "name": "session\r\nX-Evil" }
        }},
        "paths": { "/items": { "get": {
            "parameters": [{
                "name": "user;admin=true", "in": "cookie", "schema": { "type": "string" }
            }],
            "security": [{ "cookie": [] }],
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    let credentials = StaticCredentialSet {
        schemes: [(
            "cookie".to_owned(),
            StaticCredentialScheme::ApiKey {
                value: "secret".to_owned(),
            },
        )]
        .into_iter()
        .collect(),
    };
    assert!(matches!(
        build_protocol_request(
            &compiled.tools[0].binding,
            &json!({ "cookies": { "user;admin=true": "yes" } }),
            &credentials
        ),
        Err(OpenApiInvocationError::InvalidHeader(_))
    ));

    let without_parameter = json!({
        "openapi": "3.0.3",
        "info": { "title": "Credential cookie safety" },
        "servers": [{ "url": "https://api.example.test" }],
        "components": { "securitySchemes": {
            "cookie": { "type": "apiKey", "in": "cookie", "name": "session\r\nX-Evil" }
        }},
        "paths": { "/items": { "get": {
            "security": [{ "cookie": [] }],
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&without_parameter).unwrap()).unwrap();
    assert!(matches!(
        build_protocol_request(&compiled.tools[0].binding, &json!({}), &credentials),
        Err(OpenApiInvocationError::InvalidHeader(_))
    ));
}

#[test]
fn rejects_authentication_schemes_the_invoker_cannot_apply() {
    for scheme in [
        json!({ "type": "http", "scheme": "digest" }),
        json!({ "type": "mutualTLS" }),
    ] {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "Unsupported authentication" },
            "components": { "securitySchemes": { "unsupported": scheme } },
            "paths": { "/items": { "get": {
                "security": [{ "unsupported": [] }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        assert!(matches!(
            compile_document(&serde_json::to_vec(&document).unwrap()),
            Err(OpenApiError::InvalidOperation { .. })
        ));
    }
}

#[test]
fn public_request_builder_rejects_unknown_argument_members() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Strict arguments" },
        "servers": [{ "url": "https://api.example.test" }],
        "paths": { "/items": { "get": {
            "parameters": [{
                "name": "known", "in": "query", "schema": { "type": "string" }
            }],
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    for arguments in [
        json!({ "unknown": true }),
        json!({ "query": { "unknown": "value" } }),
        json!({ "query": "not-an-object" }),
        json!({ "body": { "unexpected": true } }),
        json!({ "contentType": "application/json" }),
    ] {
        assert!(matches!(
            build_protocol_request(
                &compiled.tools[0].binding,
                &arguments,
                &StaticCredentialSet::default()
            ),
            Err(OpenApiInvocationError::InvalidArgument(_))
        ));
    }
}

#[test]
fn public_request_builder_rejects_identity_and_rewrite_headers() {
    let names = [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "X-Original-Method",
        "X-Real-IP",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Original-Host",
        "X-Forwarded-Custom",
    ];
    let parameters = names
        .iter()
        .map(|name| json!({ "name": name, "in": "header", "schema": { "type": "string" } }))
        .collect::<Vec<_>>();
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Protected headers" },
        "servers": [{ "url": "https://api.example.test" }],
        "paths": { "/items": { "post": {
            "parameters": parameters,
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    for name in names {
        assert!(matches!(
            build_protocol_request(
                &compiled.tools[0].binding,
                &json!({ "headers": { (name): "spoofed" } }),
                &StaticCredentialSet::default()
            ),
            Err(OpenApiInvocationError::InvalidHeader(_))
        ));
    }
}

#[test]
fn canonical_credentials_validate_and_round_trip_every_supported_type() {
    assert_eq!(
        serde_json::from_value::<OpenApiCredentialSet>(json!({})).unwrap(),
        OpenApiCredentialSet::default()
    );
    let credentials: OpenApiCredentialSet = serde_json::from_value(json!({
        "schemes": {
            "headerKey": { "type": "api_key", "value": "key" },
            "bearer": { "type": "bearer", "token": "bearer-token" },
            "basic": { "type": "basic", "username": "user", "password": "password" },
            "oauth": { "type": "oauth_access_token", "access_token": "oauth-token" }
        }
    }))
    .expect("the canonical credential vocabulary should deserialize");
    credentials.validate().expect("credentials should validate");
    assert_eq!(
        credentials
            .schemes
            .values()
            .map(OpenApiCredential::credential_type)
            .collect::<Vec<_>>(),
        vec!["basic", "bearer", "api_key", "manual_oauth_access_token"]
    );
    assert_eq!(
        serde_json::to_value(&credentials).unwrap(),
        json!({
            "schemes": {
                "basic": { "type": "basic", "username": "user", "password": "password" },
                "bearer": { "type": "bearer", "token": "bearer-token" },
                "headerKey": { "type": "api_key", "value": "key" },
                "oauth": { "type": "oauth_access_token", "access_token": "oauth-token" }
            }
        })
    );

    let invalid = OpenApiCredentialSet {
        schemes: [(
            String::new(),
            OpenApiCredential::Bearer {
                token: String::new(),
            },
        )]
        .into_iter()
        .collect(),
    };
    assert_eq!(
        invalid.validate(),
        Err(OpenApiCredentialError::InvalidSchemeName)
    );
}

#[test]
fn canonical_builder_applies_api_key_basic_bearer_and_oauth_credentials() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Authentication" },
        "servers": [{ "url": "https://api.example.test" }],
        "components": { "securitySchemes": {
            "headerKey": { "type": "apiKey", "in": "header", "name": "X-Api-Key" },
            "queryKey": { "type": "apiKey", "in": "query", "name": "api_key" },
            "cookieKey": { "type": "apiKey", "in": "cookie", "name": "session" },
            "basic": { "type": "http", "scheme": "basic" },
            "bearer": { "type": "http", "scheme": "bearer" },
            "oauth": { "type": "oauth2", "flows": {} }
        }},
        "paths": {
            "/keys": { "get": {
                "security": [{ "headerKey": [], "queryKey": [], "cookieKey": [] }],
                "responses": { "200": { "description": "ok" } }
            }},
            "/basic": { "get": {
                "security": [{ "basic": [] }],
                "responses": { "200": { "description": "ok" } }
            }},
            "/bearer": { "get": {
                "security": [{ "bearer": [] }],
                "responses": { "200": { "description": "ok" } }
            }},
            "/oauth": { "get": {
                "security": [{ "oauth": [] }],
                "responses": { "200": { "description": "ok" } }
            }}
        }
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    let credentials = OpenApiCredentialSet {
        schemes: [
            (
                "headerKey",
                OpenApiCredential::ApiKey {
                    value: "header-secret".to_owned(),
                },
            ),
            (
                "queryKey",
                OpenApiCredential::ApiKey {
                    value: "query-secret".to_owned(),
                },
            ),
            (
                "cookieKey",
                OpenApiCredential::ApiKey {
                    value: "cookie-secret".to_owned(),
                },
            ),
            (
                "basic",
                OpenApiCredential::Basic {
                    username: "user".to_owned(),
                    password: "pass".to_owned(),
                },
            ),
            (
                "bearer",
                OpenApiCredential::Bearer {
                    token: "bearer-secret".to_owned(),
                },
            ),
            (
                "oauth",
                OpenApiCredential::OAuthAccessToken {
                    access_token: "oauth-secret".to_owned(),
                },
            ),
        ]
        .into_iter()
        .map(|(name, credential)| (name.to_owned(), credential))
        .collect(),
    };
    let request = |path: &str| {
        let binding = &compiled
            .tools
            .iter()
            .find(|tool| tool.binding.path_template == path)
            .unwrap()
            .binding;
        build_protocol_request(binding, &json!({}), &credentials).unwrap()
    };

    let keys = request("/keys");
    assert_eq!(
        keys.headers.get("x-api-key").map(String::as_str),
        Some("header-secret")
    );
    assert_eq!(
        keys.headers.get("cookie").map(String::as_str),
        Some("session=cookie-secret")
    );
    assert!(
        keys.url
            .query_pairs()
            .any(|pair| pair == ("api_key".into(), "query-secret".into()))
    );
    assert_eq!(
        request("/basic").headers["authorization"],
        "Basic dXNlcjpwYXNz"
    );
    assert_eq!(
        request("/bearer").headers["authorization"],
        "Bearer bearer-secret"
    );
    assert_eq!(
        request("/oauth").headers["authorization"],
        "Bearer oauth-secret"
    );
}

#[test]
fn canonical_builder_honors_or_and_anonymous_security_semantics() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Security semantics" },
        "servers": [{ "url": "https://api.example.test" }],
        "components": { "securitySchemes": {
            "first": { "type": "apiKey", "in": "header", "name": "X-First" },
            "second": { "type": "apiKey", "in": "query", "name": "second" }
        }},
        "paths": {
            "/or": { "get": { "security": [{ "first": [] }, { "second": [] }], "responses": {} } },
            "/and": { "get": { "security": [{ "first": [], "second": [] }], "responses": {} } },
            "/anonymous": { "get": { "security": [{ "first": [] }, {}], "responses": {} } }
        }
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    let second_only = OpenApiCredentialSet {
        schemes: [(
            "second".to_owned(),
            OpenApiCredential::ApiKey {
                value: "two".to_owned(),
            },
        )]
        .into_iter()
        .collect(),
    };
    let binding = |path: &str| {
        &compiled
            .tools
            .iter()
            .find(|tool| tool.binding.path_template == path)
            .unwrap()
            .binding
    };
    assert!(build_protocol_request(binding("/or"), &json!({}), &second_only).is_ok());
    assert!(matches!(
        build_protocol_request(binding("/and"), &json!({}), &second_only),
        Err(OpenApiInvocationError::UnsatisfiedSecurity)
    ));
    assert!(
        build_protocol_request(
            binding("/anonymous"),
            &json!({}),
            &OpenApiCredentialSet::default()
        )
        .is_ok()
    );
}

#[test]
fn canonical_builder_falls_through_an_unusable_or_security_alternative() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Security fallback" },
        "servers": [{ "url": "https://api.example.test" }],
        "components": { "securitySchemes": {
            "badHeader": { "type": "apiKey", "in": "header", "name": "Host" },
            "bearer": { "type": "http", "scheme": "bearer" }
        }},
        "paths": { "/items": { "get": {
            "security": [{ "badHeader": [] }, { "bearer": [] }],
            "responses": {}
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    let credentials = OpenApiCredentialSet {
        schemes: [
            (
                "badHeader".to_owned(),
                OpenApiCredential::ApiKey {
                    value: "bad".to_owned(),
                },
            ),
            (
                "bearer".to_owned(),
                OpenApiCredential::Bearer {
                    token: "good".to_owned(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    };
    let request = build_protocol_request(&compiled.tools[0].binding, &json!({}), &credentials)
        .expect("the valid second OR alternative should be selected");
    assert_eq!(request.headers["authorization"], "Bearer good");
    assert!(!request.headers.contains_key("host"));
}

#[test]
fn canonical_builder_serializes_cookie_form_explode_variants() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Cookies" },
        "servers": [{ "url": "https://api.example.test" }],
        "paths": { "/cookies": { "get": {
            "parameters": [
                { "name": "arrFalse", "in": "cookie", "explode": false, "schema": { "type": "array" } },
                { "name": "arrTrue", "in": "cookie", "explode": true, "schema": { "type": "array" } },
                { "name": "objectFalse", "in": "cookie", "explode": false, "schema": { "type": "object" } },
                { "name": "objectTrue", "in": "cookie", "explode": true, "schema": { "type": "object" } }
            ],
            "responses": {}
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    let request = build_protocol_request(
        &compiled.tools[0].binding,
        &json!({ "cookies": {
            "arrFalse": ["one", "two"],
            "arrTrue": ["one", "two"],
            "objectFalse": { "a": 1, "b": 2 },
            "objectTrue": { "a": 1, "b": 2 }
        }}),
        &OpenApiCredentialSet::default(),
    )
    .unwrap();
    assert_eq!(
        request.headers["cookie"],
        "arrFalse=one%2Ctwo; arrTrue=one&arrTrue=two; objectFalse=a%2C1%2Cb%2C2; a=1&b=2"
    );
}

#[test]
fn canonical_builder_encodes_bodies_resolves_relative_servers_and_validates_methods() {
    let document = json!({
        "openapi": "3.0.3",
        "info": { "title": "Transport" },
        "servers": [{ "url": "../v2" }],
        "paths": { "/submit": { "post": {
            "requestBody": { "content": {
                "application/json": { "schema": { "type": "object" } },
                "application/x-www-form-urlencoded": { "schema": {
                    "type": "object",
                    "properties": { "name": { "type": "string" } },
                    "additionalProperties": false
                }},
                "text/plain": { "schema": { "type": "string" } }
            }},
            "responses": {}
        }}}
    });
    let compiled = compile_document(&serde_json::to_vec(&document).unwrap()).unwrap();
    let binding = &compiled.tools[0].binding;
    let base = Url::parse("https://api.example.test/specs/openapi.json").unwrap();
    let request = build_protocol_request_with_base(
        binding,
        &json!({ "body": { "name": "Ada" } }),
        &OpenApiCredentialSet::default(),
        Some(&base),
    )
    .unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.url.as_str(), "https://api.example.test/v2/submit");
    assert_eq!(request.body, br#"{"name":"Ada"}"#);

    let form = build_protocol_request_with_base(
        binding,
        &json!({ "body": { "name": "Ada Lovelace" }, "contentType": "application/x-www-form-urlencoded" }),
        &OpenApiCredentialSet::default(),
        Some(&base),
    )
    .unwrap();
    assert_eq!(form.body, b"name=Ada+Lovelace");
    let text = build_protocol_request_with_base(
        binding,
        &json!({ "body": "hello", "contentType": "text/plain" }),
        &OpenApiCredentialSet::default(),
        Some(&base),
    )
    .unwrap();
    assert_eq!(text.body, b"hello");

    let mut invalid = binding.clone();
    invalid.method = "POST\r\nX-Rewrite: yes".to_owned();
    assert!(matches!(
        build_protocol_request_with_base(
            &invalid,
            &json!({}),
            &OpenApiCredentialSet::default(),
            Some(&base)
        ),
        Err(OpenApiInvocationError::InvalidArgument(argument)) if argument == "method"
    ));
}

#[test]
fn exact_success_response_precedes_2xx_wildcard_then_default() {
    let compile = |include_exact: bool| {
        let mut responses = serde_json::Map::from_iter([
            (
                "2XX".to_owned(),
                json!({
                    "description": "wildcard",
                    "content": { "application/json": { "schema": { "const": "wildcard" } } }
                }),
            ),
            (
                "default".to_owned(),
                json!({
                    "description": "default",
                    "content": { "application/json": { "schema": { "const": "default" } } }
                }),
            ),
        ]);
        if include_exact {
            responses.insert(
                "201".to_owned(),
                json!({
                    "description": "exact",
                    "content": { "application/json": { "schema": { "const": "exact" } } }
                }),
            );
        }
        let document = json!({
            "openapi": "3.0.3",
            "info": { "title": "Response precedence" },
            "paths": { "/items": { "post": { "responses": responses } } }
        });
        compile_document(&serde_json::to_vec(&document).unwrap()).unwrap()
    };
    assert_eq!(
        compile(false).tools[0].output_schema,
        Some(json!({ "const": "wildcard" }))
    );
    assert_eq!(
        compile(true).tools[0].output_schema,
        Some(json!({ "const": "exact" }))
    );
}
