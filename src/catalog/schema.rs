use std::error::Error;

use jsonschema::{Draft, PatternOptions, Retrieve, Uri, Validator};
use serde_json::Value;

const REGEX_SIZE_LIMIT: usize = 1024 * 1024;
const REGEX_DFA_SIZE_LIMIT: usize = 1024 * 1024;

#[derive(Debug)]
struct NoExternalSchemas;

impl Retrieve for NoExternalSchemas {
    fn retrieve(&self, uri: &Uri<String>) -> Result<Value, Box<dyn Error + Send + Sync>> {
        Err(format!("external JSON Schema reference is disabled: {uri}").into())
    }
}

pub(super) fn compile(schema: &Value) -> Result<Validator, ()> {
    jsonschema::options()
        .with_draft(Draft::Draft202012)
        .with_retriever(NoExternalSchemas)
        .with_pattern_options(
            PatternOptions::regex()
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT),
        )
        .should_validate_formats(false)
        .build(schema)
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::compile;

    #[test]
    fn validates_full_argument_constraints_and_openapi_nullable() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["name", "count", "mode", "tags", "maybe"],
            "properties": {
                "name": { "type": "string", "pattern": "^[A-Z][a-z]+$" },
                "count": { "type": "integer" },
                "mode": { "enum": ["safe", "fast"] },
                "tags": { "type": "array", "items": { "type": "string" }, "uniqueItems": true },
                "maybe": { "type": ["string", "null"] }
            }
        });
        let validator = compile(&schema).expect("schema should compile");
        assert!(validator.is_valid(&json!({
            "name": "Ada", "count": 1.0, "mode": "safe", "tags": ["a", "b"], "maybe": null
        })));
        assert!(!validator.is_valid(&json!({
            "name": "ada", "count": 1, "mode": "safe", "tags": ["a", "b"], "maybe": null
        })));
        assert!(!validator.is_valid(&json!({
            "name": "Ada", "count": 1.5, "mode": "safe", "tags": ["a", "b"], "maybe": null
        })));
        assert!(!validator.is_valid(&json!({
            "name": "Ada", "count": 1, "mode": "other", "tags": ["a", "b"], "maybe": null
        })));
        assert!(!validator.is_valid(&json!({
            "name": "Ada", "count": 1, "mode": "safe", "tags": ["a", "a"], "maybe": null
        })));
        assert!(!validator.is_valid(&json!({
            "name": "Ada", "count": 1, "mode": "safe", "tags": ["a"], "maybe": null, "extra": true
        })));
    }

    #[test]
    fn rejects_external_retrieval_and_handles_bounded_depth() {
        assert!(compile(&json!({ "$ref": "https://schemas.example.test/external.json" })).is_err());

        let mut schema = json!({ "type": "string" });
        let mut instance = json!("leaf");
        for _ in 0..64 {
            schema = json!({ "type": "array", "items": schema, "maxItems": 1 });
            instance = json!([instance]);
        }
        let validator = compile(&schema).expect("bounded imported schema depth should compile");
        assert!(validator.is_valid(&instance));
    }

    #[test]
    fn nullable_type_union_does_not_bypass_enum_constraints() {
        let without_null = compile(&json!({
            "type": ["string", "null"],
            "enum": ["allowed"]
        }))
        .expect("schema should compile");
        assert!(!without_null.is_valid(&Value::Null));

        let with_null = compile(&json!({
            "type": ["string", "null"],
            "enum": ["allowed", null]
        }))
        .expect("schema should compile");
        assert!(with_null.is_valid(&Value::Null));
    }
}
