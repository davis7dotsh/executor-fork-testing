use std::collections::BTreeMap;

use executor::{
    AppConfig, ExecutorApp,
    catalog::{
        ArtifactKind, AuditContext, CatalogError, CreateSource, CredentialPayload,
        InitialCatalogSnapshot, SourceKind, StagedArtifact, StagedTool, StagedToolBinding,
        ToolBinding, ToolMode,
    },
    openapi::{OpenApiBinding, OpenApiSecurityAlternative},
};
use serde_json::{Map, json};

fn source_input() -> CreateSource {
    CreateSource {
        kind: SourceKind::Openapi,
        preferred_slug: "Weather API".to_owned(),
        display_name: "Weather API".to_owned(),
        description: Some("Forecast operations".to_owned()),
        configuration: Map::from_iter([(
            "displayUrl".to_owned(),
            json!("https://weather.example.test/openapi.json"),
        )]),
    }
}

fn credential() -> CredentialPayload {
    CredentialPayload {
        schema_version: 1,
        payload: json!({
            "schemes": {
                "weatherKey": {
                    "type": "api_key",
                    "value": "atomic-secret"
                }
            }
        }),
    }
}

fn snapshot() -> InitialCatalogSnapshot {
    InitialCatalogSnapshot {
        artifacts: vec![StagedArtifact {
            kind: ArtifactKind::OpenapiDocument,
            stable_key: "document".to_owned(),
            content: json!({ "openapi": "3.1.0" }),
        }],
        tools: vec![StagedTool {
            stable_key: "get:/weather".to_owned(),
            preferred_name: "getWeather".to_owned(),
            display_name: "Get weather".to_owned(),
            description: Some("Read a forecast".to_owned()),
            input_schema: json!({ "type": "object" }),
            output_schema: Some(json!({ "type": "object" })),
            input_typescript: None,
            output_typescript: None,
            typescript_definitions: BTreeMap::new(),
            intrinsic_mode: ToolMode::Enabled,
        }],
    }
}

fn bindings() -> Vec<StagedToolBinding> {
    vec![StagedToolBinding {
        stable_key: "get:/weather".to_owned(),
        binding: ToolBinding::OpenapiV1(OpenApiBinding {
            version: 1,
            method: "GET".to_owned(),
            path_template: "/weather".to_owned(),
            server_url: "https://weather.example.test".to_owned(),
            parameters: Vec::new(),
            request_body: None,
            security: vec![OpenApiSecurityAlternative {
                requirements: Vec::new(),
            }],
        }),
    }]
}

async fn row_count(app: &ExecutorApp, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(app.pool())
        .await
        .expect("row count should read")
}

#[tokio::test]
async fn imported_source_creation_commits_every_catalog_record_or_nothing() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    sqlx::query(
        "CREATE TRIGGER reject_atomic_binding BEFORE INSERT ON tool_bindings \
         BEGIN SELECT RAISE(ABORT, 'reject atomic binding'); END",
    )
    .execute(app.pool())
    .await
    .expect("failure trigger should install");

    app.catalog()
        .create_source_with_catalog(
            source_input(),
            &credential(),
            snapshot(),
            bindings(),
            AuditContext::system(Some("atomic-failure")),
        )
        .await
        .expect_err("a binding write failure should abort creation");

    for table in [
        "sources",
        "source_credentials",
        "source_artifacts",
        "tools",
        "tool_bindings",
        "tool_search",
        "tool_search_trigram",
        "tool_search_short",
        "audit_events",
    ] {
        assert_eq!(row_count(&app, table).await, 0, "{table} must roll back");
    }
    assert_eq!(app.catalog().global_revision().await.unwrap(), 0);

    sqlx::query("DROP TRIGGER reject_atomic_binding")
        .execute(app.pool())
        .await
        .expect("failure trigger should drop");
    let (source, sync) = app
        .catalog()
        .create_source_with_catalog(
            source_input(),
            &credential(),
            snapshot(),
            bindings(),
            AuditContext::system(Some("atomic-success")),
        )
        .await
        .expect("atomic creation should succeed");

    assert_eq!(source.slug, "weather_api");
    assert_eq!(source.revision, 1);
    assert_eq!(source.catalog_revision, 1);
    assert_eq!(source.tool_count, 1);
    assert_eq!(sync.source_id, source.id);
    assert_eq!(sync.global_revision, 1);
    assert_eq!(sync.active_tool_count, 1);
    assert_eq!(
        app.catalog()
            .credential(&source.id)
            .await
            .expect("credential should read")
            .expect("credential should exist")
            .credential
            .payload["schemes"]["weatherKey"]["value"],
        "atomic-secret"
    );
    assert_eq!(row_count(&app, "source_artifacts").await, 1);
    assert_eq!(row_count(&app, "tool_bindings").await, 1);
    assert_eq!(row_count(&app, "tool_search").await, 1);
    assert_eq!(row_count(&app, "tool_search_trigram").await, 1);
    assert_eq!(row_count(&app, "tool_search_short").await, 1);
    assert_eq!(row_count(&app, "audit_events").await, 3);
}

#[tokio::test]
async fn malformed_input_schema_is_rejected_before_atomic_creation_writes() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let mut invalid_snapshot = snapshot();
    invalid_snapshot.tools[0].input_schema = json!({ "type": "not-a-json-schema-type" });

    let error = app
        .catalog()
        .create_source_with_catalog(
            source_input(),
            &credential(),
            invalid_snapshot,
            bindings(),
            AuditContext::system(Some("invalid-schema")),
        )
        .await
        .expect_err("invalid schema should fail before catalog creation");
    assert!(matches!(
        error,
        CatalogError::Validation {
            code: "invalid_tool_input_schema",
            ..
        }
    ));
    assert_eq!(row_count(&app, "sources").await, 0);
    assert_eq!(row_count(&app, "tools").await, 0);
    assert_eq!(app.catalog().global_revision().await.unwrap(), 0);
}
