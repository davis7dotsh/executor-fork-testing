use std::collections::BTreeMap;

use executor::{
    AppConfig, ExecutorApp,
    catalog::{
        ArtifactKind, AuditContext, CatalogError, CatalogSnapshot, CreateSource, CredentialPayload,
        ListToolsFilter, SourceKind, StagedArtifact, StagedTool, StagedToolBinding, ToolBinding,
        ToolMode,
    },
    openapi::{OpenApiBinding, OpenApiSecurityAlternative},
};
use serde_json::{Map, json};

async fn app() -> (tempfile::TempDir, ExecutorApp) {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    (directory, app)
}

fn staged_binding(method: &str) -> StagedToolBinding {
    StagedToolBinding {
        stable_key: "stable-get-weather".to_owned(),
        binding: ToolBinding::OpenapiV1(OpenApiBinding {
            version: 1,
            method: method.to_owned(),
            path_template: "/weather".to_owned(),
            server_url: "https://weather.example.test".to_owned(),
            parameters: Vec::new(),
            request_body: None,
            security: vec![OpenApiSecurityAlternative {
                requirements: Vec::new(),
            }],
        }),
    }
}

async fn source(app: &ExecutorApp) -> executor::catalog::SourceRecord {
    app.catalog()
        .create_source(
            CreateSource {
                kind: SourceKind::Openapi,
                preferred_slug: "weather".to_owned(),
                display_name: "Weather".to_owned(),
                description: None,
                configuration: Map::new(),
            },
            AuditContext::system(Some("test-create")),
        )
        .await
        .expect("source should be created")
}

fn snapshot(source_revision: i64, credential_revision: Option<i64>) -> CatalogSnapshot {
    CatalogSnapshot {
        expected_source_revision: source_revision,
        expected_credential_revision: credential_revision,
        artifacts: vec![StagedArtifact {
            kind: ArtifactKind::OpenapiDocument,
            stable_key: "document".to_owned(),
            content: json!({ "openapi": "3.1.0" }),
        }],
        tools: vec![StagedTool {
            stable_key: "stable-get-weather".to_owned(),
            preferred_name: "get_weather".to_owned(),
            display_name: "Get weather".to_owned(),
            description: None,
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            input_typescript: None,
            output_typescript: None,
            typescript_definitions: BTreeMap::new(),
            intrinsic_mode: ToolMode::Enabled,
        }],
    }
}

#[tokio::test]
async fn openapi_bindings_are_typed_complete_and_removed_with_the_source() {
    let (_directory, app) = app().await;
    let source = source(&app).await;
    app.catalog()
        .sync_catalog_with_bindings(
            &source.id,
            snapshot(source.revision, None),
            vec![staged_binding("GET")],
            AuditContext::system(Some("test-sync")),
        )
        .await
        .expect("catalog should sync");
    let tool = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("tools should list")
        .items
        .pop()
        .expect("tool should exist");

    let binding = app
        .catalog()
        .tool_binding(&tool.id)
        .await
        .expect("binding should read");
    assert_eq!(
        binding.binding.openapi().expect("OpenAPI binding").method,
        "GET"
    );

    let binding_before = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT revision, created_at, updated_at FROM tool_bindings WHERE tool_id = ?",
    )
    .bind(&tool.id)
    .fetch_one(app.pool())
    .await
    .expect("binding metadata should read");
    let refreshed_source = app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should read");
    app.catalog()
        .sync_catalog_with_bindings(
            &source.id,
            snapshot(refreshed_source.revision, None),
            vec![staged_binding("POST")],
            AuditContext::system(Some("test-refresh")),
        )
        .await
        .expect("catalog binding should refresh in place");
    let binding_after = sqlx::query_as::<_, (i64, i64, i64, String)>(
        "SELECT revision, created_at, updated_at, definition_json FROM tool_bindings WHERE tool_id = ?",
    )
    .bind(&tool.id)
    .fetch_one(app.pool())
    .await
    .expect("refreshed binding metadata should read");
    assert_eq!(binding_after.0, binding_before.0 + 1);
    assert_eq!(binding_after.1, binding_before.1);
    assert!(binding_after.2 >= binding_before.2);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&binding_after.3)
            .expect("binding should remain valid JSON")["method"],
        "POST"
    );

    app.catalog()
        .delete_source(&source.id, AuditContext::system(Some("test-delete")))
        .await
        .expect("source should delete");
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tool_bindings")
        .fetch_one(app.pool())
        .await
        .expect("binding count should read");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn binding_write_failure_rolls_back_the_entire_catalog_refresh() {
    let (_directory, app) = app().await;
    let source = source(&app).await;
    app.catalog()
        .sync_catalog_with_bindings(
            &source.id,
            snapshot(source.revision, None),
            vec![staged_binding("GET")],
            AuditContext::system(Some("initial-sync")),
        )
        .await
        .expect("initial catalog should sync");
    let source_before = app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should read");
    let global_revision_before = app
        .catalog()
        .global_revision()
        .await
        .expect("global revision should read");
    let tool_before = app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source.id.clone()),
            limit: 10,
            ..Default::default()
        })
        .await
        .expect("tool should list")
        .items
        .remove(0);
    let binding_before = sqlx::query_as::<_, (i64, i64, String)>(
        "SELECT revision, created_at, definition_json FROM tool_bindings WHERE tool_id = ?",
    )
    .bind(&tool_before.id)
    .fetch_one(app.pool())
    .await
    .expect("binding should read");
    let artifact_before = sqlx::query_scalar::<_, String>(
        "SELECT content_json FROM source_artifacts WHERE source_id = ?",
    )
    .bind(&source.id)
    .fetch_one(app.pool())
    .await
    .expect("artifact should read");
    sqlx::query(
        "CREATE TRIGGER reject_binding_refresh BEFORE UPDATE ON tool_bindings \
         BEGIN SELECT RAISE(ABORT, 'binding write rejected'); END",
    )
    .execute(app.pool())
    .await
    .expect("failure trigger should install");

    let mut replacement = snapshot(source_before.revision, None);
    replacement.artifacts[0].content = json!({ "openapi": "3.1.1" });
    replacement.tools[0].display_name = "Changed weather".to_owned();
    let error = app
        .catalog()
        .sync_catalog_with_bindings(
            &source.id,
            replacement,
            vec![staged_binding("POST")],
            AuditContext::system(Some("failed-refresh")),
        )
        .await
        .expect_err("binding failure should abort refresh");
    assert!(matches!(error, CatalogError::Database(_)));

    let source_after = app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should remain readable");
    assert_eq!(source_after.revision, source_before.revision);
    assert_eq!(
        source_after.catalog_revision,
        source_before.catalog_revision
    );
    assert_eq!(
        app.catalog()
            .global_revision()
            .await
            .expect("global revision should read"),
        global_revision_before
    );
    let tool_after = app
        .catalog()
        .tool(&tool_before.id)
        .await
        .expect("tool should remain readable");
    assert_eq!(tool_after.revision, tool_before.revision);
    assert_eq!(tool_after.display_name, tool_before.display_name);
    let binding_after = sqlx::query_as::<_, (i64, i64, String)>(
        "SELECT revision, created_at, definition_json FROM tool_bindings WHERE tool_id = ?",
    )
    .bind(&tool_before.id)
    .fetch_one(app.pool())
    .await
    .expect("binding should remain readable");
    assert_eq!(binding_after, binding_before);
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT content_json FROM source_artifacts WHERE source_id = ?",
        )
        .bind(&source.id)
        .fetch_one(app.pool())
        .await
        .expect("artifact should remain readable"),
        artifact_before
    );
}

#[tokio::test]
async fn credentials_delete_with_compare_and_swap_and_never_store_plaintext() {
    let (_directory, app) = app().await;
    let source = source(&app).await;
    let secret = "never-store-this-api-key";
    app.catalog()
        .put_credential(
            &source.id,
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "schemes": { "ApiKey": { "type": "api_key", "value": secret } } }),
            },
            None,
            AuditContext::system(Some("test-put-credential")),
        )
        .await
        .expect("credential should store");
    let stored = app
        .catalog()
        .credential(&source.id)
        .await
        .expect("credential should read")
        .expect("credential should exist");
    assert_eq!(
        stored.credential.payload["schemes"]["ApiKey"]["value"],
        secret
    );
    let raw = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT payload_ciphertext FROM source_credentials WHERE source_id = ?",
    )
    .bind(&source.id)
    .fetch_one(app.pool())
    .await
    .expect("ciphertext should read");
    assert!(!String::from_utf8_lossy(&raw).contains(secret));

    let conflict = app
        .catalog()
        .delete_credential(
            &source.id,
            stored.revision + 1,
            AuditContext::system(Some("test-delete-conflict")),
        )
        .await;
    assert!(matches!(
        conflict,
        Err(executor::catalog::CatalogError::RevisionConflict { .. })
    ));
    app.catalog()
        .delete_credential(
            &source.id,
            stored.revision,
            AuditContext::system(Some("test-delete-credential")),
        )
        .await
        .expect("matching revision should delete");
    assert!(
        app.catalog()
            .credential(&source.id)
            .await
            .expect("credential state should read")
            .is_none()
    );
}
