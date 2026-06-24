use std::collections::BTreeMap;

use executor::{
    AppConfig, ExecutorApp,
    catalog::{
        ArtifactKind, AuditContext, CreateSource, CredentialPayload, InitialCatalogSnapshot,
        SourceKind, StagedArtifact, StagedTool, StagedToolBinding, ToolBinding, ToolMode,
    },
    openapi::{OpenApiBinding, OpenApiSecurityAlternative},
};
use serde_json::{Map, json};

async fn imported_source() -> (tempfile::TempDir, ExecutorApp, String, String) {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let (source, _) = app
        .catalog()
        .create_source_with_catalog(
            CreateSource {
                kind: SourceKind::Openapi,
                preferred_slug: "weather".to_owned(),
                display_name: "Weather".to_owned(),
                description: None,
                configuration: Map::from_iter([(
                    "displayUrl".to_owned(),
                    json!("https://weather.example.test/openapi.json"),
                )]),
            },
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "credentials": { "schemes": {} } }),
            },
            InitialCatalogSnapshot {
                artifacts: vec![StagedArtifact {
                    kind: ArtifactKind::OpenapiDocument,
                    stable_key: "document".to_owned(),
                    content: json!({ "openapi": "3.1.0" }),
                }],
                tools: vec![StagedTool {
                    stable_key: "get-weather".to_owned(),
                    preferred_name: "getWeather".to_owned(),
                    display_name: "Get weather".to_owned(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "additionalProperties": false,
                        "properties": { "query": { "type": "object" } }
                    }),
                    output_schema: None,
                    input_typescript: None,
                    output_typescript: None,
                    typescript_definitions: BTreeMap::new(),
                    intrinsic_mode: ToolMode::Enabled,
                }],
            },
            vec![StagedToolBinding {
                stable_key: "get-weather".to_owned(),
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
            }],
            AuditContext::system(Some("initial-import")),
        )
        .await
        .expect("source should import atomically");
    let tool = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("tool should list")
        .items
        .pop()
        .expect("tool should exist");
    (directory, app, source.id, tool.id)
}

#[tokio::test]
async fn invocation_preparation_is_one_typed_catalog_snapshot() {
    let (_directory, app, source_id, tool_id) = imported_source().await;
    let lease = app
        .catalog()
        .prepare_invocation("weather.get_weather")
        .await
        .expect("invocation should prepare");

    assert_eq!(lease.lookup().source_id, source_id);
    assert_eq!(lease.lookup().tool_id, tool_id);
    assert_eq!(lease.lookup().effective_mode, ToolMode::Enabled);
    assert!(!lease.lookup().requires_approval);
    assert_eq!(lease.revisions().source_revision, 1);
    assert_eq!(lease.revisions().catalog_revision, 1);
    assert_eq!(lease.revisions().tool_revision, 0);
    assert_eq!(lease.revisions().binding_revision, 0);
    assert_eq!(lease.revisions().credential_revision, Some(0));
    assert_eq!(lease.input_schema()["additionalProperties"], false);
    assert!(lease.arguments_are_valid(&json!({ "query": {} })));
    assert!(!lease.arguments_are_valid(&json!({ "unknown": true })));
    assert_eq!(
        lease.source_configuration()["displayUrl"],
        "https://weather.example.test/openapi.json"
    );
    assert_eq!(
        lease
            .credential()
            .expect("credential snapshot should exist")
            .credential
            .payload["credentials"]["schemes"],
        json!({})
    );
    assert_eq!(
        lease
            .binding()
            .openapi()
            .expect("binding should be OpenAPI")
            .method,
        "GET"
    );
}

#[tokio::test]
async fn invocation_lease_blocks_mutation_and_old_token_revalidation_fails_after_release() {
    let (_directory, app, _source_id, tool_id) = imported_source().await;
    let lease = app
        .catalog()
        .prepare_invocation("tools.weather.get_weather")
        .await
        .expect("invocation should prepare");
    let token = lease.revisions().clone();
    let catalog = app.catalog().clone();
    let mutation = tokio::spawn(async move {
        catalog
            .set_tool_mode(
                &tool_id,
                Some(ToolMode::Ask),
                token.tool_revision,
                AuditContext::system(Some("mode-during-invocation")),
            )
            .await
    });

    tokio::task::yield_now().await;
    assert!(!mutation.is_finished());
    let token = lease.revisions().clone();
    drop(lease);
    let changed = tokio::time::timeout(std::time::Duration::from_secs(2), mutation)
        .await
        .expect("writer should resume after lease release")
        .expect("writer task should not panic")
        .expect("mode change should succeed");
    assert_eq!(changed.effective_mode.mode, ToolMode::Ask);

    assert!(
        app.catalog()
            .revalidate_invocation(&token)
            .await
            .expect("revalidation should read")
            .is_none()
    );
    let fresh = app
        .catalog()
        .prepare_invocation("weather.get_weather")
        .await
        .expect("fresh invocation should prepare");
    assert!(fresh.lookup().requires_approval);
    assert!(fresh.revisions().tool_revision > token.tool_revision);
    assert!(fresh.revisions().source_revision > token.source_revision);
}
