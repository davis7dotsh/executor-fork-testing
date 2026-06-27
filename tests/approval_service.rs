use std::collections::BTreeMap;

use executor::{
    AppConfig, ExecutorApp,
    actor::ToolActor,
    approval::{ApprovalDecision, ApprovalStatus},
    catalog::{
        ArtifactKind, AuditContext, CreateSource, CredentialPayload, InitialCatalogSnapshot,
        RequestSurface, SourceKind, StagedArtifact, StagedTool, StagedToolBinding, ToolBinding,
        ToolMode,
    },
    invocation::{ApprovalWaitError, ToolCall, ToolCallSubmission},
    openapi::{OpenApiBinding, OpenApiSecurityAlternative},
};
use serde_json::{Map, json};

async fn app_with_ask_tool() -> (tempfile::TempDir, ExecutorApp) {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    sqlx::query(
        "INSERT INTO api_tokens \
         (id, name, token_digest, token_prefix, token_suffix, created_at) \
         VALUES ('owner-token', 'Owner', x'010203', 'exr_test', 'test', 1)",
    )
    .execute(app.pool())
    .await
    .expect("owner token should insert");
    sqlx::query(
        "INSERT INTO admins (id, username, password_hash, created_at) \
         VALUES (1, 'admin', 'unused', 1)",
    )
    .execute(app.pool())
    .await
    .expect("admin should insert");
    app.catalog()
        .create_source_with_catalog(
            CreateSource {
                kind: SourceKind::Openapi,
                preferred_slug: "approval".to_owned(),
                display_name: "Approval source".to_owned(),
                description: None,
                configuration: Map::new(),
            },
            &CredentialPayload {
                schema_version: 1,
                payload: json!({
                    "locator": { "type": "inline" },
                    "credentials": { "schemes": {} }
                }),
            },
            InitialCatalogSnapshot {
                artifacts: vec![StagedArtifact {
                    kind: ArtifactKind::OpenapiDocument,
                    stable_key: "document".to_owned(),
                    content: json!({ "openapi": "3.1.0" }),
                }],
                tools: vec![StagedTool {
                    stable_key: "write".to_owned(),
                    preferred_name: "write".to_owned(),
                    display_name: "Write".to_owned(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["password"],
                        "properties": {
                            "password": { "type": "string", "format": "password" }
                        }
                    }),
                    output_schema: None,
                    input_typescript: None,
                    output_typescript: None,
                    typescript_definitions: BTreeMap::new(),
                    intrinsic_mode: ToolMode::Ask,
                }],
            },
            vec![StagedToolBinding {
                stable_key: "write".to_owned(),
                binding: ToolBinding::OpenapiV1(OpenApiBinding {
                    version: 1,
                    method: "POST".to_owned(),
                    path_template: "/write".to_owned(),
                    server_url: "http://127.0.0.1:9".to_owned(),
                    parameters: Vec::new(),
                    request_body: None,
                    security: vec![OpenApiSecurityAlternative {
                        requirements: Vec::new(),
                    }],
                }),
            }],
            AuditContext::system(Some("approval-test")),
        )
        .await
        .expect("ask tool should import");
    (directory, app)
}

fn call(arguments: serde_json::Value) -> ToolCall {
    call_for("execution-1", "call-1", arguments)
}

fn call_for(execution_id: &str, call_id: &str, arguments: serde_json::Value) -> ToolCall {
    ToolCall {
        request_id: uuid::Uuid::new_v4().to_string(),
        actor: ToolActor::api_token("owner-token", Some("Owner".to_owned())),
        surface: RequestSurface::Gateway,
        execution_id: execution_id.to_owned(),
        call_id: call_id.to_owned(),
        worker_generation: 0,
        path: "approval.write".to_owned(),
        arguments,
    }
}

async fn wait_for_terminal_log(app: &ExecutorApp, approval_id: &str, error_code: &str) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let (found, pending) = sqlx::query_as::<_, (i64, i64)>(
                "SELECT \
                 EXISTS(SELECT 1 FROM request_logs WHERE approval_id = ? AND error_code = ?), \
                 EXISTS(SELECT 1 FROM approval_log_outbox WHERE approval_id = ?)",
            )
            .bind(approval_id)
            .bind(error_code)
            .bind(approval_id)
            .fetch_one(app.pool())
            .await
            .expect("request log should read");
            if found != 0 && pending == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("terminal approval log {error_code} should be stored"));
}

#[tokio::test]
async fn wait_is_correlated_cancelable_and_wakes_for_a_denial_without_plaintext_storage() {
    let (directory, app) = app_with_ask_tool().await;
    let secret = "unique-approval-secret-92f781";
    let submission = app
        .tool_calls()
        .submit(call(json!({ "password": secret })))
        .await
        .expect("valid Ask call should become pending");
    let approval = match submission {
        ToolCallSubmission::ApprovalRequired(approval) => approval,
        ToolCallSubmission::Completed(_) => panic!("Ask call must not execute immediately"),
    };

    let admin = app
        .tool_calls()
        .approvals()
        .get_admin(&approval.id)
        .await
        .expect("approval should read")
        .expect("approval should exist");
    assert_eq!(admin.redacted_arguments["password"], "[redacted]");

    let canceled_submission = app
        .tool_calls()
        .submit(call_for(
            "execution-canceled-wait",
            "call-canceled-wait",
            json!({ "password": "cancel-wait-secret" }),
        ))
        .await
        .expect("cancelable Ask call should become pending");
    let canceled_approval = match canceled_submission {
        ToolCallSubmission::ApprovalRequired(approval) => approval,
        ToolCallSubmission::Completed(_) => panic!("Ask call must not execute immediately"),
    };
    let canceled = app
        .tool_calls()
        .wait_for_approval(
            canceled_approval,
            &ToolActor::api_token("owner-token", Some("Owner".to_owned())),
            "execution-canceled-wait",
            "call-canceled-wait",
            async {},
        )
        .await;
    assert!(matches!(canceled, Err(ApprovalWaitError::Canceled)));

    let service = app.tool_calls().clone();
    let approval_id = approval.id.clone();
    let approval_revision = approval.revision;
    let waiter = tokio::spawn(async move {
        service
            .wait_for_approval(
                approval,
                &ToolActor::api_token("owner-token", Some("Owner".to_owned())),
                "execution-1",
                "call-1",
                std::future::pending(),
            )
            .await
    });
    app.tool_calls()
        .decide(
            &approval_id,
            "deny-request",
            approval_revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("admin denial should succeed");
    let denied = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
        .await
        .expect("waiter should wake")
        .expect("wait task should not panic")
        .expect("wait should return the terminal approval");
    assert_eq!(denied.record.status, ApprovalStatus::Denied);
    assert!(denied.result.is_none());

    for entry in std::fs::read_dir(directory.path()).expect("data directory should read") {
        let path = entry.expect("data entry should read").path();
        if path.is_file() {
            let bytes = std::fs::read(&path).expect("data file should read");
            assert!(
                !bytes
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes()),
                "plaintext approval argument leaked into {}",
                path.display()
            );
        }
    }

    let audit_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'approval.deny' \
         AND json_extract(metadata_json, '$.approvalId') = ?",
    )
    .bind(&approval_id)
    .fetch_one(app.pool())
    .await
    .expect("approval audit should read");
    assert_eq!(audit_count, 1);
}

#[tokio::test]
async fn invalid_arguments_create_no_approval() {
    let (_directory, app) = app_with_ask_tool().await;
    let result = app
        .tool_calls()
        .submit(call(json!({ "unknown": true })))
        .await;
    assert!(matches!(
        result,
        Err(executor::invocation::ToolCallError::InvalidArguments)
    ));
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approvals")
        .fetch_one(app.pool())
        .await
        .expect("approval count should read");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn bulk_cancellation_and_expiry_attempt_correlated_metadata_logs() {
    let (_directory, app) = app_with_ask_tool().await;

    let canceled = app
        .tool_calls()
        .submit(call_for(
            "execution-cancel",
            "call-cancel",
            json!({ "password": "cancel-secret" }),
        ))
        .await
        .expect("cancel approval should persist");
    let canceled = match canceled {
        ToolCallSubmission::ApprovalRequired(approval) => approval,
        ToolCallSubmission::Completed(_) => panic!("Ask call must become pending"),
    };
    assert_eq!(
        app.tool_calls()
            .cancel_execution("execution-cancel")
            .await
            .expect("execution cancellation should run"),
        1
    );
    wait_for_terminal_log(&app, &canceled.id, "approval_canceled").await;

    let expiring = app
        .tool_calls()
        .submit(call_for(
            "execution-expire",
            "call-expire",
            json!({ "password": "expire-secret" }),
        ))
        .await
        .expect("expiring approval should persist");
    let expiring = match expiring {
        ToolCallSubmission::ApprovalRequired(approval) => approval,
        ToolCallSubmission::Completed(_) => panic!("Ask call must become pending"),
    };
    sqlx::query("UPDATE approval_clock SET effective_now = ? WHERE id = 1")
        .bind(expiring.expires_at)
        .execute(app.pool())
        .await
        .expect("approval clock should advance");
    assert!(
        app.tool_calls()
            .expire_approvals()
            .await
            .expect("expiry should run")
            >= 1
    );
    wait_for_terminal_log(&app, &expiring.id, "approval_expired").await;
}

#[tokio::test]
async fn token_revocation_logs_every_canceled_approval() {
    let (_directory, app) = app_with_ask_tool().await;
    let pending = app
        .tool_calls()
        .submit(call_for(
            "execution-revoke",
            "call-revoke",
            json!({ "password": "revoke-secret" }),
        ))
        .await
        .expect("revoked approval should persist");
    let pending = match pending {
        ToolCallSubmission::ApprovalRequired(approval) => approval,
        ToolCallSubmission::Completed(_) => panic!("Ask call must become pending"),
    };
    assert!(
        app.tool_calls()
            .revoke_owner_token("owner-token")
            .await
            .expect("token revocation should run")
    );
    wait_for_terminal_log(&app, &pending.id, "approval_canceled").await;
}

#[tokio::test]
async fn shutdown_releases_background_approval_activity_before_immediate_reopen() {
    let (directory, app) = app_with_ask_tool().await;

    let pending = app
        .tool_calls()
        .submit(call_for(
            "execution-shutdown-pending",
            "call-shutdown-pending",
            json!({ "password": "pending-secret" }),
        ))
        .await
        .expect("pending approval should persist");
    let pending = match pending {
        ToolCallSubmission::ApprovalRequired(approval) => approval,
        ToolCallSubmission::Completed(_) => panic!("Ask call must become pending"),
    };

    let approved = app
        .tool_calls()
        .submit(call_for(
            "execution-shutdown-approved",
            "call-shutdown-approved",
            json!({ "password": "approved-secret" }),
        ))
        .await
        .expect("approved candidate should persist");
    let approved = match approved {
        ToolCallSubmission::ApprovalRequired(approval) => approval,
        ToolCallSubmission::Completed(_) => panic!("Ask call must become pending"),
    };
    app.tool_calls()
        .decide(
            &approved.id,
            "shutdown-approve",
            approved.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("approval should persist before shutdown");

    let denied = app
        .tool_calls()
        .submit(call_for(
            "execution-shutdown-outbox",
            "call-shutdown-outbox",
            json!({ "password": "outbox-secret" }),
        ))
        .await
        .expect("denied candidate should persist");
    let denied = match denied {
        ToolCallSubmission::ApprovalRequired(approval) => approval,
        ToolCallSubmission::Completed(_) => panic!("Ask call must become pending"),
    };
    app.tool_calls()
        .decide(
            &denied.id,
            "shutdown-deny",
            denied.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("terminal outbox event should persist before shutdown");
    let config = AppConfig::new(directory.path().to_path_buf());
    app.shutdown().await;

    let reopened = ExecutorApp::open(config)
        .await
        .expect("shutdown should release the instance lock before returning");
    let pending_after_restart = reopened
        .tool_calls()
        .approvals()
        .get_admin(&pending.id)
        .await
        .expect("pending approval should read after restart")
        .expect("pending approval should remain stored after restart");
    assert_eq!(pending_after_restart.record.status, ApprovalStatus::Pending);
    wait_for_terminal_log(&reopened, &denied.id, "approval_denied").await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let recovered = reopened
                .tool_calls()
                .approvals()
                .get_admin(&approved.id)
                .await
                .expect("approved recovery state should read")
                .expect("approved recovery state should remain stored");
            if recovered.record.status.is_terminal() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("approved work should reach a recovery-safe terminal state");
    reopened.shutdown().await;
}
