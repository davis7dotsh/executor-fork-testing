use std::{collections::BTreeMap, fs, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, Response, StatusCode, header},
};
use executor::{
    AppConfig, DatabaseError, ExecutorApp,
    catalog::{
        ArtifactKind, AuditContext, CatalogError, CatalogSnapshot, CreateSource, CredentialPayload,
        ListToolsFilter, ModeProvenance, NewRequestLog, RequestOutcome, RequestSurface, SourceKind,
        StagedArtifact, StagedTool, ToolMode, UpdateSource,
    },
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";
const PASSWORD: &str = "correct-horse-battery-staple";

struct TestExecutor {
    directory: TempDir,
    app: Arc<ExecutorApp>,
}

struct AdminSession {
    cookie: String,
    csrf: String,
}

impl TestExecutor {
    async fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test Executor should open");
        Self {
            directory,
            app: Arc::new(app),
        }
    }

    fn router(&self) -> Router {
        self.app.router()
    }

    async fn source(&self, preferred_slug: &str) -> executor::catalog::SourceRecord {
        self.app
            .catalog()
            .create_source(
                CreateSource {
                    kind: SourceKind::Openapi,
                    preferred_slug: preferred_slug.to_owned(),
                    display_name: preferred_slug.to_owned(),
                    description: None,
                    configuration: Map::new(),
                },
                AuditContext::system(None),
            )
            .await
            .expect("source should be created")
    }

    async fn sync(
        &self,
        source_id: &str,
        tools: Vec<StagedTool>,
    ) -> executor::catalog::CatalogSyncResult {
        let source = self
            .app
            .catalog()
            .source(source_id)
            .await
            .expect("source should exist");
        let credential_revision = self
            .app
            .catalog()
            .credential(source_id)
            .await
            .expect("credential read should succeed")
            .map(|credential| credential.revision);
        self.app
            .catalog()
            .sync_catalog(
                source_id,
                CatalogSnapshot {
                    expected_source_revision: source.revision,
                    expected_credential_revision: credential_revision,
                    artifacts: Vec::new(),
                    tools,
                },
                AuditContext::system(None),
            )
            .await
            .expect("catalog sync should succeed")
    }

    async fn setup_admin(&self) {
        let response = send_json(
            self.router(),
            Method::POST,
            "/api/v1/setup",
            json!({
                "setupToken": self.app.setup_token().expect("setup token should exist"),
                "username": "admin",
                "password": PASSWORD
            }),
            &[(header::ORIGIN.as_str(), ORIGIN)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    async fn login(&self) -> AdminSession {
        let response = send_json(
            self.router(),
            Method::POST,
            "/api/v1/session",
            json!({ "username": "admin", "password": PASSWORD }),
            &[(header::ORIGIN.as_str(), ORIGIN)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response_cookie_header(&response);
        let body = response_json(response).await;
        let csrf = body["csrfToken"]
            .as_str()
            .expect("login should reveal CSRF")
            .to_owned();
        AdminSession { cookie, csrf }
    }

    async fn create_api_token(&self, admin: &AdminSession, name: &str) -> String {
        let response = send_json(
            self.router(),
            Method::POST,
            "/api/v1/tokens",
            json!({ "name": name }),
            &[
                (header::COOKIE.as_str(), &admin.cookie),
                (header::ORIGIN.as_str(), ORIGIN),
                ("x-executor-csrf", &admin.csrf),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        response_json(response).await["token"]
            .as_str()
            .expect("token should be revealed")
            .to_owned()
    }
}

fn staged(stable_key: &str, preferred_name: &str, mode: ToolMode) -> StagedTool {
    StagedTool {
        stable_key: stable_key.to_owned(),
        preferred_name: preferred_name.to_owned(),
        display_name: preferred_name.to_owned(),
        description: Some(format!("Operate on {preferred_name}")),
        input_schema: json!({ "type": "object" }),
        output_schema: Some(json!({ "type": "object" })),
        input_typescript: Some("{ id: string }".to_owned()),
        output_typescript: Some("{ ok: boolean }".to_owned()),
        typescript_definitions: BTreeMap::new(),
        intrinsic_mode: mode,
    }
}

#[tokio::test]
async fn catalog_migration_is_strict_and_enforces_foreign_keys_and_constraints() {
    let executor = TestExecutor::new().await;
    let strict_tables =
        sqlx::query_as::<_, (String, String, String, i64, i64, i64)>("PRAGMA table_list")
            .fetch_all(executor.app.pool())
            .await
            .expect("table list should be readable")
            .into_iter()
            .filter(|(_, name, _, _, _, _)| {
                matches!(
                    name.as_str(),
                    "catalog_state"
                        | "sources"
                        | "source_credentials"
                        | "source_artifacts"
                        | "tools"
                        | "request_logs"
                        | "audit_events"
                )
            })
            .collect::<Vec<_>>();
    assert_eq!(strict_tables.len(), 7);
    assert!(strict_tables.iter().all(|row| row.5 == 1));

    let foreign_key_error = sqlx::query(
        "INSERT INTO source_credentials \
         (source_id, schema_version, payload_ciphertext, revision, created_at, updated_at) \
         VALUES ('missing', 1, X'01', 0, 1, 1)",
    )
    .execute(executor.app.pool())
    .await
    .expect_err("credential without source must fail");
    assert!(foreign_key_error.as_database_error().is_some());

    let invalid_kind = sqlx::query(
        "INSERT INTO sources \
         (id, kind, slug, display_name, configuration_json, created_at, updated_at) \
         VALUES ('bad', 'unknown', 'bad', 'Bad', '{}', 1, 1)",
    )
    .execute(executor.app.pool())
    .await
    .expect_err("closed source kind must reject unknown values");
    assert!(invalid_kind.as_database_error().is_some());

    let reserved_slug = sqlx::query(
        "INSERT INTO sources \
         (id, kind, slug, display_name, configuration_json, created_at, updated_at) \
         VALUES ('reserved', 'openapi', 'tools', 'Reserved', '{}', 1, 1)",
    )
    .execute(executor.app.pool())
    .await
    .expect_err("reserved source roots must be rejected by SQLite");
    assert!(reserved_slug.as_database_error().is_some());

    let source = executor.source("strict").await;
    let strict_error = sqlx::query("UPDATE sources SET display_name = ? WHERE id = ?")
        .bind(vec![0_u8, 1_u8])
        .bind(source.id)
        .execute(executor.app.pool())
        .await
        .expect_err("STRICT text column must reject blobs");
    assert!(strict_error.as_database_error().is_some());

    let foreign_key_check =
        sqlx::query_as::<_, (String, i64, String, i64)>("PRAGMA foreign_key_check")
            .fetch_all(executor.app.pool())
            .await
            .expect("foreign key check should run");
    assert!(foreign_key_check.is_empty());
}

#[tokio::test]
async fn source_and_tool_names_are_collision_safe_and_order_independent() {
    let executor = TestExecutor::new().await;
    let first = executor.source("Git Hub").await;
    let second = executor.source("Git-Hub").await;
    assert_eq!(first.slug, "git_hub");
    assert_eq!(second.slug, "git_hub_2");
    for reserved in ["tools", "search", "describe", "executor"] {
        let source = executor.source(reserved).await;
        assert_eq!(source.slug, format!("{reserved}_2"));
    }

    let updated = executor
        .app
        .catalog()
        .update_source(
            &first.id,
            UpdateSource {
                display_name: "GitHub API".to_owned(),
                description: Some("Repository operations".to_owned()),
                configuration: Map::from_iter([(
                    "baseUrl".to_owned(),
                    json!("https://api.example.invalid"),
                )]),
                expected_revision: first.revision,
            },
            AuditContext::system(None),
        )
        .await
        .expect("source should update optimistically");
    assert_eq!(updated.slug, first.slug);
    assert_eq!(updated.display_name, "GitHub API");
    assert!(matches!(
        executor
            .app
            .catalog()
            .update_source(
                &first.id,
                UpdateSource {
                    display_name: "Stale".to_owned(),
                    description: None,
                    configuration: Map::new(),
                    expected_revision: first.revision,
                },
                AuditContext::system(None),
            )
            .await,
        Err(CatalogError::RevisionConflict {
            scope: "source",
            ..
        })
    ));

    executor
        .sync(
            &first.id,
            vec![
                staged("z-key", "Get Repo", ToolMode::Enabled),
                staged("a-key", "Get-Repo", ToolMode::Enabled),
            ],
        )
        .await;
    let first_tools = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(first.id.clone()),
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("tools should list")
        .items;
    let names_by_key = first_tools
        .iter()
        .map(|tool| (tool.stable_key.as_str(), tool.local_name.as_str()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(names_by_key["a-key"], "get_repo");
    assert_eq!(names_by_key["z-key"], "get_repo_2");
    assert!(first_tools.iter().all(|tool| {
        tool.callable_path == format!("tools.{}.{}", first.slug, tool.local_name)
            && tool.sandbox_path == format!("{}.{}", first.slug, tool.local_name)
    }));
}

#[tokio::test]
async fn refresh_is_atomic_and_preserves_overrides_through_tombstones() {
    let executor = TestExecutor::new().await;
    let source = executor.source("catalog").await;
    executor
        .sync(
            &source.id,
            vec![
                staged("alpha", "Run", ToolMode::Enabled),
                staged("beta", "Run", ToolMode::Ask),
            ],
        )
        .await;
    let tools = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source.id.clone()),
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("tools should list")
        .items;
    let beta = tools
        .iter()
        .find(|tool| tool.stable_key == "beta")
        .expect("beta should exist")
        .clone();
    let beta = executor
        .app
        .catalog()
        .set_tool_mode(
            &beta.id,
            Some(ToolMode::Disabled),
            beta.revision,
            AuditContext::system(None),
        )
        .await
        .expect("override should update");
    let before_failure = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    let duplicate = executor
        .app
        .catalog()
        .sync_catalog(
            &source.id,
            CatalogSnapshot {
                expected_source_revision: before_failure.revision,
                expected_credential_revision: None,
                artifacts: Vec::new(),
                tools: vec![
                    staged("same", "One", ToolMode::Enabled),
                    staged("same", "Two", ToolMode::Enabled),
                ],
            },
            AuditContext::system(None),
        )
        .await
        .expect_err("duplicate staging must fail before the transaction");
    assert!(matches!(
        duplicate,
        CatalogError::Validation {
            code: "duplicate_stable_key",
            ..
        }
    ));
    let after_failure = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    assert_eq!(
        after_failure.catalog_revision,
        before_failure.catalog_revision
    );

    executor
        .sync(&source.id, vec![staged("alpha", "Run", ToolMode::Enabled)])
        .await;
    let tombstoned = executor
        .app
        .catalog()
        .tool(&beta.id)
        .await
        .expect("tombstoned tool should remain in admin catalog");
    assert!(!tombstoned.present);
    assert_eq!(tombstoned.mode_override, Some(ToolMode::Disabled));

    executor
        .sync(
            &source.id,
            vec![
                staged("beta", "Different Display Name", ToolMode::Ask),
                staged("alpha", "Run", ToolMode::Enabled),
            ],
        )
        .await;
    let restored = executor
        .app
        .catalog()
        .tool(&beta.id)
        .await
        .expect("restored tool should retain identity");
    assert!(restored.present);
    assert_eq!(restored.id, beta.id);
    assert_eq!(restored.local_name, beta.local_name);
    assert_eq!(restored.mode_override, Some(ToolMode::Disabled));
}

#[tokio::test]
async fn refresh_rejects_oversized_serialized_schema_payloads_before_writing() {
    let executor = TestExecutor::new().await;
    let source = executor.source("payload-limit").await;
    let mut oversized = staged("large", "Large", ToolMode::Enabled);
    oversized.input_schema = json!({ "value": "x".repeat(2 * 1024 * 1024) });
    let error = executor
        .app
        .catalog()
        .sync_catalog(
            &source.id,
            CatalogSnapshot {
                expected_source_revision: source.revision,
                expected_credential_revision: None,
                artifacts: Vec::new(),
                tools: vec![oversized],
            },
            AuditContext::system(None),
        )
        .await
        .expect_err("oversized schema must be rejected before refresh");
    assert!(matches!(
        error,
        CatalogError::Validation {
            code: "schema_too_large",
            ..
        }
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tools WHERE source_id = ?")
            .bind(&source.id)
            .fetch_one(executor.app.pool())
            .await
            .expect("tool count should read"),
        0
    );
}

#[tokio::test]
async fn refresh_cas_and_writer_lock_prevent_stale_or_partial_catalogs() {
    let executor = TestExecutor::new().await;
    let source = executor.source("refresh-basis").await;
    executor
        .app
        .catalog()
        .put_credential(
            &source.id,
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "token": "first" }),
            },
            None,
            AuditContext::system(None),
        )
        .await
        .expect("credential should store");
    let first_credential = executor
        .app
        .catalog()
        .credential(&source.id)
        .await
        .expect("credential should read")
        .expect("credential should exist");
    let basis = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    executor
        .app
        .catalog()
        .put_credential(
            &source.id,
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "token": "second" }),
            },
            Some(first_credential.revision),
            AuditContext::system(None),
        )
        .await
        .expect("credential should rotate");
    let current = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    let credential = executor
        .app
        .catalog()
        .credential(&source.id)
        .await
        .expect("credential should read")
        .expect("credential should exist");
    let stale_credential = executor
        .app
        .catalog()
        .sync_catalog(
            &source.id,
            CatalogSnapshot {
                expected_source_revision: current.revision,
                expected_credential_revision: Some(credential.revision - 1),
                artifacts: vec![StagedArtifact {
                    kind: ArtifactKind::OpenapiDocument,
                    stable_key: "root".to_owned(),
                    content: json!({ "openapi": "3.1.0" }),
                }],
                tools: vec![staged("new", "New", ToolMode::Enabled)],
            },
            AuditContext::system(None),
        )
        .await;
    assert!(matches!(
        stale_credential,
        Err(CatalogError::RevisionConflict {
            scope: "credential",
            ..
        })
    ));
    assert_eq!(
        executor
            .app
            .catalog()
            .source(&source.id)
            .await
            .expect("source should exist")
            .catalog_revision,
        basis.catalog_revision
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM source_artifacts")
            .fetch_one(executor.app.pool())
            .await
            .expect("artifact count should read"),
        0
    );

    let current = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    let snapshot = CatalogSnapshot {
        expected_source_revision: current.revision,
        expected_credential_revision: Some(credential.revision),
        artifacts: vec![StagedArtifact {
            kind: ArtifactKind::OpenapiDocument,
            stable_key: "root".to_owned(),
            content: json!({ "openapi": "3.1.0" }),
        }],
        tools: vec![staged("new", "New", ToolMode::Enabled)],
    };
    let first_store = executor.app.catalog().clone();
    let second_store = executor.app.catalog().clone();
    let first = first_store.sync_catalog(
        &source.id,
        snapshot.clone(),
        AuditContext::system(Some("refresh-race-1")),
    );
    let second = second_store.sync_catalog(
        &source.id,
        snapshot,
        AuditContext::system(Some("refresh-race-2")),
    );
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first, second];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(CatalogError::RevisionConflict {
                    scope: "source",
                    ..
                })
            ))
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM source_artifacts")
            .fetch_one(executor.app.pool())
            .await
            .expect("artifact count should read"),
        1
    );
}

#[tokio::test]
async fn credential_writes_require_absence_or_the_current_revision() {
    let executor = TestExecutor::new().await;
    let source = executor.source("credential-cas").await;
    executor
        .app
        .catalog()
        .put_credential(
            &source.id,
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "token": "first" }),
            },
            None,
            AuditContext::system(Some("credential-create")),
        )
        .await
        .expect("an absent credential should be created");
    let first = executor
        .app
        .catalog()
        .credential(&source.id)
        .await
        .expect("credential should read")
        .expect("credential should exist");
    assert_eq!(first.revision, 0);

    let source_after_create = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    let global_after_create = executor
        .app
        .catalog()
        .global_revision()
        .await
        .expect("global revision should read");
    let duplicate_create = executor
        .app
        .catalog()
        .put_credential(
            &source.id,
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "token": "duplicate" }),
            },
            None,
            AuditContext::system(Some("credential-duplicate")),
        )
        .await;
    assert!(matches!(
        duplicate_create,
        Err(CatalogError::RevisionConflict {
            scope: "credential",
            expected: -1,
            actual: 0,
        })
    ));
    assert_eq!(
        executor
            .app
            .catalog()
            .source(&source.id)
            .await
            .expect("source should exist")
            .revision,
        source_after_create.revision
    );
    assert_eq!(
        executor
            .app
            .catalog()
            .global_revision()
            .await
            .expect("global revision should read"),
        global_after_create
    );

    executor
        .app
        .catalog()
        .put_credential(
            &source.id,
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "token": "newer" }),
            },
            Some(first.revision),
            AuditContext::system(Some("credential-rotate")),
        )
        .await
        .expect("the current credential revision should rotate");
    let source_after_rotate = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    let global_after_rotate = executor
        .app
        .catalog()
        .global_revision()
        .await
        .expect("global revision should read");
    let audit_after_rotate = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_events \
         WHERE action = 'source.credential_changed' AND source_id = ?",
    )
    .bind(&source.id)
    .fetch_one(executor.app.pool())
    .await
    .expect("credential audit count should read");
    assert_eq!(audit_after_rotate, 2);

    let stale_rotate = executor
        .app
        .catalog()
        .put_credential(
            &source.id,
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "token": "stale" }),
            },
            Some(first.revision),
            AuditContext::system(Some("credential-stale")),
        )
        .await;
    assert!(matches!(
        stale_rotate,
        Err(CatalogError::RevisionConflict {
            scope: "credential",
            expected: 0,
            actual: 1,
        })
    ));
    let stored = executor
        .app
        .catalog()
        .credential(&source.id)
        .await
        .expect("credential should read")
        .expect("credential should exist");
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.credential.payload["token"], "newer");
    assert_eq!(
        executor
            .app
            .catalog()
            .source(&source.id)
            .await
            .expect("source should exist")
            .revision,
        source_after_rotate.revision
    );
    assert_eq!(
        executor
            .app
            .catalog()
            .global_revision()
            .await
            .expect("global revision should read"),
        global_after_rotate
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_events \
             WHERE action = 'source.credential_changed' AND source_id = ?",
        )
        .bind(&source.id)
        .fetch_one(executor.app.pool())
        .await
        .expect("credential audit count should read"),
        audit_after_rotate
    );
}

#[tokio::test]
async fn refresh_audits_preserve_correlation_and_explicit_actor() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let source = executor.source("refresh-audit").await;
    executor
        .app
        .catalog()
        .sync_catalog(
            &source.id,
            CatalogSnapshot {
                expected_source_revision: source.revision,
                expected_credential_revision: None,
                artifacts: Vec::new(),
                tools: vec![staged("run", "Run", ToolMode::Enabled)],
            },
            AuditContext::system(Some("refresh-job-1")),
        )
        .await
        .expect("background refresh should commit");
    let system_audit = sqlx::query_as::<_, (Option<String>, Option<i64>)>(
        "SELECT request_id, actor_admin_id FROM audit_events \
         WHERE action = 'source.catalog_refreshed' AND request_id = 'refresh-job-1'",
    )
    .fetch_one(executor.app.pool())
    .await
    .expect("system refresh audit should exist");
    assert_eq!(system_audit, (Some("refresh-job-1".to_owned()), None));

    let current = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    executor
        .app
        .catalog()
        .sync_catalog(
            &source.id,
            CatalogSnapshot {
                expected_source_revision: current.revision,
                expected_credential_revision: None,
                artifacts: Vec::new(),
                tools: vec![staged("run", "Run", ToolMode::Enabled)],
            },
            AuditContext::admin("admin-request-1", 1),
        )
        .await
        .expect("administrator refresh should commit");
    let admin_audit = sqlx::query_as::<_, (Option<String>, Option<i64>)>(
        "SELECT request_id, actor_admin_id FROM audit_events \
         WHERE action = 'source.catalog_refreshed' AND request_id = 'admin-request-1'",
    )
    .fetch_one(executor.app.pool())
    .await
    .expect("administrator refresh audit should exist");
    assert_eq!(admin_audit, (Some("admin-request-1".to_owned()), Some(1)));
}

#[tokio::test]
async fn effective_modes_follow_precedence_and_gateway_visibility_rules() {
    let executor = TestExecutor::new().await;
    let source = executor.source("modes").await;
    executor
        .sync(&source.id, vec![staged("review", "Review", ToolMode::Ask)])
        .await;
    let tool = executor
        .app
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
    assert_eq!(tool.effective_mode.mode, ToolMode::Ask);
    assert_eq!(tool.effective_mode.provenance, ModeProvenance::Intrinsic);
    let discovery = executor
        .app
        .catalog()
        .search_tools("review", None, 10, 0)
        .await
        .expect("search should work");
    assert_eq!(discovery.total, 1);
    assert!(discovery.items[0].requires_approval);
    assert_eq!(discovery.items[0].effective_mode, ToolMode::Ask);
    let ask_lookup = executor
        .app
        .catalog()
        .guard_invocation(&tool.callable_path)
        .await
        .expect("Ask tool should remain callable through approval");
    assert!(ask_lookup.requires_approval);

    let source = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    executor
        .app
        .catalog()
        .set_source_mode(
            &source.id,
            Some(ToolMode::Disabled),
            source.revision,
            AuditContext::system(None),
        )
        .await
        .expect("source override should update");
    let disabled = executor
        .app
        .catalog()
        .tool(&tool.id)
        .await
        .expect("admin catalog should retain disabled tool");
    assert_eq!(disabled.effective_mode.mode, ToolMode::Disabled);
    assert_eq!(
        disabled.effective_mode.provenance,
        ModeProvenance::SourceOverride
    );
    assert_eq!(
        executor
            .app
            .catalog()
            .search_tools("review", None, 10, 0)
            .await
            .expect("search should work")
            .total,
        0
    );
    assert!(matches!(
        executor
            .app
            .catalog()
            .describe_tool(&tool.sandbox_path)
            .await,
        Err(CatalogError::ToolNotFound { .. })
    ));
    assert!(matches!(
        executor
            .app
            .catalog()
            .guard_invocation(&tool.sandbox_path)
            .await,
        Err(CatalogError::ToolDisabled { .. })
    ));

    let override_enabled = executor
        .app
        .catalog()
        .set_tool_mode(
            &tool.id,
            Some(ToolMode::Enabled),
            disabled.revision,
            AuditContext::system(None),
        )
        .await
        .expect("tool override should update");
    assert_eq!(override_enabled.effective_mode.mode, ToolMode::Enabled);
    assert_eq!(
        override_enabled.effective_mode.provenance,
        ModeProvenance::ToolOverride
    );
    let reset = executor
        .app
        .catalog()
        .set_tool_mode(
            &tool.id,
            None,
            override_enabled.revision,
            AuditContext::system(None),
        )
        .await
        .expect("tool override should reset");
    assert_eq!(reset.effective_mode.mode, ToolMode::Disabled);
}

#[tokio::test]
async fn lexical_search_ranks_filters_and_paginates_like_the_typescript_runtime() {
    let executor = TestExecutor::new().await;
    let github = executor.source("github").await;
    let stripe = executor.source("stripe").await;
    let go = executor.source("go").await;
    executor
        .sync(
            &github.id,
            vec![
                staged("create-issue", "createIssue", ToolMode::Ask),
                staged("list-issues", "listIssues", ToolMode::Enabled),
            ],
        )
        .await;
    executor
        .sync(&go.id, vec![staged("ping", "ping", ToolMode::Enabled)])
        .await;
    let mut camel_description = staged("customer-ledger", "archive", ToolMode::Enabled);
    camel_description.description = Some("CustomerLedger workflow".to_owned());
    executor
        .sync(
            &stripe.id,
            vec![
                staged("create-invoice", "createInvoice", ToolMode::Enabled),
                camel_description,
            ],
        )
        .await;

    let exact = executor
        .app
        .catalog()
        .search_tools("create issue", None, 10, 0)
        .await
        .expect("search should work");
    assert_eq!(exact.total, 1);
    assert_eq!(exact.items[0].path, "github.create_issue");

    let first_page = executor
        .app
        .catalog()
        .search_tools("create", None, 1, 0)
        .await
        .expect("search should work");
    assert_eq!(first_page.total, 2);
    assert!(first_page.has_more);
    assert_eq!(first_page.next_offset, Some(1));
    let second_page = executor
        .app
        .catalog()
        .search_tools("create", None, 1, 1)
        .await
        .expect("search should work");
    assert_eq!(second_page.items.len(), 1);
    assert!(!second_page.has_more);
    assert_ne!(first_page.items[0].path, second_page.items[0].path);

    let github_only = executor
        .app
        .catalog()
        .search_tools("create", Some("github"), 10, 0)
        .await
        .expect("namespace search should work");
    assert_eq!(github_only.total, 1);
    assert_eq!(github_only.items[0].integration, "github");
    let camel_description = executor
        .app
        .catalog()
        .search_tools("ledger", None, 10, 0)
        .await
        .expect("normalized description search should work");
    assert_eq!(camel_description.total, 1);
    assert_eq!(camel_description.items[0].path, "stripe.archive");
    for query in ["hub", "githubs", "it"] {
        let legacy_match = executor
            .app
            .catalog()
            .search_tools(query, None, 10, 0)
            .await
            .expect("legacy substring and reverse-prefix search should work");
        assert!(
            legacy_match
                .items
                .iter()
                .any(|item| item.integration == "github"),
            "{query} should reach the indexed github candidate"
        );
    }
    let short_reverse_prefix = executor
        .app
        .catalog()
        .search_tools("google", None, 10, 0)
        .await
        .expect("short reverse-prefix search should work");
    assert!(
        short_reverse_prefix
            .items
            .iter()
            .any(|item| item.integration == "go")
    );
    let empty = executor
        .app
        .catalog()
        .search_tools("---", None, 10, 0)
        .await
        .expect("punctuation search should be empty");
    assert_eq!(empty.total, 0);
}

#[tokio::test]
async fn gateway_search_rejects_unbounded_direct_store_queries_before_index_work() {
    let executor = TestExecutor::new().await;
    let excessive_bytes = "token ".repeat(100_000);
    for (query, namespace) in [
        (excessive_bytes.as_str(), None),
        (&"x".repeat(257), None),
        (&"x ".repeat(65), None),
        ("safe", Some(excessive_bytes.as_str())),
    ] {
        assert!(matches!(
            executor
                .app
                .catalog()
                .search_tools(query, namespace, 10, 0)
                .await,
            Err(CatalogError::Validation {
                code: "invalid_search_query",
                ..
            })
        ));
    }
}

#[tokio::test]
async fn gateway_search_bounds_candidates_and_filters_historical_rows_before_ranking() {
    let executor = TestExecutor::new().await;
    let source = executor.source("search-scale").await;
    executor
        .sync(
            &source.id,
            vec![staged("active", "Needle", ToolMode::Enabled)],
        )
        .await;

    sqlx::query(
        "WITH RECURSIVE sequence(value) AS ( \
         SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < 10000) \
         INSERT INTO tools \
         (id, source_id, stable_key, local_name, display_name, description, input_schema_json, \
          typescript_definitions_json, intrinsic_mode, present, revision, created_at, updated_at, \
          last_seen_at, tombstoned_at) \
         SELECT printf('historical-%05d', value), ?, printf('historical-key-%05d', value), \
                printf('needle_historical_%05d', value), 'Historical Needle', \
                'needle historical entry', '{}', '{}', \
                CASE WHEN value <= 5000 THEN 'enabled' ELSE 'disabled' END, \
                CASE WHEN value <= 5000 THEN 0 ELSE 1 END, 0, 1, 1, 1, \
                CASE WHEN value <= 5000 THEN 1 ELSE NULL END \
         FROM sequence",
    )
    .bind(&source.id)
    .execute(executor.app.pool())
    .await
    .expect("large tombstone history should seed");
    sqlx::query(
        "INSERT INTO tool_search \
         (source_id, tool_id, source_slug, local_name, description, sandbox_path) \
         SELECT tools.source_id, tools.id, replace(sources.slug, '_', ' '), \
                replace(tools.local_name, '_', ' '), tools.description, \
                replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') \
         FROM tools JOIN sources ON sources.id = tools.source_id \
         WHERE tools.source_id = ? AND tools.id LIKE 'historical-%'",
    )
    .bind(&source.id)
    .execute(executor.app.pool())
    .await
    .expect("historical search entries should seed");

    let historical = executor
        .app
        .catalog()
        .search_tools("needle", None, 10, 0)
        .await
        .expect("search should ignore historical candidates in SQL");
    assert_eq!(historical.total, 1);
    assert_eq!(historical.items[0].path, "search_scale.needle");

    sqlx::query(
        "WITH RECURSIVE sequence(value) AS ( \
         SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < 5000) \
         INSERT INTO tools \
         (id, source_id, stable_key, local_name, display_name, description, input_schema_json, \
          typescript_definitions_json, intrinsic_mode, present, revision, created_at, updated_at, \
          last_seen_at, tombstoned_at) \
         SELECT printf('bounded-%05d', value), ?, printf('bounded-key-%05d', value), \
                printf('common_%05d', value), 'Common', 'common candidate', '{}', '{}', \
                'enabled', 1, 0, 1, 1, 1, NULL FROM sequence",
    )
    .bind(&source.id)
    .execute(executor.app.pool())
    .await
    .expect("large active catalog should seed");
    sqlx::query(
        "INSERT INTO tool_search \
         (source_id, tool_id, source_slug, local_name, description, sandbox_path) \
         SELECT tools.source_id, tools.id, replace(sources.slug, '_', ' '), \
                replace(tools.local_name, '_', ' '), tools.description, \
                replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') \
         FROM tools JOIN sources ON sources.id = tools.source_id \
         WHERE tools.source_id = ? AND tools.id LIKE 'bounded-%'",
    )
    .bind(&source.id)
    .execute(executor.app.pool())
    .await
    .expect("active search entries should seed");
    let bounded = executor
        .app
        .catalog()
        .search_tools("common", None, 10, 0)
        .await
        .expect("large search should remain bounded");
    assert_eq!(bounded.items.len(), 10);
    assert_eq!(bounded.total, 4096);
    assert!(bounded.has_more);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM tools WHERE source_id = ? AND present = 1 \
             AND description = 'common candidate'",
        )
        .bind(&source.id)
        .fetch_one(executor.app.pool())
        .await
        .expect("active candidate count should read"),
        5000
    );
}

#[tokio::test]
async fn admin_tool_listing_filters_counts_and_pages_in_sql() {
    let executor = TestExecutor::new().await;
    let alpha = executor.source("alpha-list").await;
    let beta = executor.source("beta-list").await;
    executor
        .sync(
            &alpha.id,
            vec![
                staged("keep", "Alpha Search", ToolMode::Enabled),
                staged("gone", "Archived Match", ToolMode::Enabled),
                staged("ask", "Review Match", ToolMode::Ask),
            ],
        )
        .await;
    executor
        .sync(
            &beta.id,
            vec![staged("other", "Alpha Other", ToolMode::Enabled)],
        )
        .await;
    executor
        .sync(
            &alpha.id,
            vec![
                staged("keep", "Alpha Search", ToolMode::Enabled),
                staged("ask", "Review Match", ToolMode::Ask),
            ],
        )
        .await;

    let active = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("active tools should list");
    assert_eq!(active.total, 3);
    assert!(active.items.iter().all(|tool| tool.present));

    let source_query = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            query: Some("match".to_owned()),
            source_id: Some(alpha.id.clone()),
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("source and query filters should compose");
    assert_eq!(source_query.total, 1);
    assert_eq!(source_query.items[0].stable_key, "ask");

    let with_tombstones = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            query: Some("match".to_owned()),
            source_id: Some(alpha.id.clone()),
            include_tombstoned: true,
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("tombstones should be included on request");
    assert_eq!(with_tombstones.total, 2);
    assert_eq!(
        with_tombstones
            .items
            .iter()
            .filter(|tool| !tool.present)
            .count(),
        1
    );

    let ask_only = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(alpha.id),
            effective_mode: Some(ToolMode::Ask),
            include_tombstoned: true,
            limit: 100,
            ..Default::default()
        })
        .await
        .expect("effective mode should filter in SQL");
    assert_eq!(ask_only.total, 1);
    assert_eq!(ask_only.items[0].stable_key, "ask");

    let first_page = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            include_tombstoned: true,
            limit: 2,
            offset: 0,
            ..Default::default()
        })
        .await
        .expect("first page should list");
    let second_page = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            include_tombstoned: true,
            limit: 2,
            offset: 2,
            ..Default::default()
        })
        .await
        .expect("second page should list");
    assert_eq!(first_page.total, 4);
    assert_eq!(second_page.total, 4);
    assert!(first_page.has_more);
    assert_eq!(first_page.next_offset, Some(2));
    assert!(!second_page.has_more);
    let mut combined_paths = first_page
        .items
        .iter()
        .chain(&second_page.items)
        .map(|tool| tool.callable_path.clone())
        .collect::<Vec<_>>();
    let original_paths = combined_paths.clone();
    combined_paths.sort();
    assert_eq!(original_paths, combined_paths);
    combined_paths.dedup();
    assert_eq!(combined_paths.len(), 4);
}

#[tokio::test]
async fn catalog_churn_rejects_tombstone_history_overflow_atomically() {
    let executor = TestExecutor::new().await;
    let source = executor.source("history-ceiling").await;
    executor
        .sync(
            &source.id,
            vec![staged("current", "Current", ToolMode::Enabled)],
        )
        .await;
    sqlx::query(
        "WITH RECURSIVE sequence(value) AS ( \
         SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < 25000) \
         INSERT INTO tools \
         (id, source_id, stable_key, local_name, display_name, description, input_schema_json, \
          typescript_definitions_json, intrinsic_mode, present, revision, created_at, updated_at, \
          last_seen_at, tombstoned_at) \
         SELECT printf('retained-history-%05d', value), ?, printf('retained-key-%05d', value), \
                printf('retained_%05d', value), 'Retained', NULL, '{}', '{}', 'enabled', \
                0, 0, 1, 1, 1, 1 FROM sequence",
    )
    .bind(&source.id)
    .execute(executor.app.pool())
    .await
    .expect("tombstone ceiling fixture should seed");
    let before = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    let error = executor
        .app
        .catalog()
        .sync_catalog(
            &source.id,
            CatalogSnapshot {
                expected_source_revision: before.revision,
                expected_credential_revision: None,
                artifacts: vec![StagedArtifact {
                    kind: ArtifactKind::Metadata,
                    stable_key: "must-not-write".to_owned(),
                    content: json!({ "atomic": true }),
                }],
                tools: vec![staged("new-key", "New Tool", ToolMode::Enabled)],
            },
            AuditContext::system(None),
        )
        .await
        .expect_err("churn beyond retained tombstone ceiling must fail");
    assert!(matches!(
        error,
        CatalogError::Validation {
            code: "catalog_too_large",
            ..
        }
    ));
    let after = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should remain");
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.catalog_revision, before.catalog_revision);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM tools WHERE source_id = ? AND stable_key = 'current' \
             AND present = 1",
        )
        .bind(&source.id)
        .fetch_one(executor.app.pool())
        .await
        .expect("current tool state should read"),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM tools WHERE source_id = ? AND stable_key = 'new-key'",
        )
        .bind(&source.id)
        .fetch_one(executor.app.pool())
        .await
        .expect("new tool state should read"),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM source_artifacts WHERE source_id = ? \
             AND stable_key = 'must-not-write'",
        )
        .bind(&source.id)
        .fetch_one(executor.app.pool())
        .await
        .expect("artifact state should read"),
        0
    );
}

#[tokio::test]
async fn optimistic_and_bulk_mode_changes_are_atomic() {
    let executor = TestExecutor::new().await;
    let source = executor.source("bulk").await;
    executor
        .sync(
            &source.id,
            vec![
                staged("one", "One", ToolMode::Enabled),
                staged("two", "Two", ToolMode::Enabled),
            ],
        )
        .await;
    let tools = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source.id.clone()),
            limit: 10,
            ..Default::default()
        })
        .await
        .expect("tools should list")
        .items;
    let first = &tools[0];
    executor
        .app
        .catalog()
        .set_tool_mode(
            &first.id,
            Some(ToolMode::Ask),
            first.revision,
            AuditContext::system(None),
        )
        .await
        .expect("first optimistic update should work");
    assert!(matches!(
        executor
            .app
            .catalog()
            .set_tool_mode(
                &first.id,
                Some(ToolMode::Disabled),
                first.revision,
                AuditContext::system(None),
            )
            .await,
        Err(CatalogError::RevisionConflict { scope: "tool", .. })
    ));

    let global_revision = executor
        .app
        .catalog()
        .global_revision()
        .await
        .expect("revision should read");
    let invalid_bulk = executor
        .app
        .catalog()
        .bulk_set_tool_modes(
            &[tools[1].id.clone(), "missing".to_owned()],
            Some(ToolMode::Disabled),
            global_revision,
            AuditContext::system(None),
        )
        .await;
    assert!(matches!(
        invalid_bulk,
        Err(CatalogError::NotFound { entity: "tool" })
    ));
    assert_eq!(
        executor
            .app
            .catalog()
            .tool(&tools[1].id)
            .await
            .expect("tool should remain")
            .mode_override,
        None
    );

    let result = executor
        .app
        .catalog()
        .bulk_set_tool_modes(
            &tools.iter().map(|tool| tool.id.clone()).collect::<Vec<_>>(),
            Some(ToolMode::Disabled),
            global_revision,
            AuditContext::system(Some("explicit-bulk-audit")),
        )
        .await
        .expect("valid bulk update should commit");
    assert_eq!(result.updated_count, 2);
    let audit_metadata = sqlx::query_scalar::<_, String>(
        "SELECT metadata_json FROM audit_events \
         WHERE request_id = 'explicit-bulk-audit' AND action = 'tool.mode_bulk_changed'",
    )
    .fetch_one(executor.app.pool())
    .await
    .expect("explicit bulk audit metadata should exist");
    let audit_metadata: Value =
        serde_json::from_str(&audit_metadata).expect("audit metadata should be valid JSON");
    let mut expected_selection = tools
        .iter()
        .map(|tool| {
            json!({
                "toolId": tool.id,
                "path": tool.callable_path
            })
        })
        .collect::<Vec<_>>();
    expected_selection
        .sort_by(|left, right| left["toolId"].as_str().cmp(&right["toolId"].as_str()));
    assert_eq!(
        audit_metadata["selectedTools"],
        Value::Array(expected_selection)
    );
    for tool in &tools {
        assert_eq!(
            executor
                .app
                .catalog()
                .tool(&tool.id)
                .await
                .expect("tool should exist")
                .mode_override,
            Some(ToolMode::Disabled)
        );
    }

    let stale_source = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist");
    assert!(matches!(
        executor
            .app
            .catalog()
            .bulk_set_source_tool_modes(
                &source.id,
                Some(ToolMode::Enabled),
                stale_source.revision - 1,
                AuditContext::system(None),
            )
            .await,
        Err(CatalogError::RevisionConflict {
            scope: "source",
            ..
        })
    ));
}

#[tokio::test]
async fn catalog_writes_wait_for_non_catalog_writers_without_busy_snapshots() {
    let executor = TestExecutor::new().await;
    let source = executor.source("writer-race").await;
    let mut outside_write = executor
        .app
        .pool()
        .begin_with("BEGIN IMMEDIATE")
        .await
        .expect("outside writer should reserve SQLite");
    sqlx::query(
        "INSERT INTO request_logs \
         (request_id, surface, path_snapshot, outcome, duration_ms, created_at) \
         VALUES ('blocking-write', 'gateway', 'tools.search', 'succeeded', 1, 1)",
    )
    .execute(&mut *outside_write)
    .await
    .expect("outside writer should hold an uncommitted write");

    let catalog = executor.app.catalog().clone();
    let source_id = source.id.clone();
    let update = tokio::spawn(async move {
        catalog
            .set_source_mode(
                &source_id,
                Some(ToolMode::Ask),
                source.revision,
                AuditContext::system(None),
            )
            .await
    });
    tokio::task::yield_now().await;
    assert!(!update.is_finished());
    outside_write
        .commit()
        .await
        .expect("outside writer should commit");
    let updated = tokio::time::timeout(std::time::Duration::from_secs(2), update)
        .await
        .expect("catalog writer should resume before the busy timeout")
        .expect("catalog writer task should not panic")
        .expect("catalog writer should succeed");
    assert_eq!(updated.mode_override, Some(ToolMode::Ask));
}

#[tokio::test]
async fn credentials_are_encrypted_bound_to_the_source_and_never_logged() {
    let executor = TestExecutor::new().await;
    let first = executor.source("credential-one").await;
    let second = executor.source("credential-two").await;
    let secret = "catalog-super-secret-value";
    executor
        .app
        .catalog()
        .put_credential(
            &first.id,
            &CredentialPayload {
                schema_version: 1,
                payload: json!({ "token": secret, "header": "Authorization" }),
            },
            None,
            AuditContext::system(None),
        )
        .await
        .expect("credential should be stored");
    let stored = executor
        .app
        .catalog()
        .credential(&first.id)
        .await
        .expect("credential should decrypt")
        .expect("credential should exist");
    assert_eq!(stored.credential.payload["token"], secret);

    let ciphertext = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT payload_ciphertext FROM source_credentials WHERE source_id = ?",
    )
    .bind(&first.id)
    .fetch_one(executor.app.pool())
    .await
    .expect("ciphertext should exist");
    assert!(!String::from_utf8_lossy(&ciphertext).contains(secret));
    sqlx::query(
        "INSERT INTO source_credentials \
         (source_id, schema_version, payload_ciphertext, revision, created_at, updated_at) \
         VALUES (?, 1, ?, 0, 1, 1)",
    )
    .bind(&second.id)
    .bind(ciphertext)
    .execute(executor.app.pool())
    .await
    .expect("test should copy ciphertext to another record");
    assert!(matches!(
        executor.app.catalog().credential(&second.id).await,
        Err(CatalogError::Crypto(_))
    ));

    let database_bytes = fs::read(executor.directory.path().join("executor.db"))
        .expect("database should be readable");
    assert!(!String::from_utf8_lossy(&database_bytes).contains(secret));
    let leaked_logs = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM request_logs WHERE path_snapshot LIKE '%' || ? || '%' \
         OR error_code LIKE '%' || ? || '%'",
    )
    .bind(secret)
    .bind(secret)
    .fetch_one(executor.app.pool())
    .await
    .expect("logs should be queryable");
    assert_eq!(leaked_logs, 0);
}

#[tokio::test]
async fn request_logs_are_redacted_paginated_and_survive_catalog_deletion() {
    let executor = TestExecutor::new().await;
    let source = executor.source("history").await;
    executor
        .sync(&source.id, vec![staged("run", "Run", ToolMode::Enabled)])
        .await;
    let tool = executor
        .app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source.id.clone()),
            limit: 10,
            ..Default::default()
        })
        .await
        .expect("tools should list")
        .items
        .remove(0);
    executor
        .app
        .catalog()
        .record_request(NewRequestLog {
            request_id: "request-2".to_owned(),
            actor_api_token_id: None,
            surface: RequestSurface::Gateway,
            source_id: Some(source.id.clone()),
            tool_id: Some(tool.id.clone()),
            path_snapshot: Some(tool.callable_path.clone()),
            outcome: RequestOutcome::Failed,
            error_code: Some("upstream_unavailable".to_owned()),
            duration_ms: 12,
            approval_id: None,
            created_at: 2,
        })
        .await
        .expect("log should store");
    executor
        .app
        .catalog()
        .record_request(NewRequestLog {
            request_id: "request-1".to_owned(),
            actor_api_token_id: None,
            surface: RequestSurface::Gateway,
            source_id: None,
            tool_id: None,
            path_snapshot: Some("tools.search".to_owned()),
            outcome: RequestOutcome::Succeeded,
            error_code: None,
            duration_ms: 1,
            approval_id: None,
            created_at: 1,
        })
        .await
        .expect("second log should store");
    let first_page = executor
        .app
        .catalog()
        .list_request_logs(None, 1)
        .await
        .expect("logs should list");
    assert_eq!(first_page.items[0].request_id, "request-2");
    let second_page = executor
        .app
        .catalog()
        .list_request_logs(first_page.next_cursor.as_deref(), 1)
        .await
        .expect("cursor should continue");
    assert_eq!(second_page.items[0].request_id, "request-1");

    let columns = sqlx::query_as::<_, (i64, String, String, i64, Option<String>, i64)>(
        "PRAGMA table_info(request_logs)",
    )
    .fetch_all(executor.app.pool())
    .await
    .expect("log columns should be readable")
    .into_iter()
    .map(|row| row.1)
    .collect::<Vec<_>>();
    for forbidden in ["headers", "credentials", "arguments", "results", "body"] {
        assert!(!columns.iter().any(|column| column.contains(forbidden)));
    }

    executor
        .app
        .catalog()
        .delete_source(&source.id, AuditContext::system(None))
        .await
        .expect("source should delete");
    let retained = executor
        .app
        .catalog()
        .request_log("request-2")
        .await
        .expect("history should survive");
    assert_eq!(retained.source_id, None);
    assert_eq!(retained.tool_id, None);
    assert_eq!(
        retained.path_snapshot.as_deref(),
        Some(tool.callable_path.as_str())
    );
    let audit_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
        .fetch_one(executor.app.pool())
        .await
        .expect("audit count should read");
    assert!(audit_count > 0);
    let audit_without_snapshot = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_events \
         WHERE action LIKE 'source.%' AND target_path_snapshot IS NULL",
    )
    .fetch_one(executor.app.pool())
    .await
    .expect("source audit snapshots should be queryable");
    assert_eq!(audit_without_snapshot, 0);

    executor
        .app
        .catalog()
        .record_request(NewRequestLog {
            request_id: "late-request".to_owned(),
            actor_api_token_id: None,
            surface: RequestSurface::Gateway,
            source_id: Some(source.id),
            tool_id: Some(tool.id),
            path_snapshot: Some(tool.callable_path),
            outcome: RequestOutcome::Succeeded,
            error_code: None,
            duration_ms: 2,
            approval_id: None,
            created_at: 3,
        })
        .await
        .expect("late logs should null stale foreign keys");
    let late = executor
        .app
        .catalog()
        .request_log("late-request")
        .await
        .expect("late log should exist");
    assert_eq!(late.source_id, None);
    assert_eq!(late.tool_id, None);
}

#[tokio::test]
async fn request_logs_prune_atomically_and_apply_bounded_writer_backpressure() {
    let executor = TestExecutor::new().await;
    sqlx::query(
        "WITH RECURSIVE sequence(value) AS ( \
         SELECT 1 UNION ALL SELECT value + 1 FROM sequence WHERE value < 10000) \
         INSERT INTO request_logs \
         (request_id, surface, path_snapshot, outcome, duration_ms, created_at) \
         SELECT printf('retained-%05d', value), 'gateway', 'tools.search', \
                'succeeded', 1, value FROM sequence",
    )
    .execute(executor.app.pool())
    .await
    .expect("retention boundary should seed");
    executor
        .app
        .catalog()
        .record_request(NewRequestLog {
            request_id: "newest-retained".to_owned(),
            actor_api_token_id: None,
            surface: RequestSurface::Gateway,
            source_id: None,
            tool_id: None,
            path_snapshot: Some("tools.search".to_owned()),
            outcome: RequestOutcome::Succeeded,
            error_code: None,
            duration_ms: 1,
            approval_id: None,
            created_at: 10001,
        })
        .await
        .expect("insert and retention prune should commit together");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM request_logs")
            .fetch_one(executor.app.pool())
            .await
            .expect("retained count should read"),
        10000
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM request_logs WHERE request_id = 'retained-00001'",
        )
        .fetch_one(executor.app.pool())
        .await
        .expect("oldest retention state should read"),
        0
    );
    executor
        .app
        .catalog()
        .request_log("newest-retained")
        .await
        .expect("new log should survive pruning");

    let outside_writer = executor
        .app
        .pool()
        .begin_with("BEGIN IMMEDIATE")
        .await
        .expect("outside writer should reserve SQLite");
    let blocked_catalog = executor.app.catalog().clone();
    let blocked = tokio::spawn(async move {
        blocked_catalog
            .record_request(NewRequestLog {
                request_id: "blocked-log".to_owned(),
                actor_api_token_id: None,
                surface: RequestSurface::Gateway,
                source_id: None,
                tool_id: None,
                path_snapshot: Some("tools.search".to_owned()),
                outcome: RequestOutcome::Succeeded,
                error_code: None,
                duration_ms: 1,
                approval_id: None,
                created_at: 10002,
            })
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let overloaded = executor
        .app
        .catalog()
        .record_request(NewRequestLog {
            request_id: "overloaded-log".to_owned(),
            actor_api_token_id: None,
            surface: RequestSurface::Gateway,
            source_id: None,
            tool_id: None,
            path_snapshot: Some("tools.search".to_owned()),
            outcome: RequestOutcome::Succeeded,
            error_code: None,
            duration_ms: 1,
            approval_id: None,
            created_at: 10003,
        })
        .await;
    assert!(matches!(
        overloaded,
        Err(CatalogError::Validation {
            code: "request_log_backpressure",
            ..
        })
    ));
    assert!(!blocked.is_finished());
    outside_writer
        .commit()
        .await
        .expect("outside writer should commit");
    tokio::time::timeout(std::time::Duration::from_secs(2), blocked)
        .await
        .expect("the single logger should resume after contention clears")
        .expect("blocked logger task should not panic")
        .expect("blocked log should persist after contention clears");
    executor
        .app
        .catalog()
        .record_request(NewRequestLog {
            request_id: "after-backpressure".to_owned(),
            actor_api_token_id: None,
            surface: RequestSurface::Gateway,
            source_id: None,
            tool_id: None,
            path_snapshot: Some("tools.search".to_owned()),
            outcome: RequestOutcome::Succeeded,
            error_code: None,
            duration_ms: 1,
            approval_id: None,
            created_at: 10004,
        })
        .await
        .expect("logger should recover after database contention");
}

#[tokio::test]
async fn catalog_state_keeps_missing_boot_sentinels_fail_closed() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let config = AppConfig::new(directory.path().to_path_buf());
    let app = ExecutorApp::open(config.clone())
        .await
        .expect("initial open should succeed");
    app.catalog()
        .create_source(
            CreateSource {
                kind: SourceKind::Graphql,
                preferred_slug: "state".to_owned(),
                display_name: "State".to_owned(),
                description: None,
                configuration: Map::new(),
            },
            AuditContext::system(None),
        )
        .await
        .expect("source should create");
    sqlx::query("DELETE FROM setup_state")
        .execute(app.pool())
        .await
        .expect("setup state should delete");
    sqlx::query("DELETE FROM instance_metadata WHERE key = 'boot_sentinel'")
        .execute(app.pool())
        .await
        .expect("sentinel should delete");
    app.pool().close().await;
    drop(app);
    let Err(error) = ExecutorApp::open(config).await else {
        panic!("catalog state without sentinel must fail closed");
    };
    assert!(matches!(error, DatabaseError::MissingBootSentinel));
}

#[tokio::test]
async fn catalog_api_preserves_auth_planes_csrf_and_global_token_equivalence() {
    let executor = TestExecutor::new().await;
    let source = executor.source("tools").await;
    assert_eq!(source.slug, "tools_2");
    executor
        .sync(&source.id, vec![staged("run", "Run", ToolMode::Enabled)])
        .await;
    let tool = executor
        .app
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
    executor.setup_admin().await;
    let admin = executor.login().await;
    let first_token = executor.create_api_token(&admin, "First").await;
    let second_token = executor.create_api_token(&admin, "Second").await;

    let admin_list = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/tools",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(admin_list.status(), StatusCode::OK);
    let admin_body = response_json(admin_list).await;
    assert_eq!(admin_body["total"], 1);
    assert!(admin_body["items"][0].get("inputSchema").is_none());
    assert!(admin_body["items"][0].get("inputTypescript").is_none());

    let admin_detail = send_empty(
        executor.router(),
        Method::GET,
        &format!("/api/v1/tools/{}", tool.id),
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(admin_detail.status(), StatusCode::OK);
    assert_eq!(
        response_json(admin_detail).await["inputSchema"]["type"],
        "object"
    );

    let bearer_control = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/tools",
        &[(
            header::AUTHORIZATION.as_str(),
            &format!("Bearer {first_token}"),
        )],
    )
    .await;
    assert_error(bearer_control, StatusCode::UNAUTHORIZED, "unauthorized").await;

    let session_gateway = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/gateway/tools/search",
        json!({ "query": "run" }),
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_error(session_gateway, StatusCode::UNAUTHORIZED, "unauthorized").await;

    let first_search = gateway_search_request(&executor, &first_token, "run").await;
    let second_search = gateway_search_request(&executor, &second_token, "run").await;
    assert_eq!(first_search, second_search);
    assert_eq!(first_search["total"], 1);
    let discovered_path = first_search["items"][0]["path"]
        .as_str()
        .expect("search should return a sandbox path")
        .to_owned();
    assert_eq!(discovered_path, "tools_2.run");
    let described = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/gateway/tools/describe",
        json!({ "path": discovered_path }),
        &[(
            header::AUTHORIZATION.as_str(),
            &format!("Bearer {first_token}"),
        )],
    )
    .await;
    assert_eq!(described.status(), StatusCode::OK);
    assert!(
        response_json(described).await["outputTypescript"]
            .as_str()
            .is_some_and(|output| output.contains("ToolError"))
    );

    let missing_csrf = send_json(
        executor.router(),
        Method::PATCH,
        &format!("/api/v1/tools/{}/mode", tool.id),
        json!({ "mode": "disabled", "expectedRevision": tool.revision }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
        ],
    )
    .await;
    assert_error(missing_csrf, StatusCode::FORBIDDEN, "invalid_csrf").await;

    let disabled = send_json(
        executor.router(),
        Method::PATCH,
        &format!("/api/v1/tools/{}/mode", tool.id),
        json!({ "mode": "disabled", "expectedRevision": tool.revision }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(disabled.status(), StatusCode::OK);
    let disabled_request_id = disabled
        .headers()
        .get("x-request-id")
        .expect("mutation should have a request ID")
        .to_str()
        .expect("request ID should be text")
        .to_owned();
    let disabled_body = response_json(disabled).await;
    assert_eq!(disabled_body["effectiveMode"]["mode"], "disabled");
    assert_eq!(
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT actor_admin_id FROM audit_events \
             WHERE request_id = ? AND action = 'tool.mode_changed'",
        )
        .bind(disabled_request_id)
        .fetch_one(executor.app.pool())
        .await
        .expect("administrator audit actor should read"),
        Some(1)
    );
    let disabled_revision = disabled_body["revision"]
        .as_i64()
        .expect("updated revision should be an integer");

    let missing_mode = send_json(
        executor.router(),
        Method::PATCH,
        &format!("/api/v1/tools/{}/mode", tool.id),
        json!({ "expectedRevision": disabled_revision }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_error(missing_mode, StatusCode::BAD_REQUEST, "invalid_json").await;
    assert_eq!(
        executor
            .app
            .catalog()
            .tool(&tool.id)
            .await
            .expect("tool should remain disabled")
            .mode_override,
        Some(ToolMode::Disabled)
    );

    assert_eq!(
        gateway_search_request(&executor, &first_token, "run").await["total"],
        0
    );
    assert_eq!(
        gateway_search_request(&executor, &second_token, "run").await["total"],
        0
    );
    let guarded = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/gateway/tools/lookup",
        json!({ "path": tool.callable_path }),
        &[(
            header::AUTHORIZATION.as_str(),
            &format!("Bearer {first_token}"),
        )],
    )
    .await;
    assert_error(guarded, StatusCode::FORBIDDEN, "tool_disabled").await;

    let logs = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let logs = executor
                .app
                .catalog()
                .list_request_logs(None, 20)
                .await
                .expect("gateway calls should be readable");
            let disabled_call_recorded = logs.items.iter().any(|log| {
                log.path_snapshot.as_deref() == Some(tool.callable_path.as_str())
                    && log.error_code.as_deref() == Some("tool_disabled")
            });
            let actor_count = logs
                .items
                .iter()
                .filter_map(|log| log.actor_api_token_id.as_deref())
                .collect::<std::collections::HashSet<_>>()
                .len();
            if disabled_call_recorded && actor_count == 2 {
                break logs;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("queued gateway logs should be stored");
    assert!(logs.items.iter().any(|log| {
        log.path_snapshot.as_deref() == Some(tool.callable_path.as_str())
            && log.error_code.as_deref() == Some("tool_disabled")
    }));
    assert_eq!(
        logs.items
            .iter()
            .filter_map(|log| log.actor_api_token_id.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        2
    );

    let log_list = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/request-logs?limit=1",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(log_list.status(), StatusCode::OK);
    let log_body = response_json(log_list).await;
    let log_id = log_body["items"][0]["requestId"]
        .as_str()
        .expect("log list should return request ID");
    let log_detail = send_empty(
        executor.router(),
        Method::GET,
        &format!("/api/v1/request-logs/{log_id}"),
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(log_detail.status(), StatusCode::OK);

    let catalog_revision = executor
        .app
        .catalog()
        .global_revision()
        .await
        .expect("catalog revision should read");
    let explicit_bulk = send_json(
        executor.router(),
        Method::PATCH,
        "/api/v1/tools/modes",
        json!({
            "selection": {
                "type": "tool_ids",
                "toolIds": [tool.id],
                "expectedCatalogRevision": catalog_revision
            },
            "mode": "enabled"
        }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(explicit_bulk.status(), StatusCode::OK);
    assert_eq!(response_json(explicit_bulk).await["updatedCount"], 1);

    let source_revision = executor
        .app
        .catalog()
        .source(&source.id)
        .await
        .expect("source should exist")
        .revision;
    let source_bulk = send_json(
        executor.router(),
        Method::PATCH,
        "/api/v1/tools/modes",
        json!({
            "selection": {
                "type": "source",
                "sourceId": source.id,
                "expectedSourceRevision": source_revision
            },
            "mode": "ask"
        }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(source_bulk.status(), StatusCode::OK);
    assert_eq!(response_json(source_bulk).await["updatedCount"], 1);

    let ask_lookup = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/gateway/tools/lookup",
        json!({ "path": discovered_path }),
        &[(
            header::AUTHORIZATION.as_str(),
            &format!("Bearer {second_token}"),
        )],
    )
    .await;
    assert_eq!(ask_lookup.status(), StatusCode::OK);
    assert_eq!(response_json(ask_lookup).await["requiresApproval"], true);

    let sources = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/sources",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(sources.status(), StatusCode::OK);
    assert_eq!(
        response_json(sources).await["sources"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let source_detail = send_empty(
        executor.router(),
        Method::GET,
        &format!("/api/v1/sources/{}", source.id),
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(source_detail.status(), StatusCode::OK);
    let source_body = response_json(source_detail).await;
    let source_revision = source_body["revision"]
        .as_i64()
        .expect("source revision should be an integer");
    let source_mode = send_json(
        executor.router(),
        Method::PATCH,
        &format!("/api/v1/sources/{}/mode", source.id),
        json!({ "mode": "disabled", "expectedRevision": source_revision }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(source_mode.status(), StatusCode::OK);
    let deleted = send_empty(
        executor.router(),
        Method::DELETE,
        &format!("/api/v1/sources/{}", source.id),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn gateway_auth_stays_responsive_during_token_timestamp_contention() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let admin = executor.login().await;
    let token = executor.create_api_token(&admin, "Contention").await;
    let outside_writer = executor
        .app
        .pool()
        .begin_with("BEGIN IMMEDIATE")
        .await
        .expect("outside writer should reserve SQLite");

    for _ in 0..2 {
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            gateway_whoami_burst(&executor, &token, 24),
        )
        .await
        .expect("authentication reads should not wait for the timestamp writer");
    }

    outside_writer
        .commit()
        .await
        .expect("outside writer should commit");
    for _ in 0..100 {
        let last_used = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_used_at FROM api_tokens WHERE name = 'Contention'",
        )
        .fetch_one(executor.app.pool())
        .await
        .expect("last-used timestamp should be readable");
        if last_used.is_some() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the coalesced last-used update should settle after contention clears");
}

async fn gateway_whoami_burst(executor: &TestExecutor, token: &str, requests: usize) {
    let mut requests_in_flight = tokio::task::JoinSet::new();
    for _ in 0..requests {
        let router = executor.router();
        let authorization = format!("Bearer {token}");
        requests_in_flight.spawn(async move {
            send_empty(
                router,
                Method::GET,
                "/api/v1/gateway/whoami",
                &[(header::AUTHORIZATION.as_str(), &authorization)],
            )
            .await
            .status()
        });
    }
    while let Some(response) = requests_in_flight.join_next().await {
        assert_eq!(
            response.expect("gateway authentication task should not panic"),
            StatusCode::OK
        );
    }
}

async fn gateway_search_request(executor: &TestExecutor, token: &str, query: &str) -> Value {
    let response = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/gateway/tools/search",
        json!({ "query": query, "limit": 10, "offset": 0 }),
        &[(header::AUTHORIZATION.as_str(), &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

async fn send_json(
    router: Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .oneshot(
            request
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should answer")
}

async fn send_empty(
    router: Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .oneshot(request.body(Body::empty()).expect("request should build"))
        .await
        .expect("router should answer")
}

fn response_cookie_header(response: &Response<Body>) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("set-cookie should be text")
                .split(';')
                .next()
                .expect("cookie should contain a value")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn response_json(response: Response<Body>) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body should collect")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("response should contain JSON")
}

async fn assert_error(response: Response<Body>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("error should have a request ID")
        .to_str()
        .expect("request ID should be text")
        .to_owned();
    let body = response_json(response).await;
    assert_eq!(body["error"]["code"], code);
    assert_eq!(body["error"]["requestId"], request_id);
}
