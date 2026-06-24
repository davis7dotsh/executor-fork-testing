use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};

use crate::{
    AppConfig, ExecutorApp,
    actor::ToolActor,
    catalog::{InvocationRevisionToken, ModeProvenance, RequestSurface},
    crypto::Keyring,
};
use serde_json::json;

use super::{
    ApprovalDecision, ApprovalError, ApprovalListQuery, ApprovalStatus, ApprovalStore, Clock,
    ExecutionOutcome, NewApproval,
};

struct TestClock(AtomicI64);

impl TestClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

async fn approval_store() -> (
    tempfile::TempDir,
    ExecutorApp,
    ApprovalStore,
    Arc<TestClock>,
) {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    sqlx::query(
        "INSERT INTO admins (id, username, password_hash, created_at) VALUES (1, 'admin', 'hash', 1)",
    )
    .execute(app.pool())
    .await
    .expect("admin fixture should insert");
    sqlx::query(
        "INSERT INTO api_tokens (id, name, token_digest, token_prefix, token_suffix, created_at) \
         VALUES ('token-1', 'Automation', ?, 'exe_test', 'last', 1)",
    )
    .bind(vec![7_u8; 32])
    .execute(app.pool())
    .await
    .expect("token fixture should insert");
    sqlx::query("UPDATE approval_clock SET effective_now = 0 WHERE id = 1")
        .execute(app.pool())
        .await
        .expect("test clock high-water should reset");
    let clock = Arc::new(TestClock::new(1_000));
    let store = ApprovalStore::new(
        app.pool().clone(),
        Keyring::random().expect("test keyring should generate"),
        clock.clone(),
    );
    (directory, app, store, clock)
}

fn new_approval(execution_id: &str, call_id: &str) -> NewApproval {
    NewApproval {
        execution_id: execution_id.to_owned(),
        call_id: call_id.to_owned(),
        worker_generation: 0,
        actor: ToolActor::api_token("token-1", Some("Automation".to_owned())),
        surface: RequestSurface::Gateway,
        callable_path_snapshot: "weather.delete_forecast".to_owned(),
        source_display_name_snapshot: Some("Weather".to_owned()),
        tool_display_name_snapshot: Some("Delete forecast".to_owned()),
        mode_provenance: ModeProvenance::Intrinsic,
        revisions: InvocationRevisionToken {
            source_id: "source-1".to_owned(),
            tool_id: "tool-1".to_owned(),
            source_revision: 11,
            catalog_revision: 12,
            tool_revision: 13,
            binding_revision: 14,
            credential_revision: Some(15),
        },
        arguments: json!({ "location": "secret-location" }),
        input_schema: json!({
            "type": "object",
            "required": ["location"],
            "properties": { "location": { "type": "string" } }
        }),
        output_schema: Some(json!({ "type": "object" })),
        invocation_snapshot: json!({ "binding": "exact-secret-binding" }),
    }
}

fn local_approval(execution_id: &str, call_id: &str, actor: ToolActor) -> NewApproval {
    let mut approval = new_approval(execution_id, call_id);
    approval.actor = actor;
    approval.surface = RequestSurface::Cli;
    approval
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
async fn snapshots_are_encrypted_bounded_and_exposed_only_through_the_right_views() {
    let (directory, app, store, _clock) = approval_store().await;
    let created = store
        .create(new_approval("execution-1", "call-1"))
        .await
        .expect("approval should persist");

    assert_eq!(created.record.status, ApprovalStatus::Pending);
    assert_eq!(created.record.expires_at, 1_600);
    assert_eq!(created.record.revisions.source_revision, 11);
    assert_eq!(
        created.redacted_arguments,
        json!({ "location": "[redacted]" })
    );
    assert_eq!(created.input_schema["required"], json!(["location"]));
    assert!(
        store
            .get_for_token(&created.record.id, "another-token")
            .await
            .expect("owner lookup should read")
            .is_none()
    );

    let approved = store
        .decide(
            &created.record.id,
            "decision-snapshot",
            created.record.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("snapshot approval should be accepted");
    let execution = store
        .claim_execution(&created.record.id, 0, approved.record.revision)
        .await
        .expect("execution snapshot should be claimed");
    assert_eq!(
        execution.arguments,
        json!({ "location": "secret-location" })
    );
    assert_eq!(execution.output_schema, Some(json!({ "type": "object" })));
    assert_eq!(
        execution.invocation_snapshot["binding"],
        "exact-secret-binding"
    );
    let stored = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT arguments_ciphertext, redacted_arguments_ciphertext, \
         input_schema_ciphertext, invocation_snapshot_ciphertext FROM approvals WHERE id = ?",
    )
    .bind(&created.record.id)
    .fetch_one(app.pool())
    .await
    .expect("ciphertexts should read");
    for ciphertext in [stored.0, stored.1, stored.2, stored.3] {
        assert!(
            !ciphertext
                .windows(b"secret-location".len())
                .any(|part| part == b"secret-location")
        );
        assert!(
            !ciphertext
                .windows(b"exact-secret-binding".len())
                .any(|part| part == b"exact-secret-binding")
        );
    }
    for name in ["executor.db", "executor.db-wal", "executor.db-shm"] {
        let path = directory.path().join(name);
        if path.exists() {
            let bytes = std::fs::read(path).expect("SQLite storage should be readable");
            assert!(
                !bytes
                    .windows(b"secret-location".len())
                    .any(|part| part == b"secret-location")
            );
            assert!(
                !bytes
                    .windows(b"exact-secret-binding".len())
                    .any(|part| part == b"exact-secret-binding")
            );
        }
    }

    let oversized = "x".repeat(8 * 1024 * 1024 + 1);
    let mut approval = new_approval("execution-big", "call-big");
    approval.arguments = json!(oversized);
    assert!(matches!(
        store.create(approval).await,
        Err(ApprovalError::PayloadTooLarge {
            label: "arguments",
            ..
        })
    ));
}

#[tokio::test]
async fn decisions_are_cas_guarded_idempotent_and_follow_the_legal_transition_graph() {
    let (_directory, app, store, _clock) = approval_store().await;
    let created = store
        .create(new_approval("execution-2", "call-2"))
        .await
        .expect("approval should persist");
    let approved = store
        .decide(
            &created.record.id,
            "decision-retry-with-new-id",
            created.record.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("approval should be accepted");
    assert!(!approved.idempotent);
    assert_eq!(approved.record.status, ApprovalStatus::Approved);

    let replay = store
        .decide(
            &created.record.id,
            "decision-1",
            created.record.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("identical decision should replay");
    assert!(replay.idempotent);
    assert_eq!(replay.record.revision, approved.record.revision);
    let audits = sqlx::query_as::<_, (String, String, i64, String, String)>(
        "SELECT request_id, action, actor_admin_id, target_path_snapshot, metadata_json \
         FROM audit_events WHERE action = 'approval.approve'",
    )
    .fetch_all(app.pool())
    .await
    .expect("approval audit should read");
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].0, "decision-retry-with-new-id");
    assert_eq!(audits[0].1, "approval.approve");
    assert_eq!(audits[0].2, 1);
    assert_eq!(audits[0].3, "weather.delete_forecast");
    let metadata: serde_json::Value =
        serde_json::from_str(&audits[0].4).expect("audit metadata should be JSON");
    assert_eq!(metadata["approvalId"], created.record.id);
    assert_eq!(metadata["from"], "pending");
    assert_eq!(metadata["to"], "approved");
    assert_eq!(metadata["revision"], 1);
    assert!(!audits[0].4.contains("secret-location"));
    assert!(matches!(
        store
            .decide(
                &created.record.id,
                "decision-2",
                approved.record.revision,
                ApprovalDecision::Deny,
                1,
            )
            .await,
        Err(ApprovalError::DecisionConflict)
    ));

    let executing = store
        .claim_execution(&created.record.id, 0, approved.record.revision)
        .await
        .expect("approved call should enter executing");
    assert!(matches!(
        store
            .cancel_token_owner(&created.record.id, "token-1", executing.record.revision)
            .await,
        Err(ApprovalError::InvalidTransition {
            status: ApprovalStatus::Executing
        })
    ));
    let completed = store
        .finish(
            &created.record.id,
            executing.record.revision,
            ExecutionOutcome::Succeeded,
            &json!({ "ok": true, "secretResult": "private" }),
            None,
        )
        .await
        .expect("execution should complete");
    assert_eq!(completed.status, ApprovalStatus::Succeeded);
    let terminal_replay = store
        .decide(
            &created.record.id,
            "decision-after-completion",
            0,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("the same decision should remain idempotent after completion");
    assert!(terminal_replay.idempotent);
    assert_eq!(terminal_replay.record.status, ApprovalStatus::Succeeded);
    let owner = store
        .get_for_token(&created.record.id, "token-1")
        .await
        .expect("owner lookup should read")
        .expect("owner lookup should exist");
    assert_eq!(
        owner.result,
        Some(json!({ "ok": true, "secretResult": "private" }))
    );
    let admin = store
        .get_admin(&created.record.id)
        .await
        .expect("admin lookup should read")
        .expect("admin lookup should exist");
    let serialized = serde_json::to_string(&admin).expect("admin detail should serialize");
    assert!(!serialized.contains("secretResult"));
    assert!(!serialized.contains("private"));
}

#[tokio::test]
async fn owner_cancellation_is_idempotent_and_decision_races_have_one_winner() {
    let (_directory, _app, store, _clock) = approval_store().await;
    let canceled = store
        .create(new_approval("execution-cancel", "call-cancel"))
        .await
        .expect("cancelable approval should persist");
    let duplicate = store
        .create(new_approval("execution-cancel", "call-cancel"))
        .await
        .expect("identical duplicate should recover the approval");
    assert!(duplicate.reused);
    assert_eq!(duplicate.record.id, canceled.record.id);
    let canceled = store
        .cancel_token_owner(&canceled.record.id, "token-1", 0)
        .await
        .expect("owner cancellation should succeed");
    let replay = store
        .cancel_token_owner(&canceled.id, "token-1", 0)
        .await
        .expect("owner cancellation replay should be idempotent");
    assert_eq!(replay.status, ApprovalStatus::Canceled);
    assert_eq!(replay.revision, canceled.revision);

    let raced = store
        .create(new_approval("execution-race", "call-race"))
        .await
        .expect("raced approval should persist");
    let approve_store = store.clone();
    let approve_id = raced.record.id.clone();
    let approve = tokio::spawn(async move {
        approve_store
            .decide(&approve_id, "race-approve", 0, ApprovalDecision::Approve, 1)
            .await
    });
    let deny_store = store.clone();
    let deny_id = raced.record.id;
    let deny = tokio::spawn(async move {
        deny_store
            .decide(&deny_id, "race-deny", 0, ApprovalDecision::Deny, 1)
            .await
    });
    let outcomes = [
        approve.await.expect("approve task should join"),
        deny.await.expect("deny task should join"),
    ];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(ApprovalError::DecisionConflict)))
            .count(),
        1
    );
}

#[tokio::test]
async fn concurrent_identical_creates_recover_one_correlated_approval() {
    let (_directory, app, store, _clock) = approval_store().await;
    let first_store = store.clone();
    let second_store = store.clone();
    let (first, second) = tokio::join!(
        first_store.create(new_approval("execution-create-race", "call-create-race")),
        second_store.create(new_approval("execution-create-race", "call-create-race")),
    );
    let first = first.expect("first concurrent create should resolve");
    let second = second.expect("second concurrent create should resolve");

    assert_eq!(first.record.id, second.record.id);
    assert_ne!(first.reused, second.reused);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approvals WHERE execution_id = ? AND call_id = ?",
        )
        .bind("execution-create-race")
        .bind("call-create-race")
        .fetch_one(app.pool())
        .await
        .expect("approval count should read"),
        1
    );
}

#[tokio::test]
async fn duplicate_correlation_requires_matching_request_identity_without_catalog_revisions() {
    let (_directory, _app, store, _clock) = approval_store().await;
    let created = store
        .create(new_approval("execution-correlation", "call-correlation"))
        .await
        .expect("approval should persist");

    let mut catalog_changed = new_approval("execution-correlation", "call-correlation");
    catalog_changed.revisions.source_revision += 100;
    catalog_changed.revisions.catalog_revision += 100;
    catalog_changed.revisions.tool_revision += 100;
    catalog_changed.revisions.binding_revision += 100;
    catalog_changed.revisions.credential_revision = Some(500);
    let recovered = store
        .create(catalog_changed)
        .await
        .expect("catalog changes should not break caller retry correlation");
    assert!(recovered.reused);
    assert_eq!(recovered.record.id, created.record.id);

    let mut different_arguments = new_approval("execution-correlation", "call-correlation");
    different_arguments.arguments = json!({ "location": "different" });
    assert!(matches!(
        store.create(different_arguments).await,
        Err(ApprovalError::CorrelationConflict)
    ));

    let mut different_path = new_approval("execution-correlation", "call-correlation");
    different_path.callable_path_snapshot = "weather.create_forecast".to_owned();
    assert!(matches!(
        store.create(different_path).await,
        Err(ApprovalError::CorrelationConflict)
    ));

    let mut different_surface = new_approval("execution-correlation", "call-correlation");
    different_surface.surface = RequestSurface::Mcp;
    assert!(matches!(
        store.create(different_surface).await,
        Err(ApprovalError::CorrelationConflict)
    ));

    let mut different_generation = new_approval("execution-correlation", "call-correlation");
    different_generation.worker_generation += 1;
    assert!(matches!(
        store.create(different_generation).await,
        Err(ApprovalError::CorrelationConflict)
    ));
}

#[tokio::test]
async fn duplicate_correlation_is_actor_typed_and_never_returns_another_actors_record() {
    let (_directory, app, store, _clock) = approval_store().await;
    sqlx::query(
        "INSERT INTO api_tokens (id, name, token_digest, token_prefix, token_suffix, created_at) \
         VALUES ('1', 'Other actor', ?, 'exe_other', 'last', 1)",
    )
    .bind(vec![8_u8; 32])
    .execute(app.pool())
    .await
    .expect("second token fixture should insert");
    let mut original = new_approval("execution-cross-actor", "call-cross-actor");
    original.actor = ToolActor::admin(1);
    let created = store
        .create(original)
        .await
        .expect("admin approval should persist");
    let mut cross_actor = new_approval("execution-cross-actor", "call-cross-actor");
    cross_actor.actor = ToolActor::api_token("1", Some("Other actor".to_owned()));
    let cross_actor = store
        .create(cross_actor)
        .await
        .expect("another actor should have an isolated correlation namespace");
    assert!(!cross_actor.reused);
    assert_ne!(cross_actor.record.id, created.record.id);
    assert!(
        store
            .get_for_actor(
                &created.record.id,
                &ToolActor::api_token("1", Some("Other actor".to_owned())),
            )
            .await
            .expect("cross-actor lookup should read")
            .is_none()
    );
    assert!(
        store
            .get_for_actor(&cross_actor.record.id, &ToolActor::admin(1))
            .await
            .expect("reverse cross-actor lookup should read")
            .is_none()
    );
}

#[tokio::test]
async fn duplicate_correlation_uses_canonical_argument_object_order() {
    let (_directory, _app, store, _clock) = approval_store().await;
    let mut first = new_approval("execution-canonical", "call-canonical");
    first.arguments =
        serde_json::from_str(r#"{"b":2,"a":{"y":2,"x":1}}"#).expect("first arguments should parse");
    let created = store.create(first).await.expect("approval should persist");
    let mut reordered = new_approval("execution-canonical", "call-canonical");
    reordered.arguments = serde_json::from_str(r#"{"a":{"x":1,"y":2},"b":2}"#)
        .expect("reordered arguments should parse");
    let recovered = store
        .create(reordered)
        .await
        .expect("equivalent arguments should recover the approval");

    assert!(recovered.reused);
    assert_eq!(recovered.record.id, created.record.id);

    let mut integer = new_approval("execution-number-type", "call-number-type");
    integer.arguments =
        serde_json::from_str(r#"{"value":1}"#).expect("integer arguments should parse");
    store
        .create(integer)
        .await
        .expect("integer approval should persist");
    let mut decimal = new_approval("execution-number-type", "call-number-type");
    decimal.arguments =
        serde_json::from_str(r#"{"value":1.0}"#).expect("decimal arguments should parse");
    assert!(matches!(
        store.create(decimal).await,
        Err(ApprovalError::CorrelationConflict)
    ));
}

#[tokio::test]
async fn retained_correlation_prevents_recreation_after_approval_payload_retention() {
    let (_directory, app, store, _clock) = approval_store().await;
    let created = store
        .create(new_approval("execution-retired", "call-retired"))
        .await
        .expect("approval should persist");
    store
        .decide(
            &created.record.id,
            "deny-before-payload-retention",
            created.record.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("approval should become terminal before payload retention");
    sqlx::query("DELETE FROM approvals WHERE id = ?")
        .bind(&created.record.id)
        .execute(app.pool())
        .await
        .expect("retention simulation should remove approval payload");

    assert!(matches!(
        store
            .create(new_approval("execution-retired", "call-retired"))
            .await,
        Err(ApprovalError::CorrelationRetired)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approvals WHERE actor_kind = 'api_token' AND actor_id = 'token-1' \
             AND execution_id = ? AND call_id = ?",
        )
        .bind("execution-retired")
        .bind("call-retired")
        .fetch_one(app.pool())
        .await
        .expect("approval count should read"),
        0
    );
}

#[tokio::test]
async fn terminal_correlation_is_retained_for_the_full_ttl_then_reclaimed() {
    let (_directory, app, store, clock) = approval_store().await;
    clock.set(2_000);
    let created = store
        .create(new_approval("execution-terminal-ttl", "call-terminal-ttl"))
        .await
        .expect("approval should persist");
    store
        .decide(
            &created.record.id,
            "deny-terminal-ttl",
            created.record.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("approval should become terminal");
    let expires_at = sqlx::query_scalar::<_, i64>(
        "SELECT expires_at FROM approval_correlations WHERE approval_id = ?",
    )
    .bind(&created.record.id)
    .fetch_one(app.pool())
    .await
    .expect("correlation expiry should read");
    assert_eq!(expires_at, 2_000 + super::APPROVAL_CORRELATION_TTL_SECONDS);

    clock.set(expires_at - 1);
    let early_retry = store
        .create(new_approval("execution-terminal-ttl", "call-terminal-ttl"))
        .await
        .expect("retry before correlation expiry should recover the approval");
    assert!(early_retry.reused);
    assert_eq!(early_retry.record.id, created.record.id);

    clock.set(expires_at);
    let reused_call = store
        .create(new_approval("execution-terminal-ttl", "call-terminal-ttl"))
        .await
        .expect("call at correlation expiry should start a new approval");
    assert!(!reused_call.reused);
    assert_ne!(reused_call.record.id, created.record.id);
    assert!(
        store
            .get_admin(&created.record.id)
            .await
            .expect("retired approval lookup should read")
            .is_none()
    );
}

#[tokio::test]
async fn expired_terminal_correlation_waits_for_delivery_pin_release_before_reclamation() {
    let (_directory, app, store, clock) = approval_store().await;
    clock.set(3_000);
    let mut request = new_approval("execution-pinned-correlation", "call-pinned-correlation");
    request.worker_generation = 7;
    let created = store
        .create(request)
        .await
        .expect("pinned approval should persist");
    store
        .decide(
            &created.record.id,
            "deny-pinned-correlation",
            created.record.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("pinned approval should become terminal");
    let expires_at = sqlx::query_scalar::<_, i64>(
        "SELECT expires_at FROM approval_correlations WHERE approval_id = ?",
    )
    .bind(&created.record.id)
    .fetch_one(app.pool())
    .await
    .expect("pinned correlation expiry should read");

    clock.set(expires_at);
    store
        .create(new_approval(
            "execution-pinned-cleanup-before",
            "call-pinned-cleanup-before",
        ))
        .await
        .expect("cleanup should skip the pinned terminal correlation");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approval_correlations WHERE approval_id = ?",
        )
        .bind(&created.record.id)
        .fetch_one(app.pool())
        .await
        .expect("pinned correlation should read"),
        1
    );

    store
        .release_delivery_pin(&super::ApprovalDeliveryIdentity {
            approval_id: created.record.id.clone(),
            actor: ToolActor::api_token("token-1", Some("Automation".to_owned())),
            execution_id: created.record.execution_id.clone(),
            call_id: created.record.call_id.clone(),
        })
        .await
        .expect("delivery pin should release after terminal result delivery");
    store
        .create(new_approval(
            "execution-pinned-cleanup-after",
            "call-pinned-cleanup-after",
        ))
        .await
        .expect("cleanup should reclaim the unpinned expired correlation");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approval_correlations WHERE approval_id = ?",
        )
        .bind(&created.record.id)
        .fetch_one(app.pool())
        .await
        .expect("reclaimed correlation should read"),
        0
    );
    assert!(
        store
            .get_admin(&created.record.id)
            .await
            .expect("reclaimed approval should read")
            .is_none()
    );
}

#[tokio::test]
async fn nonterminal_correlation_never_expires_or_gets_reclaimed() {
    let (_directory, app, store, clock) = approval_store().await;
    let created = store
        .create(new_approval(
            "execution-active-correlation",
            "call-active-correlation",
        ))
        .await
        .expect("approval should persist");
    let approved = store
        .decide(
            &created.record.id,
            "approve-active-correlation",
            created.record.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("approval should remain nonterminal");
    assert!(
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT expires_at FROM approval_correlations WHERE approval_id = ?",
        )
        .bind(&approved.record.id)
        .fetch_one(app.pool())
        .await
        .expect("active correlation expiry should read")
        .is_none()
    );

    clock.set(1_000 + super::APPROVAL_CORRELATION_TTL_SECONDS * 2);
    store
        .create(new_approval(
            "execution-active-cleanup-trigger",
            "call-active-cleanup-trigger",
        ))
        .await
        .expect("unrelated create should run correlation cleanup");
    let retry = store
        .create(new_approval(
            "execution-active-correlation",
            "call-active-correlation",
        ))
        .await
        .expect("active correlation should remain recoverable");
    assert!(retry.reused);
    assert_eq!(retry.record.id, approved.record.id);
}

#[tokio::test]
async fn live_gateway_idempotency_retention_extends_correlation_protection() {
    let (_directory, app, store, clock) = approval_store().await;
    let created = store
        .create(new_approval(
            "execution-idempotency-guard",
            "call-idempotency-guard",
        ))
        .await
        .expect("approval should persist");
    store
        .decide(
            &created.record.id,
            "deny-idempotency-guard",
            created.record.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("approval should become terminal");
    let correlation_expiry = 1_000 + super::APPROVAL_CORRELATION_TTL_SECONDS;
    let idempotency_expiry = correlation_expiry + 60;
    sqlx::query(
        "INSERT INTO gateway_invocation_idempotency ( \
             id, owner_api_token_id, key_digest, request_digest, state, approval_id, \
             created_at, updated_at, completed_at, expires_at \
         ) VALUES (?, 'token-1', ?, ?, 'indeterminate', ?, 1000, 1000, 1000, ?)",
    )
    .bind("idempotency-correlation-guard")
    .bind(vec![3_u8; 32])
    .bind(vec![4_u8; 32])
    .bind(&created.record.id)
    .bind(idempotency_expiry)
    .execute(app.pool())
    .await
    .expect("idempotency retention fixture should insert");

    clock.set(correlation_expiry);
    let protected = store
        .create(new_approval(
            "execution-idempotency-guard",
            "call-idempotency-guard",
        ))
        .await
        .expect("live idempotency should preserve the correlation");
    assert!(protected.reused);
    assert_eq!(protected.record.id, created.record.id);

    clock.set(idempotency_expiry);
    let reclaimed = store
        .create(new_approval(
            "execution-idempotency-guard",
            "call-idempotency-guard",
        ))
        .await
        .expect("expired idempotency should release the correlation");
    assert!(!reclaimed.reused);
    assert_ne!(reclaimed.record.id, created.record.id);
}

#[tokio::test]
async fn reserved_gateway_idempotency_linkage_prevents_correlation_reclamation() {
    let (_directory, app, store, clock) = approval_store().await;
    let mut approval = new_approval("gateway-idempotency:reserved-correlation-guard", "gateway");
    approval.worker_generation = 0;
    let created = store
        .create(approval.clone())
        .await
        .expect("approval should persist");
    store
        .decide(
            &created.record.id,
            "deny-reserved-correlation-guard",
            created.record.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("approval should become terminal");
    sqlx::query(
        "INSERT INTO gateway_invocation_idempotency ( \
             id, owner_api_token_id, key_digest, request_digest, state, \
             created_at, updated_at \
         ) VALUES (?, 'token-1', ?, ?, 'reserved', 1000, 1000)",
    )
    .bind("reserved-correlation-guard")
    .bind(vec![5_u8; 32])
    .bind(vec![6_u8; 32])
    .execute(app.pool())
    .await
    .expect("reserved idempotency fixture should insert");

    clock.set(1_000 + super::APPROVAL_CORRELATION_TTL_SECONDS);
    let protected = store
        .create(approval.clone())
        .await
        .expect("reserved idempotency should preserve its execution-linked correlation");
    assert!(protected.reused);
    assert_eq!(protected.record.id, created.record.id);

    sqlx::query("DELETE FROM gateway_invocation_idempotency WHERE id = ?")
        .bind("reserved-correlation-guard")
        .execute(app.pool())
        .await
        .expect("reserved idempotency fixture should clear");
    let reclaimed = store
        .create(approval)
        .await
        .expect("released reservation should permit correlation reclamation");
    assert!(!reclaimed.reused);
    assert_ne!(reclaimed.record.id, created.record.id);
}

#[tokio::test]
async fn correlation_capacity_fails_closed_without_blocking_existing_retries() {
    let (_directory, app, store, _clock) = approval_store().await;
    let existing = store
        .create(new_approval("execution-cap-existing", "call-cap-existing"))
        .await
        .expect("existing correlation should persist");
    sqlx::query("UPDATE approval_correlation_state SET correlation_count = 100000 WHERE id = 1")
        .execute(app.pool())
        .await
        .expect("correlation capacity fixture should update");

    let recovered = store
        .create(new_approval("execution-cap-existing", "call-cap-existing"))
        .await
        .expect("existing correlation should remain recoverable at capacity");
    assert!(recovered.reused);
    assert_eq!(recovered.record.id, existing.record.id);
    assert!(matches!(
        store
            .create(new_approval("execution-cap-new", "call-cap-new"))
            .await,
        Err(ApprovalError::Capacity {
            scope: "correlations"
        })
    ));
}

#[tokio::test]
async fn expired_terminal_correlation_recovers_capacity_before_new_insert() {
    let (_directory, app, store, clock) = approval_store().await;
    let created = store
        .create(new_approval("execution-cap-reclaim", "call-cap-reclaim"))
        .await
        .expect("approval should persist");
    store
        .decide(
            &created.record.id,
            "deny-cap-reclaim",
            created.record.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("approval should become terminal");
    sqlx::query("UPDATE approval_correlation_state SET correlation_count = 100000 WHERE id = 1")
        .execute(app.pool())
        .await
        .expect("correlation capacity fixture should update");
    clock.set(1_000 + super::APPROVAL_CORRELATION_TTL_SECONDS);

    let created_after_reclaim = store
        .create(new_approval(
            "execution-cap-after-reclaim",
            "call-cap-after-reclaim",
        ))
        .await
        .expect("expired terminal correlation should reclaim capacity first");
    assert!(!created_after_reclaim.reused);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT correlation_count FROM approval_correlation_state WHERE id = 1",
        )
        .fetch_one(app.pool())
        .await
        .expect("correlation count should read"),
        100_000
    );
}

#[tokio::test]
async fn terminal_log_ids_are_unique_for_sibling_calls_in_one_execution() {
    let (_directory, _app, store, _clock) = approval_store().await;
    let first = store
        .create(new_approval("shared-execution", "first-call"))
        .await
        .expect("first sibling approval should persist");
    let second = store
        .create(new_approval("shared-execution", "second-call"))
        .await
        .expect("second sibling approval should persist");
    for (index, approval) in [first, second].into_iter().enumerate() {
        store
            .decide(
                &approval.record.id,
                &format!("sibling-deny-{index}"),
                approval.record.revision,
                ApprovalDecision::Deny,
                1,
            )
            .await
            .expect("sibling approval should be denied");
    }
    let events = store
        .log_outbox(10)
        .await
        .expect("approval log outbox should read");
    let unique_ids = events
        .iter()
        .map(|event| event.request_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(events.len(), 2);
    assert_eq!(unique_ids.len(), 2);
}

#[tokio::test]
async fn token_activity_caps_and_monotonic_clock_are_enforced_at_storage_boundaries() {
    let (_directory, app, store, clock) = approval_store().await;
    clock.set(5_000);
    let first = store
        .create(new_approval("execution-clock-1", "call-clock-1"))
        .await
        .expect("first clock approval should persist");
    clock.set(100);
    let second = store
        .create(new_approval("execution-clock-2", "call-clock-2"))
        .await
        .expect("backward clock approval should persist");
    assert_eq!(first.record.created_at, 5_000);
    assert_eq!(second.record.created_at, 5_000);
    assert_eq!(second.record.expires_at, 5_600);
    clock.set(5_599);
    assert_eq!(store.expire_pending().await.expect("expiry should run"), 0);
    clock.set(5_600);
    assert_eq!(store.expire_pending().await.expect("expiry should run"), 2);

    clock.set(6_000);
    let approved = store
        .create(new_approval("execution-revoke-race", "call-revoke-race"))
        .await
        .expect("approval should persist");
    let approved = store
        .decide(
            &approved.record.id,
            "approve-before-revoke",
            0,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("approval should be accepted");
    assert!(matches!(
        store
            .claim_execution(&approved.record.id, 4, approved.record.revision,)
            .await,
        Err(ApprovalError::WorkerGenerationConflict)
    ));
    sqlx::query("UPDATE api_tokens SET revoked_at = 6_001 WHERE id = 'token-1'")
        .execute(app.pool())
        .await
        .expect("token should revoke");
    assert!(matches!(
        store
            .claim_execution(&approved.record.id, 0, approved.record.revision,)
            .await,
        Err(ApprovalError::OwnerTokenInactive)
    ));
    assert!(matches!(
        store
            .create(new_approval("execution-after-revoke", "call-after-revoke"))
            .await,
        Err(ApprovalError::OwnerTokenInactive)
    ));

    sqlx::query("UPDATE api_tokens SET revoked_at = NULL WHERE id = 'token-1'")
        .execute(app.pool())
        .await
        .expect("token should reactivate for capacity fixture");
    store
        .cancel_token("token-1")
        .await
        .expect("active approvals should clear");
    for index in 0..128 {
        store
            .create(new_approval(
                &format!("execution-cap-{index}"),
                &format!("call-cap-{index}"),
            ))
            .await
            .expect("approval below the owner cap should persist");
    }
    assert!(matches!(
        store
            .create(new_approval("execution-over-cap", "call-over-cap"))
            .await,
        Err(ApprovalError::Capacity { scope: "owner" })
    ));
    clock.set(6_600);
    store
        .create(new_approval(
            "execution-after-cap-expiry",
            "call-after-cap-expiry",
        ))
        .await
        .expect("create should reclaim expired capacity in the same transaction");
}

#[tokio::test]
async fn local_actors_are_isolated_from_gateway_ownership_and_token_revocation() {
    let (_directory, app, store, _clock) = approval_store().await;
    let admin = store
        .create(local_approval(
            "execution-admin",
            "call-admin",
            ToolActor::admin(1),
        ))
        .await
        .expect("admin-owned approval should persist without a synthetic token");
    let system = store
        .create(local_approval(
            "execution-system",
            "call-system",
            ToolActor::local_cli(),
        ))
        .await
        .expect("system-owned approval should persist without a synthetic token");
    let token = store
        .create(new_approval("execution-token", "call-token"))
        .await
        .expect("token-owned approval should persist");

    assert_eq!(admin.record.actor_kind, crate::actor::ActorKind::Admin);
    assert_eq!(admin.record.actor_api_token_id, None);
    assert_eq!(system.record.actor_kind, crate::actor::ActorKind::System);
    assert_eq!(system.record.actor_api_token_id, None);
    assert!(
        store
            .get_for_token(&admin.record.id, "token-1")
            .await
            .expect("gateway lookup should read")
            .is_none()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_tokens")
            .fetch_one(app.pool())
            .await
            .expect("token count should read"),
        1
    );

    assert!(
        store
            .revoke_owner_token("token-1")
            .await
            .expect("token revocation should run")
    );
    assert_eq!(
        store
            .get_admin(&token.record.id)
            .await
            .expect("token approval should read")
            .expect("token approval should exist")
            .record
            .status,
        ApprovalStatus::Canceled
    );
    for local in [&admin, &system] {
        assert_eq!(
            store
                .get_admin(&local.record.id)
                .await
                .expect("local approval should read")
                .expect("local approval should exist")
                .record
                .status,
            ApprovalStatus::Pending
        );
    }

    let approved = store
        .decide(
            &admin.record.id,
            "approve-admin",
            admin.record.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("admin-owned approval should be approved");
    store
        .claim_execution(&admin.record.id, 0, approved.record.revision)
        .await
        .expect("admin-owned approval should execute without a token check");
    let denied = store
        .decide(
            &system.record.id,
            "deny-system",
            system.record.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("system-owned approval should be denied");
    assert_eq!(denied.record.status, ApprovalStatus::Denied);
    assert!(
        store
            .log_outbox(256)
            .await
            .expect("outbox should read")
            .iter()
            .any(|event| {
                event.approval_id.as_deref() == Some(system.record.id.as_str())
                    && event.actor_api_token_id.is_none()
            })
    );
}

#[tokio::test]
async fn aggregate_ciphertext_caps_bound_active_and_terminal_disk_usage() {
    let (_directory, _app, store, _clock) = approval_store().await;
    let large = "x".repeat(7 * 1024 * 1024);
    let mut ids = Vec::new();
    for index in 0..4 {
        let mut approval = new_approval(
            &format!("execution-bytes-{index}"),
            &format!("call-bytes-{index}"),
        );
        approval.arguments = json!({ "location": large });
        approval.invocation_snapshot = json!(large);
        let created = store
            .create(approval)
            .await
            .expect("approval below aggregate byte cap should persist");
        ids.push(created.record.id);
    }
    let mut over_cap = new_approval("execution-bytes-over", "call-bytes-over");
    over_cap.arguments = json!({ "location": large });
    over_cap.invocation_snapshot = json!(large);
    assert!(matches!(
        store.create(over_cap).await,
        Err(ApprovalError::Capacity {
            scope: "active_bytes"
        })
    ));

    for (index, id) in ids.iter().enumerate().skip(1) {
        store
            .decide(
                id,
                &format!("deny-bytes-{index}"),
                0,
                ApprovalDecision::Deny,
                1,
            )
            .await
            .expect("large approval should be denied");
    }
    let mut newest = new_approval("execution-bytes-newest", "call-bytes-newest");
    newest.arguments = json!({ "location": large });
    newest.invocation_snapshot = json!(large);
    let newest = store
        .create(newest)
        .await
        .expect("terminal rows should not consume active byte capacity");
    store
        .decide(
            &newest.record.id,
            "deny-bytes-newest",
            0,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("newest large approval should be denied");
    store
        .decide(
            &ids[0],
            "deny-old-active-last",
            0,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("old active approval should be retained when it terminalizes last");
    assert!(
        store
            .get_admin(&ids[1])
            .await
            .expect("oldest approval lookup should read")
            .is_none()
    );
    assert!(
        store
            .get_admin(&ids[0])
            .await
            .expect("newly terminal old approval should read")
            .is_some()
    );
    assert!(
        store
            .get_admin(&newest.record.id)
            .await
            .expect("newest approval lookup should read")
            .is_some()
    );
    let outbox = store
        .log_outbox(256)
        .await
        .expect("terminal log outbox should read");
    assert!(
        outbox
            .iter()
            .any(|event| event.approval_id.as_deref() == Some(ids[1].as_str())),
        "terminal logging metadata must survive approval retention"
    );
}

#[tokio::test]
async fn delivery_pins_preserve_sixteen_large_results_until_each_waiter_copies_its_own_result() {
    let (_directory, app, store, _clock) = approval_store().await;
    let payload = "r".repeat(super::MAX_APPROVAL_RESULT_BYTES - 512);
    let actor = ToolActor::api_token("token-1", Some("Automation".to_owned()));
    let mut prepared = Vec::new();

    for index in 0..16 {
        let mut request = new_approval(
            &format!("execution-large-result-{index}"),
            &format!("call-large-result-{index}"),
        );
        request.worker_generation = 9;
        let pending = store
            .create(request)
            .await
            .expect("pinned approval should persist");
        let approved = store
            .decide(
                &pending.record.id,
                &format!("approve-large-result-{index}"),
                pending.record.revision,
                ApprovalDecision::Approve,
                1,
            )
            .await
            .expect("large result approval should be approved");
        let executing = store
            .claim_execution(&pending.record.id, 9, approved.record.revision)
            .await
            .expect("large result approval should execute");
        let result = json!({ "index": index, "payload": payload });
        prepared.push((pending.record, executing.record.revision, result));
    }

    let barrier = Arc::new(tokio::sync::Barrier::new(prepared.len() + 1));
    let mut completions = Vec::new();
    for (record, revision, result) in prepared {
        let finish_store = store.clone();
        let finish_barrier = barrier.clone();
        completions.push(tokio::spawn(async move {
            finish_barrier.wait().await;
            finish_store
                .finish(
                    &record.id,
                    revision,
                    ExecutionOutcome::Succeeded,
                    &result,
                    None,
                )
                .await
                .expect("concurrent large result should become terminal while pinned");
            (record, result)
        }));
    }
    barrier.wait().await;
    let mut completed = Vec::new();
    for completion in completions {
        completed.push(
            completion
                .await
                .expect("concurrent large result task should join"),
        );
    }

    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approval_delivery_pins")
            .fetch_one(app.pool())
            .await
            .expect("delivery pin count should read"),
        16
    );
    for (record, expected) in &completed {
        let copied = store
            .get_for_actor(&record.id, &actor)
            .await
            .expect("pinned result should read")
            .expect("pinned result must not be retained away");
        assert_eq!(copied.result.as_ref(), Some(expected));
    }
    for (record, _) in &completed {
        store
            .release_delivery_pin(&super::ApprovalDeliveryIdentity {
                approval_id: record.id.clone(),
                actor: actor.clone(),
                execution_id: record.execution_id.clone(),
                call_id: record.call_id.clone(),
            })
            .await
            .expect("copied result should become reclaimable");
    }

    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approval_delivery_pins")
            .fetch_one(app.pool())
            .await
            .expect("delivery pins should read"),
        0
    );
    let retained_bytes = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(length(arguments_ciphertext) \
         + length(redacted_arguments_ciphertext) + length(input_schema_ciphertext) \
         + COALESCE(length(output_schema_ciphertext), 0) \
         + length(invocation_snapshot_ciphertext) + COALESCE(length(result_ciphertext), 0)), 0) \
         FROM approvals WHERE status IN \
         ('denied', 'expired', 'canceled', 'succeeded', 'failed', 'stale', 'interrupted')",
    )
    .fetch_one(app.pool())
    .await
    .expect("terminal ciphertext usage should read");
    assert!(retained_bytes <= super::MAX_TERMINAL_APPROVAL_CIPHERTEXT_BYTES);
    let mut evicted = 0;
    for (record, _) in &completed {
        if store
            .get_admin(&record.id)
            .await
            .expect("reclaimed approval lookup should read")
            .is_none()
        {
            evicted += 1;
        }
    }
    assert!(evicted > 0);
}

#[tokio::test]
async fn delivery_pin_retries_are_refcounted_bounded_and_cleared_by_recovery() {
    let (_directory, app, store, _clock) = approval_store().await;
    let actor = ToolActor::api_token("token-1", Some("Automation".to_owned()));
    let mut retry_request = new_approval("execution-pin-retry", "call-pin-retry");
    retry_request.worker_generation = 1;
    let retried = store
        .create(retry_request.clone())
        .await
        .expect("initial pinned approval should persist");
    store
        .create(retry_request)
        .await
        .expect("duplicate retry should acquire another delivery reference");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT ref_count FROM approval_delivery_pins WHERE approval_id = ?",
        )
        .bind(&retried.record.id)
        .fetch_one(app.pool())
        .await
        .expect("delivery refcount should read"),
        2
    );
    let retry_identity = super::ApprovalDeliveryIdentity {
        approval_id: retried.record.id.clone(),
        actor: actor.clone(),
        execution_id: retried.record.execution_id.clone(),
        call_id: retried.record.call_id.clone(),
    };
    assert!(
        store
            .release_delivery_pin(&retry_identity)
            .await
            .expect("first retry reference should release")
    );
    assert!(
        store
            .release_delivery_pin(&retry_identity)
            .await
            .expect("second retry reference should release")
    );
    let mut pinned = Vec::new();
    for index in 0..super::MAX_APPROVAL_DELIVERY_PINS {
        let mut request = new_approval(
            &format!("execution-pin-cap-{index}"),
            &format!("call-pin-cap-{index}"),
        );
        request.worker_generation = 1;
        let created = store
            .create(request)
            .await
            .expect("approval below delivery pin cap should persist");
        store
            .decide(
                &created.record.id,
                &format!("deny-pin-cap-{index}"),
                created.record.revision,
                ApprovalDecision::Deny,
                1,
            )
            .await
            .expect("denial should free active approval capacity");
        pinned.push(created.record);
    }
    let mut over_cap = new_approval("execution-pin-over-cap", "call-pin-over-cap");
    over_cap.worker_generation = 1;
    assert!(matches!(
        store.create(over_cap).await,
        Err(ApprovalError::Capacity {
            scope: "delivery_pins"
        })
    ));

    let first = &pinned[0];
    let identity = super::ApprovalDeliveryIdentity {
        approval_id: first.id.clone(),
        actor,
        execution_id: first.execution_id.clone(),
        call_id: first.call_id.clone(),
    };
    assert!(
        store
            .release_delivery_pin(&identity)
            .await
            .expect("pin releases")
    );
    assert!(
        !store
            .release_delivery_pin(&identity)
            .await
            .expect("release replays")
    );

    store
        .recover_startup()
        .await
        .expect("startup recovery should clear stale continuation pins");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approval_delivery_pins")
            .fetch_one(app.pool())
            .await
            .expect("delivery pins should read"),
        0
    );
}

#[tokio::test]
async fn expiry_token_revocation_and_startup_recovery_are_durable() {
    let (_directory, _app, store, clock) = approval_store().await;
    let expiring = store
        .create(new_approval("execution-expire", "call-expire"))
        .await
        .expect("expiring approval should persist");
    clock.set(1_600);
    assert_eq!(store.expire_pending().await.expect("expiry should run"), 1);
    assert_eq!(
        store
            .get_admin(&expiring.record.id)
            .await
            .expect("approval should read")
            .expect("approval should exist")
            .record
            .status,
        ApprovalStatus::Expired
    );
    assert!(matches!(
        store
            .decide(
                &expiring.record.id,
                "decision-too-late",
                expiring.record.revision,
                ApprovalDecision::Approve,
                1,
            )
            .await,
        Err(ApprovalError::Expired)
    ));

    clock.set(2_000);
    let mut interrupted_request = new_approval("execution-interrupted", "call-interrupted");
    interrupted_request.worker_generation = 3;
    let interrupted = store
        .create(interrupted_request)
        .await
        .expect("interrupted approval should persist");
    let interrupted = store
        .decide(
            &interrupted.record.id,
            "decision-interrupted",
            0,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("approval should be accepted");
    let interrupted = store
        .claim_execution(&interrupted.record.id, 3, interrupted.record.revision)
        .await
        .expect("approval should execute");
    let mut orphan_pending_request =
        new_approval("execution-orphan-pending", "call-orphan-pending");
    orphan_pending_request.worker_generation = 3;
    let orphan_pending = store
        .create(orphan_pending_request)
        .await
        .expect("orphan pending approval should persist");
    let mut orphan_approved_request =
        new_approval("execution-orphan-approved", "call-orphan-approved");
    orphan_approved_request.worker_generation = 3;
    let orphan_approved = store
        .create(orphan_approved_request)
        .await
        .expect("orphan approved approval should persist");
    let orphan_approved = store
        .decide(
            &orphan_approved.record.id,
            "decision-orphan-approved",
            0,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("orphan approval should be accepted before restart");
    let mut direct_approval = new_approval("execution-approved", "call-approved");
    direct_approval.worker_generation = 0;
    let recoverable = store
        .create(direct_approval)
        .await
        .expect("recoverable approval should persist");
    let recoverable = store
        .decide(
            &recoverable.record.id,
            "decision-approved",
            0,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("approval should be accepted");
    let recovery = store
        .recover_startup()
        .await
        .expect("startup recovery should run");
    assert_eq!(recovery.interrupted_count, 1);
    assert_eq!(recovery.approved_ids, vec![recoverable.record.id.clone()]);
    assert_eq!(
        store
            .get_admin(&orphan_pending.record.id)
            .await
            .expect("orphan pending should read")
            .expect("orphan pending should exist")
            .record
            .status,
        ApprovalStatus::Canceled
    );
    assert_eq!(
        store
            .get_admin(&orphan_approved.record.id)
            .await
            .expect("orphan approved should read")
            .expect("orphan approved should exist")
            .record
            .status,
        ApprovalStatus::Stale
    );
    assert_eq!(
        store
            .get_admin(&interrupted.record.id)
            .await
            .expect("approval should read")
            .expect("approval should exist")
            .record
            .status,
        ApprovalStatus::Interrupted
    );

    let revoked = store
        .create(new_approval("execution-revoked", "call-revoked"))
        .await
        .expect("revoked-token approval should persist");
    let retained = store
        .create(new_approval("execution-retained", "call-retained"))
        .await
        .expect("executing approval should persist");
    let retained = store
        .decide(
            &retained.record.id,
            "decision-retained",
            0,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("executing approval should be accepted");
    let retained = store
        .claim_execution(&retained.record.id, 0, retained.record.revision)
        .await
        .expect("executing approval should start");
    assert!(
        store
            .revoke_owner_token("token-1")
            .await
            .expect("atomic revocation should run")
    );
    assert!(
        !store
            .revoke_owner_token("token-1")
            .await
            .expect("repeat revocation should read")
    );
    assert_eq!(
        store
            .get_admin(&revoked.record.id)
            .await
            .expect("approval should read")
            .expect("approval should exist")
            .record
            .status,
        ApprovalStatus::Canceled
    );
    assert_eq!(
        store
            .get_admin(&retained.record.id)
            .await
            .expect("approval should read")
            .expect("approval should exist")
            .record
            .status,
        ApprovalStatus::Executing
    );

    let page = store
        .list_admin(ApprovalListQuery {
            limit: 2,
            ..Default::default()
        })
        .await
        .expect("approval page should list");
    assert_eq!(page.items.len(), 2);
    assert!(page.next_cursor.is_some());
}

#[tokio::test]
async fn terminal_outbox_survives_restart_until_durable_log_acknowledgement() {
    let (directory, app, store, _clock) = approval_store().await;
    let pending = store
        .create(new_approval("execution-restart-log", "call-restart-log"))
        .await
        .expect("restart approval should persist");
    store
        .decide(
            &pending.record.id,
            "direct-deny-before-restart",
            pending.record.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("direct denial should commit its outbox event");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approval_log_outbox WHERE approval_id = ?",
        )
        .bind(&pending.record.id)
        .fetch_one(app.pool())
        .await
        .expect("outbox count should read"),
        1
    );

    drop(store);
    drop(app);

    let config = AppConfig::new(directory.path().to_path_buf());
    let reopened = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match ExecutorApp::open(config.clone()).await {
                Ok(app) => break app,
                Err(crate::DatabaseError::AlreadyRunning(_)) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(error) => panic!("Executor should reopen: {error}"),
            }
        }
    })
    .await
    .expect("background request logger should release the instance lock");
    wait_for_terminal_log(&reopened, &pending.record.id, "approval_denied").await;
}
