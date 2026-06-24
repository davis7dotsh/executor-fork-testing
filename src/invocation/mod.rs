use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use thiserror::Error;

use crate::{
    actor::ToolActor,
    approval::{
        ApprovalAdminDetail, ApprovalDecision, ApprovalDeliveryIdentity, ApprovalError,
        ApprovalOwnerDetail, ApprovalRecord, ApprovalStatus, ApprovalStore, ExecutionOutcome,
        NewApproval,
    },
    catalog::{
        CatalogError, CatalogStore, InvocationLease, ListToolsFilter, NewRequestLog,
        RequestOutcome, RequestSurface, ToolMode,
    },
    crypto::Keyring,
    outbound::OutboundError,
    protocols::{
        PreparedProtocolInvocation, ProtocolError, ProtocolInvocationError, ProtocolRegistry,
    },
    request_logs::RequestLogSink,
    tasks::TaskTracker,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, RwLock, Semaphore, oneshot};

mod idempotency;

use idempotency::{
    CorrelatedApproval, GatewayIdempotencyStore, IdempotencyClaim, IdempotencyError,
    IdempotencyOwner, IdempotencyRecord, IdempotencyRequest, IdempotencyResponse,
    IdempotencyResponseKind, idempotency_execution_id,
};

const APPROVAL_EXECUTION_CONCURRENCY: usize = 16;
const GATEWAY_INVOKE_ROUTE: &str = "POST /api/v1/gateway/tools/invoke";

pub const MAX_ARGUMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn gateway_idempotency_key_is_valid(key: &str) -> bool {
    idempotency::validate_key(key).is_ok()
}

#[derive(Clone, Debug)]
pub struct ToolCall {
    pub request_id: String,
    pub actor: ToolActor,
    pub surface: RequestSurface,
    pub execution_id: String,
    pub call_id: String,
    /// Zero identifies a directly resumable call. Sandbox generations start at one and are never
    /// replayed after their worker continuation has been lost.
    pub worker_generation: u64,
    pub path: String,
    pub arguments: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    pub ok: bool,
    pub data: Option<Value>,
    pub error: Option<PublicToolError>,
    pub http: Option<ToolHttpMetadata>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicToolError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ToolHttpMetadata {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub truncated: bool,
}

#[derive(Debug, Error)]
pub enum ToolCallError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error("{message}")]
    Adapter { code: &'static str, message: String },
    #[error("tool arguments exceed the allowed size")]
    ArgumentsTooLarge,
    #[error("tool arguments do not match the input schema")]
    InvalidArguments,
    #[error("the invocation changed before it could execute")]
    Stale,
    #[error(transparent)]
    Outbound(#[from] OutboundError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("the tool result exceeds the allowed size")]
    ResultTooLarge,
}

#[derive(Clone)]
pub struct ToolCallService {
    catalog: CatalogStore,
    protocols: ProtocolRegistry,
    approvals: ApprovalStore,
    approval_queries: ApprovalQueries,
    idempotency: GatewayIdempotencyStore,
    request_logs: RequestLogSink,
    approval_notifications: ApprovalNotificationRegistry,
    global_approval_notify: Arc<Notify>,
    expiry_slot: Arc<Semaphore>,
    next_expiry_scan: Arc<Mutex<Instant>>,
    approval_log_flush: Arc<Semaphore>,
    approval_log_requested: Arc<AtomicBool>,
    discovery_slots: Arc<Semaphore>,
    execution_slots: Arc<Semaphore>,
    in_flight_approvals: Arc<Mutex<HashSet<String>>>,
    deferred_execution_cancellations: Arc<RwLock<HashSet<String>>>,
    execution_stopping_flags: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    background_tasks: TaskTracker,
}

#[derive(Clone)]
pub struct ApprovalQueries {
    approvals: ApprovalStore,
}

impl ApprovalQueries {
    pub async fn get_admin(
        &self,
        approval_id: &str,
    ) -> Result<Option<ApprovalAdminDetail>, ApprovalError> {
        self.approvals.get_admin(approval_id).await
    }

    pub async fn get_for_token(
        &self,
        approval_id: &str,
        actor_api_token_id: &str,
    ) -> Result<Option<ApprovalOwnerDetail>, ApprovalError> {
        self.approvals
            .get_for_token(approval_id, actor_api_token_id)
            .await
    }

    pub async fn list_admin(
        &self,
        query: crate::approval::ApprovalListQuery,
    ) -> Result<crate::approval::ApprovalPage, ApprovalError> {
        self.approvals.list_admin(query).await
    }
}

#[derive(Debug)]
pub enum ToolCallSubmission {
    Completed(ToolResult),
    ApprovalRequired(ApprovalRequired),
}

pub struct ApprovalRequired {
    record: Box<ApprovalRecord>,
    delivery: Option<ApprovalDeliveryTicket>,
}

impl std::fmt::Debug for ApprovalRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalRequired")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for ApprovalRequired {
    type Target = ApprovalRecord;

    fn deref(&self) -> &Self::Target {
        &self.record
    }
}

struct ApprovalDeliveryTicket {
    identity: Option<ApprovalDeliveryIdentity>,
    approvals: ApprovalStore,
    notifications: ApprovalNotificationRegistry,
    tasks: TaskTracker,
}

impl ApprovalDeliveryTicket {
    async fn release(&mut self) {
        let Some(identity) = self.identity.take() else {
            return;
        };
        if let Err(error) = self.approvals.release_delivery_pin(&identity).await {
            tracing::warn!(
                approval_id = identity.approval_id,
                error = %error,
                "approval delivery pin release will retry"
            );
            self.identity = Some(identity);
            return;
        }
        notify_registry(&self.notifications, &identity.approval_id);
    }
}

impl Drop for ApprovalDeliveryTicket {
    fn drop(&mut self) {
        let Some(identity) = self.identity.take() else {
            return;
        };
        let approvals = self.approvals.clone();
        let notifications = self.notifications.clone();
        self.tasks.spawn(async move {
            let mut delay = Duration::from_millis(25);
            loop {
                match approvals.release_delivery_pin(&identity).await {
                    Ok(_) => {
                        notify_registry(&notifications, &identity.approval_id);
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            approval_id = identity.approval_id,
                            error = %error,
                            "approval delivery pin cleanup will retry"
                        );
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
        });
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GatewayInvokeResponse {
    pub response: IdempotencyResponse,
    pub replayed: bool,
}

#[derive(Debug, Error)]
pub(crate) enum GatewayInvokeError {
    #[error(transparent)]
    ToolCall(#[from] ToolCallError),
    #[error("the Idempotency-Key is invalid")]
    InvalidKey,
    #[error("gateway idempotency capacity has been reached")]
    Capacity,
    #[error("gateway idempotency failed: {0}")]
    Idempotency(String),
    #[error("the Idempotency-Key was already used for a different invocation")]
    KeyMismatch,
    #[error("the idempotent invocation is still in progress")]
    InProgress,
    #[error("the idempotent invocation outcome is unknown")]
    OutcomeUnknown,
}

impl From<IdempotencyError> for GatewayInvokeError {
    fn from(error: IdempotencyError) -> Self {
        match error {
            IdempotencyError::InvalidKey => Self::InvalidKey,
            IdempotencyError::Capacity => Self::Capacity,
            error => Self::Idempotency(error.to_string()),
        }
    }
}

#[derive(Debug, Error)]
pub enum ApprovalWaitError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    #[error("approval wait was canceled")]
    Canceled,
}

#[derive(Debug, Error)]
pub enum ToolDiscoveryError {
    #[error("tool search is busy")]
    Busy,
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error("tool discovery task was interrupted")]
    Interrupted,
}

type ApprovalNotificationRegistry = Arc<Mutex<HashMap<String, ApprovalNotificationEntry>>>;

struct ApprovalNotificationEntry {
    notify: Arc<Notify>,
    waiters: usize,
}

struct ApprovalWaitRegistration {
    approval_id: String,
    notify: Arc<Notify>,
    registry: ApprovalNotificationRegistry,
}

struct IdempotencyReservationGuard {
    record: IdempotencyRecord,
    store: GatewayIdempotencyStore,
    approvals: ApprovalStore,
    tasks: TaskTracker,
    armed: bool,
}

impl IdempotencyReservationGuard {
    fn new(
        record: IdempotencyRecord,
        store: GatewayIdempotencyStore,
        approvals: ApprovalStore,
        tasks: TaskTracker,
    ) -> Self {
        Self {
            record,
            store,
            approvals,
            tasks,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for IdempotencyReservationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let id = self.record.id.clone();
        let record = self.record.clone();
        let store = self.store.clone();
        let approvals = self.approvals.clone();
        self.tasks.spawn(async move {
            let mut delay = Duration::from_millis(25);
            loop {
                match settle_abandoned_reservation(&store, &approvals, &record).await {
                    Ok(()) => break,
                    Err(error) => {
                        tracing::warn!(idempotency_id = id, error = %error, "idempotency reservation cleanup will retry");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
        });
    }
}

async fn settle_abandoned_reservation(
    store: &GatewayIdempotencyStore,
    approvals: &ApprovalStore,
    record: &IdempotencyRecord,
) -> Result<(), String> {
    match store
        .correlated_approval_id(record)
        .await
        .map_err(|error| error.to_string())?
    {
        Some(CorrelatedApproval::Live(approval_id)) => {
            let approval = approvals
                .get_admin(&approval_id)
                .await
                .map_err(|error| error.to_string())?;
            let Some(approval) = approval else {
                return store
                    .abandon(&record.id)
                    .await
                    .map_err(|error| error.to_string());
            };
            let response = match approval_required_response(&approval.record) {
                Ok(response) => response,
                Err(_) => {
                    terminalize_idempotency(store, &record.id).await;
                    return Ok(());
                }
            };
            match store
                .complete(
                    &record.id,
                    IdempotencyResponseKind::Approval,
                    &response,
                    Some(&approval_id),
                )
                .await
            {
                Ok(_) | Err(IdempotencyError::InvalidTransition("completed" | "indeterminate")) => {
                    Ok(())
                }
                Err(_) => {
                    terminalize_idempotency(store, &record.id).await;
                    Ok(())
                }
            }
        }
        Some(CorrelatedApproval::Retired) | None => store
            .abandon(&record.id)
            .await
            .map_err(|error| error.to_string()),
    }
}

struct IdempotencyExecutionGuard {
    id: String,
    store: GatewayIdempotencyStore,
    tasks: TaskTracker,
    armed: bool,
}

impl IdempotencyExecutionGuard {
    fn new(id: String, store: GatewayIdempotencyStore, tasks: TaskTracker) -> Self {
        Self {
            id,
            store,
            tasks,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for IdempotencyExecutionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let id = self.id.clone();
        let store = self.store.clone();
        self.tasks.spawn(async move {
            let mut delay = Duration::from_millis(25);
            loop {
                match store.mark_indeterminate(&id).await {
                    Ok(_)
                    | Err(IdempotencyError::InvalidTransition(
                        "completed" | "indeterminate",
                    )) => break,
                    Err(error) => {
                        tracing::error!(idempotency_id = id, error = %error, "uncertain invocation terminalization will retry");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
        });
    }
}

struct IdempotencyAskCompletionGuard {
    id: String,
    approval_id: String,
    response: IdempotencyResponse,
    store: GatewayIdempotencyStore,
    tasks: TaskTracker,
    armed: bool,
}

impl IdempotencyAskCompletionGuard {
    fn new(
        id: String,
        approval_id: String,
        response: IdempotencyResponse,
        store: GatewayIdempotencyStore,
        tasks: TaskTracker,
    ) -> Self {
        Self {
            id,
            approval_id,
            response,
            store,
            tasks,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for IdempotencyAskCompletionGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let id = self.id.clone();
        let approval_id = self.approval_id.clone();
        let response = self.response.clone();
        let store = self.store.clone();
        self.tasks.spawn(async move {
            match store
                .complete(
                    &id,
                    IdempotencyResponseKind::Approval,
                    &response,
                    Some(&approval_id),
                )
                .await
            {
                Ok(_) | Err(IdempotencyError::InvalidTransition("completed")) => {}
                Err(_) => terminalize_idempotency(&store, &id).await,
            }
        });
    }
}

async fn terminalize_idempotency(store: &GatewayIdempotencyStore, id: &str) {
    let mut delay = Duration::from_millis(25);
    loop {
        match store.mark_indeterminate(id).await {
            Ok(_)
            | Err(IdempotencyError::InvalidTransition("completed" | "indeterminate"))
            | Err(IdempotencyError::NotFound) => return,
            Err(error) => {
                tracing::error!(idempotency_id = id, error = %error, "idempotency terminalization will retry");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
}

impl Drop for ApprovalWaitRegistration {
    fn drop(&mut self) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove = registry.get_mut(&self.approval_id).is_some_and(|entry| {
            if !Arc::ptr_eq(&entry.notify, &self.notify) {
                return false;
            }
            entry.waiters = entry.waiters.saturating_sub(1);
            entry.waiters == 0
        });
        if remove {
            registry.remove(&self.approval_id);
        }
    }
}

impl ToolCallService {
    pub(crate) fn new(
        catalog: CatalogStore,
        protocols: ProtocolRegistry,
        pool: SqlitePool,
        keyring: Keyring,
        request_logs: RequestLogSink,
    ) -> Self {
        let idempotency = GatewayIdempotencyStore::new(pool.clone(), keyring.clone());
        let approvals = ApprovalStore::system(pool, keyring);
        Self {
            catalog,
            protocols,
            approval_queries: ApprovalQueries {
                approvals: approvals.clone(),
            },
            approvals,
            idempotency,
            request_logs,
            approval_notifications: Arc::new(Mutex::new(HashMap::new())),
            global_approval_notify: Arc::new(Notify::new()),
            expiry_slot: Arc::new(Semaphore::new(1)),
            next_expiry_scan: Arc::new(Mutex::new(Instant::now())),
            approval_log_flush: Arc::new(Semaphore::new(1)),
            approval_log_requested: Arc::new(AtomicBool::new(false)),
            discovery_slots: Arc::new(Semaphore::new(1)),
            execution_slots: Arc::new(Semaphore::new(APPROVAL_EXECUTION_CONCURRENCY)),
            in_flight_approvals: Arc::new(Mutex::new(HashSet::new())),
            deferred_execution_cancellations: Arc::new(RwLock::new(HashSet::new())),
            execution_stopping_flags: Arc::new(Mutex::new(HashMap::new())),
            background_tasks: TaskTracker::default(),
        }
    }

    pub fn approvals(&self) -> &ApprovalQueries {
        &self.approval_queries
    }

    pub(crate) fn discovery_slots(&self) -> Arc<Semaphore> {
        self.discovery_slots.clone()
    }

    pub(crate) fn record_rejected_request(
        &self,
        request_id: &str,
        actor_api_token_id: &str,
        surface: RequestSurface,
        path: &str,
        error_code: &str,
    ) {
        self.record(NewRequestLog {
            request_id: request_id.to_owned(),
            actor_api_token_id: Some(actor_api_token_id.to_owned()),
            surface,
            source_id: None,
            tool_id: None,
            path_snapshot: Some(path.to_owned()),
            outcome: RequestOutcome::Failed,
            error_code: Some(error_code.to_owned()),
            duration_ms: 0,
            approval_id: None,
            created_at: crate::unix_timestamp(),
        });
    }

    pub(crate) async fn shutdown(&self) {
        self.background_tasks.shutdown().await;
        self.settle_idempotency_shutdown().await;
        let mut delay = Duration::from_millis(25);
        loop {
            match self.approvals.clear_delivery_pins().await {
                Ok(_) => break,
                Err(error) => {
                    tracing::error!(error = %error, "shutdown approval delivery cleanup will retry");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            }
        }
        self.global_approval_notify.notify_waiters();
        self.request_logs.shutdown().await;
    }

    async fn settle_idempotency_shutdown(&self) {
        let mut delay = Duration::from_millis(25);
        loop {
            let result = async {
                let recovery = self
                    .idempotency
                    .recover_startup()
                    .await
                    .map_err(|error| error.to_string())?;
                for reservation in recovery.reserved {
                    settle_abandoned_reservation(&self.idempotency, &self.approvals, &reservation)
                        .await?;
                }
                Ok::<_, String>(())
            }
            .await;
            match result {
                Ok(()) => return,
                Err(error) => {
                    tracing::error!(error, "shutdown idempotency settlement will retry");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
            }
        }
    }

    pub(crate) fn abort_background_tasks(&self) {
        self.background_tasks.abort_all();
        self.request_logs.abort();
    }

    pub(crate) async fn recover_startup(&self) -> Result<(), ApprovalError> {
        let idempotency_recovery = self
            .idempotency
            .recover_startup()
            .await
            .map_err(idempotency_startup_error)?;
        for reservation in idempotency_recovery.reserved {
            let approval_id = self
                .idempotency
                .correlated_approval_id(&reservation)
                .await
                .map_err(idempotency_startup_error)?;
            let approval = match approval_id {
                Some(CorrelatedApproval::Live(approval_id)) => {
                    match self.approvals.get_admin(&approval_id).await? {
                        Some(approval) => approval,
                        None => {
                            terminalize_idempotency(&self.idempotency, &reservation.id).await;
                            continue;
                        }
                    }
                }
                Some(CorrelatedApproval::Retired) => {
                    self.idempotency
                        .mark_indeterminate(&reservation.id)
                        .await
                        .map_err(idempotency_startup_error)?;
                    continue;
                }
                None => {
                    self.idempotency
                        .release_reserved(&reservation.id)
                        .await
                        .map_err(idempotency_startup_error)?;
                    continue;
                }
            };
            let response = match approval_required_response(&approval.record) {
                Ok(response) => response,
                Err(_) => {
                    terminalize_idempotency(&self.idempotency, &reservation.id).await;
                    continue;
                }
            };
            if self
                .idempotency
                .complete(
                    &reservation.id,
                    IdempotencyResponseKind::Approval,
                    &response,
                    Some(&approval.record.id),
                )
                .await
                .is_err()
            {
                terminalize_idempotency(&self.idempotency, &reservation.id).await;
            }
        }
        let recovery = self.approvals.recover_startup().await?;
        self.schedule_approval_log_flush_if_pending().await?;
        for approval_id in &recovery.approved_ids {
            if self
                .approvals
                .get_admin(approval_id)
                .await?
                .is_some_and(|detail| detail.record.worker_generation == 0)
            {
                self.spawn_approved(approval_id.clone());
            }
        }
        Ok(())
    }

    pub async fn submit(&self, call: ToolCall) -> Result<ToolCallSubmission, ToolCallError> {
        let started = Instant::now();
        if let Some(actor_api_token_id) = call.actor.api_token_id()
            && !token_is_active(self.catalog.pool(), actor_api_token_id).await?
        {
            self.record_attempt(
                &call,
                None,
                None,
                RequestOutcome::Denied,
                Some("token_revoked"),
                None,
                started,
            );
            return Err(ApprovalError::OwnerTokenInactive.into());
        }
        let encoded_arguments =
            serde_json::to_vec(&call.arguments).map_err(|_| ToolCallError::InvalidArguments)?;
        if encoded_arguments.len() > MAX_ARGUMENT_BYTES {
            self.record_attempt(
                &call,
                None,
                None,
                RequestOutcome::Failed,
                Some("arguments_too_large"),
                None,
                started,
            );
            return Err(ToolCallError::ArgumentsTooLarge);
        }
        let preflight = match self.catalog.preflight_invocation(&call.path).await {
            Ok(preflight) => preflight,
            Err(error) => {
                let outcome = if matches!(error, CatalogError::ToolDisabled { .. }) {
                    RequestOutcome::Denied
                } else {
                    RequestOutcome::Failed
                };
                let error = ToolCallError::Catalog(error);
                let code = error_code(&error);
                self.record_attempt(&call, None, None, outcome, Some(code), None, started);
                return Err(error);
            }
        };
        if !preflight.arguments_are_valid(&call.arguments) {
            self.record_attempt(
                &call,
                Some(preflight.lookup().source_id.clone()),
                Some(preflight.lookup().tool_id.clone()),
                RequestOutcome::Failed,
                Some("invalid_tool_arguments"),
                None,
                started,
            );
            return Err(ToolCallError::InvalidArguments);
        }
        let token = preflight.revisions().clone();
        let lookup = preflight.lookup().clone();
        if lookup.requires_approval {
            let input_schema = preflight.input_schema().clone();
            drop(preflight);
            let invocation_snapshot = json!({
                "version": 1,
                "requestId": call.request_id.clone(),
                "actorKind": call.actor.kind(),
                "actorId": call.actor.id(),
                "actorApiTokenId": call.actor.api_token_id(),
                "surface": call.surface,
                "executionId": call.execution_id.clone(),
                "callId": call.call_id.clone(),
                "path": lookup.callable_path.clone(),
                "sourceId": lookup.source_id.clone(),
                "toolId": lookup.tool_id.clone(),
            });
            let service = self.clone();
            let (completed, result) = oneshot::channel();
            let spawned = self.background_tasks.spawn(async move {
                let pending = service
                    .approvals
                    .create(NewApproval {
                        execution_id: call.execution_id.clone(),
                        call_id: call.call_id.clone(),
                        worker_generation: call.worker_generation,
                        actor: call.actor.clone(),
                        surface: call.surface,
                        callable_path_snapshot: lookup.callable_path.clone(),
                        source_display_name_snapshot: Some(lookup.source_display_name.clone()),
                        tool_display_name_snapshot: Some(lookup.tool_display_name.clone()),
                        mode_provenance: lookup.mode_provenance,
                        revisions: token,
                        arguments: call.arguments.clone(),
                        input_schema,
                        output_schema: None,
                        invocation_snapshot,
                    })
                    .await;
                let submission = pending.map(|pending| {
                    let approval_id = pending.record.id.clone();
                    service.record_attempt(
                        &call,
                        Some(lookup.source_id),
                        Some(lookup.tool_id),
                        RequestOutcome::PendingApproval,
                        Some("approval_required"),
                        Some(approval_id),
                        started,
                    );
                    let delivery = pending.delivery_pin.then(|| ApprovalDeliveryTicket {
                        identity: Some(ApprovalDeliveryIdentity {
                            approval_id: pending.record.id.clone(),
                            actor: call.actor.clone(),
                            execution_id: call.execution_id.clone(),
                            call_id: call.call_id.clone(),
                        }),
                        approvals: service.approvals.clone(),
                        notifications: service.approval_notifications.clone(),
                        tasks: service.background_tasks.clone(),
                    });
                    ToolCallSubmission::ApprovalRequired(ApprovalRequired {
                        record: Box::new(pending.record),
                        delivery,
                    })
                });
                let _ = completed.send(submission.map_err(ToolCallError::from));
            });
            if !spawned {
                return Err(ToolCallError::Adapter {
                    code: "approval_persistence_unavailable",
                    message: "approval persistence is shutting down".to_owned(),
                });
            }
            return result.await.unwrap_or_else(|_| {
                Err(ToolCallError::Adapter {
                    code: "approval_persistence_interrupted",
                    message: "approval persistence was interrupted".to_owned(),
                })
            });
        }
        drop(preflight);
        let lease = self
            .catalog
            .revalidate_invocation(&token)
            .await?
            .ok_or(ToolCallError::Stale)?;
        let result = execute_with_lease(&self.protocols, lease, &call.arguments).await;
        match result {
            Ok(result) => {
                self.record_attempt(
                    &call,
                    Some(lookup.source_id),
                    Some(lookup.tool_id),
                    if result.ok {
                        RequestOutcome::Succeeded
                    } else {
                        RequestOutcome::Failed
                    },
                    (!result.ok).then_some("upstream_http_error"),
                    None,
                    started,
                );
                Ok(ToolCallSubmission::Completed(result))
            }
            Err(error) => {
                self.record_attempt(
                    &call,
                    Some(lookup.source_id),
                    Some(lookup.tool_id),
                    RequestOutcome::Failed,
                    Some(error_code(&error)),
                    None,
                    started,
                );
                Err(error)
            }
        }
    }

    pub(crate) async fn submit_gateway_idempotent(
        &self,
        mut call: ToolCall,
        key: &str,
    ) -> Result<GatewayInvokeResponse, GatewayInvokeError> {
        let started = Instant::now();
        let actor_api_token_id = call
            .actor
            .api_token_id()
            .ok_or(IdempotencyError::InvalidMetadata)?
            .to_owned();
        if call.surface != RequestSurface::Gateway {
            return Err(IdempotencyError::InvalidMetadata.into());
        }
        if !token_is_active(self.catalog.pool(), &actor_api_token_id)
            .await
            .map_err(ToolCallError::Approval)?
        {
            self.record_attempt(
                &call,
                None,
                None,
                RequestOutcome::Denied,
                Some("token_revoked"),
                None,
                started,
            );
            return Err(ToolCallError::Approval(ApprovalError::OwnerTokenInactive).into());
        }
        let encoded_arguments =
            serde_json::to_vec(&call.arguments).map_err(|_| ToolCallError::InvalidArguments)?;
        if encoded_arguments.len() > MAX_ARGUMENT_BYTES {
            self.record_attempt(
                &call,
                None,
                None,
                RequestOutcome::Failed,
                Some("arguments_too_large"),
                None,
                started,
            );
            return Err(ToolCallError::ArgumentsTooLarge.into());
        }
        let request_path = idempotency::canonical_callable_path(&call.path)?;
        if let Some(existing) = self
            .idempotency
            .lookup(IdempotencyRequest {
                owner: IdempotencyOwner {
                    owner_api_token_id: &actor_api_token_id,
                },
                key,
                route: GATEWAY_INVOKE_ROUTE,
                callable_path: &request_path,
                arguments: &call.arguments,
            })
            .await?
        {
            match existing {
                IdempotencyClaim::Replay { response, .. } => {
                    return Ok(GatewayInvokeResponse {
                        response,
                        replayed: true,
                    });
                }
                IdempotencyClaim::Mismatch => return Err(GatewayInvokeError::KeyMismatch),
                IdempotencyClaim::Indeterminate(_) => {
                    return Err(GatewayInvokeError::OutcomeUnknown);
                }
                IdempotencyClaim::InProgress(record) => {
                    if record.state == idempotency::IdempotencyState::Reserved
                        && let Some(response) = self
                            .reconcile_idempotent_approval(
                                &record,
                                &actor_api_token_id,
                                key,
                                &request_path,
                                &call.arguments,
                            )
                            .await?
                    {
                        return Ok(response);
                    }
                    return Err(GatewayInvokeError::InProgress);
                }
                IdempotencyClaim::Fresh(_) => {
                    return Err(GatewayInvokeError::Idempotency(
                        "lookup returned a fresh idempotency claim".to_owned(),
                    ));
                }
            }
        }
        let preflight = match self.catalog.preflight_invocation(&call.path).await {
            Ok(preflight) => preflight,
            Err(error) => {
                let outcome = if matches!(error, CatalogError::ToolDisabled { .. }) {
                    RequestOutcome::Denied
                } else {
                    RequestOutcome::Failed
                };
                let error = ToolCallError::Catalog(error);
                let code = error_code(&error);
                self.record_attempt(&call, None, None, outcome, Some(code), None, started);
                return Err(error.into());
            }
        };
        if !preflight.arguments_are_valid(&call.arguments) {
            self.record_attempt(
                &call,
                Some(preflight.lookup().source_id.clone()),
                Some(preflight.lookup().tool_id.clone()),
                RequestOutcome::Failed,
                Some("invalid_tool_arguments"),
                None,
                started,
            );
            return Err(ToolCallError::InvalidArguments.into());
        }
        let token = preflight.revisions().clone();
        let lookup = preflight.lookup().clone();
        let claim = self
            .idempotency
            .claim(IdempotencyRequest {
                owner: IdempotencyOwner {
                    owner_api_token_id: &actor_api_token_id,
                },
                key,
                route: GATEWAY_INVOKE_ROUTE,
                callable_path: &lookup.callable_path,
                arguments: &call.arguments,
            })
            .await?;
        let record = match claim {
            IdempotencyClaim::Fresh(record) => record,
            IdempotencyClaim::Replay { response, .. } => {
                return Ok(GatewayInvokeResponse {
                    response,
                    replayed: true,
                });
            }
            IdempotencyClaim::Mismatch => return Err(GatewayInvokeError::KeyMismatch),
            IdempotencyClaim::Indeterminate(_) => {
                return Err(GatewayInvokeError::OutcomeUnknown);
            }
            IdempotencyClaim::InProgress(record) => {
                if record.state == idempotency::IdempotencyState::Reserved
                    && let Some(response) = self
                        .reconcile_idempotent_approval(
                            &record,
                            &actor_api_token_id,
                            key,
                            &lookup.callable_path,
                            &call.arguments,
                        )
                        .await?
                {
                    return Ok(response);
                }
                return Err(GatewayInvokeError::InProgress);
            }
        };
        let mut reservation = IdempotencyReservationGuard::new(
            record,
            self.idempotency.clone(),
            self.approvals.clone(),
            self.background_tasks.clone(),
        );
        call.execution_id = idempotency_execution_id(&reservation.record.id);
        call.call_id = "gateway".to_owned();

        if lookup.requires_approval {
            let input_schema = preflight.input_schema().clone();
            let invocation_snapshot = json!({
                "version": 1,
                "requestId": call.request_id.clone(),
                "actorKind": call.actor.kind(),
                "actorId": call.actor.id(),
                "actorApiTokenId": call.actor.api_token_id(),
                "surface": call.surface,
                "executionId": call.execution_id.clone(),
                "callId": call.call_id.clone(),
                "path": lookup.callable_path.clone(),
                "sourceId": lookup.source_id.clone(),
                "toolId": lookup.tool_id.clone(),
            });
            let pending = match self
                .approvals
                .create(NewApproval {
                    execution_id: call.execution_id.clone(),
                    call_id: call.call_id.clone(),
                    worker_generation: call.worker_generation,
                    actor: call.actor.clone(),
                    surface: call.surface,
                    callable_path_snapshot: lookup.callable_path.clone(),
                    source_display_name_snapshot: Some(lookup.source_display_name.clone()),
                    tool_display_name_snapshot: Some(lookup.tool_display_name.clone()),
                    mode_provenance: lookup.mode_provenance,
                    revisions: token,
                    arguments: call.arguments.clone(),
                    input_schema,
                    output_schema: None,
                    invocation_snapshot,
                })
                .await
            {
                Ok(pending) => pending,
                Err(error) => {
                    let existing = self
                        .idempotency
                        .correlated_approval_id(&reservation.record)
                        .await?;
                    if existing.is_none() {
                        self.idempotency
                            .release_reserved(&reservation.record.id)
                            .await?;
                    }
                    return Err(ToolCallError::Approval(error).into());
                }
            };
            let approval_id = pending.record.id.clone();
            let mut response = approval_required_response(&pending.record)?;
            let mut ask_completion = IdempotencyAskCompletionGuard::new(
                reservation.record.id.clone(),
                approval_id.clone(),
                response.clone(),
                self.idempotency.clone(),
                self.background_tasks.clone(),
            );
            reservation.disarm();
            let replayed = match self
                .idempotency
                .complete(
                    &reservation.record.id,
                    IdempotencyResponseKind::Approval,
                    &response,
                    Some(&approval_id),
                )
                .await
            {
                Ok(_) => {
                    ask_completion.disarm();
                    false
                }
                Err(IdempotencyError::InvalidTransition("completed")) => {
                    let replayed = match self
                        .idempotency
                        .claim(IdempotencyRequest {
                            owner: IdempotencyOwner {
                                owner_api_token_id: &actor_api_token_id,
                            },
                            key,
                            route: GATEWAY_INVOKE_ROUTE,
                            callable_path: &lookup.callable_path,
                            arguments: &call.arguments,
                        })
                        .await?
                    {
                        IdempotencyClaim::Replay {
                            response: replay_response,
                            ..
                        } => {
                            response = replay_response;
                            true
                        }
                        _ => return Err(GatewayInvokeError::InProgress),
                    };
                    ask_completion.disarm();
                    replayed
                }
                Err(error) => {
                    terminalize_idempotency(&self.idempotency, &reservation.record.id).await;
                    ask_completion.disarm();
                    return Err(error.into());
                }
            };
            self.record_attempt(
                &call,
                Some(lookup.source_id),
                Some(lookup.tool_id),
                RequestOutcome::PendingApproval,
                Some("approval_required"),
                Some(approval_id),
                started,
            );
            drop(preflight);
            return Ok(GatewayInvokeResponse { response, replayed });
        }

        drop(preflight);
        let lease = match self.catalog.revalidate_invocation(&token).await {
            Ok(Some(lease)) => lease,
            Ok(None) => {
                self.idempotency
                    .release_reserved(&reservation.record.id)
                    .await?;
                reservation.disarm();
                return Err(ToolCallError::Stale.into());
            }
            Err(error) => {
                self.idempotency
                    .release_reserved(&reservation.record.id)
                    .await?;
                reservation.disarm();
                return Err(ToolCallError::Catalog(error).into());
            }
        };
        let prepared = match prepare_with_lease(&self.protocols, lease, &call.arguments) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.idempotency
                    .release_reserved(&reservation.record.id)
                    .await?;
                reservation.disarm();
                return Err(error.into());
            }
        };
        self.idempotency
            .mark_executing(&reservation.record.id)
            .await?;
        reservation.disarm();
        let mut execution_guard = IdempotencyExecutionGuard::new(
            reservation.record.id.clone(),
            self.idempotency.clone(),
            self.background_tasks.clone(),
        );
        let result = match execute_prepared(&self.protocols, prepared).await {
            Ok(result) => result,
            Err(error) => {
                match self
                    .idempotency
                    .mark_indeterminate(&reservation.record.id)
                    .await
                {
                    Ok(_) | Err(IdempotencyError::InvalidTransition("indeterminate")) => {
                        execution_guard.disarm();
                    }
                    Err(idempotency_error) => {
                        tracing::error!(
                            idempotency_id = reservation.record.id,
                            error = %idempotency_error,
                            "failed to mark an uncertain gateway invocation indeterminate"
                        );
                        return Err(idempotency_error.into());
                    }
                }
                self.record_attempt(
                    &call,
                    Some(lookup.source_id),
                    Some(lookup.tool_id),
                    RequestOutcome::Failed,
                    Some(error_code(&error)),
                    None,
                    started,
                );
                return Err(error.into());
            }
        };
        let response = tool_result_response(&result)?;
        if let Err(error) = self
            .idempotency
            .complete(
                &reservation.record.id,
                IdempotencyResponseKind::Tool,
                &response,
                None,
            )
            .await
        {
            match self
                .idempotency
                .mark_indeterminate(&reservation.record.id)
                .await
            {
                Ok(_) | Err(IdempotencyError::InvalidTransition("completed" | "indeterminate")) => {
                    execution_guard.disarm();
                }
                Err(mark_error) => return Err(mark_error.into()),
            }
            return Err(error.into());
        }
        execution_guard.disarm();
        self.record_attempt(
            &call,
            Some(lookup.source_id),
            Some(lookup.tool_id),
            if result.ok {
                RequestOutcome::Succeeded
            } else {
                RequestOutcome::Failed
            },
            (!result.ok).then_some("upstream_http_error"),
            None,
            started,
        );
        Ok(GatewayInvokeResponse {
            response,
            replayed: false,
        })
    }

    async fn reconcile_idempotent_approval(
        &self,
        record: &IdempotencyRecord,
        actor_api_token_id: &str,
        key: &str,
        callable_path: &str,
        arguments: &Value,
    ) -> Result<Option<GatewayInvokeResponse>, GatewayInvokeError> {
        let approval_id = match self.idempotency.correlated_approval_id(record).await? {
            Some(CorrelatedApproval::Live(approval_id)) => approval_id,
            Some(CorrelatedApproval::Retired) => {
                self.idempotency.mark_indeterminate(&record.id).await?;
                return Err(GatewayInvokeError::OutcomeUnknown);
            }
            None => return Ok(None),
        };
        let Some(approval) = self
            .approvals
            .get_admin(&approval_id)
            .await
            .map_err(ToolCallError::Approval)?
        else {
            terminalize_idempotency(&self.idempotency, &record.id).await;
            return Err(GatewayInvokeError::OutcomeUnknown);
        };
        let response = match approval_required_response(&approval.record) {
            Ok(response) => response,
            Err(_) => {
                terminalize_idempotency(&self.idempotency, &record.id).await;
                return Err(GatewayInvokeError::OutcomeUnknown);
            }
        };
        match self
            .idempotency
            .complete(
                &record.id,
                IdempotencyResponseKind::Approval,
                &response,
                Some(&approval_id),
            )
            .await
        {
            Ok(_) => Ok(Some(GatewayInvokeResponse {
                response,
                replayed: true,
            })),
            Err(IdempotencyError::InvalidTransition("completed")) => {
                match self
                    .idempotency
                    .claim(IdempotencyRequest {
                        owner: IdempotencyOwner {
                            owner_api_token_id: actor_api_token_id,
                        },
                        key,
                        route: GATEWAY_INVOKE_ROUTE,
                        callable_path,
                        arguments,
                    })
                    .await?
                {
                    IdempotencyClaim::Replay { response, .. } => Ok(Some(GatewayInvokeResponse {
                        response,
                        replayed: true,
                    })),
                    _ => Err(GatewayInvokeError::InProgress),
                }
            }
            Err(_) => {
                terminalize_idempotency(&self.idempotency, &record.id).await;
                Err(GatewayInvokeError::OutcomeUnknown)
            }
        }
    }

    pub async fn discover_search(
        &self,
        call: &ToolCall,
        query: String,
        namespace: Option<String>,
        limit: u32,
        offset: u32,
    ) -> Result<crate::catalog::DiscoveryPage, ToolDiscoveryError> {
        let started = Instant::now();
        let permit = match self.discovery_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.record_attempt(
                    call,
                    None,
                    None,
                    RequestOutcome::Failed,
                    Some("search_busy"),
                    None,
                    started,
                );
                return Err(ToolDiscoveryError::Busy);
            }
        };
        let catalog = self.catalog.clone();
        let result = tokio::spawn(async move {
            let result = catalog
                .search_tools(&query, namespace.as_deref(), limit, offset)
                .await;
            drop(permit);
            result
        })
        .await
        .map_err(|_| ToolDiscoveryError::Interrupted)?;
        self.record_discovery_result(call, started, &result);
        result.map_err(ToolDiscoveryError::Catalog)
    }

    pub async fn discover_describe(
        &self,
        call: &ToolCall,
        path: &str,
    ) -> Result<crate::catalog::DescribedTool, ToolDiscoveryError> {
        let started = Instant::now();
        let result = self.catalog.describe_tool(path).await;
        self.record_discovery_result(call, started, &result);
        result.map_err(ToolDiscoveryError::Catalog)
    }

    pub async fn discover_sources(&self, call: &ToolCall) -> Result<Value, ToolDiscoveryError> {
        let started = Instant::now();
        let _permit = match self.discovery_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.record_attempt(
                    call,
                    None,
                    None,
                    RequestOutcome::Failed,
                    Some("search_busy"),
                    None,
                    started,
                );
                return Err(ToolDiscoveryError::Busy);
            }
        };
        let sources = self.catalog.list_sources().await;
        let sources = match sources {
            Ok(sources) => sources,
            Err(error) => {
                self.record_attempt(
                    call,
                    None,
                    None,
                    RequestOutcome::Failed,
                    Some(catalog_error_code(&error)),
                    None,
                    started,
                );
                return Err(ToolDiscoveryError::Catalog(error));
            }
        };
        let mut visible = Vec::new();
        for source in sources {
            let mut tool_count = 0usize;
            for mode in [ToolMode::Enabled, ToolMode::Ask] {
                let tools = match self
                    .catalog
                    .list_tools(ListToolsFilter {
                        source_id: Some(source.id.clone()),
                        effective_mode: Some(mode),
                        limit: 1,
                        ..Default::default()
                    })
                    .await
                {
                    Ok(tools) => tools,
                    Err(error) => {
                        self.record_attempt(
                            call,
                            None,
                            None,
                            RequestOutcome::Failed,
                            Some(catalog_error_code(&error)),
                            None,
                            started,
                        );
                        return Err(ToolDiscoveryError::Catalog(error));
                    }
                };
                tool_count = tool_count.saturating_add(tools.total);
            }
            if tool_count == 0 {
                continue;
            }
            visible.push(json!({
                "id": source.id,
                "kind": source.kind,
                "slug": source.slug,
                "displayName": source.display_name,
                "description": source.description,
                "toolCount": tool_count,
            }));
        }
        self.record_attempt(
            call,
            None,
            None,
            RequestOutcome::Succeeded,
            None,
            None,
            started,
        );
        Ok(Value::Array(visible))
    }

    fn record_discovery_result<T>(
        &self,
        call: &ToolCall,
        started: Instant,
        result: &Result<T, CatalogError>,
    ) {
        let (outcome, code) = match result {
            Ok(_) => (RequestOutcome::Succeeded, None),
            Err(CatalogError::ToolDisabled { .. }) => {
                (RequestOutcome::Denied, Some("tool_disabled"))
            }
            Err(error) => (RequestOutcome::Failed, Some(catalog_error_code(error))),
        };
        self.record_attempt(call, None, None, outcome, code, None, started);
    }

    pub async fn decide(
        &self,
        approval_id: &str,
        request_id: &str,
        expected_revision: i64,
        decision: ApprovalDecision,
        admin_id: i64,
    ) -> Result<ApprovalAdminDetail, ApprovalError> {
        let cancellation_guard = if decision == ApprovalDecision::Approve
            && let Some(detail) = self.approvals.get_admin(approval_id).await?
        {
            let guard = self.deferred_execution_cancellations.read().await;
            if guard.contains(&detail.record.execution_id)
                || self.execution_is_stopping(&detail.record.execution_id)
            {
                drop(guard);
                self.cancel_execution(&detail.record.execution_id).await?;
                return Err(ApprovalError::InvalidTransition {
                    status: crate::approval::ApprovalStatus::Canceled,
                });
            }
            Some(guard)
        } else {
            None
        };
        let result = self
            .approvals
            .decide(
                approval_id,
                request_id,
                expected_revision,
                decision,
                admin_id,
            )
            .await;
        drop(cancellation_guard);
        let result = result?;
        if result.record.status.is_terminal() {
            self.schedule_approval_log_flush_if_pending().await?;
        }
        if result.record.status == crate::approval::ApprovalStatus::Approved && !result.idempotent {
            self.spawn_approved(result.record.id.clone());
        }
        self.notify_approval(approval_id);
        self.approvals
            .get_admin(approval_id)
            .await?
            .ok_or(ApprovalError::NotFound)
    }

    pub async fn cancel_execution(&self, execution_id: &str) -> Result<u64, ApprovalError> {
        let affected = self.approvals.cancel_execution(execution_id).await?;
        if affected > 0 {
            self.schedule_approval_log_flush();
            self.global_approval_notify.notify_waiters();
        }
        Ok(affected)
    }

    pub(crate) async fn mark_execution_lost(&self, execution_id: &str) {
        self.execution_stopping_flag(execution_id)
            .store(true, Ordering::Release);
        self.deferred_execution_cancellations
            .write()
            .await
            .insert(execution_id.to_owned());
    }

    pub(crate) async fn cancel_lost_execution(&self, execution_id: &str) {
        self.mark_execution_lost(execution_id).await;
        let mut retry_delay = Duration::from_millis(50);
        for attempt in 0..3 {
            match self.cancel_execution(execution_id).await {
                Ok(_) => {
                    self.deferred_execution_cancellations
                        .write()
                        .await
                        .remove(execution_id);
                    self.clear_execution_stopping_flag(execution_id);
                    return;
                }
                Err(error) => {
                    tracing::warn!(
                        execution_id,
                        error = %error,
                        "execution approval cleanup failed"
                    );
                    if attempt < 2 {
                        tokio::time::sleep(retry_delay).await;
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
        }
        let service = self.clone();
        let deferred_execution_id = execution_id.to_owned();
        if !self.background_tasks.spawn(async move {
            let mut retry_delay = Duration::from_millis(100);
            loop {
                match service.cancel_execution(&deferred_execution_id).await {
                    Ok(_) => {
                        service
                            .deferred_execution_cancellations
                            .write()
                            .await
                            .remove(&deferred_execution_id);
                        service.clear_execution_stopping_flag(&deferred_execution_id);
                        return;
                    }
                    Err(error) => {
                        tracing::warn!(
                            execution_id = deferred_execution_id,
                            error = %error,
                            "deferred execution approval cleanup failed"
                        );
                        tokio::time::sleep(retry_delay).await;
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                    }
                }
            }
        }) {
            tracing::warn!(
                execution_id,
                "execution cleanup deferred until startup recovery"
            );
        }
    }

    pub(crate) fn execution_stopping_flag(&self, execution_id: &str) -> Arc<AtomicBool> {
        self.execution_stopping_flags
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(execution_id.to_owned())
            .or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone()
    }

    fn execution_is_stopping(&self, execution_id: &str) -> bool {
        self.execution_stopping_flags
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(execution_id)
            .is_some_and(|stopping| stopping.load(Ordering::Acquire))
    }

    pub(crate) fn clear_execution_stopping_flag(&self, execution_id: &str) {
        self.execution_stopping_flags
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(execution_id);
    }

    pub async fn expire_approvals(&self) -> Result<u64, ApprovalError> {
        let affected = self.approvals.expire_pending().await?;
        if affected > 0 {
            self.schedule_approval_log_flush();
            self.global_approval_notify.notify_waiters();
        }
        Ok(affected)
    }

    pub async fn revoke_owner_token(
        &self,
        actor_api_token_id: &str,
    ) -> Result<bool, ApprovalError> {
        let revoked = self
            .approvals
            .revoke_owner_token(actor_api_token_id)
            .await?;
        if revoked {
            self.schedule_approval_log_flush();
            self.global_approval_notify.notify_waiters();
        }
        Ok(revoked)
    }

    pub async fn cancel_approval(
        &self,
        approval_id: &str,
        actor_api_token_id: &str,
        expected_revision: i64,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let record = self
            .approvals
            .cancel_token_owner(approval_id, actor_api_token_id, expected_revision)
            .await?;
        self.schedule_approval_log_flush();
        self.notify_approval(approval_id);
        Ok(record)
    }

    pub async fn wait_for_approval<C>(
        &self,
        mut approval: ApprovalRequired,
        actor: &ToolActor,
        execution_id: &str,
        call_id: &str,
        cancellation: C,
    ) -> Result<ApprovalOwnerDetail, ApprovalWaitError>
    where
        C: Future<Output = ()> + Send,
    {
        let approval_id = approval.id.clone();
        if approval.actor_kind != actor.kind()
            || approval.actor_id != actor.id()
            || approval.execution_id != execution_id
            || approval.call_id != call_id
        {
            return Err(ApprovalError::NotFound.into());
        }
        tokio::pin!(cancellation);
        let registration = self.register_approval_wait(&approval_id);
        loop {
            let targeted_notification = registration.notify.notified();
            tokio::pin!(targeted_notification);
            targeted_notification.as_mut().enable();
            let global_notification = self.global_approval_notify.notified();
            tokio::pin!(global_notification);
            global_notification.as_mut().enable();
            let detail = self
                .approvals
                .get_for_actor(&approval_id, actor)
                .await?
                .ok_or(ApprovalError::NotFound)?;
            if detail.record.execution_id != execution_id || detail.record.call_id != call_id {
                return Err(ApprovalError::NotFound.into());
            }
            if detail.record.status.is_terminal() {
                if let Some(delivery) = approval.delivery.as_mut() {
                    delivery.release().await;
                }
                return Ok(detail);
            }
            let now = crate::unix_timestamp();
            let until_expiry = u64::try_from(detail.record.expires_at.saturating_sub(now))
                .unwrap_or(0)
                .clamp(1, 30);
            tokio::select! {
                () = &mut cancellation => {
                    if let Some(delivery) = approval.delivery.as_mut() {
                        delivery.release().await;
                    }
                    return Err(ApprovalWaitError::Canceled);
                },
                () = &mut targeted_notification => {}
                () = &mut global_notification => {}
                () = tokio::time::sleep(Duration::from_secs(until_expiry)) => {
                    let should_scan = {
                        let now = Instant::now();
                        let mut next_scan = self
                            .next_expiry_scan
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if now >= *next_scan {
                            *next_scan = now + Duration::from_secs(30);
                            true
                        } else {
                            false
                        }
                    };
                    if should_scan
                        && let Ok(_permit) = self.expiry_slot.clone().try_acquire_owned()
                    {
                        self.expire_approvals().await?;
                    }
                }
            }
        }
    }

    fn spawn_approved(&self, approval_id: String) {
        if !self
            .in_flight_approvals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(approval_id.clone())
        {
            return;
        }
        let worker_service = self.clone();
        let worker_approval_id = approval_id.clone();
        let (worker_completed, worker_result) = oneshot::channel();
        let worker = async move {
            let Ok(_permit) = worker_service.execution_slots.clone().acquire_owned().await else {
                let _ = worker_completed.send(Err(ToolCallError::Approval(
                    ApprovalError::InvalidTransition {
                        status: crate::approval::ApprovalStatus::Approved,
                    },
                )));
                return;
            };
            let result = worker_service.execute_approved(&worker_approval_id).await;
            let _ = worker_completed.send(result);
        };
        let monitor_service = self.clone();
        let monitor_approval_id = approval_id.clone();
        let monitor = async move {
            let failure_code = match worker_result.await {
                Ok(Ok(())) => None,
                Ok(Err(error)) => {
                    tracing::warn!(approval_id = monitor_approval_id, error = %error, "approved tool call did not execute");
                    Some("execution_task_failed")
                }
                Err(_) => {
                    tracing::error!(
                        approval_id = monitor_approval_id,
                        "approved tool call task stopped unexpectedly"
                    );
                    Some("execution_task_interrupted")
                }
            };
            if let Some(failure_code) = failure_code {
                monitor_service
                    .finalize_abandoned_execution(&monitor_approval_id, failure_code)
                    .await;
            }
            monitor_service
                .in_flight_approvals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&monitor_approval_id);
        };
        if !self.background_tasks.spawn_pair(worker, monitor) {
            self.in_flight_approvals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&approval_id);
        }
    }

    async fn finalize_abandoned_execution(&self, approval_id: &str, failure_code: &str) {
        for attempt in 0..3 {
            let result = async {
                let Some(detail) = self.approvals.get_admin(approval_id).await? else {
                    return Ok::<_, ApprovalError>(());
                };
                match detail.record.status {
                    crate::approval::ApprovalStatus::Approved => {
                        self.approvals
                            .mark_stale(approval_id, detail.record.revision, failure_code)
                            .await?;
                    }
                    crate::approval::ApprovalStatus::Executing => {
                        self.approvals
                            .finish(
                                approval_id,
                                detail.record.revision,
                                ExecutionOutcome::Interrupted,
                                &serde_json::to_value(error_result(&ToolCallError::Stale))
                                    .map_err(ApprovalError::Json)?,
                                Some(failure_code),
                            )
                            .await?;
                    }
                    _ => {}
                }
                self.schedule_approval_log_flush_if_pending().await?;
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    self.notify_approval(approval_id);
                    return;
                }
                Err(error) if attempt < 2 => {
                    tracing::warn!(approval_id, error = %error, "retrying approval task finalization");
                    tokio::time::sleep(Duration::from_millis(50 * (attempt + 1))).await;
                }
                Err(error) => {
                    tracing::error!(approval_id, error = %error, "approval task finalization failed");
                }
            }
        }
    }

    async fn execute_approved(&self, approval_id: &str) -> Result<(), ToolCallError> {
        let Some(detail) = self.approvals.get_admin(approval_id).await? else {
            return Ok(());
        };
        let record = detail.record;
        if record.status != crate::approval::ApprovalStatus::Approved {
            return Ok(());
        }
        let expected_revision = record.revision;
        let token = record.revisions.clone().into();
        let lease = match self.catalog.revalidate_invocation(&token).await {
            Ok(Some(lease)) => lease,
            Ok(None) => {
                self.approvals
                    .mark_stale(approval_id, expected_revision, "approval_stale")
                    .await?;
                self.schedule_approval_log_flush();
                self.notify_approval(approval_id);
                self.wait_for_delivery_release(approval_id).await?;
                return Ok(());
            }
            Err(error) => {
                let failure_code = error_code(&ToolCallError::Catalog(error));
                self.approvals
                    .mark_stale(approval_id, expected_revision, failure_code)
                    .await?;
                self.schedule_approval_log_flush();
                self.notify_approval(approval_id);
                self.wait_for_delivery_release(approval_id).await?;
                return Ok(());
            }
        };
        let cancellation_guard = self.deferred_execution_cancellations.read().await;
        if cancellation_guard.contains(&record.execution_id)
            || self.execution_is_stopping(&record.execution_id)
        {
            drop(cancellation_guard);
            self.cancel_execution(&record.execution_id).await?;
            self.wait_for_delivery_release(approval_id).await?;
            return Ok(());
        }
        let snapshot = match self
            .approvals
            .claim_execution(approval_id, record.worker_generation, expected_revision)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(
                ApprovalError::RevisionConflict { .. } | ApprovalError::InvalidTransition { .. },
            ) => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if self.execution_is_stopping(&record.execution_id) {
            drop(cancellation_guard);
            let result = ToolResult {
                ok: false,
                data: None,
                error: Some(PublicToolError {
                    code: "execution_cancelled".to_owned(),
                    message: "The execution was canceled before the tool call started.".to_owned(),
                }),
                http: None,
            };
            self.approvals
                .finish(
                    approval_id,
                    snapshot.record.revision,
                    ExecutionOutcome::Interrupted,
                    &serde_json::to_value(result).map_err(ApprovalError::Json)?,
                    Some("execution_cancelled"),
                )
                .await?;
            self.schedule_approval_log_flush();
            self.notify_approval(approval_id);
            self.wait_for_delivery_release(approval_id).await?;
            return Ok(());
        }
        drop(cancellation_guard);
        if !lease.arguments_are_valid(&snapshot.arguments) {
            let result = error_result(&ToolCallError::InvalidArguments);
            self.approvals
                .finish(
                    approval_id,
                    snapshot.record.revision,
                    ExecutionOutcome::Failed,
                    &serde_json::to_value(result).map_err(ApprovalError::Json)?,
                    Some("invalid_tool_arguments"),
                )
                .await?;
            self.schedule_approval_log_flush();
            self.notify_approval(approval_id);
            self.wait_for_delivery_release(approval_id).await?;
            return Ok(());
        }
        let result = execute_with_lease(&self.protocols, lease, &snapshot.arguments).await;
        let (tool_result, outcome, failure_code) = match result {
            Ok(result) if result.ok => (result, ExecutionOutcome::Succeeded, None),
            Ok(result) => (
                result,
                ExecutionOutcome::Failed,
                Some("upstream_http_error"),
            ),
            Err(error) => (
                error_result(&error),
                ExecutionOutcome::Failed,
                Some(error_code(&error)),
            ),
        };
        let result_json = serde_json::to_value(&tool_result).map_err(ApprovalError::Json)?;
        self.approvals
            .finish(
                approval_id,
                snapshot.record.revision,
                outcome,
                &result_json,
                failure_code,
            )
            .await?;
        self.schedule_approval_log_flush();
        self.notify_approval(approval_id);
        self.wait_for_delivery_release(approval_id).await?;
        Ok(())
    }

    async fn wait_for_delivery_release(&self, approval_id: &str) -> Result<(), ApprovalError> {
        let registration = self.register_approval_wait(approval_id);
        loop {
            let notification = registration.notify.notified();
            tokio::pin!(notification);
            notification.as_mut().enable();
            if !self.approvals.delivery_pin_exists(approval_id).await? {
                return Ok(());
            }
            notification.await;
        }
    }

    fn register_approval_wait(&self, approval_id: &str) -> ApprovalWaitRegistration {
        let mut registry = self
            .approval_notifications
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry =
            registry
                .entry(approval_id.to_owned())
                .or_insert_with(|| ApprovalNotificationEntry {
                    notify: Arc::new(Notify::new()),
                    waiters: 0,
                });
        entry.waiters = entry.waiters.saturating_add(1);
        let notify = entry.notify.clone();
        ApprovalWaitRegistration {
            approval_id: approval_id.to_owned(),
            notify,
            registry: self.approval_notifications.clone(),
        }
    }

    fn notify_approval(&self, approval_id: &str) {
        notify_registry(&self.approval_notifications, approval_id);
    }

    #[allow(clippy::too_many_arguments)]
    fn record_attempt(
        &self,
        call: &ToolCall,
        source_id: Option<String>,
        tool_id: Option<String>,
        outcome: RequestOutcome,
        error_code: Option<&str>,
        approval_id: Option<String>,
        started: Instant,
    ) {
        let path = normalized_path_snapshot(&call.path);
        self.record(NewRequestLog {
            request_id: call.request_id.clone(),
            actor_api_token_id: call.actor.api_token_id().map(str::to_owned),
            surface: call.surface,
            source_id,
            tool_id,
            path_snapshot: Some(path),
            outcome,
            error_code: error_code.map(str::to_owned),
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            approval_id,
            created_at: crate::unix_timestamp(),
        });
    }

    fn record(&self, log: NewRequestLog) {
        self.request_logs.try_record(log);
    }

    fn schedule_approval_log_flush(&self) {
        self.approval_log_requested.store(true, Ordering::Release);
        let Ok(permit) = self.approval_log_flush.clone().try_acquire_owned() else {
            return;
        };
        let service = self.clone();
        self.background_tasks.spawn(async move {
            service.flush_approval_logs(permit).await;
        });
    }

    async fn schedule_approval_log_flush_if_pending(&self) -> Result<(), ApprovalError> {
        if !self.approvals.log_outbox(1).await?.is_empty() {
            self.schedule_approval_log_flush();
        }
        Ok(())
    }

    async fn flush_approval_logs(&self, permit: OwnedSemaphorePermit) {
        let mut retry_delay = Duration::from_millis(50);
        loop {
            self.approval_log_requested.store(false, Ordering::Release);
            let events = match self.approvals.log_outbox(256).await {
                Ok(events) => events,
                Err(error) => {
                    tracing::warn!(error = %error, "approval log outbox could not be read");
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                    continue;
                }
            };
            if events.is_empty() {
                if self.approval_log_requested.load(Ordering::Acquire) {
                    continue;
                }
                drop(permit);
                if self.approval_log_requested.swap(false, Ordering::AcqRel) {
                    self.schedule_approval_log_flush();
                }
                return;
            }
            for event in events {
                let request_id = event.request_id.clone();
                while !self.request_logs.record_durable(event.clone()).await {
                    tracing::warn!(
                        request_id,
                        "approval terminal log persistence will be retried"
                    );
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                }
                loop {
                    match self.approvals.acknowledge_log_outbox(&request_id).await {
                        Ok(()) => break,
                        Err(error) => {
                            tracing::warn!(request_id, error = %error, "approval log outbox acknowledgement will be retried");
                            tokio::time::sleep(retry_delay).await;
                            retry_delay = (retry_delay * 2).min(Duration::from_secs(5));
                        }
                    }
                }
                retry_delay = Duration::from_millis(50);
            }
        }
    }
}

fn notify_registry(registry: &ApprovalNotificationRegistry, approval_id: &str) {
    let notify = registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(approval_id)
        .map(|entry| entry.notify.clone());
    if let Some(notify) = notify {
        notify.notify_waiters();
    }
}

pub(crate) async fn execute_with_lease(
    protocols: &ProtocolRegistry,
    lease: InvocationLease,
    arguments: &Value,
) -> Result<ToolResult, ToolCallError> {
    let prepared = prepare_with_lease(protocols, lease, arguments)?;
    execute_prepared(protocols, prepared).await
}

fn prepare_with_lease(
    protocols: &ProtocolRegistry,
    lease: InvocationLease,
    arguments: &Value,
) -> Result<PreparedProtocolInvocation, ToolCallError> {
    protocols
        .prepare_invocation(lease, arguments)
        .map_err(ToolCallError::Protocol)
}

async fn execute_prepared(
    protocols: &ProtocolRegistry,
    prepared: PreparedProtocolInvocation,
) -> Result<ToolResult, ToolCallError> {
    let response = protocols
        .execute_invocation(prepared)
        .await
        .map_err(|error| match error {
            ProtocolInvocationError::Outbound(error) => ToolCallError::Outbound(error),
        })?;
    let result = ToolResult {
        ok: response.ok,
        data: response.data,
        error: response.error.map(|error| PublicToolError {
            code: error.code,
            message: error.message,
        }),
        http: response.http.map(|http| ToolHttpMetadata {
            status: http.status,
            headers: http.headers,
            truncated: http.truncated,
        }),
    };
    if serde_json::to_vec(&result).is_ok_and(|encoded| encoded.len() > MAX_RESULT_BYTES) {
        return Err(ToolCallError::ResultTooLarge);
    }
    Ok(result)
}

fn tool_result_response(result: &ToolResult) -> Result<IdempotencyResponse, IdempotencyError> {
    Ok(IdempotencyResponse {
        status: 200,
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: serde_json::to_vec(result)?,
    })
}

fn approval_required_response(
    approval: &ApprovalRecord,
) -> Result<IdempotencyResponse, IdempotencyError> {
    Ok(IdempotencyResponse {
        status: 202,
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: serde_json::to_vec(&json!({
            "status": "approval_required",
            "approval": {
                "id": approval.id,
                "status": ApprovalStatus::Pending,
                "revision": 0,
                "path": approval.callable_path_snapshot,
                "createdAt": approval.created_at,
                "expiresAt": approval.expires_at,
                "statusUrl": format!("/api/v1/gateway/approvals/{}", approval.id),
            }
        }))?,
    })
}

fn normalized_path_snapshot(path: &str) -> String {
    let path = if path.starts_with("tools.") {
        path.to_owned()
    } else {
        format!("tools.{path}")
    };
    if path.len() <= 512 && !path.contains('\0') {
        path
    } else {
        "tools.invoke".to_owned()
    }
}

async fn token_is_active(pool: &SqlitePool, token_id: &str) -> Result<bool, ApprovalError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM api_tokens WHERE id = ? AND revoked_at IS NULL)",
    )
    .bind(token_id)
    .fetch_one(pool)
    .await
    .map(|active| active != 0)
    .map_err(ApprovalError::Database)
}

fn idempotency_startup_error(error: IdempotencyError) -> ApprovalError {
    match error {
        IdempotencyError::Database(error) => ApprovalError::Database(error),
        IdempotencyError::Crypto(error) => ApprovalError::Crypto(error),
        IdempotencyError::Json(error) => ApprovalError::Json(error),
        IdempotencyError::InvalidKey
        | IdempotencyError::InvalidMetadata
        | IdempotencyError::PayloadTooLarge
        | IdempotencyError::Capacity
        | IdempotencyError::NotFound
        | IdempotencyError::InvalidTransition(_)
        | IdempotencyError::CorruptData => {
            ApprovalError::CorruptData("gateway idempotency recovery")
        }
    }
}

fn error_code(error: &ToolCallError) -> &'static str {
    match error {
        ToolCallError::Approval(_) => "approval_error",
        ToolCallError::Catalog(CatalogError::Validation { code, .. }) => code,
        ToolCallError::Catalog(CatalogError::NotFound { entity: "source" }) => "source_not_found",
        ToolCallError::Catalog(CatalogError::NotFound { .. })
        | ToolCallError::Catalog(CatalogError::ToolNotFound { .. }) => "tool_not_found",
        ToolCallError::Catalog(CatalogError::ToolDisabled { .. }) => "tool_disabled",
        ToolCallError::Catalog(CatalogError::RevisionConflict { .. }) => "revision_conflict",
        ToolCallError::Catalog(_) => "catalog_error",
        ToolCallError::Adapter { code, .. } => code,
        ToolCallError::ArgumentsTooLarge => "arguments_too_large",
        ToolCallError::InvalidArguments => "invalid_tool_arguments",
        ToolCallError::Stale => "invocation_stale",
        ToolCallError::Outbound(error) => error.code(),
        ToolCallError::Protocol(error) => error.code,
        ToolCallError::ResultTooLarge => "result_too_large",
    }
}

fn catalog_error_code(error: &CatalogError) -> &'static str {
    match error {
        CatalogError::Validation { code, .. } => code,
        CatalogError::NotFound { entity: "source" } => "source_not_found",
        CatalogError::NotFound { .. } | CatalogError::ToolNotFound { .. } => "tool_not_found",
        CatalogError::ToolDisabled { .. } => "tool_disabled",
        CatalogError::RevisionConflict { .. } => "revision_conflict",
        CatalogError::Database(_)
        | CatalogError::Crypto(_)
        | CatalogError::Json(_)
        | CatalogError::CorruptData(_) => "internal_error",
    }
}

fn error_result(error: &ToolCallError) -> ToolResult {
    ToolResult {
        ok: false,
        data: None,
        error: Some(PublicToolError {
            code: error_code(error).to_owned(),
            message: "The tool call could not be completed safely.".to_owned(),
        }),
        http: None,
    }
}

#[cfg(test)]
mod idempotency_guard_tests {
    use std::{future::pending, time::Duration};

    use serde_json::json;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

    #[tokio::test]
    async fn canceled_pre_execution_task_releases_its_reservation() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(directory.path().join("guard.db"))
                    .create_if_missing(true)
                    .foreign_keys(true)
                    .busy_timeout(Duration::from_secs(2)),
            )
            .await
            .expect("database pool");
        MIGRATOR.run(&pool).await.expect("migrations");
        sqlx::query(
            "INSERT INTO api_tokens (id, name, token_digest, token_prefix, token_suffix, created_at) \
             VALUES ('owner', 'Owner', zeroblob(32), 'tok_', 'tail', 1)",
        )
        .execute(&pool)
        .await
        .expect("owner token");
        let store = GatewayIdempotencyStore::new(
            pool.clone(),
            Keyring::from_master_key([9; 32]).expect("keyring"),
        );
        let arguments = json!({});
        let claim = store
            .claim(IdempotencyRequest {
                owner: IdempotencyOwner {
                    owner_api_token_id: "owner",
                },
                key: "canceled-call",
                route: GATEWAY_INVOKE_ROUTE,
                callable_path: "tools.source.tool",
                arguments: &arguments,
            })
            .await
            .expect("reservation");
        let IdempotencyClaim::Fresh(record) = claim else {
            panic!("claim must be fresh");
        };
        let tasks = TaskTracker::default();
        let (ready, waiting) = oneshot::channel();
        let guard_store = store.clone();
        let guard_tasks = tasks.clone();
        let guard_approvals = ApprovalStore::system(
            pool.clone(),
            Keyring::from_master_key([9; 32]).expect("guard keyring"),
        );
        let task = tokio::spawn(async move {
            let _guard =
                IdempotencyReservationGuard::new(record, guard_store, guard_approvals, guard_tasks);
            let _ = ready.send(());
            pending::<()>().await;
        });
        waiting.await.expect("guard task starts");
        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM gateway_invocation_idempotency",
                )
                .fetch_one(&pool)
                .await
                .expect("idempotency rows count");
                if count == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reservation is released without restart");

        let execution_claim = store
            .claim(IdempotencyRequest {
                owner: IdempotencyOwner {
                    owner_api_token_id: "owner",
                },
                key: "canceled-execution",
                route: GATEWAY_INVOKE_ROUTE,
                callable_path: "tools.source.tool",
                arguments: &arguments,
            })
            .await
            .expect("execution reservation");
        let IdempotencyClaim::Fresh(execution_record) = execution_claim else {
            panic!("execution claim must be fresh");
        };
        store
            .mark_executing(&execution_record.id)
            .await
            .expect("execution boundary");
        let (ready, waiting) = oneshot::channel();
        let execution_store = store.clone();
        let execution_tasks = tasks.clone();
        let execution_id = execution_record.id.clone();
        let task = tokio::spawn(async move {
            let _guard =
                IdempotencyExecutionGuard::new(execution_id, execution_store, execution_tasks);
            let _ = ready.send(());
            pending::<()>().await;
        });
        waiting.await.expect("execution guard task starts");
        task.abort();
        let _ = task.await;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = sqlx::query_scalar::<_, String>(
                    "SELECT state FROM gateway_invocation_idempotency WHERE id = ?",
                )
                .bind(&execution_record.id)
                .fetch_one(&pool)
                .await
                .expect("execution state reads");
                if state == "indeterminate" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborted execution becomes indeterminate without restart");

        let ask_claim = store
            .claim(IdempotencyRequest {
                owner: IdempotencyOwner {
                    owner_api_token_id: "owner",
                },
                key: "canceled-ask-completion",
                route: GATEWAY_INVOKE_ROUTE,
                callable_path: "tools.source.tool",
                arguments: &arguments,
            })
            .await
            .expect("Ask reservation");
        let IdempotencyClaim::Fresh(ask_record) = ask_claim else {
            panic!("Ask claim must be fresh");
        };
        sqlx::query(
            "INSERT INTO approvals ( \
                 id, execution_id, call_id, worker_generation, actor_kind, actor_id, \
                 actor_api_token_id, surface, source_id, tool_id, callable_path_snapshot, \
                 mode_provenance, source_revision, catalog_revision, tool_revision, \
                 binding_revision, arguments_digest, arguments_ciphertext, \
                 redacted_arguments_ciphertext, input_schema_ciphertext, \
                 invocation_snapshot_ciphertext, status, created_at, updated_at, expires_at \
             ) VALUES ( \
                 'guard-approval', ?, 'gateway', 0, 'api_token', 'owner', 'owner', \
                 'gateway', 'source', 'tool', 'tools.source.tool', 'intrinsic', \
                 0, 0, 0, 0, zeroblob(32), zeroblob(42), zeroblob(42), zeroblob(42), \
                 zeroblob(42), 'pending', 1, 1, 601 \
             )",
        )
        .bind(idempotency_execution_id(&ask_record.id))
        .execute(&pool)
        .await
        .expect("Ask approval fixture");
        let response = IdempotencyResponse {
            status: 202,
            headers: BTreeMap::new(),
            body: b"approval required".to_vec(),
        };
        let mut lock = pool.acquire().await.expect("writer connection");
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *lock)
            .await
            .expect("writer lock");
        let (ready, waiting) = oneshot::channel();
        let completion_store = store.clone();
        let completion_tasks = tasks.clone();
        let completion_record = ask_record.clone();
        let completion_response = response.clone();
        let task = tokio::spawn(async move {
            let mut guard = IdempotencyAskCompletionGuard::new(
                completion_record.id.clone(),
                "guard-approval".to_owned(),
                completion_response.clone(),
                completion_store.clone(),
                completion_tasks,
            );
            let _ = ready.send(());
            if completion_store
                .complete(
                    &completion_record.id,
                    IdempotencyResponseKind::Approval,
                    &completion_response,
                    Some("guard-approval"),
                )
                .await
                .is_ok()
            {
                guard.disarm();
            }
        });
        waiting.await.expect("Ask completion starts");
        tokio::time::sleep(Duration::from_millis(25)).await;
        task.abort();
        let _ = task.await;
        sqlx::query("ROLLBACK")
            .execute(&mut *lock)
            .await
            .expect("writer lock releases");
        drop(lock);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = sqlx::query_scalar::<_, String>(
                    "SELECT state FROM gateway_invocation_idempotency WHERE id = ?",
                )
                .bind(&ask_record.id)
                .fetch_one(&pool)
                .await
                .expect("Ask completion state reads");
                if state == "completed" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped Ask completion is durably finished");
        tasks.shutdown().await;
    }
}
