use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    pin::Pin,
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
    oauth::{OAuthBinding, OAuthError, OAuthService},
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
    oauth: OAuthService,
    approval_notifications: ApprovalNotificationRegistry,
    global_approval_notify: Arc<Notify>,
    expiry_slot: Arc<Semaphore>,
    next_expiry_scan: Arc<Mutex<Instant>>,
    approval_log_flush: Arc<Semaphore>,
    approval_log_requested: Arc<AtomicBool>,
    discovery_slots: Arc<Semaphore>,
    execution_slots: Arc<Semaphore>,
    in_flight_approvals: Arc<Mutex<HashSet<String>>>,
    in_flight_mcp_settlements: Arc<Mutex<HashSet<String>>>,
    deferred_execution_cancellations: Arc<RwLock<HashSet<String>>>,
    execution_stopping_flags: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
    #[cfg(test)]
    approval_cancellation_race_hook: Arc<Mutex<Option<Arc<ApprovalCancellationRaceHook>>>>,
    #[cfg(test)]
    approved_execution_hook: Arc<Mutex<Option<Arc<ApprovedExecutionHook>>>>,
    #[cfg(test)]
    cancel_execution_hook: Arc<Mutex<Option<Arc<CancelExecutionHook>>>>,
    background_tasks: TaskTracker,
}

#[cfg(test)]
#[derive(Default)]
struct ApprovalCancellationRaceHook {
    decision_read_acquired: Notify,
    cancellation_write_queued: Notify,
    release_decision: Notify,
}

#[cfg(test)]
#[derive(Default)]
struct ApprovedExecutionHook {
    started: Notify,
    release: Notify,
    dispatches: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
#[derive(Default)]
struct CancelExecutionHook {
    failures: std::sync::atomic::AtomicUsize,
    block_retries: AtomicBool,
    retry_waiters: std::sync::atomic::AtomicUsize,
    retry_waiting: Notify,
    release_retries: Notify,
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

#[derive(Clone, Debug)]
pub(crate) struct McpIdempotencyRequest {
    pub owner_api_token_id: String,
    pub key: String,
    pub route: String,
    pub callable_path: String,
    pub arguments: Value,
}

#[derive(Clone, Debug)]
pub(crate) struct McpIdempotencyBlob {
    pub body: Vec<u8>,
}

pub(crate) enum McpIdempotencyClaim {
    Fresh(Box<McpIdempotencyReservation>),
    InProgress,
    Replay(McpIdempotencyBlob),
    Indeterminate,
    Mismatch,
}

pub(crate) struct McpIdempotencyReservation {
    guard: Option<IdempotencyReservationGuard>,
}

pub(crate) struct McpIdempotencyExecution {
    guard: Option<IdempotencyExecutionGuard>,
}

#[derive(Clone, Debug)]
pub(crate) struct McpIdempotentResponse {
    pub result: ToolResult,
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
    #[error("the idempotent invocation wait was canceled")]
    Canceled,
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
            if approval.record.surface == RequestSurface::Mcp {
                return Ok(());
            }
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

impl McpIdempotencyReservation {
    pub(crate) async fn mark_executing(
        mut self,
    ) -> Result<McpIdempotencyExecution, GatewayInvokeError> {
        let mut guard = self.guard.take().ok_or_else(|| {
            GatewayInvokeError::Idempotency(
                "idempotency reservation was already consumed".to_owned(),
            )
        })?;
        guard.store.mark_executing(&guard.record.id).await?;
        guard.disarm();
        Ok(McpIdempotencyExecution {
            guard: Some(IdempotencyExecutionGuard::new(
                guard.record.id.clone(),
                guard.store.clone(),
                guard.tasks.clone(),
            )),
        })
    }
}

impl McpIdempotencyExecution {
    pub(crate) async fn mark_indeterminate(mut self) -> Result<(), GatewayInvokeError> {
        let mut guard = self.guard.take().ok_or_else(|| {
            GatewayInvokeError::Idempotency("idempotency execution was already consumed".to_owned())
        })?;
        guard.store.mark_indeterminate(&guard.id).await?;
        guard.disarm();
        Ok(())
    }

    pub(crate) async fn complete(
        mut self,
        response: McpIdempotencyBlob,
    ) -> Result<(), GatewayInvokeError> {
        let mut guard = self.guard.take().ok_or_else(|| {
            GatewayInvokeError::Idempotency("idempotency execution was already consumed".to_owned())
        })?;
        let response = mcp_blob_response(response);
        guard
            .store
            .complete(&guard.id, IdempotencyResponseKind::Tool, &response, None)
            .await?;
        guard.disarm();
        Ok(())
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

struct McpApprovalSettlementGuard {
    service: ToolCallService,
    record: IdempotencyRecord,
    actor: ToolActor,
    armed: bool,
}

impl McpApprovalSettlementGuard {
    fn new(service: ToolCallService, record: IdempotencyRecord, actor: ToolActor) -> Self {
        Self {
            service,
            record,
            actor,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for McpApprovalSettlementGuard {
    fn drop(&mut self) {
        if self.armed {
            self.service
                .spawn_mcp_idempotency_settlement(self.record.clone(), self.actor.clone());
        }
    }
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
        oauth: OAuthService,
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
            oauth,
            approval_notifications: Arc::new(Mutex::new(HashMap::new())),
            global_approval_notify: Arc::new(Notify::new()),
            expiry_slot: Arc::new(Semaphore::new(1)),
            next_expiry_scan: Arc::new(Mutex::new(Instant::now())),
            approval_log_flush: Arc::new(Semaphore::new(1)),
            approval_log_requested: Arc::new(AtomicBool::new(false)),
            discovery_slots: Arc::new(Semaphore::new(1)),
            execution_slots: Arc::new(Semaphore::new(APPROVAL_EXECUTION_CONCURRENCY)),
            in_flight_approvals: Arc::new(Mutex::new(HashSet::new())),
            in_flight_mcp_settlements: Arc::new(Mutex::new(HashSet::new())),
            deferred_execution_cancellations: Arc::new(RwLock::new(HashSet::new())),
            execution_stopping_flags: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(test)]
            approval_cancellation_race_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            approved_execution_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            cancel_execution_hook: Arc::new(Mutex::new(None)),
            background_tasks: TaskTracker::default(),
        }
    }

    pub fn approvals(&self) -> &ApprovalQueries {
        &self.approval_queries
    }

    pub(crate) async fn claim_mcp_idempotency(
        &self,
        request: &McpIdempotencyRequest,
    ) -> Result<McpIdempotencyClaim, GatewayInvokeError> {
        if !token_is_active(self.catalog.pool(), &request.owner_api_token_id)
            .await
            .map_err(ToolCallError::Approval)?
        {
            return Err(ToolCallError::Approval(ApprovalError::OwnerTokenInactive).into());
        }
        let claim = self
            .idempotency
            .claim(IdempotencyRequest {
                owner: IdempotencyOwner {
                    owner_api_token_id: &request.owner_api_token_id,
                },
                key: &request.key,
                route: &request.route,
                callable_path: &request.callable_path,
                arguments: &request.arguments,
            })
            .await?;
        Ok(match claim {
            IdempotencyClaim::Fresh(record) => {
                McpIdempotencyClaim::Fresh(Box::new(McpIdempotencyReservation {
                    guard: Some(IdempotencyReservationGuard::new(
                        record,
                        self.idempotency.clone(),
                        self.approvals.clone(),
                        self.background_tasks.clone(),
                    )),
                }))
            }
            IdempotencyClaim::InProgress(_) => McpIdempotencyClaim::InProgress,
            IdempotencyClaim::Replay { response, .. } => {
                McpIdempotencyClaim::Replay(mcp_response_blob(response)?)
            }
            IdempotencyClaim::Indeterminate(_) => McpIdempotencyClaim::Indeterminate,
            IdempotencyClaim::Mismatch => McpIdempotencyClaim::Mismatch,
        })
    }

    pub(crate) async fn wait_mcp_idempotency<C>(
        &self,
        request: &McpIdempotencyRequest,
        cancellation: C,
    ) -> Result<McpIdempotencyClaim, GatewayInvokeError>
    where
        C: Future<Output = ()> + Send,
    {
        tokio::pin!(cancellation);
        let mut delay = Duration::from_millis(10);
        loop {
            match self.claim_mcp_idempotency(request).await? {
                McpIdempotencyClaim::InProgress => {}
                terminal => return Ok(terminal),
            }
            tokio::select! {
                () = &mut cancellation => return Err(GatewayInvokeError::Canceled),
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(Duration::from_millis(250));
        }
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
        let mut mcp_settlements = Vec::new();
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
            if approval.record.surface == RequestSurface::Mcp {
                if approval.record.status == ApprovalStatus::Executing {
                    self.idempotency
                        .mark_indeterminate(&reservation.id)
                        .await
                        .map_err(idempotency_startup_error)?;
                    continue;
                }
                let Some(actor_api_token_id) = approval.record.actor_api_token_id.clone() else {
                    terminalize_idempotency(&self.idempotency, &reservation.id).await;
                    continue;
                };
                mcp_settlements.push((
                    reservation,
                    ToolActor::api_token(
                        actor_api_token_id,
                        approval.record.actor_name_snapshot.clone(),
                    ),
                ));
                continue;
            }
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
        for (reservation, actor) in mcp_settlements {
            self.spawn_mcp_idempotency_settlement(reservation, actor);
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
            let oauth_bindings = self
                .oauth
                .bindings_for_source(&lookup.source_id)
                .await
                .map_err(oauth_tool_error)?;
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
                "oauthBindings": oauth_bindings,
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
        let result = execute_with_lease(&self.protocols, lease, &call.arguments, None).await;
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
                    completed_failure_code(&result),
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

    pub(crate) async fn submit_mcp_idempotent<C>(
        &self,
        mut call: ToolCall,
        route: &str,
        key: &str,
        cancellation: C,
    ) -> Result<McpIdempotentResponse, GatewayInvokeError>
    where
        C: Future<Output = ()> + Send,
    {
        if call.surface != RequestSurface::Mcp {
            return Err(IdempotencyError::InvalidMetadata.into());
        }
        let actor_api_token_id = call
            .actor
            .api_token_id()
            .ok_or(IdempotencyError::InvalidMetadata)?
            .to_owned();
        if !token_is_active(self.catalog.pool(), &actor_api_token_id)
            .await
            .map_err(ToolCallError::Approval)?
        {
            return Err(ToolCallError::Approval(ApprovalError::OwnerTokenInactive).into());
        }
        let encoded_arguments =
            serde_json::to_vec(&call.arguments).map_err(|_| ToolCallError::InvalidArguments)?;
        if encoded_arguments.len() > MAX_ARGUMENT_BYTES {
            return Err(ToolCallError::ArgumentsTooLarge.into());
        }
        let request_path = idempotency::canonical_callable_path(&call.path)?;
        tokio::pin!(cancellation);
        let request = || IdempotencyRequest {
            owner: IdempotencyOwner {
                owner_api_token_id: &actor_api_token_id,
            },
            key,
            route,
            callable_path: &request_path,
            arguments: &call.arguments,
        };
        if let Some(claim) = self.idempotency.lookup(request()).await?
            && let Some(response) = self
                .resolve_mcp_idempotency_claim(claim, &call, &request, cancellation.as_mut(), true)
                .await?
        {
            return Ok(response);
        }

        let (preflight, record) = loop {
            let preflight = self
                .catalog
                .preflight_invocation(&call.path)
                .await
                .map_err(ToolCallError::Catalog)?;
            if !preflight.arguments_are_valid(&call.arguments) {
                return Err(ToolCallError::InvalidArguments.into());
            }
            match self.idempotency.claim(request()).await? {
                IdempotencyClaim::Fresh(record) => break (preflight, record),
                existing => {
                    drop(preflight);
                    if let Some(response) = self
                        .resolve_mcp_idempotency_claim(
                            existing,
                            &call,
                            &request,
                            cancellation.as_mut(),
                            true,
                        )
                        .await?
                    {
                        return Ok(response);
                    }
                }
            }
        };
        let token = preflight.revisions().clone();
        let lookup = preflight.lookup().clone();
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
            drop(preflight);
            let oauth_bindings = self
                .oauth
                .bindings_for_source(&lookup.source_id)
                .await
                .map_err(oauth_tool_error)?;
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
                "oauthBindings": oauth_bindings,
            });
            let pending = self
                .approvals
                .create(NewApproval {
                    execution_id: call.execution_id.clone(),
                    call_id: call.call_id.clone(),
                    worker_generation: call.worker_generation,
                    actor: call.actor.clone(),
                    surface: call.surface,
                    callable_path_snapshot: lookup.callable_path,
                    source_display_name_snapshot: Some(lookup.source_display_name),
                    tool_display_name_snapshot: Some(lookup.tool_display_name),
                    mode_provenance: lookup.mode_provenance,
                    revisions: token,
                    arguments: call.arguments.clone(),
                    input_schema,
                    output_schema: None,
                    invocation_snapshot,
                })
                .await
                .map_err(ToolCallError::Approval)?;
            let approval = ApprovalRequired {
                delivery: pending.delivery_pin.then(|| ApprovalDeliveryTicket {
                    identity: Some(ApprovalDeliveryIdentity {
                        approval_id: pending.record.id.clone(),
                        actor: call.actor.clone(),
                        execution_id: call.execution_id.clone(),
                        call_id: call.call_id.clone(),
                    }),
                    approvals: self.approvals.clone(),
                    notifications: self.approval_notifications.clone(),
                    tasks: self.background_tasks.clone(),
                }),
                record: Box::new(pending.record),
            };
            reservation.disarm();
            return self
                .finish_mcp_idempotent_approval(
                    &reservation.record,
                    &call,
                    approval,
                    cancellation.as_mut(),
                    false,
                )
                .await;
        }

        drop(preflight);
        let lease = match self
            .catalog
            .revalidate_invocation(&token)
            .await
            .map_err(ToolCallError::Catalog)?
        {
            Some(lease) => lease,
            None => {
                self.idempotency
                    .release_reserved(&reservation.record.id)
                    .await?;
                reservation.disarm();
                return Err(ToolCallError::Stale.into());
            }
        };
        let prepared = match prepare_with_lease(&self.protocols, lease, &call.arguments, None).await
        {
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
        let execution = execute_prepared(&self.protocols, prepared);
        tokio::pin!(execution);
        let execution_result = tokio::select! {
            result = &mut execution => result,
            () = &mut cancellation => {
                self.idempotency
                    .mark_indeterminate(&reservation.record.id)
                    .await?;
                execution_guard.disarm();
                return Err(GatewayInvokeError::Canceled);
            }
        };
        let result = match execution_result {
            Ok(result) => result,
            Err(error) => {
                self.idempotency
                    .mark_indeterminate(&reservation.record.id)
                    .await?;
                execution_guard.disarm();
                return Err(error.into());
            }
        };
        let response = tool_result_response(&result)?;
        self.idempotency
            .complete(
                &reservation.record.id,
                IdempotencyResponseKind::Tool,
                &response,
                None,
            )
            .await?;
        execution_guard.disarm();
        Ok(McpIdempotentResponse {
            result,
            replayed: false,
        })
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
            let oauth_bindings = self
                .oauth
                .bindings_for_source(&lookup.source_id)
                .await
                .map_err(oauth_tool_error)?;
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
                "oauthBindings": oauth_bindings,
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
        let prepared = match prepare_with_lease(&self.protocols, lease, &call.arguments, None).await
        {
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
            completed_failure_code(&result),
            None,
            started,
        );
        Ok(GatewayInvokeResponse {
            response,
            replayed: false,
        })
    }

    async fn resolve_mcp_idempotency_claim<'a, C, F>(
        &self,
        mut claim: IdempotencyClaim,
        call: &ToolCall,
        request: &F,
        mut cancellation: Pin<&mut C>,
        replayed: bool,
    ) -> Result<Option<McpIdempotentResponse>, GatewayInvokeError>
    where
        C: Future<Output = ()> + Send,
        F: Fn() -> IdempotencyRequest<'a>,
    {
        let mut delay = Duration::from_millis(10);
        loop {
            match claim {
                IdempotencyClaim::Fresh(_) => return Ok(None),
                IdempotencyClaim::Mismatch => return Err(GatewayInvokeError::KeyMismatch),
                IdempotencyClaim::Indeterminate(_) => {
                    return Err(GatewayInvokeError::OutcomeUnknown);
                }
                IdempotencyClaim::Replay { record, response } => {
                    if record.response_kind == Some(IdempotencyResponseKind::Tool) {
                        return Ok(Some(McpIdempotentResponse {
                            result: tool_result_from_response(&response)?,
                            replayed,
                        }));
                    }
                    let approval = self.idempotent_approval(&record, call).await?;
                    return self
                        .finish_mcp_idempotent_approval(
                            &record,
                            call,
                            approval,
                            cancellation,
                            replayed,
                        )
                        .await
                        .map(Some);
                }
                IdempotencyClaim::InProgress(record) => {
                    if record.state == idempotency::IdempotencyState::Reserved
                        && let Some(CorrelatedApproval::Live(_)) =
                            self.idempotency.correlated_approval_id(&record).await?
                    {
                        let approval = self.idempotent_approval(&record, call).await?;
                        return self
                            .finish_mcp_idempotent_approval(
                                &record,
                                call,
                                approval,
                                cancellation,
                                replayed,
                            )
                            .await
                            .map(Some);
                    }
                }
            }
            tokio::select! {
                () = &mut cancellation => return Err(GatewayInvokeError::Canceled),
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(Duration::from_millis(250));
            let Some(next_claim) = self.idempotency.lookup(request()).await? else {
                return Ok(None);
            };
            claim = next_claim;
        }
    }

    async fn idempotent_approval(
        &self,
        record: &IdempotencyRecord,
        call: &ToolCall,
    ) -> Result<ApprovalRequired, GatewayInvokeError> {
        let approval_id = match self.idempotency.correlated_approval_id(record).await? {
            Some(CorrelatedApproval::Live(approval_id)) => approval_id,
            Some(CorrelatedApproval::Retired) | None => {
                return Err(GatewayInvokeError::OutcomeUnknown);
            }
        };
        let detail = self
            .approvals
            .get_for_actor(&approval_id, &call.actor)
            .await
            .map_err(ToolCallError::Approval)?
            .ok_or(GatewayInvokeError::OutcomeUnknown)?;
        if detail.record.execution_id != idempotency_execution_id(&record.id)
            || detail.record.call_id != "gateway"
            || detail.record.surface != RequestSurface::Mcp
        {
            return Err(GatewayInvokeError::OutcomeUnknown);
        }
        Ok(ApprovalRequired {
            record: Box::new(detail.record),
            delivery: None,
        })
    }

    async fn finish_mcp_idempotent_approval<C>(
        &self,
        record: &IdempotencyRecord,
        call: &ToolCall,
        approval: ApprovalRequired,
        cancellation: Pin<&mut C>,
        replayed: bool,
    ) -> Result<McpIdempotentResponse, GatewayInvokeError>
    where
        C: Future<Output = ()> + Send,
    {
        let mut settlement_guard =
            McpApprovalSettlementGuard::new(self.clone(), record.clone(), call.actor.clone());
        let approval_id = approval.id.clone();
        let approval_execution_id = approval.execution_id.clone();
        let idempotency_execution_id = idempotency_execution_id(&record.id);
        let approval_wait = self.wait_for_approval(
            approval,
            &call.actor,
            &idempotency_execution_id,
            "gateway",
            cancellation,
        );
        let idempotency_failure = self.wait_for_mcp_indeterminate(&record.id);
        tokio::pin!(approval_wait);
        tokio::pin!(idempotency_failure);
        let approval_result = tokio::select! {
            detail = &mut approval_wait => detail,
            result = &mut idempotency_failure => {
                result?;
                return Err(GatewayInvokeError::OutcomeUnknown);
            }
        };
        let detail = match approval_result {
            Ok(detail) => detail,
            Err(ApprovalWaitError::Approval(error)) => {
                return Err(GatewayInvokeError::ToolCall(ToolCallError::Approval(error)));
            }
            Err(ApprovalWaitError::Canceled) => {
                self.cancel_mcp_approval_execution(&approval_execution_id)
                    .await
                    .map_err(ToolCallError::Approval)?;
                self.notify_approval(&approval_id);
                if let Some(detail) = self
                    .approvals
                    .get_for_actor(&approval_id, &call.actor)
                    .await
                    .map_err(ToolCallError::Approval)?
                {
                    if detail.record.status.is_terminal() {
                        let result = terminal_approval_result(detail.record.status, detail.result)?;
                        self.complete_mcp_approval_result(record, &result).await?;
                        settlement_guard.disarm();
                    } else if detail.record.status == ApprovalStatus::Executing {
                        match self.idempotency.mark_indeterminate(&record.id).await {
                            Ok(_) | Err(IdempotencyError::InvalidTransition("indeterminate")) => {}
                            Err(IdempotencyError::InvalidTransition("completed")) => {}
                            Err(error) => return Err(error.into()),
                        }
                        settlement_guard.disarm();
                    }
                }
                return Err(GatewayInvokeError::Canceled);
            }
        };
        let result = terminal_approval_result(detail.record.status, detail.result)?;
        self.complete_mcp_approval_result(record, &result).await?;
        settlement_guard.disarm();
        Ok(McpIdempotentResponse { result, replayed })
    }

    async fn wait_for_mcp_indeterminate(&self, id: &str) -> Result<(), GatewayInvokeError> {
        loop {
            match self.idempotency.state(id).await? {
                Some(idempotency::IdempotencyState::Indeterminate) => return Ok(()),
                Some(
                    idempotency::IdempotencyState::Reserved
                    | idempotency::IdempotencyState::Executing
                    | idempotency::IdempotencyState::Completed,
                ) => {}
                None => return Err(GatewayInvokeError::OutcomeUnknown),
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn complete_mcp_approval_result(
        &self,
        record: &IdempotencyRecord,
        result: &ToolResult,
    ) -> Result<(), GatewayInvokeError> {
        if !matches!(
            record.state,
            idempotency::IdempotencyState::Reserved | idempotency::IdempotencyState::Executing
        ) {
            return Ok(());
        }
        let response = tool_result_response(result)?;
        match self
            .idempotency
            .complete(&record.id, IdempotencyResponseKind::Tool, &response, None)
            .await
        {
            Ok(_) | Err(IdempotencyError::InvalidTransition("completed")) => Ok(()),
            Err(IdempotencyError::InvalidTransition("indeterminate")) => {
                Err(GatewayInvokeError::OutcomeUnknown)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn spawn_mcp_idempotency_settlement(&self, record: IdempotencyRecord, actor: ToolActor) {
        if !self
            .in_flight_mcp_settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(record.id.clone())
        {
            return;
        }
        let service = self.clone();
        let settlement_id = record.id.clone();
        let spawned = self.background_tasks.spawn(async move {
            let call = ToolCall {
                request_id: format!("mcp-idempotency-settlement:{}", record.id),
                actor,
                surface: RequestSurface::Mcp,
                execution_id: idempotency_execution_id(&record.id),
                call_id: "gateway".to_owned(),
                worker_generation: 0,
                path: "executor.settlement".to_owned(),
                arguments: Value::Null,
            };
            let result = async {
                let approval = service.idempotent_approval(&record, &call).await?;
                let cancellation = std::future::pending::<()>();
                tokio::pin!(cancellation);
                service
                    .finish_mcp_idempotent_approval(
                        &record,
                        &call,
                        approval,
                        cancellation.as_mut(),
                        false,
                    )
                    .await
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(
                    idempotency_id = record.id,
                    error = %error,
                    "MCP approval idempotency settlement stopped"
                );
            }
            service
                .in_flight_mcp_settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&record.id);
        });
        if !spawned {
            self.in_flight_mcp_settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&settlement_id);
        }
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
        #[cfg(test)]
        let race_hook = {
            self.approval_cancellation_race_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        #[cfg(test)]
        if cancellation_guard.is_some()
            && let Some(hook) = race_hook
        {
            hook.decision_read_acquired.notify_one();
            hook.release_decision.notified().await;
        }
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
        #[cfg(test)]
        let cancel_hook = {
            self.cancel_execution_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        #[cfg(test)]
        if let Some(hook) = cancel_hook {
            if hook
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
            {
                hook.block_retries.store(true, Ordering::SeqCst);
                return Err(ApprovalError::Database(sqlx::Error::Protocol(
                    "forced cancellation persistence failure".to_owned(),
                )));
            }
            if hook.block_retries.load(Ordering::SeqCst) {
                let release = hook.release_retries.notified();
                tokio::pin!(release);
                release.as_mut().enable();
                hook.retry_waiters.fetch_add(1, Ordering::SeqCst);
                hook.retry_waiting.notify_one();
                release.await;
            }
        }
        let affected = self.approvals.cancel_execution(execution_id).await?;
        if affected > 0 {
            self.schedule_approval_log_flush();
            self.global_approval_notify.notify_waiters();
        }
        Ok(affected)
    }

    async fn cancel_mcp_approval_execution(
        &self,
        execution_id: &str,
    ) -> Result<u64, ApprovalError> {
        #[cfg(test)]
        if let Some(hook) = self
            .approval_cancellation_race_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook.cancellation_write_queued.notify_one();
        }
        let mut fence = self.deferred_execution_cancellations.write().await;
        let stopping = self.execution_stopping_flag(execution_id);
        stopping.store(true, Ordering::Release);
        fence.insert(execution_id.to_owned());
        let result = self.cancel_execution(execution_id).await;
        if result.is_ok() {
            fence.remove(execution_id);
            self.clear_execution_stopping_flag(execution_id);
        } else {
            drop(fence);
            self.defer_execution_cancellation(execution_id);
        }
        result
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
        self.defer_execution_cancellation(execution_id);
    }

    fn defer_execution_cancellation(&self, execution_id: &str) {
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
        let expected_oauth_bindings = match self
            .approvals
            .invocation_snapshot(approval_id)
            .await?
            .and_then(|snapshot| snapshot.get("oauthBindings").cloned())
            .map(serde_json::from_value::<Vec<OAuthBinding>>)
        {
            Some(Ok(bindings)) => bindings,
            Some(Err(_)) | None => {
                self.approvals
                    .mark_stale(approval_id, expected_revision, "oauth_binding_stale")
                    .await?;
                self.schedule_approval_log_flush();
                self.notify_approval(approval_id);
                self.wait_for_delivery_release(approval_id).await?;
                return Ok(());
            }
        };
        if !self
            .oauth
            .bindings_match(&record.revisions.source_id, &expected_oauth_bindings)
            .await
            .unwrap_or(false)
        {
            self.approvals
                .mark_stale(approval_id, expected_revision, "oauth_binding_stale")
                .await?;
            self.schedule_approval_log_flush();
            self.notify_approval(approval_id);
            self.wait_for_delivery_release(approval_id).await?;
            return Ok(());
        }
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
        let mut mcp_idempotency_execution = if record.surface == RequestSurface::Mcp {
            let id = record
                .execution_id
                .strip_prefix("gateway-idempotency:")
                .filter(|id| !id.is_empty() && record.call_id == "gateway")
                .ok_or_else(|| ToolCallError::Adapter {
                    code: "idempotency_metadata_invalid",
                    message: "The MCP approval idempotency metadata is invalid.".to_owned(),
                })?
                .to_owned();
            self.idempotency
                .mark_executing(&id)
                .await
                .map_err(idempotency_tool_call_error)?;
            Some(IdempotencyExecutionGuard::new(
                id,
                self.idempotency.clone(),
                self.background_tasks.clone(),
            ))
        } else {
            None
        };
        drop(cancellation_guard);
        #[cfg(test)]
        let execution_hook = {
            self.approved_execution_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };
        #[cfg(test)]
        let result = if let Some(hook) = execution_hook {
            hook.dispatches.fetch_add(1, Ordering::SeqCst);
            hook.started.notify_one();
            hook.release.notified().await;
            Ok(ToolResult {
                ok: true,
                data: Some(json!({ "ok": true })),
                error: None,
                http: None,
            })
        } else {
            execute_with_lease(
                &self.protocols,
                lease,
                &snapshot.arguments,
                Some(&expected_oauth_bindings),
            )
            .await
        };
        #[cfg(not(test))]
        let result = execute_with_lease(
            &self.protocols,
            lease,
            &snapshot.arguments,
            Some(&expected_oauth_bindings),
        )
        .await;
        if result.is_err()
            && let Some(execution) = mcp_idempotency_execution.as_mut()
        {
            self.idempotency
                .mark_indeterminate(&execution.id)
                .await
                .map_err(idempotency_tool_call_error)?;
            execution.disarm();
        }
        let completed_failure_code = result
            .as_ref()
            .ok()
            .and_then(|result| completed_failure_code(result).map(str::to_owned));
        let (tool_result, outcome, failure_code) = match result {
            Ok(result) if result.ok => (result, ExecutionOutcome::Succeeded, None),
            Ok(result) => (
                result,
                ExecutionOutcome::Failed,
                completed_failure_code.as_deref(),
            ),
            Err(error) => (
                error_result(&error),
                ExecutionOutcome::Failed,
                Some(error_code(&error)),
            ),
        };
        let result_json = serde_json::to_value(&tool_result).map_err(ApprovalError::Json)?;
        let approval_finish = self
            .approvals
            .finish(
                approval_id,
                snapshot.record.revision,
                outcome,
                &result_json,
                failure_code,
            )
            .await;
        if let Err(error) = approval_finish {
            if let Some(execution) = mcp_idempotency_execution.as_mut()
                && execution.armed
            {
                self.idempotency
                    .mark_indeterminate(&execution.id)
                    .await
                    .map_err(idempotency_tool_call_error)?;
                execution.disarm();
            }
            return Err(error.into());
        }
        if let Some(execution) = mcp_idempotency_execution.as_mut()
            && execution.armed
        {
            let response =
                tool_result_response(&tool_result).map_err(idempotency_tool_call_error)?;
            match self
                .idempotency
                .complete(
                    &execution.id,
                    IdempotencyResponseKind::Tool,
                    &response,
                    None,
                )
                .await
            {
                Ok(_) | Err(IdempotencyError::InvalidTransition("completed")) => {
                    execution.disarm();
                }
                Err(error) => {
                    self.schedule_approval_log_flush();
                    self.notify_approval(approval_id);
                    return Err(idempotency_tool_call_error(error));
                }
            }
        }
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

fn oauth_tool_error(_error: OAuthError) -> ToolCallError {
    ToolCallError::Adapter {
        code: "oauth_connection_failed",
        message: "The managed OAuth connection could not be resolved safely.".to_owned(),
    }
}

pub(crate) async fn execute_with_lease(
    protocols: &ProtocolRegistry,
    lease: InvocationLease,
    arguments: &Value,
    expected_oauth_bindings: Option<&[OAuthBinding]>,
) -> Result<ToolResult, ToolCallError> {
    let prepared = prepare_with_lease(protocols, lease, arguments, expected_oauth_bindings).await?;
    execute_prepared(protocols, prepared).await
}

async fn prepare_with_lease(
    protocols: &ProtocolRegistry,
    lease: InvocationLease,
    arguments: &Value,
    expected_oauth_bindings: Option<&[OAuthBinding]>,
) -> Result<PreparedProtocolInvocation, ToolCallError> {
    protocols
        .prepare_invocation(lease, arguments, expected_oauth_bindings)
        .await
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
            ProtocolInvocationError::OpenApi(error) => ToolCallError::Adapter {
                code: if error.outcome_unknown() {
                    "openapi_outcome_unknown"
                } else {
                    error.code()
                },
                message: "The upstream OpenAPI operation could not be completed safely.".to_owned(),
            },
            ProtocolInvocationError::Graphql(error) => ToolCallError::Adapter {
                code: if error.outcome_unknown() {
                    "graphql_outcome_unknown"
                } else {
                    "graphql_invocation_failed"
                },
                message: "The upstream GraphQL operation could not be completed safely.".to_owned(),
            },
            ProtocolInvocationError::Mcp(error) => ToolCallError::Adapter {
                code: if error.outcome_unknown() {
                    "mcp_outcome_unknown"
                } else {
                    "mcp_invocation_failed"
                },
                message: "The upstream MCP tool call could not be completed safely.".to_owned(),
            },
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

fn completed_failure_code(result: &ToolResult) -> Option<&str> {
    (!result.ok).then(|| {
        result
            .error
            .as_ref()
            .map(|error| error.code.as_str())
            .unwrap_or("upstream_http_error")
    })
}

fn tool_result_response(result: &ToolResult) -> Result<IdempotencyResponse, IdempotencyError> {
    Ok(IdempotencyResponse {
        status: 200,
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: serde_json::to_vec(result)?,
    })
}

fn tool_result_from_response(
    response: &IdempotencyResponse,
) -> Result<ToolResult, GatewayInvokeError> {
    if response.status != 200 {
        return Err(GatewayInvokeError::Idempotency(
            "stored MCP idempotency response has an invalid status".to_owned(),
        ));
    }
    serde_json::from_slice(&response.body)
        .map_err(IdempotencyError::Json)
        .map_err(GatewayInvokeError::from)
}

fn mcp_blob_response(response: McpIdempotencyBlob) -> IdempotencyResponse {
    IdempotencyResponse {
        status: 200,
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: response.body,
    }
}

fn mcp_response_blob(
    response: IdempotencyResponse,
) -> Result<McpIdempotencyBlob, GatewayInvokeError> {
    if response.status != 200 {
        return Err(GatewayInvokeError::Idempotency(
            "stored MCP idempotency response has an invalid status".to_owned(),
        ));
    }
    Ok(McpIdempotencyBlob {
        body: response.body,
    })
}

fn terminal_approval_result(
    status: ApprovalStatus,
    result: Option<Value>,
) -> Result<ToolResult, GatewayInvokeError> {
    match status {
        ApprovalStatus::Succeeded | ApprovalStatus::Failed => result
            .ok_or_else(|| {
                GatewayInvokeError::Idempotency("terminal approval result is missing".to_owned())
            })
            .and_then(|result| {
                serde_json::from_value(result)
                    .map_err(IdempotencyError::Json)
                    .map_err(GatewayInvokeError::from)
            }),
        ApprovalStatus::Denied => Ok(approval_failure_result(
            "approval_denied",
            "The tool call was denied.",
        )),
        ApprovalStatus::Expired => Ok(approval_failure_result(
            "approval_expired",
            "The tool approval expired.",
        )),
        ApprovalStatus::Canceled => Ok(approval_failure_result(
            "approval_canceled",
            "The tool call was canceled.",
        )),
        ApprovalStatus::Stale => Ok(approval_failure_result(
            "approval_stale",
            "The tool changed before approval completed.",
        )),
        ApprovalStatus::Interrupted => Ok(approval_failure_result(
            "approval_interrupted",
            "The approved tool call was interrupted.",
        )),
        ApprovalStatus::Pending | ApprovalStatus::Approved | ApprovalStatus::Executing => {
            Err(GatewayInvokeError::Idempotency(
                "approval wait returned a nonterminal state".to_owned(),
            ))
        }
    }
}

fn approval_failure_result(code: &str, message: &str) -> ToolResult {
    ToolResult {
        ok: false,
        data: None,
        error: Some(PublicToolError {
            code: code.to_owned(),
            message: message.to_owned(),
        }),
        http: None,
    }
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

fn idempotency_tool_call_error(_error: IdempotencyError) -> ToolCallError {
    ToolCallError::Adapter {
        code: "idempotency_failed",
        message: "The idempotent tool call could not be completed safely.".to_owned(),
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
    use std::{collections::BTreeMap, future::pending, time::Duration};

    use serde_json::json;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{
        AppConfig, ExecutorApp,
        catalog::{
            ArtifactKind, AuditContext, CreateSource, CredentialPayload, InitialCatalogSnapshot,
            SourceKind, StagedArtifact, StagedTool, StagedToolBinding, ToolBinding, ToolMode,
        },
        openapi::{OpenApiBinding, OpenApiSecurityAlternative},
    };

    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

    #[test]
    fn completed_protocol_failures_preserve_their_stable_error_code() {
        let result = ToolResult {
            ok: false,
            data: None,
            error: Some(PublicToolError {
                code: "graphql_error".to_owned(),
                message: "sanitized".to_owned(),
            }),
            http: None,
        };
        assert_eq!(completed_failure_code(&result), Some("graphql_error"));
    }

    async fn app_with_mcp_ask_tool_at(server_url: &str) -> (tempfile::TempDir, ExecutorApp) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("Executor should open");
        sqlx::query(
            "INSERT INTO api_tokens \
             (id, name, token_digest, token_prefix, token_suffix, created_at) \
             VALUES ('mcp-owner', 'MCP owner', x'010203', 'exr_test', 'test', 1)",
        )
        .execute(app.pool())
        .await
        .expect("owner token");
        sqlx::query(
            "INSERT INTO admins (id, username, password_hash, created_at) \
             VALUES (1, 'admin', 'unused', 1)",
        )
        .execute(app.pool())
        .await
        .expect("admin");
        app.catalog()
            .create_source_with_catalog(
                CreateSource {
                    kind: SourceKind::Openapi,
                    preferred_slug: "mcp-approval".to_owned(),
                    display_name: "MCP approval source".to_owned(),
                    description: None,
                    configuration: json!({
                        "spec": { "type": "inline" },
                        "allowPrivateNetwork": true
                    })
                    .as_object()
                    .expect("source configuration should be an object")
                    .clone(),
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
                            "required": ["value"],
                            "properties": { "value": { "type": "string" } }
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
                        server_url: server_url.to_owned(),
                        parameters: Vec::new(),
                        request_body: None,
                        security: vec![OpenApiSecurityAlternative {
                            requirements: Vec::new(),
                        }],
                    }),
                }],
                AuditContext::system(Some("mcp-approval-test")),
            )
            .await
            .expect("Ask tool should import");
        (directory, app)
    }

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

    #[tokio::test]
    async fn explicit_mcp_ask_cancellation_blocks_later_approval_and_replays_canceled() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test upstream should bind");
        let server_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("listener should have an address")
        );
        let upstream_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_count = upstream_count.clone();
        let (stop_server, mut server_stopped) = oneshot::channel::<()>();
        let upstream = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut server_stopped => break,
                    accepted = listener.accept() => {
                        let (mut connection, _) = accepted.expect("upstream should accept");
                        server_count.fetch_add(1, Ordering::SeqCst);
                        let mut request = vec![0_u8; 4096];
                        let _ = connection.read(&mut request).await;
                        let _ = connection.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
                        ).await;
                    }
                }
            }
        });
        let (_directory, app) = app_with_mcp_ask_tool_at(&server_url).await;
        let race_hook = Arc::new(ApprovalCancellationRaceHook::default());
        *app.tool_calls()
            .approval_cancellation_race_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(race_hook.clone());
        let service = app.tool_calls().clone();
        let call = ToolCall {
            request_id: "mcp-ask-request".to_owned(),
            actor: ToolActor::api_token("mcp-owner", Some("MCP owner".to_owned())),
            surface: RequestSurface::Mcp,
            execution_id: "downstream-session".to_owned(),
            call_id: "rpc-42".to_owned(),
            worker_generation: 0,
            path: "mcp_approval.write".to_owned(),
            arguments: json!({ "value": "write once" }),
        };
        let retry_call = call.clone();
        let (cancel, canceled) = oneshot::channel::<()>();
        let submission = tokio::spawn(async move {
            service
                .submit_mcp_idempotent(call, "POST /mcp tools/call", "session:rpc-42", async {
                    let _ = canceled.await;
                })
                .await
        });

        let approval_id = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(approval_id) = sqlx::query_scalar::<_, String>(
                    "SELECT approval_id FROM approval_correlations \
                     WHERE execution_id LIKE 'gateway-idempotency:%' AND call_id = 'gateway'",
                )
                .fetch_optional(app.pool())
                .await
                .expect("approval correlation should read")
                {
                    break approval_id;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("approval correlation should appear");
        let pending_approval = app
            .tool_calls()
            .approvals()
            .get_admin(&approval_id)
            .await
            .expect("approval should read before cancellation")
            .expect("approval should exist before cancellation");
        let decision_service = app.tool_calls().clone();
        let decision_approval_id = approval_id.clone();
        let decision = tokio::spawn(async move {
            decision_service
                .decide(
                    &decision_approval_id,
                    "approve-racing-cancel",
                    pending_approval.record.revision,
                    ApprovalDecision::Approve,
                    1,
                )
                .await
        });
        tokio::time::timeout(
            Duration::from_secs(2),
            race_hook.decision_read_acquired.notified(),
        )
        .await
        .expect("approval should hold the cancellation read fence");
        cancel.send(()).expect("wait cancellation should send");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let delivery_pin = sqlx::query_scalar::<_, i64>(
                    "SELECT EXISTS(SELECT 1 FROM approval_delivery_pins WHERE approval_id = ?)",
                )
                .bind(&approval_id)
                .fetch_one(app.pool())
                .await
                .expect("approval delivery pin should read");
                if delivery_pin == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("explicit cancellation should release delivery before fencing execution");
        tokio::time::timeout(
            Duration::from_secs(2),
            race_hook.cancellation_write_queued.notified(),
        )
        .await
        .expect("cancellation should queue behind the approval read fence");
        race_hook.release_decision.notify_one();
        let canceled = submission
            .await
            .expect("submission task should not panic")
            .expect_err("submission wait should be canceled");
        assert!(matches!(canceled, GatewayInvokeError::Canceled));

        let _ = decision.await.expect("decision task should not panic");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let after_later_approval = app
                    .tool_calls()
                    .approvals()
                    .get_admin(&approval_id)
                    .await
                    .expect("approval should reread")
                    .expect("approval should remain stored");
                if after_later_approval.record.status == ApprovalStatus::Canceled {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation should win before approved execution starts");

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = sqlx::query_scalar::<_, String>(
                    "SELECT state FROM gateway_invocation_idempotency \
                     WHERE owner_api_token_id = 'mcp-owner'",
                )
                .fetch_one(app.pool())
                .await
                .expect("idempotency state should read");
                if state == "completed" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("settlement worker should complete the idempotency row");

        let replay = app
            .tool_calls()
            .submit_mcp_idempotent(
                retry_call,
                "POST /mcp tools/call",
                "session:rpc-42",
                pending(),
            )
            .await
            .expect("exact retry should replay");
        assert!(replay.replayed);
        assert!(!replay.result.ok);
        assert_eq!(
            replay
                .result
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            Some("approval_canceled")
        );
        let (rows, state, response_kind) = sqlx::query_as::<_, (i64, String, String)>(
            "SELECT COUNT(*), MIN(state), MIN(response_kind) \
             FROM gateway_invocation_idempotency WHERE owner_api_token_id = 'mcp-owner'",
        )
        .fetch_one(app.pool())
        .await
        .expect("idempotency row should read");
        assert_eq!(rows, 1);
        assert_eq!(state, "completed");
        assert_eq!(response_kind, "tool");
        stop_server.send(()).expect("upstream shutdown should send");
        upstream.await.expect("upstream task should not panic");
        assert_eq!(upstream_count.load(Ordering::SeqCst), 0);
        app.shutdown().await;
    }

    #[tokio::test]
    async fn cancellation_storage_failure_keeps_execution_fenced_until_retry_succeeds() {
        let (_directory, app) = app_with_mcp_ask_tool_at("http://127.0.0.1:9").await;
        let execution_hook = Arc::new(ApprovedExecutionHook::default());
        *app.tool_calls()
            .approved_execution_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(execution_hook.clone());
        let cancel_hook = Arc::new(CancelExecutionHook::default());
        cancel_hook.failures.store(1, Ordering::SeqCst);
        *app.tool_calls()
            .cancel_execution_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cancel_hook.clone());
        let call = ToolCall {
            request_id: "mcp-cancel-storage-failure".to_owned(),
            actor: ToolActor::api_token("mcp-owner", Some("MCP owner".to_owned())),
            surface: RequestSurface::Mcp,
            execution_id: "downstream-session".to_owned(),
            call_id: "rpc-cancel-storage-failure".to_owned(),
            worker_generation: 0,
            path: "mcp_approval.write".to_owned(),
            arguments: json!({ "value": "write once" }),
        };
        let retry_call = call.clone();
        let service = app.tool_calls().clone();
        let (cancel, canceled) = oneshot::channel::<()>();
        let submission = tokio::spawn(async move {
            service
                .submit_mcp_idempotent(
                    call,
                    "POST /mcp tools/call",
                    "session:cancel-storage-failure",
                    async {
                        let _ = canceled.await;
                    },
                )
                .await
        });
        let approval = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(detail) = app
                    .tool_calls()
                    .approvals()
                    .list_admin(crate::approval::ApprovalListQuery {
                        before_sequence: None,
                        limit: 1,
                        status: None,
                    })
                    .await
                    .expect("approvals should list")
                    .items
                    .into_iter()
                    .next()
                {
                    break detail;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("approval should appear");
        cancel.send(()).expect("explicit cancellation should send");
        let first_result = tokio::time::timeout(Duration::from_secs(2), submission)
            .await
            .expect("storage failure should return to the original request")
            .expect("submission task should not panic")
            .expect_err("forced cancellation storage failure should surface");
        assert!(matches!(
            first_result,
            GatewayInvokeError::ToolCall(ToolCallError::Approval(ApprovalError::Database(_)))
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            while cancel_hook.retry_waiters.load(Ordering::SeqCst) < 1 {
                cancel_hook.retry_waiting.notified().await;
            }
        })
        .await
        .expect("deferred cancellation retry should start");

        let decision_service = app.tool_calls().clone();
        let approval_id = approval.id.clone();
        let decision = tokio::spawn(async move {
            decision_service
                .decide(
                    &approval_id,
                    "approve-while-cancel-retries",
                    approval.revision,
                    ApprovalDecision::Approve,
                    1,
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while cancel_hook.retry_waiters.load(Ordering::SeqCst) < 2 {
                cancel_hook.retry_waiting.notified().await;
            }
        })
        .await
        .expect("approval should remain blocked behind cancellation retry");
        assert!(!decision.is_finished());
        assert_eq!(execution_hook.dispatches.load(Ordering::SeqCst), 0);
        cancel_hook.block_retries.store(false, Ordering::SeqCst);
        cancel_hook.release_retries.notify_waiters();
        let decision_result = decision.await.expect("decision task should not panic");
        assert!(decision_result.is_err());

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let detail = app
                    .tool_calls()
                    .approvals()
                    .get_admin(&approval.id)
                    .await
                    .expect("approval should read")
                    .expect("approval should remain stored");
                if detail.record.status == ApprovalStatus::Canceled {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation retry should persist the canceled state");
        let replay = app
            .tool_calls()
            .submit_mcp_idempotent(
                retry_call,
                "POST /mcp tools/call",
                "session:cancel-storage-failure",
                pending(),
            )
            .await
            .expect("retry should replay canceled result");
        assert!(replay.replayed);
        assert_eq!(
            replay
                .result
                .error
                .as_ref()
                .map(|error| error.code.as_str()),
            Some("approval_canceled")
        );
        assert_eq!(execution_hook.dispatches.load(Ordering::SeqCst), 0);
        app.shutdown().await;
    }

    #[tokio::test]
    async fn approval_finish_failure_makes_current_and_replay_outcomes_unknown() {
        let (_directory, app) = app_with_mcp_ask_tool_at("http://127.0.0.1:9").await;
        let execution_hook = Arc::new(ApprovedExecutionHook::default());
        *app.tool_calls()
            .approved_execution_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(execution_hook.clone());
        sqlx::query(
            "CREATE TRIGGER fail_mcp_approval_finish \
             BEFORE UPDATE OF status ON approvals \
             WHEN OLD.status = 'executing' \
              AND NEW.status IN ('succeeded', 'failed', 'interrupted') \
             BEGIN SELECT RAISE(ABORT, 'forced approval finish failure'); END",
        )
        .execute(app.pool())
        .await
        .expect("finish failure trigger should install");

        let call = ToolCall {
            request_id: "mcp-finish-failure".to_owned(),
            actor: ToolActor::api_token("mcp-owner", Some("MCP owner".to_owned())),
            surface: RequestSurface::Mcp,
            execution_id: "downstream-session".to_owned(),
            call_id: "rpc-finish-failure".to_owned(),
            worker_generation: 0,
            path: "mcp_approval.write".to_owned(),
            arguments: json!({ "value": "write once" }),
        };
        let retry_call = call.clone();
        let service = app.tool_calls().clone();
        let submission = tokio::spawn(async move {
            service
                .submit_mcp_idempotent(
                    call,
                    "POST /mcp tools/call",
                    "session:finish-failure",
                    pending(),
                )
                .await
        });
        let approval = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(detail) = app
                    .tool_calls()
                    .approvals()
                    .list_admin(crate::approval::ApprovalListQuery {
                        before_sequence: None,
                        limit: 1,
                        status: None,
                    })
                    .await
                    .expect("approvals should list")
                    .items
                    .into_iter()
                    .next()
                {
                    break detail;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("approval should appear");

        app.tool_calls()
            .decide(
                &approval.id,
                "approve-for-finish-failure",
                approval.revision,
                ApprovalDecision::Approve,
                1,
            )
            .await
            .expect("approval decision should persist");
        tokio::time::timeout(Duration::from_secs(2), execution_hook.started.notified())
            .await
            .expect("approved execution should reach dispatch");
        execution_hook.release.notify_one();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let state = sqlx::query_scalar::<_, String>(
                    "SELECT state FROM gateway_invocation_idempotency \
                     WHERE owner_api_token_id = 'mcp-owner'",
                )
                .fetch_one(app.pool())
                .await
                .expect("idempotency state should read");
                if state == "indeterminate" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("finish failure should first make the invocation indeterminate");
        let unfinished_approval = app
            .tool_calls()
            .approvals()
            .get_admin(&approval.id)
            .await
            .expect("approval should read after finish failure")
            .expect("approval should remain stored after finish failure");
        assert_eq!(unfinished_approval.record.status, ApprovalStatus::Executing);

        let current = tokio::time::timeout(Duration::from_secs(2), submission)
            .await
            .expect("current request should finish")
            .expect("submission task should not panic")
            .expect_err("failed terminal persistence should be uncertain");
        assert!(matches!(current, GatewayInvokeError::OutcomeUnknown));
        let replay = app
            .tool_calls()
            .submit_mcp_idempotent(
                retry_call,
                "POST /mcp tools/call",
                "session:finish-failure",
                pending(),
            )
            .await
            .expect_err("retry should preserve the uncertain outcome");
        assert!(matches!(replay, GatewayInvokeError::OutcomeUnknown));
        let state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM gateway_invocation_idempotency \
             WHERE owner_api_token_id = 'mcp-owner'",
        )
        .fetch_one(app.pool())
        .await
        .expect("idempotency state should read");
        assert_eq!(state, "indeterminate");
        app.shutdown().await;
    }

    #[tokio::test]
    async fn explicit_cancellation_after_execution_starts_returns_and_stays_indeterminate() {
        let (_directory, app) = app_with_mcp_ask_tool_at("http://127.0.0.1:9").await;
        let execution_hook = Arc::new(ApprovedExecutionHook::default());
        *app.tool_calls()
            .approved_execution_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(execution_hook.clone());
        let call = ToolCall {
            request_id: "mcp-cancel-executing".to_owned(),
            actor: ToolActor::api_token("mcp-owner", Some("MCP owner".to_owned())),
            surface: RequestSurface::Mcp,
            execution_id: "downstream-session".to_owned(),
            call_id: "rpc-cancel-executing".to_owned(),
            worker_generation: 0,
            path: "mcp_approval.write".to_owned(),
            arguments: json!({ "value": "write once" }),
        };
        let retry_call = call.clone();
        let service = app.tool_calls().clone();
        let (cancel, canceled) = oneshot::channel::<()>();
        let submission = tokio::spawn(async move {
            service
                .submit_mcp_idempotent(
                    call,
                    "POST /mcp tools/call",
                    "session:cancel-executing",
                    async {
                        let _ = canceled.await;
                    },
                )
                .await
        });
        let approval = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(detail) = app
                    .tool_calls()
                    .approvals()
                    .list_admin(crate::approval::ApprovalListQuery {
                        before_sequence: None,
                        limit: 1,
                        status: None,
                    })
                    .await
                    .expect("approvals should list")
                    .items
                    .into_iter()
                    .next()
                {
                    break detail;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("approval should appear");
        app.tool_calls()
            .decide(
                &approval.id,
                "approve-before-cancel",
                approval.revision,
                ApprovalDecision::Approve,
                1,
            )
            .await
            .expect("approval should persist");
        tokio::time::timeout(Duration::from_secs(2), execution_hook.started.notified())
            .await
            .expect("execution should reach dispatch");
        let executing = app
            .tool_calls()
            .approvals()
            .get_admin(&approval.id)
            .await
            .expect("approval should read while upstream is blocked")
            .expect("approval should remain stored");
        assert_eq!(executing.record.status, ApprovalStatus::Executing);

        cancel.send(()).expect("explicit cancellation should send");
        let canceled = tokio::time::timeout(Duration::from_secs(2), submission)
            .await
            .expect("cancellation should not wait for upstream")
            .expect("submission task should not panic")
            .expect_err("executing request cancellation should return canceled");
        assert!(matches!(canceled, GatewayInvokeError::Canceled));
        let state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM gateway_invocation_idempotency \
             WHERE owner_api_token_id = 'mcp-owner'",
        )
        .fetch_one(app.pool())
        .await
        .expect("idempotency state should read");
        assert_eq!(state, "indeterminate");

        execution_hook.release.notify_one();
        let retry = app
            .tool_calls()
            .submit_mcp_idempotent(
                retry_call,
                "POST /mcp tools/call",
                "session:cancel-executing",
                pending(),
            )
            .await
            .expect_err("completed upstream work must not become a deterministic replay");
        assert!(matches!(retry, GatewayInvokeError::OutcomeUnknown));
        let final_state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM gateway_invocation_idempotency \
             WHERE owner_api_token_id = 'mcp-owner'",
        )
        .fetch_one(app.pool())
        .await
        .expect("final idempotency state should read");
        assert_eq!(final_state, "indeterminate");
        app.shutdown().await;
    }

    #[tokio::test]
    async fn generic_mcp_boundary_replays_exact_blobs_and_terminalizes_drops() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(directory.path().join("mcp-boundary.db"))
                    .create_if_missing(true)
                    .foreign_keys(true)
                    .busy_timeout(Duration::from_secs(2)),
            )
            .await
            .expect("database pool");
        MIGRATOR.run(&pool).await.expect("migrations");
        sqlx::query(
            "INSERT INTO api_tokens (id, name, token_digest, token_prefix, token_suffix, created_at) \
             VALUES ('mcp-owner', 'MCP owner', zeroblob(32), 'tok_', 'tail', 1)",
        )
        .execute(&pool)
        .await
        .expect("owner token");
        let keyring = Keyring::from_master_key([11; 32]).expect("keyring");
        let store = GatewayIdempotencyStore::new(pool.clone(), keyring.clone());
        let approvals = ApprovalStore::system(pool, keyring);
        let tasks = TaskTracker::default();
        let arguments = json!({ "code": "return 1" });
        let request = || IdempotencyRequest {
            owner: IdempotencyOwner {
                owner_api_token_id: "mcp-owner",
            },
            key: "session:request-1",
            route: "mcp tools/call",
            callable_path: "executor.execute",
            arguments: &arguments,
        };
        let IdempotencyClaim::Fresh(record) =
            store.claim(request()).await.expect("fresh reservation")
        else {
            panic!("fresh reservation expected");
        };
        let reservation = McpIdempotencyReservation {
            guard: Some(IdempotencyReservationGuard::new(
                record,
                store.clone(),
                approvals.clone(),
                tasks.clone(),
            )),
        };
        reservation
            .mark_executing()
            .await
            .expect("execution boundary")
            .complete(McpIdempotencyBlob {
                body: br#"{"result":1}"#.to_vec(),
            })
            .await
            .expect("durable completion");
        let IdempotencyClaim::Replay { response, .. } =
            store.claim(request()).await.expect("exact replay")
        else {
            panic!("completed request must replay");
        };
        assert_eq!(response.body, br#"{"result":1}"#);

        let dropped_arguments = json!({ "code": "return 2" });
        let dropped_request = || IdempotencyRequest {
            owner: IdempotencyOwner {
                owner_api_token_id: "mcp-owner",
            },
            key: "session:request-2",
            route: "mcp tools/call",
            callable_path: "executor.execute",
            arguments: &dropped_arguments,
        };
        let IdempotencyClaim::Fresh(record) = store
            .claim(dropped_request())
            .await
            .expect("second reservation")
        else {
            panic!("fresh second reservation expected");
        };
        let execution = McpIdempotencyReservation {
            guard: Some(IdempotencyReservationGuard::new(
                record,
                store.clone(),
                approvals,
                tasks.clone(),
            )),
        }
        .mark_executing()
        .await
        .expect("second execution boundary");
        drop(execution);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(
                    store.claim(dropped_request()).await.expect("dropped claim"),
                    IdempotencyClaim::Indeterminate(_)
                ) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped execution becomes indeterminate");
        tasks.shutdown().await;
    }
}
