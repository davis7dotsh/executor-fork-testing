use std::sync::{Arc, atomic::Ordering};

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    ExecutionCancellation, HostToolDispatcher, ToolCall as RuntimeToolCall,
    ToolResult as RuntimeToolResult,
};
use crate::{
    actor::ToolActor,
    approval::ApprovalStatus,
    catalog::{CatalogError, RequestSurface},
    invocation::{
        ApprovalWaitError, ToolCall, ToolCallError, ToolCallOAuthError, ToolCallService,
        ToolCallSubmission, ToolDiscoveryError, ToolResult as InvocationToolResult,
    },
};

#[derive(Clone, Debug)]
pub struct InvocationContext {
    pub request_id: String,
    pub actor: ToolActor,
    pub surface: RequestSurface,
    pub execution_id: String,
}

pub struct InvocationToolDispatcher {
    service: ToolCallService,
    context: InvocationContext,
    cleanup_completed: tokio::sync::Mutex<bool>,
}

impl InvocationToolDispatcher {
    pub fn new(service: ToolCallService, context: InvocationContext) -> Self {
        Self {
            service,
            context,
            cleanup_completed: tokio::sync::Mutex::new(false),
        }
    }

    pub async fn finish(&self) {
        self.cancel_pending_once().await;
    }

    pub(crate) fn discard_unstarted(&self) {
        self.service
            .clear_execution_stopping_flag(&self.context.execution_id);
    }

    async fn cancel_pending_once(&self) {
        let mut completed = self.cleanup_completed.lock().await;
        if *completed {
            return;
        }
        self.service
            .cancel_lost_execution(&self.context.execution_id)
            .await;
        *completed = true;
    }

    async fn dispatch_call(
        &self,
        call: RuntimeToolCall,
        cancellation: ExecutionCancellation,
    ) -> RuntimeToolResult {
        if call.execution_id != self.context.execution_id {
            return internal_failure("tool_correlation_failed");
        }
        if cancellation.is_cancelled() {
            return internal_failure("execution_cancelled");
        }
        let service_call = ToolCall {
            request_id: execution_call_request_id(&self.context.request_id, call.call_id),
            actor: self.context.actor.clone(),
            surface: self.context.surface,
            execution_id: self.context.execution_id.clone(),
            call_id: call.call_id.to_string(),
            worker_generation: call.worker_generation,
            path: call.path.clone(),
            arguments: call.arguments.clone(),
        };
        if let Some(result) = self
            .dispatch_builtin(&service_call, cancellation.clone())
            .await
        {
            return result;
        }

        let call_id = service_call.call_id.clone();
        let submission = tokio::select! {
            result = self.service.submit(service_call) => result,
            () = cancellation.cancelled() => {
                return internal_failure("execution_cancelled");
            }
        };
        let submission = match submission {
            Ok(submission) => submission,
            Err(error) => return tool_call_failure(&error),
        };
        match submission {
            ToolCallSubmission::Completed(result) => invocation_result(result),
            ToolCallSubmission::ApprovalRequired(approval) => {
                let detail = self
                    .service
                    .wait_for_approval(
                        approval,
                        &self.context.actor,
                        &self.context.execution_id,
                        &call_id,
                        cancellation.cancelled(),
                    )
                    .await;
                match detail {
                    Ok(detail) => approval_result(detail.record.status, detail.result),
                    Err(ApprovalWaitError::Canceled) => internal_failure("execution_cancelled"),
                    Err(ApprovalWaitError::Approval(_)) => internal_failure("approval_wait_failed"),
                }
            }
        }
    }

    async fn dispatch_builtin(
        &self,
        call: &ToolCall,
        cancellation: ExecutionCancellation,
    ) -> Option<RuntimeToolResult> {
        let result = match call.path.as_str() {
            "search" => {
                let arguments: SearchArguments =
                    match serde_json::from_value(call.arguments.clone()) {
                        Ok(arguments) => arguments,
                        Err(_) => {
                            return Some(failure(
                                "invalid_tool_arguments",
                                "Search arguments are invalid.",
                            ));
                        }
                    };
                if arguments.query.chars().count() > 256 {
                    return Some(failure(
                        "invalid_query",
                        "Search queries may contain at most 256 characters.",
                    ));
                }
                tokio::select! {
                    result = self.service.discover_search(
                        call,
                        arguments.query,
                        arguments.namespace,
                        arguments.limit.unwrap_or(12),
                        arguments.offset.unwrap_or(0),
                    ) => result.map(|page| serde_json::to_value(page).expect("discovery pages serialize")),
                    () = cancellation.cancelled() => {
                        return Some(internal_failure("execution_cancelled"));
                    }
                }
            }
            "describe" => {
                let arguments: PathArguments = match serde_json::from_value(call.arguments.clone())
                {
                    Ok(arguments) => arguments,
                    Err(_) => {
                        return Some(failure(
                            "invalid_tool_arguments",
                            "Describe arguments are invalid.",
                        ));
                    }
                };
                tokio::select! {
                    result = self.service.discover_describe(call, &arguments.path) => result.map(|tool| serde_json::to_value(tool).expect("described tools serialize")),
                    () = cancellation.cancelled() => {
                        return Some(internal_failure("execution_cancelled"));
                    }
                }
            }
            "sources" => tokio::select! {
                result = self.service.discover_sources(call) => result,
                () = cancellation.cancelled() => {
                    return Some(internal_failure("execution_cancelled"));
                }
            },
            _ => return None,
        };
        Some(match result {
            Ok(value) => RuntimeToolResult::Success { value },
            Err(error) => discovery_failure(&error),
        })
    }
}

fn discovery_failure(error: &ToolDiscoveryError) -> RuntimeToolResult {
    match error {
        ToolDiscoveryError::Busy => {
            failure("search_busy", "Tool search is busy. Try again shortly.")
        }
        ToolDiscoveryError::Catalog(error) => catalog_failure(error),
        ToolDiscoveryError::Interrupted => internal_failure("discovery_interrupted"),
    }
}

#[async_trait]
impl HostToolDispatcher for InvocationToolDispatcher {
    async fn dispatch(
        &self,
        call: RuntimeToolCall,
        cancellation: ExecutionCancellation,
    ) -> RuntimeToolResult {
        self.dispatch_call(call, cancellation).await
    }

    async fn execution_finished(&self, execution_id: &str) {
        if execution_id == self.context.execution_id {
            self.cancel_pending_once().await;
        }
    }

    async fn execution_stopping(&self, execution_id: &str) {
        if execution_id == self.context.execution_id {
            self.service.mark_execution_lost(execution_id).await;
        }
    }

    fn cancellation_hook(&self, execution_id: &str) -> Option<Arc<dyn Fn() + Send + Sync>> {
        if execution_id != self.context.execution_id {
            return None;
        }
        let execution_stopping = self.service.execution_stopping_flag(execution_id);
        Some(Arc::new(move || {
            execution_stopping.store(true, Ordering::Release);
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArguments {
    query: String,
    namespace: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathArguments {
    path: String,
}

fn approval_result(status: ApprovalStatus, result: Option<Value>) -> RuntimeToolResult {
    match status {
        ApprovalStatus::Succeeded | ApprovalStatus::Failed => result
            .and_then(|result| serde_json::from_value::<InvocationToolResult>(result).ok())
            .map(invocation_result)
            .unwrap_or_else(|| internal_failure("approval_result_invalid")),
        ApprovalStatus::Denied => failure("approval_denied", "The tool call was denied."),
        ApprovalStatus::Expired => failure("approval_expired", "The tool approval expired."),
        ApprovalStatus::Canceled => failure("approval_canceled", "The tool call was canceled."),
        ApprovalStatus::Stale => failure(
            "approval_stale",
            "The tool changed before approval completed.",
        ),
        ApprovalStatus::Interrupted => result
            .and_then(|result| serde_json::from_value::<InvocationToolResult>(result).ok())
            .map(invocation_result)
            .unwrap_or_else(|| internal_failure("approval_interrupted")),
        ApprovalStatus::Pending | ApprovalStatus::Approved | ApprovalStatus::Executing => {
            internal_failure("approval_state_invalid")
        }
    }
}

fn invocation_result(result: InvocationToolResult) -> RuntimeToolResult {
    if result.ok {
        RuntimeToolResult::Success {
            value: result.data.unwrap_or(Value::Null),
        }
    } else if let Some(error) = result.error {
        failure(error.code, error.message)
    } else {
        internal_failure("tool_result_invalid")
    }
}

fn tool_call_failure(error: &ToolCallError) -> RuntimeToolResult {
    match error {
        ToolCallError::Catalog(error) => catalog_failure(error),
        ToolCallError::Adapter { code, message } => failure(*code, message.clone()),
        ToolCallError::OAuth(error) if matches!(error, ToolCallOAuthError::Internal) => {
            internal_failure(error.code())
        }
        ToolCallError::OAuth(error) => failure(
            error.code(),
            "Managed OAuth could not be resolved safely for this tool call.",
        ),
        ToolCallError::ArgumentsTooLarge => failure(
            "arguments_too_large",
            "Tool arguments exceed the allowed size.",
        ),
        ToolCallError::InvalidArguments => failure(
            "invalid_tool_arguments",
            "Tool arguments do not match the input schema.",
        ),
        ToolCallError::Stale => failure("invocation_stale", "The tool changed before invocation."),
        ToolCallError::Outbound(error) => failure(
            error.code(),
            "The upstream request could not be completed safely.",
        ),
        ToolCallError::Protocol(error) => match error.category {
            crate::protocols::ProtocolErrorCategory::CorruptData
            | crate::protocols::ProtocolErrorCategory::Internal => internal_failure(error.code),
            _ => failure(error.code, error.message.clone()),
        },
        ToolCallError::ResultTooLarge => failure(
            "result_too_large",
            "The tool result exceeds the allowed size.",
        ),
        ToolCallError::Approval(error) => approval_failure(error),
    }
}

fn approval_failure(error: &crate::approval::ApprovalError) -> RuntimeToolResult {
    use crate::approval::ApprovalError;

    match error {
        ApprovalError::Capacity { .. } => failure(
            "approval_capacity",
            "Too many approvals are active. Resolve an existing approval and retry.",
        ),
        ApprovalError::OwnerTokenInactive => failure(
            "token_revoked",
            "The API token that owns this execution is no longer active.",
        ),
        ApprovalError::Expired => failure("approval_expired", "The tool approval expired."),
        ApprovalError::WorkerGenerationConflict => failure(
            "approval_stale",
            "The approval belongs to another execution generation.",
        ),
        ApprovalError::RevisionConflict { .. } | ApprovalError::DecisionConflict => failure(
            "approval_conflict",
            "The approval changed before the request completed.",
        ),
        ApprovalError::CorrelationConflict => failure(
            "approval_correlation_conflict",
            "The execution call was reused for a different request.",
        ),
        ApprovalError::CorrelationRetired => failure(
            "approval_correlation_retired",
            "The execution call replay is no longer available.",
        ),
        ApprovalError::InvalidTransition { .. } => failure(
            "approval_invalid_state",
            "The approval can no longer make this transition.",
        ),
        ApprovalError::Validation { code, message } => failure(*code, message.clone()),
        ApprovalError::PayloadTooLarge { .. } => failure(
            "approval_payload_too_large",
            "The approval payload exceeds the allowed size.",
        ),
        ApprovalError::NotFound => failure("approval_not_found", "The approval was not found."),
        ApprovalError::Database(_)
        | ApprovalError::Crypto(_)
        | ApprovalError::Json(_)
        | ApprovalError::CorruptData(_) => internal_failure("approval_submit_failed"),
    }
}

fn catalog_failure(error: &CatalogError) -> RuntimeToolResult {
    match error {
        CatalogError::Validation { code, message } => failure(*code, message.clone()),
        CatalogError::ToolDisabled { .. } => {
            failure("tool_disabled", "The requested tool is disabled.")
        }
        CatalogError::ToolNotFound { .. } | CatalogError::NotFound { .. } => {
            failure("tool_not_found", "The requested tool does not exist.")
        }
        CatalogError::RevisionConflict { .. } => failure(
            "revision_conflict",
            "The catalog changed before the request completed.",
        ),
        CatalogError::Database(_)
        | CatalogError::Crypto(_)
        | CatalogError::Json(_)
        | CatalogError::CorruptData(_) => internal_failure("catalog_failed"),
    }
}

fn failure(code: impl Into<String>, message: impl Into<String>) -> RuntimeToolResult {
    RuntimeToolResult::Failure {
        code: code.into(),
        message: message.into(),
    }
}

fn internal_failure(code: impl Into<String>) -> RuntimeToolResult {
    RuntimeToolResult::InternalFailure { code: code.into() }
}

fn execution_call_request_id(request_id: &str, call_id: u64) -> String {
    const MAX_REQUEST_LOG_ID_BYTES: usize = 128;
    let suffix = format!(":call:{call_id}");
    if request_id.len() + suffix.len() <= MAX_REQUEST_LOG_ID_BYTES {
        return format!("{request_id}{suffix}");
    }

    let mut digest = Sha256::new();
    digest.update(b"executor-runtime-request-log-v1");
    digest.update((request_id.len() as u64).to_be_bytes());
    digest.update(request_id.as_bytes());
    format!("exec:{:x}{suffix}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::execution_call_request_id;

    #[test]
    fn execution_call_request_ids_respect_the_request_log_bound() {
        let bounded_parent = "x".repeat(102);
        let bounded = execution_call_request_id(&bounded_parent, u64::MAX);
        assert_eq!(bounded.len(), 128);
        assert!(bounded.starts_with(&bounded_parent));

        let oversized_parent = "private-request-identity".repeat(64);
        let first = execution_call_request_id(&oversized_parent, u64::MAX);
        let repeated = execution_call_request_id(&oversized_parent, u64::MAX);
        let distinct = execution_call_request_id(&format!("{oversized_parent}-other"), u64::MAX);
        assert_eq!(first, repeated);
        assert_ne!(first, distinct);
        assert!(first.len() <= 128);
        assert!(!first.contains(oversized_parent.as_str()));
    }
}
