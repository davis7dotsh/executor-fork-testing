use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use thiserror::Error;
use tokio::sync::Notify;
use uuid::Uuid;

use crate::{
    actor::ToolActor,
    catalog::RequestSurface,
    invocation::ToolCallService,
    runtime::{
        ConsoleEntry, ExecutionCancellation, ExecutionRequest, HostToolDispatcher,
        InvocationContext, InvocationToolDispatcher, RuntimeFailure, RuntimeManager,
        ToolCallRecord,
    },
};

#[derive(Clone)]
pub struct ExecutionService {
    runtime: RuntimeManager,
    tool_calls: ToolCallService,
    active: ActiveExecutions,
}

#[derive(Clone, Debug)]
pub struct ExecuteCodeRequest {
    pub request_id: String,
    pub actor: ToolActor,
    pub surface: RequestSurface,
    pub code: String,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ExecuteCodeOutput {
    pub execution_id: String,
    pub result: serde_json::Value,
    pub emits: Vec<serde_json::Value>,
    pub console: Vec<ConsoleEntry>,
    pub calls: Vec<ToolCallRecord>,
}

#[derive(Debug, Error)]
pub enum ExecutionServiceError {
    #[error("TypeScript source exceeded 1 MiB")]
    SourceTooLarge,
    #[error("execution timeout must be between 1 millisecond and 5 minutes")]
    InvalidTimeout,
    #[error("the TypeScript runtime is shutting down")]
    ShuttingDown,
    #[error("the API token is no longer active")]
    OwnerRevoked,
    #[error("the execution actor stopped unexpectedly")]
    ActorFailed,
    #[error(transparent)]
    Runtime(#[from] RuntimeFailure),
}

impl ExecutionService {
    pub fn new(runtime: RuntimeManager, tool_calls: ToolCallService) -> Self {
        Self {
            runtime,
            tool_calls,
            active: ActiveExecutions::default(),
        }
    }

    pub async fn execute(
        &self,
        request: ExecuteCodeRequest,
    ) -> Result<ExecuteCodeOutput, ExecutionServiceError> {
        if request.code.len() > crate::runtime::MAX_SOURCE_BYTES {
            return Err(ExecutionServiceError::SourceTooLarge);
        }
        if request.timeout.is_zero() || request.timeout > Duration::from_secs(300) {
            return Err(ExecutionServiceError::InvalidTimeout);
        }

        let execution_id = Uuid::new_v4().to_string();
        let cancellation = ExecutionCancellation::default();
        let dispatcher = Arc::new(InvocationToolDispatcher::new(
            self.tool_calls.clone(),
            InvocationContext {
                request_id: request.request_id,
                actor: request.actor.clone(),
                surface: request.surface,
                execution_id: execution_id.clone(),
            },
        ));
        let stopper = ExecutionStopper {
            dispatcher: dispatcher.clone(),
            cancellation: cancellation.clone(),
            execution_id: execution_id.clone(),
        };
        if let Some(hook) = dispatcher.cancellation_hook(&execution_id) {
            cancellation.register_cancel_hook(hook);
        }
        let active_execution =
            match self
                .active
                .register(execution_id.clone(), request.actor.clone(), stopper.clone())
            {
                Ok(active_execution) => active_execution,
                Err(error) => {
                    dispatcher.discard_unstarted();
                    return Err(error.into());
                }
            };
        let runtime = self.runtime.clone();
        let runtime_execution_id = execution_id.clone();
        let runtime_cancellation = cancellation.clone();
        let execution = tokio::spawn(async move {
            let _active_execution = active_execution;
            runtime
                .execute(
                    ExecutionRequest {
                        execution_id: runtime_execution_id,
                        code: request.code,
                        timeout: request.timeout,
                    },
                    dispatcher,
                    runtime_cancellation,
                )
                .await
        });
        let mut cancel_on_drop = CancelOnDrop(Some(stopper));
        let output = match execution.await {
            Ok(output) => {
                cancel_on_drop.disarm();
                output?
            }
            Err(_) => return Err(ExecutionServiceError::ActorFailed),
        };
        Ok(ExecuteCodeOutput {
            execution_id,
            result: output.result,
            emits: output.emits,
            console: output.console,
            calls: output.tool_calls,
        })
    }

    pub async fn revoke_owner(&self, owner_api_token_id: &str) {
        self.active.revoke_owner(owner_api_token_id).await;
    }

    pub fn cancel_all(&self) {
        self.active.cancel_all();
    }

    pub async fn shutdown(&self) {
        self.active.shutdown().await;
    }
}

#[derive(Clone, Default)]
struct ActiveExecutions {
    state: Arc<Mutex<ActiveExecutionState>>,
    changed: Arc<Notify>,
}

#[derive(Default)]
struct ActiveExecutionState {
    shutting_down: bool,
    revoked_owners: HashSet<String>,
    entries: HashMap<String, ActiveExecution>,
}

struct ActiveExecution {
    actor: ToolActor,
    stopper: ExecutionStopper,
}

struct ActiveExecutionGuard {
    execution_id: String,
    state: Arc<Mutex<ActiveExecutionState>>,
    changed: Arc<Notify>,
}

#[derive(Debug)]
enum ExecutionRegistrationError {
    ShuttingDown,
    OwnerRevoked,
}

impl From<ExecutionRegistrationError> for ExecutionServiceError {
    fn from(error: ExecutionRegistrationError) -> Self {
        match error {
            ExecutionRegistrationError::ShuttingDown => Self::ShuttingDown,
            ExecutionRegistrationError::OwnerRevoked => Self::OwnerRevoked,
        }
    }
}

impl ActiveExecutions {
    fn register(
        &self,
        execution_id: String,
        actor: ToolActor,
        stopper: ExecutionStopper,
    ) -> Result<ActiveExecutionGuard, ExecutionRegistrationError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shutting_down {
            return Err(ExecutionRegistrationError::ShuttingDown);
        }
        if actor
            .api_token_id()
            .is_some_and(|token_id| state.revoked_owners.contains(token_id))
        {
            return Err(ExecutionRegistrationError::OwnerRevoked);
        }
        state
            .entries
            .insert(execution_id.clone(), ActiveExecution { actor, stopper });
        Ok(ActiveExecutionGuard {
            execution_id,
            state: self.state.clone(),
            changed: self.changed.clone(),
        })
    }

    async fn revoke_owner(&self, owner_api_token_id: &str) {
        let stoppers = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.revoked_owners.insert(owner_api_token_id.to_owned());
            state
                .entries
                .values()
                .filter(|execution| execution.actor.api_token_id() == Some(owner_api_token_id))
                .map(|execution| execution.stopper.clone())
                .collect::<Vec<_>>()
        };
        for stopper in stoppers {
            stopper.stop().await;
        }
    }

    fn cancel_all(&self) {
        let stoppers = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.shutting_down = true;
            state
                .entries
                .values()
                .map(|execution| execution.stopper.clone())
                .collect::<Vec<_>>()
        };
        for stopper in stoppers {
            stopper.stop_in_background();
        }
    }

    async fn shutdown(&self) {
        let stoppers = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.shutting_down = true;
            state
                .entries
                .values()
                .map(|execution| execution.stopper.clone())
                .collect::<Vec<_>>()
        };
        for stopper in stoppers {
            stopper.stop().await;
        }
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .is_empty()
            {
                return;
            }
            changed.await;
        }
    }
}

impl Drop for ActiveExecutionGuard {
    fn drop(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .remove(&self.execution_id);
        self.changed.notify_waiters();
    }
}

#[derive(Clone)]
struct ExecutionStopper {
    dispatcher: Arc<dyn HostToolDispatcher>,
    cancellation: ExecutionCancellation,
    execution_id: String,
}

impl ExecutionStopper {
    async fn stop(self) {
        self.dispatcher.execution_stopping(&self.execution_id).await;
        self.cancellation.cancel();
    }

    fn stop_in_background(self) {
        self.cancellation.cancel();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                self.dispatcher.execution_stopping(&self.execution_id).await;
            });
        }
    }
}

struct CancelOnDrop(Option<ExecutionStopper>);

impl CancelOnDrop {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(stopper) = self.0.take() {
            stopper.stop_in_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use super::ActiveExecutions;
    use crate::{actor::ToolActor, runtime::ExecutionCancellation};

    #[tokio::test]
    async fn shutdown_waits_for_detached_execution_cleanup() {
        let executions = ActiveExecutions::default();
        let cancellation = ExecutionCancellation::default();
        struct TestDispatcher;
        #[async_trait::async_trait]
        impl crate::runtime::HostToolDispatcher for TestDispatcher {
            async fn dispatch(
                &self,
                _: crate::runtime::ToolCall,
                _: ExecutionCancellation,
            ) -> crate::runtime::ToolResult {
                unreachable!("test dispatcher is never called")
            }
        }
        let stopper = super::ExecutionStopper {
            dispatcher: std::sync::Arc::new(TestDispatcher),
            cancellation: cancellation.clone(),
            execution_id: "detached-execution".to_owned(),
        };
        let guard = executions
            .register(
                "detached-execution".to_owned(),
                ToolActor::api_token("owner-token", None),
                stopper,
            )
            .expect("execution should register");
        let shutdown_executions = executions.clone();
        let mut shutdown = tokio::spawn(async move {
            shutdown_executions.shutdown().await;
        });
        tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled())
            .await
            .expect("shutdown should cancel the execution");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut shutdown)
                .await
                .is_err(),
            "shutdown must wait for the detached actor guard"
        );
        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("shutdown should finish after cleanup")
            .expect("shutdown task should not panic");
    }

    #[test]
    fn background_stop_runs_cancellation_hooks_synchronously() {
        let cancellation = ExecutionCancellation::default();
        let stopped = Arc::new(AtomicBool::new(false));
        let hook_stopped = stopped.clone();
        cancellation.register_cancel_hook(Arc::new(move || {
            hook_stopped.store(true, Ordering::Release);
        }));
        struct TestDispatcher;
        #[async_trait::async_trait]
        impl crate::runtime::HostToolDispatcher for TestDispatcher {
            async fn dispatch(
                &self,
                _: crate::runtime::ToolCall,
                _: ExecutionCancellation,
            ) -> crate::runtime::ToolResult {
                unreachable!("test dispatcher is never called")
            }
        }
        let stopper = super::ExecutionStopper {
            dispatcher: Arc::new(TestDispatcher),
            cancellation: cancellation.clone(),
            execution_id: "synchronous-stop".to_owned(),
        };

        stopper.stop_in_background();

        assert!(stopped.load(Ordering::Acquire));
        assert!(cancellation.is_cancelled());
    }
}
