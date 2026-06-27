use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;

mod parent;
mod protocol;
mod transform;
mod worker;

mod invocation;

pub use invocation::{InvocationContext, InvocationToolDispatcher};
pub use parent::RuntimeManager;
pub use worker::worker_main;

pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct ExecutionRequest {
    pub execution_id: String,
    pub code: String,
    pub timeout: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLimits {
    pub wall_time_millis: u64,
    pub heap_bytes: usize,
    pub stack_bytes: usize,
    pub argument_bytes: usize,
    pub result_bytes: usize,
    pub aggregate_bytes: usize,
    pub max_calls: usize,
    pub max_concurrent_calls: usize,
    pub max_console_entries: usize,
    pub max_console_bytes: usize,
    pub max_emits: usize,
    pub max_emit_bytes: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            wall_time_millis: 30_000,
            heap_bytes: 64 * 1024 * 1024,
            stack_bytes: 1024 * 1024,
            argument_bytes: 8 * 1024 * 1024,
            result_bytes: 8 * 1024 * 1024,
            aggregate_bytes: 32 * 1024 * 1024,
            max_calls: 128,
            max_concurrent_calls: 16,
            max_console_entries: 1000,
            max_console_bytes: 256 * 1024,
            max_emits: 100,
            max_emit_bytes: 8 * 1024 * 1024,
        }
    }
}

impl RuntimeLimits {
    fn validate(&self) -> Result<(), RuntimeFailure> {
        let valid = self.wall_time_millis > 0
            && self.wall_time_millis <= 300_000
            && self.heap_bytes > 0
            && self.heap_bytes <= 64 * 1024 * 1024
            && self.stack_bytes > 0
            && self.stack_bytes <= 1024 * 1024
            && self.argument_bytes > 0
            && self.argument_bytes <= 8 * 1024 * 1024
            && self.result_bytes > 0
            && self.result_bytes <= 8 * 1024 * 1024
            && self.aggregate_bytes > 0
            && self.aggregate_bytes <= 32 * 1024 * 1024
            && self.max_calls > 0
            && self.max_calls <= 128
            && self.max_concurrent_calls > 0
            && self.max_concurrent_calls <= 16
            && self.max_console_entries <= 1000
            && self.max_console_bytes <= 256 * 1024
            && self.max_emits <= 100
            && self.max_emit_bytes <= 8 * 1024 * 1024;
        if valid {
            Ok(())
        } else {
            Err(RuntimeFailure::internal(
                "runtime_limits_invalid",
                "sandbox limits exceeded the supported maximum",
            ))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleLevel {
    Debug,
    Info,
    Log,
    Warn,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConsoleEntry {
    pub level: ConsoleLevel,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolResult {
    Success {
        value: Value,
    },
    Failure {
        code: String,
        message: String,
    },
    #[doc(hidden)]
    InternalFailure {
        code: String,
    },
}

#[derive(Clone, Debug)]
pub struct ToolCall {
    pub execution_id: String,
    pub worker_generation: u64,
    pub call_id: u64,
    pub path: String,
    pub arguments: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallRecord {
    pub call_id: u64,
    pub path: String,
    pub result: ToolResult,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionOutput {
    pub result: Value,
    pub emits: Vec<Value>,
    pub console: Vec<ConsoleEntry>,
    pub tool_calls: Vec<ToolCallRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFailure {
    pub code: String,
    pub message: String,
    pub internal: bool,
}

impl RuntimeFailure {
    pub fn public(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            internal: false,
        }
    }

    pub(crate) fn internal(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            internal: true,
        }
    }
}

impl std::fmt::Display for RuntimeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RuntimeFailure {}

#[derive(Clone, Default)]
pub struct ExecutionCancellation {
    inner: Arc<CancellationInner>,
}

#[derive(Default)]
struct CancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
    hooks: std::sync::Mutex<CancellationHooks>,
}

#[derive(Default)]
struct CancellationHooks {
    cancelling: bool,
    pending: Vec<Arc<dyn Fn() + Send + Sync>>,
}

impl ExecutionCancellation {
    pub fn cancel(&self) {
        let mut pending = {
            let mut hooks = self
                .inner
                .hooks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.inner.cancelled.load(Ordering::Acquire) || hooks.cancelling {
                return;
            }
            hooks.cancelling = true;
            std::mem::take(&mut hooks.pending)
        };
        loop {
            for hook in pending.drain(..) {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook()));
            }
            let mut hooks = self
                .inner
                .hooks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if hooks.pending.is_empty() {
                self.inner.cancelled.store(true, Ordering::Release);
                hooks.cancelling = false;
                break;
            }
            pending = std::mem::take(&mut hooks.pending);
        }
        self.inner.notify.notify_waiters();
    }

    pub fn register_cancel_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        let mut hooks = self
            .inner
            .hooks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.inner.cancelled.load(Ordering::Acquire) {
            drop(hooks);
            hook();
        } else {
            hooks.pending.push(hook);
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[async_trait]
pub trait HostToolDispatcher: Send + Sync + 'static {
    async fn dispatch(&self, call: ToolCall, cancellation: ExecutionCancellation) -> ToolResult;

    async fn execution_stopping(&self, _execution_id: &str) {}

    fn cancellation_hook(&self, _execution_id: &str) -> Option<Arc<dyn Fn() + Send + Sync>> {
        None
    }

    async fn execution_finished(&self, _execution_id: &str) {}
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::ExecutionCancellation;

    #[test]
    fn cancellation_hooks_are_reentrant_and_panic_safe() {
        let cancellation = ExecutionCancellation::default();
        let first_hook_ran = Arc::new(AtomicBool::new(false));
        let nested_hook_ran = Arc::new(AtomicBool::new(false));
        let hook_cancellation = cancellation.clone();
        let hook_first = first_hook_ran.clone();
        let hook_nested = nested_hook_ran.clone();
        cancellation.register_cancel_hook(Arc::new(move || {
            hook_first.store(true, Ordering::Release);
            hook_cancellation.register_cancel_hook(Arc::new({
                let hook_nested = hook_nested.clone();
                move || hook_nested.store(true, Ordering::Release)
            }));
            hook_cancellation.cancel();
        }));
        cancellation.register_cancel_hook(Arc::new(|| panic!("hook failure")));

        cancellation.cancel();

        assert!(cancellation.is_cancelled());
        assert!(first_hook_ran.load(Ordering::Acquire));
        assert!(nested_hook_ran.load(Ordering::Acquire));
    }
}
