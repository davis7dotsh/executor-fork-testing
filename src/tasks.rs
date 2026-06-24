use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use tokio::{sync::oneshot, task::AbortHandle};

#[derive(Clone, Default)]
pub(crate) struct TaskTracker {
    state: Arc<Mutex<TaskState>>,
}

#[derive(Default)]
struct TaskState {
    shutting_down: bool,
    tasks: Vec<TrackedTask>,
}

struct TrackedTask {
    abort: AbortHandle,
    completed: oneshot::Receiver<()>,
}

struct CompletionSignal(Option<oneshot::Sender<()>>);

impl Drop for CompletionSignal {
    fn drop(&mut self) {
        if let Some(completed) = self.0.take() {
            let _ = completed.send(());
        }
    }
}

impl TaskTracker {
    pub(crate) fn spawn<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shutting_down {
            return false;
        }
        state.tasks.retain(|task| !task.abort.is_finished());
        state.tasks.push(spawn_tracked(future));
        true
    }

    pub(crate) fn spawn_pair<F, G>(&self, first: F, second: G) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
        G: Future<Output = ()> + Send + 'static,
    {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shutting_down {
            return false;
        }
        state.tasks.retain(|task| !task.abort.is_finished());
        state.tasks.push(spawn_tracked(first));
        state.tasks.push(spawn_tracked(second));
        true
    }

    pub(crate) fn abort_all(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.shutting_down = true;
        for task in &state.tasks {
            task.abort.abort();
        }
    }

    pub(crate) async fn shutdown(&self) {
        let tasks = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.shutting_down = true;
            std::mem::take(&mut state.tasks)
        };
        for task in &tasks {
            task.abort.abort();
        }
        for task in tasks {
            let _ = task.completed.await;
        }
    }
}

fn spawn_tracked<F>(future: F) -> TrackedTask
where
    F: Future<Output = ()> + Send + 'static,
{
    let (completed, completion) = oneshot::channel();
    let handle = tokio::spawn(async move {
        let _completion = CompletionSignal(Some(completed));
        future.await;
    });
    TrackedTask {
        abort: handle.abort_handle(),
        completed: completion,
    }
}
