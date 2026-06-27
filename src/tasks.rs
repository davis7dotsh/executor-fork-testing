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
    abort_on_shutdown: bool,
    shutdown: Option<oneshot::Sender<()>>,
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
        state.tasks.push(spawn_tracked(future, true, None));
        true
    }

    pub(crate) fn spawn_supervised<F, Fut>(&self, task: F) -> bool
    where
        F: FnOnce(oneshot::Receiver<()>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shutting_down {
            return false;
        }
        state.tasks.retain(|task| !task.abort.is_finished());
        let (shutdown, shutdown_signal) = oneshot::channel();
        state
            .tasks
            .push(spawn_tracked(task(shutdown_signal), false, Some(shutdown)));
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
        state.tasks.push(spawn_tracked(first, true, None));
        state.tasks.push(spawn_tracked(second, true, None));
        true
    }

    pub(crate) fn abort_all(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.shutting_down = true;
        for task in &mut state.tasks {
            if task.abort_on_shutdown {
                task.abort.abort();
            } else if let Some(shutdown) = task.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
    }

    pub(crate) async fn shutdown(&self) {
        let mut tasks = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.shutting_down = true;
            std::mem::take(&mut state.tasks)
        };
        for task in &mut tasks {
            if task.abort_on_shutdown {
                task.abort.abort();
            } else if let Some(shutdown) = task.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
        for task in tasks {
            let _ = task.completed.await;
        }
    }
}

fn spawn_tracked<F>(
    future: F,
    abort_on_shutdown: bool,
    shutdown: Option<oneshot::Sender<()>>,
) -> TrackedTask
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
        abort_on_shutdown,
        shutdown,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use tokio::sync::oneshot;

    use super::TaskTracker;

    #[tokio::test]
    async fn supervised_tasks_receive_shutdown_and_are_awaited() {
        let tracker = TaskTracker::default();
        let completed = Arc::new(AtomicBool::new(false));
        let task_completed = completed.clone();
        let (started_sender, started_receiver) = oneshot::channel();
        let (stopping_sender, stopping_receiver) = oneshot::channel();
        let (release_sender, release_receiver) = oneshot::channel();
        assert!(tracker.spawn_supervised(|shutdown| async move {
            let _ = started_sender.send(());
            let _ = shutdown.await;
            let _ = stopping_sender.send(());
            let _ = release_receiver.await;
            task_completed.store(true, Ordering::SeqCst);
        }));
        started_receiver.await.expect("supervised task starts");

        tracker.abort_all();
        stopping_receiver
            .await
            .expect("supervised task receives shutdown");
        assert!(!completed.load(Ordering::SeqCst));

        release_sender.send(()).expect("supervised task releases");
        tracker.shutdown().await;
        assert!(completed.load(Ordering::SeqCst));
    }
}
