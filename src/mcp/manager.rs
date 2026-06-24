use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use thiserror::Error;
use tokio::sync::Notify;

use super::upstream::stdio::StdioTemplateRegistry;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct McpConnectionManager {
    inner: Arc<ManagerInner>,
}

struct ManagerInner {
    stdio_templates: Arc<StdioTemplateRegistry>,
    shutting_down: AtomicBool,
    active_operations: AtomicUsize,
    idle: Notify,
    watcher_operations: tokio::sync::Mutex<()>,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    watcher_state: Mutex<WatcherState>,
    next_watcher_generation: AtomicU64,
}

#[derive(Default)]
struct WatcherState {
    active: HashMap<String, WatcherTask>,
    retired_sources: HashSet<String>,
    latest_source_revisions: HashMap<String, i64>,
    pending: Vec<PendingWatcherTask>,
}

struct PendingWatcherTask {
    source_id: String,
    task: tokio::task::JoinHandle<()>,
}

struct WatcherTask {
    generation: u64,
    source_revision: i64,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

pub(crate) struct McpOperationGuard {
    inner: Arc<ManagerInner>,
}

#[derive(Clone)]
pub(crate) struct WatcherRevisionLease {
    inner: Arc<ManagerInner>,
    source_id: String,
    generation: u64,
}

pub(crate) struct WatcherRevisionGuard {
    inner: Arc<ManagerInner>,
    source_id: String,
    generation: u64,
    expected_revision: i64,
    _lifecycle: tokio::sync::OwnedMutexGuard<()>,
}

#[derive(Debug, Error)]
#[error("MCP connections are shutting down")]
pub(crate) struct McpShuttingDown;

impl McpConnectionManager {
    pub(crate) fn new(stdio_templates: StdioTemplateRegistry) -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                stdio_templates: Arc::new(stdio_templates),
                shutting_down: AtomicBool::new(false),
                active_operations: AtomicUsize::new(0),
                idle: Notify::new(),
                watcher_operations: tokio::sync::Mutex::new(()),
                lifecycle: Arc::new(tokio::sync::Mutex::new(())),
                watcher_state: Mutex::new(WatcherState::default()),
                next_watcher_generation: AtomicU64::new(1),
            }),
        }
    }

    pub(crate) fn stdio_templates(&self) -> &Arc<StdioTemplateRegistry> {
        &self.inner.stdio_templates
    }

    pub(crate) fn begin_operation(&self) -> Result<McpOperationGuard, McpShuttingDown> {
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(McpShuttingDown);
        }
        self.inner.active_operations.fetch_add(1, Ordering::AcqRel);
        if self.inner.shutting_down.load(Ordering::Acquire) {
            if self.inner.active_operations.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.inner.idle.notify_waiters();
            }
            return Err(McpShuttingDown);
        }
        Ok(McpOperationGuard {
            inner: self.inner.clone(),
        })
    }

    pub(crate) fn begin_shutdown(&self) {
        self.inner.shutting_down.store(true, Ordering::Release);
        let mut state = self
            .inner
            .watcher_state
            .lock()
            .expect("MCP watcher mutex poisoned");
        for watcher in state.active.values_mut() {
            cancel_watcher(watcher);
        }
        prune_finished_tasks(&mut state.pending);
        drop(state);
        if self.inner.active_operations.load(Ordering::Acquire) == 0 {
            self.inner.idle.notify_waiters();
        }
    }

    /// Replaces a source watcher after its predecessor has completely stopped.
    ///
    /// `Ok(false)` means the source was retired or superseded while an install was prepared.
    pub(crate) async fn replace_watcher<Factory, Watcher>(
        &self,
        source_id: String,
        source_revision: i64,
        factory: Factory,
    ) -> Result<bool, McpShuttingDown>
    where
        Factory: FnOnce(tokio::sync::oneshot::Receiver<()>, WatcherRevisionLease) -> Watcher
            + Send
            + 'static,
        Watcher: Future<Output = ()> + Send + 'static,
    {
        let _operation = self.inner.watcher_operations.lock().await;
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(McpShuttingDown);
        }

        let (previous, pending) = {
            let _lifecycle = self.inner.lifecycle.lock().await;
            let mut state = self
                .inner
                .watcher_state
                .lock()
                .expect("MCP watcher mutex poisoned");
            prune_finished_tasks(&mut state.pending);
            if state.retired_sources.contains(&source_id) {
                return Ok(false);
            }
            if state
                .latest_source_revisions
                .get(&source_id)
                .is_some_and(|latest| *latest > source_revision)
            {
                return Ok(false);
            }
            state
                .latest_source_revisions
                .insert(source_id.clone(), source_revision);
            let previous = state.active.remove(&source_id);
            let pending = take_pending_tasks(&mut state, &source_id);
            (previous, pending)
        };
        if let Some(previous) = previous {
            stop_and_join_watcher(previous).await;
        }
        join_tasks(pending).await;

        let (cancel, canceled) = tokio::sync::oneshot::channel();
        let (start, mut started) = tokio::sync::oneshot::channel();
        let generation = self
            .inner
            .next_watcher_generation
            .fetch_add(1, Ordering::Relaxed);
        let inner = self.inner.clone();
        let cleanup_source_id = source_id.clone();
        let revision_lease = WatcherRevisionLease {
            inner: self.inner.clone(),
            source_id: source_id.clone(),
            generation,
        };
        let mut canceled = canceled;
        let task = tokio::spawn(async move {
            let _cleanup = WatcherCleanup {
                inner: inner.clone(),
                source_id: cleanup_source_id.clone(),
                generation,
            };
            tokio::select! {
                start = &mut started => {
                    if start.is_ok() {
                        factory(canceled, revision_lease).await;
                    }
                }
                _ = &mut canceled => {}
            }
        });
        let mut replacement = Some(WatcherTask {
            generation,
            source_revision,
            cancel: Some(cancel),
            task,
        });
        let installed = {
            let _lifecycle = self.inner.lifecycle.lock().await;
            let mut state = self
                .inner
                .watcher_state
                .lock()
                .expect("MCP watcher mutex poisoned");
            prune_finished_tasks(&mut state.pending);
            if self.inner.shutting_down.load(Ordering::Acquire) {
                None
            } else if state.retired_sources.contains(&source_id)
                || state
                    .latest_source_revisions
                    .get(&source_id)
                    .is_some_and(|latest| *latest > source_revision)
            {
                Some(false)
            } else {
                state
                    .active
                    .insert(source_id, replacement.take().expect("replacement exists"));
                Some(true)
            }
        };

        match installed {
            Some(true) => {
                let _ = start.send(());
                Ok(true)
            }
            Some(false) => {
                stop_and_join_watcher(replacement.expect("uninstalled replacement exists")).await;
                Ok(false)
            }
            None => {
                stop_and_join_watcher(replacement.expect("uninstalled replacement exists")).await;
                Err(McpShuttingDown)
            }
        }
    }

    pub(crate) async fn stop_watcher_at_revision(
        &self,
        source_id: &str,
        source_revision: i64,
    ) -> bool {
        let _lifecycle = self.inner.lifecycle.lock().await;
        let mut state = self
            .inner
            .watcher_state
            .lock()
            .expect("MCP watcher mutex poisoned");
        prune_finished_tasks(&mut state.pending);
        if state
            .latest_source_revisions
            .get(source_id)
            .is_some_and(|latest| *latest > source_revision)
        {
            return false;
        }
        state
            .latest_source_revisions
            .insert(source_id.to_owned(), source_revision);
        let watcher = state.active.remove(source_id);
        if let Some(mut watcher) = watcher {
            if watcher.source_revision > source_revision {
                state.active.insert(source_id.to_owned(), watcher);
                return false;
            }
            cancel_watcher(&mut watcher);
            state.pending.push(PendingWatcherTask {
                source_id: source_id.to_owned(),
                task: watcher.task,
            });
        }
        true
    }

    pub(crate) async fn stop_watcher_and_wait_at_revision(
        &self,
        source_id: &str,
        source_revision: i64,
    ) -> bool {
        let _operation = self.inner.watcher_operations.lock().await;
        let (watcher, pending) = {
            let _lifecycle = self.inner.lifecycle.lock().await;
            let mut state = self
                .inner
                .watcher_state
                .lock()
                .expect("MCP watcher mutex poisoned");
            prune_finished_tasks(&mut state.pending);
            if state
                .latest_source_revisions
                .get(source_id)
                .is_some_and(|latest| *latest > source_revision)
            {
                return false;
            }
            state
                .latest_source_revisions
                .insert(source_id.to_owned(), source_revision);
            if state
                .active
                .get(source_id)
                .is_some_and(|watcher| watcher.source_revision > source_revision)
            {
                return false;
            }
            let watcher = state.active.remove(source_id);
            let pending = take_pending_tasks(&mut state, source_id);
            (watcher, pending)
        };
        if let Some(watcher) = watcher {
            stop_and_join_watcher(watcher).await;
        }
        join_tasks(pending).await;
        true
    }

    pub(crate) async fn retire_source(&self, source_id: &str) {
        let _operation = self.inner.watcher_operations.lock().await;
        let (watcher, pending) = {
            let _lifecycle = self.inner.lifecycle.lock().await;
            let mut state = self
                .inner
                .watcher_state
                .lock()
                .expect("MCP watcher mutex poisoned");
            prune_finished_tasks(&mut state.pending);
            state.retired_sources.insert(source_id.to_owned());
            let watcher = state.active.remove(source_id);
            let pending = take_pending_tasks(&mut state, source_id);
            (watcher, pending)
        };
        if let Some(watcher) = watcher {
            stop_and_join_watcher(watcher).await;
        }
        join_tasks(pending).await;
    }

    pub(crate) async fn unretire_source(&self, source_id: &str) {
        let _operation = self.inner.watcher_operations.lock().await;
        let _lifecycle = self.inner.lifecycle.lock().await;
        self.inner
            .watcher_state
            .lock()
            .expect("MCP watcher mutex poisoned")
            .retired_sources
            .remove(source_id);
    }

    pub(crate) fn has_watcher(&self, source_id: &str) -> bool {
        let mut state = self
            .inner
            .watcher_state
            .lock()
            .expect("MCP watcher mutex poisoned");
        let finished = state
            .active
            .get(source_id)
            .is_some_and(|watcher| watcher.task.is_finished());
        if finished {
            let watcher = state.active.remove(source_id).expect("watcher exists");
            state.pending.push(PendingWatcherTask {
                source_id: source_id.to_owned(),
                task: watcher.task,
            });
            false
        } else {
            state.active.contains_key(source_id)
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.begin_shutdown();
        let wait_for_idle = async {
            loop {
                let notified = self.inner.idle.notified();
                if self.inner.active_operations.load(Ordering::Acquire) == 0 {
                    break;
                }
                notified.await;
            }
        };
        if tokio::time::timeout(SHUTDOWN_GRACE, wait_for_idle)
            .await
            .is_err()
        {
            tracing::warn!("MCP connections did not drain before the shutdown deadline");
        }

        let _operation = self.inner.watcher_operations.lock().await;
        let watchers = {
            let _lifecycle = self.inner.lifecycle.lock().await;
            let mut state = self
                .inner
                .watcher_state
                .lock()
                .expect("MCP watcher mutex poisoned");
            for watcher in state.active.values_mut() {
                cancel_watcher(watcher);
            }
            let mut watchers = state
                .active
                .drain()
                .map(|(_, watcher)| watcher.task)
                .collect::<Vec<_>>();
            watchers.extend(state.pending.drain(..).map(|pending| pending.task));
            watchers
        };
        drain_tasks(watchers).await;
    }
}

impl WatcherRevisionLease {
    pub(crate) async fn lock_revision(
        &self,
        expected_revision: i64,
    ) -> Option<WatcherRevisionGuard> {
        let lifecycle = self.inner.lifecycle.clone().lock_owned().await;
        let state = self
            .inner
            .watcher_state
            .lock()
            .expect("MCP watcher mutex poisoned");
        let is_current = state.active.get(&self.source_id).is_some_and(|watcher| {
            watcher.generation == self.generation && watcher.source_revision == expected_revision
        });
        if !is_current
            || state.latest_source_revisions.get(&self.source_id) != Some(&expected_revision)
        {
            return None;
        }

        drop(state);
        Some(WatcherRevisionGuard {
            inner: self.inner.clone(),
            source_id: self.source_id.clone(),
            generation: self.generation,
            expected_revision,
            _lifecycle: lifecycle,
        })
    }
}

impl WatcherRevisionGuard {
    pub(crate) fn advance(self, new_revision: i64) -> bool {
        if new_revision < self.expected_revision {
            return false;
        }

        let mut state = self
            .inner
            .watcher_state
            .lock()
            .expect("MCP watcher mutex poisoned");
        let is_current = state.active.get(&self.source_id).is_some_and(|watcher| {
            watcher.generation == self.generation
                && watcher.source_revision == self.expected_revision
        });
        if !is_current
            || state.latest_source_revisions.get(&self.source_id) != Some(&self.expected_revision)
        {
            return false;
        }
        state
            .active
            .get_mut(&self.source_id)
            .expect("current watcher exists")
            .source_revision = new_revision;
        state
            .latest_source_revisions
            .insert(self.source_id.clone(), new_revision);
        true
    }
}

struct WatcherCleanup {
    inner: Arc<ManagerInner>,
    source_id: String,
    generation: u64,
}

impl Drop for WatcherCleanup {
    fn drop(&mut self) {
        retire_watcher_if_current(&self.inner, &self.source_id, self.generation);
    }
}

fn cancel_watcher(watcher: &mut WatcherTask) {
    if let Some(cancel) = watcher.cancel.take() {
        let _ = cancel.send(());
    }
}

async fn stop_and_join_watcher(mut watcher: WatcherTask) {
    cancel_watcher(&mut watcher);
    stop_and_join_task(watcher.task).await;
}

async fn join_tasks(tasks: Vec<tokio::task::JoinHandle<()>>) {
    for task in tasks {
        stop_and_join_task(task).await;
    }
}

async fn stop_and_join_task(mut task: tokio::task::JoinHandle<()>) {
    if tokio::time::timeout(SHUTDOWN_GRACE, &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

async fn drain_tasks(tasks: Vec<tokio::task::JoinHandle<()>>) {
    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    let mut tasks = tasks.into_iter();
    while let Some(mut task) = tasks.next() {
        if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
            tracing::warn!("MCP source watchers did not stop before the shutdown deadline");
            task.abort();
            let _ = task.await;
            let remaining = tasks.collect::<Vec<_>>();
            for task in &remaining {
                task.abort();
            }
            for task in remaining {
                let _ = task.await;
            }
            return;
        }
    }
}

fn prune_finished_tasks(tasks: &mut Vec<PendingWatcherTask>) {
    tasks.retain(|pending| !pending.task.is_finished());
}

fn take_pending_tasks(
    state: &mut WatcherState,
    source_id: &str,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut matching = Vec::new();
    let mut remaining = Vec::with_capacity(state.pending.len());
    for pending in state.pending.drain(..) {
        if pending.source_id == source_id {
            matching.push(pending.task);
        } else {
            remaining.push(pending);
        }
    }
    state.pending = remaining;
    matching
}

fn retire_watcher_if_current(inner: &ManagerInner, source_id: &str, generation: u64) {
    let mut state = inner
        .watcher_state
        .lock()
        .expect("MCP watcher mutex poisoned");
    if state
        .active
        .get(source_id)
        .is_some_and(|watcher| watcher.generation == generation)
    {
        let watcher = state
            .active
            .remove(source_id)
            .expect("current watcher exists");
        state.pending.push(PendingWatcherTask {
            source_id: source_id.to_owned(),
            task: watcher.task,
        });
    }
}

impl Drop for McpOperationGuard {
    fn drop(&mut self) {
        if self.inner.active_operations.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.idle.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;

    #[tokio::test]
    async fn shutdown_rejects_new_work_and_waits_for_active_operations() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let operation = manager.begin_operation().expect("operation starts");
        manager.begin_shutdown();
        assert!(manager.begin_operation().is_err());

        let waiting = tokio::spawn({
            let manager = manager.clone();
            async move { manager.shutdown().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(operation);
        waiting.await.expect("shutdown task completes");
    }

    #[tokio::test]
    async fn watcher_replacement_waits_for_old_cleanup_and_natural_exit_is_removed() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let old_started = Arc::new(Notify::new());
        let release_old = Arc::new(Notify::new());
        manager
            .replace_watcher("source".to_owned(), 1, {
                let old_started = old_started.clone();
                let release_old = release_old.clone();
                move |mut canceled, _revision_lease| async move {
                    old_started.notify_one();
                    let _ = (&mut canceled).await;
                    release_old.notified().await;
                }
            })
            .await
            .expect("first watcher installs");
        old_started.notified().await;

        let replacement_started = Arc::new(AtomicBool::new(false));
        let replacing = tokio::spawn({
            let manager = manager.clone();
            let replacement_started = replacement_started.clone();
            async move {
                manager
                    .replace_watcher(
                        "source".to_owned(),
                        2,
                        move |_canceled, _revision_lease| async move {
                            replacement_started.store(true, Ordering::Release);
                        },
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!replacement_started.load(Ordering::Acquire));
        assert!(!replacing.is_finished());
        release_old.notify_one();
        assert!(replacing.await.expect("replacement task completes").is_ok());
        tokio::time::timeout(Duration::from_secs(1), async {
            while !replacement_started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement starts after old cleanup");
        tokio::time::timeout(Duration::from_secs(1), async {
            while manager.has_watcher("source") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("naturally completed watcher removes its registry entry");
    }

    #[tokio::test]
    async fn retired_source_atomically_rejects_install_until_unretired() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        manager.retire_source("source").await;
        let started = Arc::new(AtomicBool::new(false));
        let installed = manager
            .replace_watcher("source".to_owned(), 1, {
                let started = started.clone();
                move |_canceled, _revision_lease| async move {
                    started.store(true, Ordering::Release);
                }
            })
            .await
            .expect("manager remains available");
        assert!(!installed);
        assert!(!started.load(Ordering::Acquire));
        assert!(!manager.has_watcher("source"));

        manager.unretire_source("source").await;
        assert!(
            manager
                .replace_watcher(
                    "source".to_owned(),
                    1,
                    move |_canceled, _revision_lease| async {},
                )
                .await
                .expect("source installs after rollback")
        );
    }

    #[tokio::test]
    async fn stale_install_and_stop_cannot_replace_a_newer_watcher() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let canceled = Arc::new(Notify::new());
        manager
            .replace_watcher("source".to_owned(), 2, {
                let canceled = canceled.clone();
                move |mut stop, _revision_lease| async move {
                    let _ = (&mut stop).await;
                    canceled.notify_one();
                }
            })
            .await
            .expect("new watcher installs");

        assert!(
            !manager
                .replace_watcher(
                    "source".to_owned(),
                    1,
                    move |_stop, _revision_lease| async {},
                )
                .await
                .expect("stale install is ignored")
        );
        assert!(!manager.stop_watcher_at_revision("source", 1).await);
        assert!(!manager.stop_watcher_and_wait_at_revision("source", 1).await);
        assert!(manager.has_watcher("source"));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), canceled.notified())
                .await
                .is_err()
        );
        assert!(manager.stop_watcher_and_wait_at_revision("source", 2).await);
    }

    #[tokio::test]
    async fn stale_watcher_generation_cannot_advance_a_replacement_revision() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let (lease_sender, lease_receiver) = tokio::sync::oneshot::channel();
        manager
            .replace_watcher(
                "source".to_owned(),
                1,
                move |mut stop, revision_lease| async move {
                    assert!(lease_sender.send(revision_lease).is_ok());
                    let _ = (&mut stop).await;
                },
            )
            .await
            .expect("first watcher installs");
        let stale_lease = lease_receiver.await.expect("first watcher provides lease");

        manager
            .replace_watcher(
                "source".to_owned(),
                1,
                move |mut stop, _revision_lease| async move {
                    let _ = (&mut stop).await;
                },
            )
            .await
            .expect("replacement watcher installs");

        assert!(stale_lease.lock_revision(1).await.is_none());
        assert!(manager.has_watcher("source"));
        assert!(manager.stop_watcher_and_wait_at_revision("source", 1).await);
    }

    #[tokio::test]
    async fn active_revision_advance_fences_stale_install_and_stop() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let (lease_sender, lease_receiver) = tokio::sync::oneshot::channel();
        manager
            .replace_watcher(
                "source".to_owned(),
                1,
                move |mut stop, revision_lease| async move {
                    assert!(lease_sender.send(revision_lease).is_ok());
                    let _ = (&mut stop).await;
                },
            )
            .await
            .expect("watcher installs");
        let revision_lease = lease_receiver.await.expect("watcher provides lease");

        assert!(
            revision_lease
                .lock_revision(1)
                .await
                .expect("active revision locks")
                .advance(2)
        );
        assert!(revision_lease.lock_revision(1).await.is_none());
        assert!(
            !revision_lease
                .lock_revision(2)
                .await
                .expect("current revision locks")
                .advance(1)
        );
        assert!(
            !manager
                .replace_watcher(
                    "source".to_owned(),
                    1,
                    move |_stop, _revision_lease| async {},
                )
                .await
                .expect("stale install is ignored")
        );
        assert!(!manager.stop_watcher_at_revision("source", 1).await);
        assert!(!manager.stop_watcher_and_wait_at_revision("source", 1).await);
        assert!(manager.has_watcher("source"));
        assert!(manager.stop_watcher_and_wait_at_revision("source", 2).await);
    }

    #[tokio::test]
    async fn manual_refresh_replaces_the_old_watcher_revision_lease() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let (old_lease_sender, old_lease_receiver) = tokio::sync::oneshot::channel();
        let old_stopped = Arc::new(Notify::new());
        manager
            .replace_watcher("source".to_owned(), 1, {
                let old_stopped = old_stopped.clone();
                move |mut stop, revision_lease| async move {
                    assert!(old_lease_sender.send(revision_lease).is_ok());
                    let _ = (&mut stop).await;
                    old_stopped.notify_one();
                }
            })
            .await
            .expect("initial watcher installs");
        let old_lease = old_lease_receiver
            .await
            .expect("initial watcher provides its revision lease");

        let (refreshed_lease_sender, refreshed_lease_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(
                    "source".to_owned(),
                    2,
                    move |mut stop, revision_lease| async move {
                        assert!(refreshed_lease_sender.send(revision_lease).is_ok());
                        let _ = (&mut stop).await;
                    },
                )
                .await
                .expect("manual refresh installs its committed revision")
        );
        old_stopped.notified().await;
        let refreshed_lease = refreshed_lease_receiver
            .await
            .expect("refreshed watcher provides its revision lease");

        assert!(old_lease.lock_revision(1).await.is_none());
        assert!(refreshed_lease.lock_revision(1).await.is_none());
        assert!(refreshed_lease.lock_revision(2).await.is_some());
        assert!(manager.stop_watcher_and_wait_at_revision("source", 2).await);
    }

    #[tokio::test]
    async fn credential_rotation_guard_drains_before_shutdown_and_blocks_reinstall() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let rotation_started = Arc::new(Notify::new());
        let allow_commit = Arc::new(Notify::new());
        let committed = Arc::new(AtomicBool::new(false));
        let reinstall_started = Arc::new(AtomicBool::new(false));
        let rotating = tokio::spawn({
            let manager = manager.clone();
            let rotation_started = rotation_started.clone();
            let allow_commit = allow_commit.clone();
            let committed = committed.clone();
            let reinstall_started = reinstall_started.clone();
            async move {
                let operation = manager
                    .begin_operation()
                    .expect("credential rotation begins before shutdown");
                rotation_started.notify_one();
                allow_commit.notified().await;
                committed.store(true, Ordering::Release);
                let reinstall = manager
                    .replace_watcher(
                        "source".to_owned(),
                        2,
                        move |_stop, _revision_lease| async move {
                            reinstall_started.store(true, Ordering::Release);
                        },
                    )
                    .await;
                drop(operation);
                reinstall
            }
        });
        rotation_started.notified().await;

        manager.begin_shutdown();
        let shutdown = tokio::spawn({
            let manager = manager.clone();
            async move { manager.shutdown().await }
        });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());

        allow_commit.notify_one();
        assert!(
            rotating
                .await
                .expect("credential rotation task joins")
                .is_err(),
            "watcher reinstall is rejected once shutdown starts"
        );
        shutdown.await.expect("shutdown drains credential rotation");
        assert!(committed.load(Ordering::Acquire));
        assert!(!reinstall_started.load(Ordering::Acquire));
        assert!(!manager.has_watcher("source"));
    }

    #[tokio::test]
    async fn revision_guard_blocks_replacement_and_stop_across_a_paused_commit() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let (old_lease_sender, old_lease_receiver) = tokio::sync::oneshot::channel();
        manager
            .replace_watcher(
                "source".to_owned(),
                1,
                move |mut stop, revision_lease| async move {
                    assert!(old_lease_sender.send(revision_lease).is_ok());
                    let _ = (&mut stop).await;
                },
            )
            .await
            .expect("first watcher installs");
        let old_lease = old_lease_receiver
            .await
            .expect("first watcher provides lease");
        let revision_guard = old_lease
            .lock_revision(1)
            .await
            .expect("first watcher locks its revision");

        let (new_lease_sender, new_lease_receiver) = tokio::sync::oneshot::channel();
        let replacement_attempted = Arc::new(Notify::new());
        let replacing = tokio::spawn({
            let manager = manager.clone();
            let replacement_attempted = replacement_attempted.clone();
            async move {
                replacement_attempted.notify_one();
                manager
                    .replace_watcher(
                        "source".to_owned(),
                        2,
                        move |mut stop, revision_lease| async move {
                            assert!(new_lease_sender.send(revision_lease).is_ok());
                            let _ = (&mut stop).await;
                        },
                    )
                    .await
            }
        });
        replacement_attempted.notified().await;
        assert!(!replacing.is_finished());

        assert!(revision_guard.advance(2));
        assert!(
            replacing
                .await
                .expect("replacement task completes")
                .expect("manager remains available")
        );
        let new_lease = new_lease_receiver
            .await
            .expect("replacement watcher provides lease");
        assert!(old_lease.lock_revision(2).await.is_none());

        let revision_guard = new_lease
            .lock_revision(2)
            .await
            .expect("replacement watcher locks its revision");
        let stop_attempted = Arc::new(Notify::new());
        let stopping = tokio::spawn({
            let manager = manager.clone();
            let stop_attempted = stop_attempted.clone();
            async move {
                stop_attempted.notify_one();
                manager.stop_watcher_at_revision("source", 2).await
            }
        });
        stop_attempted.notified().await;
        assert!(!stopping.is_finished());

        assert!(revision_guard.advance(3));
        assert!(!stopping.await.expect("stop task completes"));
        assert!(manager.has_watcher("source"));
        assert!(manager.stop_watcher_and_wait_at_revision("source", 3).await);
    }

    #[tokio::test]
    async fn replacement_releases_lifecycle_before_joining_the_old_watcher() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let watcher_manager = manager.clone();
        manager
            .replace_watcher(
                "source".to_owned(),
                1,
                move |mut stop, revision_lease| async move {
                    let _ = (&mut stop).await;
                    assert!(!watcher_manager.stop_watcher_at_revision("source", 1).await);
                    assert!(revision_lease.lock_revision(1).await.is_none());
                },
            )
            .await
            .expect("first watcher installs");

        let installed = tokio::time::timeout(
            Duration::from_secs(1),
            manager.replace_watcher(
                "source".to_owned(),
                2,
                move |_stop, _revision_lease| async {},
            ),
        )
        .await
        .expect("replacement does not deadlock on the revision lifecycle")
        .expect("manager remains available");
        assert!(installed);
    }

    #[tokio::test]
    async fn panicked_watcher_is_removed_from_the_active_registry() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        manager
            .replace_watcher(
                "source".to_owned(),
                1,
                move |_stop, _revision_lease| async move {
                    panic!("watcher fixture panic");
                },
            )
            .await
            .expect("watcher installs");
        tokio::time::timeout(Duration::from_secs(1), async {
            while manager.has_watcher("source") {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("panicked watcher is removed");
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn replacement_waits_for_a_nonblocking_self_stop_to_finish() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        manager
            .replace_watcher("source".to_owned(), 1, {
                let started = started.clone();
                let release = release.clone();
                move |mut canceled, _revision_lease| async move {
                    started.notify_one();
                    let _ = (&mut canceled).await;
                    release.notified().await;
                }
            })
            .await
            .expect("watcher installs");
        started.notified().await;
        assert!(manager.stop_watcher_at_revision("source", 1).await);

        let replacement_started = Arc::new(AtomicBool::new(false));
        let replacing = tokio::spawn({
            let manager = manager.clone();
            let replacement_started = replacement_started.clone();
            async move {
                manager
                    .replace_watcher(
                        "source".to_owned(),
                        2,
                        move |_canceled, _revision_lease| async move {
                            replacement_started.store(true, Ordering::Release);
                        },
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!replacing.is_finished());
        assert!(!replacement_started.load(Ordering::Acquire));
        release.notify_one();
        assert!(replacing.await.expect("replacement task completes").is_ok());
    }

    #[tokio::test]
    async fn concurrent_replacement_and_retirement_leave_no_watcher() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let old_started = Arc::new(Notify::new());
        let release_old = Arc::new(Notify::new());
        manager
            .replace_watcher("source".to_owned(), 1, {
                let old_started = old_started.clone();
                let release_old = release_old.clone();
                move |mut canceled, _revision_lease| async move {
                    old_started.notify_one();
                    let _ = (&mut canceled).await;
                    release_old.notified().await;
                }
            })
            .await
            .expect("watcher installs");
        old_started.notified().await;

        let replacing = tokio::spawn({
            let manager = manager.clone();
            async move {
                manager
                    .replace_watcher(
                        "source".to_owned(),
                        2,
                        move |mut canceled, _revision_lease| async move {
                            let _ = (&mut canceled).await;
                        },
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        let retiring = tokio::spawn({
            let manager = manager.clone();
            async move { manager.retire_source("source").await }
        });
        release_old.notify_one();

        replacing
            .await
            .expect("replacement task completes")
            .expect("manager remains available");
        retiring.await.expect("retirement task completes");
        assert!(!manager.has_watcher("source"));
        assert!(
            !manager
                .replace_watcher(
                    "source".to_owned(),
                    3,
                    move |_canceled, _revision_lease| async {},
                )
                .await
                .expect("manager remains available")
        );
    }

    #[tokio::test]
    async fn shutdown_drains_a_nonblocking_self_stop() {
        let manager = McpConnectionManager::new(StdioTemplateRegistry::default());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        manager
            .replace_watcher("source".to_owned(), 1, {
                let started = started.clone();
                let release = release.clone();
                move |mut canceled, _revision_lease| async move {
                    started.notify_one();
                    let _ = (&mut canceled).await;
                    release.notified().await;
                }
            })
            .await
            .expect("watcher installs");
        started.notified().await;
        assert!(manager.stop_watcher_at_revision("source", 1).await);

        let shutdown = tokio::spawn({
            let manager = manager.clone();
            async move { manager.shutdown().await }
        });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished());
        release.notify_one();
        shutdown.await.expect("shutdown drains stopped watcher");
    }
}
