use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};
use tokio::task::JoinHandle;

use crate::{
    catalog::{CatalogError, CatalogStore, NewRequestLog},
    database::Database,
};

const DEFAULT_CAPACITY: usize = 1_024;
const MAX_BATCH_SIZE: usize = 64;

#[derive(Clone)]
pub(crate) struct RequestLogSink {
    sender: mpsc::Sender<QueuedRequestLog>,
    database: Database,
    telemetry: Arc<RequestLogTelemetry>,
    consumer: Arc<std::sync::Mutex<Option<JoinHandle<()>>>>,
    shutdown: Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
}

struct QueuedRequestLog {
    log: NewRequestLog,
    _database_guard: Database,
    completion: Option<oneshot::Sender<bool>>,
}

#[derive(Default)]
struct RequestLogTelemetry {
    dropped: AtomicU64,
    dropped_full: AtomicU64,
    dropped_closed: AtomicU64,
    write_failures: AtomicU64,
    writes: AtomicU64,
}

#[derive(Clone, Copy)]
enum DropReason {
    Full,
    Closed,
}

impl RequestLogSink {
    pub(crate) fn new(database: Database, catalog: CatalogStore) -> Self {
        Self::with_capacity(database, catalog, DEFAULT_CAPACITY)
    }

    pub(super) fn with_capacity(
        database: Database,
        catalog: CatalogStore,
        capacity: usize,
    ) -> Self {
        assert!(capacity > 0, "request-log sink capacity must be positive");
        let (sender, receiver) = mpsc::channel(capacity);
        let (shutdown, shutdown_requested) = oneshot::channel();
        let telemetry = Arc::new(RequestLogTelemetry::default());
        let consumer = tokio::spawn(consume(
            receiver,
            catalog,
            telemetry.clone(),
            shutdown_requested,
        ));
        Self {
            sender,
            database,
            telemetry,
            consumer: Arc::new(std::sync::Mutex::new(Some(consumer))),
            shutdown: Arc::new(std::sync::Mutex::new(Some(shutdown))),
        }
    }

    pub(crate) fn try_record(&self, log: NewRequestLog) -> bool {
        let queued = QueuedRequestLog {
            log,
            _database_guard: self.database.clone(),
            completion: None,
        };
        match self.sender.try_send(queued) {
            Ok(()) => true,
            Err(TrySendError::Full(queued)) => {
                self.telemetry
                    .record_drop(DropReason::Full, &queued.log.request_id);
                false
            }
            Err(TrySendError::Closed(queued)) => {
                self.telemetry
                    .record_drop(DropReason::Closed, &queued.log.request_id);
                false
            }
        }
    }

    pub(crate) async fn record_durable(&self, log: NewRequestLog) -> bool {
        let (completion, completed) = oneshot::channel();
        let queued = QueuedRequestLog {
            log,
            _database_guard: self.database.clone(),
            completion: Some(completion),
        };
        if self.sender.send(queued).await.is_err() {
            return false;
        }
        completed.await.unwrap_or(false)
    }

    pub(crate) fn abort(&self) {
        if let Some(consumer) = self
            .consumer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            consumer.abort();
        }
    }

    pub(crate) async fn shutdown(&self) {
        if let Some(shutdown) = self
            .shutdown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = shutdown.send(());
        }
        let consumer = self
            .consumer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(consumer) = consumer {
            let _ = consumer.await;
        }
    }

    #[cfg(test)]
    fn counters(&self) -> RequestLogSinkCounters {
        self.telemetry.counters()
    }
}

impl RequestLogTelemetry {
    fn record_drop(&self, reason: DropReason, request_id: &str) {
        let reason_total = match reason {
            DropReason::Full => increment(&self.dropped_full),
            DropReason::Closed => increment(&self.dropped_closed),
        };
        let dropped_total = increment(&self.dropped);
        if should_emit(dropped_total) {
            tracing::warn!(
                event = "gateway_request_log_dropped",
                reason = reason.as_str(),
                request_id,
                dropped_total,
                reason_total,
                "gateway request log was not queued"
            );
        }
    }

    fn record_write_failure(&self, request_id: &str, error: &CatalogError) {
        let write_failures = increment(&self.write_failures);
        if should_emit(write_failures) {
            tracing::error!(
                event = "gateway_request_log_write_failed",
                request_id,
                error = %error,
                write_failures,
                "gateway request log write failed"
            );
        }
    }

    fn record_write(&self) {
        increment(&self.writes);
    }

    #[cfg(test)]
    fn counters(&self) -> RequestLogSinkCounters {
        RequestLogSinkCounters {
            dropped: self.dropped.load(Ordering::Relaxed),
            dropped_full: self.dropped_full.load(Ordering::Relaxed),
            dropped_closed: self.dropped_closed.load(Ordering::Relaxed),
            write_failures: self.write_failures.load(Ordering::Relaxed),
            writes: self.writes.load(Ordering::Relaxed),
        }
    }
}

impl DropReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Closed => "closed",
        }
    }
}

async fn consume(
    mut receiver: mpsc::Receiver<QueuedRequestLog>,
    catalog: CatalogStore,
    telemetry: Arc<RequestLogTelemetry>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut batch = Vec::with_capacity(MAX_BATCH_SIZE);
    let mut draining = false;
    loop {
        let queued = if draining {
            receiver.recv().await
        } else {
            tokio::select! {
                queued = receiver.recv() => queued,
                _ = &mut shutdown => {
                    receiver.close();
                    draining = true;
                    receiver.recv().await
                }
            }
        };
        let Some(queued) = queued else {
            break;
        };
        batch.push(queued);
        while batch.len() < MAX_BATCH_SIZE {
            match receiver.try_recv() {
                Ok(queued) => batch.push(queued),
                Err(_) => break,
            }
        }

        for queued in batch.drain(..) {
            let QueuedRequestLog {
                log,
                _database_guard,
                completion,
            } = queued;
            let request_id = log.request_id.clone();
            let succeeded = match catalog.record_request(log).await {
                Ok(()) => {
                    telemetry.record_write();
                    true
                }
                Err(error) => {
                    if catalog.request_log(&request_id).await.is_ok() {
                        true
                    } else {
                        telemetry.record_write_failure(&request_id, &error);
                        false
                    }
                }
            };
            if let Some(completion) = completion {
                let _ = completion.send(succeeded);
            }
        }
    }
}

fn increment(counter: &AtomicU64) -> u64 {
    counter.fetch_add(1, Ordering::Relaxed).saturating_add(1)
}

fn should_emit(total: u64) -> bool {
    total.is_power_of_two()
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
struct RequestLogSinkCounters {
    dropped: u64,
    dropped_full: u64,
    dropped_closed: u64,
    write_failures: u64,
    writes: u64,
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tempfile::TempDir;
    use tokio::{sync::mpsc, time::timeout};

    use super::{RequestLogSink, RequestLogTelemetry};
    use crate::{
        AppConfig,
        catalog::{CatalogStore, NewRequestLog, RequestOutcome, RequestSurface},
        database::{Database, OpenedDatabase},
    };

    fn request_log(request_id: &str) -> NewRequestLog {
        NewRequestLog {
            request_id: request_id.to_owned(),
            actor_api_token_id: None,
            surface: RequestSurface::Mcp,
            source_id: None,
            tool_id: None,
            path_snapshot: Some("tools.example.run".to_owned()),
            outcome: RequestOutcome::PendingApproval,
            error_code: Some("approval_required".to_owned()),
            duration_ms: 37,
            approval_id: Some("approval-1".to_owned()),
            created_at: 1_750_000_000,
        }
    }

    async fn open_database() -> (TempDir, Database, CatalogStore) {
        let directory = tempfile::tempdir().expect("temporary data directory");
        let OpenedDatabase { database, .. } =
            Database::open(&AppConfig::new(directory.path().into()))
                .await
                .expect("test database opens");
        let catalog = CatalogStore::new(database.pool.clone(), database.keyring.clone());
        (directory, database, catalog)
    }

    #[tokio::test]
    async fn bounded_sender_drops_without_waiting_when_full() {
        let (_directory, database, _catalog) = open_database().await;
        let (sender, _receiver) = mpsc::channel(1);
        let telemetry = Arc::new(RequestLogTelemetry::default());
        let sink = RequestLogSink {
            sender,
            database,
            telemetry,
            consumer: Arc::new(std::sync::Mutex::new(None)),
            shutdown: Arc::new(std::sync::Mutex::new(None)),
        };

        assert!(sink.try_record(request_log("queued")));
        assert!(!sink.try_record(request_log("dropped")));
        assert_eq!(sink.counters().dropped, 1);
        assert_eq!(sink.counters().dropped_full, 1);
        assert_eq!(sink.counters().dropped_closed, 0);
    }

    #[tokio::test]
    async fn consumer_recovers_after_a_failed_record_and_preserves_metadata() {
        let (_directory, database, catalog) = open_database().await;
        let sink = RequestLogSink::with_capacity(database, catalog.clone(), 2);

        assert!(!sink.record_durable(request_log("")).await);
        assert!(sink.record_durable(request_log("recorded")).await);

        let stored = timeout(Duration::from_secs(2), async {
            loop {
                let counters = sink.counters();
                if counters.write_failures == 1
                    && counters.writes == 1
                    && let Ok(stored) = catalog.request_log("recorded").await
                {
                    break stored;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the consumer continues after a failed record");

        assert_eq!(stored.request_id, "recorded");
        assert_eq!(stored.surface, RequestSurface::Mcp);
        assert_eq!(stored.path_snapshot.as_deref(), Some("tools.example.run"));
        assert_eq!(stored.outcome, RequestOutcome::PendingApproval);
        assert_eq!(stored.error_code.as_deref(), Some("approval_required"));
        assert_eq!(stored.duration_ms, 37);
        assert_eq!(stored.approval_id.as_deref(), Some("approval-1"));
        assert_eq!(stored.created_at, 1_750_000_000);
    }
}
