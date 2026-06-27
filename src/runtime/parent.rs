use std::{
    future::Future,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::{
    net::UnixStream,
    process::{Child, Command},
    sync::{Mutex, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};

use super::{
    ExecutionCancellation, ExecutionOutput, ExecutionRequest, HostToolDispatcher, RuntimeFailure,
    RuntimeLimits, ToolCall, ToolCallRecord, ToolResult,
    protocol::{
        PROTOCOL_VERSION, ParentMessage, WorkerMessage, encode_frame, read_frame,
        write_encoded_frame,
    },
};

static WORKER_PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
const EXECUTION_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(target_os = "linux")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(target_os = "macos")]
type RlimitResource = libc::c_int;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn closefrom(low_fd: libc::c_int);
}

#[derive(Clone, Debug)]
pub struct RuntimeManager {
    executable: PathBuf,
    limits: RuntimeLimits,
}

impl RuntimeManager {
    pub fn current_executable() -> Result<Self, RuntimeFailure> {
        let executable = std::env::current_exe().map_err(|_| {
            RuntimeFailure::internal("worker_unavailable", "could not locate Executor binary")
        })?;
        Ok(Self::new(executable))
    }

    pub fn new(executable: impl Into<PathBuf>) -> Self {
        Self {
            executable: executable.into(),
            limits: RuntimeLimits::default(),
        }
    }

    pub fn with_limits(mut self, limits: RuntimeLimits) -> Self {
        self.limits = limits;
        self
    }

    pub async fn execute(
        &self,
        request: ExecutionRequest,
        dispatcher: Arc<dyn HostToolDispatcher>,
        cancellation: ExecutionCancellation,
    ) -> Result<ExecutionOutput, RuntimeFailure> {
        let actor_cancellation = ExecutionCancellation::default();
        if let Some(hook) = dispatcher.cancellation_hook(&request.execution_id) {
            cancellation.register_cancel_hook(hook.clone());
            actor_cancellation.register_cancel_hook(hook);
        }
        let mut drop_guard = ExecutionDropGuard(Some(actor_cancellation.clone()));
        let manager = self.clone();
        let actor_token = actor_cancellation.clone();
        let actor = tokio::spawn(async move {
            let forwarding_token = actor_token.clone();
            let forward_cancellation = tokio::spawn(async move {
                cancellation.cancelled().await;
                forwarding_token.cancel();
            });
            let execution_id = request.execution_id.clone();
            let cleanup_dispatcher = dispatcher.clone();
            let result = manager
                .execute_owned(request, dispatcher, actor_token)
                .await;
            let _ = tokio::time::timeout(
                EXECUTION_SHUTDOWN_GRACE,
                cleanup_dispatcher.execution_finished(&execution_id),
            )
            .await;
            forward_cancellation.abort();
            let _ = forward_cancellation.await;
            result
        });
        let result = actor.await.map_err(|_| {
            RuntimeFailure::internal("execution_actor_failed", "execution actor failed")
        })?;
        drop_guard.0 = None;
        result
    }

    async fn execute_owned(
        &self,
        request: ExecutionRequest,
        dispatcher: Arc<dyn HostToolDispatcher>,
        cancellation: ExecutionCancellation,
    ) -> Result<ExecutionOutput, RuntimeFailure> {
        if request.code.len() > super::MAX_SOURCE_BYTES {
            return Err(RuntimeFailure::public(
                "source_too_large",
                "TypeScript source exceeded 1 MiB",
            ));
        }
        if request.timeout.is_zero() {
            return Err(RuntimeFailure::public(
                "invalid_timeout",
                "execution timeout must be positive",
            ));
        }
        if request.timeout > std::time::Duration::from_secs(300) {
            return Err(RuntimeFailure::public(
                "invalid_timeout",
                "execution timeout cannot exceed five minutes",
            ));
        }
        let mut execution_limits = self.limits.clone();
        execution_limits.wall_time_millis = request.timeout.as_millis() as u64;
        execution_limits.validate()?;
        let permits = WORKER_PERMITS
            .get_or_init(|| Arc::new(Semaphore::new(8)))
            .clone();
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let permit = permits.try_acquire_owned().map_err(|_| {
            RuntimeFailure::public("runtime_busy", "all sandbox worker slots are busy")
        })?;
        let generation = random_generation();
        let temp_dir = PrivateTempDir::create()?;
        let (stream, mut child) = spawn_worker(
            &self.executable,
            generation,
            temp_dir.path(),
            request.timeout,
        )?;
        let mut process_group = ProcessGroupGuard(child.id());
        let execution_id = request.execution_id.clone();
        let run = run_execution(
            stream,
            generation,
            request.execution_id,
            request.code,
            execution_limits,
            dispatcher.clone(),
            cancellation.clone(),
        );
        tokio::pin!(run);
        let (outcome, timed_out) = match tokio::time::timeout(request.timeout, &mut run).await {
            Ok(result) => (result, false),
            Err(_) => {
                cancellation.cancel();
                drain_timed_out_execution(run.as_mut(), &dispatcher, &execution_id).await;
                (
                    Err(RuntimeFailure::public(
                        "execution_timeout",
                        "TypeScript execution timed out",
                    )),
                    true,
                )
            }
        };
        if outcome.is_err() {
            cancellation.cancel();
            if !timed_out {
                let _ = tokio::time::timeout(
                    EXECUTION_SHUTDOWN_GRACE,
                    dispatcher.execution_stopping(&execution_id),
                )
                .await;
            }
            terminate_worker(&mut child).await;
            process_group.disarm();
        } else {
            let status = tokio::time::timeout(std::time::Duration::from_secs(1), child.wait())
                .await
                .ok()
                .and_then(Result::ok);
            if !status.is_some_and(|status| status.success()) {
                cancellation.cancel();
                terminate_worker(&mut child).await;
                process_group.disarm();
                drop(permit);
                return Err(RuntimeFailure::internal(
                    "worker_crashed",
                    "sandbox worker exited unexpectedly",
                ));
            }
            process_group.disarm();
        }
        drop(permit);
        outcome
    }
}

struct ExecutionDropGuard(Option<ExecutionCancellation>);

impl Drop for ExecutionDropGuard {
    fn drop(&mut self) {
        if let Some(cancellation) = self.0.take() {
            cancellation.cancel();
        }
    }
}

async fn run_execution(
    stream: UnixStream,
    generation: u64,
    execution_id: String,
    code: String,
    limits: RuntimeLimits,
    dispatcher: Arc<dyn HostToolDispatcher>,
    cancellation: ExecutionCancellation,
) -> Result<ExecutionOutput, RuntimeFailure> {
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));
    let aggregate_bytes = Arc::new(AtomicUsize::new(0));
    let mut reader =
        WorkerFrameReader::spawn(reader, aggregate_bytes.clone(), limits.aggregate_bytes);
    write_parent_message(
        &writer,
        &aggregate_bytes,
        &ParentMessage::Start {
            version: PROTOCOL_VERSION,
            generation,
            code,
            limits: limits.clone(),
        },
        limits.aggregate_bytes,
    )
    .await?;

    let call_permits = Arc::new(Semaphore::new(limits.max_concurrent_calls));
    let records = Arc::new(Mutex::new(Vec::new()));
    let mut calls = JoinSet::new();
    let mut expected_call_id = 1u64;
    let outcome = async {
        loop {
            let message = tokio::select! {
                frame = reader.recv() => frame?,
                completed = calls.join_next(), if !calls.is_empty() => {
                    match completed {
                        Some(Ok(Ok(()))) => continue,
                        Some(Ok(Err(error))) => return Err(error),
                        Some(Err(_)) | None => {
                            return Err(RuntimeFailure::internal(
                                "tool_bridge_failed",
                                "tool dispatch task failed",
                            ));
                        }
                    }
                }
                () = cancellation.cancelled() => return Err(cancelled()),
            };
            match message {
                WorkerMessage::ToolCall {
                    version,
                    generation: message_generation,
                    call_id,
                    path,
                    arguments,
                } => {
                validate_header(version, message_generation, generation)?;
                if call_id as usize > limits.max_calls {
                    return Err(RuntimeFailure::public(
                        "tool_call_limit_exceeded",
                        "execution exceeded 128 tool calls",
                    ));
                }
                if call_id != expected_call_id {
                    return Err(RuntimeFailure::internal(
                        "ipc_protocol_violation",
                        "worker tool call ID was invalid",
                    ));
                }
                expected_call_id += 1;
                if path.is_empty() || path.len() > 512 || path.split('.').any(str::is_empty) {
                    return Err(RuntimeFailure::public(
                        "tool_path_invalid",
                        "tool path was invalid",
                    ));
                }
                let argument_size = serde_json::to_vec(&arguments)
                    .map_err(|_| {
                        RuntimeFailure::internal("ipc_frame_invalid", "arguments were invalid")
                    })?
                    .len();
                if argument_size > limits.argument_bytes {
                    return Err(RuntimeFailure::public(
                        "argument_too_large",
                        "tool arguments exceeded 8 MiB",
                    ));
                }
                let permit = tokio::select! {
                    permit = call_permits.clone().acquire_owned() => permit.map_err(|_| RuntimeFailure::internal("runtime_closed", "runtime is shutting down"))?,
                    () = cancellation.cancelled() => return Err(cancelled()),
                };
                let writer = writer.clone();
                let aggregate_bytes = aggregate_bytes.clone();
                let records = records.clone();
                let dispatcher = dispatcher.clone();
                let call_cancellation = cancellation.clone();
                let call_execution_id = execution_id.clone();
                let aggregate_limit = limits.aggregate_bytes;
                let result_limit = limits.result_bytes;
                calls.spawn(async move {
                    let call = ToolCall {
                        execution_id: call_execution_id,
                        worker_generation: generation,
                        call_id,
                        path: path.clone(),
                        arguments,
                    };
                    let mut result = dispatcher.dispatch(call, call_cancellation).await;
                    if serde_json::to_vec(&result).map_or(true, |bytes| bytes.len() > result_limit)
                    {
                        result = ToolResult::InternalFailure {
                            code: "tool_result_too_large".into(),
                        };
                    }
                    records.lock().await.push(ToolCallRecord {
                        call_id,
                        path,
                        result: result.clone(),
                    });
                    write_parent_message(
                        &writer,
                        &aggregate_bytes,
                        &ParentMessage::ToolResult {
                            version: PROTOCOL_VERSION,
                            generation,
                            call_id,
                            result,
                        },
                        aggregate_limit,
                    )
                    .await?;
                    drop(permit);
                    Ok::<_, RuntimeFailure>(())
                });
                }
                WorkerMessage::Complete {
                    version,
                    generation: message_generation,
                    result,
                    emits,
                    console,
                } => {
                validate_header(version, message_generation, generation)?;
                validate_output(&result, &emits, &console, &limits)?;
                while let Some(call) = calls.join_next().await {
                    call.map_err(|_| {
                        RuntimeFailure::internal("tool_bridge_failed", "tool dispatch task failed")
                    })??;
                }
                let mut tool_calls = records.lock().await.clone();
                tool_calls.sort_by_key(|record| record.call_id);
                return Ok(ExecutionOutput {
                    result,
                    emits,
                    console,
                    tool_calls,
                });
                }
                WorkerMessage::Failed {
                    version,
                    generation: message_generation,
                    failure,
                } => {
                validate_header(version, message_generation, generation)?;
                calls.abort_all();
                return Err(sanitize_worker_failure(failure));
                }
            }
        }
    }
    .await;
    reader.stop().await;
    if outcome.is_err() {
        calls.abort_all();
        while calls.join_next().await.is_some() {}
    }
    outcome
}

async fn drain_timed_out_execution<F>(
    run: Pin<&mut F>,
    dispatcher: &Arc<dyn HostToolDispatcher>,
    execution_id: &str,
) where
    F: Future<Output = Result<ExecutionOutput, RuntimeFailure>>,
{
    let stopping = dispatcher.execution_stopping(execution_id);
    let _ = tokio::time::timeout(EXECUTION_SHUTDOWN_GRACE, async {
        let _ = tokio::join!(stopping, run);
    })
    .await;
}

struct WorkerFrameReader {
    frames: mpsc::Receiver<Result<WorkerMessage, RuntimeFailure>>,
    task: Option<JoinHandle<()>>,
}

impl WorkerFrameReader {
    fn spawn(
        mut reader: tokio::net::unix::OwnedReadHalf,
        aggregate_bytes: Arc<AtomicUsize>,
        aggregate_limit: usize,
    ) -> Self {
        let (sender, frames) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            loop {
                let frame = read_frame::<_, WorkerMessage>(&mut reader).await.and_then(
                    |(message, frame_bytes)| {
                        add_aggregate_bytes(&aggregate_bytes, frame_bytes, aggregate_limit)?;
                        Ok(message)
                    },
                );
                let terminal = frame.is_err();
                if sender.send(frame).await.is_err() || terminal {
                    break;
                }
            }
        });
        Self {
            frames,
            task: Some(task),
        }
    }

    async fn recv(&mut self) -> Result<WorkerMessage, RuntimeFailure> {
        self.frames.recv().await.unwrap_or_else(|| {
            Err(RuntimeFailure::internal(
                "worker_disconnected",
                "sandbox worker disconnected",
            ))
        })
    }

    async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for WorkerFrameReader {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn sanitize_worker_failure(failure: RuntimeFailure) -> RuntimeFailure {
    match failure.code.as_str() {
        "source_too_large" => {
            RuntimeFailure::public("source_too_large", "TypeScript source exceeded 1 MiB")
        }
        "typescript_invalid" => {
            RuntimeFailure::public("typescript_invalid", "TypeScript could not be parsed")
        }
        "typescript_unsupported" => RuntimeFailure::public(
            "typescript_unsupported",
            "TypeScript used unsupported syntax",
        ),
        "transformed_source_too_large" => RuntimeFailure::public(
            "transformed_source_too_large",
            "transformed JavaScript exceeded 1 MiB",
        ),
        "execution_failed" => {
            RuntimeFailure::public("execution_failed", "TypeScript execution failed")
        }
        "result_too_large" => RuntimeFailure::public(
            "result_too_large",
            "execution output exceeded its size limit",
        ),
        "result_not_json" => RuntimeFailure::public(
            "result_not_json",
            "execution result was not JSON serializable",
        ),
        "javascript_runtime_failed" => RuntimeFailure::internal(
            "javascript_runtime_failed",
            "could not initialize JavaScript runtime",
        ),
        "tool_bridge_failed" => {
            RuntimeFailure::internal("tool_bridge_failed", "tool bridge failed")
        }
        _ => RuntimeFailure::internal("worker_failed", "sandbox worker failed"),
    }
}

fn validate_output(
    result: &serde_json::Value,
    emits: &[serde_json::Value],
    console: &[super::ConsoleEntry],
    limits: &RuntimeLimits,
) -> Result<(), RuntimeFailure> {
    let result_bytes = serde_json::to_vec(result)
        .map_err(|_| RuntimeFailure::internal("ipc_frame_invalid", "worker result was invalid"))?
        .len();
    if result_bytes > limits.result_bytes {
        return Err(RuntimeFailure::public(
            "result_too_large",
            "execution result exceeded 8 MiB",
        ));
    }
    let emit_bytes = emits.iter().try_fold(0usize, |total, emit| {
        serde_json::to_vec(emit)
            .ok()
            .and_then(|encoded| total.checked_add(encoded.len()))
            .ok_or_else(|| {
                RuntimeFailure::internal("ipc_frame_invalid", "worker emits were invalid")
            })
    })?;
    if emits.len() > limits.max_emits || emit_bytes > limits.max_emit_bytes {
        return Err(RuntimeFailure::internal(
            "ipc_protocol_violation",
            "worker emit limits were invalid",
        ));
    }
    let console_bytes = console
        .iter()
        .map(|entry| entry.message.len())
        .sum::<usize>();
    if console.len() > limits.max_console_entries || console_bytes > limits.max_console_bytes {
        return Err(RuntimeFailure::internal(
            "ipc_protocol_violation",
            "worker console limits were invalid",
        ));
    }
    Ok(())
}

async fn write_parent_message(
    writer: &Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    aggregate_bytes: &AtomicUsize,
    message: &ParentMessage,
    aggregate_limit: usize,
) -> Result<(), RuntimeFailure> {
    let payload = encode_frame(message)?;
    add_aggregate_bytes(aggregate_bytes, payload.len() + 4, aggregate_limit)?;
    let mut guard = writer.lock().await;
    write_encoded_frame(&mut *guard, &payload).await?;
    Ok(())
}

fn add_aggregate_bytes(
    aggregate: &AtomicUsize,
    bytes: usize,
    limit: usize,
) -> Result<(), RuntimeFailure> {
    aggregate
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current
                .checked_add(bytes)
                .filter(|updated| *updated <= limit)
        })
        .map(|_| ())
        .map_err(|_| RuntimeFailure::internal("ipc_limit_exceeded", "IPC byte limit exceeded"))
}

fn validate_header(
    version: u16,
    message_generation: u64,
    generation: u64,
) -> Result<(), RuntimeFailure> {
    if version != PROTOCOL_VERSION || message_generation != generation {
        return Err(RuntimeFailure::internal(
            "ipc_protocol_violation",
            "worker IPC version or generation was invalid",
        ));
    }
    Ok(())
}

fn spawn_worker(
    executable: &Path,
    generation: u64,
    working_directory: &Path,
    timeout: std::time::Duration,
) -> Result<(UnixStream, Child), RuntimeFailure> {
    let (parent, child_socket) = std::os::unix::net::UnixStream::pair().map_err(spawn_failure)?;
    parent.set_nonblocking(true).map_err(spawn_failure)?;
    let child_fd = child_socket.as_raw_fd();
    #[cfg(target_os = "linux")]
    let expected_parent = unsafe { libc::getpid() };
    let configured_max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max_fd = if configured_max_fd < 0 {
        1_048_576
    } else {
        configured_max_fd.min(i32::MAX as libc::c_long) as i32
    };
    let cpu_seconds = cpu_limit_seconds(timeout);
    let mut command = Command::new(executable);
    command
        .arg("sandbox-worker")
        .arg("--ipc-fd")
        .arg("3")
        .arg("--generation")
        .arg(generation.to_string())
        .env_clear()
        .current_dir(working_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.kill_on_drop(true);
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1
                    || libc::getppid() != expected_parent
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            libc::umask(0o077);
            set_limit(libc::RLIMIT_CORE, 0)?;
            set_limit(libc::RLIMIT_FSIZE, 0)?;
            set_limit(libc::RLIMIT_NOFILE, 16)?;
            set_limit(libc::RLIMIT_STACK, 8 * 1024 * 1024)?;
            set_limit(libc::RLIMIT_AS, 2 * 1024 * 1024 * 1024)?;
            set_limit(libc::RLIMIT_CPU, cpu_seconds)?;
            if child_fd != 3 && libc::dup2(child_fd, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(3, libc::F_GETFD);
            if flags == -1 || libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            close_extra_fds(max_fd)?;
            Ok(())
        });
    }
    let child = command.spawn().map_err(spawn_failure)?;
    drop(child_socket);
    let parent = UnixStream::from_std(parent).map_err(spawn_failure)?;
    Ok((parent, child))
}

unsafe fn close_extra_fds(max_fd: i32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOSYS) {
            return Err(error);
        }
    }
    #[cfg(target_os = "macos")]
    {
        unsafe { closefrom(4) };
        return Ok(());
    }
    #[allow(unreachable_code)]
    {
        for fd in 4..max_fd {
            unsafe { libc::close(fd) };
        }
        Ok(())
    }
}

unsafe fn set_limit(resource: RlimitResource, value: u64) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(resource, &limit) } == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

async fn terminate_worker(child: &mut Child) {
    if let Some(id) = child.id() {
        unsafe {
            libc::killpg(id as i32, libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
    let _ = tokio::time::timeout(EXECUTION_SHUTDOWN_GRACE, child.wait()).await;
}

fn random_generation() -> u64 {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    u64::from_le_bytes(bytes[..8].try_into().expect("UUID has eight bytes"))
        .rem_euclid(i64::MAX as u64)
        + 1
}

fn cpu_limit_seconds(timeout: std::time::Duration) -> u64 {
    timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() != 0))
        .max(1)
}

fn spawn_failure(_: std::io::Error) -> RuntimeFailure {
    RuntimeFailure::internal("worker_unavailable", "could not start sandbox worker")
}

fn cancelled() -> RuntimeFailure {
    RuntimeFailure::public("execution_cancelled", "TypeScript execution was cancelled")
}

struct PrivateTempDir(PathBuf);

impl PrivateTempDir {
    fn create() -> Result<Self, RuntimeFailure> {
        use std::os::unix::fs::DirBuilderExt;

        let path = std::env::temp_dir().join(format!("executor-sandbox-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).map_err(|_| {
            RuntimeFailure::internal("worker_unavailable", "could not create sandbox directory")
        })?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ProcessGroupGuard(Option<u32>);

impl ProcessGroupGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            unsafe {
                libc::killpg(pid as i32, libc::SIGKILL);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{mem::size_of, sync::Arc, time::Duration};

    use async_trait::async_trait;
    use serde_json::json;
    use tokio::{
        io::{AsyncWriteExt, Interest},
        sync::Notify,
    };

    use super::*;

    const TEST_GENERATION: u64 = 41;

    #[derive(Default)]
    struct BlockingFirstCallDispatcher {
        first_started: Notify,
        release_first: Notify,
        call_ids: Mutex<Vec<u64>>,
    }

    #[async_trait]
    impl HostToolDispatcher for BlockingFirstCallDispatcher {
        async fn dispatch(
            &self,
            call: ToolCall,
            _cancellation: ExecutionCancellation,
        ) -> ToolResult {
            self.call_ids.lock().await.push(call.call_id);
            if call.call_id == 1 {
                self.first_started.notify_one();
                self.release_first.notified().await;
            }
            ToolResult::Success {
                value: json!({ "callId": call.call_id }),
            }
        }
    }

    struct NoopDispatcher;

    #[async_trait]
    impl HostToolDispatcher for NoopDispatcher {
        async fn dispatch(
            &self,
            call: ToolCall,
            _cancellation: ExecutionCancellation,
        ) -> ToolResult {
            ToolResult::Success {
                value: json!({ "callId": call.call_id }),
            }
        }
    }

    struct StalledStoppingDispatcher;

    #[async_trait]
    impl HostToolDispatcher for StalledStoppingDispatcher {
        async fn dispatch(
            &self,
            _call: ToolCall,
            _cancellation: ExecutionCancellation,
        ) -> ToolResult {
            unreachable!("timeout drain test never dispatches a tool")
        }

        async fn execution_stopping(&self, _execution_id: &str) {
            std::future::pending::<()>().await;
        }
    }

    fn spawn_test_execution(
        dispatcher: Arc<dyn HostToolDispatcher>,
        cancellation: ExecutionCancellation,
    ) -> (
        UnixStream,
        JoinHandle<Result<ExecutionOutput, RuntimeFailure>>,
    ) {
        let (parent, worker) = UnixStream::pair().expect("Unix stream pair creates");
        let execution = tokio::spawn(run_execution(
            parent,
            TEST_GENERATION,
            "ipc-test".to_owned(),
            "".to_owned(),
            RuntimeLimits::default(),
            dispatcher,
            cancellation,
        ));
        (worker, execution)
    }

    async fn read_start(worker: &mut UnixStream) {
        let (message, _) = read_frame::<_, ParentMessage>(worker)
            .await
            .expect("start frame reads");
        assert!(matches!(
            message,
            ParentMessage::Start {
                version: PROTOCOL_VERSION,
                generation: TEST_GENERATION,
                ..
            }
        ));
    }

    async fn write_worker_message(worker: &mut UnixStream, message: &WorkerMessage) {
        let payload = encode_frame(message).expect("worker frame encodes");
        write_encoded_frame(worker, &payload)
            .await
            .expect("worker frame writes");
    }

    async fn read_tool_result(worker: &mut UnixStream, expected_call_id: u64) {
        let (message, _) = read_frame::<_, ParentMessage>(worker)
            .await
            .expect("tool result reads");
        assert!(matches!(
            message,
            ParentMessage::ToolResult {
                version: PROTOCOL_VERSION,
                generation: TEST_GENERATION,
                call_id,
                ..
            } if call_id == expected_call_id
        ));
    }

    fn shrink_send_buffer(worker: &UnixStream) {
        let bytes: libc::c_int = 4 * 1024;
        let result = unsafe {
            libc::setsockopt(
                worker.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_ref(&bytes).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(result, 0, "send buffer should shrink");
    }

    async fn assert_peer_reader_closed(worker: &mut UnixStream) {
        let chunk = [0_u8; 8 * 1024];
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                worker
                    .ready(Interest::WRITABLE)
                    .await
                    .expect("worker socket readiness");
                match worker.try_write(&chunk) {
                    Ok(_) => tokio::task::yield_now().await,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(_) => return,
                }
            }
        })
        .await
        .expect("framed reader task releases its socket");
    }

    #[test]
    fn cpu_limit_rounds_fractional_seconds_up_without_padding_exact_seconds() {
        assert_eq!(cpu_limit_seconds(Duration::from_millis(1)), 1);
        assert_eq!(cpu_limit_seconds(Duration::from_secs(1)), 1);
        assert_eq!(cpu_limit_seconds(Duration::from_millis(1_001)), 2);
        assert_eq!(cpu_limit_seconds(Duration::from_secs(300)), 300);
    }

    #[tokio::test]
    async fn fragmented_frame_survives_tool_completion_select_branch() {
        let dispatcher = Arc::new(BlockingFirstCallDispatcher::default());
        let (mut worker, execution) =
            spawn_test_execution(dispatcher.clone(), ExecutionCancellation::default());
        read_start(&mut worker).await;
        write_worker_message(
            &mut worker,
            &WorkerMessage::ToolCall {
                version: PROTOCOL_VERSION,
                generation: TEST_GENERATION,
                call_id: 1,
                path: "first.call".to_owned(),
                arguments: json!({}),
            },
        )
        .await;
        dispatcher.first_started.notified().await;

        shrink_send_buffer(&worker);
        let second_payload = encode_frame(&WorkerMessage::ToolCall {
            version: PROTOCOL_VERSION,
            generation: TEST_GENERATION,
            call_id: 2,
            path: "second.call".to_owned(),
            arguments: json!({ "padding": "x".repeat(512 * 1024) }),
        })
        .expect("second call frame encodes");
        worker
            .write_u32(second_payload.len() as u32)
            .await
            .expect("second call length writes");
        worker
            .write_all(&second_payload[..second_payload.len() - 1])
            .await
            .expect("partial second call writes");

        dispatcher.release_first.notify_one();
        read_tool_result(&mut worker, 1).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        worker
            .write_all(&second_payload[second_payload.len() - 1..])
            .await
            .expect("second call finishes");
        read_tool_result(&mut worker, 2).await;
        write_worker_message(
            &mut worker,
            &WorkerMessage::Complete {
                version: PROTOCOL_VERSION,
                generation: TEST_GENERATION,
                result: json!({ "complete": true }),
                emits: Vec::new(),
                console: Vec::new(),
            },
        )
        .await;

        let output = tokio::time::timeout(Duration::from_secs(2), execution)
            .await
            .expect("execution completes")
            .expect("execution task joins")
            .expect("execution succeeds");
        assert_eq!(output.result, json!({ "complete": true }));
        assert_eq!(
            output
                .tool_calls
                .iter()
                .map(|record| record.call_id)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(*dispatcher.call_ids.lock().await, [1, 2]);
    }

    #[tokio::test]
    async fn cancellation_aborts_a_fragmented_reader_without_leaking_its_task() {
        let cancellation = ExecutionCancellation::default();
        let (mut worker, execution) =
            spawn_test_execution(Arc::new(NoopDispatcher), cancellation.clone());
        read_start(&mut worker).await;
        worker.write_u32(1024).await.expect("frame length writes");
        worker.write_all(b"{").await.expect("frame prefix writes");

        cancellation.cancel();
        let error = tokio::time::timeout(Duration::from_secs(1), execution)
            .await
            .expect("cancellation completes")
            .expect("execution task joins")
            .expect_err("execution is canceled");
        assert_eq!(error.code, "execution_cancelled");
        assert_peer_reader_closed(&mut worker).await;
    }

    #[tokio::test]
    async fn aborting_execution_drops_the_fragmented_reader_task() {
        let (mut worker, execution) =
            spawn_test_execution(Arc::new(NoopDispatcher), ExecutionCancellation::default());
        read_start(&mut worker).await;
        worker.write_u32(1024).await.expect("frame length writes");
        worker.write_all(b"{").await.expect("frame prefix writes");

        execution.abort();
        let _ = execution.await;
        assert_peer_reader_closed(&mut worker).await;
    }

    #[tokio::test]
    async fn truncated_and_oversized_worker_frames_fail_closed() {
        let (mut truncated_worker, truncated_execution) =
            spawn_test_execution(Arc::new(NoopDispatcher), ExecutionCancellation::default());
        read_start(&mut truncated_worker).await;
        truncated_worker
            .write_u32(64)
            .await
            .expect("truncated frame length writes");
        truncated_worker
            .write_all(b"{}")
            .await
            .expect("truncated frame prefix writes");
        truncated_worker
            .shutdown()
            .await
            .expect("worker write side closes");
        let truncated = truncated_execution
            .await
            .expect("truncated execution joins")
            .expect_err("truncated frame fails");
        assert_eq!(truncated.code, "worker_disconnected");

        let (mut oversized_worker, oversized_execution) =
            spawn_test_execution(Arc::new(NoopDispatcher), ExecutionCancellation::default());
        read_start(&mut oversized_worker).await;
        oversized_worker
            .write_u32((super::super::protocol::FRAME_LIMIT + 1) as u32)
            .await
            .expect("oversized frame length writes");
        let oversized = oversized_execution
            .await
            .expect("oversized execution joins")
            .expect_err("oversized frame fails");
        assert_eq!(oversized.code, "ipc_frame_invalid");
        assert_peer_reader_closed(&mut oversized_worker).await;
    }

    #[tokio::test]
    async fn timeout_drain_is_bounded_when_cleanup_never_finishes() {
        let dispatcher: Arc<dyn HostToolDispatcher> = Arc::new(StalledStoppingDispatcher);
        let mut run = Box::pin(std::future::pending::<
            Result<ExecutionOutput, RuntimeFailure>,
        >());
        tokio::time::timeout(
            Duration::from_secs(2),
            drain_timed_out_execution(run.as_mut(), &dispatcher, "timeout-test"),
        )
        .await
        .expect("timeout cleanup is bounded");
    }

    #[tokio::test]
    async fn worker_reap_wait_is_bounded() {
        let mut child = Command::new("sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .expect("test child starts");

        tokio::time::timeout(Duration::from_secs(2), terminate_worker(&mut child))
            .await
            .expect("worker termination is bounded");
        assert!(
            child
                .try_wait()
                .expect("worker status is readable")
                .is_some(),
            "terminated worker is reaped"
        );
    }
}
