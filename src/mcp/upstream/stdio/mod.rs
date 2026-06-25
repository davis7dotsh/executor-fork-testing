use std::{
    collections::{BTreeMap, HashMap},
    future::pending,
    io,
    io::Read as _,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use rmcp::model::ProtocolVersion;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, ChildStdout, Command},
    sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, timeout, timeout_at},
};

const MAX_TEMPLATE_NAME_BYTES: usize = 64;
const MAX_ARGUMENTS: usize = 128;
const MAX_ENVIRONMENT_ENTRIES: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 16 * 1024;
const MAX_TEMPLATE_BYTES: usize = 128 * 1024;
const MAX_TEMPLATES: usize = 256;
const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const TOOL_LIST_CHANGED_CAPACITY: usize = 64;
const LIFECYCLE_STATE_MASK: u64 = 0b11;
const LIFECYCLE_UNINITIALIZED: u64 = 0;
const LIFECYCLE_INITIALIZING: u64 = 1;
const LIFECYCLE_INITIALIZED: u64 = 2;
const MAX_LIFECYCLE_GENERATION: u64 = u64::MAX >> 2;
pub const DEFAULT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2025_11_25;

fn lifecycle_word(generation: u64, state: u64) -> u64 {
    ((generation & MAX_LIFECYCLE_GENERATION) << 2) | (state & LIFECYCLE_STATE_MASK)
}

fn lifecycle_state(word: u64) -> u64 {
    word & LIFECYCLE_STATE_MASK
}

fn lifecycle_generation(word: u64) -> u64 {
    word >> 2
}

fn acquire_lifecycle_generation(lifecycle: &AtomicU64) -> Result<u64, StdioTransportError> {
    let mut current = lifecycle.load(Ordering::Acquire);
    loop {
        if lifecycle_state(current) != LIFECYCLE_UNINITIALIZED {
            return Err(StdioTransportError::AlreadyInitialized);
        }
        let generation =
            (lifecycle_generation(current).wrapping_add(1) & MAX_LIFECYCLE_GENERATION).max(1);
        let next = lifecycle_word(generation, LIFECYCLE_INITIALIZING);
        match lifecycle.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(generation),
            Err(observed) => current = observed,
        }
    }
}

fn reset_lifecycle_generation(lifecycle: &AtomicU64, generation: u64) {
    let _ = lifecycle.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        (lifecycle_generation(current) == generation)
            .then(|| lifecycle_word(generation, LIFECYCLE_UNINITIALIZED))
    });
}

fn reset_lifecycle_current(lifecycle: &AtomicU64) {
    let _ = lifecycle.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(lifecycle_word(
            lifecycle_generation(current),
            LIFECYCLE_UNINITIALIZED,
        ))
    });
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StdioTemplate {
    pub name: String,
    pub executable: PathBuf,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub arguments: Vec<String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub secret_environment: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct TrustedStdioTemplate {
    name: String,
    executable: PathBuf,
    cwd: Option<PathBuf>,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    secret_environment: Vec<String>,
}

impl std::fmt::Debug for TrustedStdioTemplate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedStdioTemplate")
            .field("name", &self.name)
            .field("secret_environment", &self.secret_environment)
            .finish_non_exhaustive()
    }
}

impl TrustedStdioTemplate {
    pub(crate) fn validate(template: StdioTemplate) -> Result<Self, StdioTemplateError> {
        validate_template_name(&template.name)?;
        if !template.executable.is_absolute() {
            return Err(StdioTemplateError::ExecutableMustBeAbsolute);
        }
        let executable = std::fs::canonicalize(&template.executable)
            .map_err(|_| StdioTemplateError::ExecutableUnavailable)?;
        let metadata = std::fs::metadata(&executable)
            .map_err(|_| StdioTemplateError::ExecutableUnavailable)?;
        if !metadata.is_file() {
            return Err(StdioTemplateError::ExecutableUnavailable);
        }
        validate_executable_permissions(&metadata)?;
        let cwd = match template.cwd {
            Some(cwd) => {
                if !cwd.is_absolute() {
                    return Err(StdioTemplateError::CwdMustBeAbsolute);
                }
                let cwd =
                    std::fs::canonicalize(cwd).map_err(|_| StdioTemplateError::CwdUnavailable)?;
                if !std::fs::metadata(&cwd)
                    .map_err(|_| StdioTemplateError::CwdUnavailable)?
                    .is_dir()
                {
                    return Err(StdioTemplateError::CwdUnavailable);
                }
                Some(cwd)
            }
            None => None,
        };
        validate_arguments(&template.arguments)?;
        validate_environment(&template.environment)?;
        validate_secret_environment(&template.secret_environment, &template.environment)?;

        Ok(Self {
            name: template.name,
            executable,
            cwd,
            arguments: template.arguments,
            environment: template.environment,
            secret_environment: template.secret_environment,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StdioTemplateDescriptor {
    pub name: String,
    pub secret_fields: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct StdioTemplateRegistry {
    templates: BTreeMap<String, TrustedStdioTemplate>,
}

impl StdioTemplateRegistry {
    pub fn new(templates: Vec<StdioTemplate>) -> Result<Self, StdioTemplateError> {
        if templates.len() > MAX_TEMPLATES {
            return Err(StdioTemplateError::TooManyTemplates);
        }
        let mut registry = Self::default();
        for template in templates {
            let template = TrustedStdioTemplate::validate(template)?;
            if registry
                .templates
                .insert(template.name.clone(), template)
                .is_some()
            {
                return Err(StdioTemplateError::DuplicateName);
            }
        }
        Ok(registry)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, StdioTemplateError> {
        let file = std::fs::File::open(path).map_err(|_| StdioTemplateError::ConfigRead)?;
        if file
            .metadata()
            .map_err(|_| StdioTemplateError::ConfigRead)?
            .len()
            > MAX_CONFIG_FILE_BYTES
        {
            return Err(StdioTemplateError::ConfigTooLarge);
        }
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| StdioTemplateError::ConfigRead)?;
        if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(StdioTemplateError::ConfigTooLarge);
        }
        let config: StdioTemplateFile =
            serde_json::from_slice(&bytes).map_err(|_| StdioTemplateError::ConfigInvalid)?;
        Self::new(config.templates)
    }

    pub(crate) fn template(&self, name: &str) -> Result<&TrustedStdioTemplate, StdioTemplateError> {
        self.templates
            .get(name)
            .ok_or(StdioTemplateError::UnknownTemplate)
    }

    pub fn descriptors(&self) -> Vec<StdioTemplateDescriptor> {
        self.templates
            .values()
            .map(|template| StdioTemplateDescriptor {
                name: template.name.clone(),
                secret_fields: template.secret_environment.clone(),
            })
            .collect()
    }

    pub async fn connect_with_secrets(
        &self,
        name: &str,
        secrets: &BTreeMap<String, String>,
        limits: StdioTransportLimits,
    ) -> Result<StdioClient, StdioTransportError> {
        let mut template = self.template(name)?.clone();
        validate_secret_overlay(&template.secret_environment, secrets)?;
        template.environment.extend(secrets.clone());
        validate_environment(&template.environment)?;
        StdioClient::connect(template, limits).await
    }
}

#[derive(Debug, Error)]
pub enum StdioTemplateError {
    #[error("the stdio template configuration could not be read")]
    ConfigRead,
    #[error("the stdio template configuration is too large")]
    ConfigTooLarge,
    #[error("the stdio template configuration is invalid")]
    ConfigInvalid,
    #[error("the stdio template configuration has too many templates")]
    TooManyTemplates,
    #[error("the stdio template name is invalid")]
    InvalidName,
    #[error("stdio template names must be unique")]
    DuplicateName,
    #[error("the named stdio template does not exist")]
    UnknownTemplate,
    #[error("the stdio executable must be an absolute path")]
    ExecutableMustBeAbsolute,
    #[error("the stdio executable is unavailable")]
    ExecutableUnavailable,
    #[error("the stdio executable is not executable")]
    ExecutableNotExecutable,
    #[error("the stdio working directory must be an absolute path")]
    CwdMustBeAbsolute,
    #[error("the stdio working directory is unavailable")]
    CwdUnavailable,
    #[error("the stdio template has too many arguments")]
    TooManyArguments,
    #[error("a stdio template argument is too large")]
    ArgumentTooLarge,
    #[error("the stdio template has too many environment entries")]
    TooManyEnvironmentEntries,
    #[error("a stdio template environment entry is invalid")]
    InvalidEnvironmentEntry,
    #[error("the stdio template is too large")]
    TemplateTooLarge,
    #[error("the stdio template secret fields are invalid")]
    InvalidSecretFields,
    #[error("the supplied stdio template secrets do not match the approved fields")]
    InvalidSecretOverlay,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StdioTemplateFile {
    templates: Vec<StdioTemplate>,
}

#[derive(Clone, Copy, Debug)]
pub struct StdioTransportLimits {
    pub max_message_bytes: usize,
    pub max_stderr_bytes: usize,
    pub request_timeout: Duration,
    pub shutdown_grace: Duration,
    pub initial_restart_backoff: Duration,
    pub max_restart_backoff: Duration,
    pub command_queue_capacity: usize,
}

impl Default for StdioTransportLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 16 * 1024 * 1024,
            max_stderr_bytes: 64 * 1024,
            request_timeout: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(2),
            initial_restart_backoff: Duration::from_millis(100),
            max_restart_backoff: Duration::from_secs(5),
            command_queue_capacity: 256,
        }
    }
}

impl StdioTransportLimits {
    fn validate(self) -> Result<Self, StdioTransportError> {
        if self.max_message_bytes == 0
            || self.max_message_bytes > 32 * 1024 * 1024
            || self.max_stderr_bytes == 0
            || self.max_stderr_bytes > 1024 * 1024
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(5 * 60)
            || self.shutdown_grace.is_zero()
            || self.shutdown_grace > Duration::from_secs(30)
            || self.initial_restart_backoff.is_zero()
            || self.initial_restart_backoff > Duration::from_secs(30)
            || self.max_restart_backoff < self.initial_restart_backoff
            || self.max_restart_backoff > Duration::from_secs(30)
            || self.request_timeout <= self.max_restart_backoff
            || self.command_queue_capacity == 0
            || self.command_queue_capacity > 4_096
        {
            return Err(StdioTransportError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerInfo {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub title: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: ProtocolVersion,
    #[serde(default)]
    pub capabilities: Value,
    #[serde(default)]
    pub server_info: Option<McpServerInfo>,
    #[serde(default)]
    pub instructions: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default)]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub annotations: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListToolsResult {
    #[serde(default)]
    pub tools: Vec<McpTool>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallToolResult {
    #[serde(default)]
    pub content: Vec<Value>,
    #[serde(default)]
    pub structured_content: Option<Value>,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Debug, Error)]
pub enum StdioTransportError {
    #[error(transparent)]
    Template(#[from] StdioTemplateError),
    #[error("the stdio transport limits are invalid")]
    InvalidLimits,
    #[error("the stdio process could not be started")]
    Spawn,
    #[error("the stdio transport command queue is closed")]
    Closed,
    #[error("the stdio transport must be initialized again after restart")]
    RestartRequiresInitialization,
    #[error("the stdio transport has not been initialized")]
    NotInitialized,
    #[error("the stdio transport is already initialized")]
    AlreadyInitialized,
    #[error("the stdio request timed out")]
    Timeout,
    #[error("the stdio request is too large")]
    RequestTooLarge,
    #[error("the stdio response is too large")]
    ResponseTooLarge,
    #[error("the stdio server returned an invalid JSON-RPC message")]
    InvalidResponse,
    #[error("the stdio server returned JSON-RPC error code {code}")]
    JsonRpc { code: i64 },
    #[error("the stdio process exited unexpectedly")]
    ProcessExited {
        code: Option<i32>,
        stderr_truncated: bool,
    },
    #[error("the tool call outcome is unknown because the stdio transport disconnected")]
    AmbiguousToolCall,
    #[error("the stdio request ID is already in flight")]
    DuplicateRequestId,
    #[error("the stdio transport has too many requests in flight")]
    TooManyInFlight,
    #[error("the stdio response did not match an in-flight request")]
    UnexpectedResponseId,
    #[error("the stdio request could not be encoded")]
    Encode,
    #[error("the stdio response could not be decoded")]
    Decode,
    #[error("the stdio request is invalid")]
    InvalidRequest,
    #[error("the stdio server selected an unsupported protocol version")]
    ProtocolVersionMismatch,
}

pub struct StdioClient {
    commands: mpsc::Sender<ClientCommand>,
    tool_list_changed: broadcast::Sender<()>,
    queue_bytes: std::sync::Arc<Semaphore>,
    lifecycle: std::sync::Arc<AtomicU64>,
    actor: Option<JoinHandle<()>>,
    next_request_id: AtomicU64,
    request_timeout: Duration,
    max_message_bytes: usize,
}

#[derive(Clone)]
pub(crate) struct StdioLifecycleMonitor {
    lifecycle: std::sync::Arc<AtomicU64>,
}

impl StdioLifecycleMonitor {
    pub(crate) fn is_initialized(&self) -> bool {
        lifecycle_state(self.lifecycle.load(Ordering::Acquire)) == LIFECYCLE_INITIALIZED
    }

    #[cfg(test)]
    pub(crate) fn initialized_fixture() -> Self {
        Self {
            lifecycle: std::sync::Arc::new(AtomicU64::new(lifecycle_word(
                1,
                LIFECYCLE_INITIALIZED,
            ))),
        }
    }

    #[cfg(test)]
    pub(crate) fn disconnect_fixture(&self) {
        reset_lifecycle_current(&self.lifecycle);
    }
}

impl StdioClient {
    pub(crate) async fn connect(
        template: TrustedStdioTemplate,
        limits: StdioTransportLimits,
    ) -> Result<Self, StdioTransportError> {
        let limits = limits.validate()?;
        let process = RunningProcess::spawn(&template, limits).await?;
        let (commands, receiver) = mpsc::channel(limits.command_queue_capacity);
        let (tool_list_changed, _) = broadcast::channel(TOOL_LIST_CHANGED_CAPACITY);
        let queue_bytes =
            std::sync::Arc::new(Semaphore::new(limits.max_message_bytes.saturating_mul(2)));
        let lifecycle =
            std::sync::Arc::new(AtomicU64::new(lifecycle_word(0, LIFECYCLE_UNINITIALIZED)));
        let actor = tokio::spawn(run_actor(
            template,
            limits,
            process,
            receiver,
            tool_list_changed.clone(),
            lifecycle.clone(),
        ));
        Ok(Self {
            commands,
            tool_list_changed,
            queue_bytes,
            lifecycle,
            actor: Some(actor),
            next_request_id: AtomicU64::new(1),
            request_timeout: limits.request_timeout,
            max_message_bytes: limits.max_message_bytes,
        })
    }

    pub async fn initialize(
        &self,
        protocol_version: ProtocolVersion,
        client_info: Value,
        capabilities: Value,
    ) -> Result<InitializeResult, StdioTransportError> {
        let generation = acquire_lifecycle_generation(&self.lifecycle)?;
        let mut guard =
            InitializationGuard::new(self.lifecycle.clone(), self.commands.clone(), generation);
        let result = self
            .initialize_inner(protocol_version, client_info, capabilities, generation)
            .await;
        if result.is_err() {
            self.reset_transport(generation).await;
        }
        match result {
            Ok(initialized) => {
                self.lifecycle
                    .compare_exchange(
                        lifecycle_word(generation, LIFECYCLE_INITIALIZING),
                        lifecycle_word(generation, LIFECYCLE_INITIALIZED),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .map_err(|_| StdioTransportError::Closed)?;
                guard.disarm();
                let _ = self
                    .commands
                    .try_send(ClientCommand::Healthy { generation });
                Ok(initialized)
            }
            Err(error) => {
                if lifecycle_state(self.lifecycle.load(Ordering::Acquire))
                    == LIFECYCLE_UNINITIALIZED
                {
                    guard.disarm();
                }
                Err(error)
            }
        }
    }

    async fn initialize_inner(
        &self,
        protocol_version: ProtocolVersion,
        client_info: Value,
        capabilities: Value,
        generation: u64,
    ) -> Result<InitializeResult, StdioTransportError> {
        if protocol_version != DEFAULT_PROTOCOL_VERSION
            || !client_info.is_object()
            || !capabilities.is_object()
        {
            return Err(StdioTransportError::InvalidRequest);
        }
        let result = self
            .request(
                self.next_id(),
                "initialize",
                json!({
                    "protocolVersion": protocol_version,
                    "clientInfo": client_info,
                    "capabilities": capabilities,
                }),
                RequestSemantics::Replayable,
                Some(generation),
            )
            .await?;
        let initialized: InitializeResult =
            serde_json::from_value(result).map_err(|_| StdioTransportError::Decode)?;
        if initialized.protocol_version != DEFAULT_PROTOCOL_VERSION {
            return Err(StdioTransportError::ProtocolVersionMismatch);
        }
        if !initialized.capabilities.is_object() {
            return Err(StdioTransportError::Decode);
        }
        self.notify("notifications/initialized", json!({}), Some(generation))
            .await?;
        Ok(initialized)
    }

    pub async fn list_tools(
        &self,
        cursor: Option<&str>,
    ) -> Result<ListToolsResult, StdioTransportError> {
        self.require_initialized()?;
        if cursor.is_some_and(|cursor| cursor.len() > 16 * 1024) {
            return Err(StdioTransportError::InvalidRequest);
        }
        let params = cursor.map_or_else(|| json!({}), |cursor| json!({ "cursor": cursor }));
        let result = self
            .request(
                self.next_id(),
                "tools/list",
                params,
                RequestSemantics::Replayable,
                None,
            )
            .await?;
        let result: ListToolsResult =
            serde_json::from_value(result).map_err(|_| StdioTransportError::Decode)?;
        if result.tools.iter().any(|tool| {
            tool.name.is_empty() || tool.name.len() > 1_024 || !tool.input_schema.is_object()
        }) {
            return Err(StdioTransportError::Decode);
        }
        Ok(result)
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
        request_id: u64,
    ) -> Result<CallToolResult, StdioTransportError> {
        self.require_initialized()?;
        if name.is_empty() || name.len() > 1_024 || !arguments.is_object() {
            return Err(StdioTransportError::InvalidRequest);
        }
        let result = self
            .request(
                request_id,
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
                RequestSemantics::AmbiguousAfterWrite,
                None,
            )
            .await?;
        if result
            .get("structuredContent")
            .is_some_and(|structured_content| !structured_content.is_object())
        {
            return Err(StdioTransportError::Decode);
        }
        let result: CallToolResult =
            serde_json::from_value(result).map_err(|_| StdioTransportError::Decode)?;
        if result.content.iter().any(|content| !content.is_object()) {
            return Err(StdioTransportError::Decode);
        }
        Ok(result)
    }

    fn require_initialized(&self) -> Result<(), StdioTransportError> {
        if lifecycle_state(self.lifecycle.load(Ordering::Acquire)) == LIFECYCLE_INITIALIZED {
            Ok(())
        } else {
            Err(StdioTransportError::NotInitialized)
        }
    }

    pub fn subscribe_tool_list_changed(&self) -> broadcast::Receiver<()> {
        self.tool_list_changed.subscribe()
    }

    #[cfg(test)]
    pub(crate) fn is_initialized(&self) -> bool {
        lifecycle_state(self.lifecycle.load(Ordering::Acquire)) == LIFECYCLE_INITIALIZED
    }

    pub(crate) fn lifecycle_monitor(&self) -> StdioLifecycleMonitor {
        StdioLifecycleMonitor {
            lifecycle: self.lifecycle.clone(),
        }
    }

    pub async fn shutdown(mut self) {
        let (completed, completion) = oneshot::channel();
        let _ = self
            .commands
            .send(ClientCommand::Shutdown {
                completed: Some(completed),
            })
            .await;
        let _ = completion.await;
        if let Some(actor) = self.actor.take() {
            let _ = actor.await;
        }
    }

    fn next_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn request(
        &self,
        id: u64,
        method: &str,
        params: Value,
        semantics: RequestSemantics,
        generation: Option<u64>,
    ) -> Result<Value, StdioTransportError> {
        let payload = encode_message(
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
            self.max_message_bytes,
        )?;
        let deadline = Instant::now() + self.request_timeout;
        let permit = timeout_at(
            deadline,
            self.queue_bytes
                .clone()
                .acquire_many_owned(payload.len().max(1) as u32),
        )
        .await
        .map_err(|_| StdioTransportError::Timeout)?
        .map_err(|_| StdioTransportError::Closed)?;
        let (reply, response) = oneshot::channel();
        timeout_at(
            deadline,
            self.commands.send(ClientCommand::Request {
                id,
                payload,
                permit,
                initialization: method == "initialize",
                generation,
                semantics,
                deadline,
                reply,
            }),
        )
        .await
        .map_err(|_| StdioTransportError::Timeout)?
        .map_err(|_| StdioTransportError::Closed)?;
        match timeout_at(deadline, response).await {
            Ok(response) => response.map_err(|_| StdioTransportError::Closed)?,
            Err(_) => Err(match semantics {
                RequestSemantics::Replayable => StdioTransportError::Timeout,
                RequestSemantics::AmbiguousAfterWrite => StdioTransportError::AmbiguousToolCall,
            }),
        }
    }

    async fn notify(
        &self,
        method: &str,
        params: Value,
        generation: Option<u64>,
    ) -> Result<(), StdioTransportError> {
        let payload = encode_message(
            &json!({ "jsonrpc": "2.0", "method": method, "params": params }),
            self.max_message_bytes,
        )?;
        let deadline = Instant::now() + self.request_timeout;
        let permit = timeout_at(
            deadline,
            self.queue_bytes
                .clone()
                .acquire_many_owned(payload.len().max(1) as u32),
        )
        .await
        .map_err(|_| StdioTransportError::Timeout)?
        .map_err(|_| StdioTransportError::Closed)?;
        let (reply, response) = oneshot::channel();
        timeout_at(
            deadline,
            self.commands.send(ClientCommand::Notification {
                payload,
                permit,
                deadline,
                generation,
                reply,
            }),
        )
        .await
        .map_err(|_| StdioTransportError::Timeout)?
        .map_err(|_| StdioTransportError::Closed)?;
        match timeout_at(deadline, response).await {
            Ok(response) => response.map_err(|_| StdioTransportError::Closed)?,
            Err(_) => Err(StdioTransportError::Timeout),
        }
    }

    async fn reset_transport(&self, generation: u64) {
        let (completed, completion) = oneshot::channel();
        let deadline = Instant::now() + self.request_timeout;
        let sent = timeout_at(
            deadline,
            self.commands.send(ClientCommand::Reset {
                generation,
                completed,
            }),
        )
        .await;
        if matches!(sent, Ok(Ok(()))) {
            let _ = timeout_at(deadline, completion).await;
        } else {
            reset_lifecycle_generation(&self.lifecycle, generation);
        }
    }
}

impl Drop for StdioClient {
    fn drop(&mut self) {
        if self.actor.is_none() {
            return;
        }
        let _ = self
            .commands
            .try_send(ClientCommand::Shutdown { completed: None });
    }
}

struct InitializationGuard {
    lifecycle: std::sync::Arc<AtomicU64>,
    commands: mpsc::Sender<ClientCommand>,
    generation: u64,
    armed: bool,
}

impl InitializationGuard {
    fn new(
        lifecycle: std::sync::Arc<AtomicU64>,
        commands: mpsc::Sender<ClientCommand>,
        generation: u64,
    ) -> Self {
        Self {
            lifecycle,
            commands,
            generation,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for InitializationGuard {
    fn drop(&mut self) {
        if !self.armed
            || self.lifecycle.load(Ordering::Acquire)
                != lifecycle_word(self.generation, LIFECYCLE_INITIALIZING)
        {
            return;
        }
        let lifecycle = self.lifecycle.clone();
        let commands = self.commands.clone();
        let generation = self.generation;
        let cleanup = async move {
            let (completed, completion) = oneshot::channel();
            if commands
                .send(ClientCommand::Reset {
                    generation,
                    completed,
                })
                .await
                .is_err()
            {
                reset_lifecycle_generation(&lifecycle, generation);
                return;
            }
            if completion.await.is_err() {
                reset_lifecycle_generation(&lifecycle, generation);
            }
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(cleanup);
        } else {
            reset_lifecycle_generation(&self.lifecycle, self.generation);
        }
    }
}

#[derive(Clone, Copy)]
enum RequestSemantics {
    Replayable,
    AmbiguousAfterWrite,
}

enum ClientCommand {
    Request {
        id: u64,
        payload: Vec<u8>,
        permit: OwnedSemaphorePermit,
        initialization: bool,
        generation: Option<u64>,
        semantics: RequestSemantics,
        deadline: Instant,
        reply: oneshot::Sender<Result<Value, StdioTransportError>>,
    },
    Notification {
        payload: Vec<u8>,
        permit: OwnedSemaphorePermit,
        deadline: Instant,
        generation: Option<u64>,
        reply: oneshot::Sender<Result<(), StdioTransportError>>,
    },
    Reset {
        generation: u64,
        completed: oneshot::Sender<()>,
    },
    Healthy {
        generation: u64,
    },
    Shutdown {
        completed: Option<oneshot::Sender<()>>,
    },
}

struct PendingRequest {
    semantics: RequestSemantics,
    generation: Option<u64>,
    deadline: Instant,
    reply: oneshot::Sender<Result<Value, StdioTransportError>>,
}

async fn run_actor(
    template: TrustedStdioTemplate,
    limits: StdioTransportLimits,
    initial_process: RunningProcess,
    mut commands: mpsc::Receiver<ClientCommand>,
    tool_list_changed: broadcast::Sender<()>,
    lifecycle: std::sync::Arc<AtomicU64>,
) {
    let mut process = Some(initial_process);
    let mut pending = HashMap::<u64, PendingRequest>::new();
    let mut restart = RestartState::default();

    'actor: loop {
        if process.is_none() {
            let Some(command) = commands.recv().await else {
                break;
            };
            if let ClientCommand::Shutdown { completed } = command {
                if let Some(completed) = completed {
                    let _ = completed.send(());
                }
                break;
            }
            if let ClientCommand::Reset {
                generation,
                completed,
            } = command
            {
                reset_lifecycle_generation(&lifecycle, generation);
                let _ = completed.send(());
                continue;
            }
            if matches!(&command, ClientCommand::Healthy { .. }) {
                continue;
            }
            if !matches!(
                &command,
                ClientCommand::Request {
                    initialization: true,
                    ..
                }
            ) {
                reject_command(command, StdioTransportError::RestartRequiresInitialization);
                continue;
            }
            let valid_generation = matches!(
                &command,
                ClientCommand::Request {
                    generation: Some(generation),
                    ..
                } if lifecycle.load(Ordering::Acquire)
                    == lifecycle_word(*generation, LIFECYCLE_INITIALIZING)
            );
            if !valid_generation {
                reject_command(command, StdioTransportError::Closed);
                continue;
            }
            if let Some(retry_at) = restart.retry_at {
                while Instant::now() < retry_at {
                    tokio::select! {
                        _ = tokio::time::sleep_until(retry_at) => break,
                        next = commands.recv() => match next {
                            Some(ClientCommand::Shutdown { completed }) => {
                                reject_command(command, StdioTransportError::Closed);
                                if let Some(completed) = completed {
                                    let _ = completed.send(());
                                }
                                break 'actor;
                            }
                            Some(ClientCommand::Reset { generation, completed }) => {
                                reset_lifecycle_generation(&lifecycle, generation);
                                let _ = completed.send(());
                            }
                            Some(ClientCommand::Healthy { .. }) => {}
                            Some(other) => reject_command(
                                other,
                                StdioTransportError::RestartRequiresInitialization,
                            ),
                            None => {
                                reject_command(command, StdioTransportError::Closed);
                                break 'actor;
                            }
                        }
                    }
                }
            }
            if command_reply_closed(&command) {
                continue;
            }
            match RunningProcess::spawn(&template, limits).await {
                Ok(spawned) => process = Some(spawned),
                Err(error) => {
                    reject_command(command, error);
                    restart.record_failure(limits);
                    continue;
                }
            }
            if let Some(running) = process.as_mut()
                && dispatch_command(running, command, &mut pending, &lifecycle, limits)
                    .await
                    .is_err()
            {
                let error = running.stop(limits).await;
                fail_pending(&mut pending, error);
                reset_lifecycle_current(&lifecycle);
                process = None;
                restart.record_failure(limits);
            }
            continue;
        }

        let running = process.as_mut().expect("process presence was checked");
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    let _ = running.stop(limits).await;
                    break;
                };
                if let ClientCommand::Shutdown { completed } = command {
                    let error = running.stop(limits).await;
                    fail_pending(&mut pending, error);
                    if let Some(completed) = completed {
                        let _ = completed.send(());
                    }
                    break;
                }
                if let ClientCommand::Reset {
                    generation,
                    completed,
                } = command
                {
                    if lifecycle_generation(lifecycle.load(Ordering::Acquire)) != generation {
                        let _ = completed.send(());
                        continue;
                    }
                    let error = running.stop(limits).await;
                    fail_pending(&mut pending, error);
                    reset_lifecycle_current(&lifecycle);
                    process = None;
                    restart.record_failure(limits);
                    let _ = completed.send(());
                    continue;
                }
                if let ClientCommand::Healthy { generation } = command {
                    if lifecycle.load(Ordering::Acquire)
                        == lifecycle_word(generation, LIFECYCLE_INITIALIZED)
                    {
                        restart.record_success();
                    }
                    continue;
                }
                if dispatch_command(
                    running,
                    command,
                    &mut pending,
                    &lifecycle,
                    limits,
                )
                .await
                .is_err()
                {
                    let error = running.stop(limits).await;
                    fail_pending(&mut pending, error);
                    reset_lifecycle_current(&lifecycle);
                    process = None;
                    restart.record_failure(limits);
                }
            }
            message = running.stdout.read_message(limits.max_message_bytes) => {
                match message {
                    Ok(Some(message)) => {
                        if handle_server_message(
                            message,
                            running,
                            &mut pending,
                            &tool_list_changed,
                            &lifecycle,
                            limits,
                        )
                        .await
                        .is_err()
                        {
                            let error = running.stop(limits).await;
                            fail_pending(&mut pending, error);
                            reset_lifecycle_current(&lifecycle);
                            process = None;
                            restart.record_failure(limits);
                        }
                    }
                    Ok(None) | Err(_) => {
                        let error = running.stop(limits).await;
                        fail_pending(&mut pending, error);
                        reset_lifecycle_current(&lifecycle);
                        process = None;
                        restart.record_failure(limits);
                    }
                }
            }
            status = running.child.wait() => {
                while let Ok(Ok(Some(message))) = timeout(
                    Duration::from_millis(10),
                    running.stdout.read_message(limits.max_message_bytes),
                )
                .await
                {
                    if handle_server_message(
                        message,
                        running,
                        &mut pending,
                        &tool_list_changed,
                        &lifecycle,
                        limits,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                let error = running.after_exit(status.ok(), limits).await;
                fail_pending(&mut pending, error);
                reset_lifecycle_current(&lifecycle);
                process = None;
                restart.record_failure(limits);
            }
            _ = wait_for_pending_deadline(&pending) => {
                if expire_pending(&mut pending) {
                    let error = running.stop(limits).await;
                    fail_pending(&mut pending, error);
                    reset_lifecycle_current(&lifecycle);
                    process = None;
                    restart.record_failure(limits);
                }
            }
            _ = running.writer_failed.recv() => {
                let error = running.stop(limits).await;
                fail_pending(&mut pending, error);
                reset_lifecycle_current(&lifecycle);
                process = None;
                restart.record_failure(limits);
            }
        }
    }
}

async fn wait_for_pending_deadline(pending_requests: &HashMap<u64, PendingRequest>) {
    if let Some(deadline) = pending_requests
        .values()
        .map(|request| request.deadline)
        .min()
    {
        tokio::time::sleep_until(deadline).await;
    } else {
        pending::<()>().await;
    }
}

fn expire_pending(pending_requests: &mut HashMap<u64, PendingRequest>) -> bool {
    let now = Instant::now();
    let expired = pending_requests
        .iter()
        .filter_map(|(id, request)| (request.deadline <= now).then_some(*id))
        .collect::<Vec<_>>();
    let had_expired = !expired.is_empty();
    for id in expired {
        let Some(request) = pending_requests.remove(&id) else {
            continue;
        };
        let error = match request.semantics {
            RequestSemantics::Replayable => StdioTransportError::Timeout,
            RequestSemantics::AmbiguousAfterWrite => StdioTransportError::AmbiguousToolCall,
        };
        let _ = request.reply.send(Err(error));
    }
    had_expired
}

async fn dispatch_command(
    process: &mut RunningProcess,
    command: ClientCommand,
    pending: &mut HashMap<u64, PendingRequest>,
    lifecycle: &AtomicU64,
    limits: StdioTransportLimits,
) -> Result<(), StdioTransportError> {
    match command {
        ClientCommand::Request {
            id,
            payload,
            permit,
            initialization,
            generation,
            semantics,
            deadline,
            reply,
        } => {
            if initialization
                && !generation.is_some_and(|generation| {
                    lifecycle.load(Ordering::Acquire)
                        == lifecycle_word(generation, LIFECYCLE_INITIALIZING)
                })
            {
                let _ = reply.send(Err(StdioTransportError::Closed));
                return Ok(());
            }
            if Instant::now() >= deadline {
                let error = match semantics {
                    RequestSemantics::Replayable => StdioTransportError::Timeout,
                    RequestSemantics::AmbiguousAfterWrite => StdioTransportError::AmbiguousToolCall,
                };
                let _ = reply.send(Err(error));
                return Ok(());
            }
            if pending.len() >= limits.command_queue_capacity {
                let _ = reply.send(Err(StdioTransportError::TooManyInFlight));
                return Ok(());
            }
            if pending.contains_key(&id) {
                let _ = reply.send(Err(StdioTransportError::DuplicateRequestId));
                return Ok(());
            }
            pending.insert(
                id,
                PendingRequest {
                    semantics,
                    generation,
                    deadline,
                    reply,
                },
            );
            if process.write(payload, Some(permit), None).is_err() {
                return Err(StdioTransportError::Closed);
            }
        }
        ClientCommand::Notification {
            payload,
            permit,
            deadline,
            generation,
            reply,
        } => {
            if generation.is_some_and(|generation| {
                lifecycle.load(Ordering::Acquire)
                    != lifecycle_word(generation, LIFECYCLE_INITIALIZING)
            }) {
                let _ = reply.send(Err(StdioTransportError::Closed));
                return Ok(());
            }
            if Instant::now() >= deadline {
                let _ = reply.send(Err(StdioTransportError::Timeout));
            } else {
                process.write(payload, Some(permit), Some(reply))?;
            }
        }
        ClientCommand::Reset { .. }
        | ClientCommand::Healthy { .. }
        | ClientCommand::Shutdown { .. } => {
            unreachable!("lifecycle commands are handled by the actor")
        }
    }
    Ok(())
}

async fn handle_server_message(
    message: Value,
    process: &mut RunningProcess,
    pending: &mut HashMap<u64, PendingRequest>,
    tool_list_changed: &broadcast::Sender<()>,
    lifecycle: &AtomicU64,
    limits: StdioTransportLimits,
) -> Result<(), StdioTransportError> {
    let object = message
        .as_object()
        .ok_or(StdioTransportError::InvalidResponse)?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(StdioTransportError::InvalidResponse);
    }
    if object.contains_key("method") {
        if let Some(id) = object.get("id") {
            let response = if object.get("method").and_then(Value::as_str) == Some("ping") {
                json!({ "jsonrpc": "2.0", "id": id, "result": {} })
            } else {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": "Method not found" }
                })
            };
            let payload = encode_message(&response, limits.max_message_bytes)?;
            process.write(payload, None, None)?;
        } else if object.get("method").and_then(Value::as_str)
            == Some("notifications/tools/list_changed")
        {
            let _ = tool_list_changed.send(());
        }
        return Ok(());
    }

    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .ok_or(StdioTransportError::InvalidResponse)?;
    let request = pending
        .remove(&id)
        .ok_or(StdioTransportError::UnexpectedResponseId)?;
    if request.generation.is_some_and(|generation| {
        lifecycle.load(Ordering::Acquire) != lifecycle_word(generation, LIFECYCLE_INITIALIZING)
    }) {
        let _ = request.reply.send(Err(StdioTransportError::Closed));
        return Ok(());
    }
    let response = match (object.get("result"), object.get("error")) {
        (Some(result), None) => Ok(result.clone()),
        (None, Some(Value::Object(error))) => match (
            error.get("code").and_then(Value::as_i64),
            error.get("message").and_then(Value::as_str),
        ) {
            (Some(code), Some(_)) => Err(StdioTransportError::JsonRpc { code }),
            _ => Err(StdioTransportError::InvalidResponse),
        },
        _ => Err(StdioTransportError::InvalidResponse),
    };
    let _ = request.reply.send(response);
    Ok(())
}

fn reject_command(command: ClientCommand, error: StdioTransportError) {
    match command {
        ClientCommand::Request { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        ClientCommand::Notification { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        ClientCommand::Reset { completed, .. } => {
            let _ = completed.send(());
        }
        ClientCommand::Healthy { .. } => {}
        ClientCommand::Shutdown { completed } => {
            if let Some(completed) = completed {
                let _ = completed.send(());
            }
        }
    }
}

fn command_reply_closed(command: &ClientCommand) -> bool {
    match command {
        ClientCommand::Request { reply, .. } => reply.is_closed(),
        ClientCommand::Notification { reply, .. } => reply.is_closed(),
        ClientCommand::Reset { completed, .. } => completed.is_closed(),
        ClientCommand::Healthy { .. } => false,
        ClientCommand::Shutdown { completed } => {
            completed.as_ref().is_some_and(oneshot::Sender::is_closed)
        }
    }
}

fn fail_pending(pending: &mut HashMap<u64, PendingRequest>, failure: ProcessFailure) {
    for (_, request) in pending.drain() {
        let error = match request.semantics {
            RequestSemantics::Replayable => StdioTransportError::ProcessExited {
                code: failure.code,
                stderr_truncated: failure.stderr_truncated,
            },
            RequestSemantics::AmbiguousAfterWrite => StdioTransportError::AmbiguousToolCall,
        };
        let _ = request.reply.send(Err(error));
    }
}

#[derive(Default)]
struct RestartState {
    consecutive_failures: u32,
    retry_at: Option<Instant>,
}

impl RestartState {
    fn record_failure(&mut self, limits: StdioTransportLimits) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let shift = self.consecutive_failures.saturating_sub(1).min(31);
        let multiplier = 1_u32 << shift;
        let delay = limits
            .initial_restart_backoff
            .saturating_mul(multiplier)
            .min(limits.max_restart_backoff);
        self.retry_at = Instant::now().checked_add(delay);
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.retry_at = None;
    }
}

struct RunningProcess {
    child: Child,
    writer: Option<mpsc::Sender<WriteFrame>>,
    writer_task: JoinHandle<()>,
    writer_failed: mpsc::Receiver<()>,
    stdout: BoundedMessageReader<ChildStdout>,
    stderr: JoinHandle<StderrSummary>,
    process_group: i32,
}

impl RunningProcess {
    async fn spawn(
        template: &TrustedStdioTemplate,
        limits: StdioTransportLimits,
    ) -> Result<Self, StdioTransportError> {
        for name in &template.secret_environment {
            let value = template
                .environment
                .get(name)
                .ok_or(StdioTemplateError::InvalidSecretOverlay)?;
            if value.is_empty()
                || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
                || value.as_bytes().contains(&0)
            {
                return Err(StdioTemplateError::InvalidSecretOverlay.into());
            }
        }
        verify_executable(template)?;
        verify_cwd(template)?;
        let mut command = Command::new(&template.executable);
        command
            .args(&template.arguments)
            .env_clear()
            .envs(&template.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(cwd) = &template.cwd {
            command.current_dir(cwd);
        }
        configure_process_group(&mut command);
        let mut child = command.spawn().map_err(|_| StdioTransportError::Spawn)?;
        let process_group = child.id().ok_or(StdioTransportError::Spawn)? as i32;
        let stdin = child.stdin.take().ok_or(StdioTransportError::Spawn)?;
        let stdout = child.stdout.take().ok_or(StdioTransportError::Spawn)?;
        let stderr = child.stderr.take().ok_or(StdioTransportError::Spawn)?;
        let stderr = tokio::spawn(drain_stderr(stderr, limits.max_stderr_bytes));
        let (writer, writes) = mpsc::channel(limits.command_queue_capacity);
        let (writer_failure, writer_failed) = mpsc::channel(1);
        let writer_task = tokio::spawn(write_frames(stdin, writes, writer_failure));
        Ok(Self {
            child,
            writer: Some(writer),
            writer_task,
            writer_failed,
            stdout: BoundedMessageReader::new(stdout),
            stderr,
            process_group,
        })
    }

    fn write(
        &mut self,
        payload: Vec<u8>,
        permit: Option<OwnedSemaphorePermit>,
        completion: Option<oneshot::Sender<Result<(), StdioTransportError>>>,
    ) -> Result<(), StdioTransportError> {
        let frame = WriteFrame {
            payload,
            _permit: permit,
            completion,
        };
        match self
            .writer
            .as_ref()
            .ok_or(StdioTransportError::Closed)?
            .try_send(frame)
        {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut frame = error.into_inner();
                if let Some(completion) = frame.completion.take() {
                    let _ = completion.send(Err(StdioTransportError::Closed));
                }
                Err(StdioTransportError::TooManyInFlight)
            }
        }
    }

    async fn stop(&mut self, limits: StdioTransportLimits) -> ProcessFailure {
        signal_process_group(self.process_group, libc::SIGTERM);
        let status = match timeout(limits.shutdown_grace, self.child.wait()).await {
            Ok(Ok(status)) => Some(status),
            _ => {
                signal_process_group(self.process_group, libc::SIGKILL);
                let _ = self.child.start_kill();
                self.child.wait().await.ok()
            }
        };
        let summary = self.finish_background(limits).await;
        ProcessFailure {
            code: status.as_ref().and_then(ExitStatus::code),
            stderr_truncated: summary.truncated,
        }
    }

    async fn after_exit(
        &mut self,
        status: Option<ExitStatus>,
        limits: StdioTransportLimits,
    ) -> ProcessFailure {
        signal_process_group(self.process_group, libc::SIGTERM);
        let summary = self.finish_background(limits).await;
        ProcessFailure {
            code: status.as_ref().and_then(ExitStatus::code),
            stderr_truncated: summary.truncated,
        }
    }

    async fn finish_background(&mut self, limits: StdioTransportLimits) -> StderrSummary {
        self.writer.take();
        let summary = match timeout(limits.shutdown_grace, &mut self.stderr).await {
            Ok(summary) => summary.unwrap_or_default(),
            Err(_) => {
                signal_process_group(self.process_group, libc::SIGKILL);
                match timeout(limits.shutdown_grace, &mut self.stderr).await {
                    Ok(summary) => summary.unwrap_or_default(),
                    Err(_) => {
                        self.stderr.abort();
                        StderrSummary { truncated: true }
                    }
                }
            }
        };
        if timeout(limits.shutdown_grace, &mut self.writer_task)
            .await
            .is_err()
        {
            self.writer_task.abort();
        }
        if process_group_exists(self.process_group) {
            signal_process_group(self.process_group, libc::SIGKILL);
        }
        summary
    }
}

struct WriteFrame {
    payload: Vec<u8>,
    _permit: Option<OwnedSemaphorePermit>,
    completion: Option<oneshot::Sender<Result<(), StdioTransportError>>>,
}

async fn write_frames<W>(
    mut stdin: W,
    mut frames: mpsc::Receiver<WriteFrame>,
    failure: mpsc::Sender<()>,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = frames.recv().await {
        let mut frame = frame;
        let result = async {
            stdin.write_all(&frame.payload).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await
        }
        .await;
        if let Some(completion) = frame.completion.take() {
            let _ = completion.send(if result.is_ok() {
                Ok(())
            } else {
                Err(StdioTransportError::Closed)
            });
        }
        if result.is_err() {
            let _ = failure.try_send(());
            break;
        }
    }
    let _ = stdin.shutdown().await;
}

#[derive(Clone, Copy)]
struct ProcessFailure {
    code: Option<i32>,
    stderr_truncated: bool,
}

struct BoundedMessageReader<R> {
    reader: BufReader<R>,
}

impl<R> BoundedMessageReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(reader: R) -> Self {
        Self {
            reader: BufReader::with_capacity(8 * 1024, reader),
        }
    }

    async fn read_message(
        &mut self,
        max_bytes: usize,
    ) -> Result<Option<Value>, StdioTransportError> {
        let mut bytes = Vec::new();
        loop {
            let available = self
                .reader
                .fill_buf()
                .await
                .map_err(|_| StdioTransportError::Closed)?;
            if available.is_empty() {
                if bytes.is_empty() {
                    return Ok(None);
                }
                return Err(StdioTransportError::InvalidResponse);
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let consumed = newline.map_or(available.len(), |index| index + 1);
            let content = newline.map_or(available, |index| &available[..index]);
            if bytes.len().saturating_add(content.len()) > max_bytes {
                return Err(StdioTransportError::ResponseTooLarge);
            }
            bytes.extend_from_slice(content);
            self.reader.consume(consumed);
            if newline.is_some() {
                if bytes.last() == Some(&b'\r') {
                    bytes.pop();
                }
                if bytes.is_empty() {
                    return Err(StdioTransportError::InvalidResponse);
                }
                return serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|_| StdioTransportError::InvalidResponse);
            }
        }
    }
}

#[derive(Default)]
struct StderrSummary {
    truncated: bool,
}

async fn drain_stderr<R>(mut stderr: R, max_bytes: usize) -> StderrSummary
where
    R: AsyncRead + Unpin,
{
    let mut retained = 0_usize;
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if retained.saturating_add(read) > max_bytes {
                    truncated = true;
                }
                retained = retained.saturating_add(read).min(max_bytes);
            }
        }
    }
    StderrSummary { truncated }
}

fn encode_message(value: &Value, max_bytes: usize) -> Result<Vec<u8>, StdioTransportError> {
    let payload = serde_json::to_vec(value).map_err(|_| StdioTransportError::Encode)?;
    if payload.len() > max_bytes {
        return Err(StdioTransportError::RequestTooLarge);
    }
    Ok(payload)
}

fn validate_template_name(name: &str) -> Result<(), StdioTemplateError> {
    if name.is_empty()
        || name.len() > MAX_TEMPLATE_NAME_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StdioTemplateError::InvalidName);
    }
    Ok(())
}

fn validate_arguments(arguments: &[String]) -> Result<(), StdioTemplateError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(StdioTemplateError::TooManyArguments);
    }
    let mut total = 0_usize;
    for argument in arguments {
        if argument.len() > MAX_ARGUMENT_BYTES || argument.as_bytes().contains(&0) {
            return Err(StdioTemplateError::ArgumentTooLarge);
        }
        total = total
            .checked_add(argument.len())
            .ok_or(StdioTemplateError::TemplateTooLarge)?;
    }
    if total > MAX_TEMPLATE_BYTES {
        return Err(StdioTemplateError::TemplateTooLarge);
    }
    Ok(())
}

fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), StdioTemplateError> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(StdioTemplateError::TooManyEnvironmentEntries);
    }
    let mut total = 0_usize;
    for (name, value) in environment {
        if !valid_environment_name(name)
            || value.as_bytes().contains(&0)
            || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
        {
            return Err(StdioTemplateError::InvalidEnvironmentEntry);
        }
        total = total
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(StdioTemplateError::TemplateTooLarge)?;
    }
    if total > MAX_TEMPLATE_BYTES {
        return Err(StdioTemplateError::TemplateTooLarge);
    }
    Ok(())
}

fn validate_secret_environment(
    secret_environment: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<(), StdioTemplateError> {
    if secret_environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(StdioTemplateError::TooManyEnvironmentEntries);
    }
    let mut previous: Option<&str> = None;
    let mut names = secret_environment
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    names.sort_unstable();
    for name in names {
        if !valid_environment_name(name) || environment.contains_key(name) || previous == Some(name)
        {
            return Err(StdioTemplateError::InvalidSecretFields);
        }
        previous = Some(name);
    }
    Ok(())
}

fn validate_secret_overlay(
    approved: &[String],
    secrets: &BTreeMap<String, String>,
) -> Result<(), StdioTemplateError> {
    if approved.len() != secrets.len() {
        return Err(StdioTemplateError::InvalidSecretOverlay);
    }
    for name in approved {
        let Some(value) = secrets.get(name) else {
            return Err(StdioTemplateError::InvalidSecretOverlay);
        };
        if value.is_empty()
            || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            || value.as_bytes().contains(&0)
        {
            return Err(StdioTemplateError::InvalidSecretOverlay);
        }
    }
    if secrets.keys().any(|name| !approved.contains(name)) {
        return Err(StdioTemplateError::InvalidSecretOverlay);
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn verify_executable(template: &TrustedStdioTemplate) -> Result<(), StdioTransportError> {
    let canonical =
        std::fs::canonicalize(&template.executable).map_err(|_| StdioTransportError::Spawn)?;
    if canonical != template.executable {
        return Err(StdioTransportError::Spawn);
    }
    let metadata = std::fs::metadata(&canonical).map_err(|_| StdioTransportError::Spawn)?;
    if !metadata.is_file() {
        return Err(StdioTransportError::Spawn);
    }
    validate_executable_permissions(&metadata).map_err(StdioTransportError::Template)
}

fn verify_cwd(template: &TrustedStdioTemplate) -> Result<(), StdioTransportError> {
    let Some(cwd) = &template.cwd else {
        return Ok(());
    };
    let canonical = std::fs::canonicalize(cwd).map_err(|_| StdioTransportError::Spawn)?;
    if &canonical != cwd
        || !std::fs::metadata(&canonical)
            .map_err(|_| StdioTransportError::Spawn)?
            .is_dir()
    {
        return Err(StdioTransportError::Spawn);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_executable_permissions(metadata: &std::fs::Metadata) -> Result<(), StdioTemplateError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(StdioTemplateError::ExecutableNotExecutable);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_executable_permissions(_: &std::fs::Metadata) -> Result<(), StdioTemplateError> {
    Ok(())
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_process_group(_: &mut Command) {}

#[cfg(unix)]
fn signal_process_group(process_group: i32, signal: i32) {
    if process_group > 0 {
        unsafe {
            libc::kill(-process_group, signal);
        }
    }
}

#[cfg(unix)]
fn process_group_exists(process_group: i32) -> bool {
    process_group > 0 && unsafe { libc::kill(-process_group, 0) == 0 }
}

#[cfg(not(unix))]
fn signal_process_group(_: i32, _: i32) {}

#[cfg(not(unix))]
fn process_group_exists(_: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;
    use tokio::time::{Duration, Instant};

    use super::*;

    fn script(directory: &TempDir, name: &str, contents: &str) -> PathBuf {
        let path = directory.path().join(name);
        std::fs::write(&path, contents).expect("script writes");
        let mut permissions = std::fs::metadata(&path)
            .expect("script metadata exists")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).expect("script becomes executable");
        path
    }

    fn template(path: PathBuf) -> TrustedStdioTemplate {
        TrustedStdioTemplate::validate(StdioTemplate {
            name: "fixture".to_owned(),
            executable: path,
            cwd: None,
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            secret_environment: Vec::new(),
        })
        .expect("fixture template validates")
    }

    async fn initialize_client(client: &StdioClient) {
        client
            .initialize(
                DEFAULT_PROTOCOL_VERSION,
                json!({ "name": "executor", "version": "1" }),
                json!({}),
            )
            .await
            .expect("initialization succeeds");
    }

    #[test]
    fn templates_require_named_absolute_executables_and_reject_duplicates() {
        let error = TrustedStdioTemplate::validate(StdioTemplate {
            name: "bad name".to_owned(),
            executable: PathBuf::from("relative-command"),
            cwd: None,
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            secret_environment: Vec::new(),
        })
        .expect_err("invalid name is rejected first");
        assert!(matches!(error, StdioTemplateError::InvalidName));

        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(&directory, "server", "#!/bin/sh\nexit 0\n");
        let config = StdioTemplate {
            name: "fixture".to_owned(),
            executable,
            cwd: None,
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            secret_environment: Vec::new(),
        };
        let error = StdioTemplateRegistry::new(vec![config.clone(), config])
            .expect_err("duplicate names are rejected");
        assert!(matches!(error, StdioTemplateError::DuplicateName));
    }

    #[test]
    fn loads_a_bounded_strict_configuration_file() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(&directory, "server", "#!/bin/sh\nexit 0\n");
        let config_path = directory.path().join("stdio.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&json!({
                "templates": [{
                    "name": "fixture",
                    "executable": executable,
                    "secretEnvironment": ["API_TOKEN"]
                }]
            }))
            .expect("configuration encodes"),
        )
        .expect("configuration writes");
        let registry = StdioTemplateRegistry::load(&config_path).expect("configuration loads");
        assert_eq!(registry.descriptors()[0].name, "fixture");

        std::fs::write(&config_path, br#"{"templates":[],"unexpected":true}"#)
            .expect("invalid configuration writes");
        assert!(matches!(
            StdioTemplateRegistry::load(&config_path),
            Err(StdioTemplateError::ConfigInvalid)
        ));

        std::fs::write(&config_path, vec![b' '; MAX_CONFIG_FILE_BYTES as usize + 1])
            .expect("oversized configuration writes");
        assert!(matches!(
            StdioTemplateRegistry::load(&config_path),
            Err(StdioTemplateError::ConfigTooLarge)
        ));
    }

    #[tokio::test]
    async fn initializes_lists_and_calls_with_clean_environment() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(
            &directory,
            "server",
            r#"#!/bin/sh
if [ -n "${HOME+x}" ]; then exit 9; fi
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}' '{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}' ;;
    *'"method":"tools/list"'*) printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}' ;;
    *'"method":"tools/call"'*) printf '%s\n' '{"jsonrpc":"2.0","id":77,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}' ;;
  esac
done
"#,
        );
        let client = StdioClient::connect(template(executable), StdioTransportLimits::default())
            .await
            .expect("client connects");
        let mut list_changed = client.subscribe_tool_list_changed();
        let initialized = client
            .initialize(
                DEFAULT_PROTOCOL_VERSION,
                json!({ "name": "executor", "version": "1" }),
                json!({}),
            )
            .await
            .expect("initialization succeeds");
        assert_eq!(initialized.protocol_version, DEFAULT_PROTOCOL_VERSION);
        timeout(Duration::from_secs(1), list_changed.recv())
            .await
            .expect("list changed notification arrives")
            .expect("list changed channel remains open");
        let tools = client
            .list_tools(None)
            .await
            .expect("tool listing succeeds");
        assert_eq!(tools.tools[0].name, "echo");
        let result = client
            .call_tool("echo", json!({ "value": "hi" }), 77)
            .await
            .expect("tool call succeeds");
        assert!(!result.is_error);
        client.shutdown().await;
    }

    #[tokio::test]
    async fn answers_server_ping_requests_with_an_empty_result() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(
            &directory,
            "ping-server",
            r#"#!/bin/sh
read line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'
read line
printf '%s\n' '{"jsonrpc":"2.0","id":"server-ping","method":"ping"}'
read first
read second
wire="$first$second"
case "$wire" in
  *'"id":"server-ping"'*'"result":{}'*'"method":"tools/list"'* | *'"method":"tools/list"'*'"id":"server-ping"'*'"result":{}'*) ;;
  *) exit 9 ;;
esac
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'
while IFS= read -r line; do :; done
"#,
        );
        let client = StdioClient::connect(template(executable), StdioTransportLimits::default())
            .await
            .expect("client connects");
        initialize_client(&client).await;

        let tools = client
            .list_tools(None)
            .await
            .expect("list succeeds after the server ping");
        assert!(tools.tools.is_empty());
        client.shutdown().await;
    }

    #[tokio::test]
    async fn call_tool_requires_object_structured_content() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(
            &directory,
            "structured-content-server",
            r#"#!/bin/sh
read line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'
read line
read line
printf '%s\n' '{"jsonrpc":"2.0","id":10,"result":{"content":[],"structuredContent":{"status":"ok"},"isError":false}}'
read line
printf '%s\n' '{"jsonrpc":"2.0","id":11,"result":{"content":[],"structuredContent":"not-an-object"}}'
read line
printf '%s\n' '{"jsonrpc":"2.0","id":12,"result":{"content":[],"structuredContent":[]}}'
read line
printf '%s\n' '{"jsonrpc":"2.0","id":13,"result":{"content":[],"structuredContent":null}}'
while IFS= read -r line; do :; done
"#,
        );
        let client = StdioClient::connect(template(executable), StdioTransportLimits::default())
            .await
            .expect("client connects");
        initialize_client(&client).await;

        let valid = client
            .call_tool("valid", json!({}), 10)
            .await
            .expect("object structured content is valid");
        assert_eq!(valid.structured_content, Some(json!({ "status": "ok" })));
        assert!(!valid.is_error);
        for request_id in 11..=13 {
            assert!(matches!(
                client.call_tool("invalid", json!({}), request_id).await,
                Err(StdioTransportError::Decode)
            ));
        }
        client.shutdown().await;
    }

    #[tokio::test]
    async fn registry_exposes_only_secret_descriptors_and_requires_exact_overlay() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(
            &directory,
            "secret-server",
            r#"#!/bin/sh
if [ "$API_TOKEN" != "preserve surrounding spaces" ]; then exit 8; fi
read line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'
read line
read line
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}'
"#,
        );
        let registry = StdioTemplateRegistry::new(vec![StdioTemplate {
            name: "secret-fixture".to_owned(),
            executable,
            cwd: None,
            arguments: vec!["--trusted-argument".to_owned()],
            environment: BTreeMap::new(),
            secret_environment: vec!["API_TOKEN".to_owned()],
        }])
        .expect("registry validates");
        assert_eq!(
            registry.descriptors(),
            vec![StdioTemplateDescriptor {
                name: "secret-fixture".to_owned(),
                secret_fields: vec!["API_TOKEN".to_owned()],
            }]
        );
        let error = match registry
            .connect_with_secrets(
                "secret-fixture",
                &BTreeMap::new(),
                StdioTransportLimits::default(),
            )
            .await
        {
            Ok(client) => {
                client.shutdown().await;
                panic!("required secrets cannot be omitted");
            }
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StdioTransportError::Template(StdioTemplateError::InvalidSecretOverlay)
        ));

        let secrets = BTreeMap::from([(
            "API_TOKEN".to_owned(),
            "preserve surrounding spaces".to_owned(),
        )]);
        let client = registry
            .connect_with_secrets("secret-fixture", &secrets, StdioTransportLimits::default())
            .await
            .expect("approved secret overlay connects");
        initialize_client(&client).await;
        assert!(client.list_tools(None).await.is_ok());
        client.shutdown().await;
    }

    #[tokio::test]
    async fn child_runs_in_the_exact_canonical_working_directory() {
        let directory = TempDir::new().expect("temporary directory creates");
        let working_directory = directory.path().join("working");
        std::fs::create_dir(&working_directory).expect("working directory creates");
        let output = directory.path().join("cwd.txt");
        let executable = script(
            &directory,
            "cwd-server",
            r#"#!/bin/sh
pwd > "$OUTPUT"
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}' ;;
  esac
done
"#,
        );
        let registry = StdioTemplateRegistry::new(vec![StdioTemplate {
            name: "cwd-fixture".to_owned(),
            executable,
            cwd: Some(working_directory.clone()),
            arguments: Vec::new(),
            environment: BTreeMap::from([(
                "OUTPUT".to_owned(),
                output.to_string_lossy().into_owned(),
            )]),
            secret_environment: Vec::new(),
        }])
        .expect("working directory template validates");
        let client = registry
            .connect_with_secrets(
                "cwd-fixture",
                &BTreeMap::new(),
                StdioTransportLimits::default(),
            )
            .await
            .expect("client connects");
        initialize_client(&client).await;
        assert_eq!(
            std::fs::read_to_string(output)
                .expect("working directory capture exists")
                .trim(),
            std::fs::canonicalize(working_directory)
                .expect("working directory canonicalizes")
                .to_string_lossy()
        );
        client.shutdown().await;
    }

    #[tokio::test]
    async fn oversized_stdout_is_rejected_without_unbounded_buffering() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(
            &directory,
            "server",
            "#!/bin/sh\nread line\ni=0; while [ $i -lt 2048 ]; do printf x; i=$((i+1)); done; printf '\\n'\n",
        );
        let limits = StdioTransportLimits {
            max_message_bytes: 512,
            ..StdioTransportLimits::default()
        };
        let client = StdioClient::connect(template(executable), limits)
            .await
            .expect("client connects");
        let error = client
            .initialize(
                DEFAULT_PROTOCOL_VERSION,
                json!({ "name": "executor", "version": "1" }),
                json!({}),
            )
            .await
            .expect_err("oversized response is rejected");
        assert!(matches!(error, StdioTransportError::ProcessExited { .. }));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn disconnected_tool_calls_are_never_retried() {
        let directory = TempDir::new().expect("temporary directory creates");
        let counter = directory.path().join("counter");
        let executable = script(
            &directory,
            "server",
            &format!(
                "#!/bin/sh\nread line\nprintf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}}}}}}'\nread line\nread line\nprintf x >> '{}'\nexit 1\n",
                counter.display()
            ),
        );
        let client = StdioClient::connect(template(executable), StdioTransportLimits::default())
            .await
            .expect("client connects");
        initialize_client(&client).await;
        let error = client
            .call_tool("mutate", json!({}), 41)
            .await
            .expect_err("disconnected call has an ambiguous result");
        assert!(matches!(error, StdioTransportError::AmbiguousToolCall));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(std::fs::read(&counter).expect("counter exists"), b"x");
        client.shutdown().await;
    }

    #[tokio::test]
    async fn initialized_state_clears_when_an_idle_child_exits() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(
            &directory,
            "server",
            "#!/bin/sh\nread line\nprintf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{}}}'\nread line\nexit 0\n",
        );
        let client = StdioClient::connect(template(executable), StdioTransportLimits::default())
            .await
            .expect("client connects");
        initialize_client(&client).await;
        assert!(client.is_initialized());
        timeout(Duration::from_secs(1), async {
            while client.is_initialized() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle child exit clears initialized state");
        client.shutdown().await;
    }

    #[tokio::test]
    async fn restart_attempts_observe_exponential_backoff() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(&directory, "server", "#!/bin/sh\nexit 1\n");
        let limits = StdioTransportLimits {
            initial_restart_backoff: Duration::from_millis(120),
            max_restart_backoff: Duration::from_millis(120),
            ..StdioTransportLimits::default()
        };
        let client = StdioClient::connect(template(executable), limits)
            .await
            .expect("initial spawn succeeds");
        let _ = client
            .initialize(
                DEFAULT_PROTOCOL_VERSION,
                json!({ "name": "executor", "version": "1" }),
                json!({}),
            )
            .await;
        let started = Instant::now();
        let _ = client
            .initialize(
                DEFAULT_PROTOCOL_VERSION,
                json!({ "name": "executor", "version": "1" }),
                json!({}),
            )
            .await;
        assert!(started.elapsed() >= Duration::from_millis(100));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn timed_out_requests_are_removed_and_force_reinitialization() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(
            &directory,
            "timeout-server",
            r#"#!/bin/sh
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}' ;;
  esac
done
"#,
        );
        let limits = StdioTransportLimits {
            request_timeout: Duration::from_millis(150),
            shutdown_grace: Duration::from_millis(30),
            initial_restart_backoff: Duration::from_millis(10),
            max_restart_backoff: Duration::from_millis(20),
            ..StdioTransportLimits::default()
        };
        let client = StdioClient::connect(template(executable), limits)
            .await
            .expect("client connects");
        initialize_client(&client).await;
        let started = Instant::now();
        let error = client
            .list_tools(None)
            .await
            .expect_err("unanswered request times out");
        assert!(matches!(error, StdioTransportError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(1));
        timeout(Duration::from_secs(1), async {
            while lifecycle_state(client.lifecycle.load(Ordering::Acquire))
                != LIFECYCLE_UNINITIALIZED
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("timed out request teardown completes");
        assert!(matches!(
            client.list_tools(None).await,
            Err(StdioTransportError::NotInitialized)
        ));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn stdout_is_drained_while_large_concurrent_requests_are_written() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(
            &directory,
            "duplex-server",
            r#"#!/bin/sh
read line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'
read line
i=0
while [ $i -lt 1400 ]; do
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}'
  i=$((i+1))
done
i=2
while IFS= read -r line; do
  printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[]}}\n' "$i"
  i=$((i+1))
done
"#,
        );
        let client = std::sync::Arc::new(
            StdioClient::connect(template(executable), StdioTransportLimits::default())
                .await
                .expect("client connects"),
        );
        initialize_client(&client).await;
        let mut calls = tokio::task::JoinSet::new();
        for _ in 0..64 {
            let client = client.clone();
            calls.spawn(async move {
                client
                    .list_tools(Some(&"x".repeat(4 * 1024)))
                    .await
                    .expect("concurrent list succeeds")
            });
        }
        timeout(Duration::from_secs(5), async {
            while let Some(result) = calls.join_next().await {
                result.expect("list task completes");
            }
        })
        .await
        .expect("full-duplex traffic does not deadlock");
        std::sync::Arc::try_unwrap(client)
            .ok()
            .expect("all task client references are dropped")
            .shutdown()
            .await;
    }

    #[tokio::test]
    async fn shutdown_kills_the_process_group_even_when_descendants_ignore_term() {
        let directory = TempDir::new().expect("temporary directory creates");
        let descendant_pid = directory.path().join("descendant.pid");
        let executable = script(
            &directory,
            "process-group-server",
            r#"#!/bin/sh
trap '' TERM
(trap '' TERM; while :; do /bin/sleep 1; done) &
printf '%s' "$!" > "$PID_FILE"
while IFS= read -r line; do
  case "$line" in
    *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}' ;;
  esac
done
"#,
        );
        let mut trusted = template(executable);
        trusted.environment.insert(
            "PID_FILE".to_owned(),
            descendant_pid.to_string_lossy().into_owned(),
        );
        let limits = StdioTransportLimits {
            shutdown_grace: Duration::from_millis(40),
            initial_restart_backoff: Duration::from_millis(10),
            max_restart_backoff: Duration::from_millis(20),
            ..StdioTransportLimits::default()
        };
        let client = StdioClient::connect(trusted, limits)
            .await
            .expect("client connects");
        initialize_client(&client).await;
        let pid = std::fs::read_to_string(&descendant_pid)
            .expect("descendant PID is captured")
            .parse::<i32>()
            .expect("descendant PID is numeric");
        let started = Instant::now();
        client.shutdown().await;
        assert!(started.elapsed() < Duration::from_secs(1));
        for _ in 0..200 {
            if unsafe { libc::kill(pid, 0) } == -1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("descendant process remained alive after process-group shutdown");
    }

    #[tokio::test]
    async fn failed_initialize_response_restarts_before_retry() {
        let directory = TempDir::new().expect("temporary directory creates");
        let marker = directory.path().join("started");
        let executable = script(
            &directory,
            "initialize-retry-server",
            r#"#!/bin/sh
read line
if [ -f "$MARKER" ]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'
else
  printf x > "$MARKER"
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}'
fi
while IFS= read -r line; do :; done
"#,
        );
        let mut trusted = template(executable);
        trusted
            .environment
            .insert("MARKER".to_owned(), marker.to_string_lossy().into_owned());
        let client = StdioClient::connect(trusted, StdioTransportLimits::default())
            .await
            .expect("client connects");
        let error = client
            .initialize(
                DEFAULT_PROTOCOL_VERSION,
                json!({ "name": "executor", "version": "1" }),
                json!({}),
            )
            .await
            .expect_err("mismatched protocol version is rejected");
        assert!(matches!(
            error,
            StdioTransportError::ProtocolVersionMismatch
        ));
        initialize_client(&client).await;
        client.shutdown().await;
    }

    #[tokio::test]
    async fn initialize_waits_for_initialized_notification_flush() {
        let (writer, mut reader) = tokio::io::duplex(1);
        let (frames, queued) = mpsc::channel(1);
        let (failure, _) = mpsc::channel(1);
        let writer_task = tokio::spawn(write_frames(writer, queued, failure));
        let (completed, mut completion) = oneshot::channel();
        frames
            .send(WriteFrame {
                payload: b"initialized".to_vec(),
                _permit: None,
                completion: Some(completed),
            })
            .await
            .expect("notification frame queues");

        assert!(
            timeout(Duration::from_millis(30), &mut completion)
                .await
                .is_err(),
            "notification must not report success while its write is blocked"
        );
        let mut wire = vec![0_u8; b"initialized\n".len()];
        reader
            .read_exact(&mut wire)
            .await
            .expect("notification is drained from the wire");
        completion
            .await
            .expect("writer reports notification completion")
            .expect("write and flush succeed");
        assert_eq!(wire, b"initialized\n");
        drop(frames);
        writer_task.await.expect("writer task exits cleanly");
    }

    #[tokio::test]
    async fn shutdown_interrupts_restart_backoff() {
        let directory = TempDir::new().expect("temporary directory creates");
        let executable = script(&directory, "crash-server", "#!/bin/sh\nexit 1\n");
        let limits = StdioTransportLimits {
            request_timeout: Duration::from_secs(5),
            initial_restart_backoff: Duration::from_secs(2),
            max_restart_backoff: Duration::from_secs(2),
            ..StdioTransportLimits::default()
        };
        let client = std::sync::Arc::new(
            StdioClient::connect(template(executable), limits)
                .await
                .expect("initial spawn succeeds"),
        );
        let _ = client
            .initialize(
                DEFAULT_PROTOCOL_VERSION,
                json!({ "name": "executor", "version": "1" }),
                json!({}),
            )
            .await;
        let retry_client = client.clone();
        let retry = tokio::spawn(async move {
            retry_client
                .initialize(
                    DEFAULT_PROTOCOL_VERSION,
                    json!({ "name": "executor", "version": "1" }),
                    json!({}),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (completed, completion) = oneshot::channel();
        let started = Instant::now();
        client
            .commands
            .send(ClientCommand::Shutdown {
                completed: Some(completed),
            })
            .await
            .expect("shutdown queues");
        timeout(Duration::from_millis(500), completion)
            .await
            .expect("shutdown interrupts backoff")
            .expect("actor acknowledges shutdown");
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(retry.await.expect("retry task completes").is_err());
    }

    #[tokio::test]
    async fn canceling_initialize_resets_before_retry() {
        let directory = TempDir::new().expect("temporary directory creates");
        let marker = directory.path().join("first-start");
        let executable = script(
            &directory,
            "cancel-initialize-server",
            r#"#!/bin/sh
read line
if [ -f "$MARKER" ]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'
else
  printf x > "$MARKER"
fi
while IFS= read -r line; do :; done
"#,
        );
        let mut trusted = template(executable);
        trusted
            .environment
            .insert("MARKER".to_owned(), marker.to_string_lossy().into_owned());
        let limits = StdioTransportLimits {
            request_timeout: Duration::from_secs(2),
            shutdown_grace: Duration::from_millis(40),
            initial_restart_backoff: Duration::from_millis(10),
            max_restart_backoff: Duration::from_millis(20),
            ..StdioTransportLimits::default()
        };
        let client = std::sync::Arc::new(
            StdioClient::connect(trusted, limits)
                .await
                .expect("client connects"),
        );
        let initializing_client = client.clone();
        let initializing = tokio::spawn(async move {
            initializing_client
                .initialize(
                    DEFAULT_PROTOCOL_VERSION,
                    json!({ "name": "executor", "version": "1" }),
                    json!({}),
                )
                .await
        });
        timeout(Duration::from_secs(1), async {
            while !marker.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("first initialization reaches child");
        initializing.abort();
        let _ = initializing.await;
        timeout(Duration::from_secs(1), async {
            while lifecycle_state(client.lifecycle.load(Ordering::Acquire))
                != LIFECYCLE_UNINITIALIZED
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("canceled initialization cleanup completes");
        initialize_client(&client).await;
        std::sync::Arc::try_unwrap(client)
            .ok()
            .expect("initialization task released its client")
            .shutdown()
            .await;
    }

    #[tokio::test]
    async fn stale_lifecycle_commands_cannot_mutate_a_new_generation() {
        let directory = TempDir::new().expect("temporary directory creates");
        let marker = directory.path().join("first-generation");
        let executable = script(
            &directory,
            "generation-server",
            r#"#!/bin/sh
read line
if [ -f "$MARKER" ]; then
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'
  read line
  read line
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}'
else
  printf x > "$MARKER"
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}'
fi
while IFS= read -r line; do :; done
"#,
        );
        let mut trusted = template(executable);
        trusted
            .environment
            .insert("MARKER".to_owned(), marker.to_string_lossy().into_owned());
        let client = StdioClient::connect(trusted, StdioTransportLimits::default())
            .await
            .expect("client connects");
        initialize_client(&client).await;
        let first_generation = lifecycle_generation(client.lifecycle.load(Ordering::Acquire));
        client.reset_transport(first_generation).await;
        initialize_client(&client).await;

        let (completed, completion) = oneshot::channel();
        client
            .commands
            .send(ClientCommand::Reset {
                generation: first_generation,
                completed,
            })
            .await
            .expect("stale reset queues");
        completion.await.expect("stale reset is acknowledged");
        assert_eq!(
            lifecycle_state(client.lifecycle.load(Ordering::Acquire)),
            LIFECYCLE_INITIALIZED
        );
        assert!(matches!(
            client
                .notify(
                    "notifications/initialized",
                    json!({}),
                    Some(first_generation),
                )
                .await,
            Err(StdioTransportError::Closed)
        ));
        assert_eq!(
            lifecycle_state(client.lifecycle.load(Ordering::Acquire)),
            LIFECYCLE_INITIALIZED
        );
        assert!(client.list_tools(None).await.is_ok());
        client.shutdown().await;
    }

    #[tokio::test]
    async fn mismatched_initialization_does_not_reset_exponential_backoff() {
        let directory = TempDir::new().expect("temporary directory creates");
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let executable = script(
            &directory,
            "mismatch-server",
            r#"#!/bin/sh
read line
if [ ! -f "$FIRST" ]; then
  printf x > "$FIRST"; id=1
elif [ ! -f "$SECOND" ]; then
  printf x > "$SECOND"; id=2
else
  id=3
fi
printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}\n' "$id"
while IFS= read -r line; do :; done
"#,
        );
        let mut trusted = template(executable);
        trusted.environment.extend([
            ("FIRST".to_owned(), first.to_string_lossy().into_owned()),
            ("SECOND".to_owned(), second.to_string_lossy().into_owned()),
        ]);
        let limits = StdioTransportLimits {
            request_timeout: Duration::from_secs(1),
            shutdown_grace: Duration::from_millis(20),
            initial_restart_backoff: Duration::from_millis(60),
            max_restart_backoff: Duration::from_millis(120),
            ..StdioTransportLimits::default()
        };
        let client = StdioClient::connect(trusted, limits)
            .await
            .expect("client connects");
        for (attempt, minimum_delay) in [
            (0, Duration::ZERO),
            (1, Duration::from_millis(45)),
            (2, Duration::from_millis(100)),
        ] {
            let started = Instant::now();
            let error = client
                .initialize(
                    DEFAULT_PROTOCOL_VERSION,
                    json!({ "name": "executor", "version": "1" }),
                    json!({}),
                )
                .await
                .expect_err("mismatched version remains rejected");
            assert!(matches!(
                error,
                StdioTransportError::ProtocolVersionMismatch
            ));
            assert!(
                started.elapsed() >= minimum_delay,
                "attempt {attempt} did not observe its accumulated backoff"
            );
        }
        client.shutdown().await;
    }

    #[test]
    fn limits_and_merged_secret_environment_are_strictly_bounded() {
        let limits = StdioTransportLimits {
            initial_restart_backoff: Duration::from_secs(31),
            max_restart_backoff: Duration::from_secs(31),
            ..StdioTransportLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(StdioTransportError::InvalidLimits)
        ));

        let approved = (0..128).map(|index| format!("SECRET_{index}"));
        let secrets = approved
            .clone()
            .map(|name| (name, "value".to_owned()))
            .collect::<BTreeMap<_, _>>();
        let base = BTreeMap::from([("STATIC".to_owned(), "value".to_owned())]);
        assert!(validate_environment(&base).is_ok());
        let mut merged = base;
        merged.extend(secrets);
        assert!(matches!(
            validate_environment(&merged),
            Err(StdioTemplateError::TooManyEnvironmentEntries)
        ));
    }

    #[test]
    fn packed_lifecycle_transitions_reject_stale_generation_races() {
        let lifecycle = AtomicU64::new(lifecycle_word(1, LIFECYCLE_INITIALIZING));
        assert!(matches!(
            acquire_lifecycle_generation(&lifecycle),
            Err(StdioTransportError::AlreadyInitialized)
        ));
        reset_lifecycle_generation(&lifecycle, 0);
        assert_eq!(
            lifecycle.load(Ordering::Acquire),
            lifecycle_word(1, LIFECYCLE_INITIALIZING)
        );
        reset_lifecycle_generation(&lifecycle, 1);
        let second = acquire_lifecycle_generation(&lifecycle).expect("next generation acquires");
        assert_eq!(second, 2);

        assert!(
            lifecycle
                .compare_exchange(
                    lifecycle_word(1, LIFECYCLE_INITIALIZING),
                    lifecycle_word(1, LIFECYCLE_INITIALIZED),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err(),
            "stale finalization cannot initialize the next generation"
        );
        reset_lifecycle_generation(&lifecycle, 1);
        assert_eq!(
            lifecycle.load(Ordering::Acquire),
            lifecycle_word(2, LIFECYCLE_INITIALIZING),
            "stale reset fallback cannot clear the next generation"
        );
    }
}
