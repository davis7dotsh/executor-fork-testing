use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::catalog::{
    ArtifactKind, CatalogSnapshot, InitialCatalogSnapshot, McpToolBindingV1, StagedArtifact,
    StagedTool, StagedToolBinding, ToolBinding, ToolMode,
};

const CAPABILITIES_ARTIFACT_KEY: &str = "mcp-server";

#[derive(Clone, Copy, Debug)]
pub struct DiscoveryLimits {
    pub max_pages: usize,
    pub max_tools: usize,
    pub max_cursor_bytes: usize,
    pub max_tool_name_characters: usize,
    pub max_title_characters: usize,
    pub max_description_characters: usize,
    pub max_schema_bytes: usize,
    pub max_tool_bytes: usize,
    pub max_total_tool_bytes: usize,
    pub max_capabilities_bytes: usize,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_pages: 1_000,
            max_tools: 100_000,
            max_cursor_bytes: 8 * 1024,
            max_tool_name_characters: 128,
            max_title_characters: 300,
            max_description_characters: 4_000,
            max_schema_bytes: 2 * 1024 * 1024,
            max_tool_bytes: 5 * 1024 * 1024,
            max_total_tool_bytes: 32 * 1024 * 1024,
            max_capabilities_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryBasis {
    pub expected_source_revision: i64,
    pub expected_credential_revision: Option<i64>,
    pub protocol_version: String,
    pub server_name: String,
    pub server_version: String,
    pub server_title: Option<String>,
    pub instructions: Option<String>,
    pub capabilities: Value,
    pub tools_list_changed: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolAnnotations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredMcpTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<McpToolAnnotations>,
    #[serde(default, skip_serializing_if = "Map::is_empty", rename = "_meta")]
    pub meta: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPage {
    pub tools: Vec<DiscoveredMcpTool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[async_trait]
pub trait ToolPageFetcher: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn fetch_tools_page(&mut self, cursor: Option<&str>) -> Result<ToolPage, Self::Error>;
}

#[derive(Clone, Debug)]
pub struct DiscoveryPlan {
    pub basis: DiscoveryBasis,
    pub artifacts: Vec<StagedArtifact>,
    pub tools: Vec<StagedTool>,
    pub bindings: Vec<StagedToolBinding>,
}

impl DiscoveryPlan {
    pub fn catalog_snapshot(&self) -> CatalogSnapshot {
        CatalogSnapshot {
            expected_source_revision: self.basis.expected_source_revision,
            expected_credential_revision: self.basis.expected_credential_revision,
            artifacts: self.artifacts.clone(),
            tools: self.tools.clone(),
        }
    }

    pub fn initial_catalog_snapshot(&self) -> InitialCatalogSnapshot {
        InitialCatalogSnapshot {
            artifacts: self.artifacts.clone(),
            tools: self.tools.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("MCP tools/list failed: {0}")]
    Fetch(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("MCP discovery exceeded the {maximum} page limit")]
    TooManyPages { maximum: usize },
    #[error("MCP discovery exceeded the {maximum} tool limit")]
    TooManyTools { maximum: usize },
    #[error("MCP tools/list returned an invalid cursor")]
    InvalidCursor,
    #[error("MCP tools/list returned a cursor cycle")]
    CursorCycle,
    #[error("MCP tools/list returned duplicate tool name {name:?}")]
    DuplicateTool { name: String },
    #[error("MCP tool {tool:?} is invalid: {message}")]
    InvalidTool { tool: String, message: &'static str },
    #[error("MCP server discovery metadata is too large")]
    CapabilitiesTooLarge,
    #[error("MCP server capabilities must be a JSON object")]
    InvalidCapabilities,
    #[error("MCP tools/list returned too much tool metadata")]
    ToolMetadataTooLarge,
}

pub async fn discover<F: ToolPageFetcher>(
    fetcher: &mut F,
    basis: DiscoveryBasis,
) -> Result<DiscoveryPlan, DiscoveryError> {
    discover_with_limits(fetcher, basis, DiscoveryLimits::default()).await
}

pub async fn discover_with_limits<F: ToolPageFetcher>(
    fetcher: &mut F,
    basis: DiscoveryBasis,
    limits: DiscoveryLimits,
) -> Result<DiscoveryPlan, DiscoveryError> {
    let artifact = capabilities_artifact(&basis, limits)?;
    let mut cursor = None;
    let mut seen_cursors = HashSet::new();
    let mut seen_tools = HashSet::new();
    let mut staged = Vec::new();
    let mut total_tool_bytes = 0usize;

    loop {
        if seen_cursors.len() >= limits.max_pages {
            return Err(DiscoveryError::TooManyPages {
                maximum: limits.max_pages,
            });
        }
        if !seen_cursors.insert(cursor.clone()) {
            return Err(DiscoveryError::CursorCycle);
        }

        let page = fetcher
            .fetch_tools_page(cursor.as_deref())
            .await
            .map_err(|error| DiscoveryError::Fetch(Box::new(error)))?;
        let next_count = staged
            .len()
            .checked_add(page.tools.len())
            .filter(|count| *count <= limits.max_tools)
            .ok_or(DiscoveryError::TooManyTools {
                maximum: limits.max_tools,
            })?;
        staged.reserve(next_count - staged.len());

        for tool in page.tools {
            let tool_bytes = serde_json::to_vec(&tool)
                .map_err(|_| DiscoveryError::ToolMetadataTooLarge)?
                .len();
            if tool_bytes > limits.max_tool_bytes {
                return Err(invalid_tool(&tool.name, "tool metadata is too large"));
            }
            total_tool_bytes = total_tool_bytes
                .checked_add(tool_bytes)
                .filter(|bytes| *bytes <= limits.max_total_tool_bytes)
                .ok_or(DiscoveryError::ToolMetadataTooLarge)?;
            validate_tool(&tool, limits)?;
            if !seen_tools.insert(tool.name.clone()) {
                return Err(DiscoveryError::DuplicateTool { name: tool.name });
            }
            staged.push(tool);
        }

        cursor = match page.next_cursor {
            Some(next) => {
                if next.is_empty()
                    || next.len() > limits.max_cursor_bytes
                    || next.chars().any(char::is_control)
                {
                    return Err(DiscoveryError::InvalidCursor);
                }
                let next = Some(next);
                if seen_cursors.contains(&next) {
                    return Err(DiscoveryError::CursorCycle);
                }
                next
            }
            None => break,
        };
    }

    staged.sort_by(|left, right| left.name.cmp(&right.name));
    let tools = staged.iter().map(staged_tool).collect();
    let bindings = staged
        .into_iter()
        .map(|tool| StagedToolBinding {
            stable_key: tool.name.clone(),
            binding: ToolBinding::McpHttpV1(McpToolBindingV1 {
                version: 1,
                tool_name: tool.name,
            }),
        })
        .collect();

    Ok(DiscoveryPlan {
        basis,
        artifacts: vec![artifact],
        tools,
        bindings,
    })
}

pub fn bindings_for_source_kind(mut plan: DiscoveryPlan, source_is_stdio: bool) -> DiscoveryPlan {
    if source_is_stdio {
        for binding in &mut plan.bindings {
            if let ToolBinding::McpHttpV1(definition) = &binding.binding {
                binding.binding = ToolBinding::McpStdioV1(definition.clone());
            }
        }
    }
    plan
}

fn capabilities_artifact(
    basis: &DiscoveryBasis,
    limits: DiscoveryLimits,
) -> Result<StagedArtifact, DiscoveryError> {
    if !basis.capabilities.is_object() {
        return Err(DiscoveryError::InvalidCapabilities);
    }
    let content = json!({
        "protocolVersion": basis.protocol_version,
        "serverInfo": {
            "name": basis.server_name,
            "version": basis.server_version,
            "title": basis.server_title,
        },
        "instructions": basis.instructions,
        "capabilities": basis.capabilities,
        "toolsListChanged": basis.tools_list_changed,
    });
    if serde_json::to_vec(&content)
        .map(|encoded| encoded.len() > limits.max_capabilities_bytes)
        .unwrap_or(true)
    {
        return Err(DiscoveryError::CapabilitiesTooLarge);
    }
    Ok(StagedArtifact {
        kind: ArtifactKind::McpCapabilities,
        stable_key: CAPABILITIES_ARTIFACT_KEY.to_owned(),
        content,
    })
}

fn validate_tool(tool: &DiscoveredMcpTool, limits: DiscoveryLimits) -> Result<(), DiscoveryError> {
    validate_text(
        &tool.name,
        limits.max_tool_name_characters,
        &tool.name,
        "name must contain 1 to 128 non-control characters",
        false,
    )?;
    if tool.name.trim() != tool.name {
        return Err(invalid_tool(
            &tool.name,
            "name must not have leading or trailing whitespace",
        ));
    }
    if let Some(title) = tool.title.as_deref()
        && !title.is_empty()
    {
        validate_text(
            title,
            limits.max_title_characters,
            &tool.name,
            "title is too long or contains control characters",
            false,
        )?;
    }
    if let Some(description) = tool.description.as_deref()
        && !description.is_empty()
    {
        validate_text(
            description,
            limits.max_description_characters,
            &tool.name,
            "description is too long or contains disallowed control characters",
            true,
        )?;
    }
    if let Some(title) = tool
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.title.as_deref())
        && !title.is_empty()
    {
        validate_text(
            title,
            limits.max_title_characters,
            &tool.name,
            "annotation title is too long or contains control characters",
            false,
        )?;
    }
    validate_schema(&tool.input_schema, &tool.name, limits.max_schema_bytes)?;
    if let Some(schema) = &tool.output_schema {
        validate_schema(schema, &tool.name, limits.max_schema_bytes)?;
    }
    Ok(())
}

fn validate_text(
    value: &str,
    maximum: usize,
    tool: &str,
    message: &'static str,
    allow_layout_controls: bool,
) -> Result<(), DiscoveryError> {
    if value.is_empty()
        || value.chars().count() > maximum
        || value.chars().any(|character| {
            character.is_control() && !(allow_layout_controls && matches!(character, '\n' | '\t'))
        })
    {
        return Err(invalid_tool(tool, message));
    }
    Ok(())
}

fn validate_schema(schema: &Value, tool: &str, maximum_bytes: usize) -> Result<(), DiscoveryError> {
    schema
        .as_object()
        .ok_or_else(|| invalid_tool(tool, "schema must be a JSON object"))?;
    if serde_json::to_vec(schema)
        .map(|encoded| encoded.len() > maximum_bytes)
        .unwrap_or(true)
    {
        return Err(invalid_tool(tool, "schema is too large"));
    }
    Ok(())
}

fn invalid_tool(tool: &str, message: &'static str) -> DiscoveryError {
    DiscoveryError::InvalidTool {
        tool: tool.to_owned(),
        message,
    }
}

fn staged_tool(tool: &DiscoveredMcpTool) -> StagedTool {
    let intrinsic_mode = match tool.annotations.as_ref() {
        Some(annotations)
            if annotations.read_only_hint == Some(true)
                && annotations.destructive_hint != Some(true) =>
        {
            ToolMode::Enabled
        }
        _ => ToolMode::Ask,
    };
    StagedTool {
        stable_key: tool.name.clone(),
        preferred_name: tool.name.clone(),
        display_name: tool
            .title
            .clone()
            .filter(|title| !title.is_empty())
            .or_else(|| {
                tool.annotations
                    .as_ref()
                    .and_then(|annotations| annotations.title.clone())
                    .filter(|title| !title.is_empty())
            })
            .unwrap_or_else(|| tool.name.clone()),
        description: tool
            .description
            .clone()
            .filter(|description| !description.is_empty()),
        input_schema: tool.input_schema.clone(),
        output_schema: tool.output_schema.clone(),
        input_typescript: None,
        output_typescript: None,
        typescript_definitions: BTreeMap::new(),
        intrinsic_mode,
    }
}

#[derive(Clone, Default)]
pub struct ListChangedCoalescer {
    state: Arc<Mutex<CoalescerState>>,
}

#[derive(Default)]
struct CoalescerState {
    requested_generation: u64,
    completed_generation: u64,
    running: bool,
}

impl ListChangedCoalescer {
    /// Marks the catalog dirty and returns whether no refresh runner is currently active.
    ///
    /// A notification callback may use the return value as a hint to spawn a runner. More than
    /// one callback can observe `true` before the first runner starts, which is harmless because
    /// `refresh_pending` admits only one runner.
    pub fn notify_changed(&self) -> bool {
        let mut state = self.state.lock().expect("coalescer mutex poisoned");
        state.requested_generation = state.requested_generation.saturating_add(1);
        !state.running
    }

    pub fn has_pending(&self) -> bool {
        let state = self.state.lock().expect("coalescer mutex poisoned");
        state.requested_generation != state.completed_generation
    }

    pub async fn refresh_pending<F, Fut, Error>(&self, mut refresh: F) -> Result<usize, Error>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<(), Error>>,
    {
        let Some(mut ownership) = CoalescerOwnership::acquire(self.state.clone()) else {
            return Ok(0);
        };
        let mut refresh_count = 0;
        loop {
            let Some(target) = ownership.next_target_or_finish() else {
                return Ok(refresh_count);
            };
            refresh().await?;
            refresh_count += 1;
            ownership.complete(target);
        }
    }
}

struct CoalescerOwnership {
    state: Arc<Mutex<CoalescerState>>,
    finished: bool,
}

impl CoalescerOwnership {
    fn acquire(state: Arc<Mutex<CoalescerState>>) -> Option<Self> {
        {
            let mut current = state.lock().expect("coalescer mutex poisoned");
            if current.running {
                return None;
            }
            current.running = true;
        }
        Some(Self {
            state,
            finished: false,
        })
    }

    fn next_target_or_finish(&mut self) -> Option<u64> {
        let mut state = self.state.lock().expect("coalescer mutex poisoned");
        if state.requested_generation == state.completed_generation {
            state.running = false;
            self.finished = true;
            None
        } else {
            Some(state.requested_generation)
        }
    }

    fn complete(&mut self, generation: u64) {
        self.state
            .lock()
            .expect("coalescer mutex poisoned")
            .completed_generation = generation;
    }
}

impl Drop for CoalescerOwnership {
    fn drop(&mut self) {
        if !self.finished {
            self.state.lock().expect("coalescer mutex poisoned").running = false;
        }
    }
}

#[cfg(test)]
mod tests;
