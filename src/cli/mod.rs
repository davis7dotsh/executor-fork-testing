mod client;
mod input;
mod mcp_bridge;
mod output;
mod terminal;

use std::{
    io,
    process::{Command, Stdio},
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde_json::Value;
use tokio::time::sleep;
use uuid::Uuid;

pub use client::normalized_base_url;
use client::{GatewayClient, InvokeResponse};
use input::parse_arguments;

pub const DEFAULT_BASE_URL: &str = crate::DEFAULT_ORIGIN;

#[derive(Clone, Debug)]
pub struct ConnectionOptions {
    pub base_url: String,
    pub api_token: Option<String>,
    pub json: bool,
    pub allow_insecure_http: bool,
}

#[derive(Args, Debug)]
pub struct CallArgs {
    #[arg(required = true, num_args = 1.., value_name = "PATH [PATH] [JSON-OR-@FILE]")]
    pub values: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ToolsArgs {
    #[command(subcommand)]
    pub command: ToolsCommand,
}

#[derive(Subcommand, Debug)]
pub enum ToolsCommand {
    Search(SearchArgs),
    Describe(DescribeArgs),
    Sources,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    pub query: String,
    #[arg(long)]
    pub namespace: Option<String>,
    #[arg(long, default_value_t = 12, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub limit: u32,
    #[arg(long, default_value_t = 0)]
    pub offset: u32,
}

#[derive(Args, Debug)]
pub struct DescribeArgs {
    #[arg(required = true, num_args = 1..=2, value_name = "PATH [PATH]")]
    pub path: Vec<String>,
}

pub async fn call(options: ConnectionOptions, args: CallArgs) -> Result<()> {
    let (path, input) = split_call_values(&args.values)?;
    let arguments = parse_arguments(input).context("invalid tool arguments")?;
    let client = client(&options)?;
    let idempotency_key = Uuid::new_v4().to_string();
    match client.invoke(&path, arguments, &idempotency_key).await? {
        InvokeResponse::Complete(value) => print_call(&value, options.json)?,
        InvokeResponse::ApprovalRequired(pending) => {
            let approval_url = approval_dashboard_url(&client, &pending.approval.id)?;
            eprintln!(
                "Approval required for {}.",
                terminal::safe_field(&pending.approval.path)
            );
            eprintln!("Review it at: {approval_url}");
            let _ = try_open(&approval_url);
            let value = wait_for_approval(
                &client,
                &pending.approval.id,
                pending.approval.revision,
                pending.approval.expires_at,
            )
            .await?;
            print_call(&value, options.json)?;
        }
    }
    Ok(())
}

pub async fn tools(options: ConnectionOptions, args: ToolsArgs) -> Result<()> {
    let client = client(&options)?;
    let value = match &args.command {
        ToolsCommand::Search(args) => {
            client
                .search(
                    &args.query,
                    args.namespace.as_deref(),
                    args.limit,
                    args.offset,
                )
                .await?
        }
        ToolsCommand::Describe(args) => {
            let path = normalize_path(&args.path)?;
            client.describe(&path).await?
        }
        ToolsCommand::Sources => client.sources().await?,
    };
    if options.json {
        output::write_json(io::stdout().lock(), &value)?;
        return Ok(());
    }
    match &args.command {
        ToolsCommand::Search(_) => output::write_search_human(io::stdout().lock(), &value)?,
        ToolsCommand::Describe(_) => output::write_describe_human(io::stdout().lock(), &value)?,
        ToolsCommand::Sources => output::write_sources_human(io::stdout().lock(), &value)?,
    }
    Ok(())
}

pub async fn mcp(options: ConnectionOptions) -> Result<()> {
    if options.json {
        bail!("--json is not valid with the MCP stdio bridge");
    }
    mcp_bridge::run(
        &options.base_url,
        options.api_token.as_deref(),
        options.allow_insecure_http,
    )
    .await
}

pub fn open(options: &ConnectionOptions) -> Result<()> {
    let url =
        client::normalized_base_url_with_policy(&options.base_url, options.allow_insecure_http)?;
    println!("Opening {url}");
    try_open(url.as_str())
        .with_context(|| format!("could not open a browser; copy this URL instead: {url}"))
}

fn client(options: &ConnectionOptions) -> Result<GatewayClient> {
    GatewayClient::new_with_policy(
        &options.base_url,
        options.api_token.as_deref(),
        options.allow_insecure_http,
    )
    .map_err(Into::into)
}

fn split_call_values(values: &[String]) -> Result<(String, Option<&str>)> {
    let (path_values, input) = match values {
        [] => bail!("a tool path is required"),
        [path] => (std::slice::from_ref(path), None),
        [path, input] if path.contains('.') || path.contains('/') || looks_like_json(input) => {
            (std::slice::from_ref(path), Some(input.as_str()))
        }
        [_, _] => (&values[..2], None),
        [source, tool, input] => {
            let _ = (source, tool);
            (&values[..2], Some(input.as_str()))
        }
        _ => bail!("use a dotted path, or two path segments, followed by one JSON argument"),
    };
    Ok((normalize_path(path_values)?, input))
}

fn looks_like_json(value: &str) -> bool {
    let value = value.trim_start();
    value.starts_with('{') || value.starts_with('@')
}

pub fn normalize_path(values: &[String]) -> Result<String> {
    let segments: Vec<&str> = match values {
        [path] => path
            .strip_prefix("tools.")
            .unwrap_or(path)
            .split(['.', '/'])
            .collect(),
        [source, tool] => vec![source, tool],
        _ => bail!("tool paths must be dotted or contain exactly two segments"),
    };
    if segments.len() != 2 || segments.iter().any(|segment| !valid_segment(segment)) {
        bail!("tool paths must look like source.tool or source tool");
    }
    Ok(format!("tools.{}.{}", segments[0], segments[1]))
}

fn valid_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn approval_dashboard_url(client: &GatewayClient, approval_id: &str) -> Result<String> {
    let mut url = client.dashboard_url();
    url.set_path("approvals");
    url.query_pairs_mut().append_pair("approval", approval_id);
    Ok(url.to_string())
}

async fn wait_for_approval(
    client: &GatewayClient,
    approval_id: &str,
    mut revision: i64,
    mut expires_at: i64,
) -> Result<Value> {
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    loop {
        if unix_timestamp() >= expires_at.saturating_add(2) {
            bail!("tool approval expired while waiting");
        }
        let detail = tokio::select! {
            detail = client.approval(approval_id) => detail?,
            interrupt = &mut interrupt => {
                interrupt.context("could not listen for Ctrl-C")?;
                return cancel_waiting_approval(client, approval_id, revision).await;
            }
        };
        revision = detail.revision;
        expires_at = detail.expires_at;
        match detail.status.as_str() {
            "pending" | "approved" | "executing" => {
                tokio::select! {
                    _ = sleep(Duration::from_millis(750)) => {}
                    interrupt = &mut interrupt => {
                        interrupt.context("could not listen for Ctrl-C")?;
                        return cancel_waiting_approval(client, approval_id, revision).await;
                    }
                }
            }
            "succeeded" => {
                return detail
                    .result
                    .ok_or_else(|| anyhow::anyhow!("approval succeeded without a tool result"));
            }
            "failed" if detail.result.is_some() => {
                return Ok(detail.result.expect("checked result"));
            }
            "denied" | "canceled" | "expired" | "failed" | "stale" | "interrupted" => {
                let code = detail.failure_code.unwrap_or_else(|| detail.status.clone());
                bail!(
                    "tool call ended with status {} ({})",
                    terminal::safe_field(&detail.status),
                    terminal::safe_field(&code)
                );
            }
            status => bail!(
                "Executor returned an unknown approval status: {}",
                terminal::safe_field(status)
            ),
        }
    }
}

async fn cancel_waiting_approval(
    client: &GatewayClient,
    approval_id: &str,
    revision: i64,
) -> Result<Value> {
    let cancellation = tokio::time::timeout(
        Duration::from_secs(5),
        client.cancel_approval(approval_id, revision),
    )
    .await;
    match cancellation {
        Err(_) => bail!("interrupted while waiting for approval; cancellation timed out"),
        Ok(Ok(_)) => bail!("approval canceled"),
        Ok(Err(cancel_error)) => {
            match tokio::time::timeout(Duration::from_secs(5), client.approval(approval_id)).await {
                Ok(Ok(detail))
                    if matches!(
                        detail.status.as_str(),
                        "denied" | "canceled" | "expired" | "failed" | "stale" | "interrupted"
                    ) =>
                {
                    bail!(
                        "tool call ended with status {}",
                        terminal::safe_field(&detail.status)
                    )
                }
                Ok(Ok(detail)) if detail.status == "succeeded" && detail.result.is_some() => {
                    Ok(detail.result.expect("checked result"))
                }
                _ => {
                    bail!(
                        "interrupted while waiting for approval; cancellation failed: {cancel_error}"
                    )
                }
            }
        }
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn print_call(value: &Value, json_output: bool) -> Result<()> {
    if json_output {
        output::write_json(io::stdout().lock(), value)?;
    } else {
        output::write_call_human(io::stdout().lock(), value)?;
    }
    Ok(())
}

fn try_open(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("open");
    #[cfg(target_os = "linux")]
    let mut command = Command::new("xdg-open");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    bail!("opening a browser is only supported on Linux and macOS");

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        command
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("the platform browser opener is unavailable")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, routing::get};
    use serde_json::json;

    use super::*;

    #[test]
    fn accepts_dotted_prefixed_slash_and_segmented_paths() {
        for (input, expected) in [
            (vec!["github.issues_create"], "tools.github.issues_create"),
            (
                vec!["tools.github.issues_create"],
                "tools.github.issues_create",
            ),
            (vec!["github/issues_create"], "tools.github.issues_create"),
            (
                vec!["github", "issues_create"],
                "tools.github.issues_create",
            ),
        ] {
            let input = input.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(normalize_path(&input).expect("valid path"), expected);
        }
        assert!(normalize_path(&["Github.bad".to_owned()]).is_err());
        assert!(normalize_path(&["three.part.path".to_owned()]).is_err());
    }

    #[test]
    fn splits_call_path_and_optional_arguments_without_ambiguity() {
        let values = vec!["github".to_owned(), "issues_create".to_owned()];
        let (path, input) = split_call_values(&values).expect("segmented call");
        assert_eq!(path, "tools.github.issues_create");
        assert_eq!(input, None);

        let values = vec!["github.issues_create".to_owned(), "{}".to_owned()];
        let (path, input) = split_call_values(&values).expect("dotted call");
        assert_eq!(path, "tools.github.issues_create");
        assert_eq!(input, Some("{}"));
    }

    #[test]
    fn approval_dashboard_url_contains_no_api_token() {
        let client =
            GatewayClient::new("http://localhost:4788", Some("top-secret")).expect("client");
        let url = approval_dashboard_url(&client, "approval-1").expect("URL");
        assert_eq!(url, "http://localhost:4788/approvals?approval=approval-1");
        assert!(!url.contains("top-secret"));
    }

    #[test]
    fn approval_json_shape_is_preserved() {
        let value = json!({"status": "succeeded", "result": {"ok": true}});
        let mut output = Vec::new();
        output::write_json(&mut output, &value).expect("output");
        assert_eq!(
            serde_json::from_slice::<Value>(&output).expect("JSON"),
            value
        );
    }

    #[tokio::test]
    async fn approval_wait_preserves_succeeded_and_failed_tool_results() {
        async fn succeeded() -> Json<Value> {
            Json(json!({
                "id": "approval-1", "status": "succeeded", "revision": 2,
                "path": "tools.mail.send", "createdAt": 1,
                "updatedAt": 2, "expiresAt": unix_timestamp() + 60,
                "failureCode": null,
                "result": {"ok": true, "data": {"sent": true}}
            }))
        }
        async fn failed() -> Json<Value> {
            Json(json!({
                "id": "approval-2", "status": "failed", "revision": 2,
                "path": "tools.mail.send", "createdAt": 1,
                "updatedAt": 2, "expiresAt": unix_timestamp() + 60,
                "failureCode": "upstream_failed",
                "result": {"ok": false, "data": null, "error": {"code": "upstream_failed", "message": "Nope"}}
            }))
        }
        let router = Router::new()
            .route("/api/v1/gateway/approvals/approval-1", get(succeeded))
            .route("/api/v1/gateway/approvals/approval-2", get(failed));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("server");
        });
        let client =
            GatewayClient::new(&format!("http://{address}"), Some("token")).expect("client");
        let success = wait_for_approval(&client, "approval-1", 0, unix_timestamp() + 60)
            .await
            .expect("success");
        assert_eq!(success["data"]["sent"], true);
        let failure = wait_for_approval(&client, "approval-2", 0, unix_timestamp() + 60)
            .await
            .expect("public failure result");
        assert_eq!(failure["error"]["code"], "upstream_failed");
        server.abort();
    }
}
