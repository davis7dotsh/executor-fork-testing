use std::{future::Future, pin::pin, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::{Response, StatusCode, header};
use serde_json::Value;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::mpsc,
    task::JoinSet,
};
use url::Url;

use super::terminal::safe_field;

const PROTOCOL_VERSION: &str = "2025-11-25";
const SESSION_HEADER: &str = "mcp-session-id";
const MAX_MESSAGE_BYTES: usize = crate::invocation::MAX_ARGUMENT_BYTES + 64 * 1024;
const MAX_IN_FLIGHT_REQUESTS: usize = 8;
const MAX_IN_FLIGHT_WITH_CANCELLATION: usize = 16;

pub async fn run(base_url: &str, token: Option<&str>, allow_insecure_http: bool) -> Result<()> {
    let token = token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| anyhow::anyhow!("EXECUTOR_API_TOKEN or --api-token is required"))?;
    bridge(
        base_url,
        token,
        allow_insecure_http,
        tokio::io::stdin(),
        tokio::io::stdout(),
        shutdown_signal(),
    )
    .await
}

#[cfg(unix)]
async fn shutdown_signal() {
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    let Ok(mut terminate) = terminate else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn bridge<R, W, S>(
    base_url: &str,
    token: &str,
    allow_insecure_http: bool,
    input: R,
    mut output: W,
    shutdown: S,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    S: Future<Output = ()>,
{
    let mut endpoint =
        super::client::normalized_base_url_with_policy(base_url, allow_insecure_http)?;
    endpoint.set_path("mcp");
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .build()
        .context("could not initialize the MCP HTTP client")?;
    let mut session = None;
    let result = bridge_session(
        &http,
        &endpoint,
        token,
        &mut session,
        BufReader::new(input),
        &mut output,
        shutdown,
    )
    .await;
    close_session(&http, &endpoint, token, session.as_deref()).await;
    result
}

async fn bridge_session<R, W, S>(
    http: &reqwest::Client,
    endpoint: &Url,
    token: &str,
    session: &mut Option<String>,
    mut input: BufReader<R>,
    output: &mut W,
    shutdown: S,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
    S: Future<Output = ()>,
{
    let mut shutdown = pin!(shutdown);
    let first = tokio::select! {
        line = read_line_bounded(&mut input) => line?,
        _ = &mut shutdown => return Ok(()),
    };
    let Some(first) = first else {
        return Ok(());
    };
    let first = decode_stdin_message(&first)?;
    let initialize_request = mcp_request(http, endpoint, token, None).json(&first);
    let initialize_response = tokio::select! {
        response = initialize_request.send() => {
            response.context("Executor is not reachable; start `executor server` first")?
        }
        _ = &mut shutdown => return Ok(()),
    };
    *session = response_session_id(&initialize_response)?;
    if session.is_none() {
        bail!("the first MCP message must initialize a stateful Executor session");
    }
    let reply = tokio::select! {
        reply = decode_http_response(initialize_response) => reply?,
        _ = &mut shutdown => return Ok(()),
    };
    write_protocol_reply(output, reply.stdout).await?;

    let initialized = tokio::select! {
        line = read_line_bounded(&mut input) => line?,
        _ = &mut shutdown => return Ok(()),
    };
    let Some(initialized) = initialized else {
        return Ok(());
    };
    let initialized = decode_stdin_message(&initialized)?;
    if initialized.get("method").and_then(Value::as_str) != Some("notifications/initialized")
        || initialized.get("id").is_some()
    {
        bail!("MCP initialize must be followed by notifications/initialized");
    }
    let initialized_reply = tokio::select! {
        reply = post_message(
            http,
            endpoint,
            token,
            session.as_deref(),
            initialized,
        ) => reply?,
        _ = &mut shutdown => return Ok(()),
    };
    write_protocol_reply(output, initialized_reply.stdout).await?;

    let (line_sender, mut lines) = mpsc::channel::<Result<Option<Vec<u8>>>>(8);
    let reader = tokio::spawn(async move {
        loop {
            let line = read_line_bounded(&mut input).await;
            let done = matches!(line, Ok(None) | Err(_));
            if line_sender.send(line).await.is_err() || done {
                return;
            }
        }
    });
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                reader.abort();
                requests.abort_all();
                return Ok(());
            }
            line = lines.recv() => match line {
                Some(Ok(Some(line))) => {
                    let message = decode_stdin_message(&line)?;
                    let is_cancellation = message.get("method").and_then(Value::as_str)
                        == Some("notifications/cancelled");
                    let limit = if is_cancellation {
                        MAX_IN_FLIGHT_WITH_CANCELLATION
                    } else {
                        MAX_IN_FLIGHT_REQUESTS
                    };
                    if requests.len() >= limit {
                        write_protocol_reply(output, overload_response(&message)?).await?;
                        continue;
                    }
                    let http = http.clone();
                    let endpoint = endpoint.clone();
                    let token = token.to_owned();
                    let session = session.clone().expect("session established above");
                    requests.spawn(async move {
                        post_message(&http, &endpoint, &token, Some(&session), message)
                            .await
                            .map(|reply| reply.stdout)
                    });
                }
                Some(Ok(None)) | None => {
                    reader.abort();
                    requests.abort_all();
                    return Ok(());
                }
                Some(Err(error)) => {
                    reader.abort();
                    requests.abort_all();
                    return Err(error);
                }
            },
            joined = requests.join_next(), if !requests.is_empty() => {
                let reply = joined
                    .expect("a request was active")
                    .context("MCP forwarding task stopped unexpectedly")??;
                write_protocol_reply(output, reply).await?;
            }
        }
    }
}

struct HttpReply {
    stdout: Option<Vec<u8>>,
}

async fn post_message(
    http: &reqwest::Client,
    endpoint: &Url,
    token: &str,
    session: Option<&str>,
    message: Value,
) -> Result<HttpReply> {
    let response = mcp_request(http, endpoint, token, session)
        .json(&message)
        .send()
        .await
        .context("Executor is not reachable; start `executor server` first")?;
    decode_http_response(response).await
}

fn response_session_id(response: &Response) -> Result<Option<String>> {
    let response_session = response
        .headers()
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if response_session.as_ref().is_some_and(|session| {
        session.is_empty()
            || session.len() > 128
            || !session.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    }) {
        bail!("Executor returned an invalid MCP session ID");
    }
    Ok(response_session)
}

async fn decode_http_response(response: Response) -> Result<HttpReply> {
    let _response_session = response_session_id(&response)?;
    let status = response.status();
    let body = tokio::time::timeout(
        Duration::from_secs(11 * 60),
        read_response_bounded(response),
    )
    .await
    .context("Executor MCP response timed out")??;
    if !status.is_success() {
        let detail = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .map(safe_field)
            })
            .unwrap_or_else(|| {
                status
                    .canonical_reason()
                    .unwrap_or("MCP request failed")
                    .to_owned()
            });
        bail!("Executor MCP request failed ({status}): {detail}");
    }
    let stdout = if status == StatusCode::ACCEPTED || body.is_empty() {
        None
    } else {
        let response: Value =
            serde_json::from_slice(&body).context("Executor returned invalid MCP JSON-RPC data")?;
        Some(serde_json::to_vec(&response).context("could not encode the MCP response")?)
    };
    Ok(HttpReply { stdout })
}

fn decode_stdin_message(line: &[u8]) -> Result<Value> {
    let message: Value =
        serde_json::from_slice(line).context("stdin contained an invalid MCP JSON-RPC message")?;
    if !message.is_object() {
        bail!("stdin MCP messages must be JSON objects");
    }
    Ok(message)
}

fn overload_response(message: &Value) -> Result<Option<Vec<u8>>> {
    let Some(id) = message.get("id") else {
        return Ok(None);
    };
    let response = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": "Executor CLI MCP bridge is busy"
        }
    });
    serde_json::to_vec(&response)
        .map(Some)
        .context("could not encode the MCP overload response")
}

async fn write_protocol_reply(
    output: &mut (impl AsyncWrite + Unpin),
    reply: Option<Vec<u8>>,
) -> Result<()> {
    let Some(reply) = reply else {
        return Ok(());
    };
    output.write_all(&reply).await?;
    output.write_all(b"\n").await?;
    output.flush().await?;
    Ok(())
}

fn mcp_request(
    http: &reqwest::Client,
    endpoint: &Url,
    token: &str,
    session: Option<&str>,
) -> reqwest::RequestBuilder {
    let mut request = http
        .post(endpoint.clone())
        .bearer_auth(token)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(session) = session {
        request = request
            .header(SESSION_HEADER, session)
            .header("mcp-protocol-version", PROTOCOL_VERSION);
    }
    request
}

async fn close_session(http: &reqwest::Client, endpoint: &Url, token: &str, session: Option<&str>) {
    let Some(session) = session else {
        return;
    };
    let _ = http
        .delete(endpoint.clone())
        .bearer_auth(token)
        .header(SESSION_HEADER, session)
        .header("mcp-protocol-version", PROTOCOL_VERSION)
        .timeout(Duration::from_secs(2))
        .send()
        .await;
}

async fn read_line_bounded(input: &mut (impl AsyncBufRead + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = input.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Ok(Some(line));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let payload_take = newline.unwrap_or(available.len());
        let take = newline.map_or(available.len(), |position| position + 1);
        if line.len().saturating_add(payload_take) > MAX_MESSAGE_BYTES {
            bail!("stdin MCP message exceeds the {MAX_MESSAGE_BYTES} byte limit");
        }
        line.extend_from_slice(&available[..take]);
        input.consume(take);
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

async fn read_response_bounded(mut response: Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MESSAGE_BYTES as u64)
    {
        bail!("Executor MCP response exceeds the {MAX_MESSAGE_BYTES} byte limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_MESSAGE_BYTES {
            bail!("Executor MCP response exceeds the {MAX_MESSAGE_BYTES} byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };

    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
    };
    use serde_json::json;
    use tokio::io::AsyncWriteExt;

    use super::*;

    type CapturedRequests = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

    #[derive(Clone, Default)]
    struct TestState {
        deletes: Arc<Mutex<usize>>,
        requests: CapturedRequests,
        hold_calls: Arc<AtomicBool>,
        release_call: Arc<tokio::sync::Notify>,
        cancellation_seen: Arc<AtomicBool>,
        initialized: Arc<AtomicBool>,
    }

    async fn post_mcp(
        State(state): State<TestState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> impl axum::response::IntoResponse {
        let auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let session = headers
            .get(SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        state
            .requests
            .lock()
            .expect("requests")
            .push((auth, session));
        if body.get("method") == Some(&json!("tools/call"))
            && state.hold_calls.load(Ordering::SeqCst)
        {
            state.release_call.notified().await;
        }
        if body.get("method") == Some(&json!("notifications/cancelled")) {
            state.cancellation_seen.store(true, Ordering::SeqCst);
        }
        if body.get("method") == Some(&json!("initialize")) {
            let mut response = Json(json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"protocolVersion": PROTOCOL_VERSION}
            }))
            .into_response();
            response
                .headers_mut()
                .insert(SESSION_HEADER, "session-1".parse().expect("header"));
            response
        } else if body.get("method") == Some(&json!("notifications/initialized")) {
            state.initialized.store(true, Ordering::SeqCst);
            StatusCode::ACCEPTED.into_response()
        } else if !state.initialized.load(Ordering::SeqCst) {
            StatusCode::BAD_REQUEST.into_response()
        } else if body.get("id").is_none() {
            StatusCode::ACCEPTED.into_response()
        } else {
            Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {}})).into_response()
        }
    }

    async fn delete_mcp(State(state): State<TestState>) -> StatusCode {
        *state.deletes.lock().expect("deletes") += 1;
        StatusCode::NO_CONTENT
    }

    #[tokio::test]
    async fn bridge_keeps_protocol_stdout_clean_and_closes_the_session() {
        let state = TestState::default();
        let router = Router::new()
            .route("/mcp", post(post_mcp).delete(delete_mcp))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("server");
        });
        let (mut writer, reader) = tokio::io::duplex(4096);
        writer
            .write_all(
                concat!(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
                    "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
                    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n"
                )
                .as_bytes(),
            )
            .await
            .expect("input");
        let output = VecWriter::default();
        let captured = output.bytes.clone();
        let bridge_task = tokio::spawn(async move {
            bridge(
                &format!("http://{address}"),
                "secret-token",
                false,
                reader,
                output,
                std::future::pending(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if captured
                    .lock()
                    .expect("output")
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count()
                    == 2
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("responses");
        writer.shutdown().await.expect("EOF");
        bridge_task.await.expect("bridge task").expect("bridge");
        let output = String::from_utf8(captured.lock().expect("output").clone()).expect("UTF-8");
        let lines = output.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "notifications must not produce stdout");
        assert!(
            lines
                .iter()
                .all(|line| serde_json::from_str::<Value>(line).is_ok())
        );
        let requests = state.requests.lock().expect("requests");
        assert_eq!(requests[0], (Some("Bearer secret-token".to_owned()), None));
        assert_eq!(
            requests[1],
            (
                Some("Bearer secret-token".to_owned()),
                Some("session-1".to_owned())
            )
        );
        drop(requests);
        assert_eq!(*state.deletes.lock().expect("deletes"), 1);
        server.abort();
    }

    #[tokio::test]
    async fn bridge_requires_a_running_server_without_polluting_stdout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let input = std::io::Cursor::new(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n".to_vec(),
        );
        let output = VecWriter::default();
        let captured = output.bytes.clone();
        let error = bridge(
            &format!("http://{address}"),
            "token",
            false,
            input,
            output,
            std::future::pending(),
        )
        .await
        .expect_err("server is stopped");
        assert!(error.to_string().contains("start `executor server` first"));
        assert!(captured.lock().expect("output").is_empty());
    }

    #[tokio::test]
    async fn bridge_closes_session_after_malformed_post_initialize_input() {
        let state = TestState::default();
        let router = Router::new()
            .route("/mcp", post(post_mcp).delete(delete_mcp))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("server");
        });
        let input = std::io::Cursor::new(
            concat!(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
                "not-json\n"
            )
            .as_bytes()
            .to_vec(),
        );
        let error = bridge(
            &format!("http://{address}"),
            "token",
            false,
            input,
            VecWriter::default(),
            std::future::pending(),
        )
        .await
        .expect_err("malformed input");
        assert!(error.to_string().contains("invalid MCP JSON-RPC"));
        assert_eq!(*state.deletes.lock().expect("deletes"), 1);
        server.abort();
    }

    #[tokio::test]
    async fn bridge_shutdown_signal_closes_session_without_stdout_noise() {
        let state = TestState::default();
        let router = Router::new()
            .route("/mcp", post(post_mcp).delete(delete_mcp))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("server");
        });
        let (mut writer, input) = tokio::io::duplex(4096);
        writer
            .write_all(
                concat!(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
                    "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n"
                )
                .as_bytes(),
            )
            .await
            .expect("handshake");
        let output = VecWriter::default();
        let captured = output.bytes.clone();
        let (shutdown, shutdown_requested) = tokio::sync::oneshot::channel();
        let bridge_task = tokio::spawn(async move {
            bridge(
                &format!("http://{address}"),
                "token",
                false,
                input,
                output,
                async {
                    let _ = shutdown_requested.await;
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.initialized.load(Ordering::SeqCst) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("session initialization");
        shutdown.send(()).expect("shutdown receiver");
        bridge_task.await.expect("bridge task").expect("bridge");
        assert_eq!(*state.deletes.lock().expect("deletes"), 1);
        let output = String::from_utf8(captured.lock().expect("output").clone()).expect("UTF-8");
        assert_eq!(
            output.lines().count(),
            1,
            "only initialize may reach stdout"
        );
        server.abort();
    }

    #[tokio::test]
    async fn bridge_forwards_cancellation_while_another_request_is_open() {
        let state = TestState::default();
        state.hold_calls.store(true, Ordering::SeqCst);
        let router = Router::new()
            .route("/mcp", post(post_mcp).delete(delete_mcp))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("server");
        });
        let (mut writer, input) = tokio::io::duplex(4096);
        writer
            .write_all(concat!(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}\n",
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}\n"
            )
            .as_bytes())
            .await
            .expect("input");
        let bridge_task = tokio::spawn(async move {
            bridge(
                &format!("http://{address}"),
                "token",
                false,
                input,
                VecWriter::default(),
                std::future::pending(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.cancellation_seen.load(Ordering::SeqCst) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation notification should not wait for the tool call");
        state.release_call.notify_waiters();
        writer.shutdown().await.expect("EOF");
        bridge_task.await.expect("bridge task").expect("bridge");
        server.abort();
    }

    #[tokio::test]
    async fn overload_does_not_block_the_reserved_cancellation_lane() {
        let state = TestState::default();
        state.hold_calls.store(true, Ordering::SeqCst);
        let router = Router::new()
            .route("/mcp", post(post_mcp).delete(delete_mcp))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("server");
        });
        let (mut writer, input) = tokio::io::duplex(16 * 1024);
        writer
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            )
            .await
            .expect("handshake");
        for id in 2..=10 {
            writer
                .write_all(
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\"params\":{{}}}}\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("call");
        }
        writer
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":2}}\n",
            )
            .await
            .expect("cancellation");
        let bridge_task = tokio::spawn(async move {
            bridge(
                &format!("http://{address}"),
                "token",
                false,
                input,
                VecWriter::default(),
                std::future::pending(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.cancellation_seen.load(Ordering::SeqCst) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancellation must bypass the saturated regular lane");
        writer.shutdown().await.expect("EOF");
        bridge_task.await.expect("bridge task").expect("bridge");
        server.abort();
    }

    #[derive(Clone, Default)]
    struct VecWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl AsyncWrite for VecWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
            buffer: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.bytes.lock().expect("output").extend_from_slice(buffer);
            std::task::Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
}
