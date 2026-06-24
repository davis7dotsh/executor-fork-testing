use std::{collections::VecDeque, sync::Arc};

use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};

use super::{
    StreamableHttpConfig, StreamableHttpError, StreamableHttpTransport, parse_response_messages,
};
use crate::outbound::OutboundResponse;

struct TestServer {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let endpoint = format!(
            "http://{}/mcp",
            listener.local_addr().expect("listener has an address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
        let task = tokio::spawn(async move {
            loop {
                let Some(response) = responses.lock().await.pop_front() else {
                    break;
                };
                let (mut stream, _) = listener.accept().await.expect("request is accepted");
                let mut bytes = vec![0_u8; 64 * 1024];
                let read = stream.read(&mut bytes).await.expect("request is read");
                captured
                    .lock()
                    .await
                    .push(String::from_utf8_lossy(&bytes[..read]).into_owned());
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("response is written");
            }
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }

    async fn finish(self) -> Vec<String> {
        self.task.await.expect("test server completes");
        Arc::try_unwrap(self.requests)
            .expect("request capture has one owner")
            .into_inner()
    }
}

fn response(status: &str, headers: &[(&str, &str)], body: &str) -> String {
    let mut response = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    response
}

fn make_transport(endpoint: String) -> StreamableHttpTransport {
    let mut config = StreamableHttpConfig::new(endpoint);
    config.allow_private_networks = true;
    StreamableHttpTransport::new(config).expect("test transport is valid")
}

#[tokio::test]
async fn initialization_pins_session_and_protocol_for_followup_requests() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "serverInfo": { "name": "test", "version": "1" }
        }
    })
    .to_string();
    let tools = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "tools": [{ "name": "ping", "inputSchema": { "type": "object" } }] }
    })
    .to_string();
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "session-1"),
            ],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response("200 OK", &[("Content-Type", "application/json")], &tools),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());

    transport
        .initialize()
        .await
        .expect("initialization succeeds");
    let page = transport
        .list_tools(None, json!(1))
        .await
        .expect("tools list succeeds");
    assert_eq!(page.tools[0]["name"], "ping");
    assert_eq!(transport.session_id().await.as_deref(), Some("session-1"));

    let requests = server.finish().await;
    assert!(
        !requests[0]
            .to_ascii_lowercase()
            .contains("mcp-protocol-version:")
    );
    for request in &requests[1..] {
        let request = request.to_ascii_lowercase();
        assert!(request.contains("mcp-session-id: session-1"));
        assert!(request.contains("mcp-protocol-version: 2025-11-25"));
        assert!(request.contains("accept: application/json, text/event-stream"));
        assert!(!request.contains("last-event-id:"));
    }
}

#[tokio::test]
async fn call_tool_accepts_sse_and_rejects_server_requests() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let call_sse = concat!(
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n\n",
        "event: message\n",
        "data: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[]}}\n\n"
    );
    let server_request = "data: {\"jsonrpc\":\"2.0\",\"id\":\"server-1\",\"method\":\"elicitation/create\",\"params\":{}}\n\n";
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response("200 OK", &[("Content-Type", "text/event-stream")], call_sse),
        response("202 Accepted", &[], ""),
        response(
            "200 OK",
            &[("Content-Type", "text/event-stream")],
            server_request,
        ),
        response("202 Accepted", &[], ""),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");

    let result = transport
        .call_tool("ping", json!({}), json!(7))
        .await
        .expect("SSE tool response succeeds");
    assert_eq!(result, json!({ "content": [] }));
    let error = transport
        .send_internal(
            json!({
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/list",
                "params": {}
            }),
            true,
            false,
        )
        .await
        .expect_err("server request is rejected");
    assert!(matches!(error, StreamableHttpError::InvalidResponse));
    let requests = server.finish().await;
    assert!(requests[3].contains("\"id\":7"));
    assert!(requests[3].contains("\"result\":{}"));
    assert!(requests[5].contains("\"code\":-32601"));
}

#[tokio::test]
async fn changed_and_expired_sessions_fail_closed() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let tools = json!({ "jsonrpc": "2.0", "id": 1, "result": { "tools": [] } }).to_string();
    let changed = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "one"),
            ],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "two"),
            ],
            &tools,
        ),
    ])
    .await;
    let transport = make_transport(changed.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");
    assert!(matches!(
        transport.list_tools(None, json!(1)).await,
        Err(StreamableHttpError::SessionChanged)
    ));
    changed.finish().await;

    let expired = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "one"),
            ],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response("404 Not Found", &[], ""),
    ])
    .await;
    let transport = make_transport(expired.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");
    assert!(matches!(
        transport.list_tools(None, json!(1)).await,
        Err(StreamableHttpError::SessionExpired)
    ));
    assert_eq!(transport.session_id().await, None);
    expired.finish().await;
}

#[tokio::test]
async fn termination_uses_delete_and_clears_memory() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "one"),
            ],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response("204 No Content", &[], ""),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");
    transport.terminate().await.expect("termination succeeds");
    assert_eq!(transport.session_id().await, None);

    let requests = server.finish().await;
    assert!(requests[2].starts_with("DELETE /mcp HTTP/1.1"));
    assert!(
        requests[2]
            .to_ascii_lowercase()
            .contains("mcp-session-id: one")
    );
}

#[tokio::test]
async fn termination_invalidates_before_waiting_for_delete_response() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("listener has an address")
    );
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("DELETE is accepted");
        let mut request = vec![0_u8; 8192];
        let read = stream.read(&mut request).await.expect("DELETE is read");
        assert!(read > 0, "DELETE request is not empty");
        accepted_tx.send(()).expect("test signal sends");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("DELETE response writes");
    });
    let transport = make_transport(endpoint);
    {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.session_id = Some("terminating".to_owned());
        state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
    }
    let terminating = {
        let transport = transport.clone();
        tokio::spawn(async move { transport.terminate().await })
    };
    accepted_rx.await.expect("DELETE reaches the server");

    assert!(matches!(
        transport.list_tools(None, json!(1)).await,
        Err(StreamableHttpError::NotInitialized)
    ));
    terminating
        .await
        .expect("termination task completes")
        .expect("termination succeeds");
    server.await.expect("server task completes");
}

#[tokio::test]
async fn protocol_mismatch_discards_the_server_session() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-03-26", "capabilities": {} }
    })
    .to_string();
    let server = TestServer::start(vec![response(
        "200 OK",
        &[
            ("Content-Type", "application/json"),
            ("Mcp-Session-Id", "unusable"),
        ],
        &initialize,
    )])
    .await;
    let transport = make_transport(server.endpoint.clone());

    assert!(matches!(
        transport.initialize().await,
        Err(StreamableHttpError::ProtocolVersionMismatch)
    ));
    assert_eq!(transport.session_id().await, None);
    assert!(matches!(
        transport.list_tools(None, json!(1)).await,
        Err(StreamableHttpError::NotInitialized)
    ));
    server.finish().await;
}

#[tokio::test]
async fn aborted_initialize_discards_provisional_session_state() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("listener has an address")
    );
    let (headers_tx, headers_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("initialize is accepted");
        let mut request = vec![0_u8; 8192];
        let read = stream.read(&mut request).await.expect("initialize is read");
        assert!(read > 0, "initialize request is not empty");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nMcp-Session-Id: provisional\r\n\r\n",
            )
            .await
            .expect("initialize headers write");
        stream.flush().await.expect("initialize headers flush");
        headers_tx.send(()).expect("header signal sends");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });
    let transport = make_transport(endpoint);
    let initializing = {
        let transport = transport.clone();
        tokio::spawn(async move { transport.initialize().await })
    };
    headers_rx.await.expect("initialize headers arrive");
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    initializing.abort();
    let _ = initializing.await;

    let state = transport.lock_state();
    assert!(!state.initialized);
    assert_eq!(state.session_id, None);
    assert_eq!(state.negotiated_protocol_version, None);
    drop(state);
    server.abort();
}

#[tokio::test]
async fn initialized_notification_requires_empty_202() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &initialize,
        ),
        response("204 No Content", &[], ""),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());

    assert!(matches!(
        transport.initialize().await,
        Err(StreamableHttpError::InvalidResponse)
    ));
    assert_eq!(transport.session_id().await, None);
    server.finish().await;

    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &initialize,
        ),
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &json!({ "jsonrpc": "2.0", "method": "notifications/progress" }).to_string(),
        ),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());
    assert!(matches!(
        transport.initialize().await,
        Err(StreamableHttpError::InvalidResponse)
    ));
    server.finish().await;
}

#[tokio::test]
async fn interrupted_sse_resumes_with_last_event_id() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let resumed = "id: event-2\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n";
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "resume-session"),
            ],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response(
            "200 OK",
            &[("Content-Type", "text/event-stream")],
            "id: event-1\ndata:\n\n",
        ),
        response("503 Service Unavailable", &[], ""),
        response("200 OK", &[("Content-Type", "text/event-stream")], resumed),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");

    let page = transport
        .list_tools(None, json!(1))
        .await
        .expect("resumed list succeeds");
    assert!(page.tools.is_empty());
    let requests = server.finish().await;
    for request in &requests[3..=4] {
        assert!(request.starts_with("GET /mcp HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("last-event-id: event-1")
        );
    }
}

#[tokio::test]
async fn initialize_sse_resume_uses_newly_assigned_session() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "text/event-stream"),
                ("Mcp-Session-Id", "initialize-session"),
            ],
            "id: initialize-1\ndata:\n\n",
        ),
        response(
            "200 OK",
            &[("Content-Type", "text/event-stream")],
            &format!("data: {initialize}\n\n"),
        ),
        response("202 Accepted", &[], ""),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());

    transport
        .initialize()
        .await
        .expect("stateful initialize resumes");
    let requests = server.finish().await;
    let resume = requests[1].to_ascii_lowercase();
    assert!(resume.starts_with("get /mcp http/1.1"));
    assert!(resume.contains("mcp-session-id: initialize-session"));
    assert!(resume.contains("last-event-id: initialize-1"));
    let initialized = requests[2].to_ascii_lowercase();
    assert!(initialized.starts_with("post /mcp http/1.1"));
    assert!(initialized.contains("mcp-session-id: initialize-session"));
    assert!(initialized.contains("mcp-protocol-version: 2025-11-25"));
}

#[tokio::test]
async fn stateless_sse_also_resumes_with_last_event_id() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response(
            "200 OK",
            &[("Content-Type", "text/event-stream")],
            "id: stateless-1\ndata:\n\n",
        ),
        response(
            "200 OK",
            &[("Content-Type", "text/event-stream")],
            "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n",
        ),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");
    transport
        .list_tools(None, json!(2))
        .await
        .expect("stateless resume succeeds");

    let requests = server.finish().await;
    let resumed = requests[3].to_ascii_lowercase();
    assert!(resumed.starts_with("get /mcp http/1.1"));
    assert!(resumed.contains("last-event-id: stateless-1"));
    assert!(!resumed.contains("mcp-session-id:"));
}

#[tokio::test]
async fn matching_sse_response_returns_before_stream_eof() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("listener has an address")
    );
    let task = tokio::spawn(async move {
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
        })
        .to_string();
        for response in [
            response(
                "200 OK",
                &[
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", "stream-session"),
                ],
                &initialize,
            ),
            response("202 Accepted", &[], ""),
        ] {
            let (mut stream, _) = listener.accept().await.expect("request is accepted");
            let mut request = vec![0_u8; 8192];
            let read = stream.read(&mut request).await.expect("request is read");
            assert!(read > 0, "request is not empty");
            stream
                .write_all(response.as_bytes())
                .await
                .expect("response is written");
        }
        let (mut stream, _) = listener.accept().await.expect("tool request is accepted");
        let mut request = vec![0_u8; 8192];
        let read = stream
            .read(&mut request)
            .await
            .expect("tool request is read");
        assert!(read > 0, "tool request is not empty");
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nid: result-1\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"content\":[]}}\n\n",
            )
            .await
            .expect("stream event is written");
        stream.flush().await.expect("stream event is flushed");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });
    let transport = make_transport(endpoint);
    transport
        .initialize()
        .await
        .expect("initialization succeeds");

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        transport.call_tool("ping", json!({}), json!(9)),
    )
    .await
    .expect("matching response does not wait for EOF")
    .expect("tool call succeeds");
    assert_eq!(result, json!({ "content": [] }));
    task.abort();
}

#[tokio::test]
async fn notification_get_stream_signals_tool_list_changes() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let notification = "id: changed-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n";
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "notify-session"),
            ],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response(
            "200 OK",
            &[("Content-Type", "text/event-stream")],
            notification,
        ),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");
    let mut changes = transport.subscribe_tool_list_changed();
    let listener_transport = transport.clone();
    let listener = tokio::spawn(async move { listener_transport.listen_notifications().await });

    tokio::time::timeout(std::time::Duration::from_secs(1), changes.recv())
        .await
        .expect("change signal arrives before timeout")
        .expect("change channel remains open");
    let requests = server.finish().await;
    assert!(requests[2].starts_with("GET /mcp HTTP/1.1"));
    listener.abort();
}

#[test]
fn sse_parser_handles_multiline_data_and_rejects_empty_streams() {
    let body = b"id: prime\ndata:\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{}}\n\n";
    let parsed = parse_response_messages(&OutboundResponse {
        status: reqwest::StatusCode::OK,
        headers: [(
            reqwest::header::CONTENT_TYPE,
            "text/event-stream".parse().unwrap(),
        )]
        .into_iter()
        .collect(),
        body: body.to_vec(),
        final_url: "https://example.com/mcp".parse().unwrap(),
    })
    .expect("multiline SSE data parses");
    assert_eq!(
        parsed,
        vec![json!({ "jsonrpc": "2.0", "id": 1, "result": {} })]
    );

    let empty = parse_response_messages(&OutboundResponse {
        status: reqwest::StatusCode::OK,
        headers: [(
            reqwest::header::CONTENT_TYPE,
            "text/event-stream".parse().unwrap(),
        )]
        .into_iter()
        .collect(),
        body: b": keepalive\n\n".to_vec(),
        final_url: "https://example.com/mcp".parse().unwrap(),
    });
    assert!(matches!(empty, Err(StreamableHttpError::InvalidResponse)));
}

#[test]
fn public_networks_are_the_default_and_protocol_headers_are_reserved() {
    let denied =
        StreamableHttpTransport::new(StreamableHttpConfig::new("http://127.0.0.1:1234/mcp"));
    assert!(matches!(
        denied,
        Err(StreamableHttpError::Outbound(
            crate::outbound::OutboundError::PrivateAddress
        ))
    ));

    let mut config = StreamableHttpConfig::new("https://example.com/mcp");
    config
        .headers
        .insert("mcp-session-id", "injected".parse().unwrap());
    assert!(matches!(
        StreamableHttpTransport::new(config),
        Err(StreamableHttpError::ReservedHeader)
    ));

    let mut config = StreamableHttpConfig::new("https://example.com/mcp");
    config
        .headers
        .insert("last-event-id", "leaked".parse().unwrap());
    assert!(matches!(
        StreamableHttpTransport::new(config),
        Err(StreamableHttpError::ReservedHeader)
    ));
}

#[test]
fn response_error_data_is_structured_and_sanitizable_by_the_caller() {
    let error = super::response_result(
        vec![json!({
            "jsonrpc": "2.0",
            "id": "call",
            "error": { "code": -32602, "message": "bad args", "data": { "secret": true } }
        })],
        &Value::String("call".to_owned()),
    )
    .expect_err("JSON-RPC error is returned");
    assert!(matches!(
        error,
        StreamableHttpError::JsonRpc { code: -32602, .. }
    ));
}

#[test]
fn outgoing_json_rpc_rejects_fractional_and_ambiguous_responses() {
    for message in [
        json!({ "jsonrpc": "2.0", "id": 1.5, "method": "tools/list" }),
        json!({ "jsonrpc": "2.0", "result": {} }),
        json!({ "jsonrpc": "2.0", "id": 1, "result": {}, "error": { "code": -1, "message": "bad" } }),
    ] {
        assert!(matches!(
            super::validate_outgoing_message(&message),
            Err(StreamableHttpError::InvalidRequest)
        ));
    }
}

#[tokio::test]
async fn notifications_are_validated_and_never_classified_as_responses() {
    let transport = make_transport("http://127.0.0.1:1/mcp".to_owned());
    let mut changes = transport.subscribe_tool_list_changed();
    let generation = transport.lock_state().generation;
    assert!(matches!(
        transport
            .handle_server_message(
                &json!({
                    "method": "notifications/tools/list_changed",
                    "result": {}
                }),
                generation,
            )
            .await,
        Err(StreamableHttpError::InvalidResponse)
    ));
    assert!(matches!(
        changes.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(
        !transport
            .handle_server_message(
                &json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": {} }),
                generation,
            )
            .await
            .expect("valid notification is accepted")
    );
}

#[test]
fn sse_retry_is_bounded_and_retained_for_reconnect() {
    let mut decoder = super::SseDecoder::default();
    assert_eq!(decoder.retry_delay(), std::time::Duration::from_millis(250));
    decoder
        .push(b"retry: 60000\nid: one\ndata:\n\n")
        .expect("retry event parses");
    assert_eq!(decoder.retry_delay(), std::time::Duration::from_secs(10));
    assert_eq!(decoder.last_event_id(), Some("one"));
    decoder
        .push(b"retry: 0\nid: two\ndata:\n\n")
        .expect("minimum retry event parses");
    assert_eq!(decoder.retry_delay(), std::time::Duration::from_millis(50));
}

#[test]
fn unterminated_sse_event_is_discarded_without_advancing_cursor() {
    let mut decoder = super::SseDecoder::default();
    let events = decoder
        .push(b"id: truncated\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}")
        .expect("partial event bytes are buffered");
    assert!(events.is_empty());
    assert!(
        decoder
            .finish()
            .expect("partial event is discarded")
            .is_empty()
    );
    assert_eq!(decoder.last_event_id(), None);
}

#[test]
fn sse_accepts_bom_and_all_standard_line_endings_across_chunks() {
    for body in [
        b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n".as_slice(),
        b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\n\r\n".as_slice(),
        b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\r\r".as_slice(),
    ] {
        let parsed = super::parse_sse(body).expect("standard SSE line endings parse");
        assert_eq!(parsed[0]["id"], 1);
    }

    let mut decoder = super::SseDecoder::default();
    assert!(
        decoder
            .push(&[0xef])
            .expect("BOM prefix buffers")
            .is_empty()
    );
    assert!(
        decoder
            .push(b"\xbb\xbfdata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\r")
            .expect("split BOM and CR buffer")
            .is_empty()
    );
    let mut events = decoder.push(b"\r").expect("lone CR boundary parses");
    events.extend(decoder.finish().expect("stream finishes"));
    assert_eq!(events[0].message.as_ref().expect("message exists")["id"], 2);
}

#[test]
fn sse_trickle_and_many_data_lines_remain_linearly_bounded() {
    let mut decoder = super::SseDecoder::default();
    for _ in 0..10_000 {
        assert!(decoder.push(b"x").expect("trickle byte buffers").is_empty());
        assert_eq!(decoder.scan_offset, decoder.pending.len());
    }
    assert!(
        decoder
            .finish()
            .expect("trickle stream finishes")
            .is_empty()
    );

    let mut body = Vec::new();
    for _ in 0..10_000 {
        body.extend_from_slice(b"data:\n");
    }
    body.extend_from_slice(b"data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}\n\n");
    let messages = super::parse_sse(&body).expect("many bounded data lines parse");
    assert_eq!(messages[0]["id"], 3);
}

#[tokio::test]
async fn generation_change_during_retry_delay_prevents_stale_resume_get() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "retry-session"),
            ],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response(
            "200 OK",
            &[("Content-Type", "text/event-stream")],
            "retry: 100\nid: retry-1\ndata:\n\n",
        ),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");
    let listing = {
        let transport = transport.clone();
        tokio::spawn(async move { transport.list_tools(None, json!(4)).await })
    };
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    transport.reset_state().await;

    assert!(matches!(
        listing.await.expect("listing task completes"),
        Err(StreamableHttpError::SessionInvalidated)
    ));
    let requests = server.finish().await;
    assert_eq!(requests.len(), 3);
}

#[tokio::test]
async fn stale_responses_cannot_restore_an_invalidated_session() {
    let transport = make_transport("http://127.0.0.1:1/mcp".to_owned());
    {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.session_id = Some("old".to_owned());
    }
    let generation = transport.lock_state().generation;
    transport.reset_state().await;
    let response = OutboundResponse {
        status: reqwest::StatusCode::OK,
        headers: [(super::MCP_SESSION_ID, "old".parse().unwrap())]
            .into_iter()
            .collect(),
        body: Vec::new(),
        final_url: "http://127.0.0.1:1/mcp".parse().unwrap(),
    };

    assert!(matches!(
        transport
            .accept_response_session(&response.headers, generation, false)
            .await,
        Err(StreamableHttpError::SessionInvalidated)
    ));
    assert_eq!(transport.session_id().await, None);
}

#[tokio::test]
async fn only_initialize_can_establish_a_session() {
    let transport = make_transport("http://127.0.0.1:1/mcp".to_owned());
    transport.lock_state().initialized = true;
    let generation = transport.lock_state().generation;
    let response = OutboundResponse {
        status: reqwest::StatusCode::OK,
        headers: [(super::MCP_SESSION_ID, "late".parse().unwrap())]
            .into_iter()
            .collect(),
        body: Vec::new(),
        final_url: "http://127.0.0.1:1/mcp".parse().unwrap(),
    };

    assert!(matches!(
        transport
            .accept_response_session(&response.headers, generation, false)
            .await,
        Err(StreamableHttpError::InvalidSessionId)
    ));
    assert_eq!(transport.session_id().await, None);
}

#[tokio::test]
async fn invalid_resumed_session_header_invalidates_local_state() {
    let transport = make_transport("http://127.0.0.1:1/mcp".to_owned());
    {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.session_id = Some("expected".to_owned());
    }
    let generation = transport.lock_state().generation;
    let headers = [(super::MCP_SESSION_ID, "changed".parse().unwrap())]
        .into_iter()
        .collect();

    assert!(matches!(
        transport
            .accept_response_session_or_reset(&headers, generation, false)
            .await,
        Err(StreamableHttpError::SessionChanged)
    ));
    assert_eq!(transport.session_id().await, None);
    assert!(matches!(
        transport.list_tools(None, json!(1)).await,
        Err(StreamableHttpError::NotInitialized)
    ));
}

#[tokio::test]
async fn auxiliary_responses_enforce_session_expiry_and_header_pinning() {
    for (status, response_headers, expected_changed) in [
        ("404 Not Found", Vec::new(), false),
        ("202 Accepted", vec![("Mcp-Session-Id", "different")], true),
    ] {
        let server = TestServer::start(vec![response(status, &response_headers, "")]).await;
        let transport = make_transport(server.endpoint.clone());
        {
            let mut state = transport.lock_state();
            state.initialized = true;
            state.session_id = Some("expected".to_owned());
            state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
        }
        let generation = transport.lock_state().generation;
        let error = transport
            .post_auxiliary_response(
                json!({ "jsonrpc": "2.0", "id": "server", "result": {} }),
                generation,
            )
            .await
            .expect_err("invalid auxiliary session response is rejected");
        if expected_changed {
            assert!(matches!(error, StreamableHttpError::SessionChanged));
        } else {
            assert!(matches!(error, StreamableHttpError::SessionExpired));
        }
        assert_eq!(transport.session_id().await, None);
        server.finish().await;
    }
}

#[tokio::test]
async fn auxiliary_headers_invalidate_session_before_stalled_or_oversized_body() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("listener has an address")
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("auxiliary POST accepts");
        let mut request = vec![0_u8; 8192];
        let read = stream
            .read(&mut request)
            .await
            .expect("auxiliary POST reads");
        assert!(read > 0, "auxiliary request is not empty");
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\n\r\n")
            .await
            .expect("stalled 404 headers write");
        stream.flush().await.expect("stalled 404 headers flush");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });
    let transport = make_transport(endpoint);
    {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.session_id = Some("expected".to_owned());
        state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
    }
    let generation = transport.lock_state().generation;
    let error = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        transport.post_auxiliary_response(
            json!({ "jsonrpc": "2.0", "id": "server", "result": {} }),
            generation,
        ),
    )
    .await
    .expect("404 invalidates before stalled body")
    .expect_err("stalled 404 expires session");
    assert!(matches!(error, StreamableHttpError::SessionExpired));
    assert_eq!(transport.session_id().await, None);
    server.abort();

    let server = TestServer::start(vec![
        "HTTP/1.1 202 Accepted\r\nMcp-Session-Id: changed\r\nContent-Length: 16777217\r\n\r\n"
            .to_owned(),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());
    {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.session_id = Some("expected".to_owned());
        state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
    }
    let generation = transport.lock_state().generation;
    assert!(matches!(
        transport
            .post_auxiliary_response(
                json!({ "jsonrpc": "2.0", "id": "server", "result": {} }),
                generation,
            )
            .await,
        Err(StreamableHttpError::SessionChanged)
    ));
    assert_eq!(transport.session_id().await, None);
    server.finish().await;
}
