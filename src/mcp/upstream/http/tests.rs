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
async fn initialization_negotiates_legacy_and_pins_followup_headers() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "serverInfo": { "name": "legacy", "version": "1" }
        }
    })
    .to_string();
    let tools = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": { "tools": [] }
    })
    .to_string();
    let server = TestServer::start(vec![
        response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", "legacy-session"),
            ],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response("200 OK", &[("Content-Type", "application/json")], &tools),
        response("204 No Content", &[], ""),
    ])
    .await;
    let transport = make_transport(server.endpoint.clone());

    transport
        .initialize()
        .await
        .expect("legacy protocol negotiation succeeds");
    transport
        .list_tools(None, json!(1))
        .await
        .expect("legacy tools list succeeds");
    transport
        .terminate()
        .await
        .expect("legacy session termination succeeds");

    let requests = server.finish().await;
    assert!(requests[0].contains("\"protocolVersion\":\"2025-11-25\""));
    assert!(
        !requests[0]
            .to_ascii_lowercase()
            .contains("mcp-protocol-version:")
    );
    for request in &requests[1..] {
        let request = request.to_ascii_lowercase();
        assert!(request.contains("mcp-session-id: legacy-session"));
        assert!(request.contains("mcp-protocol-version: 2025-06-18"));
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
async fn call_tool_rejects_malformed_success_results() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    let valid = json!({
        "content": [],
        "structuredContent": { "status": "ok" },
        "isError": false
    });
    let malformed = [
        json!({ "content": "not-an-array" }),
        json!({ "content": [{ "text": "missing content type" }] }),
        json!({ "unexpected": true }),
        json!({ "content": [], "structuredContent": "not-an-object" }),
        json!({ "content": [], "structuredContent": [] }),
        json!({ "content": [], "structuredContent": null }),
    ];
    let mut responses = vec![
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &initialize,
        ),
        response("202 Accepted", &[], ""),
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &json!({ "jsonrpc": "2.0", "id": 1, "result": valid.clone() }).to_string(),
        ),
    ];
    responses.extend(malformed.iter().enumerate().map(|(index, result)| {
        response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &json!({ "jsonrpc": "2.0", "id": index + 2, "result": result }).to_string(),
        )
    }));
    let server = TestServer::start(responses).await;
    let transport = make_transport(server.endpoint.clone());
    transport
        .initialize()
        .await
        .expect("initialization succeeds");

    let result = transport
        .call_tool("valid", json!({}), json!(1))
        .await
        .expect("object structured content is valid");
    assert_eq!(result, valid);
    for (index, _) in malformed.iter().enumerate() {
        assert!(matches!(
            transport
                .call_tool("invalid", json!({}), json!(index + 2))
                .await,
            Err(StreamableHttpError::InvalidResponse)
        ));
    }
    server.finish().await;
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
async fn initialization_header_conflicts_delete_the_issued_session_once() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-11-25", "capabilities": {} }
    })
    .to_string();
    for notification_headers in [
        vec![("Mcp-Session-Id", "session-b")],
        vec![
            ("Mcp-Session-Id", "session-a"),
            ("Mcp-Session-Id", "session-a"),
        ],
    ] {
        let server = TestServer::start(vec![
            response(
                "200 OK",
                &[
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", "session-a"),
                ],
                &initialize,
            ),
            response("202 Accepted", &notification_headers, ""),
            response("204 No Content", &[], ""),
        ])
        .await;
        let transport = make_transport(server.endpoint.clone());

        assert!(matches!(
            transport.initialize().await,
            Err(StreamableHttpError::SessionChanged | StreamableHttpError::InvalidSessionId)
        ));
        assert_eq!(transport.session_id().await, None);
        let requests = server.finish().await;
        assert_eq!(requests.len(), 3);
        assert!(requests[2].starts_with("DELETE /mcp HTTP/1.1"));
        assert!(
            requests[2]
                .to_ascii_lowercase()
                .contains("mcp-session-id: session-a")
        );
    }
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
async fn aborted_termination_keeps_cleanup_owned_until_delete_finishes() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("listener has an address")
    );
    let (delete_started_tx, delete_started_rx) = tokio::sync::oneshot::channel();
    let (release_delete_tx, release_delete_rx) = tokio::sync::oneshot::channel();
    let (retry_seen_tx, mut retry_seen_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut delete, _) = listener.accept().await.expect("DELETE accepts");
        let mut request = vec![0_u8; 8192];
        let read = delete.read(&mut request).await.expect("DELETE reads");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("DELETE /mcp HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("mcp-session-id: abort-owned")
        );
        delete_started_tx.send(()).expect("DELETE start signals");
        let delete_response = tokio::spawn(async move {
            release_delete_rx.await.expect("DELETE release signals");
            delete
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("DELETE response writes after caller cancellation");
        });

        let (mut retry, _) = listener.accept().await.expect("retry initialize accepts");
        retry_seen_tx.send(()).expect("retry signal sends");
        let mut request = vec![0_u8; 8192];
        let read = retry
            .read(&mut request)
            .await
            .expect("retry initialize reads");
        assert!(String::from_utf8_lossy(&request[..read]).starts_with("POST /mcp HTTP/1.1"));
        retry
            .write_all(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("retry error response writes");
        delete_response.await.expect("DELETE responder joins");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "caller cancellation must not duplicate DELETE"
        );
    });
    let transport = make_transport(endpoint);
    {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.session_id = Some("abort-owned".to_owned());
        state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
    }
    let terminating = {
        let transport = transport.clone();
        tokio::spawn(async move { transport.terminate().await })
    };
    delete_started_rx.await.expect("DELETE reaches server");
    terminating.abort();
    assert!(
        terminating
            .await
            .expect_err("terminate task is aborted")
            .is_cancelled()
    );
    let retry = {
        let transport = transport.clone();
        tokio::spawn(async move { transport.initialize().await })
    };
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut retry_seen_rx)
            .await
            .is_err(),
        "initialize stays gated while the owned DELETE is pending"
    );
    release_delete_tx.send(()).expect("DELETE releases");
    tokio::time::timeout(std::time::Duration::from_secs(1), retry_seen_rx)
        .await
        .expect("initialize reaches server after DELETE")
        .expect("retry signal arrives");
    assert!(matches!(
        retry.await.expect("retry task joins"),
        Err(StreamableHttpError::HttpStatus(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        ))
    ));
    server.await.expect("cancellation server joins");
}

#[tokio::test]
async fn old_and_unknown_protocol_versions_discard_the_server_session() {
    for (protocol_version, session_id) in [
        ("2025-03-26", "old-session"),
        ("2099-01-01", "unknown-session"),
    ] {
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "result": { "protocolVersion": protocol_version, "capabilities": {} }
        })
        .to_string();
        let server = TestServer::start(vec![
            response(
                "200 OK",
                &[
                    ("Content-Type", "application/json"),
                    ("Mcp-Session-Id", session_id),
                ],
                &initialize,
            ),
            response("204 No Content", &[], ""),
        ])
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
        let requests = server.finish().await;
        assert_eq!(requests.len(), 2);
        let cleanup = requests[1].to_ascii_lowercase();
        assert!(cleanup.starts_with("delete /mcp http/1.1"));
        assert!(cleanup.contains(&format!("mcp-session-id: {session_id}")));
        assert!(cleanup.contains("mcp-protocol-version: 2025-11-25"));
    }
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
    let (delete_tx, delete_rx) = tokio::sync::oneshot::channel();
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
        let (mut cleanup, _) = listener.accept().await.expect("cleanup DELETE is accepted");
        let mut request = vec![0_u8; 8192];
        let read = cleanup
            .read(&mut request)
            .await
            .expect("cleanup DELETE is read");
        cleanup
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("cleanup DELETE response writes");
        delete_tx
            .send(String::from_utf8_lossy(&request[..read]).into_owned())
            .expect("cleanup request signal sends");
    });
    let transport = make_transport(endpoint);
    let initializing = {
        let transport = transport.clone();
        tokio::spawn(async move { transport.initialize().await })
    };
    headers_rx.await.expect("initialize headers arrive");
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while transport.session_id().await.as_deref() != Some("provisional") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("provisional session is recorded");
    initializing.abort();
    let _ = initializing.await;

    let delete = tokio::time::timeout(std::time::Duration::from_secs(1), delete_rx)
        .await
        .expect("cleanup DELETE arrives")
        .expect("cleanup request is captured");
    assert!(delete.starts_with("DELETE /mcp HTTP/1.1"));
    assert!(
        delete
            .to_ascii_lowercase()
            .contains("mcp-session-id: provisional")
    );

    {
        let state = transport.lock_state();
        assert!(!state.initialized);
        assert_eq!(state.session_id, None);
        assert_eq!(state.negotiated_protocol_version, None);
    }
    transport
        .terminate()
        .await
        .expect("already cleaned transport terminates without another DELETE");
    server.await.expect("cleanup server completes");
}

#[tokio::test]
async fn failed_initializations_do_not_accumulate_server_sessions() {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-03-26", "capabilities": {} }
    })
    .to_string();
    let mut responses = Vec::new();
    for index in 0..3 {
        responses.push(response(
            "200 OK",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &format!("ledger-{index}")),
            ],
            &initialize,
        ));
        responses.push(response("204 No Content", &[], ""));
    }
    let server = TestServer::start(responses).await;
    let transport = make_transport(server.endpoint.clone());

    for _ in 0..3 {
        assert!(matches!(
            transport.initialize().await,
            Err(StreamableHttpError::ProtocolVersionMismatch)
        ));
    }

    let requests = server.finish().await;
    assert_eq!(requests.len(), 6);
    for (index, pair) in requests.chunks_exact(2).enumerate() {
        assert!(pair[0].starts_with("POST /mcp HTTP/1.1"));
        assert!(pair[1].starts_with("DELETE /mcp HTTP/1.1"));
        assert!(
            pair[1]
                .to_ascii_lowercase()
                .contains(&format!("mcp-session-id: ledger-{index}"))
        );
    }
}

#[tokio::test]
async fn initialization_retry_waits_for_the_previous_session_delete() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("listener has an address")
    );
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "protocolVersion": "2025-03-26", "capabilities": {} }
    })
    .to_string();
    let (delete_started_tx, delete_started_rx) = tokio::sync::oneshot::channel();
    let (release_delete_tx, release_delete_rx) = tokio::sync::oneshot::channel();
    let (retry_seen_tx, mut retry_seen_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut delete, _) = listener.accept().await.expect("first DELETE accepts");
        let mut request = vec![0_u8; 8192];
        let read = delete.read(&mut request).await.expect("first DELETE reads");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("DELETE /mcp HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("mcp-session-id: ledger-first")
        );
        delete_started_tx.send(()).expect("DELETE start signals");
        let delete_response = tokio::spawn(async move {
            release_delete_rx.await.expect("DELETE release signals");
            delete
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("first DELETE response writes");
        });

        {
            let (mut stream, _) = listener.accept().await.expect("retry initialize accepts");
            retry_seen_tx.send(()).expect("retry signal sends");
            let mut request = vec![0_u8; 8192];
            let read = stream
                .read(&mut request)
                .await
                .expect("retry initialize reads");
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("POST /mcp HTTP/1.1"));
            stream
                .write_all(
                    response(
                        "200 OK",
                        &[
                            ("Content-Type", "application/json"),
                            ("Mcp-Session-Id", "ledger-second"),
                        ],
                        &initialize,
                    )
                    .as_bytes(),
                )
                .await
                .expect("retry initialize response writes");
        }
        delete_response.await.expect("first DELETE responder joins");

        let (mut cleanup, _) = listener.accept().await.expect("second DELETE accepts");
        let mut request = vec![0_u8; 8192];
        let read = cleanup
            .read(&mut request)
            .await
            .expect("second DELETE reads");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("DELETE /mcp HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("mcp-session-id: ledger-second")
        );
        cleanup
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("second DELETE response writes");
    });
    let transport = make_transport(endpoint);
    let generation = {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.session_id = Some("ledger-first".to_owned());
        state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
        state.generation
    };
    let interleave = Arc::new(super::InitializationCleanupInterleave::default());
    *transport
        .initialization_cleanup_interleave
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(interleave.clone());
    let retry = {
        let transport = transport.clone();
        tokio::spawn(async move { transport.initialize().await })
    };
    interleave.drained.notified().await;
    let changed_headers = [(super::MCP_SESSION_ID, "listener-changed".parse().unwrap())]
        .into_iter()
        .collect();
    assert!(matches!(
        transport
            .accept_response_session_or_reset(&changed_headers, generation, false)
            .await,
        Err(StreamableHttpError::SessionChanged)
    ));
    delete_started_rx.await.expect("first DELETE starts");
    interleave.resume.notify_one();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut retry_seen_rx)
            .await
            .is_err(),
        "retry must not allocate a session while DELETE is pending"
    );
    release_delete_tx.send(()).expect("first DELETE releases");
    tokio::time::timeout(std::time::Duration::from_secs(1), retry_seen_rx)
        .await
        .expect("retry reaches server after DELETE")
        .expect("retry signal arrives");
    assert!(matches!(
        retry.await.expect("retry task joins"),
        Err(StreamableHttpError::ProtocolVersionMismatch)
    ));
    server.await.expect("session ledger server joins");
}

#[tokio::test]
async fn listener_invalidation_and_terminate_share_one_delete_owner() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let endpoint = format!(
        "http://{}/mcp",
        listener.local_addr().expect("listener has an address")
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("DELETE accepts");
        let mut request = vec![0_u8; 8192];
        let read = stream.read(&mut request).await.expect("DELETE reads");
        let request = String::from_utf8_lossy(&request[..read]).into_owned();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("DELETE response writes");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "only one path may issue DELETE"
        );
        request
    });
    let transport = make_transport(endpoint);
    let generation = {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.session_id = Some("shared-owner".to_owned());
        state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
        state.generation
    };
    let start = Arc::new(tokio::sync::Barrier::new(3));
    let listener_invalidation = {
        let transport = transport.clone();
        let start = start.clone();
        tokio::spawn(async move {
            let headers = [(super::MCP_SESSION_ID, "changed".parse().unwrap())]
                .into_iter()
                .collect();
            start.wait().await;
            transport
                .accept_response_session_or_reset(&headers, generation, false)
                .await
        })
    };
    let termination = {
        let transport = transport.clone();
        let start = start.clone();
        tokio::spawn(async move {
            start.wait().await;
            transport.terminate().await
        })
    };
    start.wait().await;

    assert!(matches!(
        listener_invalidation
            .await
            .expect("listener invalidation joins"),
        Err(StreamableHttpError::SessionChanged | StreamableHttpError::SessionInvalidated)
    ));
    termination
        .await
        .expect("termination joins")
        .expect("termination succeeds");
    let request = server.await.expect("DELETE server joins");
    assert!(request.starts_with("DELETE /mcp HTTP/1.1"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("mcp-session-id: shared-owner")
    );
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
fn only_https_and_loopback_http_endpoints_pass_transport_policy() {
    for endpoint in [
        "https://example.com/mcp",
        "https://10.0.0.1/mcp",
        "http://127.0.0.1:1/mcp",
        "http://[::1]:1/mcp",
        "http://localhost:1/mcp",
        "http://service.localhost:1/mcp",
        "http://LOCALHOST.:1/mcp",
    ] {
        let mut config = StreamableHttpConfig::new(endpoint);
        config.allow_private_networks = true;
        assert!(
            StreamableHttpTransport::new(config).is_ok(),
            "{endpoint} should be allowed"
        );
    }

    for endpoint in [
        "http://example.com/mcp",
        "http://10.0.0.1/mcp",
        "http://0.0.0.0/mcp",
    ] {
        let mut config = StreamableHttpConfig::new(endpoint);
        config.allow_private_networks = true;
        assert!(matches!(
            StreamableHttpTransport::new(config),
            Err(StreamableHttpError::InsecureEndpoint)
        ));
    }
}

#[tokio::test]
async fn insecure_static_credentials_are_rejected_without_a_request() {
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .expect("test listener binds");
    let endpoint = format!(
        "http://0.0.0.0:{}/mcp",
        listener
            .local_addr()
            .expect("listener has an address")
            .port()
    );
    let mut config = StreamableHttpConfig::new(endpoint);
    config.allow_private_networks = true;
    config.headers.insert(
        reqwest::header::AUTHORIZATION,
        "Bearer static-secret".parse().unwrap(),
    );

    assert!(matches!(
        StreamableHttpTransport::new(config),
        Err(StreamableHttpError::InsecureEndpoint)
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "insecure configuration must make zero requests"
    );
}

#[tokio::test]
async fn endpoint_recheck_blocks_managed_credentials_before_init_and_dispatch() {
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .expect("test listener binds");
    let insecure_endpoint = format!(
        "http://0.0.0.0:{}/mcp",
        listener
            .local_addr()
            .expect("listener has an address")
            .port()
    );
    let mut transport = make_transport("http://127.0.0.1:1/mcp".to_owned());
    transport.endpoint = insecure_endpoint.parse().expect("test endpoint parses");
    transport.headers.insert(
        reqwest::header::AUTHORIZATION,
        "Bearer managed-secret".parse().unwrap(),
    );

    assert!(matches!(
        transport.initialize().await,
        Err(StreamableHttpError::InsecureEndpoint)
    ));
    {
        let mut state = transport.lock_state();
        state.initialized = true;
        state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
    }
    assert!(matches!(
        transport.call_tool("blocked", json!({}), json!(1)).await,
        Err(StreamableHttpError::InsecureEndpoint)
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "endpoint rechecks must make zero requests"
    );
}

#[tokio::test]
async fn poisoned_localhost_resolution_blocks_static_and_managed_credentials() {
    let route = std::net::UdpSocket::bind("0.0.0.0:0").expect("route probe binds");
    route
        .connect("192.0.2.1:9")
        .expect("route probe selects an interface");
    let target_ip = route.local_addr().expect("route has an address").ip();
    assert!(!target_ip.is_loopback());
    let target = TcpListener::bind(std::net::SocketAddr::new(target_ip, 0))
        .await
        .expect("non-loopback target binds");
    let endpoint = format!(
        "http://poison.localhost:{}/mcp",
        target.local_addr().expect("target has an address").port()
    );
    let poisoned_addresses = vec![target_ip, "8.8.8.8".parse().expect("public IP parses")];

    let mut static_config = StreamableHttpConfig::new(endpoint.clone());
    static_config.allow_private_networks = true;
    static_config.headers.insert(
        reqwest::header::AUTHORIZATION,
        "Bearer static-secret".parse().unwrap(),
    );
    let mut static_transport = StreamableHttpTransport::new(static_config)
        .expect("localhost-like URL is syntactically valid");
    static_transport.client = static_transport
        .client
        .clone()
        .with_test_dns_resolution("poison.localhost", poisoned_addresses.clone());
    assert!(matches!(
        static_transport.initialize().await,
        Err(StreamableHttpError::Outbound(
            crate::outbound::OutboundError::InsecureTransport
        ))
    ));

    let mut managed_config = StreamableHttpConfig::new(endpoint);
    managed_config.allow_private_networks = true;
    managed_config.headers.insert(
        reqwest::header::AUTHORIZATION,
        "Bearer managed-secret".parse().unwrap(),
    );
    let mut managed_transport = StreamableHttpTransport::new(managed_config)
        .expect("localhost-like managed URL is syntactically valid");
    managed_transport.client = managed_transport
        .client
        .clone()
        .with_test_dns_resolution("poison.localhost", poisoned_addresses);
    {
        let mut state = managed_transport.lock_state();
        state.initialized = true;
        state.negotiated_protocol_version = Some(rmcp::model::ProtocolVersion::V_2025_11_25);
    }
    assert!(matches!(
        managed_transport
            .call_tool("blocked", json!({}), json!(1))
            .await,
        Err(StreamableHttpError::Outbound(
            crate::outbound::OutboundError::InsecureTransport
        ))
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), target.accept())
            .await
            .is_err(),
        "poisoned localhost target must receive zero credentialed requests"
    );
}

#[tokio::test]
async fn localhost_name_resolving_to_loopback_remains_allowed() {
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
    ])
    .await;
    let port = url::Url::parse(&server.endpoint)
        .expect("server endpoint parses")
        .port()
        .expect("server endpoint has a port");
    let mut config = StreamableHttpConfig::new(format!("http://safe.localhost:{port}/mcp"));
    config.allow_private_networks = true;
    let mut transport =
        StreamableHttpTransport::new(config).expect("localhost-like endpoint is valid");
    transport.client = transport.client.clone().with_test_dns_resolution(
        "safe.localhost",
        vec!["127.0.0.1".parse().expect("loopback IP parses")],
    );

    transport
        .initialize()
        .await
        .expect("resolved loopback HTTP initializes");
    assert_eq!(server.finish().await.len(), 2);
}

#[tokio::test]
async fn credentialed_redirects_are_not_followed() {
    let redirect_target = TcpListener::bind("0.0.0.0:0")
        .await
        .expect("redirect target binds");
    let location = format!(
        "http://0.0.0.0:{}/credential-sink",
        redirect_target
            .local_addr()
            .expect("redirect target has an address")
            .port()
    );
    let server =
        TestServer::start(vec![response("302 Found", &[("Location", &location)], "")]).await;
    let mut transport = make_transport(server.endpoint.clone());
    transport.headers.insert(
        reqwest::header::AUTHORIZATION,
        "Bearer redirect-secret".parse().unwrap(),
    );

    assert!(matches!(
        transport.initialize().await,
        Err(StreamableHttpError::HttpStatus(reqwest::StatusCode::FOUND))
    ));
    let requests = server.finish().await;
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer redirect-secret")
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            redirect_target.accept()
        )
        .await
        .is_err(),
        "redirect target must receive zero requests"
    );
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
