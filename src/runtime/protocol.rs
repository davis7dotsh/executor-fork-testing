use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ConsoleEntry, RuntimeFailure, RuntimeLimits, ToolResult};

pub(crate) const PROTOCOL_VERSION: u16 = 1;
pub(crate) const FRAME_LIMIT: usize = 18 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ParentMessage {
    Start {
        version: u16,
        generation: u64,
        code: String,
        limits: RuntimeLimits,
    },
    ToolResult {
        version: u16,
        generation: u64,
        call_id: u64,
        result: ToolResult,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkerMessage {
    ToolCall {
        version: u16,
        generation: u64,
        call_id: u64,
        path: String,
        arguments: Value,
    },
    Complete {
        version: u16,
        generation: u64,
        result: Value,
        emits: Vec<Value>,
        console: Vec<ConsoleEntry>,
    },
    Failed {
        version: u16,
        generation: u64,
        failure: RuntimeFailure,
    },
}

pub(crate) fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, RuntimeFailure> {
    let payload = serde_json::to_vec(value)
        .map_err(|_| RuntimeFailure::internal("ipc_encode_failed", "could not encode IPC frame"))?;
    if payload.len() > FRAME_LIMIT {
        return Err(RuntimeFailure::internal(
            "ipc_frame_too_large",
            "IPC frame exceeded its size limit",
        ));
    }
    Ok(payload)
}

pub(crate) async fn write_encoded_frame<W>(
    writer: &mut W,
    payload: &[u8],
) -> Result<usize, RuntimeFailure>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_u32(payload.len() as u32)
        .await
        .map_err(io_failure)?;
    writer.write_all(payload).await.map_err(io_failure)?;
    writer.flush().await.map_err(io_failure)?;
    Ok(payload.len() + 4)
}

pub(crate) async fn read_frame<R, T>(reader: &mut R) -> Result<(T, usize), RuntimeFailure>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let length = reader.read_u32().await.map_err(io_failure)? as usize;
    if length == 0 || length > FRAME_LIMIT {
        return Err(RuntimeFailure::internal(
            "ipc_frame_invalid",
            "IPC frame length was invalid",
        ));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await.map_err(io_failure)?;
    validate_json_structure(&payload)?;
    let value = serde_json::from_slice(&payload).map_err(|_| {
        RuntimeFailure::internal("ipc_frame_invalid", "IPC frame schema was invalid")
    })?;
    Ok((value, length + 4))
}

fn validate_json_structure(payload: &[u8]) -> Result<(), RuntimeFailure> {
    const MAX_JSON_NODES: usize = 250_000;
    const MAX_JSON_DEPTH: usize = 128;

    let mut in_string = false;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut nodes = 1usize;
    for byte in payload {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                nodes += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(invalid_structure());
                }
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or_else(invalid_structure)?;
            }
            b',' => nodes += 1,
            _ => {}
        }
        if nodes > MAX_JSON_NODES {
            return Err(invalid_structure());
        }
    }
    if in_string || depth != 0 {
        return Err(invalid_structure());
    }
    Ok(())
}

fn invalid_structure() -> RuntimeFailure {
    RuntimeFailure::internal("ipc_frame_invalid", "IPC JSON structure was invalid")
}

fn io_failure(_: std::io::Error) -> RuntimeFailure {
    RuntimeFailure::internal("worker_disconnected", "sandbox worker disconnected")
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn rejects_oversized_length_before_reading_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer
            .write_u32((FRAME_LIMIT + 1) as u32)
            .await
            .expect("length should write");
        let error = read_frame::<_, ParentMessage>(&mut reader)
            .await
            .expect_err("oversized frame must fail");
        assert_eq!(error.code, "ipc_frame_invalid");
    }

    #[tokio::test]
    async fn rejects_partial_and_unknown_field_frames() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer.write_u32(10).await.expect("length should write");
        writer.write_all(b"{}").await.expect("payload should write");
        drop(writer);
        assert_eq!(
            read_frame::<_, ParentMessage>(&mut reader)
                .await
                .expect_err("partial frame must fail")
                .code,
            "worker_disconnected"
        );

        let payload =
            br#"{"type":"start","version":1,"generation":1,"code":"","limits":{},"host":"leak"}"#;
        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer
            .write_u32(payload.len() as u32)
            .await
            .expect("length should write");
        writer
            .write_all(payload)
            .await
            .expect("payload should write");
        assert_eq!(
            read_frame::<_, ParentMessage>(&mut reader)
                .await
                .expect_err("unknown field must fail")
                .code,
            "ipc_frame_invalid"
        );
    }

    #[tokio::test]
    async fn rejects_deeply_nested_json() {
        let nested = format!("{}null{}", "[".repeat(256), "]".repeat(256));
        let payload = format!(
            r#"{{"type":"tool_call","version":1,"generation":1,"call_id":1,"path":"safe.path","arguments":{nested}}}"#
        );
        let (mut writer, mut reader) = tokio::io::duplex(payload.len() + 8);
        writer
            .write_u32(payload.len() as u32)
            .await
            .expect("length should write");
        writer
            .write_all(payload.as_bytes())
            .await
            .expect("payload should write");
        assert_eq!(
            read_frame::<_, WorkerMessage>(&mut reader)
                .await
                .expect_err("deep JSON must fail")
                .code,
            "ipc_frame_invalid"
        );
    }

    #[tokio::test]
    async fn rejects_excessively_wide_json_before_deserialization() {
        let arguments = format!("[{}]", "0,".repeat(250_001));
        let payload = format!(
            r#"{{"type":"tool_call","version":1,"generation":1,"call_id":1,"path":"safe.path","arguments":{arguments}}}"#
        );
        let (mut writer, mut reader) = tokio::io::duplex(payload.len() + 8);
        writer
            .write_u32(payload.len() as u32)
            .await
            .expect("length should write");
        writer
            .write_all(payload.as_bytes())
            .await
            .expect("payload should write");
        assert_eq!(
            read_frame::<_, WorkerMessage>(&mut reader)
                .await
                .expect_err("wide JSON must fail")
                .code,
            "ipc_frame_invalid"
        );
    }
}
