use std::{fs::File, io::Read, path::Path};

use serde_json::{Map, Value};
use thiserror::Error;

pub const MAX_ARGUMENT_FILE_BYTES: usize = crate::invocation::MAX_ARGUMENT_BYTES;

#[derive(Debug, Error)]
pub enum InputError {
    #[error("could not read arguments from {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("tool arguments exceed the {MAX_ARGUMENT_FILE_BYTES} byte CLI limit")]
    TooLarge,
    #[error("tool arguments are not valid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("tool arguments must be a JSON object")]
    NotObject,
}

pub fn parse_arguments(input: Option<&str>) -> Result<Value, InputError> {
    let Some(input) = input else {
        return Ok(Value::Object(Map::new()));
    };
    let bytes = match input.strip_prefix('@') {
        Some(path) => read_bounded(path)?,
        None => {
            if input.len() > MAX_ARGUMENT_FILE_BYTES {
                return Err(InputError::TooLarge);
            }
            input.as_bytes().to_vec()
        }
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(InputError::InvalidJson)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(InputError::NotObject)
    }
}

fn read_bounded(path: &str) -> Result<Vec<u8>, InputError> {
    if path.is_empty() {
        return Err(InputError::Read {
            path: path.to_owned(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "the @file path is empty",
            ),
        });
    }
    let mut file = File::open(Path::new(path)).map_err(|source| InputError::Read {
        path: path.to_owned(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_ARGUMENT_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| InputError::Read {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() > MAX_ARGUMENT_FILE_BYTES {
        return Err(InputError::TooLarge);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;

    use super::*;

    #[test]
    fn parses_inline_file_and_default_objects() {
        assert_eq!(parse_arguments(None).expect("default"), json!({}));
        assert_eq!(
            parse_arguments(Some(r#"{"message":"hello"}"#)).expect("inline"),
            json!({"message": "hello"})
        );
        let mut file = tempfile::NamedTempFile::new().expect("temporary file");
        file.write_all(br#"{"from":"file"}"#).expect("write");
        let argument = format!("@{}", file.path().display());
        assert_eq!(
            parse_arguments(Some(&argument)).expect("file"),
            json!({"from": "file"})
        );
    }

    #[test]
    fn rejects_invalid_non_object_and_oversized_inputs() {
        assert!(matches!(
            parse_arguments(Some("{")),
            Err(InputError::InvalidJson(_))
        ));
        assert!(matches!(
            parse_arguments(Some("[]")),
            Err(InputError::NotObject)
        ));
        let oversized = "x".repeat(MAX_ARGUMENT_FILE_BYTES + 1);
        assert!(matches!(
            parse_arguments(Some(&oversized)),
            Err(InputError::TooLarge)
        ));
    }

    #[test]
    fn rejects_oversized_files_without_unbounded_reads() {
        let mut file = tempfile::NamedTempFile::new().expect("temporary file");
        file.write_all(&vec![b'x'; MAX_ARGUMENT_FILE_BYTES + 1])
            .expect("write");
        let argument = format!("@{}", file.path().display());
        assert!(matches!(
            parse_arguments(Some(&argument)),
            Err(InputError::TooLarge)
        ));
    }
}
