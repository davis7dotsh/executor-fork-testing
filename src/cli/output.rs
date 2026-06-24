use std::io::{self, Write};

use serde_json::Value;

use super::terminal::safe_field;

pub fn write_json(mut output: impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)
}

pub fn write_call_human(output: impl Write, value: &Value) -> io::Result<()> {
    if value.get("ok") == Some(&Value::Bool(true))
        && let Some(data) = value.get("data")
    {
        return write_json(output, data);
    }
    write_json(output, value)
}

pub fn write_search_human(mut output: impl Write, value: &Value) -> io::Result<()> {
    let Some(items) = value.get("items").and_then(Value::as_array) else {
        return write_json(output, value);
    };
    if items.is_empty() {
        return writeln!(output, "No tools found.");
    }
    for item in items {
        let path = item
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let approval = item
            .get("requiresApproval")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        writeln!(
            output,
            "{}{}",
            safe_field(path),
            if approval {
                "  [approval required]"
            } else {
                ""
            }
        )?;
        if let Some(description) = item.get("description").and_then(Value::as_str) {
            writeln!(output, "  {}", safe_field(description))?;
        }
    }
    if value
        .get("hasMore")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        writeln!(
            output,
            "More results are available. Use --offset to continue."
        )?;
    }
    Ok(())
}

pub fn write_describe_human(mut output: impl Write, value: &Value) -> io::Result<()> {
    let path = value
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    writeln!(output, "{}", safe_field(path))?;
    if let Some(description) = value.get("description").and_then(Value::as_str) {
        writeln!(output, "{}", safe_field(description))?;
    }
    if let Some(mode) = value.pointer("/effectiveMode/mode").and_then(Value::as_str) {
        writeln!(output, "Mode: {}", safe_field(mode))?;
    }
    if let Some(input) = value.get("inputSchema") {
        writeln!(output, "Input:")?;
        serde_json::to_writer_pretty(&mut output, input)?;
        writeln!(output)?;
    }
    Ok(())
}

pub fn write_sources_human(mut output: impl Write, value: &Value) -> io::Result<()> {
    let Some(sources) = value.get("sources").and_then(Value::as_array) else {
        return write_json(output, value);
    };
    if sources.is_empty() {
        return writeln!(output, "No sources connected.");
    }
    for source in sources {
        let slug = source
            .get("slug")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let display_name = source
            .get("displayName")
            .and_then(Value::as_str)
            .unwrap_or(slug);
        let kind = source
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let count = source.get("toolCount").and_then(Value::as_i64).unwrap_or(0);
        writeln!(
            output,
            "{}  {}  {}  {count} tools",
            safe_field(slug),
            safe_field(display_name),
            safe_field(kind)
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn human_and_json_outputs_are_stable_and_secret_free() {
        let value = json!({
            "items": [{
                "path": "tools.github.issue_create",
                "description": "Create an issue",
                "requiresApproval": true
            }],
            "hasMore": true
        });
        let mut human = Vec::new();
        write_search_human(&mut human, &value).expect("human output");
        let human = String::from_utf8(human).expect("UTF-8");
        assert!(human.contains("tools.github.issue_create  [approval required]"));
        assert!(human.contains("Use --offset"));

        let mut json_output = Vec::new();
        write_json(&mut json_output, &value).expect("JSON output");
        assert_eq!(
            serde_json::from_slice::<Value>(&json_output).expect("valid JSON"),
            value
        );
    }
}
