const MAX_TERMINAL_FIELD_CHARACTERS: usize = 2_000;

pub fn safe_field(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars().take(MAX_TERMINAL_FIELD_CHARACTERS) {
        if character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
        {
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    if value.chars().count() > MAX_TERMINAL_FIELD_CHARACTERS {
        output.push_str("...");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_terminal_controls_and_bounds_fields() {
        assert_eq!(
            safe_field("hello\n\u{1b}]52;c;evil\u{7}world"),
            "hello  ]52;c;evil world"
        );
        let long = "x".repeat(MAX_TERMINAL_FIELD_CHARACTERS + 1);
        let safe = safe_field(&long);
        assert!(safe.ends_with("..."));
        assert_eq!(safe.len(), MAX_TERMINAL_FIELD_CHARACTERS + 3);
    }
}
