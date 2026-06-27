use std::collections::{BTreeSet, HashSet};

use super::{DiscoveryPage, ToolDiscoveryResult, ToolSummary};

const PATH_WEIGHT: i64 = 12;
const INTEGRATION_WEIGHT: i64 = 8;
const NAME_WEIGHT: i64 = 10;
const DESCRIPTION_WEIGHT: i64 = 5;
const MAX_GENERATED_TRIGRAM_TERMS: usize = 1_024;

pub(super) struct CandidateExpressions {
    pub(super) word: String,
    pub(super) trigram: Option<String>,
    pub(super) short_bigram: Option<String>,
    pub(super) short_unigram: String,
}

pub(super) fn candidate_expressions(query: &str) -> Option<CandidateExpressions> {
    let mut tokens = tokenize(query);
    tokens.sort_unstable();
    tokens.dedup();
    if tokens.is_empty() {
        return None;
    }

    let word = tokens
        .iter()
        .map(|token| format!(r#""{token}"*"#))
        .collect::<Vec<_>>()
        .join(" OR ");
    let mut trigram_terms = BTreeSet::new();
    let mut bigram_terms = BTreeSet::new();
    let mut unigram_terms = BTreeSet::new();
    for token in &tokens {
        let bytes = token.as_bytes();
        if let Some(first) = bytes.first() {
            unigram_terms.insert(encode_short_gram(std::slice::from_ref(first)));
        }
        if bytes.len() >= 2 {
            bigram_terms.insert(encode_short_gram(&bytes[..2]));
        }
        for end in 3..=bytes.len() {
            if trigram_terms.len() == MAX_GENERATED_TRIGRAM_TERMS {
                break;
            }
            trigram_terms.insert(token[..end].to_owned());
        }
    }

    Some(CandidateExpressions {
        word,
        trigram: quoted_terms(trigram_terms),
        short_bigram: quoted_terms(bigram_terms),
        short_unigram: quoted_terms(unigram_terms).expect("a nonempty search token has a unigram"),
    })
}

pub(super) fn namespace_prefix(namespace: Option<&str>) -> Option<String> {
    let tokens = tokenize(namespace?);
    (!tokens.is_empty()).then(|| tokens.join(" "))
}

pub(super) fn normalize_for_index(value: &str) -> String {
    normalize(value)
}

pub(super) fn query_tokens(value: &str) -> Vec<String> {
    tokenize(value)
}

pub(super) fn short_gram_document(values: &[&str]) -> String {
    let mut grams = BTreeSet::new();
    for value in values {
        for token in tokenize(value) {
            let bytes = token.as_bytes();
            for byte in bytes {
                grams.insert(encode_short_gram(std::slice::from_ref(byte)));
            }
            for gram in bytes.windows(2) {
                grams.insert(encode_short_gram(gram));
            }
        }
    }
    grams.into_iter().collect::<Vec<_>>().join(" ")
}

fn quoted_terms(terms: BTreeSet<String>) -> Option<String> {
    (!terms.is_empty()).then(|| {
        terms
            .into_iter()
            .map(|term| format!(r#""{term}""#))
            .collect::<Vec<_>>()
            .join(" OR ")
    })
}

fn encode_short_gram(gram: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(2 + gram.len() * 2);
    encoded.push('g');
    encoded.push(char::from(b'0' + gram.len() as u8));
    for byte in gram {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

struct PreparedField {
    raw: String,
    tokens: Vec<String>,
}

struct FieldScore {
    score: i64,
    matched_tokens: HashSet<String>,
    exact_phrase_match: bool,
}

pub(super) fn search(
    tools: &[ToolSummary],
    query: &str,
    namespace: Option<&str>,
    limit: usize,
    offset: usize,
) -> DiscoveryPage {
    let normalized_query = normalize(query);
    let query_tokens = tokenize(query);
    if normalized_query.is_empty() || query_tokens.is_empty() {
        return DiscoveryPage {
            items: Vec::new(),
            total: 0,
            has_more: false,
            next_offset: None,
        };
    }

    let mut ranked = tools
        .iter()
        .filter(|tool| namespace_matches(tool, namespace))
        .filter_map(|tool| score_tool(tool, &normalized_query, &query_tokens))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.path.cmp(&right.path))
    });

    let total = ranked.len();
    let start = offset.min(total);
    let items = ranked
        .into_iter()
        .skip(start)
        .take(limit)
        .collect::<Vec<_>>();
    let consumed = start + items.len();
    let has_more = consumed < total;
    DiscoveryPage {
        items,
        total,
        has_more,
        next_offset: has_more.then_some(consumed),
    }
}

fn score_tool(
    tool: &ToolSummary,
    normalized_query: &str,
    query_tokens: &[String],
) -> Option<ToolDiscoveryResult> {
    let path = prepare(&tool.sandbox_path);
    let integration = prepare(&tool.source_slug);
    let name = prepare(&tool.local_name);
    let description = prepare(tool.description.as_deref().unwrap_or_default());
    let fields = [
        score_field(normalized_query, query_tokens, &path, PATH_WEIGHT),
        score_field(
            normalized_query,
            query_tokens,
            &integration,
            INTEGRATION_WEIGHT,
        ),
        score_field(normalized_query, query_tokens, &name, NAME_WEIGHT),
        score_field(
            normalized_query,
            query_tokens,
            &description,
            DESCRIPTION_WEIGHT,
        ),
    ];

    let mut score = 0_i64;
    let mut matched_tokens = HashSet::new();
    let mut exact_phrase_match = false;
    for field in fields {
        score += field.score;
        exact_phrase_match |= field.exact_phrase_match;
        matched_tokens.extend(field.matched_tokens);
    }
    if matched_tokens.is_empty() {
        return None;
    }

    let coverage = matched_tokens.len() as f64 / query_tokens.len() as f64;
    let minimum_coverage = if query_tokens.len() <= 2 { 1.0 } else { 0.6 };
    if coverage < minimum_coverage && !exact_phrase_match {
        return None;
    }
    if coverage == 1.0 {
        score += 25;
    } else {
        score += (coverage * 10.0).round() as i64;
    }
    if path.tokens.first() == query_tokens.first() || name.tokens.first() == query_tokens.first() {
        score += 8;
    }
    if path.raw == normalized_query || name.raw == normalized_query {
        score += 20;
    }

    Some(ToolDiscoveryResult {
        path: tool.sandbox_path.clone(),
        name: tool.local_name.clone(),
        description: tool.description.clone(),
        integration: tool.source_slug.clone(),
        score,
        effective_mode: tool.effective_mode.mode,
        requires_approval: tool.effective_mode.mode == super::ToolMode::Ask,
    })
}

fn score_field(
    query: &str,
    query_tokens: &[String],
    field: &PreparedField,
    weight: i64,
) -> FieldScore {
    if field.raw.is_empty() {
        return FieldScore {
            score: 0,
            matched_tokens: HashSet::new(),
            exact_phrase_match: false,
        };
    }

    let mut score = 0_i64;
    let mut matched_tokens = HashSet::new();
    let exact_phrase_match = !query.is_empty() && field.raw.contains(query);
    if !query.is_empty() {
        if field.raw == query {
            score += weight * 14;
        } else if field.raw.starts_with(query) {
            score += weight * 9;
        } else if exact_phrase_match {
            score += weight * 6;
        }
    }

    for token in query_tokens {
        if field.tokens.contains(token) {
            score += weight * 4;
            matched_tokens.insert(token.clone());
        } else if field
            .tokens
            .iter()
            .any(|candidate| candidate.starts_with(token) || token.starts_with(candidate))
        {
            score += weight * 2;
            matched_tokens.insert(token.clone());
        } else if field.raw.contains(token) {
            score += weight;
            matched_tokens.insert(token.clone());
        }
    }

    FieldScore {
        score,
        matched_tokens,
        exact_phrase_match,
    }
}

fn namespace_matches(tool: &ToolSummary, namespace: Option<&str>) -> bool {
    let Some(namespace) = namespace else {
        return true;
    };
    if normalize(namespace).is_empty() {
        return true;
    }
    let namespace_tokens = tokenize(namespace);
    if namespace_tokens.is_empty() {
        return true;
    }

    prefix_matches(&tokenize(&tool.source_slug), &namespace_tokens)
        || prefix_matches(&tokenize(&tool.sandbox_path), &namespace_tokens)
}

fn prefix_matches(candidate: &[String], prefix: &[String]) -> bool {
    prefix
        .iter()
        .enumerate()
        .all(|(index, token)| candidate.get(index) == Some(token))
}

fn prepare(value: &str) -> PreparedField {
    PreparedField {
        raw: normalize(value),
        tokens: tokenize(value),
    }
}

fn tokenize(value: &str) -> Vec<String> {
    normalize(value)
        .split(|character: char| !character.is_ascii_lowercase() && !character.is_ascii_digit())
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

fn normalize(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut previous: Option<char> = None;
    let mut separator_run = false;
    for character in value.chars() {
        if character.is_ascii_uppercase()
            && previous
                .is_some_and(|previous| previous.is_ascii_lowercase() || previous.is_ascii_digit())
        {
            normalized.push(' ');
        }
        if matches!(character, '_' | '.' | '/' | ':' | '-') {
            if !separator_run {
                normalized.push(' ');
            }
            separator_run = true;
        } else {
            normalized.extend(character.to_lowercase());
            separator_run = false;
        }
        previous = Some(character);
    }
    normalized.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_expressions, namespace_prefix, normalize, short_gram_document, tokenize,
    };

    #[test]
    fn normalization_matches_the_typescript_catalog_rules() {
        assert_eq!(normalize("getHTTP/User-ID"), "get http user id");
        assert_eq!(
            tokenize("GitHub.getRepo:v2"),
            ["git", "hub", "get", "repo", "v2"]
        );
    }

    #[test]
    fn sql_candidate_terms_are_normalized_and_escaped_as_tokens() {
        let expressions = candidate_expressions("GetRepo repo").expect("tokens should compile");
        assert_eq!(expressions.word, r#""get"* OR "repo"*"#);
        assert_eq!(
            expressions.trigram.as_deref(),
            Some(r#""get" OR "rep" OR "repo""#)
        );
        assert_eq!(
            expressions.short_bigram.as_deref(),
            Some(r#""g26765" OR "g27265""#)
        );
        assert_eq!(expressions.short_unigram, r#""g167" OR "g172""#);
        assert_eq!(
            namespace_prefix(Some("GitHub/GetRepo")),
            Some("git hub get repo".to_owned())
        );
        assert!(candidate_expressions("---").is_none());
        assert_eq!(namespace_prefix(Some("---")), None);
        assert!(short_gram_document(&["github"]).contains("g26974"));
    }
}
