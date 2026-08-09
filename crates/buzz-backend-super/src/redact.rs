//! Scrubbing for everything this provider says out loud.
//!
//! §Provider Output places the redaction obligation on the *desktop* — it
//! treats all provider output as hostile. This module is the same rule
//! applied one layer earlier, and it is not redundant: this binding echoes
//! remote material (a harness log tail) into its error strings so a failed
//! start is diagnosable, and that material is produced by a process holding
//! the nsec. Redacting at the point where the secret is still in scope is
//! cheaper and more certain than hoping the far side's scrubber has the same
//! value list.

/// Values shorter than this are too collision-prone to blank out — redacting
/// every occurrence of a 3-character env value would shred the message
/// without protecting anything. Same threshold the desktop uses.
const MIN_REDACTABLE: usize = 4;

const PLACEHOLDER: &str = "[redacted]";

/// Prefixes of self-identifying secret tokens, redacted even when the value
/// was never in our env list — a stack trace can carry a key we never sent.
const TOKEN_PREFIXES: [&str; 2] = ["nsec1", "sprt_tok_"];

/// Scrub `text` of every secret in `secrets`, then of any bare secret-shaped
/// token.
///
/// Longest-first ordering is load-bearing: if one secret is a substring of
/// another, replacing the shorter one first leaves the longer one's tail in
/// the clear.
pub fn scrub(text: &str, secrets: &[String]) -> String {
    let mut ordered: Vec<&String> = secrets
        .iter()
        .filter(|s| s.trim().len() >= MIN_REDACTABLE)
        .collect();
    ordered.sort_by_key(|s| std::cmp::Reverse(s.len()));

    let mut out = text.to_string();
    for secret in ordered {
        if out.contains(secret.as_str()) {
            out = out.replace(secret.as_str(), PLACEHOLDER);
        }
    }
    scrub_tokens(&out)
}

/// Blank out anything shaped like a self-identifying secret token.
fn scrub_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    'outer: while !rest.is_empty() {
        for prefix in TOKEN_PREFIXES {
            if let Some(at) = rest.find(prefix) {
                let (before, from_token) = rest.split_at(at);
                // A token runs to the first character that cannot be part of
                // one. bech32 and the token alphabet are both alphanumeric
                // plus `_`, so that is the whole stop set.
                let end = from_token
                    .char_indices()
                    .find(|(i, c)| *i >= prefix.len() && !(c.is_ascii_alphanumeric() || *c == '_'))
                    .map(|(i, _)| i)
                    .unwrap_or(from_token.len());
                // A bare prefix with nothing after it is prose, not a secret.
                if end > prefix.len() {
                    out.push_str(before);
                    out.push_str(PLACEHOLDER);
                    rest = &from_token[end..];
                    continue 'outer;
                }
            }
        }
        out.push_str(rest);
        break;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_secrets() {
        let out = scrub("token=hunter2secret rest", &["hunter2secret".to_string()]);
        assert_eq!(out, "token=[redacted] rest");
    }

    /// The reason ordering is longest-first: a short secret that is a
    /// substring of a long one must not consume it and leave the tail bare.
    #[test]
    fn longest_secret_wins() {
        let out = scrub(
            "value=abcdefgh",
            &["abcd".to_string(), "abcdefgh".to_string()],
        );
        assert_eq!(out, "value=[redacted]");
    }

    #[test]
    fn short_values_are_left_alone() {
        let out = scrub("a=xy and more", &["xy".to_string()]);
        assert_eq!(out, "a=xy and more");
    }

    /// The case this module exists for: a harness log line carrying a key we
    /// never put in the env list.
    #[test]
    fn redacts_unknown_nsec_tokens() {
        let out = scrub(
            "failed to auth with nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9la, retrying",
            &[],
        );
        assert!(!out.contains("nsec1vl029"), "{out}");
        assert!(out.contains("[redacted]"), "{out}");
        assert!(out.contains("retrying"), "{out}");
    }

    #[test]
    fn redacts_multiple_tokens_in_one_line() {
        let out = scrub("a nsec1abcdefgh b sprt_tok_zzzzzz c", &[]);
        assert_eq!(out, "a [redacted] b [redacted] c");
    }

    /// Prose mentioning the prefix is not a secret; blanking it would make
    /// error text mysterious for no gain.
    #[test]
    fn bare_prefix_is_not_a_token() {
        assert_eq!(scrub("set nsec1 in the env", &[]), "set nsec1 in the env");
    }

    #[test]
    fn leaves_clean_text_untouched() {
        let text = "harness exited with status 1";
        assert_eq!(scrub(text, &["unused-value".to_string()]), text);
    }
}
