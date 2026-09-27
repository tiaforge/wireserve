//! Reading and editing `/etc/wireserve/coordinator.env` without disturbing
//! anything the installer was not asked about.
//!
//! The file is the operator's as much as the installer's: it may hold
//! settings nobody asked about, comments, or a value the operator set by
//! hand. So an edit only ever touches the keys it is given. A key being set
//! replaces its line where it stands, a key being cleared is commented out
//! rather than removed, and every other line comes back byte for byte.

/// What to do with one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Set(String),
    /// Comment out any active line for the key, so the coordinator's own
    /// default applies again and the old value stays visible.
    Clear,
}

/// The heading the installer puts above keys it had to append.
const APPENDED_HEADING: &str = "# ---- Set by `wireserve-coordinator install` ----";

/// The value of `key` in env-file text, as systemd reads it: the last
/// active `KEY=value` line wins.
#[must_use]
pub fn get(text: &str, key: &str) -> Option<String> {
    text.lines().filter_map(|line| active_value(line, key)).next_back().map(str::to_string)
}

/// `value` when `line` is an active (not commented) assignment to `key`.
fn active_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(key)?;
    rest.strip_prefix('=').map(str::trim)
}

/// Applies `changes` to `text`. A set key replaces every active line for it
/// in place (there is normally one); one that has no line yet is appended
/// at the end, under a heading. A cleared key has each active line commented
/// out. Everything else is kept exactly.
#[must_use]
pub fn apply(text: &str, changes: &[(&str, Change)]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for line in text.lines() {
        let hit = changes.iter().find(|(key, _)| active_value(line, key).is_some());
        match hit {
            Some((key, Change::Set(value))) => {
                seen.push(key);
                out.push(format!("{key}={value}"));
            }
            Some((_, Change::Clear)) => out.push(format!("# {}", line.trim_start())),
            None => out.push(line.to_string()),
        }
    }
    let missing: Vec<String> = changes
        .iter()
        .filter_map(|(key, change)| match change {
            Change::Set(value) if !seen.contains(key) => Some(format!("{key}={value}")),
            _ => None,
        })
        .collect();
    if !missing.is_empty() {
        if !out.iter().any(|l| l == APPENDED_HEADING) {
            if out.last().is_some_and(|l| !l.trim().is_empty()) {
                out.push(String::new());
            }
            out.push(APPENDED_HEADING.to_string());
        }
        out.extend(missing);
    }
    let mut joined = out.join("\n");
    joined.push('\n');
    joined
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_reads_the_last_active_assignment_and_ignores_comments() {
        let text = "# WIRESERVE_LISTEN_ADDR=1.1.1.1:1\nWIRESERVE_LISTEN_ADDR=127.0.0.1:1\n  WIRESERVE_LISTEN_ADDR = x\nWIRESERVE_LISTEN_ADDR=127.0.0.1:2\n";
        assert_eq!(get(text, "WIRESERVE_LISTEN_ADDR").as_deref(), Some("127.0.0.1:2"));
        assert_eq!(get(text, "WIRESERVE_LISTEN"), None, "a prefix of a key is not the key");
        assert_eq!(get("", "X"), None);
    }

    #[test]
    fn a_set_key_is_replaced_where_it_stands() {
        let text = "# comment\nA=1\nOTHER=keep\n";
        let out = apply(text, &[("A", Change::Set("2".into()))]);
        assert_eq!(out, "# comment\nA=2\nOTHER=keep\n");
    }

    #[test]
    fn a_new_key_is_appended_under_one_heading() {
        let out = apply("OTHER=keep", &[("A", Change::Set("1".into())), ("B", Change::Set("2".into()))]);
        assert_eq!(out, format!("OTHER=keep\n\n{APPENDED_HEADING}\nA=1\nB=2\n"));
        // A second run adds to the same block instead of a second heading.
        let again = apply(&out, &[("C", Change::Set("3".into()))]);
        assert_eq!(again.matches(APPENDED_HEADING).count(), 1);
        assert!(again.ends_with("B=2\nC=3\n"));
    }

    #[test]
    fn a_cleared_key_is_commented_out_not_removed() {
        let out = apply("A=1\nB=2\n", &[("A", Change::Clear)]);
        assert_eq!(out, "# A=1\nB=2\n");
        assert_eq!(get(&out, "A"), None);
        // Clearing a key that is not there adds nothing.
        assert_eq!(apply("B=2\n", &[("A", Change::Clear)]), "B=2\n");
    }

    #[test]
    fn unrelated_lines_and_commented_examples_survive_untouched() {
        let text = "# WIRESERVE_SERVICE_DOMAIN=example\n\n# note\nRUST_LOG=debug\n";
        let out = apply(text, &[("WIRESERVE_SERVICE_DOMAIN", Change::Set("int.example.com".into()))]);
        assert!(out.starts_with(text), "{out}");
        assert_eq!(get(&out, "WIRESERVE_SERVICE_DOMAIN").as_deref(), Some("int.example.com"));
    }
}
