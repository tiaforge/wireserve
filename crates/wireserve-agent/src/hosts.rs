//! Managed `/etc/hosts` block (spec §6). Every declared service gets a
//! synthetic `<service-name>.wg` hostname pointing at its owning node's
//! IPv4 address. Entries live between fixed markers so each poll cycle can
//! safely wipe-and-rewrite just that span without touching anything else
//! already in the file.

use std::path::Path;

use wireserve_types::ServiceInfo;

use crate::fsutil::atomic_write;

const BEGIN_MARKER: &str = "# BEGIN WIRESERVE";
const END_MARKER: &str = "# END WIRESERVE";

/// Renders the managed block's body (without markers) for the given
/// services, one `<ip> <name>.wg` line per service, sorted for a stable
/// diff-free rewrite when nothing has actually changed.
fn render_block(services: &[ServiceInfo]) -> String {
    let mut lines: Vec<String> = services
        .iter()
        .map(|s| format!("{} {}.wg", s.ip4, s.name))
        .collect();
    lines.sort();
    lines.join("\n")
}

/// Replaces the managed block in `contents`, creating the markers
/// (appended, with a leading blank line for separation) if they're not
/// already present. Everything outside the markers is preserved verbatim.
fn replace_managed_block(contents: &str, services: &[ServiceInfo]) -> String {
    let body = render_block(services);
    let new_block = format!("{BEGIN_MARKER}\n{body}\n{END_MARKER}");

    if let (Some(start), Some(end)) = (contents.find(BEGIN_MARKER), contents.find(END_MARKER)) {
        if end >= start {
            let before = &contents[..start];
            let after = &contents[end + END_MARKER.len()..];
            let mut out = String::new();
            out.push_str(before);
            out.push_str(&new_block);
            out.push_str(after);
            return out;
        }
    }

    // Markers absent (or malformed/out of order — treat as absent rather
    // than guess): append, preserving whatever was already there.
    let mut out = contents.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(&new_block);
    out.push('\n');
    out
}

/// Reads `path`, rewrites only the managed block, and writes the result
/// back atomically. Preserves the original file's permission bits (an
/// `/etc/hosts` on a real system is typically world-readable, 644, and
/// this writer has no business changing that).
pub fn sync(path: &Path, services: &[ServiceInfo]) -> std::io::Result<()> {
    let existing = read_existing(path)?;
    let updated = replace_managed_block(&existing, services);
    write_preserving_mode(path, &updated)
}

/// Reads the current hosts file. A missing file is treated as empty (the
/// block gets created from scratch); **any other failure is an error**,
/// never silently treated as empty — a transient permission error or a
/// non-UTF-8 byte somewhere in the file must abort this cycle, not cause
/// the whole file to be rewritten as nothing but the managed block
/// (security review G1: that would drop `localhost` and everything else
/// the operator had in there).
fn read_existing(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Strips the managed block (markers included) entirely, rather than
/// leaving an empty-but-present block behind. Used by `wireserve leave`
/// (spec §4.6: "tears down interface, firewall, hosts block" — security
/// review F2 flagged that this project's `leave` implementation was only
/// doing the first two). A no-op if the markers aren't present.
pub fn remove_block(path: &Path) -> std::io::Result<()> {
    let existing = read_existing(path)?;
    let Some(stripped) = strip_managed_block(&existing) else {
        return Ok(());
    };
    write_preserving_mode(path, &stripped)
}

/// Removes the marked span (and one adjoining blank separator line, if
/// `replace_managed_block` added one) from `contents`. Returns `None` if
/// the markers aren't present, so callers can treat that as a no-op
/// rather than rewriting a file that doesn't need it.
fn strip_managed_block(contents: &str) -> Option<String> {
    let (start, end) = (contents.find(BEGIN_MARKER)?, contents.find(END_MARKER)?);
    if end < start {
        return None;
    }
    let before = contents[..start].trim_end_matches('\n');
    let after = &contents[end + END_MARKER.len()..];
    let after = after.strip_prefix('\n').unwrap_or(after);

    let mut out = String::new();
    out.push_str(before);
    if !before.is_empty() && !after.is_empty() {
        out.push('\n');
    }
    out.push_str(after);
    Some(out)
}

fn write_preserving_mode(path: &Path, contents: &str) -> std::io::Result<()> {
    let mode = std::fs::metadata(path)
        .map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode() & 0o777
        })
        .unwrap_or(0o644);

    atomic_write(path, contents.as_bytes(), mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::Proto;

    fn svc(name: &str, ip4: &str) -> ServiceInfo {
        ServiceInfo {
            name: name.into(),
            node: "somenode".into(),
            ip4: ip4.into(),
            port: 1234,
            proto: Proto::Tcp,
            online: true,
        }
    }

    #[test]
    fn creates_markers_when_absent_preserving_existing_content() {
        let original = "127.0.0.1 localhost\n::1 localhost\n";
        let out = replace_managed_block(original, &[svc("plex", "100.90.0.3")]);
        assert!(out.starts_with(original));
        assert!(out.contains(BEGIN_MARKER));
        assert!(out.contains("100.90.0.3 plex.wg"));
        assert!(out.contains(END_MARKER));
    }

    #[test]
    fn rewrites_only_the_marked_span() {
        let original = format!(
            "127.0.0.1 localhost\n{BEGIN_MARKER}\n100.90.0.3 old.wg\n{END_MARKER}\n192.168.1.1 router\n"
        );
        let out = replace_managed_block(&original, &[svc("plex", "100.90.0.3")]);
        assert!(out.contains("127.0.0.1 localhost"));
        assert!(out.contains("192.168.1.1 router"));
        assert!(!out.contains("old.wg"));
        assert!(out.contains("100.90.0.3 plex.wg"));
    }

    #[test]
    fn idempotent_when_services_unchanged() {
        let original = "127.0.0.1 localhost\n";
        let first = replace_managed_block(original, &[svc("plex", "100.90.0.3")]);
        let second = replace_managed_block(&first, &[svc("plex", "100.90.0.3")]);
        assert_eq!(first, second);
    }

    #[test]
    fn empty_services_yields_empty_but_present_block() {
        let out = replace_managed_block("", &[]);
        assert!(out.contains(BEGIN_MARKER));
        assert!(out.contains(END_MARKER));
    }

    #[test]
    fn sync_writes_file_and_is_atomic_on_repeated_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();

        sync(&path, &[svc("plex", "100.90.0.3")]).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("plex.wg"));
        assert!(contents.contains("127.0.0.1 localhost"));

        sync(&path, &[svc("homeassistant", "100.90.0.5")]).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains("plex.wg"), "old entry must be gone");
        assert!(contents.contains("homeassistant.wg"));

        // No leftover temp file.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn sync_failure_leaves_original_file_untouched() {
        // Point "the file to sync" at a path whose parent directory does
        // not exist, so the temp-file creation inside atomic_write fails
        // before any rename is attempted — the caller's separately-tracked
        // "real" hosts file (simulated here by a sibling temp file) must be
        // completely unaffected by that failure.
        let dir = tempfile::tempdir().unwrap();
        let real_hosts = dir.path().join("hosts");
        std::fs::write(&real_hosts, "127.0.0.1 localhost\n").unwrap();

        let bad_path = dir.path().join("missing-dir").join("hosts");
        let err = sync(&bad_path, &[svc("plex", "100.90.0.3")]);
        assert!(err.is_err());

        assert_eq!(
            std::fs::read_to_string(&real_hosts).unwrap(),
            "127.0.0.1 localhost\n"
        );
    }

    // ---- G1: an unreadable hosts file must abort, never be replaced ----

    #[test]
    fn sync_refuses_to_rewrite_a_file_it_could_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        // Invalid UTF-8 makes read_to_string fail; the old code treated
        // that as an empty file and would have written back ONLY the
        // managed block, dropping every other entry.
        let original: &[u8] = b"127.0.0.1 localhost\n\xff\xfe not utf8\n";
        std::fs::write(&path, original).unwrap();

        let err = sync(&path, &[svc("plex", "100.90.0.3")]);
        assert!(err.is_err(), "sync must fail rather than guess");
        assert_eq!(std::fs::read(&path).unwrap(), original, "file must be untouched");

        let err = remove_block(&path);
        assert!(err.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn sync_creates_a_missing_hosts_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        sync(&path, &[svc("plex", "100.90.0.3")]).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("plex.wg"));
    }

    // ---- F2: `leave` must remove the managed block, not just empty it ----

    #[test]
    fn remove_block_strips_markers_and_body_preserving_surrounding_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(
            &path,
            format!(
                "127.0.0.1 localhost\n\n{BEGIN_MARKER}\n100.90.0.3 plex.wg\n{END_MARKER}\n192.168.1.1 router\n"
            ),
        )
        .unwrap();

        remove_block(&path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(!contents.contains(BEGIN_MARKER));
        assert!(!contents.contains(END_MARKER));
        assert!(!contents.contains("plex.wg"));
        assert!(contents.contains("127.0.0.1 localhost"));
        assert!(contents.contains("192.168.1.1 router"));
    }

    #[test]
    fn remove_block_is_a_no_op_when_markers_are_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();

        remove_block(&path).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "127.0.0.1 localhost\n"
        );
    }
}
