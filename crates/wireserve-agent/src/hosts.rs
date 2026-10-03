//! Managed `/etc/hosts` block (spec §6). Every declared service gets a
//! synthetic `<service-name>.wg` hostname pointing at its own address
//! (PLAN.md M20), or at its owning node's IPv4 address for a service the
//! coordinator gave no address of its own. Entries live between fixed markers so each poll cycle can
//! safely wipe-and-rewrite just that span without touching anything else
//! already in the file.
//!
//! Each agent instance on a host owns its own block: the default instance
//! writes the bare `# BEGIN WIRESERVE` / `# END WIRESERVE` markers, a
//! named instance `<n>` writes
//! `# BEGIN WIRESERVE <n>` / `# END WIRESERVE <n>`. Markers only ever
//! match a whole line, so `# BEGIN WIRESERVE` never finds the start of
//! another instance's labelled block.

use std::net::Ipv4Addr;
use std::path::Path;

use wireserve_types::naming::own_address;
use wireserve_types::{ServiceInfo, ServiceNames};

use crate::fsutil::atomic_write;

const BEGIN_MARKER: &str = "# BEGIN WIRESERVE";
const END_MARKER: &str = "# END WIRESERVE";

fn markers(label: Option<&str>) -> (String, String) {
    match label {
        None => (BEGIN_MARKER.to_string(), END_MARKER.to_string()),
        Some(l) => (format!("{BEGIN_MARKER} {l}"), format!("{END_MARKER} {l}")),
    }
}

/// How services are named this cycle (PLAN.md M25): the shared rule in
/// [`ServiceNames`], which the coordinator's DNS records follow too.
pub type Naming<'a> = ServiceNames<'a>;

/// Renders the managed block's body (without markers) for the given
/// services, one `<ip> <name>` line per service, sorted for a stable
/// diff-free rewrite when nothing has actually changed.
fn render_block(services: &[ServiceInfo], naming: Naming<'_>) -> String {
    let mut lines: Vec<String> = services
        .iter()
        .filter(|s| is_safe_entry(s))
        .filter_map(|s| Some(format!("{} {}", naming.address(s)?, naming.host_name(s))))
        .collect();
    lines.sort();
    lines.join("\n")
}

/// Defense in depth: the coordinator validates service names and
/// allocates the addresses itself, so a bad entry here means either a
/// coordinator bug or a compromised coordinator. Either way this writer
/// is the last thing standing between that and a line of attacker-chosen
/// text in every node's `/etc/hosts`, so it re-checks both fields (a
/// strict DNS label, a literal IPv4 address) and drops anything else with
/// a loud warning rather than trusting the wire.
fn is_safe_entry(s: &ServiceInfo) -> bool {
    let ok = wireserve_types::is_valid_dns_label(&s.name)
        && own_address(s).parse::<Ipv4Addr>().is_ok();
    if !ok {
        tracing::warn!(
            service = %s.name.escape_debug(),
            ip4 = %s.ip4.escape_debug(),
            "refusing to write malformed directory entry to the hosts file"
        );
    }
    ok
}

/// The byte span of this label's block: from the start of its begin line
/// to the end of its end-marker text (the newline after it is not part of
/// the span). `None` unless both markers are present, each as a whole
/// line, the end after the begin.
fn find_block(contents: &str, label: Option<&str>) -> Option<(usize, usize)> {
    let (begin, end) = markers(label);
    let mut offset = 0;
    let mut start = None;
    for line in contents.split_inclusive('\n') {
        let text = line.trim_end();
        match start {
            None if text == begin => start = Some(offset),
            Some(s) if text == end => return Some((s, offset + line.trim_end_matches(['\n', '\r']).len())),
            _ => {}
        }
        offset += line.len();
    }
    None
}

/// Replaces the managed block in `contents`, creating the markers
/// (appended, with a leading blank line for separation) if they're not
/// already present. Everything outside the markers is preserved verbatim.
fn replace_managed_block(
    contents: &str,
    label: Option<&str>,
    services: &[ServiceInfo],
    naming: Naming<'_>,
) -> String {
    let (begin, end) = markers(label);
    let body = render_block(services, naming);
    let new_block = format!("{begin}\n{body}\n{end}");

    if let Some((start, stop)) = find_block(contents, label) {
        let mut out = String::new();
        out.push_str(&contents[..start]);
        out.push_str(&new_block);
        out.push_str(&contents[stop..]);
        return out;
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

/// Reads `path`, rewrites only this instance's managed block, and writes
/// the result back atomically. Preserves the original file's permission
/// bits (an `/etc/hosts` on a real system is typically world-readable,
/// 644, and this writer has no business changing that).
pub fn sync(
    path: &Path,
    label: Option<&str>,
    services: &[ServiceInfo],
    naming: Naming<'_>,
) -> std::io::Result<()> {
    with_lock(path, || {
        let existing = read_existing(path)?;
        let updated = replace_managed_block(&existing, label, services, naming);
        if updated == existing {
            return Ok(());
        }
        write_preserving_mode(path, &updated)?;
        // Once per actual change, never per cycle: enough to tell from the
        // log alone what the block held at any moment.
        let names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
        tracing::info!(path = %path.display(), services = ?names, "hosts-file block rewritten");
        Ok(())
    })
}

/// Runs a read-modify-write of `path` under an exclusive `flock`, so two
/// agent instances rewriting their own blocks at the same moment can't
/// each write back a copy missing the other's change.
///
/// The lock is on the file itself, and `atomic_write` replaces the file by
/// renaming a new one over it, so a lock taken while waiting may end up on
/// the replaced file rather than the current one. Checked after locking,
/// by comparing the locked descriptor's inode with the path's, and retried
/// until the two agree — the usual protocol for locking a file that is
/// updated by rename. A missing file has nothing to lock; the write that
/// creates it goes ahead unlocked.
fn with_lock<T>(path: &Path, f: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    loop {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return f(),
            Err(e) => return Err(e),
        };
        // SAFETY: a plain syscall on a descriptor that outlives the call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let locked = file.metadata()?;
        match std::fs::metadata(path) {
            Ok(now) if now.dev() == locked.dev() && now.ino() == locked.ino() => return f(),
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return f(),
            Err(e) => return Err(e),
        }
    }
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

/// Strips this instance's managed block (markers included) entirely,
/// rather than leaving an empty-but-present block behind. Used by
/// `wireserve leave` (spec §4.6: "tears down interface, firewall, hosts
/// block" — security review F2 flagged that this project's `leave`
/// implementation was only doing the first two). A no-op if the markers
/// aren't present.
pub fn remove_block(path: &Path, label: Option<&str>) -> std::io::Result<()> {
    with_lock(path, || {
        let existing = read_existing(path)?;
        let Some(stripped) = strip_managed_block(&existing, label) else {
            return Ok(());
        };
        write_preserving_mode(path, &stripped)
    })
}

/// Removes the marked span (and one adjoining blank separator line, if
/// `replace_managed_block` added one) from `contents`. Returns `None` if
/// the markers aren't present, so callers can treat that as a no-op
/// rather than rewriting a file that doesn't need it.
fn strip_managed_block(contents: &str, label: Option<&str>) -> Option<String> {
    let (start, end) = find_block(contents, label)?;
    let before = contents[..start].trim_end_matches('\n');
    let after = &contents[end..];
    let after = after.strip_prefix('\n').unwrap_or(after);

    let mut out = String::new();
    out.push_str(before);
    if !before.is_empty() {
        // Separates `before` from `after`, or — with the block last in the
        // file — restores the final newline the trim above took. Without
        // it the file ends mid-line, and the next `echo ... >> /etc/hosts`
        // glues its entry onto the last hostname.
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

    fn svc(name: &str, ip4: &str) -> ServiceInfo {
        ServiceInfo {
            terminated: false,
            reach: None,
            name: name.into(),
            node: "somenode".into(),
            ip4: ip4.into(),
            online: true,
            vip4: None,
            ports: vec![],
        }
    }

    #[test]
    fn a_service_with_its_own_address_resolves_to_it() {
        let mut web = svc("web", "100.90.0.3");
        web.vip4 = Some("100.90.0.50".into());
        let old = svc("plex", "100.90.0.3");
        assert_eq!(render_block(&[web, old], Naming::default()), "100.90.0.3 plex.wg\n100.90.0.50 web.wg");
    }

    #[test]
    fn a_malformed_service_address_drops_the_entry() {
        // `vip::sanitize` clears these before they get here; this writer
        // still refuses to be the one that puts text in /etc/hosts.
        let mut web = svc("web", "100.90.0.3");
        web.vip4 = Some("100.90.0.50 evil.example".into());
        assert_eq!(render_block(&[web], Naming::default()), "");
    }

    #[test]
    fn creates_markers_when_absent_preserving_existing_content() {
        let original = "127.0.0.1 localhost\n::1 localhost\n";
        let out = replace_managed_block(original, None, &[svc("plex", "100.90.0.3")], Naming::default());
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
        let out = replace_managed_block(&original, None, &[svc("plex", "100.90.0.3")], Naming::default());
        assert!(out.contains("127.0.0.1 localhost"));
        assert!(out.contains("192.168.1.1 router"));
        assert!(!out.contains("old.wg"));
        assert!(out.contains("100.90.0.3 plex.wg"));
    }

    #[test]
    fn idempotent_when_services_unchanged() {
        let original = "127.0.0.1 localhost\n";
        let first = replace_managed_block(original, None, &[svc("plex", "100.90.0.3")], Naming::default());
        let second = replace_managed_block(&first, None, &[svc("plex", "100.90.0.3")], Naming::default());
        assert_eq!(first, second);
    }

    #[test]
    fn empty_services_yields_empty_but_present_block() {
        let out = replace_managed_block("", None, &[], Naming::default());
        assert!(out.contains(BEGIN_MARKER));
        assert!(out.contains(END_MARKER));
    }

    #[test]
    fn sync_writes_file_and_is_atomic_on_repeated_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();

        sync(&path, None, &[svc("plex", "100.90.0.3")], Naming::default()).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("plex.wg"));
        assert!(contents.contains("127.0.0.1 localhost"));

        sync(&path, None, &[svc("homeassistant", "100.90.0.5")], Naming::default()).unwrap();
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
        let err = sync(&bad_path, None, &[svc("plex", "100.90.0.3")], Naming::default());
        assert!(err.is_err());

        assert_eq!(
            std::fs::read_to_string(&real_hosts).unwrap(),
            "127.0.0.1 localhost\n"
        );
    }

    // ---- defense in depth: never trust the wire for what lands in /etc/hosts ----

    #[test]
    fn malformed_directory_entries_are_dropped_not_written() {
        let evil = vec![
            svc("plex", "100.90.0.3"),
            // Name carrying extra hosts-file syntax.
            svc("evil.wg 10.0.0.1 bank.example", "100.90.0.4"),
            // Name with a newline: a second, attacker-chosen line.
            svc("x\n10.0.0.2 mail.example", "100.90.0.5"),
            // Not an IP at all.
            svc("ok-name", "not-an-ip"),
            // IPv6 where the writer expects v4 (would still be a valid
            // hosts line, but not what this block is defined to carry).
            svc("six", "fd00::1"),
        ];
        let out = replace_managed_block("127.0.0.1 localhost\n", None, &evil, Naming::default());
        assert!(out.contains("100.90.0.3 plex.wg"));
        assert!(!out.contains("bank.example"));
        assert!(!out.contains("mail.example"));
        assert!(!out.contains("not-an-ip"));
        assert!(!out.contains("fd00::1"));
        // Exactly one entry line between the markers.
        let body = out
            .split(BEGIN_MARKER)
            .nth(1)
            .unwrap()
            .split(END_MARKER)
            .next()
            .unwrap();
        assert_eq!(body.trim().lines().count(), 1);
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

        let err = sync(&path, None, &[svc("plex", "100.90.0.3")], Naming::default());
        assert!(err.is_err(), "sync must fail rather than guess");
        assert_eq!(std::fs::read(&path).unwrap(), original, "file must be untouched");

        let err = remove_block(&path, None);
        assert!(err.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn sync_creates_a_missing_hosts_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        sync(&path, None, &[svc("plex", "100.90.0.3")], Naming::default()).unwrap();
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

        remove_block(&path, None).unwrap();

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

        remove_block(&path, None).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "127.0.0.1 localhost\n"
        );
    }

    // ---- several instances, one hosts file ----

    #[test]
    fn instances_own_separate_blocks() {
        let base = "127.0.0.1 localhost\n";
        let a = replace_managed_block(base, None, &[svc("plex", "100.90.0.3")], Naming::default());
        let ab = replace_managed_block(&a, Some("work"), &[svc("git", "10.77.0.2")], Naming::default());
        assert!(ab.contains("# BEGIN WIRESERVE\n100.90.0.3 plex.wg\n# END WIRESERVE\n"), "{ab}");
        assert!(ab.contains("# BEGIN WIRESERVE work\n10.77.0.2 git.wg\n# END WIRESERVE work\n"), "{ab}");

        // Rewriting either leaves the other alone.
        let ab2 = replace_managed_block(&ab, None, &[svc("jellyfin", "100.90.0.4")], Naming::default());
        assert!(ab2.contains("git.wg") && ab2.contains("jellyfin.wg") && !ab2.contains("plex.wg"), "{ab2}");
        let ab3 = replace_managed_block(&ab2, Some("work"), &[], Naming::default());
        assert!(!ab3.contains("git.wg") && ab3.contains("jellyfin.wg"), "{ab3}");

        // Removing one keeps the other intact.
        let only_work = strip_managed_block(&ab, None).unwrap();
        assert!(!only_work.contains("plex.wg") && only_work.contains("# BEGIN WIRESERVE work"), "{only_work}");
        let only_default = strip_managed_block(&ab, Some("work")).unwrap();
        assert!(only_default.contains("plex.wg") && !only_default.contains("work"), "{only_default}");
        assert_eq!(strip_managed_block(&only_default, None).unwrap(), base);
    }

    #[test]
    fn sync_then_remove_restores_the_file_byte_for_byte() {
        // A block appended to the end of the file and removed again used
        // to take the file's own final newline with it.
        for original in ["127.0.0.1 localhost\n::1 localhost\n", "127.0.0.1 localhost\n\n# tail\n"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("hosts");
            std::fs::write(&path, original).unwrap();
            sync(&path, None, &[svc("plex", "100.90.0.3")], Naming::default()).unwrap();
            remove_block(&path, None).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        }
    }

    #[test]
    fn the_default_markers_never_match_a_labelled_block() {
        // The labelled block comes first, so a substring search for the
        // bare markers would have matched inside it.
        let text = "# BEGIN WIRESERVE work\n10.77.0.2 git.wg\n# END WIRESERVE work\n";
        assert_eq!(find_block(text, None), None);
        assert_eq!(strip_managed_block(text, None), None);
        let out = replace_managed_block(text, None, &[svc("plex", "100.90.0.3")], Naming::default());
        assert!(out.starts_with(text), "labelled block untouched: {out}");
        assert!(out.ends_with("# BEGIN WIRESERVE\n100.90.0.3 plex.wg\n# END WIRESERVE\n"), "{out}");
    }

    #[test]
    fn concurrent_writers_never_lose_each_others_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, "127.0.0.1 localhost\n").unwrap();
        let labels = ["a", "b", "c", "d"];
        std::thread::scope(|s| {
            for (i, label) in labels.iter().enumerate() {
                let path = &path;
                s.spawn(move || {
                    for round in 0..50 {
                        let ip = format!("10.{i}.0.{}", round % 250 + 1);
                        sync(path, Some(label), &[svc(label, &ip)], Naming::default()).unwrap();
                    }
                });
            }
        });
        let out = std::fs::read_to_string(&path).unwrap();
        for label in labels {
            assert!(out.contains(&format!("# BEGIN WIRESERVE {label}\n10.")), "{label} missing:\n{out}");
            assert_eq!(out.matches(&format!("# BEGIN WIRESERVE {label}\n")).count(), 1, "{out}");
        }
        assert!(out.starts_with("127.0.0.1 localhost\n"));
    }
}

#[cfg(test)]
mod naming_tests {
    use super::*;
    use wireserve_types::{PortMap, Proto, ServiceNaming};

    fn svc(name: &str, vip: &str, public: u16) -> ServiceInfo {
        ServiceInfo {
            terminated: false,
            reach: None,
            name: name.into(),
            node: "somenode".into(),
            ip4: "100.90.0.3".into(),
            online: true,
            vip4: Some(vip.into()),
            ports: vec![PortMap { public, target: 9999, proto: Proto::Tcp, addr: None }],
        }
    }

    fn cfg_for(domain: &str) -> ServiceNaming {
        ServiceNaming { domain: domain.into(), acme: None, sign_in: None, identity_headers: Default::default(), strip_headers: Vec::new(), forwarding_nodes: Vec::new(), cross_site_services: Vec::new() }
    }

    #[test]
    fn without_a_domain_nothing_changes() {
        let services = [svc("plex", "100.90.0.50", 443), svc("prom", "100.90.0.51", 80)];
        let n = Naming::new(None);
        assert_eq!(
            render_block(&services, n),
            "100.90.0.50 plex.wg\n100.90.0.51 prom.wg",
            "a mesh with no domain configured must be byte-identical to before"
        );
    }

    #[test]
    fn a_domain_replaces_the_suffix_rather_than_adding_a_second_name() {
        let services = [svc("prom", "100.90.0.51", 80)];
        let cfg = cfg_for("int.example.com");
        let out = render_block(&services, Naming::new(Some(&cfg)));
        assert_eq!(out, "100.90.0.51 prom.int.example.com");
        assert!(
            !out.contains(".wg"),
            "two working names give an app two base URLs, which is the bug this avoids"
        );
    }

    #[test]
    fn every_name_resolves_to_its_own_address() {
        // PLAN.md M34: a 443 service is served by its own node, so its name
        // points there like every other.
        let services = [
            svc("plex", "100.90.0.50", 443),
            svc("prom", "100.90.0.51", 80),
            svc("web", "100.90.0.2", 443),
        ];
        let cfg = cfg_for("int.example.com");
        let out = render_block(&services, Naming::new(Some(&cfg)));
        assert_eq!(out, "100.90.0.2 web.int.example.com\n100.90.0.50 plex.int.example.com\n100.90.0.51 prom.int.example.com");
    }
}
