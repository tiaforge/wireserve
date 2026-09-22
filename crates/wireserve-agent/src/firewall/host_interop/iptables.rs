//! The iptables side: which iptables rulesets are in use, reading our
//! tagged lines out of `-S INPUT`, and the exact argv for every change.
//!
//! Goes through the real `iptables` binaries rather than nft, because
//! iptables-nft's tables are only safely writable by iptables itself: its
//! rules use `xt` compat expressions nft can't reproduce (the comment we
//! tag with is one — nft shows it only as an opaque `xt comment`), and an
//! nft-native rule in there makes `iptables -S`/`iptables-save` fail with
//! "table is incompatible".

use std::path::{Path, PathBuf};
use std::process::Command;

use super::model::{tag, Hook, IpVersion, IptablesObservation, IptablesTarget, IptablesVariant, TAG_PREFIX};

const SEARCH_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// How long to wait for the xtables lock (legacy iptables only; the nft
/// variant ignores it) before giving up, so a stuck ufw or docker call
/// can't hang reconciliation forever.
const LOCK_WAIT_SECS: &str = "5";

fn find(name: &str) -> Option<PathBuf> {
    SEARCH_DIRS
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

fn base_name(version: IpVersion) -> &'static str {
    match version {
        IpVersion::V4 => "iptables",
        IpVersion::V6 => "ip6tables",
    }
}

/// `iptables v1.8.13 (nf_tables)` / `(legacy)`.
#[must_use]
pub fn variant_from_version_output(out: &str) -> Option<IptablesVariant> {
    if out.contains("(nf_tables)") {
        Some(IptablesVariant::Nft)
    } else if out.contains("(legacy)") {
        Some(IptablesVariant::Legacy)
    } else {
        None
    }
}

fn reported_variant(binary: &Path) -> Option<IptablesVariant> {
    let out = Command::new(binary).arg("-V").output().ok()?;
    variant_from_version_output(&String::from_utf8_lossy(&out.stdout))
}

/// The binary that writes to `variant`'s ruleset: the explicitly-suffixed
/// one if installed, otherwise the plain name if `-V` says it is that
/// variant. Never guesses.
#[must_use]
pub fn locate(version: IpVersion, variant: IptablesVariant) -> Option<IptablesTarget> {
    let base = base_name(version);
    let suffixed = match variant {
        IptablesVariant::Nft => format!("{base}-nft"),
        IptablesVariant::Legacy => format!("{base}-legacy"),
    };
    let binary = find(&suffixed).or_else(|| {
        let plain = find(base)?;
        (reported_variant(&plain) == Some(variant)).then_some(plain)
    })?;
    Some(IptablesTarget {
        version,
        variant,
        binary,
    })
}

/// Is the legacy (x_tables) `filter` table loaded? `/proc/net/ip_tables_names`
/// only lists tables legacy iptables has registered, so this is how a
/// legacy ruleset in use is detected without touching it.
#[must_use]
pub fn legacy_filter_loaded(version: IpVersion) -> bool {
    let path = match version {
        IpVersion::V4 => "/proc/net/ip_tables_names",
        IpVersion::V6 => "/proc/net/ip6_tables_names",
    };
    std::fs::read_to_string(path).is_ok_and(|s| names_include_filter(&s))
}

#[must_use]
pub fn names_include_filter(names: &str) -> bool {
    names.lines().any(|l| l.trim() == "filter")
}

// ---- argv builders (exact, pinned by tests) ----

/// `-i <ifname>`, plus `-o <ifname>` too for `Forward` — `INPUT` traffic is
/// always "to this host" regardless of egress, but `FORWARD` must be pinned
/// to both interfaces or it would open routing from the mesh to any other
/// interface on the host, not just hairpin traffic back onto the mesh.
fn rule_spec(ifname: &str, hook: Hook) -> Vec<String> {
    let mut spec = vec!["-i".to_string(), ifname.into()];
    if hook == Hook::Forward {
        spec.push("-o".into());
        spec.push(ifname.into());
    }
    spec.extend(["-m".into(), "comment".into(), "--comment".into(), tag(ifname), "-j".into(), "ACCEPT".into()]);
    spec
}

#[must_use]
pub fn insert_args(ifname: &str, hook: Hook) -> Vec<String> {
    let mut args: Vec<String> = ["-w", LOCK_WAIT_SECS, "-I", hook.iptables_chain(), "1"].map(Into::into).into();
    args.extend(rule_spec(ifname, hook));
    args
}

#[must_use]
pub fn list_args(hook: Hook) -> Vec<String> {
    ["-w", LOCK_WAIT_SECS, "-S", hook.iptables_chain()].map(Into::into).into()
}

/// `-D` for one line exactly as `-S INPUT`/`-S FORWARD` printed it
/// (`-A INPUT …`/`-A FORWARD …`), so that stale rules for other interface
/// names, or hand-edited ones, are deleted by their real spec rather than
/// one rebuilt from a guess.
pub fn delete_args(line: &str) -> Result<Vec<String>, String> {
    let words = split_words(line)?;
    match words.as_slice() {
        [a, chain, rest @ ..] if a == "-A" && (chain == "INPUT" || chain == "FORWARD") => {
            let mut args: Vec<String> = ["-w", LOCK_WAIT_SECS, "-D"].map(Into::into).into();
            args.push(chain.clone());
            args.extend(rest.iter().cloned());
            Ok(args)
        }
        _ => Err(format!("not an `-A INPUT`/`-A FORWARD` line: {line:?}")),
    }
}

/// Splits one `iptables -S` line into words: whitespace-separated, with
/// double-quoted words (iptables quotes comments, escaping `"` and `\`
/// with a backslash).
pub fn split_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            return Ok(words);
        };
        let mut word = String::new();
        if first == '"' {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some(c) => word.push(c),
                        None => return Err(format!("dangling escape in {line:?}")),
                    },
                    Some(c) => word.push(c),
                    None => return Err(format!("unterminated quote in {line:?}")),
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                word.push(c);
                chars.next();
            }
        }
        words.push(word);
    }
}

/// The comment of a `-S` line if it carries our tag prefix — the whole
/// tag, `wireserve:<ifname>`.
#[must_use]
pub fn line_tag(line: &str) -> Option<String> {
    let words = split_words(line).ok()?;
    words
        .windows(2)
        .find(|p| p[0] == "--comment" && p[1].starts_with(TAG_PREFIX))
        .map(|p| p[1].clone())
}

/// Every `-A INPUT`/`-A FORWARD` line in `-S <hook>` output whose comment
/// carries our tag prefix — nothing else, however similar.
#[must_use]
pub fn tagged_lines(listing: &str, hook: Hook) -> Vec<String> {
    let prefix = format!("-A {} ", hook.iptables_chain());
    listing
        .lines()
        .filter(|l| l.starts_with(&prefix))
        .filter(|l| line_tag(l).is_some())
        .map(str::to_string)
        .collect()
}

/// Runs `binary args…`; `Ok(stdout)` on success, `Err(stderr)` otherwise.
pub fn run(target: &IptablesTarget, args: &[String]) -> Result<String, String> {
    let out = Command::new(&target.binary)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {}: {e}", target.binary.display()))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{} {} exited with {}: {}",
            target.binary.display(),
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Every iptables ruleset worth looking at on this host, with our tagged
/// lines in each. iptables-nft is observed whenever its binary exists
/// (the planner decides whether its table is in use); legacy only when
/// its `filter` table is actually loaded. Both `INPUT` and `FORWARD` are
/// always observed, regardless of `transit_capable` — the planner is what
/// gates whether `FORWARD` ever gets a rule *inserted*, but observing it
/// regardless means a stray rule left behind by an earlier, transit-capable
/// run still gets found and removed after a restart with transit turned
/// back off (PLAN.md M23), the same as the nft side already does.
#[must_use]
pub fn observe() -> Vec<IptablesObservation> {
    let mut out = Vec::new();
    let hooks: &[Hook] = &[Hook::Input, Hook::Forward];
    for version in [IpVersion::V4, IpVersion::V6] {
        let mut targets = Vec::new();
        if let Some(t) = locate(version, IptablesVariant::Nft) {
            targets.push(t);
        }
        if legacy_filter_loaded(version) {
            match locate(version, IptablesVariant::Legacy) {
                Some(t) => targets.push(t),
                None => tracing::warn!(
                    ?version,
                    "a legacy iptables filter table is loaded but no {}-legacy binary was \
                     found — traffic on the mesh interface may be blocked by it",
                    base_name(version)
                ),
            }
        }
        for target in targets {
            for &hook in hooks {
                let tagged = match run(&target, &list_args(hook)) {
                    Ok(listing) => Some(tagged_lines(&listing, hook)),
                    Err(e) => {
                        tracing::debug!(error = %e, "iptables listing failed");
                        None
                    }
                };
                out.push(IptablesObservation {
                    target: target.clone(),
                    hook,
                    tagged_lines: tagged,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_args_are_exact_and_scoped_to_the_interface() {
        assert_eq!(
            insert_args("wg0", Hook::Input),
            [
                "-w", "5", "-I", "INPUT", "1", "-i", "wg0", "-m", "comment", "--comment",
                "wireserve:wg0", "-j", "ACCEPT"
            ]
        );
        assert_eq!(
            insert_args("wg0", Hook::Forward),
            [
                "-w", "5", "-I", "FORWARD", "1", "-i", "wg0", "-o", "wg0", "-m", "comment", "--comment",
                "wireserve:wg0", "-j", "ACCEPT"
            ]
        );
        for hook in [Hook::Input, Hook::Forward] {
            for ifname in ["wg0", "wireserve0", "a.b-c_d"] {
                let args = insert_args(ifname, hook);
                let i = args.iter().position(|a| a == "-i").unwrap();
                assert_eq!(args[i + 1], ifname);
                assert!(args.iter().all(|a| !a.contains('+')), "no iptables wildcard: {args:?}");
            }
        }
    }

    #[test]
    fn delete_args_reproduce_the_listed_spec() {
        let line = "-A INPUT -i wg1 -m comment --comment \"wireserve:wg1\" -j ACCEPT";
        assert_eq!(
            delete_args(line).unwrap(),
            [
                "-w", "5", "-D", "INPUT", "-i", "wg1", "-m", "comment", "--comment",
                "wireserve:wg1", "-j", "ACCEPT"
            ]
        );
        let fwd_line = "-A FORWARD -i wg1 -o wg1 -m comment --comment \"wireserve:wg1\" -j ACCEPT";
        assert_eq!(
            delete_args(fwd_line).unwrap(),
            [
                "-w", "5", "-D", "FORWARD", "-i", "wg1", "-o", "wg1", "-m", "comment", "--comment",
                "wireserve:wg1", "-j", "ACCEPT"
            ]
        );
        assert!(delete_args("-A OUTPUT -j ACCEPT").is_err());
        assert!(delete_args("-P INPUT DROP").is_err());
    }

    #[test]
    fn list_args_are_exact() {
        assert_eq!(list_args(Hook::Input), ["-w", "5", "-S", "INPUT"]);
        assert_eq!(list_args(Hook::Forward), ["-w", "5", "-S", "FORWARD"]);
    }

    #[test]
    fn words_handle_iptables_quoting() {
        assert_eq!(
            split_words(r#"-A INPUT -m comment --comment "has space \"q\" \\ x" -j ACCEPT"#).unwrap(),
            ["-A", "INPUT", "-m", "comment", "--comment", r#"has space "q" \ x"#, "-j", "ACCEPT"]
        );
        assert!(split_words(r#"--comment "open"#).is_err());
    }

    /// `-S INPUT` as a ufw host with our rule prints it (captured from real
    /// iptables-nft 1.8.13 in a network namespace).
    const UFW_LISTING: &str = "-P INPUT DROP
-A INPUT -i wg0 -m comment --comment \"wireserve:wg0\" -j ACCEPT
-A INPUT -j ts-input
-A INPUT -j ufw-before-logging-input
-A INPUT -j ufw-before-input
-A INPUT -j ufw-after-input
-A INPUT -i old0 -m comment --comment \"wireserve:old0\" -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -m comment --comment \"wireserve-other: not ours\" -j ACCEPT
-A INPUT -i wg0 -m comment --comment \"ssh wireserve:wg0\" -j ACCEPT
-A INPUT -i wg0 -j ACCEPT
";

    #[test]
    fn tagged_lines_finds_only_our_rules() {
        assert_eq!(
            tagged_lines(UFW_LISTING, Hook::Input),
            [
                "-A INPUT -i wg0 -m comment --comment \"wireserve:wg0\" -j ACCEPT",
                "-A INPUT -i old0 -m comment --comment \"wireserve:old0\" -j ACCEPT",
            ]
        );
        assert!(tagged_lines("-P INPUT ACCEPT\n", Hook::Input).is_empty());
        assert!(tagged_lines("", Hook::Input).is_empty());
        // A FORWARD listing is never confused with INPUT's, even sharing a
        // host: only its own chain's lines match.
        let fwd = "-P FORWARD DROP\n-A FORWARD -i wg0 -o wg0 -m comment --comment \"wireserve:wg0\" -j ACCEPT\n";
        assert_eq!(
            tagged_lines(fwd, Hook::Forward),
            ["-A FORWARD -i wg0 -o wg0 -m comment --comment \"wireserve:wg0\" -j ACCEPT"]
        );
        assert!(tagged_lines(fwd, Hook::Input).is_empty());
    }

    #[test]
    fn our_listed_line_matches_the_planners_expected_line() {
        // What we insert must read back as exactly what the planner keeps,
        // or every reconcile would delete and re-insert it.
        assert_eq!(
            tagged_lines(UFW_LISTING, Hook::Input)[0],
            super::super::planner::iptables_line("wg0", Hook::Input)
        );
    }

    #[test]
    fn version_output_identifies_the_backend() {
        assert_eq!(
            variant_from_version_output("iptables v1.8.13 (nf_tables)\n"),
            Some(IptablesVariant::Nft)
        );
        assert_eq!(
            variant_from_version_output("iptables v1.8.7 (legacy)\n"),
            Some(IptablesVariant::Legacy)
        );
        assert_eq!(variant_from_version_output("iptables v1.4.21\n"), None);
    }

    #[test]
    fn legacy_detection_reads_table_names() {
        assert!(names_include_filter("mangle\nfilter\n"));
        assert!(!names_include_filter("nat\nmangle\n"));
        assert!(!names_include_filter(""));
    }

    // ---- real kernel (unprivileged netns, skipped where unavailable) ----

    #[test]
    fn kernel_insert_list_delete_round_trip() {
        let Some(t) = locate(IpVersion::V4, IptablesVariant::Nft) else {
            eprintln!("SKIPPED: no iptables-nft");
            return;
        };
        let bin = t.binary.display();
        let q = |args: Vec<String>| {
            args.iter()
                .map(|a| format!("'{a}'"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let script = format!(
            "{bin} -P INPUT DROP\n{bin} -A INPUT -i lo -j ACCEPT\n\
             {bin} {ins}\n{bin} {list}\necho ---\n{bin} {del}\n{bin} {list}",
            ins = q(insert_args("wg0", Hook::Input)),
            list = q(list_args(Hook::Input)),
            del = q(delete_args(&super::super::planner::iptables_line("wg0", Hook::Input)).unwrap()),
        );
        let Some(out) = crate::firewall::netns::run(&script) else {
            return;
        };
        let (before, after) = out.split_once("---\n").unwrap();
        assert_eq!(
            before.lines().nth(1),
            Some(super::super::planner::iptables_line("wg0", Hook::Input).as_str()),
            "inserted at the head of INPUT:\n{before}"
        );
        assert_eq!(tagged_lines(before, Hook::Input).len(), 1);
        assert!(tagged_lines(after, Hook::Input).is_empty(), "{after}");
        assert!(after.contains("-A INPUT -i lo -j ACCEPT"), "foreign rules untouched: {after}");
    }
}
