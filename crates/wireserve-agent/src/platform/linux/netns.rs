//! Real-kernel test support: runs a shell script inside a throwaway
//! unprivileged user+network namespace (`unshare -rn`), where `nft` and
//! `iptables` get `CAP_NET_ADMIN` over a private, empty netfilter state.
//! Nothing touches the host's firewall and no root is needed — but not
//! every environment allows unprivileged user namespaces (some CI
//! containers don't), so callers get `None` there and skip, loudly.
//!
//! Run as root, it is a network namespace alone (`unshare -n`): a user
//! namespace would leave out what only real root may do — the service
//! addresses' payload rewrites — and an unmapped owner's test binary could
//! not even be executed in it.

use std::process::Command;

/// `unshare`'s flags: a network namespace, and a user namespace unless
/// this already is root.
fn flags() -> &'static str {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } == 0 { "-n" } else { "-rn" }
}

/// Says why a kernel test is skipping. Under `WIRESERVE_TEST_STRICT=1`
/// (CI sets it) a skip is a failure instead: there the environment is
/// meant to have everything, and a test that quietly skipped would
/// look the same as one that passed.
pub fn skip(why: &str) {
    assert!(std::env::var_os("WIRESERVE_TEST_STRICT").is_none(), "would skip under WIRESERVE_TEST_STRICT: {why}");
    eprintln!("SKIPPED: {why}");
}

/// Whether this is root of the whole machine, not just of an
/// unprivileged namespace (where `geteuid` says 0 too): only the
/// initial user namespace maps every uid onto itself.
pub fn real_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    euid == 0
        && std::fs::read_to_string("/proc/self/uid_map")
            .is_ok_and(|m| m.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"])
}

pub fn available() -> bool {
    Command::new("unshare")
        .args([flags(), "true"])
        .status()
        .is_ok_and(|s| s.success())
        && super::nft::NFT_CANDIDATES
            .iter()
            .any(|p| std::path::Path::new(p).is_file())
}

const IN_NETNS: &str = "WIRESERVE_TEST_IN_NETNS";

/// Re-runs the test at `path` (as `--exact` knows it) inside a fresh
/// network namespace. Returns whether the caller is already inside it
/// and should do the work; outside, it waits for the inner run and
/// fails if that did.
pub fn reexec(path: &str) -> bool {
    if std::env::var_os(IN_NETNS).is_some() {
        return true;
    }
    if !available() {
        skip("unprivileged network namespaces or nft unavailable");
        return false;
    }
    let status = Command::new("unshare")
        .arg(flags())
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", path, "--nocapture"])
        .env(IN_NETNS, "1")
        .status()
        .unwrap();
    assert!(status.success(), "in-namespace run failed");
    false
}

/// Like [`run`], but a failing script is returned rather than a
/// panic: stdout and stderr, for a test that inspects what failed.
pub fn run_capturing(script: &str) -> Option<(String, String)> {
    if !available() {
        skip("unprivileged network namespaces or nft unavailable");
        return None;
    }
    let out = Command::new("unshare").args([flags(), "sh", "-euc", script]).output().expect("spawn unshare");
    Some((String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap()))
}

/// Runs `script` with `sh -c` in a fresh namespace. Returns stdout, or
/// `None` (after printing why) when namespaces or `nft` are
/// unavailable. Panics with stderr if the script itself fails.
pub fn run(script: &str) -> Option<String> {
    if !available() {
        skip("unprivileged network namespaces or nft unavailable");
        return None;
    }
    let out = Command::new("unshare")
        .args([flags(), "sh", "-euc", script])
        .output()
        .expect("spawn unshare");
    assert!(
        out.status.success(),
        "netns script failed ({}):\n{}\n--- script ---\n{script}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).unwrap())
}
