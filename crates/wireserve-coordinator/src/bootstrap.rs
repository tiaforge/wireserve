//! First-run generation of the values an operator would otherwise have to
//! invent by hand before the coordinator would start at all: the admin
//! token, and the two mesh address ranges.
//!
//! Resolution order per key, matching every other setting's env-var
//! precedence: an explicit env var always wins and is never written back
//! here; otherwise a value already persisted in `coordinator-secrets.env`
//! is reused; otherwise a fresh value is generated and appended to that
//! file. An existing line is never rewritten, so setting the env var for
//! one run doesn't erase a previously generated value — removing the env
//! var later brings it back rather than silently rotating it.
//!
//! The persisted file lives next to the database, at
//! `<state_dir>/coordinator-secrets.env`, created mode 600 the same way
//! `db::harden_file_permissions` hardens the SQLite file.

use std::collections::HashMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

const ADMIN_TOKEN_KEY: &str = "WIRESERVE_ADMIN_TOKEN";
const NET_V4_KEY: &str = "WIRESERVE_NET_V4_CIDR";
const NET_V6_KEY: &str = "WIRESERVE_NET_V6_PREFIX";
/// Seals the device owners' refresh tokens in the database (PLAN.md M38).
/// Kept here rather than in the database it protects, so a copy of the
/// database alone does not carry the tokens in the clear.
pub const OIDC_TOKEN_KEY: &str = "WIRESERVE_OIDC_TOKEN_KEY";
/// Signs the sign-in's session tokens (PLAN.md M48): the seed of an
/// Ed25519 key whose public half every node gets. Whoever holds it can let
/// anyone into any service, so it never leaves this file.
pub const SIGN_IN_KEY: &str = "WIRESERVE_SIGN_IN_KEY";

const KEYS: [&str; 5] = [ADMIN_TOKEN_KEY, NET_V4_KEY, NET_V6_KEY, OIDC_TOKEN_KEY, SIGN_IN_KEY];

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("could not read {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("could not write {0}: {1}")]
    Write(PathBuf, std::io::Error),
}

pub struct Bootstrapped {
    pub admin_token: String,
    pub net_v4_cidr: String,
    pub net_v6_prefix: String,
    /// 32 bytes, hex. Generated silently — it is not something an operator
    /// has to know about — and so never listed in `generated`.
    pub oidc_token_key: String,
    /// 32 bytes, hex, generated silently the same way.
    pub sign_in_key: String,
    /// Which of the three keys were freshly generated (not found in an env
    /// var or the persisted file) on this call.
    pub generated: Vec<&'static str>,
    /// Where freshly generated values were (or would be) persisted.
    pub path: PathBuf,
}

/// Resolves the admin token and both mesh ranges, generating and
/// persisting whichever of the three are missing from both the
/// environment and any prior run.
pub fn resolve(state_dir: &Path) -> Result<Bootstrapped, BootstrapError> {
    resolve_with(state_dir, |key| std::env::var(key).ok())
}

/// [`resolve`], with the "explicit value" of each key looked up by `lookup`
/// instead of the process environment. `wireserve-coordinator install`
/// generates the values before the first start, as root, and must see what
/// the service will see — the env file — not whatever its own sudo session
/// carries.
pub fn resolve_with(
    state_dir: &Path,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Bootstrapped, BootstrapError> {
    let path = state_dir.join("coordinator-secrets.env");
    let mut persisted = read_persisted(&path)?;
    let mut generated = Vec::new();
    let mut to_append = Vec::new();

    let mut resolve_one = |key: &'static str, generate: fn() -> String| -> String {
        if let Some(v) = lookup(key) {
            if !v.is_empty() {
                return v;
            }
        }
        if let Some(v) = persisted.remove(key) {
            return v;
        }
        let fresh = generate();
        generated.push(key);
        to_append.push((key, fresh.clone()));
        fresh
    };

    let admin_token = resolve_one(ADMIN_TOKEN_KEY, generate_admin_token);
    let net_v4_cidr = resolve_one(NET_V4_KEY, generate_v4_cidr);
    let net_v6_prefix = resolve_one(NET_V6_KEY, generate_v6_prefix);
    let oidc_token_key = resolve_one(OIDC_TOKEN_KEY, generate_token_key);
    let sign_in_key = resolve_one(SIGN_IN_KEY, generate_token_key);
    generated.retain(|k| *k != OIDC_TOKEN_KEY && *k != SIGN_IN_KEY);

    if !to_append.is_empty() {
        append_to_file(&path, &to_append)?;
    }

    Ok(Bootstrapped {
        admin_token,
        net_v4_cidr,
        net_v6_prefix,
        oidc_token_key,
        sign_in_key,
        generated,
        path,
    })
}

fn generate_token_key() -> String {
    crate::tokengen::generate("")
}

fn generate_admin_token() -> String {
    crate::tokengen::generate("")
}

/// A private-use IPv4 /16 that can never overlap `100.64.0.0/10` (the
/// carrier-grade-NAT range Tailscale and some ISPs allocate from), because
/// it's drawn from `10.0.0.0/8` by construction rather than checked after
/// the fact — and clear of this host's own networks. See
/// [`v4_cidr_clear_of`].
fn generate_v4_cidr() -> String {
    v4_cidr_clear_of(&host_v4_networks(), |n| rand::random::<u32>() as usize % n)
}

/// A `10.X.0.0/16` that overlaps none of `host` (network address, prefix
/// length), with `pick(n)` choosing among the `n` that qualify.
///
/// A coordinator on a 10.x network — a cloud VPC, a homelab LAN, a
/// container network — would otherwise draw its own network one time in
/// 256. Its nodes are then handed addresses alongside the coordinator's,
/// route the coordinator into the tunnel, and every poll after the first
/// is lost. A host whose networks cover all of `10.0.0.0/8` leaves no /16
/// clear; then only the ranges holding one of its own addresses are
/// skipped, which is the case that cuts nodes off.
fn v4_cidr_clear_of(host: &[(Ipv4Addr, u8)], pick: impl FnOnce(usize) -> usize) -> String {
    let range = |second: u8| u32::from(Ipv4Addr::new(10, second, 0, 0));
    // Two prefixes overlap when they agree on the shorter of the two masks.
    let overlaps = |second: u8, &(net, len): &(Ipv4Addr, u8)| {
        let mask = mask32(len.min(16));
        range(second) & mask == u32::from(net) & mask
    };
    let holds = |second: u8, &(addr, _): &(Ipv4Addr, u8)| u32::from(addr) & mask32(16) == range(second);
    let mut clear: Vec<u8> = (0..=255).filter(|&s| !host.iter().any(|n| overlaps(s, n))).collect();
    if clear.is_empty() {
        clear = (0..=255).filter(|&s| !host.iter().any(|n| holds(s, n))).collect();
    }
    if clear.is_empty() {
        clear = (0..=255).collect();
    }
    let second = clear[pick(clear.len()).min(clear.len() - 1)];
    format!("10.{second}.0.0/16")
}

fn mask32(len: u8) -> u32 {
    if len == 0 { 0 } else { u32::MAX << (32 - u32::from(len)) }
}

/// This host's IPv4 addresses with their prefix lengths, every interface
/// alike: a container bridge reaches the coordinator as surely as a LAN
/// does. Empty if they can't be listed, which leaves the draw as random
/// as it always was.
#[cfg(unix)]
pub fn host_v4_networks() -> Vec<(Ipv4Addr, u8)> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: every node of the list is valid until freeifaddrs; the
        // sockaddrs are read as AF_INET only after the family says so.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
        let mask = unsafe { &*ifa.ifa_netmask.cast::<libc::sockaddr_in>() };
        let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        let len = u32::from_be(mask.sin_addr.s_addr).count_ones() as u8;
        out.push((addr, len));
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(not(unix))]
pub fn host_v4_networks() -> Vec<(Ipv4Addr, u8)> {
    Vec::new()
}

/// A properly-random RFC 4193 unique local address prefix: `fd` followed
/// by 40 pseudo-random bits, exactly the shape `main.rs`'s startup warning
/// already asks operators to generate by hand with a `python3` one-liner.
///
/// Rerolls the roughly 1-in-256 case where the random top byte happens to
/// land on 0x00 — the "hand-picked" `fd00::/16` shape the startup warning
/// exists to flag — so a freshly generated prefix can never trip that
/// warning on an operator's very first run.
fn generate_v6_prefix() -> String {
    loop {
        let bytes: [u8; 5] = rand::random();
        let candidate = format!(
            "fd{:02x}:{:02x}{:02x}:{:02x}{:02x}::/64",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4]
        );
        if !crate::config::v6_prefix_has_nonrandom_global_id(&candidate) {
            return candidate;
        }
    }
}

fn read_persisted(path: &Path) -> Result<HashMap<String, String>, BootstrapError> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(BootstrapError::Read(path.to_path_buf(), e)),
    };
    let mut map = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            // Only keys this module manages are ever read back — an
            // operator hand-editing this file to add something else isn't
            // a case this needs to support.
            if KEYS.contains(&k) {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    Ok(map)
}

fn append_to_file(path: &Path, entries: &[(&'static str, String)]) -> Result<(), BootstrapError> {
    let existed = path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| BootstrapError::Write(path.to_path_buf(), e))?;
    if !existed {
        writeln!(
            file,
            "# Generated by wireserve-coordinator on first start. Do not delete: \
             these values are allocated once and kept for the life of the mesh. \
             An explicit environment variable of the same name always overrides \
             the value stored here."
        )
        .map_err(|e| BootstrapError::Write(path.to_path_buf(), e))?;
    }
    for (k, v) in entries {
        writeln!(file, "{k}={v}").map_err(|e| BootstrapError::Write(path.to_path_buf(), e))?;
    }
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| BootstrapError::Write(path.to_path_buf(), e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env vars are process-global state and cargo runs tests in parallel
    // threads by default; serialize the tests that touch them so they
    // can't interleave and read each other's values (same pattern as
    // wireserve-admin's config tests).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn generates_and_persists_on_first_call() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve(dir.path()).unwrap();
        assert_eq!(b.generated.len(), 3);
        assert_eq!(b.admin_token.len(), 64);
        assert!(b.net_v4_cidr.starts_with("10."));
        assert!(b.net_v6_prefix.starts_with("fd"));
        assert!(b.path.exists());
    }

    #[test]
    fn second_call_reuses_persisted_values() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = resolve(dir.path()).unwrap();
        let second = resolve(dir.path()).unwrap();
        assert!(second.generated.is_empty());
        assert_eq!(first.admin_token, second.admin_token);
        assert_eq!(first.net_v4_cidr, second.net_v4_cidr);
        assert_eq!(first.net_v6_prefix, second.net_v6_prefix);
    }

    #[test]
    fn env_var_overrides_without_being_persisted() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(ADMIN_TOKEN_KEY, "explicit-token");
        let b = resolve(dir.path()).unwrap();
        std::env::remove_var(ADMIN_TOKEN_KEY);
        assert_eq!(b.admin_token, "explicit-token");
        assert!(!b.generated.contains(&ADMIN_TOKEN_KEY));
        // Not written back to the file: the two remaining keys were
        // generated, but a subsequent run without the env var must not see
        // "explicit-token" persisted anywhere.
        let contents = std::fs::read_to_string(&b.path).unwrap();
        assert!(!contents.contains("explicit-token"));
    }

    #[test]
    fn removing_env_var_falls_back_to_previously_persisted_value() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let first = resolve(dir.path()).unwrap();
        // An operator sets the env var to override for one run...
        std::env::set_var(NET_V4_KEY, "10.55.55.0/24");
        let overridden = resolve(dir.path()).unwrap();
        assert_eq!(overridden.net_v4_cidr, "10.55.55.0/24");
        // ...then removes it. The original generated value comes back,
        // not a fresh one.
        std::env::remove_var(NET_V4_KEY);
        let restored = resolve(dir.path()).unwrap();
        assert_eq!(restored.net_v4_cidr, first.net_v4_cidr);
    }

    #[test]
    fn persisted_file_is_mode_600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _g = ENV_LOCK.lock().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let b = resolve(dir.path()).unwrap();
            let mode = std::fs::metadata(&b.path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn v4_cidr_never_overlaps_cgnat() {
        for _ in 0..100 {
            let cidr = generate_v4_cidr();
            assert!(!crate::config::v4_cidr_overlaps_cgnat(&cidr), "{cidr}");
        }
    }

    #[test]
    fn v4_cidr_skips_the_hosts_own_networks() {
        let host: Vec<(Ipv4Addr, u8)> = vec![
            ("127.0.0.1".parse().unwrap(), 8),
            ("10.88.0.1".parse().unwrap(), 16),
            ("10.89.3.7".parse().unwrap(), 24),
            ("10.0.0.0".parse().unwrap(), 12),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..240 {
            let cidr = v4_cidr_clear_of(&host, |n| i % n);
            assert!(!["10.88.0.0/16", "10.89.0.0/16"].contains(&cidr.as_str()), "{cidr}");
            let second: u8 = cidr.split('.').nth(1).unwrap().parse().unwrap();
            assert!(second >= 16, "{cidr} is inside 10.0.0.0/12");
            seen.insert(cidr);
        }
        assert_eq!(seen.len(), 256 - 16 - 2, "every clear range can be drawn");
    }

    #[test]
    fn v4_cidr_under_a_host_covering_all_of_10_still_avoids_its_addresses() {
        let host: Vec<(Ipv4Addr, u8)> = vec![("10.3.4.5".parse().unwrap(), 8)];
        for i in 0..256 {
            assert_ne!(v4_cidr_clear_of(&host, |n| i % n), "10.3.0.0/16");
        }
    }

    #[test]
    fn v6_prefix_always_has_random_global_id() {
        for _ in 0..100 {
            let prefix = generate_v6_prefix();
            assert!(!crate::config::v6_prefix_has_nonrandom_global_id(&prefix), "{prefix}");
        }
    }
}
