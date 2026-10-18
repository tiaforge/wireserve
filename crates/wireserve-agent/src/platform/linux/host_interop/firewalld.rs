//! firewalld: its nftables table is owned (`owner` flag — writes from
//! anyone else fail with EPERM), so instead of inserting rules we bind the
//! interface to its `trusted` zone, for this boot only (no `--permanent`),
//! through `firewall-cmd`. The planner decides when; this module only
//! observes and runs the commands.
//!
//! `firewall-cmd` is Python: every run costs about half a second and
//! 25-30 MB, charged to the agent's cgroup while it runs. Asking it on
//! every reconcile, as this did, took the agent from about 20 MB to 60-70
//! MB every poll tick, and that was on a host where firewalld was stopped:
//! the only way to hear "not running" was to ask. So it is now asked only
//! when firewalld's table is in the ruleset we list anyway, and only when
//! that table has changed since the last answer (see [`table_fingerprint`]).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use super::model::{Family, FirewalldState, NftView, FIREWALLD_TABLE};

const CANDIDATES: &[&str] = &["/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd", "/bin/firewall-cmd", "/sbin/firewall-cmd"];

#[must_use]
pub fn locate() -> Option<PathBuf> {
    CANDIDATES.iter().map(Path::new).find(|p| p.is_file()).map(Path::to_path_buf)
}

#[must_use]
pub fn state_args() -> Vec<String> {
    vec!["--state".into()]
}

#[must_use]
pub fn zone_args(ifname: &str, permanent: bool) -> Vec<String> {
    let mut args = Vec::new();
    if permanent {
        args.push("--permanent".into());
    }
    args.push(format!("--get-zone-of-interface={ifname}"));
    args
}

/// Runtime only — deliberately never `--permanent`: the binding must not
/// outlive the agent (a reboot, or a crash followed by an uninstall, must
/// not leave the interface name trusted for whatever uses it next).
#[must_use]
pub fn trust_args(ifname: &str) -> Vec<String> {
    vec!["--zone=trusted".into(), format!("--change-interface={ifname}")]
}

#[must_use]
pub fn untrust_args(ifname: &str) -> Vec<String> {
    vec!["--zone=trusted".into(), format!("--remove-interface={ifname}")]
}

/// `--get-zone-of-interface` prints the zone and exits 0, or prints
/// `no zone` and exits non-zero (2) when the interface has none.
#[must_use]
pub fn parse_zone(success: bool, stdout: &str) -> Option<String> {
    let zone = stdout.trim();
    (success && !zone.is_empty() && zone != "no zone").then(|| zone.to_string())
}

fn run(bin: &Path, args: &[String]) -> Option<(bool, String)> {
    let out = Command::new(bin).args(args).output().ok()?;
    Some((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

/// firewalld's view of `ifname`. Anything that prevents a clear answer —
/// no binary, not running, D-Bus unreachable (e.g. inside a container) —
/// is `Unavailable`, and the planner then does nothing on this side.
#[must_use]
pub fn observe(ifname: &str) -> FirewalldState {
    let Some(bin) = locate() else {
        return FirewalldState::Unavailable;
    };
    match run(&bin, &state_args()) {
        Some((true, _)) => {}
        _ => return FirewalldState::Unavailable,
    }
    let zone = |permanent| {
        run(&bin, &zone_args(ifname, permanent)).and_then(|(ok, out)| parse_zone(ok, &out))
    };
    FirewalldState::Running {
        runtime_zone: zone(false),
        permanent_zone: zone(true),
    }
}

/// A digest of firewalld's table as `view` shows it, or `None` when there
/// is no such table — firewalld is not running then (its nftables backend
/// creates the table on start and removes it on stop), and there is
/// nothing to ask it.
///
/// Whatever firewalld changes at runtime changes this table: binding an
/// interface to a zone adds the rules that dispatch it there, and a
/// `--reload` or restart rebuilds the whole table. So an unchanged digest
/// means an unchanged answer, with one exception it shares with firewalld
/// itself: a `--permanent` binding made without a reload shows up at the
/// next reload, which is also when firewalld applies it.
///
/// firewalld on its iptables backend (deprecated, not the default since
/// 0.6) has no such table and counts as not running here; the iptables
/// side of the interop still opens that host's INPUT chain.
#[must_use]
pub fn table_fingerprint(view: &NftView) -> Option<u64> {
    let ours = |family: Family, table: &str| family == Family::Inet && table == FIREWALLD_TABLE;
    if !view.tables.iter().any(|t| ours(t.family, &t.name)) {
        return None;
    }
    let mut h = DefaultHasher::new();
    for chain in view.chains.iter().filter(|c| ours(c.chain.family, &c.chain.table)) {
        (&chain.chain.chain, &chain.hook, &chain.chain_type).hash(&mut h);
        for rule in &chain.rules {
            (rule.handle, &rule.comment).hash(&mut h);
            for expr in &rule.expr {
                hash_config(expr, &mut h);
            }
        }
    }
    Some(h.finish())
}

/// What a rule says, without what traffic changes in it: a `counter`'s
/// packets and bytes, a `quota`'s used amount, `last`'s timestamp. Were
/// those hashed, a firewalld rule that counts would make every reconcile
/// look like a firewalld change and ask `firewall-cmd` each time again.
fn hash_config(value: &Value, h: &mut DefaultHasher) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if matches!(key.as_str(), "packets" | "bytes" | "used" | "used_unit") {
                    continue;
                }
                key.hash(h);
                hash_config(inner, h);
            }
        }
        Value::Array(items) => {
            items.len().hash(h);
            for item in items {
                hash_config(item, h);
            }
        }
        // `Value` has no `Hash`; for a leaf, its JSON text stands in.
        leaf => leaf.to_string().hash(h),
    }
}

/// firewalld's last answer, the interface it was about and the
/// [`table_fingerprint`] it was given against.
#[derive(Debug, Default)]
pub struct Cache(Option<(u64, String, FirewalldState)>);

impl Cache {
    /// firewalld's view of `ifname`, asking `query` only when the answer
    /// can have changed. `view` is `None` when the ruleset could not be
    /// listed: firewalld is asked then, as there is no table to go by.
    ///
    /// Only a `Running` answer is kept. `Unavailable` with the table in
    /// place is a firewalld still starting up (its table is filled before
    /// it answers on D-Bus) or one that can't be reached at all; the first
    /// must be asked again, and the second is rare enough to pay for.
    pub fn get(&mut self, view: Option<&NftView>, ifname: &str, query: impl FnOnce() -> FirewalldState) -> FirewalldState {
        let Some(view) = view else {
            self.0 = None;
            return query();
        };
        let Some(fingerprint) = table_fingerprint(view) else {
            self.0 = None;
            return FirewalldState::Unavailable;
        };
        if let Some((seen, seen_for, state)) = &self.0 {
            if *seen == fingerprint && seen_for == ifname {
                return state.clone();
            }
        }
        let state = query();
        self.0 = matches!(state, FirewalldState::Running { .. }).then(|| (fingerprint, ifname.to_string(), state.clone()));
        state
    }

    /// After we changed firewalld ourselves: whatever it says next is news.
    pub fn forget(&mut self) {
        self.0 = None;
    }
}

pub fn execute(args: &[String]) -> Result<(), String> {
    let bin = locate().ok_or("firewall-cmd not found")?;
    let out = Command::new(&bin)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {}: {e}", bin.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "firewall-cmd {} exited with {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_is_exact_and_runtime_only() {
        assert_eq!(state_args(), ["--state"]);
        assert_eq!(zone_args("wg0", false), ["--get-zone-of-interface=wg0"]);
        assert_eq!(zone_args("wg0", true), ["--permanent", "--get-zone-of-interface=wg0"]);
        assert_eq!(trust_args("wg0"), ["--zone=trusted", "--change-interface=wg0"]);
        assert_eq!(untrust_args("wg0"), ["--zone=trusted", "--remove-interface=wg0"]);
        for args in [trust_args("wg0"), untrust_args("wg0")] {
            assert!(!args.iter().any(|a| a == "--permanent"), "{args:?}");
        }
    }

    const FIREWALLD_LIKE: &[u8] = include_bytes!("../../../../tests/fixtures/nft/firewalld_like.json");
    const NATIVE: &[u8] = include_bytes!("../../../../tests/fixtures/nft/native.json");

    fn running(zone: &str) -> FirewalldState {
        FirewalldState::Running { runtime_zone: Some(zone.into()), permanent_zone: None }
    }

    /// `cache.get`, counting how often firewalld was asked.
    fn get(cache: &mut Cache, view: Option<&NftView>, ifname: &str, answer: &FirewalldState, asked: &mut usize) -> FirewalldState {
        cache.get(view, ifname, || {
            *asked += 1;
            answer.clone()
        })
    }

    #[test]
    fn without_firewallds_table_it_is_never_asked() {
        let view = super::super::ruleset::parse(NATIVE).unwrap();
        assert_eq!(table_fingerprint(&view), None);
        let (mut cache, mut asked) = (Cache::default(), 0);
        for _ in 0..3 {
            assert_eq!(get(&mut cache, Some(&view), "wg0", &running("public"), &mut asked), FirewalldState::Unavailable);
        }
        assert_eq!(asked, 0);
    }

    #[test]
    fn it_is_asked_again_only_when_its_table_changes() {
        let view = super::super::ruleset::parse(FIREWALLD_LIKE).unwrap();
        let (mut cache, mut asked) = (Cache::default(), 0);
        for _ in 0..3 {
            assert_eq!(get(&mut cache, Some(&view), "wg0", &running("public"), &mut asked), running("public"));
        }
        assert_eq!(asked, 1);

        // `--change-interface` adds firewalld rules; any change to its
        // table counts.
        let mut changed = view.clone();
        let chain = changed.chains.iter_mut().find(|c| c.chain.table == FIREWALLD_TABLE).unwrap();
        chain.rules[0].expr.push(serde_json::json!({"accept": null}));
        assert_ne!(table_fingerprint(&changed), table_fingerprint(&view));
        assert_eq!(get(&mut cache, Some(&changed), "wg0", &running("trusted"), &mut asked), running("trusted"));
        assert_eq!(asked, 2);

        // Changes outside its table don't.
        let mut elsewhere = changed.clone();
        elsewhere.chains.retain(|c| c.chain.table == FIREWALLD_TABLE);
        assert_eq!(table_fingerprint(&elsewhere), table_fingerprint(&changed));
        get(&mut cache, Some(&elsewhere), "wg0", &running("trusted"), &mut asked);
        assert_eq!(asked, 2);

        // Nor do the numbers a counting rule moves on every packet.
        let counting = |counter: serde_json::Value| {
            let mut view = changed.clone();
            let chain = view.chains.iter_mut().find(|c| c.chain.table == FIREWALLD_TABLE).unwrap();
            chain.rules[0].expr.insert(0, serde_json::json!({ "counter": counter }));
            table_fingerprint(&view)
        };
        let before = counting(serde_json::json!({"packets": 1, "bytes": 60}));
        assert_eq!(counting(serde_json::json!({"packets": 9000, "bytes": 540_000})), before);
        assert_ne!(counting(serde_json::json!("named")), before);

        // Nor is one interface's answer another's.
        get(&mut cache, Some(&elsewhere), "wg1", &running("public"), &mut asked);
        assert_eq!(asked, 3);
    }

    #[test]
    fn it_is_asked_again_after_we_changed_it() {
        let view = super::super::ruleset::parse(FIREWALLD_LIKE).unwrap();
        let (mut cache, mut asked) = (Cache::default(), 0);
        get(&mut cache, Some(&view), "wg0", &running("public"), &mut asked);
        cache.forget();
        get(&mut cache, Some(&view), "wg0", &running("trusted"), &mut asked);
        assert_eq!(asked, 2);
    }

    /// A firewalld that fills its table before it answers on D-Bus must
    /// not stay "unavailable" for as long as the table stays the same.
    #[test]
    fn unavailable_is_not_kept() {
        let view = super::super::ruleset::parse(FIREWALLD_LIKE).unwrap();
        let (mut cache, mut asked) = (Cache::default(), 0);
        get(&mut cache, Some(&view), "wg0", &FirewalldState::Unavailable, &mut asked);
        assert_eq!(get(&mut cache, Some(&view), "wg0", &running("public"), &mut asked), running("public"));
        assert_eq!(asked, 2);
    }

    /// No ruleset to go by: firewalld is asked every time, as before.
    #[test]
    fn without_a_ruleset_it_is_always_asked() {
        let view = super::super::ruleset::parse(FIREWALLD_LIKE).unwrap();
        let (mut cache, mut asked) = (Cache::default(), 0);
        get(&mut cache, Some(&view), "wg0", &running("public"), &mut asked);
        get(&mut cache, None, "wg0", &running("public"), &mut asked);
        get(&mut cache, None, "wg0", &running("public"), &mut asked);
        assert_eq!(asked, 3);
    }

    #[test]
    fn zone_output_parsing() {
        // As printed by firewalld 2.5.0 on SteamOS.
        assert_eq!(parse_zone(true, "public\n"), Some("public".into()));
        assert_eq!(parse_zone(true, "trusted\n"), Some("trusted".into()));
        assert_eq!(parse_zone(false, "no zone\n"), None);
        assert_eq!(parse_zone(true, "no zone\n"), None);
        assert_eq!(parse_zone(false, ""), None);
        assert_eq!(parse_zone(true, ""), None);
    }
}
