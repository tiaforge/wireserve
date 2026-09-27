//! Which interface name an instance runs on.
//!
//! Without `--ifname` the agent picks one of `wireserve0` … `wireserve15`
//! and remembers it in its state, so each instance keeps the same
//! interface across restarts. A name is usable when no running agent
//! claims it (`crate::lock`) and nothing but this node's own interface
//! from an earlier run exists under it; one another instance on the host
//! has stored as its own is left for that instance even while it is
//! stopped.
//!
//! `--ifname <name>` pins a name: it is used as given or the daemon
//! refuses to start, never quietly swapped for another, since an operator
//! who named one presumably refers to it elsewhere. `--ifname auto`
//! removes a pin.
//!
//! The choice itself is pure: it takes a `probe` that claims and inspects
//! a name, so the rules are tested without a kernel.

use std::collections::BTreeMap;

pub const PREFIX: &str = "wireserve";
/// `wireserve0` … `wireserve15`. Enough for any realistic number of
/// agents plus other tunnels squatting on some of the names, small enough
/// that a scan stays cheap.
pub const CANDIDATES: u32 = 16;

pub fn candidates() -> impl Iterator<Item = String> {
    (0..CANDIDATES).map(|n| format!("{PREFIX}{n}"))
}

/// `--ifname`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    /// Pick automatically, and drop any earlier pin.
    Auto,
    /// Use exactly this name, and keep using it.
    Name(String),
}

impl Flag {
    #[must_use]
    pub fn parse(s: &str) -> Self {
        if s == "auto" {
            Flag::Auto
        } else {
            Flag::Name(s.to_string())
        }
    }
}

#[derive(Debug)]
pub struct Request<'a> {
    pub flag: Option<&'a Flag>,
    /// The name this instance used last, from its state.
    pub stored: Option<&'a str>,
    pub stored_pinned: bool,
    /// Names other instances have stored, with the instance that did.
    pub reserved: &'a BTreeMap<String, String>,
}

/// The outcome of probing one name.
#[derive(Debug)]
pub enum Probe<C> {
    /// Claimed; `ours` if our own interface already exists under it.
    Usable { claim: C, ours: bool },
    /// Can't be used, and why.
    Unusable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Named with `--ifname` now, or pinned by an earlier `--ifname`.
    Pinned,
    /// The name this instance used last.
    Stored,
    /// Our own interface, found under a candidate name — left behind by a
    /// run that never got to save or tear down.
    Reused,
    /// The first free candidate.
    Free,
}

#[derive(Debug)]
pub struct Choice<C> {
    pub ifname: String,
    pub claim: C,
    pub source: Source,
    pub pinned: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChooseError {
    #[error(
        "cannot use the interface name '{ifname}': {reason}. It is pinned for this instance \
         (by --ifname); pass `--ifname auto` to let the agent pick a free name instead, or \
         `--ifname <name>` for another one"
    )]
    Pinned { ifname: String, reason: String },
    #[error("no free interface name among {PREFIX}0..{PREFIX}{}: {}; free one up, or pass `--ifname <name>`", CANDIDATES - 1, list(.0))]
    Exhausted(Vec<(String, String)>),
}

fn list(taken: &[(String, String)]) -> String {
    taken
        .iter()
        .map(|(name, why)| format!("{name} ({why})"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn choose<C>(req: &Request<'_>, mut probe: impl FnMut(&str) -> Probe<C>) -> Result<Choice<C>, ChooseError> {
    let pinned = match req.flag {
        Some(Flag::Name(n)) => Some(n.as_str()),
        Some(Flag::Auto) => None,
        None => req.stored.filter(|_| req.stored_pinned),
    };
    if let Some(name) = pinned {
        if let Some(other) = req.reserved.get(name) {
            tracing::warn!(
                ifname = name,
                instance = %other,
                "this interface name is also stored by another instance; only one of the two can run at a time"
            );
        }
        return match probe(name) {
            Probe::Usable { claim, .. } => Ok(Choice {
                ifname: name.to_string(),
                claim,
                source: Source::Pinned,
                pinned: true,
            }),
            Probe::Unusable(reason) => Err(ChooseError::Pinned {
                ifname: name.to_string(),
                reason,
            }),
        };
    }

    // The name used last, if it still works: an instance keeps its name.
    let mut taken = Vec::new();
    if let Some(name) = req.stored {
        match probe(name) {
            Probe::Usable { claim, .. } => {
                return Ok(Choice {
                    ifname: name.to_string(),
                    claim,
                    source: Source::Stored,
                    pinned: false,
                })
            }
            Probe::Unusable(reason) => {
                tracing::warn!(ifname = name, %reason, "can't use this instance's interface name any more; picking another");
                taken.push((name.to_string(), reason));
            }
        }
    }

    // Our own interface first — anywhere among the candidates — so a run
    // that died before saving its choice doesn't leave it orphaned; then
    // the first free name. The first free one's claim is held while the
    // rest are looked at, so nobody else can take it meanwhile.
    let mut first_free: Option<(String, C)> = None;
    for name in candidates() {
        if req.stored == Some(name.as_str()) {
            continue;
        }
        if let Some(other) = req.reserved.get(&name) {
            taken.push((name, format!("kept by instance '{other}'")));
            continue;
        }
        match probe(&name) {
            Probe::Usable { claim, ours: true } => {
                return Ok(Choice {
                    ifname: name,
                    claim,
                    source: Source::Reused,
                    pinned: false,
                })
            }
            Probe::Usable { claim, ours: false } => {
                if first_free.is_none() {
                    first_free = Some((name, claim));
                }
            }
            Probe::Unusable(reason) => taken.push((name, reason)),
        }
    }
    match first_free {
        Some((ifname, claim)) => Ok(Choice {
            ifname,
            claim,
            source: Source::Free,
            pinned: false,
        }),
        None => Err(ChooseError::Exhausted(taken)),
    }
}

/// Claims `name` and looks at what is on the host under it — the probe
/// `choose` runs against in the daemon.
pub fn probe_host(name: &str, private_key_b64: &str) -> Probe<crate::lock::IfnameClaim> {
    use crate::wg::{Slot, WgInterface};

    if let Err(e) = crate::wg::validate_ifname(name) {
        return Probe::Unusable(e.to_string());
    }
    let claim = match crate::lock::IfnameClaim::take(name) {
        Ok(Ok(claim)) => claim,
        Ok(Err(holder)) => return Probe::Unusable(holder.to_string()),
        Err(e) => return Probe::Unusable(format!("could not claim it ({e})")),
    };
    let wg = match WgInterface::new(name) {
        Ok(wg) => wg,
        Err(e) => return Probe::Unusable(e.to_string()),
    };
    match wg.classify(private_key_b64) {
        Slot::Free => Probe::Usable { claim, ours: false },
        Slot::Ours => Probe::Usable { claim, ours: true },
        Slot::Foreign(reason) => Probe::Unusable(reason),
    }
}

/// Names this instance might have left an interface under: every
/// candidate, and whatever it used last.
#[must_use]
pub fn leftover_names(chosen: &str, previous: Option<&str>) -> Vec<String> {
    let mut names: Vec<String> = candidates().collect();
    names.extend(previous.map(str::to_string));
    names.sort();
    names.dedup();
    names.retain(|n| n != chosen);
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// What each name looks like to the fake probe. Unlisted = free.
    #[derive(Clone, Copy)]
    enum Host {
        Ours,
        Foreign,
    }

    struct Fake {
        host: HashMap<String, Host>,
        /// Claims currently held — by the chooser, through the probe.
        held: RefCell<Vec<String>>,
        probed: RefCell<Vec<String>>,
    }

    /// A claim that records its release, like the real one.
    struct Claim<'a>(String, &'a RefCell<Vec<String>>);
    impl Drop for Claim<'_> {
        fn drop(&mut self) {
            self.1.borrow_mut().retain(|n| *n != self.0);
        }
    }

    impl Fake {
        fn new(host: &[(&str, Host)]) -> Self {
            Self {
                host: host.iter().map(|(n, h)| ((*n).to_string(), *h)).collect(),
                held: RefCell::default(),
                probed: RefCell::default(),
            }
        }

        fn probe(&self, name: &str) -> Probe<Claim<'_>> {
            self.probed.borrow_mut().push(name.to_string());
            match self.host.get(name) {
                Some(Host::Foreign) => Probe::Unusable("foreign".into()),
                other => {
                    self.held.borrow_mut().push(name.to_string());
                    Probe::Usable {
                        claim: Claim(name.to_string(), &self.held),
                        ours: matches!(other, Some(Host::Ours)),
                    }
                }
            }
        }

        fn choose(&self, flag: Option<&Flag>, stored: Option<&str>, pinned: bool, reserved: &[(&str, &str)]) -> Result<(String, Source, bool), ChooseError> {
            let reserved: BTreeMap<String, String> =
                reserved.iter().map(|(n, i)| ((*n).to_string(), (*i).to_string())).collect();
            let req = Request {
                flag,
                stored,
                stored_pinned: pinned,
                reserved: &reserved,
            };
            let choice = choose(&req, |n| self.probe(n))?;
            assert_eq!(*self.held.borrow(), std::slice::from_ref(&choice.ifname), "only the chosen claim is still held");
            Ok((choice.ifname.clone(), choice.source, choice.pinned))
        }
    }

    fn name(n: &str) -> Flag {
        Flag::Name(n.into())
    }

    #[test]
    fn a_fresh_instance_takes_the_first_free_name() {
        let f = Fake::new(&[]);
        assert_eq!(f.choose(None, None, false, &[]).unwrap(), ("wireserve0".into(), Source::Free, false));
    }

    #[test]
    fn foreign_and_reserved_names_are_skipped() {
        let f = Fake::new(&[("wireserve0", Host::Foreign)]);
        assert_eq!(
            f.choose(None, None, false, &[("wireserve1", "work")]).unwrap(),
            ("wireserve2".into(), Source::Free, false)
        );
        assert!(!f.probed.borrow().contains(&"wireserve1".to_string()), "a reserved name is not even claimed");
    }

    #[test]
    fn the_stored_name_is_kept_while_it_works() {
        let f = Fake::new(&[]);
        assert_eq!(
            f.choose(None, Some("wireserve3"), false, &[]).unwrap(),
            ("wireserve3".into(), Source::Stored, false)
        );
    }

    #[test]
    fn a_lost_stored_name_is_replaced() {
        let f = Fake::new(&[("wireserve3", Host::Foreign)]);
        assert_eq!(
            f.choose(None, Some("wireserve3"), false, &[]).unwrap(),
            ("wireserve0".into(), Source::Free, false)
        );
    }

    #[test]
    fn our_own_interface_wins_over_a_lower_free_name() {
        // A run on wireserve2 died before saving its choice; wireserve0
        // and 1 have become free since.
        let f = Fake::new(&[("wireserve2", Host::Ours)]);
        assert_eq!(f.choose(None, None, false, &[]).unwrap(), ("wireserve2".into(), Source::Reused, false));
    }

    #[test]
    fn a_pinned_name_is_used_or_refused_never_swapped() {
        let f = Fake::new(&[("wg0", Host::Foreign)]);
        assert_eq!(f.choose(Some(&name("wg7")), None, false, &[]).unwrap(), ("wg7".into(), Source::Pinned, true));
        assert_eq!(
            f.choose(Some(&name("wg0")), None, false, &[]),
            Err(ChooseError::Pinned {
                ifname: "wg0".into(),
                reason: "foreign".into()
            })
        );
        // Pinned earlier and stored: same, without the flag.
        assert_eq!(f.choose(None, Some("wg7"), true, &[]).unwrap(), ("wg7".into(), Source::Pinned, true));
        assert!(matches!(f.choose(None, Some("wg0"), true, &[]), Err(ChooseError::Pinned { .. })));
    }

    #[test]
    fn auto_unpins_but_keeps_the_stored_name_if_it_works() {
        let f = Fake::new(&[("wg0", Host::Foreign)]);
        assert_eq!(
            f.choose(Some(&Flag::Auto), Some("wg7"), true, &[]).unwrap(),
            ("wg7".into(), Source::Stored, false)
        );
        assert_eq!(
            f.choose(Some(&Flag::Auto), Some("wg0"), true, &[]).unwrap(),
            ("wireserve0".into(), Source::Free, false)
        );
    }

    #[test]
    fn exhaustion_lists_every_reason() {
        let host: Vec<(String, Host)> = candidates().map(|n| (n, Host::Foreign)).collect();
        let host: Vec<(&str, Host)> = host.iter().map(|(n, h)| (n.as_str(), *h)).collect();
        let f = Fake::new(&host);
        let Err(ChooseError::Exhausted(taken)) = f.choose(None, None, false, &[("wireserve5", "work")]) else {
            panic!("expected exhaustion");
        };
        assert_eq!(taken.len(), 16);
        assert!(taken.contains(&("wireserve5".into(), "kept by instance 'work'".into())));
        let msg = ChooseError::Exhausted(taken).to_string();
        assert!(msg.contains("wireserve0 (foreign)") && msg.contains("wireserve0..wireserve15"), "{msg}");
    }

    #[test]
    fn candidates_are_valid_interface_names() {
        let all: Vec<String> = candidates().collect();
        assert_eq!(all.first().unwrap(), "wireserve0");
        assert_eq!(all.last().unwrap(), "wireserve15");
        for n in &all {
            crate::wg::validate_ifname(n).unwrap();
        }
    }

    #[test]
    fn leftovers_cover_every_name_but_the_chosen_one() {
        let names = leftover_names("wireserve1", Some("mesh7"));
        assert_eq!(names.len(), 16 - 1 + 1);
        assert!(names.contains(&"mesh7".to_string()));
        assert!(!names.contains(&"wireserve1".to_string()));
        assert_eq!(leftover_names("wg0", Some("wg0")).len(), 16);
    }

    #[test]
    fn flag_parsing() {
        assert_eq!(Flag::parse("auto"), Flag::Auto);
        assert_eq!(Flag::parse("wg0"), name("wg0"));
    }

    /// The real probe against real interfaces, in a throwaway network
    /// namespace: a foreign WireGuard tunnel, a non-WireGuard interface,
    /// our own interface from an earlier run, and a free name.
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_probe_and_choice_against_real_interfaces() {
        use defguard_wireguard_rs::key::Key;
        if !crate::firewall::netns::reexec("ifname::tests::kernel_probe_and_choice_against_real_interfaces") {
            return;
        }
        let ours = crate::wg::clamp_private_key(&Key::generate()).to_string();
        let theirs = Key::generate().to_string();
        let sh = |script: &str| {
            let out = std::process::Command::new("sh").args(["-euc", script]).output().unwrap();
            assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
        };
        let dir = tempfile::tempdir().unwrap();
        let (k_ours, k_theirs) = (dir.path().join("ours"), dir.path().join("theirs"));
        std::fs::write(&k_ours, &ours).unwrap();
        std::fs::write(&k_theirs, &theirs).unwrap();
        sh(&format!(
            "ip link add wireserve0 type wireguard && wg set wireserve0 private-key {t}
             ip link add wireserve1 type dummy
             ip link add wireserve3 type wireguard && wg set wireserve3 private-key {o}",
            t = k_theirs.display(),
            o = k_ours.display()
        ));

        let unusable = |name: &str| match probe_host(name, &ours) {
            Probe::Unusable(reason) => reason,
            Probe::Usable { .. } => panic!("{name} should be unusable"),
        };
        assert!(unusable("wireserve0").contains("different private key"));
        assert!(unusable("wireserve1").contains("could not be read"));
        assert!(matches!(probe_host("wireserve2", &ours), Probe::Usable { ours: false, .. }));

        let reserved = BTreeMap::new();
        let req = Request {
            flag: None,
            stored: None,
            stored_pinned: false,
            reserved: &reserved,
        };
        let choice = choose(&req, |n| probe_host(n, &ours)).unwrap();
        assert_eq!((choice.ifname.as_str(), choice.source), ("wireserve3", Source::Reused));

        // While claimed, nobody else gets it — not even with the same key.
        assert!(unusable("wireserve3").contains("claimed by another wireserve agent"));
        drop(choice);
        assert!(matches!(probe_host("wireserve3", &ours), Probe::Usable { ours: true, .. }));
    }
}
