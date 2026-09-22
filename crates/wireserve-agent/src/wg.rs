//! Wraps `defguard_wireguard_rs`'s `WGApi<Kernel>` for the agent's own
//! interface: bring-up with this node's own keypair/addresses, and
//! reconciling the kernel peer set against each poll's `peers` array.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use defguard_wireguard_rs::error::WireguardInterfaceError;
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi};
use wireserve_types::{PeerInfo, ServiceInfo, TransitEndpoint, TransitForward, TransitPair};

/// Why `bring_up` can fail before it has touched anything.
#[derive(Debug, thiserror::Error)]
pub enum BringUpError {
    #[error(transparent)]
    Wg(#[from] WireguardInterfaceError),
    #[error(
        "refusing to take over the existing network interface '{ifname}': {reason}. \
         Bringing up the agent on an interface it did not create would flush that \
         interface's addresses, overwrite its private key and listen port, and remove \
         every peer configured on it — silently destroying whatever tunnel is currently \
         using that name, which may well be how this machine is reached. Start the agent \
         with `--ifname auto` to have it pick a free name, or `--ifname <name>` pointing \
         at an unused one, or remove the existing interface first if it really is disposable"
    )]
    InterfaceConflict { ifname: String, reason: String },
}

/// Applies Curve25519/X25519 "clamping" to a private key: clears the low 3
/// bits of the first byte and fixes the top two bits of the last byte.
/// `defguard_wireguard_rs::Key::generate()` returns `x25519_dalek`'s raw,
/// unclamped scalar, but the Linux kernel's WireGuard implementation always
/// clamps a private key before storing it — so a freshly generated key
/// round-trips back from the kernel as a *different* value than the one
/// that was sent in, even though both represent the same key for actual
/// tunnel use. Persisting (and comparing against) the clamped form keeps
/// this node's own state consistent with what the kernel will ever report
/// back via `read_interface_data`.
pub fn clamp_private_key(key: &Key) -> Key {
    let mut bytes = key.as_array();
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    Key::new(bytes)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "invalid interface name {0:?}: use 1-15 characters from A-Z, a-z, 0-9, '_', '.', '-' \
     (and not \".\" or \"..\")"
)]
pub struct InvalidIfname(pub String);

/// Rejects anything but a plain, exact interface name, before the name is
/// used anywhere. Every firewall rule the agent installs — its own table
/// and every rule it puts into another tool's chain — is scoped by this
/// name, so a name that some tool reads as a *pattern* would open more
/// than the mesh interface: iptables treats a trailing `+` as a wildcard
/// (`-i wg+` matches every `wg*` interface) and nft accepts `*` wildcards
/// in `iifname` strings. The kernel itself allows almost any byte except
/// `/` and whitespace; this is deliberately much narrower. 15 bytes is
/// `IFNAMSIZ` minus the NUL.
pub fn validate_ifname(name: &str) -> Result<(), InvalidIfname> {
    let ok = (1..=15).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(InvalidIfname(name.to_string()))
    }
}

/// Every interface other than `except` that has `addr` assigned.
pub fn interfaces_with_address(addr: IpAddr, except: &str) -> std::io::Result<Vec<String>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: every node of the list is valid until freeifaddrs; the
        // sockaddr is read as the type its family says it is.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        let found = match i32::from(unsafe { (*ifa.ifa_addr).sa_family }) {
            libc::AF_INET => {
                let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr))
            }
            _ => continue,
        };
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        if found == addr && name != except && !out.contains(&name) {
            out.push(name);
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

// ---- NAT-hairpin fix: LAN-address candidates (PLAN.md decisions log #85) ----

/// One of this node's own IPv4 interfaces that looks like a real LAN
/// uplink, for the NAT-hairpin LAN-candidate feature.
#[derive(Debug, Clone, Copy)]
pub struct LocalLan {
    pub addr: Ipv4Addr,
    pub prefix_len: u8,
}

/// Interface-name prefixes treated as virtual rather than a real LAN
/// uplink — a private address on one of these is a container bridge or
/// VPN overlay, not the home network this feature means to reach.
/// Judgment call, not exhaustive; worth revisiting if a real deployment's
/// LAN NIC gets misclassified.
const VIRTUAL_IFACE_PREFIXES: &[&str] = &[
    "lo", "docker", "veth", "br-", "virbr", "tun", "tap", "wg", "tailscale", "zt", "cni", "flannel", "podman",
];

fn looks_virtual(name: &str) -> bool {
    VIRTUAL_IFACE_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// This node's own private-range (RFC1918) IPv4 interfaces, in
/// `getifaddrs` enumeration order, excluding `except` (this node's own
/// mesh interface — same hygiene `interfaces_with_address` applies) and
/// anything that `looks_virtual`. IPv4 only: v1 of the NAT-hairpin fix has
/// no IPv6 LAN candidate — real hairpin is an IPv4 NAT problem. Impure —
/// the actual syscall; kept separate from the pure functions below so
/// those stay unit-testable without a live interface, same probe/choice
/// split as `interfaces_with_address` itself.
pub fn local_lan_ifaces(except: &str) -> std::io::Result<Vec<LocalLan>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: every node of the list is valid until freeifaddrs; the
        // sockaddr is read as the type its family says it is.
        let ifa = unsafe { &*cursor };
        cursor = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        // SAFETY: family checked above.
        let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
        let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
        // SAFETY: ifa_netmask is non-null and shares ifa_addr's family for
        // an AF_INET entry.
        let mask_sin = unsafe { &*ifa.ifa_netmask.cast::<libc::sockaddr_in>() };
        let prefix_len = u32::from_be(mask_sin.sin_addr.s_addr).count_ones() as u8;
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
        if addr.is_private() && name != except && !looks_virtual(&name) {
            out.push(LocalLan { addr, prefix_len });
        }
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// This node's single "best" LAN address to advertise on `/register` and
/// `/poll`: the first entry `local_lan_ifaces` found.
#[must_use]
pub fn pick_lan_address(ifaces: &[LocalLan]) -> Option<Ipv4Addr> {
    ifaces.first().map(|i| i.addr)
}

fn mask_for(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

fn network_address(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(addr) & mask_for(prefix_len))
}

/// This node's own local subnets (network address, prefix length), masked
/// down from each interface's address+netmask — used to test whether a
/// PEER's `lan_addr` is reachable without a router at all.
#[must_use]
pub fn own_lan_subnets(ifaces: &[LocalLan]) -> Vec<(Ipv4Addr, u8)> {
    ifaces.iter().map(|i| (network_address(i.addr, i.prefix_len), i.prefix_len)).collect()
}

/// Whether `addr` falls inside any of `own_subnets`. A `true` result is a
/// hint, not proof, that a peer advertising it is actually on this LAN —
/// two unrelated sites both using `192.168.1.0/24` collide here by
/// construction, which is exactly why `resolve_lan_candidate` treats a
/// match as an optimistic attempt to verify, never a fact.
#[must_use]
pub fn is_on_own_lan(own_subnets: &[(Ipv4Addr, u8)], addr: Ipv4Addr) -> bool {
    own_subnets.iter().any(|&(net, prefix_len)| network_address(addr, prefix_len) == net)
}

/// This node's ranked endpoint-candidate tiers for reaching a peer.
/// `Wan` needs no entry in [`RANKED_TIERS`]: every peer always resolves
/// *some* WAN candidate via `choose_peer_endpoint`'s existing explicit/
/// v4/v6 chain (or `None`), so it is [`EndpointTracker`]'s universal,
/// always-available fallback — only ever a *return value*, never a key
/// tracked in its per-tier backoff state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointTier {
    Lan,
    Reflexive,
    Wan,
}

/// Every tracked tier, most-preferred first. NAT-traversal step 3
/// (PLAN.md M23, opt-in transit) is deliberately **not** a tier here —
/// it reroutes `AllowedIPs`, not `Endpoint=`, and is layered above this
/// whole mechanism instead. See `TransitAssignments` and
/// `desired_peers`'s pass 2.
const RANKED_TIERS: &[EndpointTier] = &[EndpointTier::Lan, EndpointTier::Reflexive];

/// One peer's currently-advertised candidate values, this cycle, built
/// once per cycle by the caller (`poll_loop::run_once`) from a
/// `PeerInfo` plus this node's own `own_lan_subnets` (the `Lan` tier's
/// subnet-containment check happens here — `Reflexive` has no analogous
/// check; any structurally well-formed value is a plausible candidate,
/// same as `is_valid_reflexive_addr`'s own limited guarantee).
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerTierCandidates<'a> {
    pub lan: Option<&'a str>,
    pub reflexive: Option<&'a str>,
}

/// Builds `peer`'s candidates for this cycle. A `Lan` value is present
/// only when it both parses and falls inside one of `own_subnets` (see
/// `is_on_own_lan`'s doc comment on why that's a hint, not proof); a
/// `Reflexive` value is present whenever it's structurally well-formed.
#[must_use]
pub fn peer_tier_candidates<'a>(own_subnets: &[(Ipv4Addr, u8)], peer: &'a PeerInfo) -> PeerTierCandidates<'a> {
    let lan = peer
        .lan_addr
        .as_deref()
        .filter(|s| s.parse::<Ipv4Addr>().is_ok_and(|a| is_on_own_lan(own_subnets, a)));
    let reflexive = peer.reflexive_addr.as_deref().filter(|s| wireserve_types::is_valid_reflexive_addr(s));
    PeerTierCandidates { lan, reflexive }
}

fn candidate_value<'a>(candidates: &PeerTierCandidates<'a>, tier: EndpointTier) -> Option<&'a str> {
    match tier {
        EndpointTier::Lan => candidates.lan,
        EndpointTier::Reflexive => candidates.reflexive,
        EndpointTier::Wan => None,
    }
}

/// Per-tier grace/backoff bookkeeping — at most `RANKED_TIERS.len()`
/// entries ever exist in an `EndpointPeerState`'s map. `last_seen_value`
/// lives here, per tier, rather than once on `EndpointPeerState`: roam
/// detection (see `resolve_endpoint_candidate`) has to work for a tier
/// that isn't even the currently-active one — a NAT remapping can just
/// as easily happen to a candidate that's presently sitting out a
/// backoff window on `Wan`, and that stale backoff history must not
/// survive the address it was measured against.
#[derive(Debug, Clone)]
struct TierState {
    last_seen_value: String,
    next_retry_at: Option<std::time::Instant>,
    backoff: std::time::Duration,
}

impl TierState {
    fn fresh(value: &str) -> Self {
        Self { last_seen_value: value.to_string(), next_retry_at: None, backoff: ENDPOINT_RETRY_BACKOFF_INITIAL }
    }
}

/// Per-peer endpoint-tier state across poll cycles. `Instant`, not
/// wall-clock time — process-local scheduling only, never persisted,
/// never compared across a restart (an agent restart simply repeats one
/// optimistic attempt per tier, which is acceptable).
#[derive(Debug, Clone)]
pub struct EndpointPeerState {
    current: EndpointTier,
    switched_at: std::time::Instant,
    /// The kernel's `last_handshake` at the moment `current` last
    /// switched to its present tier. A grace-window "success" is
    /// detected as this value *advancing* — a genuinely new handshake
    /// happened — never by comparing it against `switched_at` directly:
    /// `Instant` and the kernel's wall-clock `last_handshake` are
    /// different clocks and cannot be compared. `switched_at` is used
    /// only for the (purely relative, monotonic) grace-window/backoff
    /// deadlines below.
    baseline_handshake: Option<chrono::DateTime<chrono::Utc>>,
    per_tier: HashMap<EndpointTier, TierState>,
}

/// How long a freshly-tried tier gets to produce a real handshake before
/// falling back — long enough for at least two
/// `persistent_keepalive`-triggered handshake attempts.
pub const ENDPOINT_GRACE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// The first backoff before retrying a tier that just failed.
pub const ENDPOINT_RETRY_BACKOFF_INITIAL: std::time::Duration = std::time::Duration::from_secs(120);
/// The cap the backoff doubles up to on repeated failures — bounds the
/// cost of a persistently-wrong candidate (a subnet collision, a stale
/// NAT mapping) to one brief, infrequent probe rather than either
/// permanent failure or hot flapping.
pub const ENDPOINT_RETRY_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(1800);

/// Picks the best tier available this cycle: the first (most preferred)
/// tier in [`RANKED_TIERS`] that both has a candidate this cycle and
/// isn't itself inside a backoff window. `None` if every ranked tier is
/// unavailable or backed off, meaning fall to [`EndpointTier::Wan`].
fn pick_tier(
    candidates: &PeerTierCandidates<'_>,
    per_tier: &HashMap<EndpointTier, TierState>,
    now: std::time::Instant,
) -> Option<EndpointTier> {
    RANKED_TIERS.iter().copied().find(|&tier| {
        if candidate_value(candidates, tier).is_none() {
            return false;
        }
        match per_tier.get(&tier).and_then(|t| t.next_retry_at) {
            Some(retry_at) => now >= retry_at,
            None => true,
        }
    })
}

/// Decides this cycle's endpoint-tier preference for one peer, and the
/// updated state to keep (`None` to stop tracking it entirely — no
/// candidate on any ranked tier at all, today's plain-`Wan` behavior).
/// Pure: `now` and `kernel_last_handshake` are read once per cycle by
/// the caller (`poll_loop::run_once`, via `tunnel_peers`) and passed in,
/// same pure-decision/stateful-caller split as the rest of this file.
///
/// Generalizes the original LAN-only state machine to any number of
/// ranked tiers: each tracks its own independent grace-window/backoff
/// schedule (`EndpointPeerState::per_tier`), and when the active tier's
/// grace window expires without confirmation, the very same cycle tries
/// the next-best tier that isn't itself backed off — rather than
/// jumping straight to `Wan` — before eventually landing there once
/// nothing ranked is available.
#[must_use]
pub fn resolve_endpoint_candidate(
    candidates: PeerTierCandidates<'_>,
    kernel_last_handshake: Option<chrono::DateTime<chrono::Utc>>,
    state: Option<EndpointPeerState>,
    now: std::time::Instant,
) -> (EndpointTier, Option<EndpointPeerState>) {
    if RANKED_TIERS.iter().all(|&t| candidate_value(&candidates, t).is_none()) {
        return (EndpointTier::Wan, None);
    }

    let mut per_tier: HashMap<EndpointTier, TierState> =
        state.as_ref().map(|s| s.per_tier.clone()).unwrap_or_default();

    // Roam detection, per tier, independent of which tier (if any) is
    // currently active: a candidate whose value differs from what was
    // last seen for that specific tier gets a fresh start -- its prior
    // backoff history says nothing about a new address/NAT mapping.
    for &tier in RANKED_TIERS {
        if let Some(value) = candidate_value(&candidates, tier) {
            if per_tier.get(&tier).is_some_and(|t| t.last_seen_value != value) {
                per_tier.remove(&tier);
            }
        }
    }

    // Try to continue on the currently-active tier, if it's ranked,
    // still has a candidate this cycle, and didn't just get reset above
    // by the roam check (a survived entry means "same tier, same value").
    if let Some(s) = &state {
        if RANKED_TIERS.contains(&s.current) {
            if let (Some(_value), true) = (candidate_value(&candidates, s.current), per_tier.contains_key(&s.current)) {
                let confirmed = match (kernel_last_handshake, s.baseline_handshake) {
                    (Some(h), Some(baseline)) => h > baseline,
                    (Some(_), None) => true,
                    (None, _) => false,
                };
                let tier = s.current;
                if confirmed {
                    per_tier.get_mut(&tier).unwrap().backoff = ENDPOINT_RETRY_BACKOFF_INITIAL;
                    return (
                        tier,
                        Some(EndpointPeerState { current: tier, switched_at: s.switched_at, baseline_handshake: kernel_last_handshake, per_tier }),
                    );
                } else if now.duration_since(s.switched_at) < ENDPOINT_GRACE_WINDOW {
                    return (
                        tier,
                        Some(EndpointPeerState { current: tier, switched_at: s.switched_at, baseline_handshake: s.baseline_handshake, per_tier }),
                    );
                }
                // Grace window expired without confirmation -- fail this
                // tier's own backoff, then fall through to reselect.
                let entry = per_tier.get_mut(&tier).unwrap();
                entry.next_retry_at = Some(now + entry.backoff);
                entry.backoff = (entry.backoff * 2).min(ENDPOINT_RETRY_BACKOFF_MAX);
            }
        }
    }

    // Reselect: reached for a brand-new peer, a peer currently on `Wan`,
    // an active tier whose candidate vanished or just roamed, or an
    // active tier that just failed its grace window above -- in every
    // case, pick whichever ranked tier is best available this cycle
    // (preserving any existing tier's accumulated backoff, since a
    // retry-due tier is not a fresh one), or fall to `Wan`.
    match pick_tier(&candidates, &per_tier, now) {
        Some(tier) => {
            let value = candidate_value(&candidates, tier).expect("pick_tier only ever returns a tier with a candidate this cycle");
            per_tier.entry(tier).or_insert_with(|| TierState::fresh(value));
            (
                tier,
                Some(EndpointPeerState { current: tier, switched_at: now, baseline_handshake: kernel_last_handshake, per_tier }),
            )
        }
        None => (
            EndpointTier::Wan,
            Some(EndpointPeerState { current: EndpointTier::Wan, switched_at: now, baseline_handshake: None, per_tier }),
        ),
    }
}

/// Tracks every peer's endpoint-tier state across poll cycles —
/// in-memory only. Constructed once at daemon startup and lives exactly
/// as long as `WgInterface` (same lifetime pattern as its own
/// `applied`/`routed`), threaded through `poll_loop::PollContext`.
#[derive(Debug, Default)]
pub struct EndpointTracker {
    states: HashMap<String, EndpointPeerState>,
}

impl EndpointTracker {
    pub fn resolve(
        &mut self,
        pubkey: &str,
        candidates: PeerTierCandidates<'_>,
        kernel_last_handshake: Option<chrono::DateTime<chrono::Utc>>,
        now: std::time::Instant,
    ) -> EndpointTier {
        let state = self.states.remove(pubkey);
        let (tier, new_state) = resolve_endpoint_candidate(candidates, kernel_last_handshake, state, now);
        if let Some(new_state) = new_state {
            self.states.insert(pubkey.to_string(), new_state);
        }
        tier
    }

    /// Drops tracked state for any pubkey not in `current` — a peer that
    /// left the mesh must not accumulate forever (same care as
    /// `WgInterface::reconcile`'s `peers_to_remove`).
    pub fn prune<'a>(&mut self, current: impl Iterator<Item = &'a str>) {
        let keep: std::collections::HashSet<&str> = current.collect();
        self.states.retain(|k, _| keep.contains(k.as_str()));
    }

    /// Every pubkey with real tracked history (it once had a ranked
    /// candidate to try) whose current resolution has fallen all the way
    /// to [`EndpointTier::Wan`]. Excludes a pubkey with no tracked entry
    /// at all: the ordinary plain-WAN-works-fine case, which must never
    /// request transit help for free. This is exactly
    /// `EndpointPeerState::current == Wan` on an entry that exists —
    /// already present in the state machine above, no new tracking
    /// needed.
    ///
    /// This is the raw *tier* signal only — "my LAN/Reflexive NAT-punch
    /// probe failed" — not this node's actual "I need transit help"
    /// signal, since a failed probe still falls back to a working plain
    /// WAN dial in the common case. See [`Self::peers_wanting_transit`]
    /// for the signal that accounts for that.
    pub fn peers_on_wan(&self) -> Vec<&str> {
        self.states
            .iter()
            .filter(|(_, s)| s.current == EndpointTier::Wan)
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// This node's actual "I need transit help reaching this peer" signal
    /// (PLAN.md M23) — [`Self::peers_on_wan`] narrowed to peers this node
    /// does NOT currently have a live handshake with. `peers_on_wan`
    /// alone conflates "my LAN/Reflexive NAT-punch probe failed" with "I
    /// can't reach this peer at all" — but a failed probe still falls
    /// back to a working plain WAN dial in the common case, and that
    /// fallback must not trigger a false transit request. Uses the same
    /// freshness ground truth as [`transit_reachable_peers`],
    /// deliberately: a peer must be able to fail this same test on both
    /// the "do I need help" and "can I offer help" sides for the same
    /// reason.
    pub fn peers_wanting_transit<'a>(
        &'a self,
        handshakes: &HashMap<String, Option<chrono::DateTime<chrono::Utc>>>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<&'a str> {
        let fresh: std::collections::HashSet<&str> = transit_reachable_peers(handshakes, now).into_iter().collect();
        self.peers_on_wan().into_iter().filter(|pk| !fresh.contains(pk)).collect()
    }
}

/// How fresh a kernel `last_handshake` must be to count as "currently,
/// actually reachable" for transit purposes (PLAN.md M23) — comfortably
/// above WireGuard's own ~120s `REKEY_AFTER_TIME` ceiling under
/// continuous 25s keepalive traffic (see `desired_peers`'s
/// `persistent_keepalive_interval`), so a genuinely live connection is
/// never misreported, while still catching a dropped peer within a
/// handful of poll cycles.
pub const TRANSIT_REACHABLE_HANDSHAKE_MAX: std::time::Duration = std::time::Duration::from_secs(150);

/// This node's own ground truth for "I actually reach this peer right
/// now" (PLAN.md M23) — the kernel's own `last_handshake` freshness,
/// **not** `EndpointTracker`'s tier state, which conflates "never had a
/// ranked candidate to try" (the ordinary, fine, plain-WAN case) with
/// "tried and failed." Sorted for deterministic truncation by the caller
/// (`poll_loop::run_once`, to
/// [`wireserve_types::MAX_TRANSIT_REACHABLE_PER_POLL`]) — never
/// `HashMap`-iteration-order-dependent.
#[must_use]
pub fn transit_reachable_peers(
    handshakes: &HashMap<String, Option<chrono::DateTime<chrono::Utc>>>,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<&str> {
    let max_age = chrono::Duration::from_std(TRANSIT_REACHABLE_HANDSHAKE_MAX)
        .expect("TRANSIT_REACHABLE_HANDSHAKE_MAX fits in a chrono::Duration");
    let mut fresh: Vec<&str> = handshakes
        .iter()
        .filter_map(|(pubkey, handshake)| {
            let h = (*handshake)?;
            (now - h <= max_age).then_some(pubkey.as_str())
        })
        .collect();
    fresh.sort_unstable();
    fresh
}

/// A WireGuard peer's own `/32` + `/128` `AllowedIPs` — never a shared
/// subnet block, so every peer only ever routes to itself on this
/// interface (same non-overlapping-`AllowedIPs` reasoning as spec §9's
/// `export-config`). Kept as a free function so it's testable without a
/// live interface.
pub fn peer_allowed_ips(ip4: &str, ip6: &str) -> Vec<IpAddrMask> {
    let mut out = Vec::new();
    if let Ok(v4) = ip4.parse::<Ipv4Addr>() {
        out.push(IpAddrMask::host(IpAddr::V4(v4)));
    }
    if let Ok(v6) = ip6.parse::<Ipv6Addr>() {
        out.push(IpAddrMask::host(IpAddr::V6(v6)));
    }
    out
}

/// Picks which of a peer's endpoint candidates to actually configure.
/// The operator's/passive-fallback's explicit `endpoint_addr` wins over
/// the actively-probed `endpoint_addr_v4`/`_v6` pair, *unless* it turns
/// out to be an IPv6 literal and this node has no real v6 of its own —
/// the coordinator's `endpoint_addr` column is filled from whatever
/// family a node's poll happened to arrive over (routing, not a
/// considered choice), so a dual-stack peer can just as easily end up
/// with a v6 address sitting there as a v4 one. `prefer_ipv6` — this
/// node's own live "do I have real working IPv6 right now" self-test
/// against the coordinator (see `probe::has_working_ipv6`, threaded in
/// from `poll_loop::run_once`) — is what an IPv6-less node lacks, so an
/// unusable `endpoint_addr` falls through to the v4/v6 pair below exactly
/// like the no-explicit-value case already did (the incident that pair
/// was added to fix: a peer's auto-detected endpoint happened to be IPv6,
/// which an IPv6-less node could never dial — that fix only covered the
/// pair, not this field, until now).
///
/// `tier` — this cycle's `EndpointTracker::resolve` result for this peer
/// (`None` when the tracker isn't tracking any ranked candidate for it
/// at all) — takes priority over all of the above when it names a
/// ranked tier: a direct, router-free (`Lan`) or NAT-punched
/// (`Reflexive`) path beats every WAN candidate, operator override
/// included, since a ranked tier is only ever *offered* when it has
/// already been optimistically verified or is being re-verified (see
/// `resolve_endpoint_candidate`). Falls through to the WAN logic below
/// when the named tier's own value doesn't parse, or (for `Lan`, which
/// is a bare address) no WAN candidate exists to borrow a port from
/// (PLAN.md decisions log #85, #90+).
pub fn choose_peer_endpoint(p: &PeerInfo, prefer_ipv6: bool, tier: Option<EndpointTier>) -> Option<String> {
    match tier {
        Some(EndpointTier::Lan) => {
            if let (Some(ip), Some(port)) =
                (p.lan_addr.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok()), wan_port(p))
            {
                return Some(format!("{ip}:{port}"));
            }
        }
        Some(EndpointTier::Reflexive) => {
            if let Some(addr) = p.reflexive_addr.as_deref() {
                if wireserve_types::is_valid_reflexive_addr(addr) {
                    return Some(addr.to_string());
                }
            }
        }
        Some(EndpointTier::Wan) | None => {}
    }
    if let Some(explicit) = &p.endpoint_addr {
        let is_ipv6_literal = explicit.starts_with('[');
        if !is_ipv6_literal || prefer_ipv6 {
            return Some(explicit.clone());
        }
    }
    match (&p.endpoint_addr_v4, &p.endpoint_addr_v6) {
        (Some(v4), Some(v6)) => Some(if prefer_ipv6 { v6.clone() } else { v4.clone() }),
        (Some(v4), None) => Some(v4.clone()),
        (None, Some(v6)) => Some(v6.clone()),
        (None, None) => None,
    }
}

/// The port half of whichever WAN candidate a peer has — the LAN
/// candidate is a bare address (`PeerInfo::lan_addr`), so it borrows its
/// port from here rather than carrying its own.
fn wan_port(p: &PeerInfo) -> Option<u16> {
    [p.endpoint_addr_v4.as_deref(), p.endpoint_addr.as_deref(), p.endpoint_addr_v6.as_deref()]
        .into_iter()
        .flatten()
        .find_map(|s| s.rsplit_once(':').and_then(|(_, port)| port.parse().ok()))
}

/// Transited peer's pubkey → its via peer's pubkey (PLAN.md M23), built
/// once per cycle in `poll_loop::run_once` from a `/poll` response's
/// `PeerInfo::transit_via` fields, filtered to exclude this node's own
/// pubkey as a key (defensive — the coordinator should never name this
/// node itself as something to route via itself).
pub type TransitAssignments<'a> = HashMap<&'a str, &'a str>;

/// Builds the desired kernel peer set (keyed by pubkey) from a `/poll`
/// response's `peers` array, skipping this node's own entry (peers
/// includes self — PLAN.md decisions log #12) and any entry whose pubkey
/// doesn't parse (defensive: a malformed directory entry must not crash
/// reconciliation for every other peer). `prefer_ipv6` is this node's own
/// live self-test result — see `choose_peer_endpoint`. Stays fully
/// pure/network-free: the actual probe happens once per cycle in
/// `poll_loop::run_once`, outside this module.
///
/// A peer's `AllowedIPs` also hold the address of every service it owns
/// (`services`, already through `vip::sanitize`), which is what routes a
/// connection to `<name>.wg` to that peer.
///
/// `endpoint_tiers` is this cycle's `EndpointTracker` resolution per
/// peer pubkey (PLAN.md decisions log #85, #90+) — a peer absent from it
/// (or resolved to `Wan`) gets plain WAN behavior, unchanged from before
/// this feature existed.
///
/// `transit` (PLAN.md M23) makes this a **two-pass** build. `AllowedIPs`
/// is dual-purpose — an outbound routing table and an inbound
/// cryptographic source filter — so a destination can only ever sit in
/// one peer's `AllowedIPs` at a time:
///
/// - **Pass 1** builds one entry for every peer that is *not* a key in
///   `transit` (i.e. not itself being redirected elsewhere) — the same
///   logic as before this feature existed.
/// - **Pass 2** folds each transited peer's address(es) and owned VIPs
///   into its `via` peer's *already-built* entry from pass 1, instead of
///   giving the transited peer its own entry at all.
///
/// Edge cases, all handled by construction, not special-cased: a `via`
/// peer that's also an ordinary direct peer is the common case, not
/// special (pass 1 builds it normally, pass 2 just extends it); a
/// dangling `via` (unparseable, or naming a peer this node has no record
/// for — a stale/inconsistent directory) is a safe no-op, since there is
/// nothing to fold into and the transited peer correctly gets no entry
/// either; a cycle (A via B, B via A — shouldn't happen given the
/// coordinator excludes both endpoints from candidacy, but a
/// stale/adversarial coordinator could send it) leaves both peers with
/// no entry at all, safely, since pass 1 skips both.
pub fn desired_peers(
    peers: &[PeerInfo],
    services: &[ServiceInfo],
    self_pubkey: &str,
    prefer_ipv6: bool,
    endpoint_tiers: &HashMap<String, EndpointTier>,
    transit: &TransitAssignments<'_>,
) -> HashMap<Key, Peer> {
    let mut desired = HashMap::new();
    for p in peers {
        if p.pubkey == self_pubkey || transit.contains_key(p.pubkey.as_str()) {
            continue;
        }
        let Ok(key) = Key::try_from(p.pubkey.as_str()) else {
            tracing::warn!(peer = %p.name, "skipping peer with unparseable pubkey");
            continue;
        };
        let mut peer = Peer::new(key.clone());
        peer.allowed_ips = peer_allowed_ips(&p.ip4, &p.ip6);
        peer.allowed_ips.extend(
            owned_vips(services, &p.name).map(|vip| IpAddrMask::host(IpAddr::V4(vip))),
        );
        let tier = endpoint_tiers.get(&p.pubkey).copied();
        if let Some(endpoint) = choose_peer_endpoint(p, prefer_ipv6, tier) {
            if let Err(e) = peer.set_endpoint(&endpoint) {
                tracing::warn!(peer = %p.name, error = %e, "could not resolve peer endpoint");
            }
        }
        // This node likely roams networks (dynamic DNS, NAT rebinding) —
        // same reasoning as spec §9's export-config PersistentKeepalive.
        peer.persistent_keepalive_interval = Some(25);
        desired.insert(key, peer);
    }

    // Pass 2: fold each transited peer into its via peer's entry above.
    for p in peers {
        let Some(&via) = transit.get(p.pubkey.as_str()) else {
            continue;
        };
        let Ok(via_key) = Key::try_from(via) else {
            continue;
        };
        let Some(via_peer) = desired.get_mut(&via_key) else {
            continue;
        };
        via_peer.allowed_ips.extend(peer_allowed_ips(&p.ip4, &p.ip6));
        via_peer
            .allowed_ips
            .extend(owned_vips(services, &p.name).map(|vip| IpAddrMask::host(IpAddr::V4(vip))));
    }

    desired
}

/// The addresses of the services `node` owns.
fn owned_vips<'a>(services: &'a [ServiceInfo], node: &'a str) -> impl Iterator<Item = Ipv4Addr> + 'a {
    services
        .iter()
        .filter(move |s| s.node == node)
        .filter_map(|s| s.vip4.as_deref()?.parse().ok())
}

/// Builds this node's own forwarding rules for the transit pairs it
/// carries this cycle (PLAN.md M23), from `PollResponse::transit_carrying`
/// plus each named pubkey's own `PeerInfo`/`ServiceInfo` entries in the
/// same response. A pair naming a pubkey this node has no peer record for
/// (a stale/inconsistent directory) is a safe no-op — dropped rather than
/// guessed at, same defensive posture as `desired_peers`'s dangling-`via`
/// handling.
#[must_use]
pub fn transit_forwards(peers: &[PeerInfo], services: &[ServiceInfo], carrying: &[TransitPair]) -> Vec<TransitForward> {
    let endpoint = |pubkey: &str| -> Option<TransitEndpoint> {
        let p = peers.iter().find(|p| p.pubkey == pubkey)?;
        Some(TransitEndpoint {
            ip4: p.ip4.parse().ok(),
            ip6: p.ip6.parse().ok(),
            vips: owned_vips(services, &p.name).collect(),
        })
    };
    carrying
        .iter()
        .filter_map(|pair| Some(TransitForward { near: endpoint(&pair.a)?, far: endpoint(&pair.c)? }))
        .collect()
}

/// Every address this node routes into the mesh interface: each peer's
/// `AllowedIPs`, and this node's own service addresses. The latter reach
/// no peer — the firewall's output rewrite turns a local connection to one
/// into a local connection to the service's target port — but they need a
/// route for the connection to start at all on a host with no default
/// route, and it has to be this interface, whose address a local client
/// then connects from.
pub fn desired_routes(peers: &HashMap<Key, Peer>, own_vips: impl Iterator<Item = Ipv4Addr>) -> BTreeSet<IpAddr> {
    peers
        .values()
        .flat_map(|p| &p.allowed_ips)
        .map(|a| a.address)
        .chain(own_vips.map(IpAddr::V4))
        .collect()
}

/// Computes which currently-applied pubkeys are no longer desired (to
/// `remove_peer`) — kept pure/testable separately from the netlink calls.
pub fn peers_to_remove<'a>(
    applied: impl Iterator<Item = &'a Key>,
    desired: &HashMap<Key, Peer>,
) -> Vec<Key> {
    applied
        .filter(|k| !desired.contains_key(*k))
        .cloned()
        .collect()
}

/// Computes which desired peers actually need a `configure_peer` call:
/// new peers, or ones whose configuration changed since last applied.
/// Security review F6 — kept pure/testable separately from the netlink
/// calls, same reasoning as `peers_to_remove`. See `WgInterface::reconcile`
/// for why re-sending an unchanged peer defeats WireGuard's own roaming
/// correction.
pub fn peers_to_configure<'a>(
    applied: &HashMap<Key, Peer>,
    desired: &'a HashMap<Key, Peer>,
) -> Vec<&'a Peer> {
    desired
        .iter()
        .filter(|(key, peer)| applied.get(*key) != Some(*peer))
        .map(|(_, peer)| peer)
        .collect()
}

/// What the kernel reports for each peer on `ifname`, for `list`. Reads
/// through its own handle rather than the daemon's `WgInterface`, which
/// the poll loop owns; reading is harmless alongside it.
pub fn tunnel_peers(ifname: &str) -> Result<Vec<crate::ipc::protocol::TunnelPeer>, WireguardInterfaceError> {
    let host = WGApi::<Kernel>::new(ifname.to_string())?.read_interface_data()?;
    Ok(host
        .peers
        .values()
        .map(|p| crate::ipc::protocol::TunnelPeer {
            pubkey: p.public_key.to_string(),
            endpoint: p.endpoint.map(|e| e.to_string()),
            // The kernel reports "never" as time zero.
            last_handshake: p
                .last_handshake
                .filter(|t| *t > std::time::SystemTime::UNIX_EPOCH)
                .map(chrono::DateTime::<chrono::Utc>::from),
        })
        .collect())
}

/// See [`WgInterface::classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    Free,
    Ours,
    Foreign(String),
}

pub struct WgInterface {
    api: WGApi<Kernel>,
    ifname: String,
    applied: HashMap<Key, Peer>,
    /// What `routes::sync` last installed, so it only runs on a change.
    routed: BTreeSet<IpAddr>,
}

impl WgInterface {
    pub fn new(ifname: impl Into<String>) -> Result<Self, WireguardInterfaceError> {
        let ifname = ifname.into();
        let api = WGApi::<Kernel>::new(ifname.clone())?;
        Ok(Self {
            api,
            ifname,
            applied: HashMap::new(),
            routed: BTreeSet::new(),
        })
    }

    /// This interface's name — for callers (the poll loop) that need to
    /// pass it to a free function like `local_lan_ifaces`/`tunnel_peers`
    /// without duplicating the string themselves.
    #[must_use]
    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Whether a network interface with this name already exists on the
    /// host, WireGuard or otherwise. Asked directly rather than inferred
    /// from a netlink error, because the distinction that matters here
    /// ("something already owns this name") is not one the WireGuard API
    /// reports cleanly: `create_interface` deliberately treats `EEXIST` as
    /// success so that restarts are idempotent.
    ///
    /// `if_nametoindex`, not `/sys/class/net`: sysfs shows the network
    /// namespace of whoever mounted it, which is not ours when the agent is
    /// started in a namespace without its own sysfs mount (`nsenter`,
    /// `unshare -n`) — there it would call a name that is taken here free.
    /// Anything but "no such device" counts as taken: when in doubt, the
    /// name is not ours to configure.
    fn interface_exists(ifname: &str) -> bool {
        let Ok(name) = std::ffi::CString::new(ifname) else {
            return true;
        };
        // SAFETY: `name` is a valid NUL-terminated string for the call.
        if unsafe { libc::if_nametoindex(name.as_ptr()) } != 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ENODEV)
    }

    /// Who has this interface name right now, as far as the host itself
    /// can tell: nobody, this node (a WireGuard device carrying our own
    /// private key — our interface from a previous run), or something
    /// else. Claims by other agents are a separate question
    /// (`crate::lock`).
    pub fn classify(&self, private_key_b64: &str) -> Slot {
        if !Self::interface_exists(&self.ifname) {
            return Slot::Free;
        }
        match self.api.read_interface_data() {
            Ok(host) => {
                // The kernel always reports a clamped key back (see
                // `clamp_private_key`); clamp our own candidate too so
                // an unclamped persisted key (e.g. from a state file
                // written before this fix) still compares equal to the
                // same key's clamped, kernel-reported form.
                let ours = Key::try_from(private_key_b64)
                    .ok()
                    .map(|k| clamp_private_key(&k));
                match (&host.private_key, &ours) {
                    (Some(existing), Some(ours)) if existing == ours => Slot::Ours,
                    _ => Slot::Foreign(
                        "it is a WireGuard interface configured with a different private key, \
                         so it belongs to another tunnel"
                            .to_string(),
                    ),
                }
            }
            Err(err) => Slot::Foreign(format!(
                "an interface with that name exists but its WireGuard configuration could \
                 not be read ({err})"
            )),
        }
    }

    /// The ownership check `bring_up` depends on, runnable on its own —
    /// `cmd_daemon` calls it **before touching any firewall state**. The
    /// firewall rules are keyed on the interface *name*, so running them
    /// first for a name that belongs to someone else (a wg-quick `wg0`, or
    /// a typo like `--ifname eth0`) would default-deny that interface —
    /// cutting off the other tunnel, or SSH — and the host-firewall
    /// interop would open it through ufw/firewalld, all before `bring_up`
    /// got the chance to refuse. Passing this means the name is free or
    /// is this agent's own interface from a previous run.
    pub fn preflight(&self, private_key_b64: &str) -> Result<(), BringUpError> {
        match self.classify(private_key_b64) {
            Slot::Free => Ok(()),
            Slot::Ours => {
                tracing::info!(
                    ifname = %self.ifname,
                    "reusing this agent's own existing WireGuard interface"
                );
                Ok(())
            }
            Slot::Foreign(reason) => Err(BringUpError::InterfaceConflict {
                ifname: self.ifname.clone(),
                reason,
            }),
        }
    }

    /// Creates the interface and applies this node's own identity. Must be
    /// called once at daemon startup before any peer reconciliation.
    ///
    /// **Refuses to adopt an interface this agent did not create.** The
    /// underlying library is idempotent to a fault: `create_interface`
    /// swallows `EEXIST`, and `configure_interface` then flushes every
    /// address from the interface, overwrites its private key and listen
    /// port, and sends the WireGuard `ReplacePeers` flag, which removes
    /// all of its existing peers. On a host that already has a `wg0` —
    /// the default name `wg-quick` uses, and a common way to reach a
    /// machine remotely — starting this daemon would therefore tear down
    /// that tunnel without a word. So: if the name is already taken, it
    /// is only reused when the interface is a readable WireGuard device
    /// whose private key is the one in this node's own state, i.e. it is
    /// this agent's own interface from a previous run.
    pub fn bring_up(
        &mut self,
        private_key_b64: &str,
        ip4: Ipv4Addr,
        ip6: Ipv6Addr,
        listen_port: u16,
    ) -> Result<(), BringUpError> {
        // Checked again here even though `cmd_daemon` already ran it:
        // cheap, and it keeps `bring_up` safe on its own.
        self.preflight(private_key_b64)?;

        self.api.create_interface()?;
        let config = InterfaceConfiguration {
            name: self.ifname.clone(),
            prvkey: private_key_b64.to_string(),
            addresses: vec![
                IpAddrMask::host(IpAddr::V4(ip4)),
                IpAddrMask::host(IpAddr::V6(ip6)),
            ],
            port: listen_port,
            peers: Vec::new(),
            mtu: None,
            fwmark: None,
        };
        self.api.configure_interface(&config)?;
        Ok(())
    }

    /// Reconciles the kernel peer set to exactly `peers` (minus `self`).
    ///
    /// **Only calls `configure_peer` for peers that are new or actually
    /// changed** (security review F6): re-sending an unchanged peer's
    /// config on every cycle — including its `Endpoint` — resets
    /// WireGuard's own kernel-level roaming correction every cycle
    /// (`persistent_keepalive`/normal traffic updates the kernel's live
    /// endpoint when a peer's source address changes, e.g. after a NAT
    /// rebind; spec §4.2 explicitly relies on this), defeating the exact
    /// mechanism spec §4.2 relies on to correct a stale `endpoint_addr`.
    /// `Peer` derives `PartialEq` over all its fields, and neither side
    /// of this comparison is ever populated with real kernel stats
    /// (`last_handshake`/`tx_bytes`/`rx_bytes` stay at their `Peer::new`
    /// defaults on both the freshly-built `desired` value and whatever
    /// was stored in `self.applied` on a previous cycle), so the
    /// comparison only ever reflects the fields this code actually sets.
    pub fn reconcile(
        &mut self,
        peers: &[PeerInfo],
        services: &[ServiceInfo],
        self_pubkey: &str,
        prefer_ipv6: bool,
        endpoint_tiers: &HashMap<String, EndpointTier>,
        transit: &TransitAssignments<'_>,
    ) -> Result<(), WireguardInterfaceError> {
        let desired = desired_peers(peers, services, self_pubkey, prefer_ipv6, endpoint_tiers, transit);

        let to_remove = peers_to_remove(self.applied.keys(), &desired);
        for key in &to_remove {
            self.api.remove_peer(key)?;
        }
        let to_configure: Vec<Peer> = peers_to_configure(&self.applied, &desired)
            .into_iter()
            .cloned()
            .collect();
        for peer in &to_configure {
            self.api.configure_peer(peer)?;
        }

        // Install a route for every peer's address.
        //
        // WireGuard's `AllowedIPs` is a cryptographic routing table, not a
        // kernel one: it decides which peer a packet belongs to once the
        // packet has already been handed to the interface. It does not put
        // anything in the host's routing table, so without this step
        // nothing ever sends a packet to the interface in the first place.
        // The interface's own address is assigned as a `/32` (plus a
        // `/128`), which creates a local route for this node alone and no
        // route at all towards the other members of the mesh — so
        // `plex.wg` resolving to a peer's address would still fail to
        // connect, and on a host running an overlay that claims the
        // surrounding range (Tailscale and `100.64.0.0/10`, say) the packet
        // would be handed to *that* interface instead. `wg-quick` does this
        // same step from `AllowedIPs` and it has to happen here too.
        //
        // Our own routes, not defguard's `configure_peer_routing`, which
        // also routes every peer *endpoint* via the default gateway — and
        // blackholes it on a host without one. See `crate::routes`.
        //
        // Only run when the routed set actually changed, to keep it off the
        // steady-state path.
        let self_name = peers.iter().find(|p| p.pubkey == self_pubkey).map(|p| p.name.as_str());
        let routes = desired_routes(&desired, self_name.into_iter().flat_map(|n| owned_vips(services, n)));
        if routes != self.routed {
            // A route that couldn't be set is logged (by `sync`) and retried
            // on the next cycle, not fatal: failing here would leave
            // `applied` stale and reconfigure every peer next cycle, which
            // resets WireGuard's own endpoint roaming (see above).
            match crate::routes::sync(&self.ifname, &self.routed, &routes) {
                Ok(()) => self.routed = routes,
                Err(e) => tracing::warn!(ifname = %self.ifname, error = %e, "peer routes are incomplete"),
            }
        }

        self.applied = desired;
        Ok(())
    }

    /// Deletes the interface, and with it its addresses and routes. Not
    /// defguard's `remove_interface`; see `routes::delete_link` for why.
    pub fn teardown(&mut self) -> Result<(), WireguardInterfaceError> {
        crate::routes::delete_link(&self.ifname)?;
        self.applied.clear();
        self.routed.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::PeerInfo;

    fn key_b64(byte: u8) -> String {
        // Any 32 distinct bytes make a syntactically valid base64 WG key
        // for exercising the parsing/diffing logic — these are never used
        // against a real interface in these tests.
        defguard_wireguard_rs::key::Key::new([byte; 32]).to_string()
    }

    fn peer(name: &str, pubkey: &str) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: pubkey.into(),
            ip4: "100.90.0.5".into(),
            ip6: "fd00:90::5".into(),
            endpoint_addr: None,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            transit_via: None,
        }
    }

    #[test]
    fn clamp_private_key_matches_the_kernels_own_clamping() {
        // Regression test for a real bug: a freshly generated key (via
        // x25519_dalek's raw, unclamped StaticSecret::to_bytes()) came back
        // from the kernel with different bytes after configure_interface,
        // because the kernel clamps every private key it stores. Observed
        // on real hardware: state.json held
        // "AVAJTj9yprpuSrnk0YxwidG1TTnX4kniiJqLe/jsY2o=" (byte 0 = 0x01)
        // while `wg show wg0 private-key` reported
        // "AFAJTj9yprpuSrnk0YxwidG1TTnX4kniiJqLe/jsY2o=" (byte 0 = 0x00) —
        // the same key, differing only by clamping.
        let unclamped =
            Key::try_from("AVAJTj9yprpuSrnk0YxwidG1TTnX4kniiJqLe/jsY2o=").unwrap();
        let kernel_reported =
            Key::try_from("AFAJTj9yprpuSrnk0YxwidG1TTnX4kniiJqLe/jsY2o=").unwrap();
        assert_eq!(
            clamp_private_key(&unclamped).as_array(),
            kernel_reported.as_array()
        );
        // Clamping an already-clamped key must be a no-op (idempotent),
        // since `bring_up` clamps its candidate unconditionally regardless
        // of whether the persisted key predates this fix.
        assert_eq!(
            clamp_private_key(&kernel_reported).as_array(),
            kernel_reported.as_array()
        );
    }

    #[test]
    fn peer_allowed_ips_covers_v4_and_v6_as_host_masks() {
        let ips = peer_allowed_ips("100.90.0.3", "fd00:90::3");
        assert_eq!(ips.len(), 2);
        assert!(ips.iter().all(|m| m.cidr == 32 || m.cidr == 128));
    }

    #[test]
    fn peer_allowed_ips_skips_unparseable_addresses() {
        let ips = peer_allowed_ips("not-an-ip", "also-not-one");
        assert!(ips.is_empty());
    }

    #[test]
    fn desired_peers_excludes_self() {
        let self_key = key_b64(1);
        let other_key = key_b64(2);
        let peers = vec![peer("me", &self_key), peer("other", &other_key)];
        let desired = desired_peers(&peers, &[], &self_key, false, &HashMap::new(), &HashMap::new());
        assert_eq!(desired.len(), 1);
    }

    #[test]
    fn desired_peers_skips_unparseable_pubkey_without_dropping_others() {
        let self_key = key_b64(1);
        let good_key = key_b64(2);
        let peers = vec![
            peer("bad", "not-a-real-base64-key"),
            peer("good", &good_key),
        ];
        let desired = desired_peers(&peers, &[], &self_key, false, &HashMap::new(), &HashMap::new());
        assert_eq!(desired.len(), 1);
    }

    // ---- transit (PLAN.md M23) ----

    #[test]
    fn a_transited_peer_gets_no_kernel_entry_of_its_own() {
        let self_key = key_b64(1);
        let (b_key, c_key) = (key_b64(2), key_b64(3));
        let peers = vec![peer("b", &b_key), peer("c", &c_key)];
        let transit: TransitAssignments<'_> = HashMap::from([(c_key.as_str(), b_key.as_str())]);
        let desired = desired_peers(&peers, &[], &self_key, false, &HashMap::new(), &transit);
        assert_eq!(desired.len(), 1);
        assert!(desired.contains_key(&Key::try_from(b_key.as_str()).unwrap()));
    }

    #[test]
    fn a_transited_peers_address_and_vips_fold_into_its_via_peers_entry() {
        let self_key = key_b64(1);
        let (b_key, c_key) = (key_b64(2), key_b64(3));
        let mut b = peer("b", &b_key);
        b.ip4 = "100.90.0.2".into();
        b.ip6 = String::new();
        let mut c = peer("c", &c_key);
        c.ip4 = "100.90.0.3".into();
        c.ip6 = String::new();
        let services = [service("web", "c", Some("100.90.0.53"))];
        let transit: TransitAssignments<'_> = HashMap::from([(c_key.as_str(), b_key.as_str())]);
        let desired = desired_peers(&[b, c], &services, &self_key, false, &HashMap::new(), &transit);
        let via = desired.get(&Key::try_from(b_key.as_str()).unwrap()).unwrap();
        let ips: Vec<String> = via.allowed_ips.iter().map(ToString::to_string).collect();
        assert_eq!(ips, ["100.90.0.2/32", "100.90.0.3/32", "100.90.0.53/32"]);
    }

    #[test]
    fn a_direct_peer_that_is_also_a_via_peer_keeps_both_its_own_and_the_transited_address() {
        let self_key = key_b64(1);
        let (b_key, c_key) = (key_b64(2), key_b64(3));
        let mut b = peer("b", &b_key);
        b.ip4 = "100.90.0.2".into();
        b.ip6 = String::new();
        let mut c = peer("c", &c_key);
        c.ip4 = "100.90.0.3".into();
        c.ip6 = String::new();
        let transit: TransitAssignments<'_> = HashMap::from([(c_key.as_str(), b_key.as_str())]);
        let desired = desired_peers(&[b, c], &[], &self_key, false, &HashMap::new(), &transit);
        assert_eq!(desired.len(), 1);
        let via = desired.get(&Key::try_from(b_key.as_str()).unwrap()).unwrap();
        let ips: Vec<String> = via.allowed_ips.iter().map(ToString::to_string).collect();
        assert_eq!(ips, ["100.90.0.2/32", "100.90.0.3/32"]);
    }

    #[test]
    fn a_dangling_via_naming_an_unknown_peer_is_a_safe_no_op() {
        let self_key = key_b64(1);
        let c_key = key_b64(3);
        let unknown_via = key_b64(9);
        let peers = vec![peer("c", &c_key)];
        let transit: TransitAssignments<'_> = HashMap::from([(c_key.as_str(), unknown_via.as_str())]);
        let desired = desired_peers(&peers, &[], &self_key, false, &HashMap::new(), &transit);
        assert!(desired.is_empty());
    }

    #[test]
    fn a_transit_cycle_leaves_both_sides_unreachable_rather_than_misrouted() {
        let self_key = key_b64(1);
        let (b_key, c_key) = (key_b64(2), key_b64(3));
        let peers = vec![peer("b", &b_key), peer("c", &c_key)];
        // A stale/adversarial coordinator naming each as the other's via.
        let transit: TransitAssignments<'_> = HashMap::from([(b_key.as_str(), c_key.as_str()), (c_key.as_str(), b_key.as_str())]);
        let desired = desired_peers(&peers, &[], &self_key, false, &HashMap::new(), &transit);
        assert!(desired.is_empty());
    }

    #[test]
    fn desired_routes_still_covers_a_transited_peers_address() {
        let self_key = key_b64(1);
        let (b_key, c_key) = (key_b64(2), key_b64(3));
        let mut b = peer("b", &b_key);
        b.ip4 = "100.90.0.2".into();
        b.ip6 = String::new();
        let mut c = peer("c", &c_key);
        c.ip4 = "100.90.0.3".into();
        c.ip6 = String::new();
        let transit: TransitAssignments<'_> = HashMap::from([(c_key.as_str(), b_key.as_str())]);
        let desired = desired_peers(&[b, c], &[], &self_key, false, &HashMap::new(), &transit);
        let routes: Vec<String> =
            desired_routes(&desired, std::iter::empty()).iter().map(ToString::to_string).collect();
        assert_eq!(routes, ["100.90.0.2", "100.90.0.3"]);
    }

    #[test]
    fn transit_reachable_peers_keeps_only_fresh_handshakes_sorted_and_deduped_order() {
        let now = chrono::Utc::now();
        let handshakes = HashMap::from([
            ("fresh".to_string(), Some(now - chrono::Duration::seconds(10))),
            ("stale".to_string(), Some(now - chrono::Duration::seconds(200))),
            ("never".to_string(), None),
        ]);
        assert_eq!(transit_reachable_peers(&handshakes, now), vec!["fresh"]);
    }

    #[test]
    fn transit_reachable_peers_boundary_is_inclusive() {
        let now = chrono::Utc::now();
        let handshakes = HashMap::from([(
            "edge".to_string(),
            Some(now - chrono::Duration::from_std(TRANSIT_REACHABLE_HANDSHAKE_MAX).unwrap()),
        )]);
        assert_eq!(transit_reachable_peers(&handshakes, now), vec!["edge"]);
    }

    #[test]
    fn peers_on_wan_excludes_a_peer_with_no_tracked_history() {
        let tracker = EndpointTracker::default();
        assert!(tracker.peers_on_wan().is_empty());
    }

    #[test]
    fn peers_on_wan_includes_a_peer_tracked_and_resolved_to_wan() {
        // Same shape as `no_handshake_within_the_grace_window_falls_back_
        // to_wan_and_schedules_a_retry`: a peer that DID have a ranked
        // candidate (real tracked history), whose grace window then
        // expired without a handshake, landing it on `Wan` — as opposed
        // to a peer with no ranked candidate at all, the ordinary
        // untracked plain-WAN case, which must never show up here.
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        let pubkey = key_b64(2).to_string();
        tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now);
        let tier = tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now + GRACE);
        assert_eq!(tier, EndpointTier::Wan);
        assert_eq!(tracker.peers_on_wan(), vec![pubkey.as_str()]);
    }

    #[test]
    fn peers_wanting_transit_excludes_a_wan_peer_with_a_fresh_handshake() {
        // The false-positive this whole method exists to fix: a peer
        // whose LAN/Reflexive probe failed (landing it on `Wan`, per
        // `peers_on_wan_includes_a_peer_tracked_and_resolved_to_wan`
        // above) but whose plain WAN dial is, in fact, live right now —
        // it must never request transit help for free.
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        let pubkey = key_b64(2).to_string();
        tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now);
        let tier = tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now + GRACE);
        assert_eq!(tier, EndpointTier::Wan);

        let now_utc = chrono::Utc::now();
        let handshakes = HashMap::from([(pubkey.clone(), Some(now_utc))]);
        assert!(tracker.peers_wanting_transit(&handshakes, now_utc).is_empty());
    }

    #[test]
    fn peers_wanting_transit_includes_a_wan_peer_with_a_stale_or_missing_handshake() {
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        let pubkey = key_b64(2).to_string();
        tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now);
        let tier = tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now + GRACE);
        assert_eq!(tier, EndpointTier::Wan);

        let now_utc = chrono::Utc::now();
        // No entry at all for this pubkey in `handshakes` — never handshaked.
        assert_eq!(tracker.peers_wanting_transit(&HashMap::new(), now_utc), vec![pubkey.as_str()]);

        // A handshake that exists but is older than
        // `TRANSIT_REACHABLE_HANDSHAKE_MAX` counts the same as none.
        let stale = HashMap::from([(
            pubkey.clone(),
            Some(now_utc - chrono::Duration::from_std(TRANSIT_REACHABLE_HANDSHAKE_MAX).unwrap() - chrono::Duration::seconds(1)),
        )]);
        assert_eq!(tracker.peers_wanting_transit(&stale, now_utc), vec![pubkey.as_str()]);
    }

    #[test]
    fn transit_forwards_builds_near_and_far_from_the_named_peers_own_entries() {
        let (a_key, c_key) = (key_b64(2), key_b64(3));
        let mut a = peer("a", &a_key);
        a.ip4 = "100.90.0.2".into();
        a.ip6 = String::new();
        let mut c = peer("c", &c_key);
        c.ip4 = "100.90.0.3".into();
        c.ip6 = String::new();
        let services = [service("web", "c", Some("100.90.0.53"))];
        let carrying = vec![TransitPair { a: a_key.clone(), c: c_key.clone() }];
        let forwards = transit_forwards(&[a, c], &services, &carrying);
        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].near.ip4, Some("100.90.0.2".parse().unwrap()));
        assert_eq!(forwards[0].far.ip4, Some("100.90.0.3".parse().unwrap()));
        assert_eq!(forwards[0].far.vips, vec!["100.90.0.53".parse::<Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn transit_forwards_drops_a_pair_naming_an_unknown_peer() {
        let a_key = key_b64(2);
        let a = peer("a", &a_key);
        let carrying = vec![TransitPair { a: a_key, c: key_b64(9) }];
        assert!(transit_forwards(&[a], &[], &carrying).is_empty());
    }

    fn service(name: &str, node: &str, vip4: Option<&str>) -> ServiceInfo {
        ServiceInfo {
            name: name.into(),
            node: node.into(),
            ip4: String::new(),
            port: 80,
            proto: wireserve_types::Proto::Tcp,
            online: true,
            vip4: vip4.map(Into::into),
            ports: vec![],
        }
    }

    #[test]
    fn a_peers_allowed_ips_include_the_addresses_of_its_services() {
        let self_key = key_b64(1);
        let mut other = peer("other", &key_b64(2));
        other.ip4 = "100.90.0.2".into();
        other.ip6 = "fd00:90::2".into();
        let services = [
            service("web", "other", Some("100.90.0.50")),
            service("dns", "other", Some("100.90.0.51")),
            service("old", "other", None),
            service("mine", "me", Some("100.90.0.52")),
        ];
        let desired = desired_peers(&[peer("me", &self_key), other], &services, &self_key, false, &HashMap::new(), &HashMap::new());
        let peer = desired.values().next().unwrap();
        let ips: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();
        assert_eq!(ips, ["100.90.0.2/32", "fd00:90::2/128", "100.90.0.50/32", "100.90.0.51/32"]);
    }

    #[test]
    fn routes_cover_every_allowed_ip_and_this_nodes_own_service_addresses() {
        let self_key = key_b64(1);
        let mut other = peer("other", &key_b64(2));
        other.ip4 = "100.90.0.2".into();
        other.ip6 = String::new();
        let services = [service("web", "other", Some("100.90.0.50"))];
        let desired = desired_peers(&[other], &services, &self_key, false, &HashMap::new(), &HashMap::new());
        let own: Vec<Ipv4Addr> = vec!["100.90.0.60".parse().unwrap()];
        let routes: Vec<String> = desired_routes(&desired, own.into_iter()).iter().map(ToString::to_string).collect();
        assert_eq!(routes, ["100.90.0.2", "100.90.0.50", "100.90.0.60"]);
    }

    #[test]
    fn choose_peer_endpoint_prefers_v4_by_default() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, false, None),
            Some("203.0.113.5:51820".into())
        );
    }

    #[test]
    fn choose_peer_endpoint_prefers_v6_only_when_asked_and_both_exist() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, true, None),
            Some("[2001:db8::1]:51820".into())
        );
    }

    #[test]
    fn choose_peer_endpoint_falls_back_to_whichever_single_candidate_exists() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, false, None),
            Some("[2001:db8::1]:51820".into()),
            "no v4 candidate at all — v6 is used even though prefer_ipv6 is false"
        );
        assert_eq!(choose_peer_endpoint(&p, true, None), Some("[2001:db8::1]:51820".into()));
    }

    #[test]
    fn choose_peer_endpoint_explicit_override_always_wins() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr = Some("explicit.example.com:51820".into());
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, false, None),
            Some("explicit.example.com:51820".into())
        );
        assert_eq!(
            choose_peer_endpoint(&p, true, None),
            Some("explicit.example.com:51820".into()),
            "explicit wins regardless of prefer_ipv6"
        );
    }

    #[test]
    fn choose_peer_endpoint_falls_through_an_ipv6_only_explicit_field_when_this_node_has_no_v6() {
        // The coordinator's `endpoint_addr` column is filled from
        // whatever family a dual-stack peer's poll happened to arrive
        // over — not a considered choice — so it can be IPv6 even though
        // the peer also actively reported a perfectly good v4 candidate.
        // An IPv6-less receiver must not be handed that anyway.
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr = Some("[2001:db8::1]:51820".into());
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, false, None),
            Some("203.0.113.5:51820".into()),
            "an IPv6-only explicit value is useless to a node with no working v6"
        );
        assert_eq!(
            choose_peer_endpoint(&p, true, None),
            Some("[2001:db8::1]:51820".into()),
            "a node with real v6 can still use it"
        );
    }

    // ---- NAT-hairpin fix: choose_peer_endpoint's LAN preference ----

    #[test]
    fn choose_peer_endpoint_prefers_the_resolved_lan_candidate() {
        // Even over an explicit operator override — see the doc comment
        // on `choose_peer_endpoint` for why: a home-router-plus-dynamic-
        // DNS deployment (the exact case this feature targets) almost
        // always has an explicit endpoint_addr set, and the LAN path is
        // strictly better whenever the tracker has actually offered it.
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr = Some("duckdns.example.com:51820".into());
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.lan_addr = Some("192.168.1.50".into());
        assert_eq!(
            choose_peer_endpoint(&p, false, Some(EndpointTier::Lan)),
            Some("192.168.1.50:51820".into()),
            "borrows its port from the v4 WAN candidate"
        );
        assert_eq!(
            choose_peer_endpoint(&p, false, Some(EndpointTier::Wan)),
            Some("duckdns.example.com:51820".into()),
            "Wan resolves exactly as if tier were None"
        );
        assert_eq!(
            choose_peer_endpoint(&p, false, None),
            Some("duckdns.example.com:51820".into())
        );
    }

    #[test]
    fn choose_peer_endpoint_falls_back_when_lan_chosen_but_no_wan_port_is_known() {
        // No endpoint_addr/_v4/_v6 at all to borrow a port from — the LAN
        // candidate can't be used, so this falls through to ordinary WAN
        // logic (here, nothing at all).
        let mut p = peer("n1", &key_b64(2));
        p.lan_addr = Some("192.168.1.50".into());
        assert_eq!(choose_peer_endpoint(&p, false, Some(EndpointTier::Lan)), None);
    }

    #[test]
    fn choose_peer_endpoint_falls_back_when_lan_is_some_but_lan_addr_is_unparseable() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.lan_addr = Some("not-an-ip".into());
        assert_eq!(
            choose_peer_endpoint(&p, false, Some(EndpointTier::Lan)),
            Some("203.0.113.5:51820".into())
        );
    }

    #[test]
    fn choose_peer_endpoint_prefers_the_resolved_reflexive_candidate() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr = Some("duckdns.example.com:51820".into());
        p.reflexive_addr = Some("203.0.113.5:55123".into());
        assert_eq!(
            choose_peer_endpoint(&p, false, Some(EndpointTier::Reflexive)),
            Some("203.0.113.5:55123".into()),
            "carries its own port, unlike Lan"
        );
        assert_eq!(
            choose_peer_endpoint(&p, false, Some(EndpointTier::Wan)),
            Some("duckdns.example.com:51820".into())
        );
    }

    #[test]
    fn choose_peer_endpoint_falls_back_when_reflexive_chosen_but_malformed() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.reflexive_addr = Some("not-an-ip:port".into());
        assert_eq!(
            choose_peer_endpoint(&p, false, Some(EndpointTier::Reflexive)),
            Some("203.0.113.5:51820".into())
        );
    }

    #[test]
    fn desired_peers_wires_prefer_ipv6_through_to_the_configured_endpoint() {
        let self_key = key_b64(1);
        let mut other = peer("other", &key_b64(2));
        other.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        other.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());

        let desired_v4 = desired_peers(&[other.clone()], &[], &self_key, false, &HashMap::new(), &HashMap::new());
        let key = defguard_wireguard_rs::key::Key::try_from(key_b64(2).as_str()).unwrap();
        assert_eq!(
            desired_v4[&key].endpoint,
            Some("203.0.113.5:51820".parse().unwrap())
        );

        let desired_v6 = desired_peers(&[other], &[], &self_key, true, &HashMap::new(), &HashMap::new());
        assert_eq!(
            desired_v6[&key].endpoint,
            Some("[2001:db8::1]:51820".parse::<std::net::SocketAddr>().unwrap())
        );
    }

    #[test]
    fn peers_to_remove_is_the_set_difference() {
        let a = defguard_wireguard_rs::key::Key::new([1; 32]);
        let b = defguard_wireguard_rs::key::Key::new([2; 32]);
        let applied = [a.clone(), b.clone()];
        let mut desired = HashMap::new();
        desired.insert(a.clone(), Peer::new(a.clone()));

        let to_remove = peers_to_remove(applied.iter(), &desired);
        assert_eq!(to_remove, vec![b]);
    }

    // ---- F6: peers_to_configure must skip unchanged peers ----

    #[test]
    fn peers_to_configure_includes_brand_new_peers() {
        let a = defguard_wireguard_rs::key::Key::new([1; 32]);
        let applied = HashMap::new();
        let mut desired = HashMap::new();
        desired.insert(a.clone(), Peer::new(a.clone()));

        let to_configure = peers_to_configure(&applied, &desired);
        assert_eq!(to_configure.len(), 1);
    }

    #[test]
    fn peers_to_configure_skips_a_peer_that_is_byte_for_byte_unchanged() {
        let a = defguard_wireguard_rs::key::Key::new([1; 32]);
        let mut peer = Peer::new(a.clone());
        peer.persistent_keepalive_interval = Some(25);
        peer.set_endpoint("10.0.0.1:51820").unwrap();

        let mut applied = HashMap::new();
        applied.insert(a.clone(), peer.clone());
        let mut desired = HashMap::new();
        desired.insert(a.clone(), peer);

        // This is the exact regression: re-sending an identical peer
        // config every poll cycle resets WireGuard's own kernel-level
        // roaming correction (spec §4.2) every cycle.
        assert!(
            peers_to_configure(&applied, &desired).is_empty(),
            "an unchanged peer must not be re-sent to configure_peer"
        );
    }

    #[test]
    fn peers_to_configure_includes_a_peer_whose_endpoint_changed() {
        let a = defguard_wireguard_rs::key::Key::new([1; 32]);
        let mut old_peer = Peer::new(a.clone());
        old_peer.set_endpoint("10.0.0.1:51820").unwrap();
        let mut new_peer = Peer::new(a.clone());
        new_peer.set_endpoint("10.0.0.2:51820").unwrap();

        let mut applied = HashMap::new();
        applied.insert(a.clone(), old_peer);
        let mut desired = HashMap::new();
        desired.insert(a.clone(), new_peer);

        assert_eq!(peers_to_configure(&applied, &desired).len(), 1);
    }

    #[test]
    fn peers_to_configure_only_returns_the_changed_peer_not_every_peer() {
        let a = defguard_wireguard_rs::key::Key::new([1; 32]);
        let b = defguard_wireguard_rs::key::Key::new([2; 32]);
        let unchanged = Peer::new(a.clone());
        let mut old_b = Peer::new(b.clone());
        old_b.set_endpoint("10.0.0.1:51820").unwrap();
        let mut new_b = Peer::new(b.clone());
        new_b.set_endpoint("10.0.0.2:51820").unwrap();

        let mut applied = HashMap::new();
        applied.insert(a.clone(), unchanged.clone());
        applied.insert(b.clone(), old_b);
        let mut desired = HashMap::new();
        desired.insert(a.clone(), unchanged);
        desired.insert(b.clone(), new_b);

        let to_configure = peers_to_configure(&applied, &desired);
        assert_eq!(to_configure.len(), 1);
        assert_eq!(to_configure[0].public_key, b);
    }

    // ---- NAT-hairpin fix: subnet math and containment ----

    fn lan(addr: &str, prefix_len: u8) -> LocalLan {
        LocalLan { addr: addr.parse().unwrap(), prefix_len }
    }

    #[test]
    fn own_lan_subnets_masks_addresses_to_their_network() {
        let subnets = own_lan_subnets(&[lan("192.168.1.50", 24), lan("10.0.5.9", 8)]);
        assert_eq!(
            subnets,
            vec![("192.168.1.0".parse().unwrap(), 24), ("10.0.0.0".parse().unwrap(), 8)]
        );
    }

    #[test]
    fn own_lan_subnets_handles_a_host_route_and_the_whole_internet() {
        assert_eq!(own_lan_subnets(&[lan("192.168.1.50", 32)])[0].0, "192.168.1.50".parse::<Ipv4Addr>().unwrap());
        assert_eq!(own_lan_subnets(&[lan("192.168.1.50", 0)])[0].0, "0.0.0.0".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn is_on_own_lan_true_for_an_address_in_range() {
        let subnets = own_lan_subnets(&[lan("192.168.1.50", 24)]);
        assert!(is_on_own_lan(&subnets, "192.168.1.99".parse().unwrap()));
    }

    #[test]
    fn is_on_own_lan_false_outside_every_own_subnet() {
        let subnets = own_lan_subnets(&[lan("192.168.1.50", 24)]);
        assert!(!is_on_own_lan(&subnets, "192.168.2.1".parse().unwrap()));
        assert!(!is_on_own_lan(&subnets, "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_on_own_lan_matches_purely_on_the_subnet_a_deliberate_false_positive() {
        // The whole reason `resolve_lan_candidate` treats a match as an
        // optimistic attempt rather than a fact: two completely unrelated
        // sites both using the most common home-router default collide
        // here by construction.
        let subnets = own_lan_subnets(&[lan("192.168.1.2", 24)]);
        assert!(is_on_own_lan(&subnets, "192.168.1.200".parse().unwrap()));
    }

    // ---- NAT-hairpin fix: peer_tier_candidates ----

    fn info_with(lan_addr: Option<&str>, reflexive_addr: Option<&str>) -> PeerInfo {
        let mut p = peer("n1", &key_b64(2));
        p.lan_addr = lan_addr.map(String::from);
        p.reflexive_addr = reflexive_addr.map(String::from);
        p
    }

    #[test]
    fn peer_tier_candidates_keeps_a_lan_addr_inside_an_own_subnet() {
        let subnets = own_lan_subnets(&[lan("192.168.1.2", 24)]);
        let p = info_with(Some("192.168.1.50"), None);
        assert_eq!(peer_tier_candidates(&subnets, &p).lan, Some("192.168.1.50"));
    }

    #[test]
    fn peer_tier_candidates_drops_a_lan_addr_outside_every_own_subnet() {
        let subnets = own_lan_subnets(&[lan("192.168.1.2", 24)]);
        let p = info_with(Some("10.0.0.5"), None);
        assert_eq!(peer_tier_candidates(&subnets, &p).lan, None);
    }

    #[test]
    fn peer_tier_candidates_keeps_a_well_formed_reflexive_addr() {
        let p = info_with(None, Some("203.0.113.5:55123"));
        assert_eq!(peer_tier_candidates(&[], &p).reflexive, Some("203.0.113.5:55123"));
    }

    #[test]
    fn peer_tier_candidates_drops_a_malformed_reflexive_addr() {
        let p = info_with(None, Some("not-an-ip:port"));
        assert_eq!(peer_tier_candidates(&[], &p).reflexive, None);
    }

    // ---- NAT-hairpin fix: resolve_endpoint_candidate's staleness state machine ----

    const GRACE: std::time::Duration = ENDPOINT_GRACE_WINDOW;

    fn lan_only(addr: &str) -> PeerTierCandidates<'_> {
        PeerTierCandidates { lan: Some(addr), reflexive: None }
    }

    fn reflexive_only(addr: &str) -> PeerTierCandidates<'_> {
        PeerTierCandidates { lan: None, reflexive: Some(addr) }
    }

    #[test]
    fn no_candidate_on_any_tier_is_plain_wan_untracked() {
        let now = std::time::Instant::now();
        let (tier, state) = resolve_endpoint_candidate(PeerTierCandidates::default(), None, None, now);
        assert_eq!(tier, EndpointTier::Wan);
        assert!(state.is_none());
    }

    #[test]
    fn first_cycle_on_a_matching_lan_optimistically_tries_lan() {
        let now = std::time::Instant::now();
        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, now);
        assert_eq!(tier, EndpointTier::Lan);
        assert!(state.is_some());
    }

    #[test]
    fn a_handshake_after_switching_confirms_the_tier_and_resets_its_backoff() {
        let now = std::time::Instant::now();
        let t0 = chrono::Utc::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(t0), None, now);
        // A genuinely newer handshake than the baseline taken at switch time.
        let newer = t0 + chrono::Duration::seconds(5);
        let (tier, state) = resolve_endpoint_candidate(
            lan_only("192.168.1.50"),
            Some(newer),
            state,
            now + std::time::Duration::from_secs(1),
        );
        assert_eq!(tier, EndpointTier::Lan);
        assert_eq!(state.unwrap().per_tier[&EndpointTier::Lan].backoff, ENDPOINT_RETRY_BACKOFF_INITIAL);
    }

    #[test]
    fn still_within_the_grace_window_stays_put_awaiting_a_handshake() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, now);
        let (tier, _) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, now + GRACE / 2);
        assert_eq!(tier, EndpointTier::Lan);
    }

    #[test]
    fn no_handshake_within_the_grace_window_falls_back_to_wan_and_schedules_a_retry() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, now);
        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, now + GRACE);
        assert_eq!(tier, EndpointTier::Wan);
        let state = state.unwrap();
        let lan = &state.per_tier[&EndpointTier::Lan];
        assert!(lan.next_retry_at.is_some());
        assert_eq!(lan.backoff, ENDPOINT_RETRY_BACKOFF_INITIAL * 2);
    }

    #[test]
    fn wan_retries_the_tier_once_the_backoff_elapses_not_before() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, now);
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, now + GRACE);
        // Not due yet.
        let (tier, state) = resolve_endpoint_candidate(
            lan_only("192.168.1.50"),
            None,
            state,
            now + GRACE + std::time::Duration::from_secs(1),
        );
        assert_eq!(tier, EndpointTier::Wan);
        // Due.
        let (tier, _) = resolve_endpoint_candidate(
            lan_only("192.168.1.50"),
            None,
            state,
            now + GRACE + ENDPOINT_RETRY_BACKOFF_INITIAL,
        );
        assert_eq!(tier, EndpointTier::Lan);
    }

    #[test]
    fn backoff_doubles_up_to_the_cap_on_repeated_failures() {
        let now = std::time::Instant::now();
        let (_, mut state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, now);
        let mut t = now;
        let mut last_backoff = ENDPOINT_RETRY_BACKOFF_INITIAL;
        for _ in 0..10 {
            // Fail the grace window.
            t += GRACE;
            let (_, s) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, t);
            let s = s.unwrap();
            let lan = s.per_tier[&EndpointTier::Lan].clone();
            assert!(lan.backoff <= ENDPOINT_RETRY_BACKOFF_MAX);
            last_backoff = lan.backoff;
            // Retry once due, so the next iteration fails from Lan again.
            t = lan.next_retry_at.unwrap();
            let (_, s) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, Some(s), t);
            state = s;
        }
        assert_eq!(last_backoff, ENDPOINT_RETRY_BACKOFF_MAX, "must have capped by now");
    }

    #[test]
    fn a_peer_roaming_to_a_different_lan_address_resets_to_a_fresh_optimistic_attempt() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, now);
        // Fall back to Wan first, so the roam is a real behavior change,
        // not just staying on Lan by coincidence.
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, now + GRACE);
        assert_eq!(state.as_ref().unwrap().current, EndpointTier::Wan);

        let (tier, state) = resolve_endpoint_candidate(
            lan_only("192.168.2.50"),
            None,
            state,
            now + GRACE + std::time::Duration::from_secs(1),
        );
        assert_eq!(tier, EndpointTier::Lan, "a new address gets a fresh optimistic attempt");
        assert_eq!(state.unwrap().per_tier[&EndpointTier::Lan].backoff, ENDPOINT_RETRY_BACKOFF_INITIAL);
    }

    #[test]
    fn a_peer_roaming_to_a_different_reflexive_address_resets_to_a_fresh_optimistic_attempt() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:55123"), None, None, now);
        let (_, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:55123"), None, state, now + GRACE);
        assert_eq!(state.as_ref().unwrap().current, EndpointTier::Wan);

        let (tier, state) = resolve_endpoint_candidate(
            reflexive_only("203.0.113.5:60000"),
            None,
            state,
            now + GRACE + std::time::Duration::from_secs(1),
        );
        assert_eq!(tier, EndpointTier::Reflexive);
        assert_eq!(state.unwrap().per_tier[&EndpointTier::Reflexive].backoff, ENDPOINT_RETRY_BACKOFF_INITIAL);
    }

    // ---- the genuinely new behavior: tier advancement ----

    fn lan_and_reflexive<'a>(lan: &'a str, reflexive: &'a str) -> PeerTierCandidates<'a> {
        PeerTierCandidates { lan: Some(lan), reflexive: Some(reflexive) }
    }

    #[test]
    fn lan_failing_its_grace_window_advances_to_reflexive_in_the_same_cycle() {
        let now = std::time::Instant::now();
        let candidates = lan_and_reflexive("192.168.1.50", "203.0.113.5:55123");
        let (tier, state) = resolve_endpoint_candidate(candidates, None, None, now);
        assert_eq!(tier, EndpointTier::Lan);

        // Lan never confirms within its own grace window.
        let (tier, state) = resolve_endpoint_candidate(candidates, None, state, now + GRACE);
        assert_eq!(
            tier,
            EndpointTier::Reflexive,
            "must advance to the next-best tier this same cycle, not fall straight to Wan"
        );
        let state = state.unwrap();
        assert!(
            state.per_tier[&EndpointTier::Lan].next_retry_at.is_some(),
            "Lan's own backoff is scheduled independently of Reflexive's"
        );
        assert!(state.per_tier.get(&EndpointTier::Reflexive).is_none_or(|b| b.next_retry_at.is_none()));
    }

    #[test]
    fn reflexive_also_failing_falls_back_to_wan_with_independent_backoff_timers() {
        let now = std::time::Instant::now();
        let candidates = lan_and_reflexive("192.168.1.50", "203.0.113.5:55123");
        let (_, state) = resolve_endpoint_candidate(candidates, None, None, now);
        // Lan fails -> advances to Reflexive this same cycle.
        let (tier, state) = resolve_endpoint_candidate(candidates, None, state, now + GRACE);
        assert_eq!(tier, EndpointTier::Reflexive);
        // Reflexive, now active, also fails its own grace window.
        let (tier, state) = resolve_endpoint_candidate(candidates, None, state, now + GRACE + GRACE);
        assert_eq!(tier, EndpointTier::Wan);
        let state = state.unwrap();
        assert_eq!(
            state.per_tier[&EndpointTier::Lan].backoff,
            ENDPOINT_RETRY_BACKOFF_INITIAL * 2,
            "Lan failed once"
        );
        assert_eq!(
            state.per_tier[&EndpointTier::Reflexive].backoff,
            ENDPOINT_RETRY_BACKOFF_INITIAL * 2,
            "Reflexive failed once, independently of Lan's own timer"
        );
    }

    #[test]
    fn endpoint_tracker_resolves_per_pubkey_independently() {
        let mut tracker = EndpointTracker::default();
        let now = std::time::Instant::now();
        assert_eq!(tracker.resolve("pk-a", lan_only("192.168.1.50"), None, now), EndpointTier::Lan);
        assert_eq!(tracker.resolve("pk-b", PeerTierCandidates::default(), None, now), EndpointTier::Wan);
        // pk-a's own state persists across calls, independent of pk-b's.
        assert_eq!(
            tracker.resolve("pk-a", lan_only("192.168.1.50"), None, now + GRACE),
            EndpointTier::Wan
        );
    }

    #[test]
    fn endpoint_tracker_prune_drops_departed_peers() {
        let mut tracker = EndpointTracker::default();
        let now = std::time::Instant::now();
        tracker.resolve("pk-a", lan_only("192.168.1.50"), None, now);
        assert!(tracker.states.contains_key("pk-a"));
        tracker.prune(std::iter::empty());
        assert!(!tracker.states.contains_key("pk-a"));
    }

    // ---- validate_ifname ----

    #[test]
    fn validate_ifname_accepts_plain_names() {
        for name in ["wg0", "wireserve0", "wg-mesh.1", "a", "x_y", "abcdefghijklmno"] {
            assert_eq!(validate_ifname(name), Ok(()), "{name}");
        }
    }

    #[test]
    fn validate_ifname_rejects_anything_a_firewall_could_read_as_a_pattern_or_path() {
        for name in [
            "",
            "abcdefghijklmnop", // 16 bytes: over IFNAMSIZ-1
            "wg+",              // iptables wildcard
            "wg*",              // nft wildcard
            "a b",
            "a/b",
            "a\tb",
            ".",
            "..",
            "wg\"0",
            "wg0\u{e9}",
        ] {
            assert!(validate_ifname(name).is_err(), "{name:?} should be rejected");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_finds_an_address_on_other_interfaces_only() {
        if !crate::firewall::netns::reexec("wg::tests::kernel_finds_an_address_on_other_interfaces_only") {
            return;
        }
        let out = std::process::Command::new("sh")
            .args(["-euc", "ip link add other type dummy && ip addr add 10.77.0.1/32 dev other && ip addr add fd77::1/128 dev other nodad && ip link set other up"])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let v4: IpAddr = "10.77.0.1".parse().unwrap();
        let v6: IpAddr = "fd77::1".parse().unwrap();
        assert_eq!(interfaces_with_address(v4, "wireserve0").unwrap(), ["other"]);
        assert_eq!(interfaces_with_address(v6, "wireserve0").unwrap(), ["other"]);
        assert!(interfaces_with_address(v4, "other").unwrap().is_empty());
        assert!(interfaces_with_address("10.77.0.2".parse().unwrap(), "x").unwrap().is_empty());
    }

    /// Regression test for the endpoint blackhole: on a host with no
    /// default route, defguard's `configure_peer_routing` added a
    /// blackhole route to every peer's endpoint. Our routing adds a route
    /// for each peer's mesh addresses on the interface and nothing else,
    /// and removes it again when the peer goes.
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_reconcile_routes_peers_and_never_their_endpoints() {
        if !crate::firewall::netns::reexec("wg::tests::kernel_reconcile_routes_peers_and_never_their_endpoints") {
            return;
        }
        let sh = |script: &str| {
            let out = std::process::Command::new("sh").args(["-euc", script]).output().unwrap();
            assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8(out.stdout).unwrap()
        };
        // A LAN and no default route — the case that broke.
        sh("ip link set lo up && ip link add lan type dummy && ip addr add 10.99.0.2/24 dev lan && ip link set lan up");

        let own = clamp_private_key(&Key::generate());
        let mut wg = WgInterface::new("wgtest").unwrap();
        wg.bring_up(&own.to_string(), "100.90.0.2".parse().unwrap(), "fd00:90::2".parse().unwrap(), 51820)
            .unwrap();

        let mut p = peer("peer", &key_b64(9));
        p.endpoint_addr = Some("10.99.0.1:51820".into());
        wg.reconcile(std::slice::from_ref(&p), &[], &own.public_key().to_string(), false, &HashMap::new(), &HashMap::new()).unwrap();

        // What `list` reads: the configured endpoint, and no handshake
        // yet — not a handshake in 1970, which is how the kernel says it.
        let tunnel = tunnel_peers("wgtest").unwrap();
        assert_eq!(
            tunnel,
            [crate::ipc::protocol::TunnelPeer {
                pubkey: p.pubkey.clone(),
                endpoint: Some("10.99.0.1:51820".into()),
                last_handshake: None,
            }]
        );

        let routes = sh("ip -4 route show table all; ip -6 route show table all");
        assert!(!routes.contains("blackhole"), "{routes}");
        assert!(!routes.contains("10.99.0.1"), "no route to the endpoint at all: {routes}");
        assert!(routes.contains("100.90.0.5 dev wgtest"), "{routes}");
        assert!(routes.contains("fd00:90::5 dev wgtest"), "{routes}");

        wg.reconcile(&[], &[], &own.public_key().to_string(), false, &HashMap::new(), &HashMap::new()).unwrap();
        let routes = sh("ip -4 route show table all; ip -6 route show table all");
        assert!(!routes.contains("100.90.0.5") && !routes.contains("fd00:90::5"), "departed peer's route removed: {routes}");
        wg.teardown().unwrap();
    }

    /// Service addresses: a peer's is routed to the interface and handed
    /// to that peer, this node's own is routed to the interface for local
    /// clients, and both go again when the service does — even while the
    /// peer set itself stays exactly the same.
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_reconcile_routes_service_addresses() {
        if !crate::firewall::netns::reexec("wg::tests::kernel_reconcile_routes_service_addresses") {
            return;
        }
        let sh = |script: &str| {
            let out = std::process::Command::new("sh").args(["-euc", script]).output().unwrap();
            assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8(out.stdout).unwrap()
        };
        sh("ip link set lo up");
        let own = clamp_private_key(&Key::generate());
        let own_pub = own.public_key().to_string();
        let mut wg = WgInterface::new("wgtest").unwrap();
        wg.bring_up(&own.to_string(), "100.90.0.2".parse().unwrap(), "fd00:90::2".parse().unwrap(), 51820)
            .unwrap();

        let mut me = peer("me", &own_pub);
        me.ip4 = "100.90.0.2".into();
        let other = peer("peer", &key_b64(9));
        let peers = [me, other];
        let services = [
            service("web", "peer", Some("100.90.0.50")),
            service("mine", "me", Some("100.90.0.51")),
        ];
        wg.reconcile(&peers, &services, &own_pub, false, &HashMap::new(), &HashMap::new()).unwrap();

        let routes = sh("ip -4 route show table all");
        assert!(routes.contains("100.90.0.50 dev wgtest"), "{routes}");
        assert!(routes.contains("100.90.0.51 dev wgtest"), "{routes}");
        let allowed = sh("wg show wgtest allowed-ips 2>/dev/null || true");
        if !allowed.is_empty() {
            assert!(allowed.contains("100.90.0.50/32"), "{allowed}");
            assert!(!allowed.contains("100.90.0.51"), "our own address is no peer's: {allowed}");
        }

        wg.reconcile(&peers, &[], &own_pub, false, &HashMap::new(), &HashMap::new()).unwrap();
        let routes = sh("ip -4 route show table all");
        assert!(!routes.contains("100.90.0.50") && !routes.contains("100.90.0.51"), "{routes}");

        // Teardown deletes the interface itself, and is a no-op once gone.
        wg.teardown().unwrap();
        assert!(!sh("ip -o link show").contains("wgtest"), "interface still there after teardown");
        wg.teardown().unwrap();
    }

    /// NAT-hairpin fix (PLAN.md decisions log #85), end to end: when the
    /// tracker resolves a peer to `Lan`, `reconcile` actually configures
    /// the kernel peer's endpoint as the LAN address, not `endpoint_addr`.
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_reconcile_configures_the_lan_endpoint_when_resolved() {
        if !crate::firewall::netns::reexec("wg::tests::kernel_reconcile_configures_the_lan_endpoint_when_resolved") {
            return;
        }
        let sh = |script: &str| {
            let out = std::process::Command::new("sh").args(["-euc", script]).output().unwrap();
            assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
        };
        sh("ip link set lo up");

        let own = clamp_private_key(&Key::generate());
        let mut wg = WgInterface::new("wgtest").unwrap();
        wg.bring_up(&own.to_string(), "100.90.0.2".parse().unwrap(), "fd00:90::2".parse().unwrap(), 51820)
            .unwrap();

        let mut p = peer("peer", &key_b64(9));
        p.endpoint_addr = Some("203.0.113.5:51820".into());
        p.lan_addr = Some("192.168.1.50".into());

        let mut endpoint_tiers = HashMap::new();
        endpoint_tiers.insert(p.pubkey.clone(), EndpointTier::Lan);
        wg.reconcile(std::slice::from_ref(&p), &[], &own.public_key().to_string(), false, &endpoint_tiers, &HashMap::new()).unwrap();

        let tunnel = tunnel_peers("wgtest").unwrap();
        assert_eq!(
            tunnel[0].endpoint.as_deref(),
            Some("192.168.1.50:51820"),
            "must configure the LAN address, not endpoint_addr, once the tracker resolves to Lan"
        );

        wg.teardown().unwrap();
    }

    /// Sibling of the above: when the tracker resolves a peer to
    /// `Reflexive`, `reconcile` configures the peer's `reflexive_addr`,
    /// not `endpoint_addr`/`lan_addr` (PLAN.md decisions log #90+).
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_reconcile_configures_the_reflexive_endpoint_when_resolved() {
        if !crate::firewall::netns::reexec("wg::tests::kernel_reconcile_configures_the_reflexive_endpoint_when_resolved") {
            return;
        }
        let sh = |script: &str| {
            let out = std::process::Command::new("sh").args(["-euc", script]).output().unwrap();
            assert!(out.status.success(), "{script}: {}", String::from_utf8_lossy(&out.stderr));
        };
        sh("ip link set lo up");

        let own = clamp_private_key(&Key::generate());
        let mut wg = WgInterface::new("wgtest2").unwrap();
        wg.bring_up(&own.to_string(), "100.90.0.3".parse().unwrap(), "fd00:90::3".parse().unwrap(), 51821)
            .unwrap();

        let mut p = peer("peer", &key_b64(10));
        p.endpoint_addr = Some("203.0.113.5:51820".into());
        p.reflexive_addr = Some("198.51.100.9:55123".into());

        let mut endpoint_tiers = HashMap::new();
        endpoint_tiers.insert(p.pubkey.clone(), EndpointTier::Reflexive);
        wg.reconcile(std::slice::from_ref(&p), &[], &own.public_key().to_string(), false, &endpoint_tiers, &HashMap::new()).unwrap();

        let tunnel = tunnel_peers("wgtest2").unwrap();
        assert_eq!(
            tunnel[0].endpoint.as_deref(),
            Some("198.51.100.9:55123"),
            "must configure the reflexive address, not endpoint_addr, once the tracker resolves to Reflexive"
        );

        wg.teardown().unwrap();
    }
}
