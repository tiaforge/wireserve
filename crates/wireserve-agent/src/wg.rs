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
use wireserve_types::{PeerInfo, RelayEnd, RelayForward, ServiceInfo, TransitPair};

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
/// construction (every Fritz!Box ships `192.168.178.0/24`), which is why
/// `peer_tier_candidates` also compares public addresses, and why a match
/// is still only ever an optimistic attempt to verify, never a fact.
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
/// (PLAN.md M23, now the end-to-end relay of M39) is deliberately **not**
/// a tier here — it moves a peer's `AllowedIPs` onto the carry interface
/// rather than choosing an `Endpoint=`, and is layered above this whole
/// mechanism instead. See `RelayAssignments` and `desired_carry_peers`.
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
/// `is_on_own_lan`'s doc comment on why that's a hint, not proof), and
/// the peer isn't known to sit behind a different public address; a
/// `Reflexive` value is present whenever it's structurally well-formed.
///
/// `own_public` is this node's own public IPv4 addresses (see
/// [`public_v4s`]). Two nodes behind one router share its public address,
/// so when both sides know theirs and none match, the peer is on some
/// other LAN that merely reuses the same range — lego2 and minipc, both
/// `192.168.178.0/24` at different homes, spent a failed grace window on
/// each other's private address every time, and fell into transit
/// through it. When either side's is unknown, the attempt stays
/// optimistic, as before.
#[must_use]
pub fn peer_tier_candidates<'a>(
    own_subnets: &[(Ipv4Addr, u8)],
    own_public: &[Ipv4Addr],
    peer: &'a PeerInfo,
) -> PeerTierCandidates<'a> {
    let peer_public = public_v4s(peer, None);
    let other_site = !own_public.is_empty() && !peer_public.is_empty() && !peer_public.iter().any(|a| own_public.contains(a));
    let lan = peer
        .lan_addr
        .as_deref()
        .filter(|_| !other_site)
        .filter(|s| s.parse::<Ipv4Addr>().is_ok_and(|a| is_on_own_lan(own_subnets, a)));
    let reflexive = peer.reflexive_addr.as_deref().filter(|s| wireserve_types::is_valid_reflexive_addr(s));
    PeerTierCandidates { lan, reflexive }
}

/// The public IPv4 addresses a node is known by: its probed
/// `endpoint_addr_v4`, an `endpoint_addr` that is a v4 literal (an
/// operator's hostname is skipped rather than looked up), its advertised
/// `reflexive_addr`, and `reflexive` — for this node itself, whose own
/// reflexive address comes from its startup probe rather than the
/// directory. Ports are dropped: only the address says which router.
#[must_use]
pub fn public_v4s(p: &PeerInfo, reflexive: Option<&str>) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = [p.endpoint_addr_v4.as_deref(), p.endpoint_addr.as_deref(), p.reflexive_addr.as_deref(), reflexive]
        .into_iter()
        .flatten()
        .filter_map(|s| s.parse::<std::net::SocketAddrV4>().ok())
        .map(|a| *a.ip())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
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
    /// When `current` last produced a handshake newer than
    /// `baseline_handshake`, or `None` if it hasn't since it was switched
    /// to. See [`ENDPOINT_CONFIRMED_MAX`].
    confirmed_at: Option<std::time::Instant>,
    per_tier: HashMap<EndpointTier, TierState>,
}

/// How long a freshly-tried tier gets to produce a real handshake before
/// falling back. WireGuard sends its first handshake the moment the
/// endpoint is configured and retries every 5 seconds, so a working path
/// handshakes almost at once; what this has to cover is the poll interval,
/// since a tier is only judged once per poll. At the default 20s, 30s means
/// a tier is judged at the second poll after switching, not the first.
pub const ENDPOINT_GRACE_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);
/// How long a confirmed tier stays confirmed without a newer handshake. A
/// live session handshakes afresh about every two minutes (it rekeys when
/// sending on a key older than 120s, and the keepalive keeps it sending),
/// and never lasts past 180s without one — plus a grace window for when the
/// poll happens to see it. Without this a confirmed tier fell back to `Wan`
/// at the first poll that saw no newer handshake, which on a live session
/// is nearly every one. A path that dies is noticed sooner, by its silence
/// ([`PEER_SILENT_MAX`]); this only catches a peer that keeps sending
/// without ever completing a handshake.
pub const ENDPOINT_CONFIRMED_MAX: std::time::Duration =
    std::time::Duration::from_secs(180).saturating_add(ENDPOINT_GRACE_WINDOW);
/// How long a peer may send nothing at all before its path counts as dead.
/// Every agent sends a keepalive at the latest [`AGENT_KEEPALIVE_SECS`]
/// after its last packet, so a live path delivers something at least that
/// often: this is three of them, so two lost in a row don't count, and it
/// still covers a peer on an older build that keeps alive every 25s. The
/// handshake can't tell sooner: WireGuard only renews it every two minutes,
/// which is what made a dead direct path take four minutes to be given up.
pub const PEER_SILENT_MAX: std::time::Duration = std::time::Duration::from_secs(30);
/// How often the daemon reads the kernel's receive counters between polls
/// (`main.rs`), so a path that went quiet is noticed within this of
/// [`PEER_SILENT_MAX`], and the poll that asks for a relay runs at once.
pub const LIVENESS_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// How long a direct agent peer may stay quiet before it is nudged: sent one
/// datagram through the tunnel, to its mesh address. Any data packet makes
/// the peer's WireGuard answer with a keepalive within 10 seconds, whatever
/// its own keepalive setting — the kernel's passive keepalive, in every
/// version — even though nothing on the peer listens and its firewall drops
/// it. The peer's own keepalive can't be relied on: the kernel restarts its
/// countdown whenever anything arrives from this side, so a peer keeping
/// alive less often than this node never sends one at all (measured: 10s
/// against 25s, the 25s side stays silent until the next handshake, every
/// two minutes). One nudge per check while quiet: three go out before
/// [`PEER_SILENT_MAX`], so two lost answers don't count.
pub const NUDGE_AFTER: std::time::Duration = LIVENESS_CHECK_INTERVAL;
// The third nudge's answer (the kernel's passive keepalive, within 10s) still
// arrives before the peer counts as silent.
const _: () = assert!(NUDGE_AFTER.as_secs() + 2 * LIVENESS_CHECK_INTERVAL.as_secs() + 10 < PEER_SILENT_MAX.as_secs());
/// The port a nudge is sent to: discard. The datagram only has to reach the
/// peer's WireGuard; what its host does with it after that doesn't matter.
pub const NUDGE_PORT: u16 = 9;
/// The keepalive towards another agent, on both interfaces. It bounds how
/// soon a dead path can be told from a quiet one ([`PEER_SILENT_MAX`]), and
/// costs one 32-byte packet per peer this often.
pub const AGENT_KEEPALIVE_SECS: u16 = 10;
/// The keepalive towards a phone or any other static peer: every packet
/// can wake its radio, so it stays at the usual 25s.
pub const STATIC_KEEPALIVE_SECS: u16 = 25;

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

/// The next ranked tier after `after` that has a candidate this cycle,
/// wrapping around (so `after` itself when it is the only one).
fn next_tier_round(candidates: &PeerTierCandidates<'_>, after: EndpointTier) -> Option<EndpointTier> {
    let at = RANKED_TIERS.iter().position(|&t| t == after).unwrap_or(RANKED_TIERS.len() - 1);
    (1..=RANKED_TIERS.len())
        .map(|i| RANKED_TIERS[(at + i) % RANKED_TIERS.len()])
        .find(|&t| candidate_value(candidates, t).is_some())
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
///
/// A `transited` peer (its traffic goes via a carrier, PLAN.md M23) is
/// never put on `Wan` or backed off: its kernel entry is only a probe
/// (see `desired_peers`), so a failing candidate costs nothing, and the
/// backoff that protects real traffic from one would only stop both sides
/// of a NAT hole-punch from ever sending at the same time. It keeps
/// dialling its ranked candidates, taking turns each grace window, until
/// one handshakes.
///
/// `silent`: nothing has arrived from the peer for [`PEER_SILENT_MAX`]. A
/// confirmed tier is then given up at once rather than when its last
/// handshake ages past [`ENDPOINT_CONFIRMED_MAX`].
#[must_use]
pub fn resolve_endpoint_candidate(
    candidates: PeerTierCandidates<'_>,
    kernel_last_handshake: Option<chrono::DateTime<chrono::Utc>>,
    state: Option<EndpointPeerState>,
    transited: bool,
    silent: bool,
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
                let advanced = !silent
                    && match (kernel_last_handshake, s.baseline_handshake) {
                        (Some(h), Some(baseline)) => h > baseline,
                        (Some(_), None) => true,
                        (None, _) => false,
                    };
                let tier = s.current;
                if advanced {
                    per_tier.get_mut(&tier).unwrap().backoff = ENDPOINT_RETRY_BACKOFF_INITIAL;
                    return (
                        tier,
                        Some(EndpointPeerState {
                            current: tier,
                            switched_at: s.switched_at,
                            baseline_handshake: kernel_last_handshake,
                            confirmed_at: Some(now),
                            per_tier,
                        }),
                    );
                }
                let still_confirmed =
                    !silent && s.confirmed_at.is_some_and(|c| now.duration_since(c) < ENDPOINT_CONFIRMED_MAX);
                if still_confirmed || now.duration_since(s.switched_at) < ENDPOINT_GRACE_WINDOW {
                    return (
                        tier,
                        Some(EndpointPeerState {
                            current: tier,
                            switched_at: s.switched_at,
                            baseline_handshake: s.baseline_handshake,
                            confirmed_at: s.confirmed_at,
                            per_tier,
                        }),
                    );
                }
                if transited {
                    // Next candidate's turn, with nothing held against the
                    // one that just failed.
                    let next = next_tier_round(&candidates, tier).expect("`tier` itself still has a candidate");
                    let value = candidate_value(&candidates, next).expect("next_tier_round only returns a tier with a candidate");
                    per_tier.entry(next).or_insert_with(|| TierState::fresh(value));
                    return (
                        next,
                        Some(EndpointPeerState {
                            current: next,
                            switched_at: now,
                            baseline_handshake: kernel_last_handshake,
                            confirmed_at: None,
                            per_tier,
                        }),
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
    // retry-due tier is not a fresh one), or fall to `Wan`. A transited
    // peer ignores backoff (see above).
    let picked = if transited {
        RANKED_TIERS.iter().copied().find(|&t| candidate_value(&candidates, t).is_some())
    } else {
        pick_tier(&candidates, &per_tier, now)
    };
    match picked {
        Some(tier) => {
            let value = candidate_value(&candidates, tier).expect("pick_tier only ever returns a tier with a candidate this cycle");
            per_tier.entry(tier).or_insert_with(|| TierState::fresh(value));
            (
                tier,
                Some(EndpointPeerState {
                    current: tier,
                    switched_at: now,
                    baseline_handshake: kernel_last_handshake,
                    confirmed_at: None,
                    per_tier,
                }),
            )
        }
        // Staying on `Wan` keeps the time it was entered: that is what
        // `EndpointTracker::peers_wanting_transit` measures the WAN dial's
        // own grace window from.
        None => {
            let switched_at = state.filter(|s| s.current == EndpointTier::Wan).map_or(now, |s| s.switched_at);
            (
                EndpointTier::Wan,
                Some(EndpointPeerState {
                    current: EndpointTier::Wan,
                    switched_at,
                    baseline_handshake: None,
                    confirmed_at: None,
                    per_tier,
                }),
            )
        }
    }
}

/// Tracks every peer's endpoint-tier state across poll cycles —
/// in-memory only. Constructed once at daemon startup and lives exactly
/// as long as `WgInterface` (same lifetime pattern as its own
/// `applied`/`routed`), threaded through `poll_loop::PollContext`.
#[derive(Debug, Default)]
pub struct EndpointTracker {
    states: HashMap<String, EndpointPeerState>,
    /// The peers last cycle's directory routed via a carrier (PLAN.md
    /// M23) — see [`Self::peers_wanting_transit`].
    transited: std::collections::HashSet<String>,
    /// Each peer's receive counter as last read, and when it last moved —
    /// see [`Self::observe_rx`].
    rx: HashMap<String, RxSeen>,
    /// The tracked peers already found silent, so each going quiet wakes
    /// the poll loop once.
    silent_noted: std::collections::HashSet<String>,
    /// Every other agent this node reaches directly, by pubkey, with its
    /// mesh address — see [`Self::peers_to_nudge`].
    nudge: HashMap<String, Ipv4Addr>,
}

#[derive(Debug, Clone, Copy)]
struct RxSeen {
    bytes: u64,
    changed_at: std::time::Instant,
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
        let transited = self.transited.contains(pubkey);
        let silent = self.silent(pubkey, now);
        let (tier, new_state) = resolve_endpoint_candidate(candidates, kernel_last_handshake, state, transited, silent, now);
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
        self.rx.retain(|k, _| keep.contains(k.as_str()));
        self.silent_noted.retain(|k| keep.contains(k.as_str()));
    }

    /// Records each peer's receive counter (`rx` = pubkey and the kernel's
    /// `rx_bytes`). A peer seen for the first time counts as heard from
    /// now, so a restart or a new peer gets a full [`PEER_SILENT_MAX`]
    /// before it can count as silent.
    ///
    /// Returns whether a peer whose endpoint is tracked has just gone
    /// silent: the caller polls at once, so the relay is asked for now
    /// rather than at the next interval. Only tracked peers count — another
    /// agent, never a phone, whose quiet is normal and which no relay could
    /// help anyway.
    pub fn observe_rx<'a>(&mut self, rx: impl IntoIterator<Item = (&'a str, u64)>, now: std::time::Instant) -> bool {
        for (pubkey, bytes) in rx {
            match self.rx.get_mut(pubkey) {
                Some(seen) if seen.bytes == bytes => {}
                Some(seen) => *seen = RxSeen { bytes, changed_at: now },
                None => {
                    self.rx.insert(pubkey.to_string(), RxSeen { bytes, changed_at: now });
                }
            }
        }
        let mut newly = false;
        for pubkey in self.states.keys() {
            if self.silent(pubkey, now) {
                if self.silent_noted.insert(pubkey.clone()) {
                    tracing::info!(peer = %pubkey, "nothing received from this peer for {}s; its path counts as dead", PEER_SILENT_MAX.as_secs());
                    newly = true;
                }
            } else {
                self.silent_noted.remove(pubkey);
            }
        }
        newly
    }

    /// Whether nothing has arrived from `pubkey` for [`PEER_SILENT_MAX`]. A
    /// peer never observed is not silent: nothing is known about it.
    ///
    /// Nor is a relayed peer. Its entry on this interface is only a probe
    /// (see `desired_peers`): it routes nothing, so it can't be nudged, and
    /// keepalives alone go quiet on one side whenever the two ends keep
    /// alive at different intervals (see [`NUDGE_AFTER`]). Its direct path
    /// is judged by its handshake alone; if that turns out to be dead once
    /// the relay ends, the nudges find out within [`PEER_SILENT_MAX`].
    #[must_use]
    pub fn silent(&self, pubkey: &str, now: std::time::Instant) -> bool {
        !self.transited.contains(pubkey)
            && self.rx.get(pubkey).is_some_and(|seen| now.duration_since(seen.changed_at) >= PEER_SILENT_MAX)
    }

    /// Records every other agent this node reaches directly this cycle, with
    /// its mesh address: the peers [`Self::peers_to_nudge`] chooses from.
    pub fn note_direct_agents<'a>(&mut self, agents: impl IntoIterator<Item = (&'a str, Ipv4Addr)>) {
        self.nudge = agents.into_iter().map(|(pk, ip)| (pk.to_string(), ip)).collect();
    }

    /// The mesh addresses of the direct agent peers nothing has arrived from
    /// for [`NUDGE_AFTER`]: each is sent a datagram, so its WireGuard answers
    /// (see [`NUDGE_AFTER`]). A peer never observed is left alone, like in
    /// [`Self::silent`].
    #[must_use]
    pub fn peers_to_nudge(&self, now: std::time::Instant) -> Vec<Ipv4Addr> {
        let mut out: Vec<Ipv4Addr> = self
            .nudge
            .iter()
            .filter(|(pk, _)| !self.transited.contains(pk.as_str()))
            .filter(|(pk, _)| self.rx.get(pk.as_str()).is_some_and(|seen| now.duration_since(seen.changed_at) >= NUDGE_AFTER))
            .map(|(_, ip)| *ip)
            .collect();
        out.sort_unstable();
        out
    }

    /// [`transit_reachable_peers`], less every peer that has gone silent:
    /// a carrier whose own path to a peer died must stop offering it at
    /// once, not when the last handshake ages out.
    #[must_use]
    pub fn reachable_peers<'a>(
        &self,
        handshakes: &'a HashMap<String, Option<chrono::DateTime<chrono::Utc>>>,
        now_utc: chrono::DateTime<chrono::Utc>,
        now: std::time::Instant,
    ) -> Vec<&'a str> {
        let mut alive = transit_reachable_peers(handshakes, now_utc);
        alive.retain(|pk| !self.silent(pk, now));
        alive
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
    /// (PLAN.md M23): every peer this node has no live handshake with
    /// (the same freshness ground truth as [`transit_reachable_peers`],
    /// deliberately — a peer must be able to fail this same test on both
    /// the "do I need help" and "can I offer help" sides for the same
    /// reason) that is either
    ///
    /// - **on `Wan` for a full [`ENDPOINT_GRACE_WINDOW`]**: a failed
    ///   LAN/Reflexive probe still falls back to a working plain WAN dial
    ///   in the common case, and that dial must get its own chance before
    ///   transit is asked for. Asking in the same cycle the peer landed on
    ///   `Wan` meant the WAN address was never dialled at all; or
    /// - **transited right now** (see [`Self::note_transit`]): a transited
    ///   peer's kernel entry is only a probe (see `desired_peers`), so its
    ///   handshake is the direct path's alone, and the pair stays transited
    ///   until that path proves itself — not merely until a tier retry
    ///   briefly moves this peer off `Wan`, which would drop the transit
    ///   and black-hole the pair for a grace window each time.
    ///
    /// - **silent** (see [`Self::silent`]): its path is dead, whatever its
    ///   tier and however recent its last handshake. Asked for at once,
    ///   without the `Wan` grace window: the direct candidates go on being
    ///   dialled through the probe entry, and the first direct handshake
    ///   ends the relay again.
    ///
    /// A peer with no tracked history that isn't transited never counts:
    /// the ordinary plain-WAN-works-fine case must never request transit
    /// help for free.
    pub fn peers_wanting_transit<'a>(
        &'a self,
        handshakes: &HashMap<String, Option<chrono::DateTime<chrono::Utc>>>,
        now_utc: chrono::DateTime<chrono::Utc>,
        now: std::time::Instant,
    ) -> Vec<&'a str> {
        let alive: std::collections::HashSet<&str> = self.reachable_peers(handshakes, now_utc, now).into_iter().collect();
        let wan_given_up = self
            .states
            .iter()
            .filter(|(_, s)| s.current == EndpointTier::Wan && now.duration_since(s.switched_at) >= ENDPOINT_GRACE_WINDOW)
            .map(|(k, _)| k.as_str());
        let silent = self.states.keys().map(String::as_str).filter(|pk| self.silent(pk, now));
        let mut wanted: Vec<&str> = wan_given_up
            .chain(self.transited.iter().map(String::as_str))
            .chain(silent)
            .filter(|pk| !alive.contains(pk))
            .collect();
        wanted.sort_unstable();
        wanted.dedup();
        wanted
    }

    /// Records which peers this cycle's directory routes via a carrier, for
    /// the next cycle's [`Self::peers_wanting_transit`].
    ///
    /// A peer whose relay just ended starts a fresh [`PEER_SILENT_MAX`]: its
    /// probe entry may have been quiet for minutes (see [`Self::silent`]),
    /// and it only now carries traffic and gets nudged.
    pub fn note_transit<'a>(&mut self, transited: impl IntoIterator<Item = &'a str>, now: std::time::Instant) {
        let transited: std::collections::HashSet<String> = transited.into_iter().map(str::to_string).collect();
        for ended in self.transited.difference(&transited) {
            if let Some(seen) = self.rx.get_mut(ended) {
                seen.changed_at = now;
            }
        }
        self.transited = transited;
    }
}

/// How fresh a kernel `last_handshake` must be to count as "currently,
/// actually reachable" for transit purposes (PLAN.md M23) — comfortably
/// above WireGuard's own ~120s `REKEY_AFTER_TIME` ceiling under
/// continuous keepalive traffic (see `desired_peers`'s
/// `persistent_keepalive_interval`), so a genuinely live connection is
/// never misreported. A path that died within it is caught by its silence
/// instead ([`EndpointTracker::reachable_peers`]).
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
/// against the coordinator (`probe::probe_both`'s v6 result, threaded in
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

/// Where a relayed peer's session goes (PLAN.md M39): to its carrier's
/// mesh address, on the peer's own relay port. The carrier sends it on to
/// the peer's carry interface without being able to read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRoute {
    pub carrier: Ipv4Addr,
    pub port: u16,
}

/// Relayed peer's pubkey → its [`RelayRoute`], this cycle.
pub type RelayAssignments<'a> = HashMap<&'a str, RelayRoute>;

/// This node's relay assignments, from each peer's `relay.via` in a
/// `/poll` response. Only a peer with a relay port whose carrier is
/// another peer in the same response, with a usable IPv4 address, counts:
/// anything else is a stale or inconsistent directory, and the peer is
/// then simply reached directly — never routed somewhere half-known.
#[must_use]
pub fn relay_assignments<'a>(peers: &'a [PeerInfo], self_pubkey: &str) -> RelayAssignments<'a> {
    peers
        .iter()
        .filter(|p| p.pubkey != self_pubkey)
        .filter_map(|p| {
            let via = p.relay.via.as_deref()?;
            if via == self_pubkey || via == p.pubkey {
                return None;
            }
            let carrier = peers.iter().find(|c| c.pubkey == via)?.ip4.parse().ok()?;
            Some((p.pubkey.as_str(), RelayRoute { carrier, port: p.relay.port? }))
        })
        .collect()
}

/// The name of the carry interface that goes with `main` (PLAN.md M39):
/// `main` plus `-t`, cut short so the whole stays within the kernel's 15
/// characters.
#[must_use]
pub fn carry_ifname(main: &str) -> String {
    const SUFFIX: &str = "-t";
    let base: String = main.chars().take(15 - SUFFIX.len()).collect();
    format!("{base}{SUFFIX}")
}

/// The mesh interface's MTU, 20 below WireGuard's usual 1420. WireGuard pads
/// what it encrypts to a multiple of 16, up to the interface's MTU, so with
/// 1420 a relayed packet of 1400 (`CARRY_MTU` plus its own outer header)
/// went out padded to 1408, and as 1468 on the wire: 20 (IPv4) + 8 (UDP) +
/// 32 (WireGuard) is 60. DS-Lite carries 1460 (Vodafone cable, measured on
/// the real mesh), so every full-size relayed packet to or from such a node
/// was fragmented, and the fragments crossed the provider's NAT only some
/// of the time: connections opened, but TLS and SSH stalled for minutes.
/// At 1400 the padding stops at 1400 and the packet is 1460 on the wire
/// (1480 over IPv6).
pub const MESH_MTU: u32 = 1400;

/// The carry interface's MTU. Its packets travel inside the mesh
/// interface's own, between mesh addresses, which are IPv4 (`relay_assignments`),
/// so they are one IPv4 outer header (60, see `MESH_MTU`) shorter: a full
/// one exactly fills a mesh packet. Larger ones would be fragmented by the
/// carrier's tunnel on every full-size packet. A phone's relayed config
/// uses the same 1340 (`export_config::render_conf`).
pub const CARRY_MTU: u32 = MESH_MTU - 60;

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
/// `resolve` turns the chosen endpoint string into an address — see
/// `crate::endpoint_dns`; a peer whose endpoint it can't resolve (yet)
/// gets none this cycle, which leaves the kernel's current one in place.
///
/// A relayed peer (`relay`, PLAN.md M39) gets no `AllowedIPs` here: its
/// addresses are the carry interface's (`desired_carry_peers`), and an
/// address can only sit in one peer's `AllowedIPs` on a host at a time
/// without the two interfaces fighting over its route. Its entry is a
/// probe: it still dials the peer's direct candidates on the keepalive, so
/// a direct handshake can happen while the session runs through the
/// carrier. Without it nothing could ever handshake directly again,
/// "wanted" never cleared, and the pair stayed relayed for good (see
/// `EndpointTracker::peers_wanting_transit`). An entry with no
/// `AllowedIPs` routes nothing and accepts nothing.
pub fn desired_peers(
    peers: &[PeerInfo],
    services: &[ServiceInfo],
    self_pubkey: &str,
    prefer_ipv6: bool,
    endpoint_tiers: &HashMap<String, EndpointTier>,
    relay: &RelayAssignments<'_>,
    resolve: &dyn Fn(&str) -> Option<std::net::SocketAddr>,
) -> HashMap<Key, Peer> {
    let mut desired = HashMap::new();
    for p in peers {
        if p.pubkey == self_pubkey {
            continue;
        }
        let Ok(key) = Key::try_from(p.pubkey.as_str()) else {
            tracing::warn!(peer = %p.name, "skipping peer with unparseable pubkey");
            continue;
        };
        let mut peer = Peer::new(key.clone());
        if !relay.contains_key(p.pubkey.as_str()) {
            peer.allowed_ips = peer_allowed_ips(&p.ip4, &p.ip6);
            peer.allowed_ips.extend(
                owned_vips(services, &p.name).map(|vip| IpAddrMask::host(IpAddr::V4(vip))),
            );
        }
        let tier = endpoint_tiers.get(&p.pubkey).copied();
        if let Some(endpoint) = choose_peer_endpoint(p, prefer_ipv6, tier) {
            peer.endpoint = resolve(&endpoint);
        }
        // This node likely roams networks (dynamic DNS, NAT rebinding) —
        // same reasoning as spec §9's export-config PersistentKeepalive.
        // Towards another agent also what tells a dead path from a quiet
        // one (`PEER_SILENT_MAX`).
        peer.persistent_keepalive_interval = Some(keepalive_for(p));
        desired.insert(key, peer);
    }

    desired
}

/// The carry interface's peers (PLAN.md M39): one per relayed peer, with
/// the addresses its main-interface entry gave up (see `desired_peers`),
/// dialled at its carrier. Its main entry stays behind as a probe, so a
/// direct path can still handshake and end the relay.
pub fn desired_carry_peers(
    peers: &[PeerInfo],
    services: &[ServiceInfo],
    self_pubkey: &str,
    relay: &RelayAssignments<'_>,
) -> HashMap<Key, Peer> {
    let mut desired = HashMap::new();
    for p in peers {
        if p.pubkey == self_pubkey {
            continue;
        }
        let Some(route) = relay.get(p.pubkey.as_str()) else {
            continue;
        };
        let Ok(key) = Key::try_from(p.pubkey.as_str()) else {
            continue;
        };
        let mut peer = Peer::new(key.clone());
        peer.allowed_ips = peer_allowed_ips(&p.ip4, &p.ip6);
        peer.allowed_ips.extend(owned_vips(services, &p.name).map(|vip| IpAddrMask::host(IpAddr::V4(vip))));
        peer.endpoint = Some(std::net::SocketAddr::from((route.carrier, route.port)));
        peer.persistent_keepalive_interval = Some(AGENT_KEEPALIVE_SECS);
        desired.insert(key, peer);
    }
    desired
}

/// The keepalive towards `p`: [`AGENT_KEEPALIVE_SECS`] for another agent,
/// [`STATIC_KEEPALIVE_SECS`] for a phone.
fn keepalive_for(p: &PeerInfo) -> u16 {
    if is_agent(p) {
        AGENT_KEEPALIVE_SECS
    } else {
        STATIC_KEEPALIVE_SECS
    }
}

/// Whether `p` is another agent rather than a phone or other static peer.
/// Every agent registers a listen port and no static peer has one, so that
/// decides; a carry port, LAN or reflexive address also only ever comes
/// from an agent, for a coordinator too old to list the port. The listen
/// port is the one that doesn't come and go: the carry port drops out of the
/// directory whenever the coordinator hasn't heard the node lately (a
/// restart forgets it), and the reflexive address when its startup check
/// failed — and either used to drop the keepalive to 25s on one side only.
#[must_use]
pub fn is_agent(p: &PeerInfo) -> bool {
    p.relay.listen_port.is_some() || p.relay.carry_port.is_some() || p.lan_addr.is_some() || p.reflexive_addr.is_some()
}

/// Sends one nudge (see [`NUDGE_AFTER`]) to each of `targets` from `socket`,
/// bound to this node's mesh address so the peer's WireGuard accepts it as
/// this node's. Best-effort: a failed send is the same as a lost answer.
pub async fn nudge(socket: &tokio::net::UdpSocket, targets: &[Ipv4Addr]) {
    for ip in targets {
        if let Err(e) = socket.send_to(&[0], (*ip, NUDGE_PORT)).await {
            tracing::debug!(peer = %ip, error = %e, "could not nudge a quiet peer");
        }
    }
}

/// The addresses of the services `node` owns.
fn owned_vips<'a>(services: &'a [ServiceInfo], node: &'a str) -> impl Iterator<Item = Ipv4Addr> + 'a {
    services
        .iter()
        .filter(move |s| s.node == node)
        .filter_map(|s| s.vip4.as_deref()?.parse().ok())
}

/// The pairs this node relays this cycle (PLAN.md M39), from
/// `PollResponse::relay_carrying` and the two peers' own entries. A pair
/// naming a peer this node doesn't know, or one without an IPv4 address,
/// relay port or carry port, is dropped: there is nothing safe to guess.
#[must_use]
pub fn relay_forwards(peers: &[PeerInfo], self_pubkey: &str, carrying: &[TransitPair]) -> Vec<RelayForward> {
    let end = |pubkey: &str| -> Option<RelayEnd> {
        if pubkey == self_pubkey {
            return None;
        }
        let p = peers.iter().find(|p| p.pubkey == pubkey)?;
        Some(RelayEnd { ip4: p.ip4.parse().ok()?, relay_port: p.relay.port?, carry_port: p.relay.carry_port? })
    };
    carrying
        .iter()
        .filter(|pair| pair.a != pair.c)
        .filter_map(|pair| Some(RelayForward { a: end(&pair.a)?, c: end(&pair.c)? }))
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
///
/// The same goes for a changed peer whose endpoint didn't change: it is
/// sent without one, which the kernel reads as "keep yours". Otherwise
/// moving a transited peer's `AllowedIPs` back onto its own entry would
/// also reset the address the kernel learned from the peer's handshake —
/// for a peer that is only reachable because *it* dialled in, the one
/// address that works.
pub fn peers_to_configure(applied: &HashMap<Key, Peer>, desired: &HashMap<Key, Peer>) -> Vec<Peer> {
    desired
        .iter()
        .filter_map(|(key, peer)| match applied.get(key) {
            Some(old) if old == peer => None,
            Some(old) if old.endpoint == peer.endpoint => Some(Peer { endpoint: None, ..peer.clone() }),
            _ => Some(peer.clone()),
        })
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
            rx_bytes: p.rx_bytes,
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
    resolver: crate::endpoint_dns::EndpointResolver,
    /// The carry interface relayed sessions run on (PLAN.md M39), once
    /// `bring_up_carry` made it.
    carry: Option<Carry>,
}

/// The carry interface: the same private key as the mesh interface, no
/// address of its own (its routes name the node's mesh address as their
/// source), and a port the kernel picked.
struct Carry {
    api: WGApi<Kernel>,
    ifname: String,
    port: u16,
    src: (Ipv4Addr, Ipv6Addr),
    applied: HashMap<Key, Peer>,
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
            resolver: crate::endpoint_dns::EndpointResolver::default(),
            carry: None,
        })
    }

    /// Creates the carry interface next to this one (PLAN.md M39) and
    /// returns its listen port. Refused, like `bring_up`, for a name held
    /// by an interface that isn't this node's own. An existing one of ours
    /// keeps its port, so a restart doesn't move every relayed session.
    ///
    /// `port` is the one it had before, from the node's state: kept, so a
    /// carrier's tracked flows for this node's relayed sessions stay right
    /// (see `AgentState::carry_port`). Only when something else holds it
    /// now does the kernel pick another.
    pub fn bring_up_carry(
        &mut self,
        private_key_b64: &str,
        ip4: Ipv4Addr,
        ip6: Ipv6Addr,
        port: Option<u16>,
    ) -> Result<u16, BringUpError> {
        let mut carry = WgInterface::new(carry_ifname(&self.ifname))?;
        let existing = match carry.classify(private_key_b64) {
            Slot::Free => None,
            Slot::Ours => carry.api.read_interface_data().ok().map(|h| h.listen_port).filter(|p| *p != 0),
            Slot::Foreign(reason) => {
                return Err(BringUpError::InterfaceConflict { ifname: carry.ifname.clone(), reason });
            }
        };
        carry.api.create_interface()?;
        let configure = |port: u16| {
            carry.api.configure_interface(&InterfaceConfiguration {
                name: carry.ifname.clone(),
                prvkey: private_key_b64.to_string(),
                addresses: Vec::new(),
                port,
                peers: Vec::new(),
                mtu: Some(CARRY_MTU),
                fwmark: None,
            })
        };
        let wanted = existing.or(port).unwrap_or(0);
        if let Err(e) = configure(wanted) {
            if wanted == 0 {
                return Err(e.into());
            }
            tracing::warn!(port = wanted, error = %e, "the carry interface's port is taken; the kernel picks another");
            configure(0)?;
        }
        let port = carry.api.read_interface_data()?.listen_port;
        self.carry = Some(Carry {
            api: carry.api,
            ifname: carry.ifname,
            port,
            src: (ip4, ip6),
            applied: HashMap::new(),
            routed: BTreeSet::new(),
        });
        Ok(port)
    }

    /// The carry interface's listen port, once it is up.
    #[must_use]
    pub fn carry_port(&self) -> Option<u16> {
        self.carry.as_ref().map(|c| c.port)
    }

    /// The carry interface's name, once it is up.
    #[must_use]
    pub fn carry_name(&self) -> Option<&str> {
        self.carry.as_ref().map(|c| c.ifname.as_str())
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
            mtu: Some(MESH_MTU),
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
        relay: &RelayAssignments<'_>,
    ) -> Result<(), WireguardInterfaceError> {
        // Without a carry interface nothing can be relayed: every peer is
        // then reached directly, whatever the coordinator said.
        let none = RelayAssignments::new();
        let relay = if self.carry.is_some() { relay } else { &none };
        // Hostname endpoints are looked up here, bounded, before the pure
        // build below reads them — never inside it (see `endpoint_dns`).
        let endpoints: Vec<String> = peers
            .iter()
            .filter(|p| p.pubkey != self_pubkey)
            .filter_map(|p| choose_peer_endpoint(p, prefer_ipv6, endpoint_tiers.get(&p.pubkey).copied()))
            .collect();
        self.resolver.prepare(endpoints.iter().map(String::as_str));
        self.resolver.retain(endpoints.iter().map(String::as_str));
        let resolver = &self.resolver;
        let desired =
            desired_peers(peers, services, self_pubkey, prefer_ipv6, endpoint_tiers, relay, &|e| resolver.get(e));

        // A peer moving onto the carry interface leaves this one first, and
        // one moving back leaves the carry interface first: the same address
        // in two peers' `AllowedIPs` on one host would do no harm, but
        // there is no reason to have it even for a moment.
        let to_remove = peers_to_remove(self.applied.keys(), &desired);
        for key in &to_remove {
            self.api.remove_peer(key)?;
        }
        let carry_desired = self
            .carry
            .as_ref()
            .map(|_| desired_carry_peers(peers, services, self_pubkey, relay))
            .unwrap_or_default();
        if let Some(carry) = &mut self.carry {
            for key in peers_to_remove(carry.applied.keys(), &carry_desired) {
                carry.api.remove_peer(&key)?;
                carry.applied.remove(&key);
            }
        }
        let to_configure = peers_to_configure(&self.applied, &desired);
        for peer in &to_configure {
            self.api.configure_peer(peer)?;
        }
        if let Some(carry) = &mut self.carry {
            for peer in peers_to_configure(&carry.applied, &carry_desired) {
                carry.api.configure_peer(&peer)?;
            }
            carry.applied = carry_desired;
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
        let carry_routes = self
            .carry
            .as_ref()
            .map(|c| desired_routes(&c.applied, std::iter::empty()))
            .unwrap_or_default();
        let carry_changed = self.carry.as_ref().is_some_and(|c| c.routed != carry_routes);
        if routes != self.routed || carry_changed {
            // A route that couldn't be set is logged (by `sync`) and retried
            // on the next cycle, not fatal: failing here would leave
            // `applied` stale and reconfigure every peer next cycle, which
            // resets WireGuard's own endpoint roaming (see above). Both
            // interfaces in one go, so an address changing interface loses
            // its old route before it gets the new one.
            let mut sets = vec![crate::routes::RouteSet { ifname: &self.ifname, old: &self.routed, new: &routes, prefsrc: None }];
            if let Some(c) = &self.carry {
                sets.push(crate::routes::RouteSet { ifname: &c.ifname, old: &c.routed, new: &carry_routes, prefsrc: Some(c.src) });
            }
            match crate::routes::sync_all(&sets) {
                Ok(()) => {
                    self.routed = routes;
                    if let Some(c) = &mut self.carry {
                        c.routed = carry_routes;
                    }
                }
                Err(e) => tracing::warn!(ifname = %self.ifname, error = %e, "peer routes are incomplete"),
            }
        }

        self.applied = desired;
        Ok(())
    }

    /// Deletes the interface, and with it its addresses and routes. Not
    /// defguard's `remove_interface`; see `routes::delete_link` for why.
    pub fn teardown(&mut self) -> Result<(), WireguardInterfaceError> {
        // The carry interface first, and whatever happens to it the mesh
        // interface still goes.
        let carry = self.carry.take().map(|c| crate::routes::delete_link(&c.ifname));
        crate::routes::delete_link(&self.ifname)?;
        self.applied.clear();
        self.routed.clear();
        carry.transpose()?;
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
            relay: Default::default(),
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
        let desired = desired_peers(&peers, &[], &self_key, false, &HashMap::new(), &HashMap::new(), &crate::endpoint_dns::literal_only);
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
        let desired = desired_peers(&peers, &[], &self_key, false, &HashMap::new(), &HashMap::new(), &crate::endpoint_dns::literal_only);
        assert_eq!(desired.len(), 1);
    }

    // ---- end-to-end relay (PLAN.md M39) ----

    fn relay_directory() -> (String, String, String, Vec<PeerInfo>) {
        let (self_key, b_key, c_key) = (key_b64(1), key_b64(2), key_b64(3));
        let mut me = peer("me", &self_key);
        me.ip4 = "100.90.0.1".into();
        let mut b = peer("b", &b_key);
        b.ip4 = "100.90.0.2".into();
        b.relay.port = Some(41001);
        b.relay.carry_port = Some(50002);
        let mut c = peer("c", &c_key);
        c.ip4 = "100.90.0.3".into();
        c.ip6 = "fd00:90::3".into();
        c.relay = wireserve_types::PeerRelay { port: Some(41002), carry_port: Some(50003), via: Some(b_key.clone()), listen_port: None };
        (self_key, b_key, c_key, vec![me, b, c])
    }

    #[test]
    fn carry_ifname_appends_the_suffix_within_the_kernels_limit() {
        assert_eq!(carry_ifname("wireserve0"), "wireserve0-t");
        assert_eq!(carry_ifname("a-very-long-nam"), "a-very-long-n-t");
        assert!(carry_ifname("a-very-long-nam").len() <= 15);
    }

    #[test]
    fn a_relayed_peer_is_dialled_at_its_carrier_on_its_own_relay_port() {
        let (self_key, _, c_key, peers) = relay_directory();
        let relay = relay_assignments(&peers, &self_key);
        assert_eq!(relay.get(c_key.as_str()), Some(&RelayRoute { carrier: "100.90.0.2".parse().unwrap(), port: 41002 }));
        assert_eq!(relay.len(), 1);
    }

    #[test]
    fn a_relay_naming_an_unknown_or_self_or_the_peer_itself_as_carrier_is_ignored() {
        let (self_key, _, c_key, mut peers) = relay_directory();
        for via in [key_b64(9), self_key.clone(), c_key.clone()] {
            peers[2].relay.via = Some(via);
            assert!(relay_assignments(&peers, &self_key).is_empty());
        }
        peers[2].relay.via = Some(key_b64(2));
        peers[2].relay.port = None;
        assert!(relay_assignments(&peers, &self_key).is_empty(), "no relay port, nothing to dial");
    }

    #[test]
    fn a_relayed_peer_keeps_a_probe_on_the_mesh_interface_and_its_addresses_move_to_the_carry_interface() {
        let (self_key, b_key, c_key, peers) = relay_directory();
        let services = [service("web", "c", Some("100.90.0.50"))];
        let relay = relay_assignments(&peers, &self_key);
        let main = desired_peers(&peers, &services, &self_key, false, &HashMap::new(), &relay, &crate::endpoint_dns::literal_only);
        let c = &main[&Key::try_from(c_key.as_str()).unwrap()];
        assert!(c.allowed_ips.is_empty(), "the probe routes nothing");
        let b = &main[&Key::try_from(b_key.as_str()).unwrap()];
        assert_eq!(b.allowed_ips.len(), 2, "nothing is folded into the carrier: {:?}", b.allowed_ips);

        let carry = desired_carry_peers(&peers, &services, &self_key, &relay);
        assert_eq!(carry.len(), 1);
        let c = &carry[&Key::try_from(c_key.as_str()).unwrap()];
        assert_eq!(c.endpoint, Some("100.90.0.2:41002".parse().unwrap()));
        let ips: Vec<String> = c.allowed_ips.iter().map(ToString::to_string).collect();
        assert_eq!(ips, ["100.90.0.3/32", "fd00:90::3/128", "100.90.0.50/32"]);
        assert_eq!(c.persistent_keepalive_interval, Some(AGENT_KEEPALIVE_SECS));
    }

    #[test]
    fn another_agent_is_kept_alive_more_often_than_a_phone() {
        let (self_key, b_key, _, mut peers) = relay_directory();
        let phone_key = key_b64(4);
        peers.push(peer("phone", &phone_key));
        let mut nat = peer("nat", &key_b64(5));
        nat.reflexive_addr = Some("203.0.113.5:40404".into());
        peers.push(nat);
        let main = desired_peers(&peers, &[], &self_key, false, &HashMap::new(), &HashMap::new(), &crate::endpoint_dns::literal_only);
        let keepalive = |k: &str| main[&Key::try_from(k).unwrap()].persistent_keepalive_interval;
        assert_eq!(keepalive(&b_key), Some(AGENT_KEEPALIVE_SECS), "an agent with a carry port");
        assert_eq!(keepalive(&key_b64(5)), Some(AGENT_KEEPALIVE_SECS), "an agent with only a reflexive address");
        assert_eq!(keepalive(&phone_key), Some(STATIC_KEEPALIVE_SECS));
    }

    #[test]
    fn relay_forwards_take_both_ends_from_the_directory_and_drop_what_is_incomplete() {
        let (self_key, b_key, c_key, mut peers) = relay_directory();
        let a_key = key_b64(4);
        let mut a = peer("a", &a_key);
        a.ip4 = "100.90.0.4".into();
        a.relay = wireserve_types::PeerRelay { port: Some(41004), carry_port: Some(50004), via: None, listen_port: None };
        peers.push(a);
        let pair = |x: &str, y: &str| TransitPair { a: x.into(), c: y.into() };
        let fwd = relay_forwards(&peers, &self_key, &[pair(&a_key, &c_key)]);
        assert_eq!(fwd, [RelayForward {
            a: RelayEnd { ip4: "100.90.0.4".parse().unwrap(), relay_port: 41004, carry_port: 50004 },
            c: RelayEnd { ip4: "100.90.0.3".parse().unwrap(), relay_port: 41002, carry_port: 50003 },
        }]);
        assert!(relay_forwards(&peers, &self_key, &[pair(&a_key, &self_key)]).is_empty(), "never this node itself");
        assert!(relay_forwards(&peers, &self_key, &[pair(&a_key, &key_b64(9))]).is_empty(), "unknown peer");
        peers[1].relay.carry_port = None;
        assert!(relay_forwards(&peers, &self_key, &[pair(&a_key, &b_key)]).is_empty(), "no carry port");
    }

    // ---- wanting help, and reaching (PLAN.md M23) ----

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
        assert!(tracker.peers_wanting_transit(&handshakes, now_utc, now + GRACE * 3).is_empty());
    }

    #[test]
    fn peers_wanting_transit_includes_a_wan_peer_with_a_stale_or_missing_handshake() {
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        let pubkey = key_b64(2).to_string();
        tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now);
        let tier = tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now + GRACE);
        assert_eq!(tier, EndpointTier::Wan);
        let later = now + GRACE * 2;

        let now_utc = chrono::Utc::now();
        // No entry at all for this pubkey in `handshakes` — never handshaked.
        assert_eq!(tracker.peers_wanting_transit(&HashMap::new(), now_utc, later), vec![pubkey.as_str()]);

        // A handshake that exists but is older than
        // `TRANSIT_REACHABLE_HANDSHAKE_MAX` counts the same as none.
        let stale = HashMap::from([(
            pubkey.clone(),
            Some(now_utc - chrono::Duration::from_std(TRANSIT_REACHABLE_HANDSHAKE_MAX).unwrap() - chrono::Duration::seconds(1)),
        )]);
        assert_eq!(tracker.peers_wanting_transit(&stale, now_utc, later), vec![pubkey.as_str()]);
    }

    #[test]
    fn peers_wanting_transit_gives_the_wan_dial_its_own_grace_window_first() {
        // The bug this guards: landing on `Wan` and asking for transit in
        // the same cycle, before the WAN address was ever dialled.
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        let pubkey = key_b64(2).to_string();
        tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, now);
        let on_wan = now + GRACE;
        assert_eq!(tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, on_wan), EndpointTier::Wan);
        let now_utc = chrono::Utc::now();
        assert!(tracker.peers_wanting_transit(&HashMap::new(), now_utc, on_wan).is_empty());

        // Further cycles on `Wan` don't restart that window.
        let mid = on_wan + GRACE / 2;
        assert_eq!(tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, mid), EndpointTier::Wan);
        assert!(tracker.peers_wanting_transit(&HashMap::new(), now_utc, mid).is_empty());
        let end = on_wan + GRACE;
        assert_eq!(tracker.resolve(&pubkey, lan_only("192.168.1.50"), None, end), EndpointTier::Wan);
        assert_eq!(tracker.peers_wanting_transit(&HashMap::new(), now_utc, end), vec![pubkey.as_str()]);
    }

    #[test]
    fn a_transited_peer_stays_wanted_until_its_direct_path_handshakes() {
        // Even while a tier retry has it off `Wan`, and with no tracked
        // history at all (the other side may be the one that asked).
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        let c_key = key_b64(3);
        tracker.resolve(&c_key, lan_only("192.168.1.50"), None, now);
        tracker.note_transit([c_key.as_str()], now);
        let now_utc = chrono::Utc::now();
        assert_eq!(tracker.peers_wanting_transit(&HashMap::new(), now_utc, now), vec![c_key.as_str()]);

        let direct = HashMap::from([(c_key.clone(), Some(now_utc))]);
        assert!(tracker.peers_wanting_transit(&direct, now_utc, now).is_empty());

        tracker.note_transit([], now);
        assert!(tracker.peers_wanting_transit(&HashMap::new(), now_utc, now).is_empty());
    }

    #[test]
    fn a_peer_is_silent_once_its_counter_stops_for_the_whole_window() {
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        tracker.observe_rx([("pk-a", 100)], now);
        assert!(!tracker.silent("pk-a", now + PEER_SILENT_MAX / 2));
        assert!(!tracker.silent("pk-never-seen", now + PEER_SILENT_MAX * 2), "nothing known is not silent");
        tracker.observe_rx([("pk-a", 164)], now + PEER_SILENT_MAX / 2);
        assert!(!tracker.silent("pk-a", now + PEER_SILENT_MAX), "a moving counter restarts the window");
        tracker.observe_rx([("pk-a", 164)], now + PEER_SILENT_MAX);
        assert!(tracker.silent("pk-a", now + PEER_SILENT_MAX / 2 + PEER_SILENT_MAX));
    }

    #[test]
    fn a_tracked_peer_going_silent_wakes_the_poll_once_and_a_phone_never_does() {
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        tracker.resolve("pk-agent", reflexive_only("203.0.113.5:40404"), None, now);
        assert!(!tracker.observe_rx([("pk-agent", 10), ("pk-phone", 10)], now));
        let later = now + PEER_SILENT_MAX;
        assert!(tracker.observe_rx([("pk-agent", 10), ("pk-phone", 10)], later), "the agent went quiet");
        assert!(!tracker.observe_rx([("pk-agent", 10), ("pk-phone", 10)], later + LIVENESS_CHECK_INTERVAL), "only once");
        assert!(!tracker.observe_rx([("pk-agent", 20), ("pk-phone", 10)], later + LIVENESS_CHECK_INTERVAL * 2));
        let again = later + LIVENESS_CHECK_INTERVAL * 2 + PEER_SILENT_MAX;
        assert!(tracker.observe_rx([("pk-agent", 20), ("pk-phone", 10)], again), "heard from, then quiet again");
    }

    #[test]
    fn a_silent_peer_wants_a_relay_at_once_despite_a_recent_handshake() {
        let now = std::time::Instant::now();
        let now_utc = chrono::Utc::now();
        let mut tracker = EndpointTracker::default();
        let pk = key_b64(3);
        tracker.resolve(&pk, reflexive_only("203.0.113.5:40404"), None, now);
        tracker.observe_rx([(pk.as_str(), 10)], now);
        let handshakes = HashMap::from([(pk.clone(), Some(now_utc))]);
        assert!(tracker.peers_wanting_transit(&handshakes, now_utc, now).is_empty());
        assert_eq!(tracker.reachable_peers(&handshakes, now_utc, now), vec![pk.as_str()]);

        let quiet = now + PEER_SILENT_MAX;
        assert_eq!(tracker.peers_wanting_transit(&handshakes, now_utc, quiet), vec![pk.as_str()]);
        assert!(tracker.reachable_peers(&handshakes, now_utc, quiet).is_empty(), "a carrier stops offering it");
    }

    #[test]
    fn a_relayed_peer_is_judged_by_its_handshake_and_gets_a_fresh_window_when_the_relay_ends() {
        let now = std::time::Instant::now();
        let now_utc = chrono::Utc::now();
        let mut tracker = EndpointTracker::default();
        let pk = key_b64(3);
        tracker.resolve(&pk, reflexive_only("203.0.113.5:40404"), None, now);
        tracker.observe_rx([(pk.as_str(), 10)], now);
        tracker.note_transit([pk.as_str()], now);
        // Its probe entry only keeps alive, and may hear nothing for minutes.
        let quiet = now + PEER_SILENT_MAX * 4;
        assert!(!tracker.observe_rx([(pk.as_str(), 10)], quiet), "a relayed peer never wakes the poll");
        assert!(!tracker.silent(&pk, quiet));
        let handshakes = HashMap::from([(pk.clone(), Some(now_utc))]);
        assert!(tracker.peers_wanting_transit(&handshakes, now_utc, quiet).is_empty(), "its fresh handshake ends the relay");

        tracker.note_transit([], quiet);
        assert!(!tracker.silent(&pk, quiet + PEER_SILENT_MAX / 2), "the direct path gets a whole window");
        assert!(tracker.silent(&pk, quiet + PEER_SILENT_MAX), "and is dead once that passes in silence");
    }

    #[test]
    fn only_a_quiet_direct_agent_is_nudged() {
        let now = std::time::Instant::now();
        let mut tracker = EndpointTracker::default();
        let (a, b, c, d): (Ipv4Addr, Ipv4Addr, Ipv4Addr, Ipv4Addr) =
            ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap(), "10.0.0.3".parse().unwrap(), "10.0.0.4".parse().unwrap());
        tracker.note_direct_agents([("pk-quiet", a), ("pk-chatty", b), ("pk-relayed", c), ("pk-never-seen", d)]);
        tracker.note_transit(["pk-relayed"], now);
        tracker.observe_rx([("pk-quiet", 1), ("pk-chatty", 1), ("pk-relayed", 1), ("pk-phone", 1)], now);
        assert!(tracker.peers_to_nudge(now + NUDGE_AFTER / 2).is_empty());
        let later = now + NUDGE_AFTER;
        tracker.observe_rx([("pk-quiet", 1), ("pk-chatty", 2), ("pk-relayed", 1), ("pk-phone", 1)], later);
        assert_eq!(tracker.peers_to_nudge(later), vec![a]);
    }

    #[test]
    fn every_agent_is_kept_alive_at_the_agent_interval_whatever_the_coordinator_forgot() {
        let mut agent = peer("strato", &key_b64(2));
        agent.relay.listen_port = Some(51820);
        assert!(agent.lan_addr.is_none() && agent.reflexive_addr.is_none() && agent.relay.carry_port.is_none());
        assert_eq!(keepalive_for(&agent), AGENT_KEEPALIVE_SECS);
        let phone = peer("s25", &key_b64(3));
        assert_eq!(keepalive_for(&phone), STATIC_KEEPALIVE_SECS);
    }

    fn service(name: &str, node: &str, vip4: Option<&str>) -> ServiceInfo {
        ServiceInfo {
            terminated: false,
            name: name.into(),
            node: node.into(),
            ip4: String::new(),
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
        let desired = desired_peers(&[peer("me", &self_key), other], &services, &self_key, false, &HashMap::new(), &HashMap::new(), &crate::endpoint_dns::literal_only);
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
        let desired = desired_peers(&[other], &services, &self_key, false, &HashMap::new(), &HashMap::new(), &crate::endpoint_dns::literal_only);
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

        let desired_v4 = desired_peers(&[other.clone()], &[], &self_key, false, &HashMap::new(), &HashMap::new(), &crate::endpoint_dns::literal_only);
        let key = defguard_wireguard_rs::key::Key::try_from(key_b64(2).as_str()).unwrap();
        assert_eq!(
            desired_v4[&key].endpoint,
            Some("203.0.113.5:51820".parse().unwrap())
        );

        let desired_v6 = desired_peers(&[other], &[], &self_key, true, &HashMap::new(), &HashMap::new(), &crate::endpoint_dns::literal_only);
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

    #[test]
    fn peers_to_configure_leaves_an_unchanged_endpoint_to_the_kernel() {
        // Moving `AllowedIPs` (a transit ending) must not reset the address
        // the kernel learned by roaming; a changed endpoint is still sent.
        let a = defguard_wireguard_rs::key::Key::new([1; 32]);
        let mut old = Peer::new(a.clone());
        old.endpoint = Some("203.0.113.9:51820".parse().unwrap());
        let applied = HashMap::from([(a.clone(), old.clone())]);

        let mut more_ips = old.clone();
        more_ips.allowed_ips = peer_allowed_ips("100.90.0.3", "");
        let sent = peers_to_configure(&applied, &HashMap::from([(a.clone(), more_ips)]));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].endpoint, None);
        assert_eq!(sent[0].allowed_ips.len(), 1);

        let mut moved = old.clone();
        moved.endpoint = Some("192.168.1.50:51820".parse().unwrap());
        let sent = peers_to_configure(&applied, &HashMap::from([(a, moved)]));
        assert_eq!(sent[0].endpoint, Some("192.168.1.50:51820".parse().unwrap()));
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
        assert_eq!(peer_tier_candidates(&subnets, &[], &p).lan, Some("192.168.1.50"));
    }

    #[test]
    fn peer_tier_candidates_drops_a_lan_addr_outside_every_own_subnet() {
        let subnets = own_lan_subnets(&[lan("192.168.1.2", 24)]);
        let p = info_with(Some("10.0.0.5"), None);
        assert_eq!(peer_tier_candidates(&subnets, &[], &p).lan, None);
    }

    #[test]
    fn peer_tier_candidates_drops_a_lan_addr_behind_a_different_public_address() {
        // lego2 and minipc: both 192.168.178.0/24, at two different homes.
        let subnets = own_lan_subnets(&[lan("192.168.178.26", 24)]);
        let own: [Ipv4Addr; 1] = ["213.196.211.215".parse().unwrap()];
        let mut p = info_with(Some("192.168.178.44"), None);
        p.endpoint_addr_v4 = Some("92.208.31.99:51820".into());
        assert_eq!(peer_tier_candidates(&subnets, &own, &p).lan, None);
    }

    #[test]
    fn peer_tier_candidates_keeps_a_lan_addr_behind_the_same_public_address() {
        let subnets = own_lan_subnets(&[lan("192.168.178.44", 24)]);
        let own: [Ipv4Addr; 1] = ["92.208.31.99".parse().unwrap()];
        // Matched on the reflexive address, a different port and all.
        let p = info_with(Some("192.168.178.28"), Some("92.208.31.99:40404"));
        assert_eq!(peer_tier_candidates(&subnets, &own, &p).lan, Some("192.168.178.28"));
    }

    #[test]
    fn peer_tier_candidates_stays_optimistic_when_either_public_address_is_unknown() {
        let subnets = own_lan_subnets(&[lan("192.168.178.26", 24)]);
        let own: [Ipv4Addr; 1] = ["213.196.211.215".parse().unwrap()];
        let p = info_with(Some("192.168.178.44"), None);
        assert_eq!(peer_tier_candidates(&subnets, &own, &p).lan, Some("192.168.178.44"));
        let mut p = p;
        p.endpoint_addr_v4 = Some("92.208.31.99:51820".into());
        assert_eq!(peer_tier_candidates(&subnets, &[], &p).lan, Some("192.168.178.44"));
    }

    #[test]
    fn public_v4s_takes_v4_addresses_and_skips_hostnames_and_v6() {
        let mut p = info_with(None, Some("198.51.100.7:40404"));
        p.endpoint_addr = Some("home.example.org:51820".into());
        p.endpoint_addr_v4 = Some("198.51.100.7:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        let got = public_v4s(&p, Some("203.0.113.1:1234"));
        assert_eq!(got, ["198.51.100.7".parse::<Ipv4Addr>().unwrap(), "203.0.113.1".parse().unwrap()]);
    }

    #[test]
    fn peer_tier_candidates_keeps_a_well_formed_reflexive_addr() {
        let p = info_with(None, Some("203.0.113.5:55123"));
        assert_eq!(peer_tier_candidates(&[], &[], &p).reflexive, Some("203.0.113.5:55123"));
    }

    #[test]
    fn peer_tier_candidates_drops_a_malformed_reflexive_addr() {
        let p = info_with(None, Some("not-an-ip:port"));
        assert_eq!(peer_tier_candidates(&[], &[], &p).reflexive, None);
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
        let (tier, state) = resolve_endpoint_candidate(PeerTierCandidates::default(), None, None, false, false, now);
        assert_eq!(tier, EndpointTier::Wan);
        assert!(state.is_none());
    }

    #[test]
    fn first_cycle_on_a_matching_lan_optimistically_tries_lan() {
        let now = std::time::Instant::now();
        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, false, false, now);
        assert_eq!(tier, EndpointTier::Lan);
        assert!(state.is_some());
    }

    #[test]
    fn a_handshake_after_switching_confirms_the_tier_and_resets_its_backoff() {
        let now = std::time::Instant::now();
        let t0 = chrono::Utc::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(t0), None, false, false, now);
        // A genuinely newer handshake than the baseline taken at switch time.
        let newer = t0 + chrono::Duration::seconds(5);
        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(newer), state, false, false, now + std::time::Duration::from_secs(1));
        assert_eq!(tier, EndpointTier::Lan);
        assert_eq!(state.unwrap().per_tier[&EndpointTier::Lan].backoff, ENDPOINT_RETRY_BACKOFF_INITIAL);
    }

    #[test]
    fn a_confirmed_tier_stays_put_between_handshakes() {
        // WireGuard only handshakes every ~2 minutes on a live session, so
        // most polls see no newer one: that must not fail a confirmed tier.
        let now = std::time::Instant::now();
        let t0 = chrono::Utc::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, false, false, now);
        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(t0), state, false, false, now + GRACE / 2);
        assert_eq!(tier, EndpointTier::Lan);
        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(t0), state, false, false, now + GRACE * 2);
        assert_eq!(tier, EndpointTier::Lan);
        let (tier, _) = resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(t0), state, false, false, now + GRACE * 3);
        assert_eq!(tier, EndpointTier::Lan);
    }

    #[test]
    fn a_confirmed_tier_falls_back_once_its_handshakes_stop() {
        let now = std::time::Instant::now();
        let t0 = chrono::Utc::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, false, false, now);
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(t0), state, false, false, now + GRACE / 2);
        let confirmed_at = now + GRACE / 2;
        let (tier, state) =
            resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(t0), state, false, false, confirmed_at + ENDPOINT_CONFIRMED_MAX / 2);
        assert_eq!(tier, EndpointTier::Lan);
        let (tier, _) =
            resolve_endpoint_candidate(lan_only("192.168.1.50"), Some(t0), state, false, false, confirmed_at + ENDPOINT_CONFIRMED_MAX);
        assert_eq!(tier, EndpointTier::Wan);
    }

    #[test]
    fn a_confirmed_tier_is_given_up_as_soon_as_the_peer_falls_silent() {
        let now = std::time::Instant::now();
        let t0 = chrono::Utc::now();
        let (_, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), None, None, false, false, now);
        let (tier, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), Some(t0), state, false, false, now + GRACE / 2);
        assert_eq!(tier, EndpointTier::Reflexive);
        let (tier, _) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), Some(t0), state, false, true, now + GRACE);
        assert_eq!(tier, EndpointTier::Wan, "long before ENDPOINT_CONFIRMED_MAX");
    }

    #[test]
    fn a_transited_peer_keeps_dialling_its_only_candidate_without_backoff() {
        // Both sides of a hole-punch have to be sending at once; a backoff
        // on either would make that a matter of luck.
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), None, None, true, false, now);
        let (tier, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), None, state, true, false, now + GRACE);
        assert_eq!(tier, EndpointTier::Reflexive);
        let state = state.unwrap();
        assert_eq!(state.per_tier[&EndpointTier::Reflexive].next_retry_at, None);
        assert_eq!(state.switched_at, now + GRACE, "a fresh grace window, so a handshake still confirms it");
    }

    #[test]
    fn a_transited_peer_takes_turns_between_its_candidates() {
        let both = PeerTierCandidates { lan: Some("192.168.1.50"), reflexive: Some("203.0.113.5:40404") };
        let now = std::time::Instant::now();
        let (tier, state) = resolve_endpoint_candidate(both, None, None, true, false, now);
        assert_eq!(tier, EndpointTier::Lan);
        let (tier, state) = resolve_endpoint_candidate(both, None, state, true, false, now + GRACE);
        assert_eq!(tier, EndpointTier::Reflexive);
        let (tier, _) = resolve_endpoint_candidate(both, None, state, true, false, now + GRACE * 2);
        assert_eq!(tier, EndpointTier::Lan);
    }

    #[test]
    fn a_peer_becoming_transited_retries_a_backed_off_candidate_at_once() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), None, None, false, false, now);
        let (tier, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), None, state, false, false, now + GRACE);
        assert_eq!(tier, EndpointTier::Wan);
        let (tier, _) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), None, state, true, false, now + GRACE * 2);
        assert_eq!(tier, EndpointTier::Reflexive);
    }

    #[test]
    fn a_tier_confirmed_while_transited_is_kept_once_the_transit_ends() {
        // The hand-over: the punched path handshakes, the transit ends, and
        // the endpoint must not move off the address that just worked.
        let now = std::time::Instant::now();
        let t0 = chrono::Utc::now();
        let (_, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), None, None, true, false, now);
        let (tier, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), Some(t0), state, true, false, now + GRACE / 2);
        assert_eq!(tier, EndpointTier::Reflexive);
        let (tier, _) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:40404"), Some(t0), state, false, false, now + GRACE * 3);
        assert_eq!(tier, EndpointTier::Reflexive);
    }

    #[test]
    fn still_within_the_grace_window_stays_put_awaiting_a_handshake() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, false, false, now);
        let (tier, _) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, false, false, now + GRACE / 2);
        assert_eq!(tier, EndpointTier::Lan);
    }

    #[test]
    fn no_handshake_within_the_grace_window_falls_back_to_wan_and_schedules_a_retry() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, false, false, now);
        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, false, false, now + GRACE);
        assert_eq!(tier, EndpointTier::Wan);
        let state = state.unwrap();
        let lan = &state.per_tier[&EndpointTier::Lan];
        assert!(lan.next_retry_at.is_some());
        assert_eq!(lan.backoff, ENDPOINT_RETRY_BACKOFF_INITIAL * 2);
    }

    #[test]
    fn wan_retries_the_tier_once_the_backoff_elapses_not_before() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, false, false, now);
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, false, false, now + GRACE);
        // Not due yet.
        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, false, false, now + GRACE + std::time::Duration::from_secs(1));
        assert_eq!(tier, EndpointTier::Wan);
        // Due.
        let (tier, _) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, false, false, now + GRACE + ENDPOINT_RETRY_BACKOFF_INITIAL);
        assert_eq!(tier, EndpointTier::Lan);
    }

    #[test]
    fn backoff_doubles_up_to_the_cap_on_repeated_failures() {
        let now = std::time::Instant::now();
        let (_, mut state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, false, false, now);
        let mut t = now;
        let mut last_backoff = ENDPOINT_RETRY_BACKOFF_INITIAL;
        for _ in 0..10 {
            // Fail the grace window.
            t += GRACE;
            let (_, s) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, false, false, t);
            let s = s.unwrap();
            let lan = s.per_tier[&EndpointTier::Lan].clone();
            assert!(lan.backoff <= ENDPOINT_RETRY_BACKOFF_MAX);
            last_backoff = lan.backoff;
            // Retry once due, so the next iteration fails from Lan again.
            t = lan.next_retry_at.unwrap();
            let (_, s) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, Some(s), false, false, t);
            state = s;
        }
        assert_eq!(last_backoff, ENDPOINT_RETRY_BACKOFF_MAX, "must have capped by now");
    }

    #[test]
    fn a_peer_roaming_to_a_different_lan_address_resets_to_a_fresh_optimistic_attempt() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, None, false, false, now);
        // Fall back to Wan first, so the roam is a real behavior change,
        // not just staying on Lan by coincidence.
        let (_, state) = resolve_endpoint_candidate(lan_only("192.168.1.50"), None, state, false, false, now + GRACE);
        assert_eq!(state.as_ref().unwrap().current, EndpointTier::Wan);

        let (tier, state) = resolve_endpoint_candidate(lan_only("192.168.2.50"), None, state, false, false, now + GRACE + std::time::Duration::from_secs(1));
        assert_eq!(tier, EndpointTier::Lan, "a new address gets a fresh optimistic attempt");
        assert_eq!(state.unwrap().per_tier[&EndpointTier::Lan].backoff, ENDPOINT_RETRY_BACKOFF_INITIAL);
    }

    #[test]
    fn a_peer_roaming_to_a_different_reflexive_address_resets_to_a_fresh_optimistic_attempt() {
        let now = std::time::Instant::now();
        let (_, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:55123"), None, None, false, false, now);
        let (_, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:55123"), None, state, false, false, now + GRACE);
        assert_eq!(state.as_ref().unwrap().current, EndpointTier::Wan);

        let (tier, state) = resolve_endpoint_candidate(reflexive_only("203.0.113.5:60000"), None, state, false, false, now + GRACE + std::time::Duration::from_secs(1));
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
        let (tier, state) = resolve_endpoint_candidate(candidates, None, None, false, false, now);
        assert_eq!(tier, EndpointTier::Lan);

        // Lan never confirms within its own grace window.
        let (tier, state) = resolve_endpoint_candidate(candidates, None, state, false, false, now + GRACE);
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
        let (_, state) = resolve_endpoint_candidate(candidates, None, None, false, false, now);
        // Lan fails -> advances to Reflexive this same cycle.
        let (tier, state) = resolve_endpoint_candidate(candidates, None, state, false, false, now + GRACE);
        assert_eq!(tier, EndpointTier::Reflexive);
        // Reflexive, now active, also fails its own grace window.
        let (tier, state) = resolve_endpoint_candidate(candidates, None, state, false, false, now + GRACE + GRACE);
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
                rx_bytes: 0,
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

    /// The relay's exit path, end to end on two real interfaces. A relayed
    /// peer's probe entry (no `AllowedIPs`) still completes a direct
    /// handshake, which is what lets a pair leave the relay at all. And
    /// once the relay ends, moving the `AllowedIPs` back keeps the endpoint
    /// the kernel learned from that handshake rather than resetting it to
    /// the configured one, which here, as for a node with no port-forward,
    /// doesn't work.
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_a_relayed_peers_probe_handshakes_and_its_roamed_endpoint_survives_the_relay_ending() {
        if !crate::firewall::netns::reexec(
            "wg::tests::kernel_a_relayed_peers_probe_handshakes_and_its_roamed_endpoint_survives_the_relay_ending",
        ) {
            return;
        }
        let out = std::process::Command::new("ip").args(["link", "set", "lo", "up"]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let (a_key, b_key) = (clamp_private_key(&Key::generate()), clamp_private_key(&Key::generate()));
        let (a_pub, b_pub) = (a_key.public_key().to_string(), b_key.public_key().to_string());
        let mut a = WgInterface::new("wgtesta").unwrap();
        a.bring_up(&a_key.to_string(), "100.90.0.2".parse().unwrap(), "fd00:90::2".parse().unwrap(), 51820).unwrap();
        a.bring_up_carry(&a_key.to_string(), "100.90.0.2".parse().unwrap(), "fd00:90::2".parse().unwrap(), None).unwrap();
        let mut b = WgInterface::new("wgtestb").unwrap();
        b.bring_up(&b_key.to_string(), "100.90.0.3".parse().unwrap(), "fd00:90::3".parse().unwrap(), 51821).unwrap();
        b.bring_up_carry(&b_key.to_string(), "100.90.0.3".parse().unwrap(), "fd00:90::3".parse().unwrap(), None).unwrap();

        let mut a_info = peer("a", &a_pub);
        a_info.ip4 = "100.90.0.2".into();
        a_info.ip6 = "fd00:90::2".into();
        // Where B is told A is: nothing listens there.
        a_info.endpoint_addr = Some("127.0.0.1:51899".into());
        let mut b_info = peer("b", &b_pub);
        b_info.ip4 = "100.90.0.3".into();
        b_info.ip6 = "fd00:90::3".into();
        b_info.endpoint_addr = Some("127.0.0.1:51821".into());
        let peers = [a_info, b_info];

        // Both sides relayed by a carrier that isn't there.
        let nowhere = RelayRoute { carrier: "100.90.0.9".parse().unwrap(), port: 41009 };
        let a_relay: RelayAssignments<'_> = HashMap::from([(b_pub.as_str(), nowhere)]);
        let b_relay: RelayAssignments<'_> = HashMap::from([(a_pub.as_str(), nowhere)]);
        a.reconcile(&peers, &[], &a_pub, false, &HashMap::new(), &a_relay).unwrap();
        b.reconcile(&peers, &[], &b_pub, false, &HashMap::new(), &b_relay).unwrap();

        let handshaked = |ifname: &str| tunnel_peers(ifname).unwrap().iter().any(|t| t.last_handshake.is_some());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !(handshaked("wgtesta") && handshaked("wgtestb")) {
            assert!(std::time::Instant::now() < deadline, "no handshake over the probe entries");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let roamed = tunnel_peers("wgtestb").unwrap()[0].endpoint.clone();
        assert_eq!(roamed.as_deref(), Some("127.0.0.1:51820"), "B learns A's real address from the handshake");

        // The relay ends on B's side: A's addresses move back onto its own
        // entry, whose configured endpoint is unchanged (and wrong).
        b.reconcile(&peers, &[], &b_pub, false, &HashMap::new(), &HashMap::new()).unwrap();
        let after = tunnel_peers("wgtestb").unwrap();
        assert_eq!(after[0].endpoint.as_deref(), Some("127.0.0.1:51820"), "the roamed endpoint must survive");

        a.teardown().unwrap();
        b.teardown().unwrap();
    }

    /// The carry interface (PLAN.md M39) on a real kernel: it comes up with
    /// the port it is given and the carry MTU, a relayed peer's addresses
    /// and route move onto it — the route with the node's own address as
    /// its source, since the interface has none — and back again when the
    /// relay ends; teardown removes it with the mesh interface.
    #[cfg(target_os = "linux")]
    #[test]
    fn kernel_a_relayed_peer_moves_to_the_carry_interface_and_back() {
        if !crate::firewall::netns::reexec("wg::tests::kernel_a_relayed_peer_moves_to_the_carry_interface_and_back") {
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
        wg.bring_up(&own.to_string(), "100.90.0.1".parse().unwrap(), "fd00:90::1".parse().unwrap(), 51820).unwrap();
        let port = wg.bring_up_carry(&own.to_string(), "100.90.0.1".parse().unwrap(), "fd00:90::1".parse().unwrap(), Some(50123)).unwrap();
        assert_eq!(port, 50123);
        assert_eq!(wg.carry_port(), Some(50123));
        assert!(sh("ip -o link show wgtest").contains("mtu 1400"));
        assert!(sh("ip -o link show wgtest-t").contains("mtu 1340"));

        let (_, _, _, mut peers) = relay_directory();
        peers[0].pubkey = own_pub.clone();
        let relay = relay_assignments(&peers, &own_pub);
        wg.reconcile(&peers, &[], &own_pub, false, &HashMap::new(), &relay).unwrap();
        let routes = sh("ip -4 route show; ip -6 route show");
        assert!(routes.contains("100.90.0.3 dev wgtest-t scope link src 100.90.0.1"), "{routes}");
        assert!(routes.contains("fd00:90::3 dev wgtest-t"), "{routes}");
        assert!(!routes.contains("100.90.0.3 dev wgtest "), "{routes}");
        let carry = tunnel_peers("wgtest-t").unwrap();
        assert_eq!(carry.len(), 1);
        assert_eq!(carry[0].endpoint.as_deref(), Some("100.90.0.2:41002"));

        // The relay ends: back onto the mesh interface.
        wg.reconcile(&peers, &[], &own_pub, false, &HashMap::new(), &HashMap::new()).unwrap();
        let routes = sh("ip -4 route show");
        assert!(routes.contains("100.90.0.3 dev wgtest "), "{routes}");
        assert!(!routes.contains("wgtest-t"), "{routes}");
        assert!(tunnel_peers("wgtest-t").unwrap().is_empty());

        wg.teardown().unwrap();
        let links = sh("ip -o link show");
        assert!(!links.contains("wgtest"), "{links}");
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
