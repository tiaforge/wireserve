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
use wireserve_types::PeerInfo;

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
pub fn choose_peer_endpoint(p: &PeerInfo, prefer_ipv6: bool) -> Option<String> {
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

/// Builds the desired kernel peer set (keyed by pubkey) from a `/poll`
/// response's `peers` array, skipping this node's own entry (peers
/// includes self — PLAN.md decisions log #12) and any entry whose pubkey
/// doesn't parse (defensive: a malformed directory entry must not crash
/// reconciliation for every other peer). `prefer_ipv6` is this node's own
/// live self-test result — see `choose_peer_endpoint`. Stays fully
/// pure/network-free: the actual probe happens once per cycle in
/// `poll_loop::run_once`, outside this module.
pub fn desired_peers(peers: &[PeerInfo], self_pubkey: &str, prefer_ipv6: bool) -> HashMap<Key, Peer> {
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
        peer.allowed_ips = peer_allowed_ips(&p.ip4, &p.ip6);
        if let Some(endpoint) = choose_peer_endpoint(p, prefer_ipv6) {
            if let Err(e) = peer.set_endpoint(&endpoint) {
                tracing::warn!(peer = %p.name, error = %e, "could not resolve peer endpoint");
            }
        }
        // This node likely roams networks (dynamic DNS, NAT rebinding) —
        // same reasoning as spec §9's export-config PersistentKeepalive.
        peer.persistent_keepalive_interval = Some(25);
        desired.insert(key, peer);
    }
    desired
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
}

impl WgInterface {
    pub fn new(ifname: impl Into<String>) -> Result<Self, WireguardInterfaceError> {
        let ifname = ifname.into();
        let api = WGApi::<Kernel>::new(ifname.clone())?;
        Ok(Self {
            api,
            ifname,
            applied: HashMap::new(),
        })
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
        self_pubkey: &str,
        prefer_ipv6: bool,
    ) -> Result<(), WireguardInterfaceError> {
        let desired = desired_peers(peers, self_pubkey, prefer_ipv6);

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
        // Only run when the peer set actually changed, to keep it off the
        // steady-state path.
        if !to_remove.is_empty() || !to_configure.is_empty() {
            let addresses = |peers: &HashMap<Key, Peer>| -> BTreeSet<IpAddr> {
                peers.values().flat_map(|p| &p.allowed_ips).map(|a| a.address).collect()
            };
            // A route that couldn't be set is logged (by `sync`) and retried
            // on the next change, not fatal: failing here would leave
            // `applied` stale and reconfigure every peer next cycle, which
            // resets WireGuard's own endpoint roaming (see above).
            if let Err(e) = crate::routes::sync(&self.ifname, &addresses(&self.applied), &addresses(&desired)) {
                tracing::warn!(ifname = %self.ifname, error = %e, "peer routes are incomplete");
            }
        }

        self.applied = desired;
        Ok(())
    }

    pub fn teardown(&mut self) -> Result<(), WireguardInterfaceError> {
        self.api.remove_interface()
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
            last_handshake: None,
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
        let desired = desired_peers(&peers, &self_key, false);
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
        let desired = desired_peers(&peers, &self_key, false);
        assert_eq!(desired.len(), 1);
    }

    #[test]
    fn choose_peer_endpoint_prefers_v4_by_default() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, false),
            Some("203.0.113.5:51820".into())
        );
    }

    #[test]
    fn choose_peer_endpoint_prefers_v6_only_when_asked_and_both_exist() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, true),
            Some("[2001:db8::1]:51820".into())
        );
    }

    #[test]
    fn choose_peer_endpoint_falls_back_to_whichever_single_candidate_exists() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, false),
            Some("[2001:db8::1]:51820".into()),
            "no v4 candidate at all — v6 is used even though prefer_ipv6 is false"
        );
        assert_eq!(choose_peer_endpoint(&p, true), Some("[2001:db8::1]:51820".into()));
    }

    #[test]
    fn choose_peer_endpoint_explicit_override_always_wins() {
        let mut p = peer("n1", &key_b64(2));
        p.endpoint_addr = Some("explicit.example.com:51820".into());
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        assert_eq!(
            choose_peer_endpoint(&p, false),
            Some("explicit.example.com:51820".into())
        );
        assert_eq!(
            choose_peer_endpoint(&p, true),
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
            choose_peer_endpoint(&p, false),
            Some("203.0.113.5:51820".into()),
            "an IPv6-only explicit value is useless to a node with no working v6"
        );
        assert_eq!(
            choose_peer_endpoint(&p, true),
            Some("[2001:db8::1]:51820".into()),
            "a node with real v6 can still use it"
        );
    }

    #[test]
    fn desired_peers_wires_prefer_ipv6_through_to_the_configured_endpoint() {
        let self_key = key_b64(1);
        let mut other = peer("other", &key_b64(2));
        other.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        other.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());

        let desired_v4 = desired_peers(&[other.clone()], &self_key, false);
        let key = defguard_wireguard_rs::key::Key::try_from(key_b64(2).as_str()).unwrap();
        assert_eq!(
            desired_v4[&key].endpoint,
            Some("203.0.113.5:51820".parse().unwrap())
        );

        let desired_v6 = desired_peers(&[other], &self_key, true);
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
        wg.reconcile(std::slice::from_ref(&p), &own.public_key().to_string(), false).unwrap();

        let routes = sh("ip -4 route show table all; ip -6 route show table all");
        assert!(!routes.contains("blackhole"), "{routes}");
        assert!(!routes.contains("10.99.0.1"), "no route to the endpoint at all: {routes}");
        assert!(routes.contains("100.90.0.5 dev wgtest"), "{routes}");
        assert!(routes.contains("fd00:90::5 dev wgtest"), "{routes}");

        wg.reconcile(&[], &own.public_key().to_string(), false).unwrap();
        let routes = sh("ip -4 route show table all; ip -6 route show table all");
        assert!(!routes.contains("100.90.0.5") && !routes.contains("fd00:90::5"), "departed peer's route removed: {routes}");
        wg.teardown().unwrap();
    }
}
