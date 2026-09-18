//! Wraps `defguard_wireguard_rs`'s `WGApi<Kernel>` for the agent's own
//! interface: bring-up with this node's own keypair/addresses, and
//! reconciling the kernel peer set against each poll's `peers` array.

use std::collections::HashMap;
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
         with `--ifname <name>` pointing at an unused name, or remove the existing \
         interface first if it really is disposable"
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

/// Builds the desired kernel peer set (keyed by pubkey) from a `/poll`
/// response's `peers` array, skipping this node's own entry (peers
/// includes self — PLAN.md decisions log #12) and any entry whose pubkey
/// doesn't parse (defensive: a malformed directory entry must not crash
/// reconciliation for every other peer).
pub fn desired_peers(peers: &[PeerInfo], self_pubkey: &str) -> HashMap<Key, Peer> {
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
        if let Some(endpoint) = &p.endpoint_addr {
            if let Err(e) = peer.set_endpoint(endpoint) {
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
    /// host, WireGuard or otherwise. Read straight from sysfs rather than
    /// inferred from a netlink error, because the distinction that
    /// matters here ("something already owns this name") is not one the
    /// WireGuard API reports cleanly: `create_interface` deliberately
    /// treats `EEXIST` as success so that restarts are idempotent.
    fn interface_exists(ifname: &str) -> bool {
        std::path::Path::new("/sys/class/net").join(ifname).exists()
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
        if Self::interface_exists(&self.ifname) {
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
                    let matches = match (&host.private_key, &ours) {
                        (Some(existing), Some(ours)) => existing == ours,
                        _ => false,
                    };
                    if !matches {
                        return Err(BringUpError::InterfaceConflict {
                            ifname: self.ifname.clone(),
                            reason: "it is a WireGuard interface configured with a different \
                                     private key, so it belongs to another tunnel"
                                .to_string(),
                        });
                    }
                    tracing::info!(
                        ifname = %self.ifname,
                        "reusing this agent's own existing WireGuard interface"
                    );
                }
                Err(err) => {
                    return Err(BringUpError::InterfaceConflict {
                        ifname: self.ifname.clone(),
                        reason: format!(
                            "an interface with that name exists but its WireGuard \
                             configuration could not be read ({err})"
                        ),
                    });
                }
            }
        }

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
    ) -> Result<(), WireguardInterfaceError> {
        let desired = desired_peers(peers, self_pubkey);

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
        // nothing ever sends a packet to `wg0` in the first place. The
        // interface's own address is assigned as a `/32` (plus a `/128`),
        // which creates a local route for this node alone and no route at
        // all towards the other members of the mesh — so `plex.wg`
        // resolving to a peer's address would still fail to connect, and
        // on a host running an overlay that claims the surrounding range
        // (Tailscale and `100.64.0.0/10`, say) the packet would be handed
        // to *that* interface instead. `wg-quick` does this same step from
        // `AllowedIPs` and it has to happen here too.
        //
        // Only run when the peer set actually changed, to keep it off the
        // steady-state path: every peer's `AllowedIPs` here is its own
        // `/32` + `/128`, never a default route, so this adds exactly one
        // host route per peer and never touches the default route or the
        // policy-routing rules that `configure_peer_routing` would set up
        // for a `0.0.0.0/0` peer.
        if !to_remove.is_empty() || !to_configure.is_empty() {
            let all: Vec<Peer> = desired.values().cloned().collect();
            self.api.configure_peer_routing(&all)?;
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
        let desired = desired_peers(&peers, &self_key);
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
        let desired = desired_peers(&peers, &self_key);
        assert_eq!(desired.len(), 1);
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
}
