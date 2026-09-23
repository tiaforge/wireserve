//! `wireserve-admin export-config <name>` (spec §9): generates a WireGuard
//! keypair locally, creates and immediately redeems a `kind: "static"` node
//! in one CLI call, and renders a `.conf` for import into an official
//! WireGuard client.

use defguard_wireguard_rs::key::Key;
use wireserve_types::{AdminServiceInfo, NodeKind, PeerInfo, RegisterRequest, ServiceApprovalState};

use crate::client::{self, AdminClient, ClientError};

#[derive(Debug, thiserror::Error)]
pub enum ExportConfigError {
    #[error(transparent)]
    Client(#[from] ClientError),
    /// `--refresh` aimed at a name the coordinator does not know. Deliberately
    /// not an auto-create: a typo would otherwise silently mint a new node.
    #[error("no such node '{name}' — run export-config without --refresh to create it ({message})")]
    NoSuchNode { name: String, message: String },
    #[error("no such node '{name}' to use as a gateway")]
    NoSuchGateway { name: String },
    #[error(
        "'{name}' is not approved to carry traffic — run `wireserve-admin approve-transit {name}` \
         (and `wireserve-agent transit on` on that node) first"
    )]
    GatewayNotApproved { name: String },
    #[error(
        "'{name}' is approved but is not currently offering to carry traffic — run \
         `wireserve-agent transit on` on it (and restart it, so it reopens the host \
         firewall's forward hook), then try again"
    )]
    GatewayNotOffering { name: String },
    #[error(
        "'{name}' has no publicly reachable endpoint, so a device off the mesh could never dial \
         it. Give it a reachable --endpoint-addr, or pick another gateway."
    )]
    GatewayNotReachable { name: String },
    #[error(
        "several nodes could be the gateway ({names}) — name one with --gateway, since the \
         choice is baked into the config and cannot be changed without re-exporting"
    )]
    AmbiguousGateway { names: String },
}

/// This node's own interface parameters for rendering: the private key
/// generated in step 1, its allocated addresses, and its own public key
/// (used only to skip a self-entry in the peer list — never sent anywhere).
pub struct InterfaceParams {
    pub private_key: String,
    pub ip4: String,
    pub ip6: String,
    pub own_pubkey: String,
}

/// Renders a full WireGuard `.conf`: this node's own `[Interface]` block,
/// then one `[Peer]` block per entry in `peers`, skipping any peer whose
/// pubkey matches this node's own (defensive — whether `/admin/peers`
/// already includes the just-registered node depends on timing, and either
/// way it must never get a `[Peer]` block pointing at itself).
///
/// Every peer's `AllowedIPs` is that peer's own `/32` (v4) + `/128` (v6),
/// plus the `/32` of every approved service it owns (`services`, PLAN.md
/// M20 — the same rule the agent applies), never a shared mesh CIDR block — spec §9 is explicit about why: a wider
/// block would make this device act as a router for other peers' traffic,
/// and WireGuard requires non-overlapping `AllowedIPs` across peers on one
/// interface regardless.
///
/// Defense in depth (security review S2): the coordinator now validates
/// `pubkey`/`endpoint_addr` strictly at `/register` and `/poll` (rejecting
/// anything containing control characters, among other checks), so a
/// value reaching this function *should* already be safe — but this
/// renderer refuses to emit any peer whose `pubkey` or `endpoint_addr`
/// contains a newline regardless, rather than trusting the coordinator's
/// validation as the only line of defense against a value that would
/// otherwise let one field smuggle an entire extra `.conf` directive
/// (e.g. an `endpoint_addr` of `"1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0"`
/// hijacking this exported device's routing).
/// What a render produced: the file itself, plus the peers that got a direct
/// `[Peer]` block.
///
/// The caller records that list against the node. `/poll` must set
/// `transit_via` for exactly the peers *absent* from it, and the only way to
/// know which those are later is to have been told at export time — the conf
/// is a snapshot, so its membership is a fact about a moment, not something
/// re-derivable from live state.
pub struct RenderedConf {
    pub text: String,
    pub direct_peers: Vec<String>,
}

/// The gateway a rendered config routes through.
pub struct Gateway<'a> {
    pub peer: &'a PeerInfo,
    pub ranges: wireserve_types::MeshRanges,
}

#[must_use]
pub fn render_conf(
    iface: &InterfaceParams,
    peers: &[PeerInfo],
    services: &[AdminServiceInfo],
    gateway: Option<&Gateway<'_>>,
) -> RenderedConf {
    let mut out = String::new();
    let mut direct_peers = Vec::new();
    out.push_str("[Interface]\n");
    out.push_str(&format!("PrivateKey = {}\n", iface.private_key));
    out.push_str(&format!("Address = {}/32, {}/128\n", iface.ip4, iface.ip6));

    for peer in peers {
        if peer.pubkey == iface.own_pubkey {
            continue;
        }
        // The gateway is rendered once, below, with the whole mesh range. It
        // necessarily has a routable endpoint, so it would otherwise also
        // qualify as a direct peer here and be emitted twice under one
        // `PublicKey` — which `wg setconf` resolves silently last-wins, but
        // the iOS and Android apps reject outright.
        if gateway.is_some_and(|g| g.peer.pubkey == peer.pubkey) {
            continue;
        }
        let endpoint = choose_endpoint(peer);
        // Checked before anything else about this peer, and on the pubkey
        // whether or not there is an endpoint: a peer with no endpoint is
        // still rendered below when there is no gateway, so deferring this
        // until after the endpoint is known would let a pubkey carrying
        // `\nAllowedIPs = 0.0.0.0/0` through on exactly that path.
        if contains_newline(&peer.pubkey) || endpoint.as_deref().is_some_and(contains_newline) {
            warn_skipped(&peer.name);
            continue;
        }
        match (&endpoint, gateway) {
            // With a gateway in play, a direct entry is only worth having when
            // the device can actually dial it from anywhere. An endpoint on a
            // private address is the trap: `is_valid_endpoint_addr` permits
            // RFC1918 on purpose, and a node on a home LAN legitimately
            // advertises one, so a naive "has an endpoint" test would mint a
            // /32 that outranks the gateway's covering route and black-holes
            // the moment the device leaves that LAN.
            (Some(e), Some(_)) if !wireserve_types::is_globally_routable_endpoint(e) => continue,
            // No endpoint and a gateway: reached through the gateway instead.
            (None, Some(_)) => continue,
            _ => {}
        }
        render_peer(&mut out, peer, services, endpoint.as_deref());
        direct_peers.push(peer.name.clone());
    }

    if let Some(gateway) = gateway {
        // Everything not listed above is reached through here. The mesh range
        // is a shorter prefix than any peer's /32, so cryptokey routing sends
        // only what has no direct entry this way — and service VIPs are
        // allocated out of the same v4 range, so they are covered without
        // being enumerated.
        let endpoint = choose_endpoint(gateway.peer);
        if contains_newline(&gateway.peer.pubkey) || endpoint.as_deref().is_some_and(contains_newline) {
            warn_skipped(&gateway.peer.name);
        } else {
            out.push('\n');
            out.push_str("[Peer]\n");
            out.push_str(&format!("PublicKey = {}\n", gateway.peer.pubkey));
            out.push_str(&format!(
                "AllowedIPs = {}, {}\n",
                gateway.ranges.v4_cidr(),
                gateway.ranges.v6_prefix()
            ));
            if let Some(endpoint) = &endpoint {
                out.push_str(&format!("Endpoint = {endpoint}\n"));
            }
            out.push_str("PersistentKeepalive = 25\n");
        }
    }

    RenderedConf { text: out, direct_peers }
}

/// One ordinary `[Peer]` block, with the peer's own host prefixes and the
/// addresses of the services it owns.
fn render_peer(
    out: &mut String,
    peer: &PeerInfo,
    services: &[AdminServiceInfo],
    endpoint: Option<&str>,
) {
    out.push('\n');
    out.push_str("[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", peer.pubkey));
    // Parsed, not copied — the same rule `service_addresses` already follows.
    // Interpolating these straight from the directory is what would let a
    // field smuggle an extra `.conf` directive into the file.
    let mut allowed = String::new();
    if let Ok(v4) = peer.ip4.parse::<std::net::Ipv4Addr>() {
        allowed.push_str(&format!("{v4}/32"));
    }
    if let Ok(v6) = peer.ip6.parse::<std::net::Ipv6Addr>() {
        if !allowed.is_empty() {
            allowed.push_str(", ");
        }
        allowed.push_str(&format!("{v6}/128"));
    }
    for vip in service_addresses(services, &peer.name) {
        allowed.push_str(&format!(", {vip}/32"));
    }
    out.push_str(&format!("AllowedIPs = {allowed}\n"));
    if let Some(endpoint) = endpoint {
        out.push_str(&format!("Endpoint = {endpoint}\n"));
    }
    // This device likely roams networks (wifi/cellular switching, laptop
    // suspend) — keep the NAT mapping alive so return traffic works.
    out.push_str("PersistentKeepalive = 25\n");
}

/// The single address to write on this peer's `Endpoint =` line.
///
/// A `.conf` holds exactly one and it can never be refreshed, so the choice
/// has to survive whatever network the device is on. An explicit
/// `endpoint_addr` wins, as it always has — except when it is a bracketed v6
/// literal and a v4 candidate exists, because `endpoint_addr` is recorded
/// family-blind from whichever family the node's poll happened to arrive
/// over, and a device on v4-only cellular could never dial a v6 address.
/// `wg::choose_peer_endpoint` already makes exactly this check on the agent
/// side; this is the same rule for the one place that cannot re-decide later.
fn choose_endpoint(peer: &PeerInfo) -> Option<String> {
    if let Some(explicit) = &peer.endpoint_addr {
        if !explicit.starts_with('[') || peer.endpoint_addr_v4.is_none() {
            return Some(explicit.clone());
        }
    }
    peer.endpoint_addr_v4.clone().or_else(|| peer.endpoint_addr_v6.clone())
}

fn warn_skipped(name: &str) {
    eprintln!(
        "warning: skipping peer '{name}' — its pubkey or endpoint_addr contains a newline, \
         which could otherwise inject extra .conf directives; this indicates either a \
         coordinator bug or a compromised/malicious node and should be investigated"
    );
}

/// The addresses of `node`'s approved services. Parsed, not copied: like
/// the pubkey and endpoint above, nothing but a literal address may reach
/// the `.conf`.
fn service_addresses<'a>(services: &'a [AdminServiceInfo], node: &'a str) -> impl Iterator<Item = std::net::Ipv4Addr> + 'a {
    services
        .iter()
        .filter(move |s| s.node == node && s.state == ServiceApprovalState::Approved)
        .filter_map(|s| s.vip4.as_deref()?.parse().ok())
}

fn contains_newline(s: &str) -> bool {
    s.contains('\n') || s.contains('\r')
}

/// Picks the node a device should route through, from the current directory.
///
/// Gateway forwarding *is* transit forwarding — the carrier sees the traffic
/// in the clear — so eligibility is the existing transit approval rather than
/// a second flag of its own. On top of that the node must be dialable from
/// wherever the device ends up, which a phone's single unrefreshable
/// `Endpoint =` line makes non-negotiable.
fn select_gateway<'a>(
    peers: &'a [PeerInfo],
    transit_approved: &[String],
    transit_offering: &[String],
    requested: Option<&str>,
) -> Result<Option<&'a PeerInfo>, ExportConfigError> {
    let eligible = |p: &PeerInfo| {
        transit_approved.iter().any(|n| n == &p.name)
            && transit_offering.iter().any(|n| n == &p.name)
            && choose_endpoint(p).is_some_and(|e| wireserve_types::is_globally_routable_endpoint(&e))
    };

    if let Some(name) = requested {
        let peer = peers
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| ExportConfigError::NoSuchGateway { name: name.to_string() })?;
        // Checked here, before the caller creates or rejoins anything: the
        // coordinator enforces all three again when the assignment is
        // recorded, but that happens at the very end of the export, and
        // failing there would leave a node created with no config to show
        // for it.
        if !transit_approved.iter().any(|n| n == name) {
            return Err(ExportConfigError::GatewayNotApproved { name: name.to_string() });
        }
        if !transit_offering.iter().any(|n| n == name) {
            return Err(ExportConfigError::GatewayNotOffering { name: name.to_string() });
        }
        if !eligible(peer) {
            return Err(ExportConfigError::GatewayNotReachable { name: name.to_string() });
        }
        return Ok(Some(peer));
    }

    let mut candidates = peers.iter().filter(|p| eligible(p));
    let first = candidates.next();
    if let (Some(a), Some(b)) = (first, candidates.next()) {
        return Err(ExportConfigError::AmbiguousGateway {
            names: std::iter::once(a.name.clone())
                .chain(std::iter::once(b.name.clone()))
                .chain(peers.iter().filter(|p| eligible(p)).skip(2).map(|p| p.name.clone()))
                .collect::<Vec<_>>()
                .join(", "),
        });
    }
    Ok(first)
}

/// Runs the full `export-config` flow end to end against a live
/// coordinator: keygen (local only), create+redeem a `kind: "static"` node,
/// fetch the peer directory, render the `.conf`.
///
/// Takes two base URLs, not one: `admin_client` talks to the coordinator's
/// admin listener (`create_node`, `list_peers`), while `node_facing_url`
/// is where `/register` actually lives — a separate listener by spec
/// §4.0's design, not just a separate path on the same one.
pub fn run(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
    gateway: Option<&str>,
) -> Result<String, ExportConfigError> {
    let directory = admin_client.list_peers()?;
    let chosen = select_gateway(
        &directory.peers,
        &directory.transit_approved,
        &directory.transit_offering,
        gateway,
    )?;
    let created = admin_client.create_node(name, NodeKind::Static, None)?;
    finish(admin_client, node_facing_url, name, &created.join_token, &directory, chosen)
}

/// Re-issues a `.conf` for a static peer that already exists (PLAN.md M24),
/// keeping its name and — because `reissue_join_token` leaves `ip4`/`ip6`
/// alone and `/register` reuses a node's existing addresses — its mesh
/// address. Only the keypair changes.
///
/// **Destructive from its first mutating call.** `rejoin` nulls the node's
/// pubkey, which drops it out of `/admin/peers` and so off every other
/// node's directory on their next poll; `/register` puts it back. A failure
/// in between leaves the node alive but unregistered, recoverable by running
/// the same command again — not a name-burning failure. The `kind`
/// expectation is checked by the coordinator *before* it mutates anything,
/// so pointing this at an agent node by mistake is refused outright rather
/// than kicking a live node off the mesh.
///
/// Everything that can fail on the way in — the directory fetch and the
/// gateway choice — happens ahead of the rejoin for the same reason.
pub fn run_refresh(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
    gateway: Option<&str>,
) -> Result<String, ExportConfigError> {
    let directory = admin_client.list_peers()?;
    let chosen = select_gateway(
        &directory.peers,
        &directory.transit_approved,
        &directory.transit_offering,
        gateway,
    )?;
    let rejoined = match admin_client.rejoin(name, None, Some(NodeKind::Static)) {
        Ok(r) => r,
        Err(ClientError::Api { status, message }) if status == reqwest::StatusCode::NOT_FOUND => {
            return Err(ExportConfigError::NoSuchNode {
                name: name.to_string(),
                message,
            });
        }
        Err(e) => return Err(e.into()),
    };
    finish(admin_client, node_facing_url, name, &rejoined.join_token, &directory, chosen)
}

/// The half both paths share, after the token exists: generate a keypair
/// locally, redeem it, render, and record how the config was shaped.
fn finish(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
    join_token: &str,
    directory: &wireserve_types::AdminPeersResponse,
    gateway: Option<&PeerInfo>,
) -> Result<String, ExportConfigError> {
    let private_key = Key::generate();
    let public_key = private_key.public_key();

    let reg = client::register(
        node_facing_url,
        &RegisterRequest {
            join_token: join_token.to_string(),
            pubkey: public_key.to_string(),
            kind: NodeKind::Static,
            listen_port: None,
            endpoint_addr: None,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            transit_capable: false,
        },
    )?;

    let services = admin_client.list_services()?;

    // The mesh range comes back from `/register`, which already carries it so
    // an agent can pin it — no new wire field needed. Without it there is
    // nothing to point the gateway peer's `AllowedIPs` at, so the export
    // falls back to all-direct rather than rendering a config that silently
    // reaches only what it lists.
    let ranges = reg.mesh.as_ref().and_then(wireserve_types::MeshRanges::parse);
    let gateway = match (gateway, ranges) {
        (Some(peer), Some(ranges)) => Some(Gateway { peer, ranges }),
        (Some(peer), None) => {
            eprintln!(
                "warning: the coordinator did not report a usable mesh range, so '{}' cannot be \
                 used as a gateway; writing an all-direct config that will need re-exporting \
                 whenever the mesh changes",
                peer.name
            );
            None
        }
        (None, _) => None,
    };

    let iface = InterfaceParams {
        private_key: private_key.to_string(),
        ip4: reg.ip4,
        ip6: reg.ip6,
        own_pubkey: public_key.to_string(),
    };

    let rendered = render_conf(&iface, &directory.peers, &services.services, gateway.as_ref());

    // Recorded, not recomputed: `/poll` sets `transit_via` for exactly the
    // peers absent from this list, and it has to match the file that is about
    // to be written rather than whatever the directory looks like later.
    admin_client.set_gateway(
        name,
        gateway.as_ref().map(|g| g.peer.name.as_str()),
        &rendered.direct_peers,
    )?;

    Ok(rendered.text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-gateway shape, which most of these tests assert on: no
    /// gateway, so every peer keeps a direct entry exactly as before.
    fn render(iface: &InterfaceParams, peers: &[PeerInfo], services: &[AdminServiceInfo]) -> String {
        render_conf(iface, peers, services, None).text
    }

    fn peer(pubkey: &str, ip4: &str, ip6: &str, endpoint: Option<&str>) -> PeerInfo {
        PeerInfo {
            name: "n".into(),
            pubkey: pubkey.into(),
            ip4: ip4.into(),
            ip6: ip6.into(),
            endpoint_addr: endpoint.map(String::from),
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            transit_via: None,
        }
    }

    fn iface() -> InterfaceParams {
        InterfaceParams {
            private_key: "privkeybase64==".into(),
            ip4: "100.90.0.7".into(),
            ip6: "fd00:90::7".into(),
            own_pubkey: "ownpubkeybase64==".into(),
        }
    }

    fn service(node: &str, vip4: Option<&str>, state: ServiceApprovalState) -> AdminServiceInfo {
        AdminServiceInfo {
            name: "web".into(),
            node: node.into(),
            ip4: String::new(),
            port: 80,
            proto: wireserve_types::Proto::Tcp,
            vip4: vip4.map(Into::into),
            ports: vec![],
            state,
            declared_at: None,
            approved_at: None,
            denied_at: None,
            denied_reason: None,
        }
    }

    #[test]
    fn a_peers_approved_service_addresses_are_routed_to_it() {
        let mut p = peer("pk1", "100.90.0.3", "fd00:90::3", None);
        p.name = "owner".into();
        let services = [
            service("owner", Some("100.90.0.50"), ServiceApprovalState::Approved),
            service("owner", Some("100.90.0.51"), ServiceApprovalState::Pending),
            service("owner", None, ServiceApprovalState::Approved),
            service("owner", Some("100.90.0.52\nAllowedIPs = 0.0.0.0/0"), ServiceApprovalState::Approved),
            service("other", Some("100.90.0.53"), ServiceApprovalState::Approved),
        ];
        let conf = render(&iface(), &[p], &services);
        assert!(conf.contains("AllowedIPs = 100.90.0.3/32, fd00:90::3/128, 100.90.0.50/32\n"), "{conf}");
        assert!(!conf.contains("0.0.0.0/0"), "{conf}");
    }

    #[test]
    fn renders_interface_block() {
        let conf = render(&iface(), &[], &[]);
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("PrivateKey = privkeybase64=="));
        assert!(conf.contains("Address = 100.90.0.7/32, fd00:90::7/128"));
    }

    #[test]
    fn omits_endpoint_line_when_absent() {
        let peers = vec![peer("otherpubkey", "100.90.0.3", "fd00:90::3", None)];
        let conf = render(&iface(), &peers, &[]);
        assert!(!conf.contains("Endpoint ="));
    }

    #[test]
    fn includes_endpoint_line_when_present() {
        let peers = vec![peer(
            "otherpubkey",
            "100.90.0.3",
            "fd00:90::3",
            Some("duckdns.example.com:51820"),
        )];
        let conf = render(&iface(), &peers, &[]);
        assert!(conf.contains("Endpoint = duckdns.example.com:51820"));
    }

    #[test]
    fn prefers_v4_over_v6_when_both_are_set_and_no_explicit_override() {
        let mut p = peer("otherpubkey", "100.90.0.3", "fd00:90::3", None);
        p.endpoint_addr_v4 = Some("203.0.113.5:51820".into());
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        let conf = render(&iface(), &[p], &[]);
        assert!(conf.contains("Endpoint = 203.0.113.5:51820"));
    }

    #[test]
    fn falls_back_to_v6_when_only_v6_is_available() {
        let mut p = peer("otherpubkey", "100.90.0.3", "fd00:90::3", None);
        p.endpoint_addr_v6 = Some("[2001:db8::1]:51820".into());
        let conf = render(&iface(), &[p], &[]);
        assert!(conf.contains("Endpoint = [2001:db8::1]:51820"));
    }

    #[test]
    fn every_peer_gets_own_32_and_128_never_a_wider_block() {
        let peers = vec![
            peer("p1", "100.90.0.3", "fd00:90::3", None),
            peer("p2", "100.90.0.4", "fd00:90::4", None),
        ];
        let conf = render(&iface(), &peers, &[]);
        assert!(conf.contains("AllowedIPs = 100.90.0.3/32, fd00:90::3/128"));
        assert!(conf.contains("AllowedIPs = 100.90.0.4/32, fd00:90::4/128"));
        assert!(!conf.contains("/24"));
        assert!(!conf.contains("/64"));
        assert!(!conf.contains("/0"));
    }

    #[test]
    fn multiple_peers_each_get_their_own_peer_block() {
        let peers = vec![
            peer("p1", "100.90.0.3", "fd00:90::3", None),
            peer("p2", "100.90.0.4", "fd00:90::4", None),
        ];
        let conf = render(&iface(), &peers, &[]);
        assert_eq!(conf.matches("[Peer]").count(), 2);
    }

    #[test]
    fn self_is_excluded_from_peer_list() {
        let i = iface();
        let peers = vec![
            peer(&i.own_pubkey, "100.90.0.7", "fd00:90::7", None),
            peer("someone-else", "100.90.0.3", "fd00:90::3", None),
        ];
        let conf = render(&i, &peers, &[]);
        assert_eq!(conf.matches("[Peer]").count(), 1);
        assert!(conf.contains("someone-else"));
    }

    // ---- S2 defense-in-depth: renderer refuses newline-smuggling peers ----

    #[test]
    fn skips_peer_with_newline_in_endpoint_addr_instead_of_rendering_it() {
        let peers = vec![peer(
            "otherpubkey",
            "100.90.0.3",
            "fd00:90::3",
            Some("1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0"),
        )];
        let conf = render(&iface(), &peers, &[]);
        assert!(
            !conf.contains("[Peer]"),
            "a peer carrying a config-injection payload must be skipped entirely, not rendered"
        );
        assert!(!conf.contains("0.0.0.0/0"));
    }

    #[test]
    fn skips_peer_with_newline_in_pubkey_instead_of_rendering_it() {
        let peers = vec![peer(
            "legit-looking-key\nEndpoint = evil.example:1",
            "100.90.0.3",
            "fd00:90::3",
            None,
        )];
        let conf = render(&iface(), &peers, &[]);
        assert!(!conf.contains("[Peer]"));
        assert!(!conf.contains("evil.example"));
    }

    #[test]
    fn other_valid_peers_are_unaffected_by_a_skipped_one() {
        let peers = vec![
            peer("good1", "100.90.0.3", "fd00:90::3", None),
            peer(
                "bad\nEndpoint = evil.example:1",
                "100.90.0.4",
                "fd00:90::4",
                None,
            ),
            peer("good2", "100.90.0.5", "fd00:90::5", None),
        ];
        let conf = render(&iface(), &peers, &[]);
        assert_eq!(conf.matches("[Peer]").count(), 2);
        assert!(conf.contains("good1"));
        assert!(conf.contains("good2"));
        assert!(!conf.contains("evil.example"));
    }

    #[test]
    fn generated_private_key_never_appears_in_register_request() {
        let private_key = Key::generate();
        let public_key = private_key.public_key();
        let req = RegisterRequest {
            join_token: "jtk_x".into(),
            pubkey: public_key.to_string(),
            kind: NodeKind::Static,
            listen_port: None,
            endpoint_addr: None,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            transit_capable: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains(&private_key.to_string()));
        assert!(json.contains(&public_key.to_string()));
    }
}

#[cfg(test)]
mod gateway_tests {
    use super::*;
    use wireserve_types::{MeshInfo, MeshRanges};

    fn ranges() -> MeshRanges {
        MeshRanges::parse(&MeshInfo {
            net_v4_cidr: "10.90.0.0/24".into(),
            net_v6_prefix: "fdb4:d481:7c21::/64".into(),
        })
        .unwrap()
    }

    fn iface() -> InterfaceParams {
        InterfaceParams {
            private_key: "privkeybase64==".into(),
            ip4: "10.90.0.7".into(),
            ip6: "fdb4:d481:7c21::7".into(),
            own_pubkey: "ownpubkeybase64==".into(),
        }
    }

    fn peer(name: &str, host: u8, endpoint: Option<&str>) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: format!("pk-{name}"),
            ip4: format!("10.90.0.{host}"),
            ip6: format!("fdb4:d481:7c21::{host}"),
            endpoint_addr: endpoint.map(Into::into),
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            transit_via: None,
        }
    }

    #[test]
    fn the_gateway_carries_the_mesh_range_and_is_rendered_exactly_once() {
        let gw = peer("vps", 2, Some("vps.example.com:51820"));
        let out = render_conf(
            &iface(),
            std::slice::from_ref(&gw),
            &[],
            Some(&Gateway { peer: &gw, ranges: ranges() }),
        );
        assert_eq!(
            out.text.matches("[Peer]").count(),
            1,
            "a gateway also qualifies as a direct peer, and two blocks under one PublicKey \
             are rejected outright by the iOS and Android apps:\n{}",
            out.text
        );
        assert!(
            out.text.contains("AllowedIPs = 10.90.0.0/24, fdb4:d481:7c21::/64\n"),
            "{}",
            out.text
        );
        assert!(out.text.contains("Endpoint = vps.example.com:51820"));
        assert!(
            !out.direct_peers.contains(&"vps".to_string()),
            "the gateway is not a direct peer — /poll must still route others through it"
        );
    }

    #[test]
    fn only_peers_reachable_from_anywhere_keep_a_direct_entry() {
        let gw = peer("vps", 2, Some("vps.example.com:51820"));
        let public = peer("vps2", 3, Some("203.0.113.9:51820"));
        // The trap this gate exists for: a real, valid, self-reported
        // endpoint that is useless the moment the device leaves that LAN.
        let lan_only = peer("homeserver", 4, Some("192.168.1.50:51820"));
        let no_endpoint = peer("laptop", 5, None);

        let out = render_conf(
            &iface(),
            &[gw.clone(), public, lan_only, no_endpoint],
            &[],
            Some(&Gateway { peer: &gw, ranges: ranges() }),
        );

        assert_eq!(out.direct_peers, vec!["vps2".to_string()]);
        assert!(out.text.contains("10.90.0.3/32"), "{}", out.text);
        assert!(
            !out.text.contains("192.168.1.50"),
            "a LAN endpoint would mint a /32 that outranks the gateway's covering route \
             and black-hole off that LAN:\n{}",
            out.text
        );
        assert!(!out.text.contains("10.90.0.4/32"), "{}", out.text);
        assert!(!out.text.contains("10.90.0.5/32"), "{}", out.text);
    }

    #[test]
    fn without_a_gateway_every_peer_still_gets_a_direct_entry_as_before() {
        let lan_only = peer("homeserver", 4, Some("192.168.1.50:51820"));
        let no_endpoint = peer("laptop", 5, None);
        let out = render_conf(&iface(), &[lan_only, no_endpoint], &[], None);
        assert_eq!(out.text.matches("[Peer]").count(), 2, "{}", out.text);
        assert_eq!(out.direct_peers, vec!["homeserver".to_string(), "laptop".to_string()]);
    }

    #[test]
    fn a_bracketed_v6_endpoint_falls_back_to_v4_so_a_cellular_device_can_dial_it() {
        // `endpoint_addr` is recorded family-blind, from whichever family the
        // node's poll arrived over. As one peer among many that mis-picks one
        // entry; as the gateway it is the whole config.
        let mut gw = peer("vps", 2, Some("[2001:db8::1]:51820"));
        gw.endpoint_addr_v4 = Some("203.0.113.9:51820".into());
        let out = render_conf(&iface(), &[gw.clone()], &[], Some(&Gateway { peer: &gw, ranges: ranges() }));
        assert!(out.text.contains("Endpoint = 203.0.113.9:51820"), "{}", out.text);
        assert!(!out.text.contains("2001:db8::1"), "{}", out.text);
    }

    #[test]
    fn a_v6_only_peer_keeps_its_v6_endpoint() {
        let gw = peer("vps", 2, Some("[2001:db8::1]:51820"));
        let out = render_conf(&iface(), std::slice::from_ref(&gw), &[], Some(&Gateway { peer: &gw, ranges: ranges() }));
        assert!(out.text.contains("Endpoint = [2001:db8::1]:51820"), "{}", out.text);
    }

    #[test]
    fn addresses_are_reparsed_rather_than_interpolated_from_the_directory() {
        let mut bad = peer("evil", 3, Some("203.0.113.9:51820"));
        bad.ip4 = "10.90.0.3/0, 0.0.0.0/0".into();
        let out = render_conf(&iface(), &[bad], &[], None);
        assert!(
            !out.text.contains("0.0.0.0/0"),
            "an address must come back out of a parser before reaching the file:\n{}",
            out.text
        );
    }

    #[test]
    fn selecting_a_gateway_refuses_a_node_that_cannot_be_dialled_from_outside() {
        let lan_only = peer("homeserver", 4, Some("192.168.1.50:51820"));
        let approved = vec!["homeserver".to_string()];
        let err = select_gateway(&[lan_only], &approved, &approved, Some("homeserver")).unwrap_err();
        assert!(matches!(err, ExportConfigError::GatewayNotReachable { .. }), "{err}");
    }

    #[test]
    fn selecting_a_gateway_refuses_an_unapproved_node() {
        let p = peer("vps", 2, Some("vps.example.com:51820"));
        let err = select_gateway(&[p], &[], &[], Some("vps")).unwrap_err();
        assert!(matches!(err, ExportConfigError::GatewayNotApproved { .. }), "{err}");
    }

    #[test]
    fn a_single_eligible_node_is_picked_automatically_and_two_are_not() {
        let a = peer("vps", 2, Some("vps.example.com:51820"));
        let b = peer("vps2", 3, Some("203.0.113.9:51820"));
        let lan = peer("homeserver", 4, Some("192.168.1.50:51820"));
        let approved = vec!["vps".to_string(), "vps2".to_string(), "homeserver".to_string()];

        let just_one = [a.clone(), lan.clone()];
        let one = select_gateway(&just_one, &approved, &approved, None).unwrap();
        assert_eq!(one.map(|p| p.name.as_str()), Some("vps"));

        // Ambiguity is an error, not a coin flip: the choice is baked into
        // the config and cannot be changed without re-exporting.
        let two = [a, b, lan];
        let err = select_gateway(&two, &approved, &approved, None).unwrap_err();
        assert!(matches!(err, ExportConfigError::AmbiguousGateway { .. }), "{err}");
    }

    #[test]
    fn an_approved_node_that_is_not_currently_offering_is_refused_before_anything_is_created() {
        // Approval alone leaves the host firewall's forward hook shut. The
        // coordinator refuses this too, but only when the assignment is
        // recorded — which is the last step of an export, and failing there
        // would leave a node created with no config to show for it.
        let p = peer("vps", 2, Some("vps.example.com:51820"));
        let approved = vec!["vps".to_string()];
        let err = select_gateway(&[p], &approved, &[], Some("vps")).unwrap_err();
        assert!(matches!(err, ExportConfigError::GatewayNotOffering { .. }), "{err}");
    }

    #[test]
    fn no_eligible_node_is_not_an_error_it_is_the_old_all_direct_behaviour() {
        let lan = peer("homeserver", 4, Some("192.168.1.50:51820"));
        assert!(select_gateway(&[lan], &[], &[], None).unwrap().is_none());
    }
}
