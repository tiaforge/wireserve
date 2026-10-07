//! `wireserve-admin device create <name>` (spec §9): generates a WireGuard
//! keypair locally, creates and immediately redeems a `kind: "static"` node
//! in one CLI call, and renders a `.conf` for import into an official
//! WireGuard client.
//!
//! Every node the device reaches, it reaches end to end (PLAN.md M40, M41):
//! directly when the node accepts inbound WireGuard, and otherwise through a
//! carrier's public relay port, which forwards the session without being
//! able to read it. Only an exit, which the device's full-tunnel profile
//! sends its internet traffic to, sees any of it — that is what an exit is.

use defguard_wireguard_rs::key::Key;
use wireserve_types::{AdminServiceInfo, ExportRecord, NodeKind, PeerInfo, RegisterRequest, RelayAssignment, RelayPlan, ServiceApprovalState};

use crate::client::{self, AdminClient, ClientError};

#[derive(Debug, thiserror::Error)]
pub enum ExportConfigError {
    #[error(transparent)]
    Client(#[from] ClientError),
    /// `device refresh` aimed at a name the coordinator does not know. Deliberately
    /// not an auto-create: a typo would otherwise silently mint a new node.
    #[error("no such node '{name}' — run `device create` to create it ({message})")]
    NoSuchNode { name: String, message: String },
    #[error("no such node '{name}' to use as the exit")]
    NoSuchExit { name: String },
    #[error(
        "'{name}' is not approved to send others' traffic on — run `wireserve-admin transit approve {name}` \
         (and `wireserve transit on` and `wireserve exit on` on that node) first"
    )]
    ExitNotApproved { name: String },
    #[error(
        "'{name}' is not offering to be an exit — run `wireserve exit on` on it, then try \
         again (a coordinator older than exit support never reports an offer at all)"
    )]
    ExitNotOffering { name: String },
    #[error(
        "'{name}' can't be dialled from outside the mesh, and a device sends its full tunnel \
         straight to its exit — pick a node with a public endpoint that accepts WireGuard"
    )]
    ExitNotDialable { name: String },
    #[error("--exit: no node qualifies as an exit (approved, `exit on`, dialable from outside) — name one")]
    NoExit,
    #[error(
        "several nodes could be the exit ({names}) — name one with --exit <node>, since the \
         choice is baked into the config and cannot be changed without re-exporting"
    )]
    AmbiguousExit { names: String },
    #[error("{0}")]
    BadDns(String),
    /// `--dns` without a profile to put it in, or a profile that needs one
    /// without it. The CLI's own argument rules catch both first; this is
    /// for a caller of the library.
    #[error("{0}")]
    DnsUsage(&'static str),
    /// Relay ports that must be opened first (PLAN.md M40) — each named with
    /// exactly where.
    #[error("{0}")]
    PortsClosed(String),
}

/// This node's own interface parameters for rendering: the private key
/// generated in step 1, its allocated addresses, and its own public key
/// (used only to skip a self-entry in the peer list — never sent anywhere).
pub struct InterfaceParams {
    pub private_key: String,
    pub ip4: String,
    pub ip6: String,
    pub own_pubkey: String,
    /// The mesh profile's own `DNS =` line (PLAN.md M28, `--mesh-dns`).
    /// `None` keeps it without one, as every export before it was: the line
    /// captures all of the device's DNS while the tunnel is up (#104).
    pub dns: Option<std::net::Ipv4Addr>,
}

/// How the device reaches each node (PLAN.md M40), from the coordinator's
/// relay plan: a node in neither list isn't reachable from outside, and
/// gets no `[Peer]` at all.
#[derive(Debug, Clone, Default)]
pub struct Routes {
    /// Dialled directly, at its own endpoint.
    pub direct: Vec<String>,
    /// Reached through a carrier: `(node, carrier, endpoint)`.
    pub relayed: Vec<(String, String, String)>,
}

impl From<&RelayPlan> for Routes {
    fn from(plan: &RelayPlan) -> Self {
        Self {
            direct: plan.direct.clone(),
            relayed: plan.relayed.iter().map(|r| (r.node.clone(), r.carrier.clone(), r.endpoint.clone())).collect(),
        }
    }
}

/// The full-tunnel profile (PLAN.md M27): which peer carries everything,
/// and the resolver it names.
pub struct ExitProfile<'a> {
    pub node: &'a str,
    pub dns: std::net::Ipv4Addr,
}

/// What a render produced: the file itself, the full-tunnel profile when one
/// was asked for, and the relays the file relies on, which the caller records.
pub struct RenderedConf {
    pub text: String,
    /// The same peers, with the exit's entry carrying everything and a
    /// `DNS =` line: longest-prefix match keeps every other node's `/32` —
    /// the mesh — end to end, and only the rest goes to the exit.
    pub exit_text: Option<String>,
    pub relays: Vec<RelayAssignment>,
}

/// Renders a full WireGuard `.conf`: this node's own `[Interface]` block,
/// then one `[Peer]` block per node `routes` reaches, skipping this node's
/// own entry (defensive — whether `/admin/peers` already includes the
/// just-registered node depends on timing).
///
/// Every peer's `AllowedIPs` is that peer's own `/32` (v4) + `/128` (v6),
/// plus the `/32` of every approved service it owns (`services`, PLAN.md
/// M20 — the same rule the agent applies), never a shared mesh CIDR block.
///
/// A relayed node's `Endpoint =` is its carrier's public relay port; with
/// one in the file, the interface's MTU drops to the carry interface's
/// 1340, since the carrier sends those packets on inside its own tunnel.
///
/// Defense in depth (security review S2): the coordinator validates
/// `pubkey`/`endpoint_addr` strictly at `/register` and `/poll`, but this
/// renderer still refuses any peer whose `pubkey` or endpoint contains a
/// newline, which would otherwise let one field smuggle an entire extra
/// `.conf` directive into the file.
#[must_use]
pub fn render_conf(
    iface: &InterfaceParams,
    peers: &[PeerInfo],
    services: &[AdminServiceInfo],
    routes: &Routes,
    exit: Option<&ExitProfile<'_>>,
) -> RenderedConf {
    let mut head = String::new();
    head.push_str("[Interface]\n");
    head.push_str(&format!("PrivateKey = {}\n", iface.private_key));
    head.push_str(&format!("Address = {}/32, {}/128\n", iface.ip4, iface.ip6));
    if !routes.relayed.is_empty() {
        head.push_str("MTU = 1340\n");
    }
    let mut mesh = String::new();
    let mut full = String::new();
    let mut relays = Vec::new();
    let mut exit_rendered = false;

    for peer in peers {
        if peer.pubkey == iface.own_pubkey {
            continue;
        }
        let relayed = routes.relayed.iter().find(|(node, ..)| node == &peer.name);
        let endpoint = if let Some((_, _, endpoint)) = relayed {
            Some(endpoint.clone())
        } else if routes.direct.iter().any(|n| n == &peer.name) {
            choose_endpoint(peer)
        } else {
            continue;
        };
        if contains_newline(&peer.pubkey) || endpoint.as_deref().is_some_and(contains_newline) {
            warn_skipped(&peer.name);
            continue;
        }
        render_peer(&mut mesh, peer, services, endpoint.as_deref(), None);
        let is_exit = relayed.is_none() && exit.is_some_and(|e| e.node == peer.name);
        exit_rendered |= is_exit;
        render_peer(&mut full, peer, services, endpoint.as_deref(), is_exit.then_some("0.0.0.0/0, ::/0"));
        if let Some((node, carrier, _)) = relayed {
            relays.push(RelayAssignment { node: node.clone(), carrier: carrier.clone() });
        }
    }

    let mut text = head.clone();
    if let Some(dns) = iface.dns {
        text.push_str(&format!("DNS = {dns}\n"));
    }
    text.push_str(&mesh);
    // `::/0` goes in too although the exit forwards no IPv6: left out, the
    // device's IPv6 would leave around the tunnel, which is the very thing a
    // full tunnel on someone else's Wi-Fi is for.
    let exit_text = exit.filter(|_| exit_rendered).map(|e| {
        let mut out = head.clone();
        out.push_str(&format!("DNS = {}\n", e.dns));
        out.push_str(&full);
        out
    });
    RenderedConf { text, exit_text, relays }
}

/// What `device create` produced: the mesh profile, and the full-tunnel one
/// when `--exit` asked for it.
pub struct Exported {
    pub conf: String,
    pub exit_conf: Option<String>,
    /// A link for the device's owner to claim it with (PLAN.md M38), when
    /// the coordinator has an identity provider. Only for a new export.
    pub claim: Option<wireserve_types::ClaimLink>,
}

/// Where the full-tunnel profile sends DNS (PLAN.md M27), from `--dns`: an
/// approved service by name, which becomes its address, or an IPv4 address.
///
/// Resolved before anything is created, like the exit. A literal must be
/// somewhere the tunnel can take it: a mesh address the directory knows, or
/// a public one the exit forwards to. A private address outside the mesh —
/// a Pi-hole on the exit's LAN, say — is exactly what the exit refuses
/// to forward to, so it is refused here with the way to reach it instead.
///
/// Also says whether the address is the mesh's own, which the mesh profile
/// needs (M28): it carries nothing but the mesh, so any other resolver would
/// be asked outside the tunnel.
fn resolve_dns(
    spec: &str,
    peers: &[PeerInfo],
    services: &[AdminServiceInfo],
) -> Result<(std::net::Ipv4Addr, bool), ExportConfigError> {
    if let Ok(ip) = spec.parse::<std::net::Ipv4Addr>() {
        let in_mesh = peers.iter().any(|p| p.ip4 == spec)
            || services
                .iter()
                .any(|s| s.state == ServiceApprovalState::Approved && s.vip4.as_deref() == Some(spec));
        if in_mesh || wireserve_types::is_internet_v4(ip) {
            return Ok((ip, in_mesh));
        }
        return Err(ExportConfigError::BadDns(format!(
            "{ip} is neither a mesh address nor a public one, and the exit forwards to neither \
             private ranges nor anything else off the internet — serve the resolver instead \
             (e.g. `wireserve dns 53:{ip}:53/udp 53:{ip}:53/tcp` on a node that \
             reaches it) and pass --dns dns"
        )));
    }
    if spec.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(ExportConfigError::BadDns(
            "the exit forwards IPv4 only, so the resolver must be an IPv4 address or a service".into(),
        ));
    }
    let service = services
        .iter()
        .find(|s| s.name == spec && s.state == ServiceApprovalState::Approved)
        .ok_or_else(|| {
            ExportConfigError::BadDns(format!("no approved service named '{spec}' to use as the resolver"))
        })?;
    let vip: std::net::Ipv4Addr = service.vip4.as_deref().and_then(|v| v.parse().ok()).ok_or_else(|| {
        ExportConfigError::BadDns(format!("service '{spec}' has no address of its own to use as the resolver"))
    })?;
    let answers_dns = service
        .ports
        .iter()
        .any(|m| m.public == 53 && m.proto == wireserve_types::Proto::Udp);
    if !answers_dns {
        eprintln!(
            "warning: service '{spec}' publishes nothing on 53/udp, so the device's DNS queries \
             to {vip} will go unanswered — `serve {spec} 53:53/udp 53:53/tcp` on its node"
        );
    }
    Ok((vip, true))
}

/// One ordinary `[Peer]` block, with the peer's own host prefixes and the
/// addresses of the services it owns — or `allowed` in their place, for the
/// exit's entry in the full-tunnel profile.
fn render_peer(
    out: &mut String,
    peer: &PeerInfo,
    services: &[AdminServiceInfo],
    endpoint: Option<&str>,
    allowed: Option<&str>,
) {
    out.push('\n');
    out.push_str("[Peer]\n");
    out.push_str(&format!("PublicKey = {}\n", peer.pubkey));
    let allowed = allowed.map_or_else(|| own_allowed_ips(peer, services), str::to_string);
    out.push_str(&format!("AllowedIPs = {allowed}\n"));
    if let Some(endpoint) = endpoint {
        out.push_str(&format!("Endpoint = {endpoint}\n"));
    }
    // This device likely roams networks (wifi/cellular switching, laptop
    // suspend) — keep the NAT mapping alive so return traffic works.
    out.push_str("PersistentKeepalive = 25\n");
}

/// A peer's own host prefixes and its services' addresses. Parsed, not
/// copied — interpolating these straight from the directory is what would
/// let a field smuggle an extra `.conf` directive into the file.
fn own_allowed_ips(peer: &PeerInfo, services: &[AdminServiceInfo]) -> String {
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
    allowed
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

/// Picks the device's exit (PLAN.md M27), when `--exit` asked for one: a
/// node that is approved, offers to be one, and that the device can dial —
/// its full tunnel goes straight to it. `Some("")` picks the one node that
/// qualifies, if exactly one does.
fn select_exit<'a>(
    directory: &'a wireserve_types::AdminPeersResponse,
    requested: Option<&str>,
) -> Result<Option<&'a PeerInfo>, ExportConfigError> {
    let Some(requested) = requested else {
        return Ok(None);
    };
    let approved = |p: &PeerInfo| directory.transit_approved.iter().any(|n| n == &p.name);
    let offering = |p: &PeerInfo| directory.exit_offering.iter().any(|n| n == &p.name);
    let dialable = |p: &PeerInfo| choose_endpoint(p).is_some_and(|e| wireserve_types::is_globally_routable_endpoint(&e));
    if !requested.is_empty() {
        let peer = directory
            .peers
            .iter()
            .find(|p| p.name == requested)
            .ok_or_else(|| ExportConfigError::NoSuchExit { name: requested.to_string() })?;
        if !approved(peer) {
            return Err(ExportConfigError::ExitNotApproved { name: requested.to_string() });
        }
        if !offering(peer) {
            return Err(ExportConfigError::ExitNotOffering { name: requested.to_string() });
        }
        if !dialable(peer) {
            return Err(ExportConfigError::ExitNotDialable { name: requested.to_string() });
        }
        return Ok(Some(peer));
    }
    let eligible: Vec<&PeerInfo> = directory.peers.iter().filter(|p| approved(p) && offering(p) && dialable(p)).collect();
    match eligible.as_slice() {
        [] => Err(ExportConfigError::NoExit),
        [one] => Ok(Some(*one)),
        many => Err(ExportConfigError::AmbiguousExit { names: many.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", ") }),
    }
}

/// How an export is shaped beyond its name.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExportOptions<'a> {
    /// `--exit [node]`: also render the full-tunnel profile (PLAN.md M27),
    /// to this node, or with `Some("")` to the one that qualifies.
    pub exit: Option<&'a str>,
    /// `--dns`: an approved service by name, or an IPv4 address.
    pub dns: Option<&'a str>,
    /// `--mesh-dns`: put the resolver into the mesh profile too (M28).
    pub mesh_dns: bool,
    /// `--allow-unverified`: write relays whose port couldn't be seen open.
    pub allow_unverified: bool,
}

/// Where each profile sends DNS, resolved from [`ExportOptions`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Resolvers {
    exit: Option<std::net::Ipv4Addr>,
    mesh: Option<std::net::Ipv4Addr>,
}

/// The resolver half of an export, checked before anything is created or
/// rejoined: for the full-tunnel profile (M27) an exit and a resolver the
/// tunnel can reach; for the mesh profile (M28) a resolver on the mesh.
fn check_dns(
    admin_client: &AdminClient,
    directory: &wireserve_types::AdminPeersResponse,
    exit: Option<&PeerInfo>,
    opts: &ExportOptions<'_>,
) -> Result<Resolvers, ExportConfigError> {
    let Some(spec) = opts.dns else {
        if opts.exit.is_some() {
            return Err(ExportConfigError::DnsUsage("--exit needs --dns: the full tunnel has to name a resolver"));
        }
        if opts.mesh_dns {
            return Err(ExportConfigError::DnsUsage("--mesh-dns needs --dns to say which resolver"));
        }
        return Ok(Resolvers::default());
    };
    if opts.exit.is_none() && !opts.mesh_dns {
        return Err(ExportConfigError::DnsUsage(
            "--dns needs --exit (for the full-tunnel profile) or --mesh-dns (for the mesh profile)",
        ));
    }
    if opts.exit.is_some() && exit.is_none() {
        return Err(ExportConfigError::NoExit);
    }
    let services = admin_client.list_services()?;
    resolve_profiles(spec, opts, &directory.peers, &services.services)
}

/// [`check_dns`] once the directory and services are in hand. Pure, so the
/// rules are testable without a coordinator.
fn resolve_profiles(
    spec: &str,
    opts: &ExportOptions<'_>,
    peers: &[PeerInfo],
    services: &[AdminServiceInfo],
) -> Result<Resolvers, ExportConfigError> {
    let (addr, in_mesh) = resolve_dns(spec, peers, services)?;
    if opts.mesh_dns && !in_mesh {
        return Err(ExportConfigError::BadDns(format!(
            "{addr} is not on the mesh, and the mesh profile carries nothing but the mesh: the \
             device would ask it outside the tunnel, where it can name nothing here — serve a \
             resolver on a node and pass its name"
        )));
    }
    Ok(Resolvers {
        exit: opts.exit.is_some().then_some(addr),
        mesh: opts.mesh_dns.then_some(addr),
    })
}

/// Asks the coordinator how the device reaches each node (PLAN.md M40), and
/// stops — before anything is created — if a relay port it needs isn't
/// open, naming exactly which port to open where.
fn plan_routes(admin_client: &AdminClient, opts: &ExportOptions<'_>, exit: Option<&PeerInfo>) -> Result<RelayPlan, ExportConfigError> {
    eprintln!("working out how the device reaches each node (checking a relay port can take up to a minute)…");
    let plan = admin_client.relay_plan(opts.allow_unverified)?;
    for u in &plan.unreachable {
        eprintln!("warning: {} is left out of the config: {}", u.node, u.reason);
    }
    if let Some(exit) = exit {
        if !plan.direct.iter().any(|n| n == &exit.name) {
            return Err(ExportConfigError::ExitNotDialable { name: exit.name.clone() });
        }
    }
    if !plan.closed.is_empty() {
        let mut msg = String::from("these relay ports must be reachable from the internet first:\n");
        for port in &plan.closed {
            let at = port.address.as_deref().unwrap_or("its public address");
            let node = port.node.as_deref().unwrap_or("a node");
            let why = if port.open == Some(false) { "was not reachable" } else { "could not be checked in time" };
            msg.push_str(&format!(
                "  open UDP {} inbound on {} ({at}) in any firewall outside the host — cloud firewall or \
                 router port forward — for {node}; it {why}\n",
                port.port, port.carrier
            ));
        }
        if opts.allow_unverified {
            eprint!("warning: writing the config anyway (--allow-unverified); {msg}");
        } else {
            msg.push_str("then run this again (or pass --allow-unverified to write the config regardless)");
            return Err(ExportConfigError::PortsClosed(msg));
        }
    }
    for r in &plan.relayed {
        eprintln!("{}: relayed by {} at {} (end to end — {} can't read it)", r.node, r.carrier, r.endpoint, r.carrier);
    }
    // What the config depends on outside the mesh, said every time: a port
    // a firewall in front of the carrier must let in. Checked ones are
    // named too, so the list is complete, not only what went wrong.
    let mut needed: Vec<String> = plan
        .relayed
        .iter()
        .map(|r| {
            let (addr, port) = r.endpoint.rsplit_once(':').unwrap_or((&r.endpoint, "?"));
            let state = match (r.open, r.unverifiable_here) {
                (_, true) => format!(
                    "NOT CHECKED: the coordinator runs on {}, so a check from it never leaves the machine — \
                     make sure it is open in any firewall in front of {}",
                    r.carrier, r.carrier
                ),
                (Some(true), _) => "seen open from outside".to_string(),
                _ => "not seen open".to_string(),
            };
            format!("  UDP {port} inbound on {} ({addr}), for {}: {state}", r.carrier, r.node)
        })
        .collect();
    needed.sort();
    needed.dedup();
    if !needed.is_empty() {
        eprintln!("this config relies on these ports being open from the internet (see `wireserve-admin transit ports`):");
        for line in &needed {
            eprintln!("{line}");
        }
    }
    Ok(plan)
}

/// Runs the full `device create` flow end to end against a live
/// coordinator: keygen (local only), create+redeem a `kind: "static"` node,
/// fetch the peer directory and relay plan, render the `.conf`, record it.
///
/// Takes two base URLs, not one: `admin_client` talks to the coordinator's
/// admin listener, while `node_facing_url` is where `/register` actually
/// lives — a separate listener by spec §4.0's design.
pub fn run(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
    opts: &ExportOptions<'_>,
) -> Result<Exported, ExportConfigError> {
    let directory = admin_client.list_peers()?;
    let exit = select_exit(&directory, opts.exit)?;
    let dns = check_dns(admin_client, &directory, exit, opts)?;
    let plan = plan_routes(admin_client, opts, exit)?;
    let created = admin_client.create_node(name, NodeKind::Static, None)?;
    let mut exported = finish(admin_client, node_facing_url, name, &created.join_token, &directory, &plan, exit, dns)?;
    exported.claim = created.claim;
    Ok(exported)
}

/// Re-issues a `.conf` for a static peer that already exists (PLAN.md M24),
/// keeping its name and — because `reissue_join_token` leaves `ip4`/`ip6`
/// alone and `/register` reuses a node's existing addresses — its mesh
/// address. Only the keypair changes.
///
/// **Destructive from its first mutating call.** `rejoin` nulls the node's
/// pubkey, which drops it out of every other node's directory on their next
/// poll; `/register` puts it back. A failure in between leaves the node
/// alive but unregistered, recoverable by running the same command again.
/// The `kind` expectation is checked by the coordinator *before* it mutates
/// anything, so pointing this at an agent node by mistake is refused.
///
/// Everything that can fail on the way in — the directory, the exit, the
/// relay ports — happens ahead of the rejoin for the same reason.
pub fn run_refresh(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
    opts: &ExportOptions<'_>,
) -> Result<Exported, ExportConfigError> {
    let directory = admin_client.list_peers()?;
    let exit = select_exit(&directory, opts.exit)?;
    let dns = check_dns(admin_client, &directory, exit, opts)?;
    let plan = plan_routes(admin_client, opts, exit)?;
    let rejoined = match admin_client.rejoin(name, None, Some(NodeKind::Static)) {
        Ok(r) => r,
        Err(ClientError::Api { status, message }) if status == reqwest::StatusCode::NOT_FOUND => {
            return Err(ExportConfigError::NoSuchNode { name: name.to_string(), message });
        }
        Err(e) => return Err(e.into()),
    };
    finish(admin_client, node_facing_url, name, &rejoined.join_token, &directory, &plan, exit, dns)
}

/// The half both paths share, after the token exists: generate a keypair
/// locally, redeem it, render, and record how the config was shaped.
#[allow(clippy::too_many_arguments)]
fn finish(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
    join_token: &str,
    directory: &wireserve_types::AdminPeersResponse,
    plan: &RelayPlan,
    exit: Option<&PeerInfo>,
    dns: Resolvers,
) -> Result<Exported, ExportConfigError> {
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
    let iface = InterfaceParams {
        private_key: private_key.to_string(),
        ip4: reg.ip4,
        ip6: reg.ip6,
        own_pubkey: public_key.to_string(),
        dns: dns.mesh,
    };
    if let Some(resolver) = dns.mesh {
        eprintln!(
            "note: while the mesh tunnel is on, ALL of the device's DNS goes to {resolver}, not \
             only the mesh's names — if that resolver is down, so is the device's DNS until the \
             tunnel is switched off"
        );
    }
    let exit_profile = match (exit, dns.exit) {
        (Some(peer), Some(dns)) => Some(ExitProfile { node: &peer.name, dns }),
        _ => None,
    };
    let rendered = render_conf(&iface, &directory.peers, &services.services, &Routes::from(plan), exit_profile.as_ref());

    // Recorded from what was actually rendered: the exit sends on this
    // device's traffic only if its profile names it, and each carrier
    // forwards exactly the relays the file relies on.
    admin_client.record_export(
        name,
        &ExportRecord {
            exit: rendered.exit_text.as_ref().and(exit).map(|p| p.name.clone()),
            relays: rendered.relays.clone(),
        },
    )?;

    Ok(Exported { conf: rendered.text, exit_conf: rendered.exit_text, claim: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every peer dialled directly, which most of these tests assert on.
    fn render(iface: &InterfaceParams, peers: &[PeerInfo], services: &[AdminServiceInfo]) -> String {
        let routes = Routes { direct: peers.iter().map(|p| p.name.clone()).collect(), relayed: vec![] };
        render_conf(iface, peers, services, &routes, None).text
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
            relay: Default::default(),
        }
    }

    fn iface() -> InterfaceParams {
        InterfaceParams {
            private_key: "privkeybase64==".into(),
            ip4: "100.90.0.7".into(),
            ip6: "fd00:90::7".into(),
            own_pubkey: "ownpubkeybase64==".into(),
            dns: None,
        }
    }

    fn service(node: &str, vip4: Option<&str>, state: ServiceApprovalState) -> AdminServiceInfo {
        AdminServiceInfo {
            groups: vec![],
            dns: None,
            name: "web".into(),
            node: node.into(),
            ip4: String::new(),
            vip4: vip4.map(Into::into),
            ports: vec![],
            state,
            declared_at: None,
            approved_at: None,
            denied_at: None,
            denied_reason: None,
            approved_ports: vec![],
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
mod routes_tests {
    use super::*;

    fn peer(name: &str, host: u8, endpoint: Option<&str>) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: format!("{name}-pubkey="),
            ip4: format!("10.90.0.{host}"),
            ip6: format!("fdb4:d481:7c21::{host}"),
            endpoint_addr: endpoint.map(Into::into),
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            relay: Default::default(),
        }
    }

    fn iface() -> InterfaceParams {
        InterfaceParams {
            private_key: "privkeybase64==".into(),
            ip4: "10.90.0.7".into(),
            ip6: "fdb4:d481:7c21::7".into(),
            own_pubkey: "ownpubkeybase64==".into(),
            dns: None,
        }
    }

    fn directory(peers: Vec<PeerInfo>, approved: &[&str], exit_offering: &[&str]) -> wireserve_types::AdminPeersResponse {
        wireserve_types::AdminPeersResponse {
            peers,
            transit_approved: approved.iter().map(ToString::to_string).collect(),
            exit_offering: exit_offering.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_relayed_node_is_dialled_at_its_carriers_relay_port_and_recorded() {
        let peers = [peer("vps", 2, Some("203.0.113.2:51820")), peer("minipc", 3, None), peer("gone", 4, None)];
        let routes = Routes {
            direct: vec!["vps".into()],
            relayed: vec![("minipc".into(), "vps".into(), "203.0.113.2:41003".into())],
        };
        let out = render_conf(&iface(), &peers, &[], &routes, None);
        assert!(out.text.contains("MTU = 1340\n"), "{}", out.text);
        assert!(out.text.contains("PublicKey = minipc-pubkey=\nAllowedIPs = 10.90.0.3/32, fdb4:d481:7c21::3/128\nEndpoint = 203.0.113.2:41003\n"), "{}", out.text);
        assert!(out.text.contains("Endpoint = 203.0.113.2:51820\n"), "{}", out.text);
        assert!(!out.text.contains("gone-pubkey"), "a node reached neither way has no entry: {}", out.text);
        assert!(!out.text.contains("/24") && !out.text.contains("/64"), "no covering route to anyone: {}", out.text);
        assert_eq!(out.relays, [RelayAssignment { node: "minipc".into(), carrier: "vps".into() }]);
    }

    #[test]
    fn without_a_relay_the_mtu_is_left_alone() {
        let peers = [peer("vps", 2, Some("203.0.113.2:51820"))];
        let out = render_conf(&iface(), &peers, &[], &Routes { direct: vec!["vps".into()], relayed: vec![] }, None);
        assert!(!out.text.contains("MTU"), "{}", out.text);
        assert!(out.relays.is_empty());
    }

    #[test]
    fn an_exit_must_be_approved_offering_and_dialable_and_one_is_picked_automatically() {
        let peers = vec![peer("vps", 2, Some("203.0.113.2:51820")), peer("home", 3, Some("192.168.1.3:51820")), peer("vps2", 5, Some("203.0.113.5:51820"))];
        let d = directory(peers.clone(), &["vps", "home"], &["vps", "home"]);
        assert_eq!(select_exit(&d, Some("")).unwrap().unwrap().name, "vps", "home's endpoint is private");
        assert!(select_exit(&d, None).unwrap().is_none());
        assert!(matches!(select_exit(&d, Some("home")), Err(ExportConfigError::ExitNotDialable { .. })));
        assert!(matches!(select_exit(&d, Some("vps2")), Err(ExportConfigError::ExitNotApproved { .. })));
        assert!(matches!(select_exit(&d, Some("nope")), Err(ExportConfigError::NoSuchExit { .. })));
        let d = directory(peers.clone(), &["vps", "vps2"], &["vps"]);
        assert!(matches!(select_exit(&d, Some("vps2")), Err(ExportConfigError::ExitNotOffering { .. })));
        let d = directory(peers.clone(), &["vps", "vps2"], &["vps", "vps2"]);
        assert!(matches!(select_exit(&d, Some("")), Err(ExportConfigError::AmbiguousExit { .. })));
        let d = directory(peers, &[], &[]);
        assert!(matches!(select_exit(&d, Some("")), Err(ExportConfigError::NoExit)));
    }
}

#[cfg(test)]
mod exit_tests {
    use super::*;
    use std::net::Ipv4Addr;
    use wireserve_types::PortMap;

    fn peer(name: &str, host: u8, endpoint: Option<&str>) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: format!("{name}-pubkey="),
            ip4: format!("10.90.0.{host}"),
            ip6: format!("fdb4:d481:7c21::{host}"),
            endpoint_addr: endpoint.map(Into::into),
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            relay: Default::default(),
        }
    }

    fn iface() -> InterfaceParams {
        InterfaceParams {
            private_key: "privkeybase64==".into(),
            ip4: "10.90.0.7".into(),
            ip6: "fdb4:d481:7c21::7".into(),
            own_pubkey: "ownpubkeybase64==".into(),
            dns: None,
        }
    }

    fn dns_service(name: &str, vip: &str, ports: &[&str], state: ServiceApprovalState) -> AdminServiceInfo {
        AdminServiceInfo {
            groups: vec![],
            dns: None,
            name: name.into(),
            node: "home".into(),
            ip4: String::new(),
            vip4: Some(vip.into()),
            ports: ports.iter().map(|p| p.parse::<PortMap>().unwrap()).collect(),
            state,
            declared_at: None,
            approved_at: None,
            denied_at: None,
            denied_reason: None,
            approved_ports: vec![],
        }
    }

    #[test]
    fn the_full_tunnel_profile_is_the_mesh_profile_with_everything_on_the_exit_and_a_resolver() {
        let exit = peer("vps", 2, Some("vps.example.com:51820"));
        let public = peer("vps2", 3, Some("203.0.113.9:51820"));
        let natted = peer("minipc", 4, None);
        let dns = Ipv4Addr::new(10, 90, 0, 50);
        let routes = Routes {
            direct: vec!["vps".into(), "vps2".into()],
            relayed: vec![("minipc".into(), "vps2".into(), "203.0.113.9:41004".into())],
        };
        let out = render_conf(&iface(), &[exit.clone(), public, natted], &[], &routes, Some(&ExitProfile { node: "vps", dns }));
        let full = out.exit_text.expect("an exit resolver asks for the second profile");

        // The mesh profile is untouched: no resolver (PLAN.md #104 still
        // holds for it), and every node on its own /32s.
        assert!(!out.text.contains("DNS ="), "{}", out.text);
        assert!(!out.text.contains("0.0.0.0/0"), "{}", out.text);

        assert!(full.contains("DNS = 10.90.0.50\n"), "{full}");
        assert!(full.contains("PublicKey = vps-pubkey=\nAllowedIPs = 0.0.0.0/0, ::/0\n"), "{full}");
        assert_eq!(full.matches("[Peer]").count(), 3, "{full}");
        // Every other node stays end to end: its /32s outrank the default
        // route, and a relayed one keeps its relay.
        assert!(full.contains("AllowedIPs = 10.90.0.3/32, fdb4:d481:7c21::3/128\n"), "{full}");
        assert!(full.contains("Endpoint = 203.0.113.9:41004\n"), "{full}");
        assert_eq!(
            out.text.replace("AllowedIPs = 10.90.0.2/32, fdb4:d481:7c21::2/128", "AllowedIPs = 0.0.0.0/0, ::/0"),
            full.replace("DNS = 10.90.0.50\n", ""),
            "the two profiles differ in exactly the resolver and the exit's range"
        );
    }

    #[test]
    fn no_resolver_no_second_profile() {
        let exit = peer("vps", 2, Some("vps.example.com:51820"));
        let routes = Routes { direct: vec!["vps".into()], relayed: vec![] };
        let out = render_conf(&iface(), std::slice::from_ref(&exit), &[], &routes, None);
        assert!(out.exit_text.is_none());
    }

    #[test]
    fn a_relayed_node_is_never_the_exit() {
        let natted = peer("minipc", 4, None);
        let routes = Routes { direct: vec![], relayed: vec![("minipc".into(), "vps".into(), "203.0.113.9:41004".into())] };
        let out = render_conf(&iface(), &[natted], &[], &routes, Some(&ExitProfile { node: "minipc", dns: Ipv4Addr::new(9, 9, 9, 9) }));
        assert!(out.exit_text.is_none(), "a full tunnel through a relay would send the internet through the carrier");
    }

    #[test]
    fn a_resolver_service_is_named_by_its_address() {
        let services = [
            dns_service("pihole", "10.90.0.50", &["53:53/udp", "53:53"], ServiceApprovalState::Approved),
            dns_service("pending", "10.90.0.51", &["53:53/udp"], ServiceApprovalState::Pending),
            dns_service("mute", "10.90.0.52", &["80:8080"], ServiceApprovalState::Approved),
        ];
        assert_eq!(resolve_dns("pihole", &[], &services).unwrap(), (Ipv4Addr::new(10, 90, 0, 50), true));
        assert!(
            matches!(resolve_dns("pending", &[], &services), Err(ExportConfigError::BadDns(_))),
            "an unapproved service has no address anyone routes to"
        );
        assert!(matches!(resolve_dns("nosuch", &[], &services), Err(ExportConfigError::BadDns(_))));
        // Nothing on 53/udp is a warning, not a refusal: the port may be
        // added before the device ever switches the tunnel on.
        assert_eq!(resolve_dns("mute", &[], &services).unwrap(), (Ipv4Addr::new(10, 90, 0, 52), true));
    }

    #[test]
    fn a_resolver_address_must_be_somewhere_the_tunnel_takes_it() {
        let peers = [peer("home", 4, None)];
        let services = [dns_service("pihole", "10.90.0.50", &["53:53/udp"], ServiceApprovalState::Approved)];
        for ok in ["9.9.9.9", "10.90.0.4", "10.90.0.50", "203.0.113.53"] {
            assert!(resolve_dns(ok, &peers, &services).is_ok(), "{ok}");
        }
        for (bad, hint) in [
            ("192.168.1.2", "serve"),
            ("10.1.2.3", "serve"),
            ("100.64.0.1", "serve"),
            ("127.0.0.1", "serve"),
            ("2001:db8::53", "IPv4"),
        ] {
            match resolve_dns(bad, &peers, &services) {
                Err(ExportConfigError::BadDns(msg)) => assert!(msg.contains(hint), "{bad}: {msg}"),
                other => panic!("{bad}: {:?}", other.map_err(|e| e.to_string())),
            }
        }
    }

    // ---- the mesh profile's resolver (PLAN.md M28) ----

    fn opts(exit: bool, mesh_dns: bool) -> ExportOptions<'static> {
        ExportOptions { exit: exit.then_some(""), dns: None, mesh_dns, allow_unverified: false }
    }

    #[test]
    fn the_mesh_profile_names_a_resolver_only_when_asked() {
        let exit = peer("vps", 2, Some("vps.example.com:51820"));
        let mut with = iface();
        with.dns = Some(Ipv4Addr::new(10, 90, 0, 50));
        let routes = Routes { direct: vec!["vps".into()], relayed: vec![] };
        let out = render_conf(&with, std::slice::from_ref(&exit), &[], &routes, Some(&ExitProfile { node: "vps", dns: Ipv4Addr::new(9, 9, 9, 9) }));
        assert!(
            out.text.contains("Address = 10.90.0.7/32, fdb4:d481:7c21::7/128\nDNS = 10.90.0.50\n\n[Peer]"),
            "{}",
            out.text
        );
        let full = out.exit_text.unwrap();
        assert_eq!(full.matches("DNS =").count(), 1, "each profile names its own resolver once: {full}");
        assert!(full.contains("DNS = 9.9.9.9\n"), "{full}");

        let out = render_conf(&iface(), std::slice::from_ref(&exit), &[], &routes, None);
        assert!(!out.text.contains("DNS ="), "{}", out.text);
    }

    #[test]
    fn each_profile_gets_the_resolver_only_when_asked_for() {
        let services = [dns_service("pihole", "10.90.0.50", &["53:53/udp"], ServiceApprovalState::Approved)];
        let r = resolve_profiles("pihole", &opts(false, true), &[], &services).unwrap();
        assert_eq!(r, Resolvers { exit: None, mesh: Some(Ipv4Addr::new(10, 90, 0, 50)) });
        let r = resolve_profiles("pihole", &opts(true, true), &[], &services).unwrap();
        assert_eq!(r.exit, r.mesh);
        let r = resolve_profiles("9.9.9.9", &opts(true, false), &[], &services).unwrap();
        assert_eq!(r, Resolvers { exit: Some(Ipv4Addr::new(9, 9, 9, 9)), mesh: None });
    }

    #[test]
    fn the_mesh_profile_refuses_a_resolver_off_the_mesh() {
        // It carries nothing but the mesh: a public resolver would be asked
        // outside the tunnel and name nothing — and quietly change where the
        // device's DNS goes, for no gain.
        let peers = [peer("home", 4, None)];
        match resolve_profiles("9.9.9.9", &opts(true, true), &peers, &[]) {
            Err(ExportConfigError::BadDns(msg)) => assert!(msg.contains("not on the mesh"), "{msg}"),
            other => panic!("{:?}", other.map_err(|e| e.to_string())),
        }
        assert_eq!(
            resolve_profiles("10.90.0.4", &opts(false, true), &peers, &[]).unwrap().mesh,
            Some(Ipv4Addr::new(10, 90, 0, 4)),
            "a node's own mesh address is on the mesh"
        );
    }

    #[test]
    fn a_resolver_needs_a_profile_and_a_profile_that_needs_one_gets_one() {
        // Decided before any request: the client points nowhere.
        let client = AdminClient::new("http://127.0.0.1:9", "t");
        let directory = wireserve_types::AdminPeersResponse::default();
        let usage = |o: ExportOptions<'_>| matches!(check_dns(&client, &directory, None, &o), Err(ExportConfigError::DnsUsage(_)));
        assert!(usage(ExportOptions { dns: Some("pihole"), ..Default::default() }));
        assert!(usage(ExportOptions { exit: Some(""), ..Default::default() }));
        assert!(usage(ExportOptions { mesh_dns: true, ..Default::default() }));
        assert_eq!(check_dns(&client, &directory, None, &ExportOptions::default()).unwrap(), Resolvers::default());
    }
}
