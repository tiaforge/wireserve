//! `wireserve-agent join <coordinator-url> <join-token>` — the bootstrap
//! command spec §4.6 implies but doesn't name (PLAN.md decisions log #5).
//! Generates a keypair locally, redeems the join token via `/register`,
//! and persists the result to local state at mode 600.

use defguard_wireguard_rs::key::Key;
use wireserve_types::{NodeKind, RegisterRequest, RegisterResponse};

use crate::state::AgentState;

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("HTTP error talking to coordinator: {0}")]
    Http(#[from] reqwest::Error),
    #[error("coordinator rejected registration: {0}")]
    Rejected(String),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
    #[error("{0}")]
    PlaintextHttp(String),
}

/// The environment override for [`check_coordinator_transport`], for a
/// node that joined before the flag existed: set to `1` in its
/// `agent.env` rather than joining again.
pub const ALLOW_PLAINTEXT_HTTP_ENV: &str = "WIRESERVE_ALLOW_PLAINTEXT_HTTP";

/// Refuses a plain-`http://` coordinator URL to anything but loopback
/// unless the operator explicitly allowed it (security review finding
/// #4, superseding S6's warning).
///
/// A warning was not enough, because of what crosses that connection:
/// the join token, the bearer token on every poll, and the peer
/// directory — which decides which WireGuard keys this node accepts and
/// what it routes to them. Anyone on the path can take over the node's
/// view of the mesh. An internal network without TLS is still a
/// legitimate topology, so it stays possible, but as a decision rather
/// than a default.
pub fn check_coordinator_transport(url: &str, allowed: bool) -> Result<(), JoinError> {
    if allowed || !wireserve_types::is_plaintext_http_to_remote_host(url) {
        return Ok(());
    }
    Err(JoinError::PlaintextHttp(format!(
        "refusing to use {url} over plain HTTP: the join token, this node's bearer token and \
         the peer directory (which decides which WireGuard keys this node trusts) would cross \
         the network unprotected. Use an https:// URL through a TLS-terminating reverse proxy \
         (spec §7), or, only if every network between here and the coordinator is trusted, \
         pass --allow-plaintext-http to `join`/`install` (or set \
         {ALLOW_PLAINTEXT_HTTP_ENV}=1 for a node that already joined)"
    )))
}

pub struct JoinParams<'a> {
    pub coordinator_url: &'a str,
    pub join_token: &'a str,
    pub listen_port: u16,
    pub endpoint_addr: Option<String>,
    pub state_path: &'a std::path::Path,
    /// Carried over from this instance's previous state, so a re-join
    /// keeps its interface.
    pub ifname: Option<String>,
    pub ifname_pinned: bool,
    /// `--allow-plaintext-http`; see [`check_coordinator_transport`].
    pub allow_plaintext_http: bool,
}

/// The first WireGuard port tried, and how many after it.
pub const DEFAULT_LISTEN_PORT: u16 = 51820;
const PORT_RANGE: u16 = 100;

/// Picks the UDP port this instance listens on when `join` isn't given
/// one: its previous port if it had one and that is still free, otherwise
/// the first free port from 51820 up. `reserved` are ports other instances
/// on this host have stored, running or not — each keeps its own.
pub fn choose_listen_port(
    previous: Option<u16>,
    reserved: &std::collections::BTreeSet<u16>,
    is_free: impl Fn(u16) -> bool,
) -> Option<u16> {
    let range = DEFAULT_LISTEN_PORT..DEFAULT_LISTEN_PORT + PORT_RANGE;
    previous
        .into_iter()
        .chain(range)
        .find(|p| !reserved.contains(p) && is_free(*p))
}

/// Whether nothing on this host is bound to UDP `port`, over IPv4 and —
/// where the host has IPv6 at all — IPv6. The kernel's WireGuard socket
/// binds both, so a port taken on either would fail bring-up.
#[must_use]
pub fn udp_port_is_free(port: u16) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
    let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok();
    let v6 = match UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)) {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::AddrInUse,
    };
    v4 && v6
}

/// Performs the join: keypair generation, `/register`, and persists the
/// resulting state. Returns the saved state on success.
pub async fn join(params: JoinParams<'_>) -> Result<AgentState, JoinError> {
    // Clamped so the persisted key already matches the form the kernel
    // will report back on every future `bring_up` (see
    // `wg::clamp_private_key`) — otherwise a freshly generated key would
    // fail that check on the very first restart.
    let private_key = crate::wg::clamp_private_key(&Key::generate());
    let public_key = private_key.public_key();

    // Before any network traffic at all, the probes below included.
    check_coordinator_transport(params.coordinator_url, params.allow_plaintext_http)?;
    if wireserve_types::is_plaintext_http_to_remote_host(params.coordinator_url) {
        eprintln!(
            "warning: registering with {} over plain HTTP, as allowed by \
             --allow-plaintext-http — the join token, the bearer token and the peer directory \
             cross the network unprotected",
            params.coordinator_url
        );
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let url = format!("{}/register", params.coordinator_url.trim_end_matches('/'));
    // Best-effort: a probe failure must not fail `join` — the mesh
    // already tolerates a node with no reachable endpoint at all, and
    // `--endpoint-addr` remains available as a manual override for a
    // coordinator this node genuinely can't reach outbound over a
    // required family at join time.
    let dual = crate::probe::probe_both(
        params.coordinator_url,
        params.listen_port,
        crate::probe::PROBE_TIMEOUT,
    )
    .await;
    // NAT-hairpin/reflexive-address discovery (PLAN.md decisions log
    // #85, #90+) is IPv4-only — a node with real working IPv6 (the same
    // signal `dual.v6.is_some()` already reports) needs neither and
    // skips both to avoid a redundant probe. Must run before `bring_up`
    // claims `listen_port` — see `reflexive` module doc — which at join
    // time hasn't happened yet at all, so this is always safe here.
    let reflexive_addr = if dual.v6.is_some() {
        None
    } else {
        crate::reflexive::learn_reflexive_addr(
            params.coordinator_url,
            params.listen_port,
            crate::reflexive::PROBE_TIMEOUT,
        )
        .await
    };
    let req = RegisterRequest {
        join_token: params.join_token.to_string(),
        pubkey: public_key.to_string(),
        kind: NodeKind::Agent,
        listen_port: Some(params.listen_port),
        endpoint_addr: params.endpoint_addr.clone(),
        endpoint_addr_v4: dual.v4,
        endpoint_addr_v6: dual.v6,
        lan_addr: crate::wg::pick_lan_address(
            &crate::wg::local_lan_ifaces(params.ifname.as_deref().unwrap_or("")).unwrap_or_default(),
        )
        .map(|ip| ip.to_string()),
        reflexive_addr,
        transit_capable: false,
    };

    let resp = client.post(&url).json(&req).send().await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(JoinError::Rejected(body));
    }
    let reg: RegisterResponse = resp.json().await?;

    let state = AgentState {
        pending_services: Vec::new(),
        coordinator_url: Some(params.coordinator_url.to_string()),
        bearer_token: Some(reg.bearer_token),
        private_key: Some(private_key.to_string()),
        public_key: Some(public_key.to_string()),
        ip4: Some(reg.ip4),
        ip6: Some(reg.ip6),
        listen_port: Some(params.listen_port),
        endpoint_addr: params.endpoint_addr,
        declared_services: Vec::new(),
        last_directory: None,
        rejected_services: Vec::new(),
        ifname: params.ifname,
        ifname_pinned: params.ifname_pinned,
        transit_capable: false,
        allow_plaintext_http: params.allow_plaintext_http,
        mesh: None,
    };
    let mut state = state;
    if let Some(offered) = reg.mesh.filter(|m| crate::mesh::pinnable(m, state.ip4.as_deref(), state.ip6.as_deref())) {
        state.mesh = Some(offered);
    }
    state.save(params.state_path)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_http_to_a_remote_coordinator_is_refused_unless_allowed() {
        for url in ["http://wireserve.example.com", "http://10.0.0.5:47820", "http://[fd00::1]:47820"] {
            assert!(check_coordinator_transport(url, false).is_err(), "{url}");
            assert!(check_coordinator_transport(url, true).is_ok(), "{url}");
        }
    }

    #[test]
    fn https_and_loopback_http_need_no_opt_in() {
        for url in [
            "https://wireserve.example.com",
            "http://127.0.0.1:47820",
            "http://localhost:47820",
            "http://[::1]:47820",
        ] {
            assert!(check_coordinator_transport(url, false).is_ok(), "{url}");
        }
    }

    #[test]
    fn generated_private_key_never_appears_in_the_register_request() {
        // The request we build must only ever carry the derived public
        // key — never the private key bytes/string, in any field.
        let private_key = Key::generate();
        let public_key = private_key.public_key();
        let req = RegisterRequest {
            join_token: "jtk_x".into(),
            pubkey: public_key.to_string(),
            kind: NodeKind::Agent,
            listen_port: Some(51820),
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

    #[test]
    fn listen_port_keeps_the_previous_one_then_takes_the_first_free() {
        let none = std::collections::BTreeSet::new();
        assert_eq!(choose_listen_port(None, &none, |_| true), Some(51820));
        assert_eq!(choose_listen_port(Some(51825), &none, |_| true), Some(51825));
        // Taken by another instance (running or not), or bound by anything.
        let reserved = std::collections::BTreeSet::from([51820, 51821]);
        assert_eq!(choose_listen_port(None, &reserved, |p| p != 51822), Some(51823));
        assert_eq!(choose_listen_port(Some(51820), &reserved, |_| true), Some(51822));
        assert_eq!(choose_listen_port(None, &none, |_| false), None);
    }

    #[test]
    fn a_bound_port_is_not_free() {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        assert!(!udp_port_is_free(port));
        drop(socket);
        assert!(udp_port_is_free(port));
    }
}
