use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;

use crate::state::AppState;

/// `GET /probe` — unauthenticated, no DB access, infallible. Echoes back
/// the source address the coordinator saw this request arrive from (via
/// `client_ip::resolve_client`, the same observation `/register`'s
/// endpoint fallback uses), with no port.
///
/// A node calls this twice, once over a connection forced to IPv4 and
/// once forced to IPv6 (see `wireserve-agent`'s `probe` module), purely
/// to learn which families it can actually reach the coordinator over —
/// unrelated to any node's registration state, which is why this needs
/// no auth and touches no node record.
///
/// Also reports `reflexive_port` (PLAN.md M22): the UDP port the
/// coordinator's self-hosted reflexive responder
/// (`wireserve_coordinator::reflexive`) is bound on — the same number as
/// this HTTP listener's own port, just UDP (see that module's doc
/// comment for why no separate port exists). This is how an agent learns
/// where to send its one-shot reflexive-address probe without a new CLI
/// flag or config value of its own.
///
/// `reflexive_ports` (PLAN.md M50) lists first the WireGuard port of the node
/// an admin named to answer there, while its own polls confirm it does, then
/// this responder's. Nothing is listed but this responder's port otherwise.
pub async fn probe(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<wireserve_types::ProbeResponse> {
    let client =
        crate::client_ip::resolve_client(
        &headers,
        peer_addr.ip(),
        state.config.trusts_forwarded_from(peer_addr.ip()),
    );
    let own = state.config.listen_addr.port();
    Json(wireserve_types::ProbeResponse {
        addr: client.ip.to_string(),
        reflexive_port: own,
        answers_twice: state.probe_udp.is_some(),
        reflexive_ports: reflexive_ports(&state, own),
    })
}

/// The ports `/probe` lists (PLAN.md M50): a confirmed WireGuard port first,
/// then `own`. Just `own` while none is confirmed — the list is then the same
/// as `reflexive_port`, and left out.
fn reflexive_ports(state: &AppState, own: u16) -> Vec<u16> {
    let mut ports = state.transit.reflexive_answering_ports(state.config.online_threshold_secs);
    if ports.is_empty() {
        return Vec::new();
    }
    ports.retain(|p| *p != own);
    ports.push(own);
    ports
}
