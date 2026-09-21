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
pub async fn probe(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<wireserve_types::ProbeResponse> {
    let client =
        crate::client_ip::resolve_client(&headers, peer_addr.ip(), state.config.trust_proxy_headers);
    Json(wireserve_types::ProbeResponse {
        addr: client.ip.to_string(),
        reflexive_port: Some(state.config.listen_addr.port()),
    })
}
