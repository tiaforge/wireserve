//! The TLS terminator's socket (PLAN.md M33): a second, narrower one than
//! the agent's own. The terminator runs as its own unprivileged user, and a
//! compromise of it — it parses TLS and HTTP from the whole mesh — must not
//! be able to `serve`, `unserve` or `leave`. So this socket decodes only
//! [`TlsRequest`], whose two operations are a check-in and a challenge
//! record for one of this node's own names.
//!
//! Shared with the `wireserve-tls` group (0660, in a 0750 directory) when
//! that group exists; root-only otherwise.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use wireserve_types::tls::{Caller, TlsConfig, TlsRequest, TlsResponse, TlsService};
use wireserve_types::{Proto, TLS_PUBLIC_PORT};

use crate::state::AgentState;
use crate::tls_link::TlsLink;

/// The group the terminator runs as, and the variable that renames it.
pub const TLS_GROUP_ENV: &str = "WIRESERVE_TLS_GROUP";
pub const DEFAULT_TLS_GROUP: &str = "wireserve-tls";

/// A request is one short line; anything longer is not one.
const MAX_REQUEST: u64 = 64 * 1024;
/// At most this many names are taken from one check-in.
const MAX_SERVING: usize = 64;

#[derive(Clone)]
pub struct TlsContext {
    pub state: Arc<Mutex<AgentState>>,
    pub link: Arc<TlsLink>,
    pub client: reqwest::Client,
}

pub fn tls_group_name() -> Option<String> {
    match std::env::var(TLS_GROUP_ENV) {
        Ok(v) if v.is_empty() => None,
        Ok(v) => Some(v),
        Err(_) => Some(DEFAULT_TLS_GROUP.to_string()),
    }
}

pub async fn serve(ctx: TlsContext, socket_path: &Path) -> std::io::Result<()> {
    let gid = tls_group_name().and_then(|g| crate::ipc::server::lookup_group(&g));
    match gid {
        Some(_) => tracing::info!(socket = %socket_path.display(), "TLS terminator socket shared with its group"),
        None => tracing::info!(socket = %socket_path.display(), "TLS terminator socket is root-only (no `wireserve-tls` group)"),
    }
    let listener = crate::ipc::server::bind_socket(socket_path, gid)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move { handle(&ctx, stream).await });
    }
}

async fn handle(ctx: &TlsContext, stream: tokio::net::UnixStream) {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half.take(MAX_REQUEST));
    let mut line = String::new();
    let response = match reader.read_line(&mut line).await {
        Ok(0) => return,
        Ok(_) => match serde_json::from_str::<TlsRequest>(line.trim_end()) {
            Ok(req) => dispatch(ctx, req).await,
            Err(e) => TlsResponse::Error { message: format!("bad request: {e}") },
        },
        Err(e) => TlsResponse::Error { message: format!("read error: {e}") },
    };
    let mut out = serde_json::to_string(&response)
        .unwrap_or_else(|_| r#"{"status":"error","message":"internal: failed to encode response"}"#.to_string());
    out.push('\n');
    let _ = write_half.write_all(out.as_bytes()).await;
}

async fn dispatch(ctx: &TlsContext, req: TlsRequest) -> TlsResponse {
    match req {
        TlsRequest::CheckIn { serving } => {
            let serving: BTreeSet<String> = serving
                .into_iter()
                .filter(|n| wireserve_types::is_valid_dns_label(n))
                .take(MAX_SERVING)
                .collect();
            let config = build_config(&*ctx.state.lock().await);
            // Only names it was asked to serve count: a terminator claiming
            // anything else is not believed.
            let asked: BTreeSet<&str> = config.services.iter().map(|s| s.name.as_str()).collect();
            ctx.link.check_in(
                serving.into_iter().filter(|n| asked.contains(n.as_str())).collect(),
                std::time::Instant::now(),
            );
            TlsResponse::Config(Box::new(config))
        }
        TlsRequest::Challenge { fqdn, value, present } => challenge(ctx, &fqdn, &value, present).await,
    }
}

/// What the terminator should serve: this node's own services published on
/// TCP 443 with an address of their own, once the coordinator publishes DNS
/// records (it sends `acme` only then). Built from the node's declarations,
/// not the directory, because the directory leaves a mapping's target
/// address out and the terminator needs it.
///
/// A service marked for sign-in is left to the proxy (PLAN.md M33): the
/// built-in sign-in comes in M34.
#[must_use]
pub fn build_config(state: &AgentState) -> TlsConfig {
    let Some(directory) = &state.last_directory else {
        return TlsConfig::default();
    };
    let node = state.ip4.as_deref().and_then(|ip| ip.parse::<Ipv4Addr>().ok());
    let callers = directory
        .peers
        .iter()
        .filter_map(|p| Some(Caller { addr: p.ip4.parse().ok()?, node: p.name.clone() }))
        .collect();
    let (Some(naming), Some(node)) = (&directory.naming, node) else {
        return TlsConfig { callers, ..TlsConfig::default() };
    };
    let Some(acme) = naming.acme.clone() else {
        return TlsConfig { callers, ..TlsConfig::default() };
    };
    let own = node.to_string();
    let services = state
        .declared_services
        .iter()
        .filter(|d| !directory.services.iter().any(|s| s.name == d.name && s.ip4 == own && s.auth))
        .filter_map(|d| {
            let vip = crate::poll_loop::own_vip(&d.name, node, directory)?;
            let map = d.port_maps().into_iter().find(|m| m.public == TLS_PUBLIC_PORT && m.proto == Proto::Tcp)?;
            Some(TlsService {
                name: d.name.clone(),
                fqdn: format!("{}.{}", d.name, naming.domain),
                vip,
                upstream: SocketAddr::new(map.addr.unwrap_or(node).into(), map.target),
            })
        })
        .collect();
    TlsConfig { acme: Some(acme), services, callers }
}

/// Publishes or withdraws a challenge value through the coordinator, for a
/// name this node's terminator is configured to serve and no other.
async fn challenge(ctx: &TlsContext, fqdn: &str, value: &str, present: bool) -> TlsResponse {
    if !wireserve_types::tls::is_challenge_value(value) {
        return TlsResponse::Error { message: "not a DNS-01 challenge value".into() };
    }
    let (url, bearer, known) = {
        let s = ctx.state.lock().await;
        let known = build_config(&s).services.iter().any(|svc| svc.fqdn == fqdn);
        (s.coordinator_url.clone().unwrap_or_default(), s.bearer_token.clone(), known)
    };
    if !known {
        return TlsResponse::Error { message: format!("{fqdn} is not one of this node's names") };
    }
    let Some(bearer) = bearer else {
        return TlsResponse::Error { message: "not registered".into() };
    };
    let url = format!("{}/tls/challenge", url.trim_end_matches('/'));
    let body = serde_json::json!({ "fqdn": fqdn, "value": value });
    let request = if present { ctx.client.post(&url) } else { ctx.client.delete(&url) };
    match request.bearer_auth(bearer).json(&body).send().await {
        Ok(r) if r.status().is_success() => TlsResponse::Ok,
        // A coordinator from before M33 has no such route.
        Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND || r.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED => {
            TlsResponse::Unsupported
        }
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            TlsResponse::Error { message: format!("coordinator refused ({status}): {}", text.escape_debug()) }
        }
        Err(e) => TlsResponse::Error { message: format!("coordinator unreachable: {e}") },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{AcmeSettings, PollResponse, ServiceDecl, ServiceNaming};

    fn state(acme: bool, auth: bool) -> AgentState {
        let directory: PollResponse = serde_json::from_value(serde_json::json!({
            "peers": [
                {"name": "home", "pubkey": "pk-home", "ip4": "10.9.0.1", "ip6": ""},
                {"name": "phone", "pubkey": "pk-phone", "ip4": "10.9.0.7", "ip6": ""},
            ],
            "services": [
                {"name": "plex", "node": "home", "ip4": "10.9.0.1", "port": 443, "proto": "tcp", "online": true,
                 "vip4": "10.9.0.50", "auth": auth},
                {"name": "prom", "node": "home", "ip4": "10.9.0.1", "port": 80, "proto": "tcp", "online": true,
                 "vip4": "10.9.0.51"},
            ],
        }))
        .unwrap();
        let mut directory = directory;
        directory.naming = Some(ServiceNaming {
            domain: "int.test".into(),
            proxy_service: None,
            acme: acme.then(|| AcmeSettings { directory: "https://acme.test/dir".into(), email: None, propagation_secs: 0 }),
        });
        AgentState {
            ip4: Some("10.9.0.1".into()),
            declared_services: vec![
                ServiceDecl::new("plex", vec!["443:32400".parse().unwrap()]),
                ServiceDecl::new("prom", vec!["80:9090".parse().unwrap()]),
                ServiceDecl::new("router", vec!["443:192.168.1.1:80".parse().unwrap()]),
            ],
            last_directory: Some(directory),
            ..AgentState::default()
        }
    }

    #[test]
    fn only_own_443_services_with_an_address_are_served() {
        let cfg = build_config(&state(true, false));
        assert_eq!(cfg.services.len(), 1, "{cfg:?}");
        let plex = &cfg.services[0];
        assert_eq!(plex.fqdn, "plex.int.test");
        assert_eq!(plex.vip, "10.9.0.50".parse::<Ipv4Addr>().unwrap());
        assert_eq!(plex.upstream, "10.9.0.1:32400".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.callers.len(), 2);
    }

    #[test]
    fn nothing_without_records_and_nothing_behind_the_sign_in() {
        assert!(build_config(&state(false, false)).services.is_empty());
        assert!(build_config(&state(true, true)).services.is_empty());
        assert!(build_config(&AgentState::default()).services.is_empty());
    }
}
