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
use wireserve_types::tls::{Caller, SignInTarget, TlsConfig, TlsRequest, TlsResponse, TlsService};
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
        TlsRequest::CheckIn { serving, port } => {
            // No port, nowhere to send anything: it serves nothing.
            let serving: BTreeSet<String> = serving
                .into_iter()
                .filter(|_| port != 0)
                .filter(|n| wireserve_types::is_valid_dns_label(n))
                .take(MAX_SERVING)
                .collect();
            let config = build_config(&*ctx.state.lock().await);
            // Only names it was asked to serve count: a terminator claiming
            // anything else is not believed.
            let asked: BTreeSet<&str> = config.services.iter().map(|s| s.name.as_str()).collect();
            ctx.link.check_in(
                serving.into_iter().filter(|n| asked.contains(n.as_str())).collect(),
                port,
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
/// A service marked for sign-in (PLAN.md M34) is served too, flagged, and
/// the sign-in resolved to where it answers: the provider's service's own
/// address, once its own node serves it with TLS — the terminator checks
/// every request there over verified TLS.
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
    let marked = |name: &str| directory.services.iter().any(|s| s.name == name && s.ip4 == own && s.auth);
    let services = state
        .declared_services
        .iter()
        .filter_map(|d| {
            let vip = crate::poll_loop::own_vip(&d.name, node, directory)?;
            let map = d.ports.clone().into_iter().find(|m| m.public == TLS_PUBLIC_PORT && m.proto == Proto::Tcp)?;
            Some(TlsService {
                name: d.name.clone(),
                fqdn: format!("{}.{}", d.name, naming.domain),
                vip,
                upstream: SocketAddr::new(map.addr.unwrap_or(node).into(), map.target),
                sign_in: marked(&d.name),
            })
        })
        .collect();
    let sign_in = naming.sign_in.as_ref().and_then(|si| {
        // Only on its own node: a service of the same name declared by any
        // other would receive every sign-in cookie, and decide who gets in.
        let provider = directory.services.iter().find(|s| s.name == si.service && s.node == si.node && s.terminated)?;
        Some(SignInTarget {
            fqdn: format!("{}.{}", si.service, naming.domain),
            vip: provider.vip4.as_deref()?.parse().ok()?,
            verify_path: si.verify_path.clone(),
            copy_headers: si.copy_headers.clone(),
            session_cookie: si.session_cookie.clone(),
        })
    });
    TlsConfig { acme: Some(acme), services, callers, sign_in }
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
                {"name": "plex", "node": "home", "ip4": "10.9.0.1", "ports": [{"public": 443, "target": 443, "proto": "tcp"}], "online": true,
                 "vip4": "10.9.0.50", "auth": auth},
                {"name": "prom", "node": "home", "ip4": "10.9.0.1", "ports": [{"public": 80, "target": 80, "proto": "tcp"}], "online": true,
                 "vip4": "10.9.0.51"},
                {"name": "auth", "node": "gate", "ip4": "10.9.0.2", "ports": [{"public": 443, "target": 443, "proto": "tcp"}], "online": true,
                 "vip4": "10.9.0.60", "terminated": true},
            ],
        }))
        .unwrap();
        let mut directory = directory;
        directory.naming = Some(ServiceNaming {
            domain: "int.test".into(),
            acme: acme.then(|| AcmeSettings { directory: "https://acme.test/dir".into(), email: None, propagation_secs: 0 }),
            sign_in: Some(wireserve_types::SignIn {
                service: "auth".into(),
                node: "gate".into(),
                verify_path: "/verify".into(),
                copy_headers: vec!["x-auth-user".into()],
                session_cookie: "authward_session".into(),
            }),
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
    fn nothing_without_records() {
        assert!(build_config(&state(false, false)).services.is_empty());
        assert!(build_config(&AgentState::default()).services.is_empty());
    }

    #[test]
    fn a_marked_service_is_served_flagged_with_the_sign_in_resolved() {
        let cfg = build_config(&state(true, true));
        assert!(cfg.services[0].sign_in);
        let si = cfg.sign_in.expect("the provider is terminated, so it can be reached");
        assert_eq!((si.fqdn.as_str(), si.vip), ("auth.int.test", "10.9.0.60".parse().unwrap()));

        // A provider its own node does not serve with TLS yet is unreachable
        // for the check, so there is no target — and marked services refuse.
        let mut st = state(true, true);
        let dir = st.last_directory.as_mut().unwrap();
        dir.services.iter_mut().find(|s| s.name == "auth").unwrap().terminated = false;
        assert!(build_config(&st).sign_in.is_none());
    }

    #[test]
    fn a_provider_on_any_other_node_is_not_the_provider() {
        let mut st = state(true, true);
        let dir = st.last_directory.as_mut().unwrap();
        dir.services.iter_mut().find(|s| s.name == "auth").unwrap().node = "impostor".into();
        assert!(build_config(&st).sign_in.is_none(), "every cookie would go to whoever declared the name");
    }
}
