//! Unix-socket IPC server backing `serve`/`unserve`/`list`/`leave` (§4.6).
//! One request/response per connection, newline-delimited JSON.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Mutex};
use wireserve_types::{PollResponse, PortMap, ServiceDecl};

use crate::ipc::protocol::{IpcRequest, IpcResponse, ListView, LocalServiceView};
use crate::state::AgentState;

#[derive(Clone)]
pub struct AgentContext {
    pub state: Arc<Mutex<AgentState>>,
    pub state_path: PathBuf,
    pub instance: String,
    pub ifname: String,
    /// Signalled when `leave` is requested, so the daemon's main loop (which
    /// owns the live WireGuard interface / firewall backend) can perform
    /// the actual teardown — the IPC handler itself only queues the
    /// request and acknowledges it, it doesn't own interface state.
    pub shutdown: mpsc::Sender<()>,
}

fn build_list_view(ctx: &AgentContext, state: &AgentState) -> ListView {
    let directory = state
        .last_directory
        .clone()
        .unwrap_or(PollResponse {
            peers: vec![],
            services: vec![],
            pending_services: vec![],
            denied_services: vec![],
            transit_carrying: vec![],
            transit_awaiting_approval: false,
            mesh: None,
            naming: None,
        });

    let self_name = state.public_key.as_ref().and_then(|pk| {
        directory
            .peers
            .iter()
            .find(|p| &p.pubkey == pk)
            .map(|p| p.name.clone())
    });

    let declared_names: HashSet<&str> = state
        .declared_services
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    let pending_names: HashSet<&str> = state
        .pending_services
        .iter()
        .map(|s| s.as_str())
        .collect();

    let mut services: Vec<LocalServiceView> = directory
        .services
        .iter()
        .map(|s| LocalServiceView {
            name: s.name.clone(),
            node: s.node.clone(),
            ip4: s.ip4.clone(),
            port: s.port,
            proto: s.proto,
            vip4: s.vip4.clone(),
            // This node's own declaration, where it is one: the directory
            // leaves a mapping's target address out (PLAN.md M26), and
            // `443:80/tcp` would read as this node's own port 80.
            ports: state
                .declared_services
                .iter()
                .find(|d| d.name == s.name)
                .map_or_else(|| s.port_maps(), ServiceDecl::port_maps),
            online: s.online,
            local: declared_names.contains(s.name.as_str()),
            // Always false in practice for a directory-derived entry,
            // since `list_approved` filters pending rows out before they
            // reach any node — set from the same source as the local
            // branch below so the two cannot drift.
            pending: pending_names.contains(s.name.as_str()),
        })
        .collect();

    let known_names: HashSet<String> = services.iter().map(|s| s.name.clone()).collect();
    for d in &state.declared_services {
        if !known_names.contains(&d.name) {
            services.push(LocalServiceView {
                name: d.name.clone(),
                node: self_name.clone().unwrap_or_else(|| "self".to_string()),
                ip4: state.ip4.clone().unwrap_or_default(),
                port: d.port,
                proto: d.proto,
                // The address a pending declaration will have, if the
                // coordinator already said.
                vip4: directory
                    .pending_services
                    .iter()
                    .find(|p| p.name == d.name)
                    .and_then(|p| p.vip4.clone()),
                ports: d.port_maps(),
                online: false,
                local: true,
                pending: pending_names.contains(d.name.as_str()),
            });
        }
    }

    ListView {
        instance: ctx.instance.clone(),
        ifname: ctx.ifname.clone(),
        node: self_name,
        transit_capable: state.transit_capable,
        transit_carrying: directory.transit_carrying.clone(),
        // Only meaningful while opted in: the directory can be one poll
        // older than a `transit off` issued since.
        transit_awaiting_approval: state.transit_capable && directory.transit_awaiting_approval,
        service_domain: directory.naming.as_ref().map(|n| n.domain.clone()),
        peers: directory.peers,
        tunnel: vec![],
        services,
        rejected_services: state.rejected_services.clone(),
    }
}

/// Handles one already-parsed request. Returns the response and whether a
/// shutdown (from `leave`) should be signalled after it's sent.
async fn dispatch(ctx: &AgentContext, req: IpcRequest) -> (IpcResponse, bool) {
    match req {
        IpcRequest::Serve { name, port, proto, ports }
        | IpcRequest::ServeForwarding { name, port, proto, ports } => {
            if !wireserve_types::is_valid_dns_label(&name) {
                return (
                    IpcResponse::error(format!("invalid service name: {name}")),
                    false,
                );
            }
            let ports = if ports.is_empty() { vec![PortMap::identity(port, proto)] } else { ports };
            if let Err(e) = wireserve_types::validate_service_ports(&ports) {
                return (IpcResponse::error(e), false);
            }
            let mut state = ctx.state.lock().await;
            // A target address inside the mesh (PLAN.md M26) would be
            // forwarding from the mesh back into it — transit, which has
            // its own opt-in and its own rules. The node's own address is
            // what the plain form already means.
            let own = state.ip4.as_deref().and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok());
            let ranges = state.mesh.as_ref().and_then(wireserve_types::MeshRanges::parse);
            if let Some(m) = ports.iter().find(|m| {
                m.addr.is_some_and(|a| Some(a) == own || ranges.is_some_and(|r| r.contains4(a)))
            }) {
                return (
                    IpcResponse::error(format!(
                        "{m}: the target address is inside the mesh; a service on this node is \
                         `[PUBLIC:]TARGET` without an address, and another node serves its own"
                    )),
                    false,
                );
            }
            // A target answers for one mapping per node; see
            // `validate_node_targets`. Checked for this declaration against
            // the ones it would sit beside (not its own old version), and
            // only for this one: a state file from before port mappings can
            // hold two names aliasing one port, and refusing every later
            // `serve` over that would leave no way to fix it but `unserve`.
            if let Err(e) = wireserve_types::validate_node_targets(ports.iter().map(|m| (name.as_str(), m))) {
                return (IpcResponse::error(e), false);
            }
            for d in state.declared_services.iter().filter(|d| d.name != name) {
                for theirs in d.port_maps() {
                    if let Some(m) = ports.iter().find(|m| wireserve_types::same_target(m, &theirs)) {
                        return (
                            IpcResponse::error(format!(
                                "target {} is already mapped by '{}'",
                                wireserve_types::target_label(m),
                                d.name
                            )),
                            false,
                        );
                    }
                }
            }
            // Enforce the coordinator's own per-node limit here too, on
            // the count this declaration would produce. A limit checked
            // only at the coordinator is not a limit, it is a trap: the
            // over-long list is persisted locally and resent verbatim on
            // every cycle, so every future poll fails with the same 400
            // and the agent stops reconciling peers, firewall rules and
            // hosts entries entirely — the exact wedge the 409
            // service-collision path was reworked to avoid, but with no
            // way for the agent to tell which declaration to drop.
            // Refusing the 65th `serve` locally costs the operator one
            // clear error message instead.
            let would_be_new = !state.declared_services.iter().any(|d| d.name == name);
            if would_be_new && state.declared_services.len() >= wireserve_types::MAX_SERVICES_PER_NODE
            {
                return (
                    IpcResponse::error(format!(
                        "this node already declares {} services, which is the limit \
                         ({}); withdraw one with `wireserve-agent unserve <name>` first",
                        state.declared_services.len(),
                        wireserve_types::MAX_SERVICES_PER_NODE
                    )),
                    false,
                );
            }
            state.declared_services.retain(|d| d.name != name);
            // A fresh `serve` for a previously-rejected name deserves a
            // clean retry, not a stale "rejected" annotation hanging
            // around until the next poll cycle re-evaluates it. The same
            // goes for a stale "waiting on approval" marker.
            state.rejected_services.retain(|r| r.name != name);
            state.pending_services.retain(|n| n != &name);
            state.declared_services.push(ServiceDecl::new(name, ports));
            match state.save(&ctx.state_path) {
                Ok(()) => (IpcResponse::Ok, false),
                Err(e) => (IpcResponse::error(e.to_string()), false),
            }
        }
        IpcRequest::Unserve { name } => {
            let mut state = ctx.state.lock().await;
            state.declared_services.retain(|d| d.name != name);
            match state.save(&ctx.state_path) {
                Ok(()) => (IpcResponse::Ok, false),
                Err(e) => (IpcResponse::error(e.to_string()), false),
            }
        }
        IpcRequest::TransitCapable { enabled } => {
            let mut state = ctx.state.lock().await;
            state.transit_capable = enabled;
            match state.save(&ctx.state_path) {
                Ok(()) => (IpcResponse::Ok, false),
                Err(e) => (IpcResponse::error(e.to_string()), false),
            }
        }
        IpcRequest::List => {
            let mut view = {
                let state = ctx.state.lock().await;
                build_list_view(ctx, &state)
            };
            let ifname = ctx.ifname.clone();
            match tokio::task::spawn_blocking(move || crate::wg::tunnel_peers(&ifname)).await {
                Ok(Ok(tunnel)) => view.tunnel = tunnel,
                Ok(Err(e)) => tracing::debug!(error = %e, "could not read the interface for `list`"),
                Err(e) => tracing::debug!(error = %e, "interface read for `list` panicked"),
            }
            (IpcResponse::List(view), false)
        }
        IpcRequest::Leave => (IpcResponse::Ok, true),
    }
}

/// Handles a single connection end to end: read one line, parse, dispatch,
/// write one line back. Malformed input never panics and never leaves the
/// connection hanging — it always gets a clean `IpcResponse::Error`.
async fn handle_connection<S>(ctx: &AgentContext, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();

    let response = match reader.read_line(&mut line).await {
        Ok(0) => return, // client closed without sending anything
        Ok(_) => match crate::ipc::protocol::parse_request(&line) {
            Ok(req) => {
                let (resp, shutdown) = dispatch(ctx, req).await;
                if shutdown {
                    let _ = ctx.shutdown.send(()).await;
                }
                resp
            }
            Err(e) => IpcResponse::error(format!("bad request: {e}")),
        },
        Err(e) => IpcResponse::error(format!("read error: {e}")),
    };

    let mut out = serde_json::to_string(&response).unwrap_or_else(|_| {
        r#"{"status":"error","message":"internal: failed to encode response"}"#.to_string()
    });
    out.push('\n');
    let _ = write_half.write_all(out.as_bytes()).await;
}

/// Binds the socket (removing any stale one from a previous run) and
/// serves connections until the process exits. The socket and its parent
/// directory are set root-only (0700/0600) explicitly after creation,
/// rather than relying on umask.
pub async fn serve(ctx: AgentContext, socket_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
        set_mode(parent, 0o700)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    set_mode(socket_path, 0o600)?;

    loop {
        let (stream, _addr) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            handle_connection(&ctx, stream).await;
        });
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> (AgentContext, tempfile::TempDir, mpsc::Receiver<()>) {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let (tx, rx) = mpsc::channel(1);
        (
            AgentContext {
                state: Arc::new(Mutex::new(AgentState::default())),
                state_path,
                instance: "default".into(),
                ifname: "wireserve0".into(),
                shutdown: tx,
            },
            dir,
            rx,
        )
    }

    #[tokio::test]
    async fn malformed_json_gets_clean_error_response() {
        let (ctx, _dir, _rx) = test_ctx();
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client.write_all(b"not valid json at all\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Error { .. }));
    }

    #[tokio::test]
    async fn valid_json_but_unknown_op_gets_clean_error_response() {
        let (ctx, _dir, _rx) = test_ctx();
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(b"{\"op\":\"not_a_real_operation\"}\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Error { .. }));
    }

    #[tokio::test]
    async fn list_marks_a_declaration_waiting_on_approval_as_pending() {
        // Before this flag a pending service looked exactly like one from
        // a node that had not polled yet: declared locally, absent from
        // the directory. This is what tells the operator which it is.
        let (ctx, _dir, _rx) = test_ctx();
        {
            let mut state = ctx.state.lock().await;
            state.declared_services.push(ServiceDecl {
                name: "plex".into(),
                port: 32400,
                proto: wireserve_types::Proto::Tcp,
                ports: vec![],
            });
            state.pending_services.push("plex".into());
        }

        let view = build_list_view(&ctx, &*ctx.state.lock().await);
        assert_eq!(view.services.len(), 1);
        assert_eq!(view.services[0].name, "plex");
        assert!(view.services[0].local);
        assert!(view.services[0].pending, "must be distinguishable from not-yet-polled");
    }

    #[tokio::test]
    async fn list_does_not_mark_an_approved_service_as_pending() {
        let (ctx, _dir, _rx) = test_ctx();
        {
            let mut state = ctx.state.lock().await;
            state.declared_services.push(ServiceDecl {
                name: "plex".into(),
                port: 32400,
                proto: wireserve_types::Proto::Tcp,
                ports: vec![],
            });
            // Approval is observed as the name leaving pending_services.
        }

        let view = build_list_view(&ctx, &*ctx.state.lock().await);
        assert_eq!(view.services.len(), 1);
        assert!(!view.services[0].pending);
    }

    #[tokio::test]
    async fn serve_clears_a_stale_pending_marker_for_the_same_name() {
        // Same reasoning as the existing rejected_services clear: a fresh
        // `serve` deserves a clean retry, not a marker from the previous
        // declaration hanging around until the next cycle re-evaluates it.
        let (ctx, _dir, _rx) = test_ctx();
        {
            let mut state = ctx.state.lock().await;
            state.pending_services.push("plex".into());
        }

        let (resp, _) = dispatch(
            &ctx,
            IpcRequest::Serve {
                name: "plex".into(),
                port: 32400,
                proto: wireserve_types::Proto::Tcp,
                ports: vec![],
            },
        )
        .await;
        assert!(matches!(resp, IpcResponse::Ok));
        assert!(ctx.state.lock().await.pending_services.is_empty());
    }

    #[tokio::test]
    async fn serve_then_list_shows_declared_service_as_local() {
        let (ctx, _dir, _rx) = test_ctx();

        let (mut client, server) = tokio::io::duplex(8192);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(b"{\"op\":\"serve\",\"name\":\"plex\",\"port\":32400,\"proto\":\"tcp\"}\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Ok));

        let (mut client, server) = tokio::io::duplex(8192);
        let ctx3 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx3, server).await });
        client.write_all(b"{\"op\":\"list\"}\n").await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        match resp {
            IpcResponse::List(view) => {
                assert_eq!(view.services.len(), 1);
                assert_eq!(view.services[0].name, "plex");
                assert!(view.services[0].local);
            }
            other => panic!("expected List, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unserve_removes_previously_declared_service() {
        let (ctx, _dir, _rx) = test_ctx();
        {
            let mut state = ctx.state.lock().await;
            state.declared_services.push(ServiceDecl {
                name: "plex".into(),
                port: 32400,
                proto: wireserve_types::Proto::Tcp,
                ports: vec![],
            });
        }

        let (mut client, server) = tokio::io::duplex(8192);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(b"{\"op\":\"unserve\",\"name\":\"plex\"}\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Ok));

        let state = ctx.state.lock().await;
        assert!(state.declared_services.is_empty());
    }

    #[tokio::test]
    async fn leave_acknowledges_and_signals_shutdown() {
        let (ctx, _dir, mut rx) = test_ctx();
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client.write_all(b"{\"op\":\"leave\"}\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Ok));

        rx.recv().await.expect("shutdown signal must be sent");
    }

    #[tokio::test]
    async fn serve_rejects_port_zero_without_mutating_state() {
        let (ctx, _dir, _rx) = test_ctx();
        let (mut client, server) = tokio::io::duplex(8192);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(b"{\"op\":\"serve\",\"name\":\"zero\",\"port\":0,\"proto\":\"tcp\"}\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Error { .. }));
        assert!(ctx.state.lock().await.declared_services.is_empty());
    }

    fn serve_req(name: &str, ports: &[&str]) -> IpcRequest {
        let ports: Vec<PortMap> = ports.iter().map(|p| p.parse().unwrap()).collect();
        IpcRequest::Serve {
            name: name.into(),
            port: ports[0].target,
            proto: ports[0].proto,
            ports,
        }
    }

    #[tokio::test]
    async fn serve_stores_every_port_mapping() {
        let (ctx, _dir, _rx) = test_ctx();
        let (resp, _) = dispatch(&ctx, serve_req("dns", &["53/udp", "53/tcp", "8080:8000"])).await;
        assert!(matches!(resp, IpcResponse::Ok), "{resp:?}");
        let state = ctx.state.lock().await;
        let d = &state.declared_services[0];
        assert_eq!(d.port_maps().iter().map(ToString::to_string).collect::<Vec<_>>(), ["53/udp", "53/tcp", "8080:8000/tcp"]);
        // What an old coordinator reads.
        assert_eq!((d.port, d.proto), (53, wireserve_types::Proto::Udp));
    }

    #[tokio::test]
    async fn serve_refuses_a_target_port_another_service_maps() {
        let (ctx, _dir, _rx) = test_ctx();
        assert!(matches!(dispatch(&ctx, serve_req("web", &["80:5080"])).await.0, IpcResponse::Ok));
        let (resp, _) = dispatch(&ctx, serve_req("api", &["8080:5080"])).await;
        assert!(matches!(&resp, IpcResponse::Error { message } if message.contains("'web'")), "{resp:?}");
        // Same port, other protocol: a different socket, fine.
        assert!(matches!(dispatch(&ctx, serve_req("api", &["8080:5080/udp"])).await.0, IpcResponse::Ok));
        // Re-declaring a service may reuse its own old targets.
        assert!(matches!(dispatch(&ctx, serve_req("web", &["8081:5080"])).await.0, IpcResponse::Ok));
        assert_eq!(ctx.state.lock().await.declared_services.len(), 2);
    }

    fn forward_req(name: &str, ports: &[&str]) -> IpcRequest {
        let IpcRequest::Serve { name, port, proto, ports } = serve_req(name, ports) else { unreachable!() };
        IpcRequest::ServeForwarding { name, port, proto, ports }
    }

    #[tokio::test]
    async fn serve_forwarding_stores_the_target_address() {
        let (ctx, _dir, _rx) = test_ctx();
        let (resp, _) = dispatch(&ctx, forward_req("myrouter", &["443:192.168.178.1:80"])).await;
        assert!(matches!(resp, IpcResponse::Ok), "{resp:?}");
        let state = ctx.state.lock().await;
        assert_eq!(state.declared_services[0].port_maps()[0].to_string(), "443:192.168.178.1:80/tcp");
    }

    #[tokio::test]
    async fn the_same_port_on_another_address_is_not_a_clash() {
        let (ctx, _dir, _rx) = test_ctx();
        assert!(matches!(dispatch(&ctx, serve_req("web", &["80"])).await.0, IpcResponse::Ok));
        assert!(matches!(dispatch(&ctx, forward_req("myrouter", &["443:192.168.178.1:80"])).await.0, IpcResponse::Ok));
        let (resp, _) = dispatch(&ctx, forward_req("admin", &["8443:192.168.178.1:80"])).await;
        assert!(matches!(&resp, IpcResponse::Error { message } if message.contains("'myrouter'")), "{resp:?}");
    }

    #[tokio::test]
    async fn serve_refuses_a_target_address_inside_the_mesh() {
        let (ctx, _dir, _rx) = test_ctx();
        {
            let mut s = ctx.state.lock().await;
            s.ip4 = Some("10.90.0.7".into());
            s.mesh = Some(wireserve_types::MeshInfo {
                net_v4_cidr: "10.90.0.0/24".into(),
                net_v6_prefix: "fd00:90::/64".into(),
            });
        }
        for target in ["443:10.90.0.7:80", "443:10.90.0.9:80"] {
            let (resp, _) = dispatch(&ctx, forward_req("x", &[target])).await;
            assert!(matches!(&resp, IpcResponse::Error { message } if message.contains("inside the mesh")), "{target}: {resp:?}");
        }
        assert!(ctx.state.lock().await.declared_services.is_empty());
    }

    #[test]
    fn a_daemon_from_before_target_addresses_cannot_read_serve_forwarding() {
        // Its request enum had no such op: it answers "bad request" rather
        // than dropping the address and mapping onto its own port.
        let text = serde_json::to_string(&forward_req("myrouter", &["443:192.168.178.1:80"])).unwrap();
        assert!(text.contains(r#""op":"serve_forwarding""#), "{text}");
    }

    #[tokio::test]
    async fn serve_refuses_a_public_port_mapped_twice() {
        let (ctx, _dir, _rx) = test_ctx();
        let (resp, _) = dispatch(&ctx, serve_req("web", &["80:5080", "80:6080"])).await;
        assert!(matches!(resp, IpcResponse::Error { .. }));
        assert!(ctx.state.lock().await.declared_services.is_empty());
    }

    #[tokio::test]
    async fn serve_from_an_old_cli_is_its_identity_mapping() {
        let (ctx, _dir, _rx) = test_ctx();
        let req = crate::ipc::protocol::parse_request(r#"{"op":"serve","name":"plex","port":32400,"proto":"tcp"}"#).unwrap();
        assert!(matches!(dispatch(&ctx, req).await.0, IpcResponse::Ok));
        let state = ctx.state.lock().await;
        assert_eq!(state.declared_services[0].port_maps(), vec![PortMap::identity(32400, wireserve_types::Proto::Tcp)]);
    }

    #[tokio::test]
    async fn serve_refuses_to_exceed_the_coordinators_per_node_service_limit() {
        // Going over the limit locally would be persisted and resent on
        // every poll, and the coordinator's 400 carries no
        // `conflicting_service` field for the agent to quarantine — so
        // every subsequent cycle would fail identically and the agent
        // would stop reconciling anything at all.
        let (ctx, _dir, _rx) = test_ctx();
        {
            let mut state = ctx.state.lock().await;
            for i in 0..wireserve_types::MAX_SERVICES_PER_NODE {
                state.declared_services.push(ServiceDecl {
                    name: format!("svc-{i}"),
                    port: 1000,
                    proto: wireserve_types::Proto::Tcp,
                    ports: vec![],
                });
            }
        }

        let (mut client, server) = tokio::io::duplex(8192);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(b"{\"op\":\"serve\",\"name\":\"one-too-many\",\"port\":1,\"proto\":\"tcp\"}\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Error { .. }));

        let state = ctx.state.lock().await;
        assert_eq!(
            state.declared_services.len(),
            wireserve_types::MAX_SERVICES_PER_NODE
        );
        assert!(!state.declared_services.iter().any(|d| d.name == "one-too-many"));
    }

    #[tokio::test]
    async fn serve_can_still_update_an_existing_service_when_at_the_limit() {
        // Re-declaring a name already present replaces it rather than
        // growing the list, so it must not be refused at the limit.
        let (ctx, _dir, _rx) = test_ctx();
        {
            let mut state = ctx.state.lock().await;
            for i in 0..wireserve_types::MAX_SERVICES_PER_NODE {
                state.declared_services.push(ServiceDecl {
                    name: format!("svc-{i}"),
                    port: 1000,
                    proto: wireserve_types::Proto::Tcp,
                    ports: vec![],
                });
            }
        }

        let (mut client, server) = tokio::io::duplex(8192);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(b"{\"op\":\"serve\",\"name\":\"svc-0\",\"port\":2000,\"proto\":\"tcp\"}\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Ok));

        let state = ctx.state.lock().await;
        assert_eq!(
            state.declared_services.len(),
            wireserve_types::MAX_SERVICES_PER_NODE
        );
        assert_eq!(
            state
                .declared_services
                .iter()
                .find(|d| d.name == "svc-0")
                .unwrap()
                .port,
            2000
        );
    }

    #[tokio::test]
    async fn serve_rejects_invalid_service_name_without_mutating_state() {
        let (ctx, _dir, _rx) = test_ctx();
        let (mut client, server) = tokio::io::duplex(8192);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(b"{\"op\":\"serve\",\"name\":\"Bad_Name\",\"port\":1,\"proto\":\"tcp\"}\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp: IpcResponse = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(matches!(resp, IpcResponse::Error { .. }));

        let state = ctx.state.lock().await;
        assert!(state.declared_services.is_empty());
    }
}
