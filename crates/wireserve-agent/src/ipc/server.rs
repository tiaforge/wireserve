//! Unix-socket IPC server backing `serve`/`unserve`/`list`/`leave` (§4.6).
//! One request/response per connection, newline-delimited JSON. Who may
//! connect is decided by the socket's file permissions alone (see `serve`):
//! root, plus the members of the `wireserve` group when there is one.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Mutex};
use wireserve_types::ServiceDecl;

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
        .unwrap_or_default();

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
            vip4: s.vip4.clone(),
            // This node's own declaration, where it is one: the directory
            // leaves a mapping's target address out (PLAN.md M26), and
            // `443:80/tcp` would read as this node's own port 80.
            ports: state
                .declared_services
                .iter()
                .find(|d| d.name == s.name)
                .map_or_else(|| s.ports.clone(), |d| d.ports.clone()),
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
                // The address a pending declaration will have, if the
                // coordinator already said.
                vip4: directory
                    .pending_services
                    .iter()
                    .find(|p| p.name == d.name)
                    .and_then(|p| p.vip4.clone()),
                ports: d.ports.clone(),
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
        relay_carrying: directory.relay_carrying.clone(),
        relay_public: directory
            .relay_public
            .iter()
            .filter_map(|pk| directory.peers.iter().find(|p| &p.pubkey == pk).map(|p| p.name.clone()))
            .collect(),
        // Only meaningful while opted in: the directory can be one poll
        // older than a `transit off` issued since.
        transit_awaiting_approval: state.transit_capable && directory.transit_awaiting_approval,
        exit_capable: state.exit_capable,
        exit_clients: directory.exit_clients.clone(),
        service_domain: directory.naming.as_ref().map(|n| n.domain.clone()),
        peers: directory.peers,
        tunnel: vec![],
        services,
        rejected_services: state.rejected_services.clone(),
        service_notices: state.service_notices.clone(),
    }
}

/// Handles one already-parsed request. Returns the response and whether a
/// shutdown (from `leave`) should be signalled after it's sent.
async fn dispatch(ctx: &AgentContext, req: IpcRequest) -> (IpcResponse, bool) {
    match req {
        IpcRequest::Serve { name, ports, group } => {
            if !wireserve_types::is_valid_dns_label(&name) {
                return (
                    IpcResponse::error(format!("invalid service name: {name}")),
                    false,
                );
            }
            if let Some(g) = group.as_deref().filter(|g| !wireserve_types::is_valid_dns_label(g)) {
                return (IpcResponse::error(format!("invalid group name: {g}")), false);
            }
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
            // only for this one: a hand-edited state file can hold two names
            // aliasing one port, and refusing every later `serve` over that
            // would leave no way to fix it but `unserve`.
            if let Err(e) = wireserve_types::validate_node_targets(ports.iter().map(|m| (name.as_str(), m))) {
                return (IpcResponse::error(e), false);
            }
            for d in state.declared_services.iter().filter(|d| d.name != name) {
                for theirs in d.ports.clone() {
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
                         ({}); withdraw one with `wireserve unserve <name>` first",
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
            let mut decl = ServiceDecl::new(name, ports);
            decl.group = group;
            state.declared_services.push(decl);
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
        IpcRequest::ExitCapable { enabled } => {
            let mut state = ctx.state.lock().await;
            state.exit_capable = enabled;
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
            (IpcResponse::List(Box::new(view)), false)
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

/// The group the daemon's socket is shared with when it exists on this
/// host, and the variable that renames it (empty disables sharing).
pub const SOCKET_GROUP_ENV: &str = "WIRESERVE_SOCKET_GROUP";
pub const DEFAULT_SOCKET_GROUP: &str = "wireserve";

/// The group to share the socket with: `$WIRESERVE_SOCKET_GROUP` (default
/// `wireserve`), if that group exists. Absent means root-only, which is what
/// every deployment had before the group did, and what a container gets, as
/// it does not see the host's groups.
pub fn socket_group() -> Option<(String, u32)> {
    let name = socket_group_name()?;
    let gid = lookup_group(&name)?;
    Some((name, gid))
}

/// The configured group's name, whether or not it exists yet; `None` when
/// sharing is switched off. `install` uses it to create the group.
pub fn socket_group_name() -> Option<String> {
    match std::env::var(SOCKET_GROUP_ENV) {
        Ok(v) if v.is_empty() => None,
        Ok(v) => Some(v),
        Err(_) => Some(DEFAULT_SOCKET_GROUP.to_string()),
    }
}

/// Whether the group exists on this host.
pub fn group_exists(name: &str) -> bool {
    lookup_group(name).is_some()
}

#[cfg(unix)]
pub(crate) fn lookup_group(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 4096];
    loop {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(cname.as_ptr(), &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut out)
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            let doubled = buf.len() * 2;
            buf.resize(doubled, 0);
            continue;
        }
        return if rc == 0 && !out.is_null() { Some(grp.gr_gid) } else { None };
    }
}

#[cfg(not(unix))]
pub(crate) fn lookup_group(_name: &str) -> Option<u32> {
    None
}

/// Binds the socket (removing any stale one from a previous run) and
/// serves connections until the process exits.
///
/// With no `group` the socket and its parent directory are root-only
/// (0600/0700). With one, the same two are handed to that group (0660/0750),
/// so its members can use `wireserve serve`/`list`/... without sudo. Modes are
/// set explicitly rather than left to umask, and the directory is only
/// opened to the group after the socket is final, so there is no moment
/// when the group can reach a socket with default permissions.
pub async fn serve(ctx: AgentContext, socket_path: &Path) -> std::io::Result<()> {
    let group = socket_group();
    match &group {
        Some((name, _)) => tracing::info!(group = %name, socket = %socket_path.display(), "IPC socket shared with group"),
        None => tracing::info!(socket = %socket_path.display(), "IPC socket is root-only (no `wireserve` group)"),
    }
    let listener = bind_socket(socket_path, group.map(|(_, gid)| gid))?;

    loop {
        let (stream, _addr) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            handle_connection(&ctx, stream).await;
        });
    }
}

pub(crate) fn bind_socket(socket_path: &Path, gid: Option<u32>) -> std::io::Result<UnixListener> {
    let parent = socket_path.parent();
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent)?;
        set_mode(parent, 0o700)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    let shared = match gid {
        None => false,
        // Sharing is a convenience; failing at it (a hand-written unit
        // without CAP_CHOWN, say) must leave a working root-only socket,
        // not a daemon nobody can talk to.
        Some(gid) => match share_with_group(socket_path, parent, gid) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "could not share the IPC socket with the group; it stays root-only");
                false
            }
        },
    };
    if !shared {
        set_mode(socket_path, 0o600)?;
        if let Some(parent) = parent {
            set_mode(parent, 0o700)?;
        }
    }
    Ok(listener)
}

/// The socket first, the directory last: until the directory opens, the
/// group cannot reach the socket whatever its permissions are.
fn share_with_group(socket_path: &Path, parent: Option<&Path>, gid: u32) -> std::io::Result<()> {
    set_group(socket_path, gid)?;
    set_mode(socket_path, 0o660)?;
    if let Some(parent) = parent {
        set_group(parent, gid)?;
        set_mode(parent, 0o750)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_group(path: &Path, gid: u32) -> std::io::Result<()> {
    std::os::unix::fs::chown(path, None, Some(gid))
}

#[cfg(not(unix))]
fn set_group(_path: &Path, _gid: u32) -> std::io::Result<()> {
    Ok(())
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
    use wireserve_types::PortMap;

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
    async fn socket_without_a_group_is_root_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/agent.sock");
        let _l = bind_socket(&path, None).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[tokio::test]
    async fn socket_with_a_group_is_shared_with_exactly_that_group() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/agent.sock");
        // A group the test process may chown to without privilege.
        let gid = unsafe { libc::getegid() };
        let _l = bind_socket(&path, Some(gid)).unwrap();
        let sock = std::fs::metadata(&path).unwrap();
        let parent = std::fs::metadata(path.parent().unwrap()).unwrap();
        assert_eq!(sock.permissions().mode() & 0o777, 0o660);
        assert_eq!(parent.permissions().mode() & 0o777, 0o750);
        assert_eq!((sock.gid(), parent.gid()), (gid, gid));
    }

    #[tokio::test]
    async fn failing_to_share_leaves_a_root_only_socket_not_an_error() {
        use std::os::unix::fs::PermissionsExt;
        // Root may chown to any group, so there is nothing to fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run/agent.sock");
        // Group 0 is one an unprivileged test process is not in.
        let _l = bind_socket(&path, Some(0)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn a_missing_group_means_no_sharing() {
        assert_eq!(lookup_group("wireserve-no-such-group-xyz"), None);
        assert_eq!(lookup_group("root"), Some(0));
    }

    #[test]
    fn group_env_empty_disables_sharing() {
        // Only this test touches the variable; it restores it.
        let prev = std::env::var(SOCKET_GROUP_ENV).ok();
        std::env::set_var(SOCKET_GROUP_ENV, "");
        assert_eq!(socket_group(), None);
        std::env::set_var(SOCKET_GROUP_ENV, "root");
        assert_eq!(socket_group(), Some(("root".to_string(), 0)));
        match prev {
            Some(v) => std::env::set_var(SOCKET_GROUP_ENV, v),
            None => std::env::remove_var(SOCKET_GROUP_ENV),
        }
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
                ports: vec![],
                group: None,
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
                ports: vec![],
                group: None,
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
            IpcRequest::Serve { name: "plex".into(), ports: vec!["32400".parse().unwrap()], group: None },
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
            .write_all(b"{\"op\":\"serve\",\"name\":\"plex\",\"ports\":[{\"public\":32400,\"target\":32400,\"proto\":\"tcp\"}]}\n")
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
                ports: vec![],
                group: None,
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
        IpcRequest::Serve { name: name.into(), ports, group: None }
    }

    #[tokio::test]
    async fn serve_stores_every_port_mapping() {
        let (ctx, _dir, _rx) = test_ctx();
        let (resp, _) = dispatch(&ctx, serve_req("dns", &["53/udp", "53/tcp", "8080:8000"])).await;
        assert!(matches!(resp, IpcResponse::Ok), "{resp:?}");
        let state = ctx.state.lock().await;
        let d = &state.declared_services[0];
        assert_eq!(d.ports.iter().map(ToString::to_string).collect::<Vec<_>>(), ["53/udp", "53/tcp", "8080:8000/tcp"]);
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

    #[tokio::test]
    async fn serve_forwarding_stores_the_target_address() {
        let (ctx, _dir, _rx) = test_ctx();
        let (resp, _) = dispatch(&ctx, serve_req("myrouter", &["443:192.168.178.1:80"])).await;
        assert!(matches!(resp, IpcResponse::Ok), "{resp:?}");
        let state = ctx.state.lock().await;
        assert_eq!(state.declared_services[0].ports[0].to_string(), "443:192.168.178.1:80/tcp");
    }

    #[tokio::test]
    async fn the_same_port_on_another_address_is_not_a_clash() {
        let (ctx, _dir, _rx) = test_ctx();
        assert!(matches!(dispatch(&ctx, serve_req("web", &["80"])).await.0, IpcResponse::Ok));
        assert!(matches!(dispatch(&ctx, serve_req("myrouter", &["443:192.168.178.1:80"])).await.0, IpcResponse::Ok));
        let (resp, _) = dispatch(&ctx, serve_req("admin", &["8443:192.168.178.1:80"])).await;
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
            let (resp, _) = dispatch(&ctx, serve_req("x", &[target])).await;
            assert!(matches!(&resp, IpcResponse::Error { message } if message.contains("inside the mesh")), "{target}: {resp:?}");
        }
        assert!(ctx.state.lock().await.declared_services.is_empty());
    }

    #[tokio::test]
    async fn serve_refuses_a_public_port_mapped_twice() {
        let (ctx, _dir, _rx) = test_ctx();
        let (resp, _) = dispatch(&ctx, serve_req("web", &["80:5080", "80:6080"])).await;
        assert!(matches!(resp, IpcResponse::Error { .. }));
        assert!(ctx.state.lock().await.declared_services.is_empty());
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
                state.declared_services.push(ServiceDecl::new(
                    format!("svc-{i}"),
                    vec![PortMap::identity(3000 + i as u16, wireserve_types::Proto::Tcp)],
                ));
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
                state.declared_services.push(ServiceDecl::new(
                    format!("svc-{i}"),
                    vec![PortMap::identity(3000 + i as u16, wireserve_types::Proto::Tcp)],
                ));
            }
        }

        let (mut client, server) = tokio::io::duplex(8192);
        let ctx2 = ctx.clone();
        tokio::spawn(async move { handle_connection(&ctx2, server).await });
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client
            .write_all(b"{\"op\":\"serve\",\"name\":\"svc-0\",\"ports\":[{\"public\":2000,\"target\":2000,\"proto\":\"tcp\"}]}\n")
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
                .ports[0]
                .target,
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
