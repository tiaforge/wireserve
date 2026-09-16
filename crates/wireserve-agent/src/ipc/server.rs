//! Unix-socket IPC server backing `serve`/`unserve`/`list`/`leave` (§4.6).
//! One request/response per connection, newline-delimited JSON.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, Mutex};
use wireserve_types::{PollResponse, ServiceDecl};

use crate::ipc::protocol::{IpcRequest, IpcResponse, ListView, LocalServiceView};
use crate::state::AgentState;

#[derive(Clone)]
pub struct AgentContext {
    pub state: Arc<Mutex<AgentState>>,
    pub state_path: PathBuf,
    /// Signalled when `leave` is requested, so the daemon's main loop (which
    /// owns the live WireGuard interface / firewall backend) can perform
    /// the actual teardown — the IPC handler itself only queues the
    /// request and acknowledges it, it doesn't own interface state.
    pub shutdown: mpsc::Sender<()>,
}

fn build_list_view(state: &AgentState) -> ListView {
    let directory = state
        .last_directory
        .clone()
        .unwrap_or(PollResponse {
            peers: vec![],
            services: vec![],
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

    let mut services: Vec<LocalServiceView> = directory
        .services
        .iter()
        .map(|s| LocalServiceView {
            name: s.name.clone(),
            node: s.node.clone(),
            ip4: s.ip4.clone(),
            port: s.port,
            proto: s.proto,
            online: s.online,
            local: declared_names.contains(s.name.as_str()),
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
                online: false,
                local: true,
            });
        }
    }

    ListView {
        peers: directory.peers,
        services,
    }
}

/// Handles one already-parsed request. Returns the response and whether a
/// shutdown (from `leave`) should be signalled after it's sent.
async fn dispatch(ctx: &AgentContext, req: IpcRequest) -> (IpcResponse, bool) {
    match req {
        IpcRequest::Serve { name, port, proto } => {
            if !wireserve_types::is_valid_dns_label(&name) {
                return (
                    IpcResponse::error(format!("invalid service name: {name}")),
                    false,
                );
            }
            let mut state = ctx.state.lock().await;
            state.declared_services.retain(|d| d.name != name);
            state.declared_services.push(ServiceDecl { name, port, proto });
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
        IpcRequest::List => {
            let state = ctx.state.lock().await;
            (IpcResponse::List(build_list_view(&state)), false)
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
