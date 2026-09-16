use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::sync::{mpsc, Mutex};
use wireserve_agent::ipc::{client, protocol::IpcRequest, AgentContext};
use wireserve_agent::state::AgentState;
use wireserve_agent::{firewall, paths, poll_loop, register, wg::WgInterface};
use wireserve_types::{FirewallBackend, Proto};

#[derive(Parser)]
#[command(name = "wireserve-agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// One-time bootstrap: redeem a join token issued by `wireserve-admin
    /// create-node`, generating this node's keypair locally.
    Join {
        coordinator_url: String,
        /// The join token, or `-` to read it from stdin. Security review
        /// S7: a token passed directly on the command line lands in shell
        /// history and is visible to any local user via `ps` for as long
        /// as the process is alive — prefer `-` (piped in) or
        /// `--join-token-file` when that matters.
        join_token: Option<String>,
        /// Read the join token from this file instead of the command line
        /// or stdin (S7) — trailing whitespace/newline is trimmed.
        #[arg(long, conflicts_with = "join_token")]
        join_token_file: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = 51820)]
        listen_port: u16,
        #[arg(long)]
        endpoint_addr: Option<String>,
    },
    /// Runs the poll loop and IPC server. This is the long-running daemon.
    Daemon {
        #[arg(long, default_value_t = 20)]
        poll_interval_secs: u64,
        #[arg(long, default_value = "wg0")]
        ifname: String,
    },
    /// Queues a local service declaration, applied on the next poll.
    Serve {
        name: String,
        port: u16,
        #[arg(default_value = "tcp")]
        proto: String,
    },
    /// Queues a local service withdrawal, applied on the next poll.
    Unserve { name: String },
    /// Reads locally cached state — no network call.
    List,
    /// Tears down the interface, firewall, and hosts-file block.
    Leave,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Join {
            coordinator_url,
            join_token,
            join_token_file,
            listen_port,
            endpoint_addr,
        } => cmd_join(coordinator_url, join_token, join_token_file, listen_port, endpoint_addr).await,
        Command::Daemon {
            poll_interval_secs,
            ifname,
        } => cmd_daemon(poll_interval_secs, ifname).await,
        Command::Serve { name, port, proto } => cmd_serve(name, port, proto).await,
        Command::Unserve { name } => cmd_unserve(name).await,
        Command::List => cmd_list().await,
        Command::Leave => cmd_leave().await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_join(
    coordinator_url: String,
    join_token: Option<String>,
    join_token_file: Option<std::path::PathBuf>,
    listen_port: u16,
    endpoint_addr: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let join_token = resolve_join_token(join_token, join_token_file)?;
    let state = register::join(register::JoinParams {
        coordinator_url: &coordinator_url,
        join_token: &join_token,
        listen_port,
        endpoint_addr,
    })
    .await?;
    println!(
        "joined as ip4={} ip6={}",
        state.ip4.unwrap_or_default(),
        state.ip6.unwrap_or_default()
    );
    Ok(())
}

/// Resolves the join token from (in order): `--join-token-file`, the
/// positional argument being literally `-` (read one line from stdin), or
/// the positional argument itself. Security review S7.
fn resolve_join_token(
    positional: Option<String>,
    file: Option<std::path::PathBuf>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = file {
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read join token file {}: {e}", path.display()))?;
        return Ok(contents.trim().to_string());
    }
    match positional.as_deref() {
        Some("-") => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(line.trim().to_string())
        }
        Some(token) => Ok(token.to_string()),
        None => Err("no join token given — pass it as an argument, '-' to read from stdin, \
                      or --join-token-file <path>"
            .into()),
    }
}

async fn cmd_daemon(poll_interval_secs: u64, ifname: String) -> Result<(), Box<dyn std::error::Error>> {
    let state_path = paths::state_path();
    let mut state = AgentState::load(&state_path)?;
    if state.bearer_token.is_none() {
        return Err("not registered — run `wireserve-agent join` first".into());
    }

    let mut wg = WgInterface::new(&ifname)?;
    let ip4: std::net::Ipv4Addr = state.ip4.clone().unwrap_or_default().parse()?;
    let ip6: std::net::Ipv6Addr = state.ip6.clone().unwrap_or_default().parse()?;
    let listen_port = state.listen_port.unwrap_or(51820);
    let private_key = state.private_key.clone().unwrap_or_default();
    wg.bring_up(&private_key, ip4, ip6, listen_port)?;

    #[cfg(all(feature = "nftables", target_os = "linux"))]
    let mut fw = firewall::nftables::NftablesBackend::new(ifname.clone());
    #[cfg(not(all(feature = "nftables", target_os = "linux")))]
    let mut fw = NoopFirewall;

    // Spec §5: teardown-then-deny-all must run before the first successful
    // apply() from a poll response — the interface must never come up
    // permissive-by-default.
    firewall::startup_sequence(&mut fw).map_err(|e| e.to_string())?;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    let shared_state = Arc::new(Mutex::new(state.clone()));
    let ipc_ctx = AgentContext {
        state: shared_state.clone(),
        state_path: state_path.clone(),
        shutdown: shutdown_tx,
    };
    let socket_path = paths::socket_path();
    let ipc_socket_path = socket_path.clone();
    tokio::spawn(async move {
        if let Err(e) = wireserve_agent::ipc::server::serve(ipc_ctx, &ipc_socket_path).await {
            tracing::error!(error = %e, "IPC server exited");
        }
    });

    let client = reqwest::Client::new();
    let coordinator_url = state.coordinator_url.clone().unwrap_or_default();
    let hosts_path = paths::hosts_path();
    let mut interval = tokio::time::interval(Duration::from_secs(poll_interval_secs));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Pull in any serve/unserve queued via IPC since the last cycle.
                {
                    let shared = shared_state.lock().await;
                    state.declared_services = shared.declared_services.clone();
                }
                let bearer_token = state.bearer_token.clone().unwrap_or_default();
                let mut ctx = poll_loop::PollContext {
                    client: &client,
                    coordinator_url: &coordinator_url,
                    bearer_token: &bearer_token,
                    hosts_path: &hosts_path,
                    wg: &mut wg,
                    firewall: &mut fw,
                };
                let result = poll_loop::run_once(&mut ctx, &mut state).await;

                // F1 (security review): this cycle's outcome — including
                // any F3 quarantine of a rejected declaration — must reach
                // the copy `wireserve list` actually reads from over IPC.
                // The two used to be separate clones that never
                // resynchronized, so `list` always reported stale/empty
                // data regardless of what polling actually did.
                *shared_state.lock().await = state.clone();

                match result {
                    Ok(_) => tracing::info!("poll cycle succeeded"),
                    Err(e) if e.is_unauthorized() => {
                        // F9: a 401 means this node's bearer token no
                        // longer works — almost always a revoke. Retrying
                        // forever with a dead token and a stale peer set
                        // serves no purpose; tear down the same way
                        // `leave` does and stop, rather than silently
                        // spinning. An operator can `join` again (with a
                        // fresh token from `wireserve-admin rejoin`) to
                        // come back.
                        tracing::error!(
                            "poll rejected with 401 — this node appears to have been revoked; \
                             tearing down and stopping (run `wireserve-agent join` again with a \
                             fresh token from `wireserve-admin rejoin` to rejoin)"
                        );
                        teardown_everything(&mut fw, &mut wg, &hosts_path, &socket_path, &mut state, &state_path).await;
                        break;
                    }
                    Err(e) => tracing::error!(error = %e, "poll cycle failed, will retry next interval"),
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("leave requested, tearing down");
                teardown_everything(&mut fw, &mut wg, &hosts_path, &socket_path, &mut state, &state_path).await;
                break;
            }
        }
    }

    Ok(())
}

/// Shared by both the `leave` IPC path and F9's revoked-node auto-teardown:
/// removes the managed hosts-file block, the firewall table, the
/// WireGuard interface, the IPC socket, and resets local state to a clean
/// default (security review F2 — spec §4.6 says `leave` "tears down
/// interface, firewall, hosts block," but the original implementation did
/// only the last two; the socket and lingering secrets in state were also
/// flagged). Every step best-effort: a failure partway through (e.g. the
/// interface already gone) must not stop the rest from running.
async fn teardown_everything<F: FirewallBackend>(
    fw: &mut F,
    wg: &mut WgInterface,
    hosts_path: &std::path::Path,
    socket_path: &std::path::Path,
    state: &mut AgentState,
    state_path: &std::path::Path,
) where
    F::Error: std::fmt::Display,
{
    if let Err(e) = wireserve_agent::hosts::remove_block(hosts_path) {
        tracing::warn!(error = %e, "failed to remove managed hosts-file block during teardown");
    }
    if let Err(e) = fw.teardown() {
        tracing::warn!(error = %e, "failed to tear down firewall rules during teardown");
    }
    if let Err(e) = wg.teardown() {
        tracing::warn!(error = %e, "failed to remove WireGuard interface during teardown");
    }
    if socket_path.exists() {
        if let Err(e) = std::fs::remove_file(socket_path) {
            tracing::warn!(error = %e, "failed to remove IPC socket during teardown");
        }
    }
    // Reset local state (bearer token, keys, declared services) rather
    // than leaving secrets for a node that no longer considers itself
    // part of the mesh sitting on disk indefinitely.
    *state = AgentState::default();
    if let Err(e) = state.save(state_path) {
        tracing::warn!(error = %e, "failed to reset local state during teardown");
    }
}

async fn cmd_serve(name: String, port: u16, proto: String) -> Result<(), Box<dyn std::error::Error>> {
    let proto: Proto = proto.parse().map_err(|e: String| e)?;
    let resp = client::call(&paths::socket_path(), &IpcRequest::Serve { name, port, proto }).await?;
    print_response(resp);
    Ok(())
}

async fn cmd_unserve(name: String) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client::call(&paths::socket_path(), &IpcRequest::Unserve { name }).await?;
    print_response(resp);
    Ok(())
}

async fn cmd_list() -> Result<(), Box<dyn std::error::Error>> {
    let resp = client::call(&paths::socket_path(), &IpcRequest::List).await?;
    match resp {
        wireserve_agent::ipc::IpcResponse::List(view) => {
            println!("{}", serde_json::to_string_pretty(&view)?);
        }
        other => print_response(other),
    }
    Ok(())
}

async fn cmd_leave() -> Result<(), Box<dyn std::error::Error>> {
    let resp = client::call(&paths::socket_path(), &IpcRequest::Leave).await?;
    print_response(resp);
    Ok(())
}

fn print_response(resp: wireserve_agent::ipc::IpcResponse) {
    match resp {
        wireserve_agent::ipc::IpcResponse::Ok => println!("ok"),
        wireserve_agent::ipc::IpcResponse::Error { message } => eprintln!("error: {message}"),
        wireserve_agent::ipc::IpcResponse::List(view) => {
            println!("{}", serde_json::to_string_pretty(&view).unwrap_or_default());
        }
    }
}

/// Used only when the real nftables backend isn't compiled in (see
/// Cargo.toml's `nftables` feature) — never a supported production
/// configuration, just keeps `daemon` linkable in that configuration.
#[cfg(not(all(feature = "nftables", target_os = "linux")))]
struct NoopFirewall;

#[cfg(not(all(feature = "nftables", target_os = "linux")))]
impl FirewallBackend for NoopFirewall {
    type Error = std::convert::Infallible;
    fn apply(&mut self, _rules: &[wireserve_types::ServiceRule]) -> Result<(), Self::Error> {
        tracing::warn!("nftables backend not compiled in — firewall rules are NOT being applied");
        Ok(())
    }
    fn teardown(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- S7: resolve_join_token ----

    #[test]
    fn resolve_join_token_prefers_file_over_positional() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "jtk_from_file\n").unwrap();

        let token = resolve_join_token(Some("jtk_positional".into()), Some(path)).unwrap();
        assert_eq!(token, "jtk_from_file");
    }

    #[test]
    fn resolve_join_token_uses_positional_when_no_file() {
        let token = resolve_join_token(Some("jtk_abc".into()), None).unwrap();
        assert_eq!(token, "jtk_abc");
    }

    #[test]
    fn resolve_join_token_errors_when_nothing_given() {
        assert!(resolve_join_token(None, None).is_err());
    }

    #[test]
    fn resolve_join_token_errors_on_unreadable_file() {
        let path = std::path::PathBuf::from("/nonexistent/path/for/test/token");
        assert!(resolve_join_token(None, Some(path)).is_err());
    }
}
