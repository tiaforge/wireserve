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
        /// Prompted for if omitted and running interactively.
        coordinator_url: Option<String>,
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

/// Initialises logging with `info` as the floor rather than tracing's own
/// default.
///
/// `tracing_subscriber::fmt::init()` builds an `EnvFilter` from `RUST_LOG`,
/// and an unset `RUST_LOG` yields a filter that passes `ERROR` only. That
/// is a reasonable default for a library and the wrong one here: this is a
/// daemon whose whole job is to notice things, and its warnings are how
/// an operator learns that the firewall backend was compiled out, that a
/// directory entry was refused, or that poll cycles have been failing for
/// an hour. Filtered out by default, a silent agent and a working one look
/// identical. `RUST_LOG`
/// still overrides this in either direction.
fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[tokio::main]
async fn main() {
    init_logging();
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
    coordinator_url: Option<String>,
    join_token: Option<String>,
    join_token_file: Option<std::path::PathBuf>,
    listen_port: u16,
    endpoint_addr: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let coordinator_url = resolve_coordinator_url(coordinator_url)?;
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

/// Whether stdin is an interactive terminal — the gate for every prompt
/// `join` can make. A script or CI invocation (stdin redirected from a
/// file, closed, or piped) never blocks waiting for input: it hits the
/// same error it always did.
fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Resolves the coordinator URL: the positional argument if given,
/// otherwise a prompt when running interactively, otherwise a clear error.
fn resolve_coordinator_url(
    positional: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(url) = positional {
        if !url.is_empty() {
            return Ok(url);
        }
    }
    if is_interactive() {
        eprint!("Coordinator URL (e.g. https://wireserve.example.com): ");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let url = line.trim().to_string();
        if !url.is_empty() {
            return Ok(url);
        }
    }
    Err("no coordinator URL given — pass it as an argument".into())
}

/// Resolves the join token from (in order): `--join-token-file`, the
/// positional argument being literally `-` (read one line from stdin), the
/// positional argument itself, or — running interactively, with neither of
/// those given — a masked prompt. Security review S7.
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
        None => {
            if is_interactive() {
                let token = rpassword::prompt_password(
                    "Join token (from 'wireserve-admin create-node'): ",
                )?;
                let token = token.trim().to_string();
                if !token.is_empty() {
                    return Ok(token);
                }
            }
            Err("no join token given — pass it as an argument, '-' to read from stdin, \
                 or --join-token-file <path>"
                .into())
        }
    }
}

async fn cmd_daemon(poll_interval_secs: u64, ifname: String) -> Result<(), Box<dyn std::error::Error>> {
    let state_path = paths::state_path();
    let state = AgentState::load(&state_path)?;
    if state.bearer_token.is_none() {
        return Err("not registered — run `wireserve-agent join` first".into());
    }

    let mut wg = WgInterface::new(&ifname)?;
    let ip4: std::net::Ipv4Addr = state.ip4.clone().unwrap_or_default().parse()?;
    let ip6: std::net::Ipv6Addr = state.ip6.clone().unwrap_or_default().parse()?;
    let listen_port = state.listen_port.unwrap_or(51820);
    let private_key = state.private_key.clone().unwrap_or_default();

    #[cfg(target_os = "linux")]
    let mut fw = firewall::nftables::NftablesBackend::new(ifname.clone())?;
    #[cfg(not(target_os = "linux"))]
    let mut fw = NoopFirewall;

    // Spec §5: teardown-then-deny-all must run before the first successful
    // apply() from a poll response — the interface must never come up
    // permissive-by-default.
    //
    // Ordered strictly before `bring_up`, not merely before the first
    // poll. The rules are matched on the interface *name*
    // (`meta iifname`), which nftables is happy to accept for a name that
    // does not exist yet, so there is no reason to let the interface
    // exist for even an instant without its default-deny in place. The
    // previous order happened to be safe — a freshly configured
    // interface has no peers, so the kernel drops everything inbound
    // anyway — but that is a property of WireGuard's own behaviour rather
    // than of the guarantee spec §5 asks for, and it would quietly stop
    // holding if bring-up ever restored a peer set.
    firewall::startup_sequence(&mut fw).map_err(|e| e.to_string())?;

    wg.bring_up(&private_key, ip4, ip6, listen_port)?;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    // F1 (security review, round 2): exactly ONE in-memory copy of the
    // agent state, shared by the poll loop and the IPC server. The
    // previous design kept two copies and re-synced them at cycle
    // boundaries, which still silently dropped any `serve`/`unserve`
    // issued while a poll request was in flight (the copy-back after the
    // poll overwrote it).
    let coordinator_url = state.coordinator_url.clone().unwrap_or_default();
    let shared_state = Arc::new(Mutex::new(state));
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

    // A bounded timeout so a hung coordinator connection can never pin the
    // poll loop (and with it `leave`, which is handled by the same
    // `select!`) indefinitely.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let hosts_path = paths::hosts_path();
    let mut interval = tokio::time::interval(Duration::from_secs(poll_interval_secs));

    // F9 follow-up: how many 401s in a row it takes before the daemon
    // concludes it has really been revoked. A single 401 could also be a
    // coordinator momentarily running against the wrong database (a
    // restore from backup, a wiped volume) — tearing the whole mesh down
    // on the first one would turn that operator mistake into every node
    // dropping off at once. Three consecutive 401s (about a minute at the
    // default interval) is still a tight bound for a genuine revoke.
    const UNAUTHORIZED_STREAK_TO_TEARDOWN: u32 = 3;
    let mut unauthorized_streak: u32 = 0;

    // SIGTERM (systemd stop) / SIGINT: tear down the interface, firewall
    // table and hosts block the same way `leave` does, but keep the state
    // file (bearer token, keys, last directory) intact — a stopped daemon
    // isn't maintaining/reconciling/firewalling anything, so it shouldn't
    // leave a live-looking `wg0` sitting on the host. The next `daemon`
    // start rejoins the mesh with the same identity, without needing
    // `join` again.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = async { tokio::select! { _ = sigterm.recv() => {}, _ = tokio::signal::ctrl_c() => {} } } => {
                tracing::info!("termination signal received — tearing down");
                teardown_everything(&mut fw, &mut wg, &hosts_path, &socket_path, &shared_state, &state_path, false).await;
                break;
            }
            _ = interval.tick() => {
                let mut ctx = poll_loop::PollContext {
                    client: &client,
                    coordinator_url: &coordinator_url,
                    hosts_path: &hosts_path,
                    wg: &mut wg,
                    firewall: &mut fw,
                };
                let result = poll_loop::run_once(&mut ctx, &shared_state).await;

                match result {
                    Ok(_) => {
                        unauthorized_streak = 0;
                        tracing::info!("poll cycle succeeded");
                    }
                    Err(e) if e.is_unauthorized() => {
                        unauthorized_streak += 1;
                        if unauthorized_streak < UNAUTHORIZED_STREAK_TO_TEARDOWN {
                            tracing::warn!(
                                streak = unauthorized_streak,
                                "poll rejected with 401 — will tear down after {} consecutive",
                                UNAUTHORIZED_STREAK_TO_TEARDOWN
                            );
                            continue;
                        }
                        // F9: a sustained 401 means this node's bearer
                        // token no longer works — a revoke. Retrying
                        // forever with a dead token and a stale peer set
                        // serves no purpose; tear down the interface,
                        // firewall, hosts block and socket the same way
                        // `leave` does, and stop. Unlike `leave`, the
                        // state file (keys, last directory) is kept, so an
                        // operator can inspect what the node last saw and
                        // nothing irreversible happens from the daemon's
                        // side; `join` with a fresh token from
                        // `wireserve-admin rejoin` overwrites it anyway.
                        tracing::error!(
                            "poll rejected with 401 {} times in a row — this node has been \
                             revoked; tearing down and stopping (run `wireserve-agent join` \
                             again with a fresh token from `wireserve-admin rejoin` to rejoin)",
                            UNAUTHORIZED_STREAK_TO_TEARDOWN
                        );
                        teardown_everything(&mut fw, &mut wg, &hosts_path, &socket_path, &shared_state, &state_path, false).await;
                        break;
                    }
                    Err(e) => tracing::error!(error = %e, "poll cycle failed, will retry next interval"),
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("leave requested, tearing down");
                teardown_everything(&mut fw, &mut wg, &hosts_path, &socket_path, &shared_state, &state_path, true).await;
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
    state: &Mutex<AgentState>,
    state_path: &std::path::Path,
    reset_state: bool,
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
    // On an explicit `leave`, reset local state (bearer token, keys,
    // declared services) rather than leaving secrets for a node that no
    // longer considers itself part of the mesh sitting on disk
    // indefinitely. The revoked-node path deliberately keeps it.
    if !reset_state {
        return;
    }
    let mut state = state.lock().await;
    *state = AgentState::default();
    if let Err(e) = state.save(state_path) {
        tracing::warn!(error = %e, "failed to reset local state during teardown");
    }
}

async fn cmd_serve(name: String, port: u16, proto: String) -> Result<(), Box<dyn std::error::Error>> {
    let proto: Proto = proto.parse().map_err(|e: String| e)?;
    let resp = client::call(&paths::socket_path(), &IpcRequest::Serve { name, port, proto }).await?;
    // "ok" alone overstates what just happened: the declaration is queued
    // locally and only reaches the coordinator on the next poll, and if
    // that coordinator requires approval it will sit pending until an
    // admin acts. The agent cannot know which until it polls, so say what
    // is actually true and point at where the answer shows up.
    if matches!(resp, wireserve_agent::ipc::IpcResponse::Ok) {
        println!("ok — queued; takes effect on the next poll");
        println!(
            "  if this coordinator requires admin approval, `wireserve-agent list` will show \
             it as pending until an admin approves it"
        );
        return Ok(());
    }
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

/// Used only on non-Linux targets, where there is no nftables backend —
/// never a supported production configuration, just keeps `daemon`
/// linkable there.
#[cfg(not(target_os = "linux"))]
struct NoopFirewall;

#[cfg(not(target_os = "linux"))]
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

    // ---- resolve_coordinator_url ----

    #[test]
    fn resolve_coordinator_url_uses_positional_when_given() {
        let url = resolve_coordinator_url(Some("https://wireserve.example.com".into())).unwrap();
        assert_eq!(url, "https://wireserve.example.com");
    }

    #[test]
    fn resolve_coordinator_url_errors_when_nothing_given_and_not_interactive() {
        assert!(!is_interactive(), "cargo test's stdin should never be a tty");
        assert!(resolve_coordinator_url(None).is_err());
    }
}
