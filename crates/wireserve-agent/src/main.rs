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
        join_token: String,
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
            listen_port,
            endpoint_addr,
        } => cmd_join(coordinator_url, join_token, listen_port, endpoint_addr).await,
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
    join_token: String,
    listen_port: u16,
    endpoint_addr: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
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
    tokio::spawn(async move {
        if let Err(e) = wireserve_agent::ipc::server::serve(ipc_ctx, &socket_path).await {
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
                match poll_loop::run_once(&mut ctx, &mut state).await {
                    Ok(_) => tracing::info!("poll cycle succeeded"),
                    Err(e) => tracing::error!(error = %e, "poll cycle failed, will retry next interval"),
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("leave requested, tearing down");
                let _ = fw.teardown();
                let _ = wg.teardown();
                break;
            }
        }
    }

    Ok(())
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
