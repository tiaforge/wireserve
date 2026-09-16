use clap::{Parser, Subcommand};
use wireserve_admin::client::AdminClient;
use wireserve_admin::config;
use wireserve_types::NodeKind;

#[derive(Parser)]
#[command(name = "wireserve-admin")]
struct Cli {
    /// Coordinator base URL (e.g. https://wireserve.example.com), or set
    /// WIRESERVE_COORDINATOR_URL.
    #[arg(long, global = true)]
    coordinator_url: Option<String>,
    /// Admin bearer token, or set WIRESERVE_ADMIN_TOKEN, or write one to
    /// ~/.config/wireserve-admin/admin_token.
    #[arg(long, global = true)]
    admin_token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a node record and issue a one-time join token (spec §4.1).
    CreateNode {
        name: String,
        #[arg(long, default_value = "agent")]
        kind: String,
    },
    /// Revoke a node — its bearer token stops working on its very next
    /// poll, and its services are removed (spec §4.4).
    Revoke { name: String },
    /// Issue a fresh join token for an existing node record (spec §4.5).
    Rejoin { name: String },
    /// List the full peer directory (spec §4.5.1).
    ListPeers,
    /// Generate a WireGuard .conf for an agent-less consumer-only device
    /// (spec §9).
    ExportConfig {
        name: String,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let Cli {
        coordinator_url,
        admin_token,
        command,
    } = cli;

    match command {
        Command::CreateNode { name, kind } => {
            check_name(&name)?;
            let kind: NodeKind = kind.parse()?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_create_node(&client, &name, kind)?;
            println!("node '{}' created — join token: {}", resp.name, resp.join_token);
        }
        Command::Revoke { name } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_revoke(&client, &name)?;
            println!("node '{name}' revoked");
        }
        Command::Rejoin { name } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_rejoin(&client, &name)?;
            println!(
                "node '{}' rejoined — new join token: {}",
                resp.name, resp.join_token
            );
        }
        Command::ListPeers => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_list_peers(&client)?;
            for p in resp.peers {
                println!(
                    "{}\t{}\t{}\t{}\tendpoint={}",
                    p.name,
                    p.pubkey,
                    p.ip4,
                    p.ip6,
                    p.endpoint_addr.as_deref().unwrap_or("-")
                );
            }
        }
        Command::ExportConfig { name, out } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let conf = wireserve_admin::cmd_export_config(&client, &name)?;
            match out {
                Some(path) => std::fs::write(path, conf)?,
                None => print!("{conf}"),
            }
        }
    }
    Ok(())
}

/// Spec §3: fail fast on an obviously invalid name before resolving config
/// or making any network call.
fn check_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if wireserve_types::is_valid_dns_label(name) {
        Ok(())
    } else {
        Err(format!("invalid name: {name}").into())
    }
}

fn build_client(
    coordinator_url: &Option<String>,
    admin_token: &Option<String>,
) -> Result<AdminClient, Box<dyn std::error::Error>> {
    let url = config::resolve_coordinator_url(coordinator_url.as_deref())?;
    let token = config::resolve_admin_token(admin_token.as_deref())?;
    Ok(AdminClient::new(url, token))
}
