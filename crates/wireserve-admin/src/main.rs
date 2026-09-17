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
    /// Permanently delete a node record and free its name. Refused while
    /// the node is still active — revoke it first.
    DeleteNode { name: String },
    /// Clear a node's advertised endpoint address. Use when a node has
    /// lost the public address other peers were dialing (a dropped port
    /// forward, a move behind CGNAT) and is still advertising it. The
    /// node reports a new one on its next poll if it still has one set
    /// locally.
    ClearEndpoint { name: String },
    /// List the full peer directory (spec §4.5.1).
    ListPeers,
    /// Generate a WireGuard .conf for an agent-less consumer-only device
    /// (spec §9).
    ExportConfig {
        name: String,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Base URL of the coordinator's NODE-FACING listener (where
        /// /register lives) — a different address/port from
        /// --coordinator-url, which talks to the admin listener. Spec
        /// §4.0 requires the two to be bound separately. Or set
        /// WIRESERVE_REGISTER_URL.
        #[arg(long)]
        register_url: Option<String>,
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
        Command::DeleteNode { name } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_delete_node(&client, &name)?;
            println!("node '{name}' deleted");
        }
        Command::ClearEndpoint { name } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_clear_endpoint(&client, &name)?;
            println!("node '{name}' endpoint cleared");
        }
        Command::ListPeers => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_list_peers(&client)?;
            for p in resp.peers {
                // S2 defense in depth: a peer field containing a newline
                // could otherwise spoof extra lines of terminal output —
                // same "don't trust the coordinator's validation as the
                // only line of defense" reasoning as export_config's
                // renderer.
                println!(
                    "{}\t{}\t{}\t{}\tendpoint={}",
                    sanitize_for_terminal(&p.name),
                    sanitize_for_terminal(&p.pubkey),
                    sanitize_for_terminal(&p.ip4),
                    sanitize_for_terminal(&p.ip6),
                    p.endpoint_addr
                        .as_deref()
                        .map(sanitize_for_terminal)
                        .unwrap_or_else(|| "-".to_string())
                );
            }
        }
        Command::ExportConfig {
            name,
            out,
            register_url,
        } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let register_url = config::resolve_register_url(register_url.as_deref())?;
            warn_if_plaintext_to_remote_host(&register_url);
            let conf = wireserve_admin::cmd_export_config(&client, &register_url, &name)?;
            match out {
                Some(path) => write_conf_file(&path, &conf)?,
                None => print!("{conf}"),
            }
        }
    }
    Ok(())
}

/// Replaces embedded newlines/carriage returns with a visible escape
/// rather than letting them fake extra lines of terminal output (S2).
fn sanitize_for_terminal(s: &str) -> String {
    s.replace('\r', "\\r").replace('\n', "\\n")
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

/// Writes the rendered `.conf` at mode 600 from the moment of creation
/// (security review S5) — it contains a WireGuard private key, the same
/// sensitivity spec §7 requires for the agent's own local key material,
/// even though this file lives on the *admin operator's* machine rather
/// than the node's own disk that §7 literally describes.
#[cfg(unix)]
fn write_conf_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_conf_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

fn build_client(
    coordinator_url: &Option<String>,
    admin_token: &Option<String>,
) -> Result<AdminClient, Box<dyn std::error::Error>> {
    let url = config::resolve_coordinator_url(coordinator_url.as_deref())?;
    warn_if_plaintext_to_remote_host(&url);
    let token = config::resolve_admin_token(admin_token.as_deref())?;
    Ok(AdminClient::new(url, token))
}

/// Security review S6: neither client here refuses plain `http://` to a
/// non-loopback host — the admin bearer token (and, for /register, a
/// join token) would go over the wire in clear. Spec §7 assumes a
/// TLS-terminating reverse proxy sits between any real client and the
/// coordinator, so this is very likely a misconfiguration rather than an
/// intentional choice whenever the host isn't loopback. A warning rather
/// than a hard refusal: `http://127.0.0.1:...` (the loopback/docker-exec
/// pattern this project's own deploy docs recommend) is completely
/// legitimate and must keep working without a flag to silence a false
/// alarm.
fn warn_if_plaintext_to_remote_host(url: &str) {
    if wireserve_types::is_plaintext_http_to_remote_host(url) {
        eprintln!(
            "warning: sending requests to {url} over plain HTTP — the admin token (and any \
             join token) will be sent in clear over the network. Spec §7 assumes a \
             TLS-terminating reverse proxy in front of the coordinator; use an https:// URL \
             unless this really is a loopback/trusted-local connection."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_conf_file_creates_file_at_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        write_conf_file(&path, "[Interface]\nPrivateKey = secret\n").unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("PrivateKey = secret"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "exported .conf contains a private key and must be mode 600");
    }

    #[test]
    fn sanitize_for_terminal_escapes_newlines() {
        assert_eq!(sanitize_for_terminal("a\nb\rc"), "a\\nb\\rc");
        assert_eq!(sanitize_for_terminal("plain"), "plain");
    }

    #[test]
    fn warn_if_plaintext_does_not_panic_on_various_inputs() {
        // No assertions on stderr output — just confirms these don't panic
        // on malformed/edge-case URLs (empty host, https, no scheme, etc.).
        for url in ["http://127.0.0.1:8081", "https://example.com", "not-a-url", "http://"] {
            warn_if_plaintext_to_remote_host(url);
        }
    }
}
