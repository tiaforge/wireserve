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
    /// Base URL of the coordinator's NODE-FACING listener (where
    /// /register lives) — a different address/port from
    /// --coordinator-url, which talks to the admin listener. Spec §4.0
    /// requires the two to be bound separately. Used by `export-config`
    /// (required) and by `create-node`/`rejoin` (optional — fills in the
    /// exact `wireserve-agent join` command they print). Or set
    /// WIRESERVE_REGISTER_URL, or write one to
    /// ~/.config/wireserve-admin/register_url.
    #[arg(long, global = true)]
    register_url: Option<String>,

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
        /// Seconds the join token stays redeemable, overriding the
        /// coordinator's default (30 minutes). Use 0 for no expiry.
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Revoke a node — its bearer token stops working on its very next
    /// poll, and its services are removed (spec §4.4).
    Revoke { name: String },
    /// Issue a fresh join token for an existing node record (spec §4.5).
    Rejoin {
        name: String,
        /// Seconds the join token stays redeemable, overriding the
        /// coordinator's default (30 minutes). Use 0 for no expiry.
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Permanently delete a node record and free its name. Refused while
    /// the node is still active — revoke it first.
    DeleteNode { name: String },
    /// Clear a node's advertised endpoint address. Use when a node has
    /// lost the public address other peers were dialing (a dropped port
    /// forward, a move behind CGNAT) and is still advertising it. The
    /// node reports a new one on its next poll if it still has one set
    /// locally.
    ClearEndpoint {
        name: String,
        /// Clear only one actively-probed candidate ("v4" or "v6"),
        /// leaving the explicit override and the other family untouched.
        /// Omit to clear everything (the explicit override plus both
        /// candidates) — today's default behavior.
        #[arg(long)]
        family: Option<String>,
    },
    /// List the full peer directory (spec §4.5.1).
    ListPeers,
    /// List every declared service and its approval state.
    ListServices {
        /// Show only declarations waiting on approval.
        #[arg(long)]
        pending: bool,
    },
    /// Approve a pending service declaration for a specific node.
    /// Approval binds to this node — it does not reserve the name for
    /// anyone else.
    ApproveService { node: String, service: String },
    /// Deny a declaration, or withdraw an approval already granted.
    ///
    /// For mistakes. For a node you no longer trust use `revoke`: a
    /// denied service still holds its globally-unique name until the
    /// declaring node withdraws it, and a compromised node will not.
    DenyService {
        node: String,
        service: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Generate a WireGuard .conf for an agent-less consumer-only device
    /// (spec §9).
    ExportConfig {
        name: String,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}

/// Prints the join token's deadline immediately under the token itself.
///
/// The operator is about to copy that token into a chat window and walk
/// to another machine; the one moment the expiry is useful is this one.
/// Discovering it instead from a `join` that fails half an hour later
/// tells them only that something is wrong, not what.
fn print_expiry(expires_at: Option<chrono::DateTime<chrono::Utc>>) {
    match expires_at {
        Some(t) => println!("  redeemable until: {}", t.to_rfc3339()),
        None => println!("  redeemable until: no expiry (token never becomes invalid on its own)"),
    }
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
        register_url,
        command,
    } = cli;

    match command {
        Command::CreateNode { name, kind, ttl } => {
            check_name(&name)?;
            let kind: NodeKind = kind.parse()?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_create_node(&client, &name, kind, ttl)?;
            println!("node '{}' created — join token: {}", resp.name, resp.join_token);
            print_expiry(resp.join_token_expires_at);
            if kind == NodeKind::Agent {
                print_join_instructions(resolve_register_url_best_effort(register_url.as_deref()));
            }
        }
        Command::Revoke { name } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_revoke(&client, &name)?;
            println!("node '{name}' revoked");
        }
        Command::Rejoin { name, ttl } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_rejoin(&client, &name, ttl)?;
            println!(
                "node '{}' rejoined — new join token: {}",
                resp.name, resp.join_token
            );
            print_expiry(resp.join_token_expires_at);
            // `rejoin`'s response doesn't carry the node's kind (unlike
            // `create-node`, which has it from the --kind flag), and a
            // static peer's `export-config` covers its own re-registration
            // anyway — an operator rejoining a static node manually is not
            // a case this needs to guess at, so this always assumes agent.
            print_join_instructions(resolve_register_url_best_effort(register_url.as_deref()));
        }
        Command::DeleteNode { name } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_delete_node(&client, &name)?;
            println!("node '{name}' deleted");
        }
        Command::ClearEndpoint { name, family } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_clear_endpoint(&client, &name, family.as_deref())?;
            match &family {
                Some(f) => println!("node '{name}' {f} endpoint cleared"),
                None => println!("node '{name}' endpoint cleared"),
            }
        }
        Command::ListServices { pending } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_list_services(&client)?;
            for s in resp.services {
                if pending && s.state != wireserve_types::ServiceApprovalState::Pending {
                    continue;
                }
                let state = match s.state {
                    wireserve_types::ServiceApprovalState::Pending => "pending",
                    wireserve_types::ServiceApprovalState::Approved => "approved",
                    wireserve_types::ServiceApprovalState::Denied => "denied",
                };
                // Same S2 defense in depth as list-peers: every field is
                // sanitized, and denied_reason especially — it is the one
                // field here an operator typed and a database round-tripped.
                // `<vip or node address>\t<mapping,...>` (in `serve` syntax): where
                // `<name>.wg` resolves and what it serves there.
                let address = s.vip4.as_deref().unwrap_or(&s.ip4);
                let ports = if s.ports.is_empty() {
                    format!("{}/{}", s.port, s.proto.as_str())
                } else {
                    s.ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
                };
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    sanitize_for_terminal(&s.name),
                    sanitize_for_terminal(&s.node),
                    state,
                    sanitize_for_terminal(address),
                    ports,
                    s.denied_reason
                        .as_deref()
                        .map(sanitize_for_terminal)
                        .unwrap_or_else(|| "-".to_string())
                );
            }
        }
        Command::ApproveService { node, service } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_approve_service(&client, &node, &service)?;
            println!("service '{service}' approved for node '{node}'");
        }
        Command::DenyService {
            node,
            service,
            reason,
        } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_deny_service(&client, &node, &service, reason.as_deref())?;
            println!("service '{service}' denied for node '{node}'");
            println!(
                "  the node withdraws it and closes its firewall hole on its next poll \
                 (up to one poll interval from now)"
            );
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
                    "{}\t{}\t{}\t{}\tendpoint={}\tv4={}\tv6={}",
                    sanitize_for_terminal(&p.name),
                    sanitize_for_terminal(&p.pubkey),
                    sanitize_for_terminal(&p.ip4),
                    sanitize_for_terminal(&p.ip6),
                    p.endpoint_addr
                        .as_deref()
                        .map(sanitize_for_terminal)
                        .unwrap_or_else(|| "-".to_string()),
                    p.endpoint_addr_v4
                        .as_deref()
                        .map(sanitize_for_terminal)
                        .unwrap_or_else(|| "-".to_string()),
                    p.endpoint_addr_v6
                        .as_deref()
                        .map(sanitize_for_terminal)
                        .unwrap_or_else(|| "-".to_string())
                );
            }
        }
        Command::ExportConfig { name, out } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let register_url = config::resolve_register_url_interactive(register_url.as_deref())?;
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
    let url = config::resolve_coordinator_url_interactive(coordinator_url.as_deref())?;
    warn_if_plaintext_to_remote_host(&url);
    let token = config::resolve_admin_token_interactive(admin_token.as_deref())?;
    Ok(AdminClient::new(url, token))
}

/// Resolves the register URL the same way `export-config` does (flag → env
/// → saved file), but never prompts and never fails the caller — used by
/// `create-node`/`rejoin`, where this is a bonus annotation on already
/// successful output, not a requirement for the command itself.
fn resolve_register_url_best_effort(cli_flag: Option<&str>) -> Option<String> {
    config::resolve_register_url(cli_flag).ok()
}

/// Printed after a fresh join token, right where the operator is looking —
/// the actual command to run on the new machine, not just the token it
/// needs. Deliberately does not embed the token itself: a token as a
/// command-line argument lands in shell history and `ps` output (S7,
/// `wireserve-agent`'s own doc comment on its `join_token` argument), which
/// `wireserve-agent join`'s interactive prompt exists to avoid — so the
/// command printed here has no secret in it, and the token is pasted in
/// response to that prompt instead.
fn print_join_instructions(register_url: Option<String>) {
    println!();
    println!("To add this node to the mesh:");
    match register_url {
        Some(url) => println!("  wireserve-agent join {url}"),
        None => {
            println!("  wireserve-agent join <this coordinator's public URL>");
            println!(
                "  (pass --register-url, or set WIRESERVE_REGISTER_URL, so this command is \
                 filled in for you)"
            );
        }
    }
    println!("  then paste the join token above when prompted");
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
