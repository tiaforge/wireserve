use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::sync::{mpsc, Mutex};
use wireserve_agent::ipc::{client, protocol::IpcRequest, AgentContext};
use wireserve_agent::state::AgentState;
use wireserve_agent::firewall::InteropHandle;
use wireserve_agent::paths::{self, Instance};
use wireserve_agent::{firewall, ifname, lock, poll_loop, register, wg::WgInterface};
use wireserve_types::{FirewallBackend, PortMap};

#[derive(Parser)]
#[command(
    name = "wireserve",
    version,
    about = "Joins this machine to a wireserve mesh and publishes its services",
    allow_external_subcommands = true,
    override_usage = "wireserve [OPTIONS] <SERVICE> [PORT]... [--group GROUP]\n       \
                      wireserve [OPTIONS] <SERVICE> off\n       \
                      wireserve [OPTIONS] <COMMAND>",
    after_help = SERVICE_HELP
)]
struct Cli {
    /// The agent instance to act on, for several meshes on one host
    // Each instance is a separate node with its own state, interface,
    // firewall rules and hosts-file block. The default instance uses the
    // paths a single agent always has.
    #[arg(long, global = true, env = "WIRESERVE_INSTANCE", default_value = paths::DEFAULT_INSTANCE, value_parser = parse_instance)]
    instance: Instance,
    #[command(subcommand)]
    command: Command,
}

const SERVICE_HELP: &str = "\
Services:
  <SERVICE> <PORT>...  Publish a service, or replace its ports
  <SERVICE> off        Stop publishing a service
  <SERVICE>            Show a service

  PORT is [PUBLIC:][ADDRESS:]TARGET[/tcp|/udp]. ADDRESS is an IPv4 address on
  this node's network; without it, TARGET is a port on this node.

  wireserve web 80:5080
  wireserve dns 53/udp 53/tcp
  wireserve router 443:192.168.1.1:80
  wireserve web off";

/// Shared by `join` and `install` — the latter does everything the former
/// does, plus installs the binary and systemd unit around it, so both
/// take exactly the same bootstrap arguments.
#[derive(clap::Args)]
struct JoinArgs {
    /// The coordinator's URL; asked for if left out
    coordinator_url: Option<String>,
    /// The join token, or `-` to read it from stdin; asked for if left out
    // Security review S7: a token passed directly on the command line lands
    // in shell history and is visible to any local user via `ps` for as
    // long as the process is alive — hence `-`, the file and the prompt.
    join_token: Option<String>,
    /// Read the join token from this file
    #[arg(long, value_name = "FILE", conflicts_with = "join_token")]
    join_token_file: Option<std::path::PathBuf>,
    /// The UDP port WireGuard listens on [default: the first free one from 51820]
    // On a re-join, this instance's previous port; never one another
    // instance on this host has.
    #[arg(long, value_name = "PORT")]
    listen_port: Option<u16>,
    /// The address other nodes reach this one at, if the coordinator can't tell
    // Without it the coordinator learns one from the address this node
    // polls from and from its startup probe; a fixed public address or a
    // forwarded port does better.
    #[arg(long = "endpoint", value_name = "HOST:PORT")]
    endpoint_addr: Option<String>,
    /// Allow a coordinator URL over plain http on a network you trust
    // Refused otherwise for a non-loopback host: the join token, this
    // node's bearer token and the peer directory would all cross the
    // network unprotected. Remembered for the daemon.
    #[arg(long)]
    allow_plaintext_http: bool,
}

#[derive(clap::Args)]
struct InstallArgs {
    #[command(flatten)]
    join: JoinArgs,
    /// The local port HTTPS is served on [default: 11443]
    // PLAN.md M35: clients still use 443, which the agent rewrites to this
    // port. Without it: the one it has, or the first free one above 11443
    // for a named instance.
    #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    tls_port: Option<u16>,
}

#[derive(Subcommand)]
enum Command {
    /// Join a mesh with a token from `wireserve-admin node create`
    // The keypair is generated locally; only the public key leaves.
    Join(JoinArgs),
    /// Install wireserve as a systemd service and join a mesh (needs root)
    // Installs the binary to /usr/local/bin and the right unit for this
    // instance (plain, or the `@.service` template for a named instance),
    // creates the `wireserve` group whose members can run the other
    // commands without sudo, then joins. Linux/systemd only: Quadlet/podman
    // deployments install by hand, per `deploy/quadlet/`.
    Install(InstallArgs),
    /// Run the agent in the foreground
    Daemon {
        /// Seconds between polls of the coordinator
        #[arg(long, value_name = "SECS", default_value_t = 20)]
        poll_interval_secs: u64,
        /// The WireGuard interface to use, kept for later starts; `auto` to let it choose again
        // Without it, the instance keeps the name it used last, or picks the
        // first free one of wireserve0..wireserve15. A name given here is
        // pinned: used exactly, on this and every later start, or the daemon
        // refuses to start.
        #[arg(long, value_parser = parse_ifname_flag)]
        ifname: Option<ifname::Flag>,
    },
    /// Relay traffic for nodes that can't reach each other (also needs an admin's approval)
    // PLAN.md M23. A live toggle: takes effect next poll, no rejoin. Off by
    // default; a node with metered traffic should never turn it on.
    Transit {
        #[command(subcommand)]
        action: Toggle,
    },
    /// Let devices send all their internet traffic out through this node
    // PLAN.md M27. A device uses it only once an admin exports it with
    // `wireserve-admin device create --exit`, and the node must already be
    // an approved carrier (`transit on`).
    Exit {
        #[command(subcommand)]
        action: Toggle,
    },
    /// Show this node's services and peers
    // From the daemon's cache of the last poll — no network call.
    Status {
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Remove this node's interface, firewall rules and hosts entries, and stop the agent
    Leave,
    /// Run the TLS terminator
    // PLAN.md M33/M35: serves each of this node's services published on TCP
    // 443 with TLS on the service's own address, with a certificate it
    // obtains itself. Run by the `wireserve-tls` unit, as its own
    // unprivileged user, on the socket `wireserve-tls.socket` holds for it.
    // `tls-serve` is its name from before M44, still in hand-installed units.
    #[command(hide = true, alias = "tls-serve")]
    TlsDaemon {
        /// Where certificates and the ACME account are kept
        #[arg(long, value_name = "DIR", env = "STATE_DIRECTORY")]
        state_dir: Option<std::path::PathBuf>,
        // Trust this CA for the ACME server itself — a test CA such as
        // Pebble. Never needed for Let's Encrypt.
        #[arg(long, value_name = "PEM", env = "WIRESERVE_ACME_CA_FILE", hide = true)]
        acme_ca_file: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = 5, hide = true)]
        check_in_secs: u64,
        // The port to listen on when not started by `wireserve-tls.socket`,
        // which otherwise decides it. Service addresses' 443 is rewritten to
        // whichever it is.
        #[arg(long, env = "WIRESERVE_TLS_PORT", default_value_t = wireserve_types::TLS_LISTEN_PORT, hide = true)]
        port: u16,
    },
    /// `wireserve <service> ...`: everything that isn't one of the commands
    /// above. See [`ServiceArgs`].
    #[command(external_subcommand)]
    Service(Vec<String>),
}

// `wireserve <service> [PORT]...` (PLAN.md M44): the service is the
// command. Parsed separately from [`Cli`], from the words clap hands
// [`Command::Service`].
/// Publish, change, withdraw or show one of this node's services
#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "wireserve <service>",
    no_binary_name = true,
    override_usage = "wireserve <SERVICE> [PORT]... [--group GROUP]\n       wireserve <SERVICE> off",
    after_help = SERVICE_HELP
)]
struct ServiceArgs {
    /// The service's name
    name: String,
    /// The ports to publish, or `off` to stop publishing
    #[arg(value_name = "PORT")]
    ports: Vec<String>,
    /// Put a new service in this group instead of `default`
    // Only the first time: after that an admin decides its groups.
    #[arg(long, value_name = "GROUP")]
    group: Option<String>,
    /// The agent instance to act on
    #[arg(long, value_parser = parse_instance)]
    instance: Option<Instance>,
}

/// What `wireserve <service> ...` asks for.
#[derive(Debug, PartialEq)]
enum ServiceAction {
    Show,
    Declare { ports: Vec<String>, group: Option<String> },
    Withdraw,
}

impl ServiceArgs {
    fn action(&self) -> Result<ServiceAction, String> {
        match self.ports.as_slice() {
            [] if self.group.is_some() => Err("--group needs the service's ports".into()),
            [] => Ok(ServiceAction::Show),
            [off] if off == "off" => match self.group {
                Some(_) => Err("--group has nothing to do with withdrawing a service".into()),
                None => Ok(ServiceAction::Withdraw),
            },
            ports if ports.iter().any(|p| p == "off") => {
                Err("`off` withdraws a service and goes alone, without ports".into())
            }
            ports => Ok(ServiceAction::Declare { ports: ports.to_vec(), group: self.group.clone() }),
        }
    }
}

#[derive(Subcommand)]
enum Toggle {
    /// Turn it on
    On,
    /// Turn it off
    Off,
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

fn parse_ifname_flag(s: &str) -> Result<ifname::Flag, wireserve_agent::wg::InvalidIfname> {
    let flag = ifname::Flag::parse(s);
    if let ifname::Flag::Name(n) = &flag {
        wireserve_agent::wg::validate_ifname(n)?;
    }
    Ok(flag)
}

fn parse_instance(name: &str) -> Result<Instance, paths::InvalidInstance> {
    Instance::new(name)
}

#[tokio::main]
async fn main() {
    init_logging();
    let cli = Cli::parse();
    let instance = cli.instance;

    let result = match cli.command {
        Command::Join(args) => cmd_join(&instance, args).await,
        Command::Install(args) => cmd_install(&instance, args).await,
        Command::Daemon {
            poll_interval_secs,
            ifname,
        } => {
            cmd_daemon(&instance, poll_interval_secs, ifname).await
        }
        Command::TlsDaemon { state_dir, acme_ca_file, check_in_secs, port } => {
            // systemd may list several colon-separated state directories;
            // the unit names exactly one.
            let state_dir = state_dir
                .and_then(|d| d.to_str().and_then(|s| s.split(':').next()).map(std::path::PathBuf::from))
                .unwrap_or_else(|| instance.tls_state_dir());
            wireserve_tls::run(wireserve_tls::Options {
                socket: instance.tls_socket_path(),
                state_dir,
                ca_file: acme_ca_file,
                check_in_every: Duration::from_secs(check_in_secs.max(1)),
                port,
            })
            .await
            .map_err(Into::into)
        }
        Command::Service(words) => cmd_service(&instance, &words).await,
        Command::Transit { action } => cmd_transit(&instance, action).await,
        Command::Exit { action } => cmd_exit(&instance, action).await,
        Command::Status { json } => cmd_status(&instance, json).await,
        Command::Leave => cmd_leave(&instance).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn cmd_join(instance: &Instance, args: JoinArgs) -> Result<(), Box<dyn std::error::Error>> {
    let JoinArgs { coordinator_url, join_token, join_token_file, listen_port, endpoint_addr, allow_plaintext_http } =
        args;
    // Held across the whole join: a daemon running on this instance would
    // otherwise keep using (and saving) the identity this is replacing.
    let _lock = lock::lock_instance(instance)?;
    let coordinator_url = resolve_coordinator_url(coordinator_url)?;
    // Before asking for the token, so a refused URL costs no typing.
    register::check_coordinator_transport(&coordinator_url, allow_plaintext_http)?;
    let join_token = resolve_join_token(join_token, join_token_file)?;
    let state_path = instance.state_path();
    // A re-join keeps the interface and port this instance already uses.
    let previous = AgentState::load(&state_path).unwrap_or_default();
    let listen_port = match listen_port {
        Some(port) => port,
        None => {
            let reserved: std::collections::BTreeSet<u16> = paths::other_instances(instance)
                .into_iter()
                .filter_map(|(_, s)| s.listen_port)
                .collect();
            register::choose_listen_port(previous.listen_port, &reserved, register::udp_port_is_free)
                .ok_or("no free UDP port from 51820 up for WireGuard to listen on; pass --listen-port")?
        }
    };
    let state = register::join(register::JoinParams {
        coordinator_url: &coordinator_url,
        join_token: &join_token,
        listen_port,
        endpoint_addr,
        state_path: &state_path,
        ifname: previous.ifname,
        ifname_pinned: previous.ifname_pinned,
        allow_plaintext_http,
    })
    .await?;
    println!(
        "joined as ip4={} ip6={}",
        state.ip4.unwrap_or_default(),
        state.ip6.unwrap_or_default()
    );
    Ok(())
}

/// Installs the binary and this instance's systemd unit, then joins via
/// exactly the same `cmd_join` a plain `wireserve join` runs — the
/// token prompt and every other bit of that behaviour lives in one place.
/// Order: root/platform check, then the two installs (both idempotent),
/// `daemon-reload`, the join itself, then `enable --now`. A failure at
/// any step after the installs leaves them in place, so re-running
/// `install` picks up where it left off.
///
/// On a node that has already joined, with no URL or token given, it is an
/// upgrade instead: same installs, no join, every running agent restarted.
async fn cmd_install(instance: &Instance, args: InstallArgs) -> Result<(), Box<dyn std::error::Error>> {
    let InstallArgs { join: args, tls_port } = args;
    // Refused before anything is installed, not after.
    if let Some(url) = &args.coordinator_url {
        register::check_coordinator_transport(url, args.allow_plaintext_http)?;
    }
    wireserve_agent::install::require_root()?;
    // A corrupt state file is an error here, not "not registered yet": that
    // would go on to ask for a token and replace an identity.
    let registered = AgentState::load(&instance.state_path())?.bearer_token.is_some();
    let join_args_given =
        args.coordinator_url.is_some() || args.join_token.is_some() || args.join_token_file.is_some();
    let upgrade = wireserve_agent::install::is_upgrade(registered, join_args_given);
    wireserve_agent::install::install_self()?;
    // Before the daemon starts: it looks the group up once, when it binds.
    let group = wireserve_agent::install::ensure_socket_group()?;
    // The TLS terminator (PLAN.md M33): its user before the daemon binds
    // the socket it hands to that user's group.
    wireserve_agent::install::ensure_tls_user()?;
    let unit = wireserve_agent::install::install_unit(instance)?;
    let tls = wireserve_agent::install::install_tls_units(instance, tls_port)?;
    if upgrade {
        wireserve_agent::install::refresh_other_unit(instance)?;
    }
    wireserve_agent::install::systemctl_daemon_reload()?;
    if upgrade {
        // Every running agent, not only this instance's: they share the
        // binary that was just replaced. Restarting is safe by design — the
        // firewall is torn down and re-applied deny-first on every start.
        let mut restarted = wireserve_agent::install::active_agent_units()?;
        if !restarted.contains(&format!("{unit}.service")) {
            wireserve_agent::install::systemctl_enable_now(&unit)?;
        }
        for running in &restarted {
            wireserve_agent::install::systemctl_restart(running)?;
        }
        restarted.sort();
        println!("upgraded; restarted: {}", if restarted.is_empty() { "nothing was running".to_string() } else { restarted.join(", ") });
    } else {
        cmd_join(instance, args).await?;
        wireserve_agent::install::systemctl_enable_now(&unit)?;
    }
    // Started with the agent from now on (`WantedBy=`), and stopped and
    // restarted with it (`PartOf=`). A node with nothing to serve over TLS
    // runs it idle: it checks in and waits.
    // Its socket from boot on, whatever the terminator does (PLAN.md M35).
    wireserve_agent::install::start_tls(&tls)?;
    let instance_flag = if instance.is_default() { String::new() } else { format!(" --instance {}", instance.name()) };
    println!();
    println!("{unit} is running — `wireserve{instance_flag} status` shows its services and peers");
    if let Some(note) = &tls.note {
        println!("{note}");
    }
    if let Some(group) = group {
        // The user who ran sudo, not root: root needs no group.
        let who = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty() && u != "root");
        println!();
        println!("To use it without sudo, join the `{group}` group and log in again:");
        println!("  sudo usermod -aG {group} {}", who.as_deref().unwrap_or("$USER"));
        if !upgrade {
            println!("If {unit} was already running, `sudo systemctl restart {unit}` makes it share its socket with that group.");
        }
    }
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
                    "Join token (from 'wireserve-admin node create'): ",
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

async fn cmd_daemon(
    instance: &Instance,
    poll_interval_secs: u64,
    ifname_flag: Option<ifname::Flag>,
) -> Result<(), Box<dyn std::error::Error>> {
    // First, before anything is looked at or changed: one daemon per
    // instance. Held until the process exits.
    let _lock = lock::lock_instance(instance)?;

    let state_path = instance.state_path();
    let mut state = AgentState::load(&state_path)?;
    if state.bearer_token.is_none() {
        return Err("not registered — run `wireserve join` first".into());
    }
    register::check_coordinator_transport(
        state.coordinator_url.as_deref().unwrap_or_default(),
        state.allow_plaintext_http,
    )?;
    if state.mesh.is_none() {
        return Err("this node has no pinned mesh range — run `wireserve join` again".into());
    }

    let ip4: std::net::Ipv4Addr = state.ip4.clone().unwrap_or_default().parse()?;
    let ip6: std::net::Ipv6Addr = state.ip6.clone().unwrap_or_default().parse()?;
    let listen_port = state.listen_port.unwrap_or(register::DEFAULT_LISTEN_PORT);
    let private_key = state.private_key.clone().unwrap_or_default();
    let coordinator_url = state.coordinator_url.clone().unwrap_or_default();

    // Which interface. Claimed here and held for the life of the process,
    // before any firewall state keyed on the name is touched — see
    // `ifname` for the rules.
    let reserved: std::collections::BTreeMap<String, String> = paths::other_instances(instance)
        .into_iter()
        .filter_map(|(other, s)| s.ifname.map(|n| (n, other.name().to_string())))
        .collect();
    let choice = ifname::choose(
        &ifname::Request {
            flag: ifname_flag.as_ref(),
            stored: state.ifname.as_deref(),
            stored_pinned: state.ifname_pinned,
            reserved: &reserved,
        },
        |name| ifname::probe_host(name, &private_key),
    )?;
    let ifname = choice.ifname.clone();
    tracing::info!(instance = instance.name(), %ifname, source = ?choice.source, pinned = choice.pinned, "using interface");
    choice.claim.hold();
    remove_leftover_interfaces(&ifname, state.ifname.as_deref(), &private_key);
    // Two meshes on one host with overlapping address ranges would fight
    // over routes; this node's own address on another interface is the
    // one clash that is certain, and cheap to see before anything changes.
    for addr in [std::net::IpAddr::V4(ip4), std::net::IpAddr::V6(ip6)] {
        match wireserve_agent::wg::interfaces_with_address(addr, &ifname) {
            Ok(others) if !others.is_empty() => {
                return Err(format!(
                    "this node's mesh address {addr} is already assigned to {} — most likely \
                     another mesh on this host uses the same address range. Give the meshes' \
                     coordinators non-overlapping ranges (WIRESERVE_NET_V4_CIDR / \
                     WIRESERVE_NET_V6_PREFIX)",
                    others.join(", ")
                )
                .into());
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "could not check whether the mesh address is already in use"),
        }
    }
    if state.ifname.as_deref() != Some(ifname.as_str()) || state.ifname_pinned != choice.pinned {
        state.ifname = Some(ifname.clone());
        state.ifname_pinned = choice.pinned;
        state.save(&state_path)?;
    }

    let mut wg = WgInterface::new(&ifname)?;
    let mut endpoint_tracker = wireserve_agent::wg::EndpointTracker::default();

    // The carry interface relayed sessions run on (PLAN.md M39). Its name
    // is checked before any firewall state names it: one that belongs to
    // something else is left alone entirely, and this node then simply
    // can't be relayed to.
    //
    // Its name is claimed like the mesh interface's: every agent's interop
    // removes tagged rules for a name no running agent claims, and that
    // includes this agent's own mesh-interface worker, which deleted the
    // carry's rules as fast as the carry's worker put them back — each
    // round a burst of nftables events and firewall-cmd calls, which kept
    // firewalld busy for as long as the agent ran.
    let carry = wireserve_agent::wg::carry_ifname(&ifname);
    let carry = match WgInterface::new(&carry).map(|c| c.classify(&private_key)) {
        Ok(wireserve_agent::wg::Slot::Free | wireserve_agent::wg::Slot::Ours) => match lock::IfnameClaim::take(&carry) {
            Ok(Ok(claim)) => {
                claim.hold();
                Some(carry)
            }
            Ok(Err(holder)) => {
                tracing::warn!(%carry, %holder, "not using the carry interface: sessions with this node can't be relayed");
                None
            }
            Err(e) => {
                tracing::warn!(%carry, error = %e, "not using the carry interface: sessions with this node can't be relayed");
                None
            }
        },
        Ok(wireserve_agent::wg::Slot::Foreign(reason)) => {
            tracing::warn!(%carry, %reason, "not using the carry interface: sessions with this node can't be relayed");
            None
        }
        Err(e) => {
            tracing::warn!(%carry, error = %e, "not using the carry interface: sessions with this node can't be relayed");
            None
        }
    };

    #[cfg(target_os = "linux")]
    let mut fw = firewall::nftables::NftablesBackend::new(ifname.clone())?
        .with_carry(carry.clone())
        .with_own(&[ip4.into(), ip6.into()]);
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
    //
    // The ownership preflight comes before all of it, and the host
    // firewall interop (other firewalls on the host letting the mesh
    // interface through to our table) right after our own default-deny —
    // see `firewall::guarded_bring_up` for why that order, and what is
    // undone if bring-up fails.
    //
    // NAT-traversal step 2 (PLAN.md decisions log #90+): the one-shot
    // reflexive-address probe MUST run here, before `bring_up` claims
    // `listen_port` in the kernel — see `reflexive` module doc for why
    // it can never run again for the life of this process. IPv4 only, and
    // run even on a node with working IPv6: its IPv4-only peers can't use
    // that, and without this address can't reach it at all (PLAN.md
    // decisions log #207).
    //
    // The same probe tells whether this node is dialable from outside
    // (PLAN.md M40), from whether the coordinator's second answer, from a
    // port this node never sent to, gets in.
    let learned = wireserve_agent::reflexive::learn_waiting(
        &coordinator_url,
        listen_port,
        wireserve_agent::reflexive::PROBE_TIMEOUT,
        wireserve_agent::reflexive::UNREACHABLE_WAIT_MAX,
    )
    .await;
    let own_reflexive_addr = learned.addr;
    let own_dialable_v4 = learned.dialable;
    tracing::info!(reflexive_addr = ?own_reflexive_addr, dialable = ?own_dialable_v4, "one-shot reflexive-address probe");

    // Where the interop restores our own table from, if something else on
    // the host removes it (see `nftables::SharedRuleset`).
    #[cfg(target_os = "linux")]
    let own_table = fw.last_applied();
    #[cfg(not(target_os = "linux"))]
    let own_table = ();
    let mut interop = firewall::guarded_bring_up(
        &mut fw,
        &mut wg,
        |wg| wg.preflight(&private_key).map_err(Into::into),
        || firewall::Interops {
            #[cfg(target_os = "linux")]
            carry: carry.as_deref().map(|c| start_interop(c, firewall::ForwardWanted::default(), own_table.clone())),
            #[cfg(not(target_os = "linux"))]
            carry: carry.as_deref().map(|c| start_interop(c, firewall::ForwardWanted::default(), ())),
            main: start_interop(&ifname, firewall::ForwardWanted::of(&state), own_table),
        },
        |wg| {
            wg.bring_up(&private_key, ip4, ip6, listen_port)
                .map_err(Into::<Box<dyn std::error::Error>>::into)
        },
    )?;
    if carry.is_some() {
        match wg.bring_up_carry(&private_key, ip4, ip6, state.carry_port) {
            Ok(port) => {
                tracing::info!(carry = ?carry, port, "carry interface up");
                if state.carry_port != Some(port) {
                    state.carry_port = Some(port);
                    state.save(&state_path)?;
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not bring up the carry interface: sessions with this node can't be relayed"),
        }
    }

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    // F1 (security review, round 2): exactly ONE in-memory copy of the
    // agent state, shared by the poll loop and the IPC server. The
    // previous design kept two copies and re-synced them at cycle
    // boundaries, which still silently dropped any declaration or withdrawal
    // issued while a poll request was in flight (the copy-back after the
    // poll overwrote it).
    // A crashed run leaves its terminator's local routes behind (PLAN.md
    // M33): the kernel keeps them, and nothing else records them. Swept
    // before the first poll, which adds back whatever is still wanted.
    #[cfg(target_os = "linux")]
    sweep_local_routes(&mut state, &state_path);

    let shared_state = Arc::new(Mutex::new(state));
    // A bounded timeout so a hung coordinator connection can never pin the
    // poll loop (and with it `leave`, which is handled by the same
    // `select!`) indefinitely.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    // The TLS terminator's own socket (PLAN.md M33).
    let tls_link = Arc::new(wireserve_agent::tls_link::TlsLink::default());
    // Relay port checks (PLAN.md M40).
    let port_checks = Arc::new(wireserve_agent::port_check::PortChecker::default());
    let tls_socket_path = instance.tls_socket_path();
    {
        let ctx = wireserve_agent::ipc::tls::TlsContext {
            state: shared_state.clone(),
            link: tls_link.clone(),
            client: client.clone(),
        };
        let path = tls_socket_path.clone();
        tokio::spawn(async move {
            if let Err(e) = wireserve_agent::ipc::tls::serve(ctx, &path).await {
                tracing::error!(error = %e, "TLS terminator socket exited");
            }
        });
    }
    let ipc_ctx = AgentContext {
        state: shared_state.clone(),
        state_path: state_path.clone(),
        instance: instance.name().to_string(),
        ifname: ifname.clone(),
        reflexive_unknown: own_reflexive_addr.is_none(),
        shutdown: shutdown_tx,
    };
    let socket_path = instance.socket_path();
    let ipc_socket_path = socket_path.clone();
    tokio::spawn(async move {
        if let Err(e) = wireserve_agent::ipc::server::serve(ipc_ctx, &ipc_socket_path).await {
            tracing::error!(error = %e, "IPC server exited");
        }
    });

    let hosts_path = paths::hosts_path();
    let mut interval = tokio::time::interval(Duration::from_secs(poll_interval_secs));
    // A poll that overran (a 30 s timeout) is not made up for by polling again
    // at once: an overloaded coordinator would never get a moment's relief.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Polls in a row the coordinator could not answer, and the earliest an
    // early wake-up (below) may poll again while backing off from them.
    let mut coordinator_failures: u32 = 0;
    let mut not_before = tokio::time::Instant::now();
    // Between polls, the kernel's receive counters: a peer whose path goes
    // quiet is noticed within seconds, not at the next poll.
    let mut liveness = tokio::time::interval(wireserve_agent::wg::LIVENESS_CHECK_INTERVAL);
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // What quiet peers are nudged from (`wg::NUDGE_AFTER`): this node's mesh
    // address, so their WireGuard takes it as this node's.
    let nudge_socket = match tokio::net::UdpSocket::bind((ip4, 0)).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!(error = %e, "could not open the socket quiet peers are nudged from: a peer that keeps alive less often than this node may count as unreachable and be relayed");
            None
        }
    };

    // F9 follow-up: how many 401s in a row it takes before the daemon
    // concludes it has really been revoked. A single 401 could also be a
    // coordinator momentarily running against the wrong database (a
    // restore from backup, a wiped volume) — tearing the whole mesh down
    // on the first one would turn that operator mistake into every node
    // dropping off at once. Three consecutive 401s (about a minute at the
    // default interval) is still a tight bound for a genuine revoke.
    const UNAUTHORIZED_STREAK_TO_TEARDOWN: u32 = 3;
    let mut unauthorized_streak: u32 = 0;

    // Whether a cycle has written the hosts file (or found it current) in
    // this run — what tells a hosts file that *became* read-only (a lost
    // bind mount, see `PollError::hosts_read_only`) from one that always
    // was, e.g. a container's `-v /etc/hosts:/etc/hosts:ro`. Only the
    // first is worth restarting over; restarting for the second would
    // just loop.
    let mut hosts_synced = false;

    // SIGTERM (systemd stop) / SIGINT: tear down the interface, firewall
    // table and hosts block the same way `leave` does, but keep the state
    // file (bearer token, keys, last directory) intact — a stopped daemon
    // isn't maintaining/reconciling/firewalling anything, so it shouldn't
    // leave a live-looking interface sitting on the host. The next `daemon`
    // start rejoins the mesh with the same identity, without needing
    // `join` again.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = async { tokio::select! { _ = sigterm.recv() => {}, _ = tokio::signal::ctrl_c() => {} } } => {
                tracing::info!("termination signal received — tearing down");
                teardown_everything(&mut fw, &mut interop, &mut wg, &hosts_path, instance.hosts_label(), &socket_path, &shared_state, &state_path, false).await;
                break;
            }
            // The interval, or a device the terminator has just seen for the
            // first time: its owner is asked after now, not at the next
            // cycle, so its first requests wait a second or two for who it is
            // rather than twenty. A moment's grace lets several arrive as one.
            scheduled = async {
                tokio::select! {
                    _ = interval.tick() => true,
                    () = tls_link.wake.notified() => { tokio::time::sleep(Duration::from_secs(1)).await; false }
                    // A port check answered: the coordinator is waiting on it.
                    () = port_checks.wake.notified() => false,
                    // A peer's path just went dead: ask for its relay now.
                    () = async {
                        loop {
                            liveness.tick().await;
                            let tunnel = wireserve_agent::wg::tunnel_peers(wg.ifname()).unwrap_or_default();
                            let rx = tunnel.iter().map(|t| (t.pubkey.as_str(), t.rx_bytes));
                            let now = std::time::Instant::now();
                            if endpoint_tracker.observe_rx(rx, now) {
                                break;
                            }
                            if let Some(socket) = &nudge_socket {
                                wireserve_agent::wg::nudge(socket, &endpoint_tracker.peers_to_nudge(now)).await;
                            }
                        }
                    } => false,
                }
            } => {
                // Backing off from a coordinator that could not answer: only
                // the schedule, which backing off moved, may poll it again.
                if !scheduled && tokio::time::Instant::now() < not_before {
                    continue;
                }
                let mut ctx = poll_loop::PollContext {
                    client: &client,
                    coordinator_url: &coordinator_url,
                    hosts_path: &hosts_path,
                    hosts_label: instance.hosts_label(),
                    state_path: &state_path,
                    wg: &mut wg,
                    firewall: &mut fw,
                    endpoint_tracker: &mut endpoint_tracker,
                    own_reflexive_addr: own_reflexive_addr.as_deref(),
                    tls: Some(&tls_link),
                    own_dialable_v4,
                    port_checks: Some(&port_checks),
                };
                let result = poll_loop::run_once(&mut ctx, &shared_state).await;
                // Safety net for host-firewall changes the interop's own
                // change monitor can't see (legacy iptables, firewalld) —
                // and the place the transit opt-in and target-address
                // services are re-read, since `transit on` and a declaration
                // mutate a running daemon and the host firewall's FORWARD
                // hook has to follow them.
                interop.tick(firewall::ForwardWanted::of(&*shared_state.lock().await));

                match &result {
                    Err(e) if e.is_coordinator_trouble() => {
                        coordinator_failures = coordinator_failures.saturating_add(1);
                        let wait = wireserve_agent::backoff::delay(
                            Duration::from_secs(poll_interval_secs),
                            coordinator_failures,
                            rand::random::<f64>(),
                        );
                        not_before = tokio::time::Instant::now() + wait;
                        interval.reset_after(wait);
                        tracing::warn!(failures = coordinator_failures, wait_secs = wait.as_secs(), "coordinator did not answer; backing off");
                    }
                    // It answered, even if with a refusal.
                    _ => coordinator_failures = 0,
                }

                match &result {
                    Ok(_) => hosts_synced = true,
                    Err(e) if e.hosts_synced() => hosts_synced = true,
                    Err(e) if hosts_synced && e.hosts_read_only() => {
                        // Exiting non-zero is the recovery: the unit's
                        // `Restart=on-failure` sets the sandbox — and with
                        // it the hosts-file mount — up again from scratch.
                        tracing::error!(
                            error = %e,
                            path = %hosts_path.display(),
                            "the hosts file became read-only after it had been written in this \
                             run — under the systemd unit that means something on the host \
                             replaced it and this unit's mount of it was dropped; exiting so \
                             the service manager restarts the agent with a fresh one"
                        );
                        teardown_everything(&mut fw, &mut interop, &mut wg, &hosts_path, instance.hosts_label(), &socket_path, &shared_state, &state_path, false).await;
                        return Err("hosts file became read-only; restart required".into());
                    }
                    Err(_) => {}
                }

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
                        // `wireserve-admin node rejoin` overwrites it anyway.
                        tracing::error!(
                            "poll rejected with 401 {} times in a row — this node has been \
                             revoked; tearing down and stopping (run `wireserve join` \
                             again with a fresh token from `wireserve-admin node rejoin` to rejoin)",
                            UNAUTHORIZED_STREAK_TO_TEARDOWN
                        );
                        teardown_everything(&mut fw, &mut interop, &mut wg, &hosts_path, instance.hosts_label(), &socket_path, &shared_state, &state_path, false).await;
                        break;
                    }
                    Err(e) => tracing::error!(error = %e, "poll cycle failed, will retry next interval"),
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("leave requested, tearing down");
                teardown_everything(&mut fw, &mut interop, &mut wg, &hosts_path, instance.hosts_label(), &socket_path, &shared_state, &state_path, true).await;
                break;
            }
        }
    }

    Ok(())
}

/// Removes the terminator's local routes (PLAN.md M33) a previous run left
/// behind: the ones recorded in the state file, plus any carrying our
/// protocol number inside this instance's own mesh range — a run that
/// crashed between adding a route and saving the state file recorded
/// nothing. Another instance's routes lie in its own range and are left.
#[cfg(target_os = "linux")]
fn sweep_local_routes(state: &mut AgentState, state_path: &std::path::Path) {
    let range = state.mesh.as_ref().and_then(wireserve_types::MeshRanges::parse);
    let mut stale: Vec<std::net::Ipv4Addr> = state.local_routes.clone();
    match wireserve_agent::routes::own_local_routes() {
        Ok(found) => stale.extend(found.into_iter().filter(|a| range.as_ref().is_some_and(|r| r.contains4(*a)))),
        Err(e) => tracing::warn!(error = %e, "could not list local routes to sweep"),
    }
    stale.sort_unstable();
    stale.dedup();
    if stale.is_empty() {
        return;
    }
    tracing::info!(routes = ?stale, "removing local routes a previous run left behind");
    let _ = wireserve_agent::routes::remove_local(&stale);
    state.local_routes.clear();
    if let Err(e) = state.save(state_path) {
        tracing::warn!(error = %e, "failed to record the swept local routes");
    }
}

/// Tears down this node's own interfaces (by private key) under any name
/// but `chosen` — left behind when a run died without tearing down, and
/// the instance has since moved to another name (or come up on a
/// `wireserve*` name for the first time, leaving a pre-instances `wg0`) —
/// together with the firewall state kept for them. Each name is claimed
/// first, so nothing a running agent uses is touched.
fn remove_leftover_interfaces(chosen: &str, previous: Option<&str>, private_key: &str) {
    for name in ifname::leftover_names(chosen, previous) {
        let ifname::Probe::Usable { claim, ours: true } = ifname::probe_host(&name, private_key) else {
            continue;
        };
        tracing::info!(ifname = %name, "removing this node's own interface left behind under another name");
        #[cfg(target_os = "linux")]
        {
            firewall::host_interop::remove_for(&name);
            match firewall::nftables::NftablesBackend::new(name.clone()) {
                Ok(mut fw) => {
                    if let Err(e) = fw.teardown() {
                        tracing::warn!(ifname = %name, error = %e, "could not remove its firewall table");
                    }
                }
                Err(e) => tracing::warn!(ifname = %name, error = %e, "could not remove its firewall table"),
            }
        }
        match WgInterface::new(&name).map(|mut wg| wg.teardown()) {
            Ok(Ok(())) => {}
            Ok(Err(e)) | Err(e) => tracing::warn!(ifname = %name, error = %e, "could not remove it"),
        }
        remove_leftover_carry(&name, private_key);
        drop(claim);
    }
}

/// Removes the carry interface (PLAN.md M39) that went with the mesh
/// interface `main`, if it is this node's own, with its firewall.
fn remove_leftover_carry(main: &str, private_key: &str) {
    let name = wireserve_agent::wg::carry_ifname(main);
    let Ok(carry) = WgInterface::new(&name) else {
        return;
    };
    if carry.classify(private_key) != wireserve_agent::wg::Slot::Ours {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        firewall::host_interop::remove_for(&name);
        // The mesh interface's table is gone already; removing it again is
        // a no-op, and this is the one call that knows both.
        if let Ok(fw) = firewall::nftables::NftablesBackend::new(main.to_string()) {
            let mut fw = fw.with_carry(Some(name.clone()));
            if let Err(e) = fw.teardown() {
                tracing::warn!(ifname = %name, error = %e, "could not remove its firewall table");
            }
        }
    }
    if let Err(e) = wireserve_agent::routes::delete_link(&name) {
        tracing::warn!(ifname = %name, error = %e, "could not remove a leftover carry interface");
    }
}

/// Shared by both the `leave` IPC path and F9's revoked-node auto-teardown:
/// removes the managed hosts-file block, the host-firewall interop, the
/// firewall table, the
/// WireGuard interface, the IPC socket, and resets local state to a clean
/// default (security review F2 — spec §4.6 says `leave` "tears down
/// interface, firewall, hosts block," but the original implementation did
/// only the last two; the socket and lingering secrets in state were also
/// flagged). Every step best-effort: a failure partway through (e.g. the
/// interface already gone) must not stop the rest from running.
#[allow(clippy::too_many_arguments)]
async fn teardown_everything<F: FirewallBackend>(
    fw: &mut F,
    interop: &mut impl InteropHandle,
    wg: &mut WgInterface,
    hosts_path: &std::path::Path,
    hosts_label: Option<&str>,
    socket_path: &std::path::Path,
    state: &Mutex<AgentState>,
    state_path: &std::path::Path,
    reset_state: bool,
) where
    F::Error: std::fmt::Display,
{
    if let Err(e) = wireserve_agent::hosts::remove_block(hosts_path, hosts_label) {
        tracing::warn!(error = %e, "failed to remove managed hosts-file block during teardown");
    }
    // Forwarding this agent turned on for service targets (PLAN.md M26)
    // goes off before the table guarding it does, and is forgotten, so
    // nothing is left forwarding unguarded.
    {
        let mut state = state.lock().await;
        if !state.forwarding_owned.is_empty() {
            firewall::ip_forward::release_egress(&state.forwarding_owned.iter().cloned().collect());
            state.forwarding_owned.clear();
            if let Err(e) = state.save(state_path) {
                tracing::warn!(error = %e, "failed to record released forwarding during teardown");
            }
        }
    }
    // The host firewall closes back first, then our own table goes: the
    // interface is never left open to the host firewalls' view while
    // nothing of ours default-denies it.
    interop.stop();
    if let Err(e) = fw.teardown() {
        tracing::warn!(error = %e, "failed to tear down firewall rules during teardown");
    }
    // The terminator's service addresses stop being this host's own
    // (PLAN.md M33) — after the firewall, which marked traffic for them.
    #[cfg(target_os = "linux")]
    {
        let mut state = state.lock().await;
        if !state.local_routes.is_empty() {
            let _ = wireserve_agent::routes::remove_local(&state.local_routes);
            state.local_routes.clear();
            if let Err(e) = state.save(state_path) {
                tracing::warn!(error = %e, "failed to record removed local routes during teardown");
            }
        }
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

/// A service's port arguments, each a [`PortMap`].
fn parse_service_ports(args: &[String]) -> Result<Vec<PortMap>, String> {
    args.iter().map(|a| a.parse::<PortMap>()).collect()
}

/// `wireserve <service> ...` — the words after the binary's own options.
async fn cmd_service(instance: &Instance, words: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let args = match ServiceArgs::try_parse_from(words) {
        Ok(args) => args,
        Err(e) => e.exit(),
    };
    let instance = args.instance.as_ref().unwrap_or(instance);
    match args.action()? {
        ServiceAction::Show => cmd_show(instance, &args.name).await,
        ServiceAction::Declare { ports, group } => cmd_declare(instance, args.name, &ports, group).await,
        ServiceAction::Withdraw => cmd_withdraw(instance, args.name).await,
    }
}

/// An error answer as an error, so the exit status says it failed.
fn into_result(resp: wireserve_agent::ipc::IpcResponse) -> Result<wireserve_agent::ipc::IpcResponse, Box<dyn std::error::Error>> {
    match resp {
        wireserve_agent::ipc::IpcResponse::Error { message } => Err(message.into()),
        other => Ok(other),
    }
}

async fn cmd_declare(
    instance: &Instance,
    name: String,
    ports: &[String],
    group: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ports = parse_service_ports(ports)?;
    wireserve_types::validate_service_ports(&ports)?;
    into_result(client::call(&instance.socket_path(), &IpcRequest::Serve { name, ports, group }).await?)?;
    // "ok" alone overstates what just happened: the declaration is queued
    // locally and only reaches the coordinator on the next poll, and if
    // that coordinator requires approval it will sit pending until an
    // admin acts. The agent cannot know which until it polls, so say what
    // is actually true and point at where the answer shows up.
    println!("ok — queued; takes effect on the next poll");
    println!(
        "  if this coordinator requires admin approval, `wireserve status` will show \
         it as pending until an admin approves it"
    );
    Ok(())
}

async fn cmd_withdraw(instance: &Instance, name: String) -> Result<(), Box<dyn std::error::Error>> {
    into_result(client::call(&instance.socket_path(), &IpcRequest::Unserve { name: name.clone() }).await?)?;
    println!("ok — {name} is withdrawn on the next poll, and its name is free for other nodes");
    println!("  `wireserve {name} <port>...` publishes it again");
    Ok(())
}

async fn cmd_show(instance: &Instance, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    match into_result(client::call(&instance.socket_path(), &IpcRequest::List).await?)? {
        wireserve_agent::ipc::IpcResponse::List(view) => match wireserve_agent::ipc::render::render_service(&view, name) {
            Some(out) => {
                print!("{out}");
                Ok(())
            }
            None => Err(format!(
                "no service named {name} — `wireserve {name} <port>...` publishes one, `wireserve status` lists them all"
            )
            .into()),
        },
        other => {
            print_response(other);
            Ok(())
        }
    }
}

async fn cmd_transit(instance: &Instance, action: Toggle) -> Result<(), Box<dyn std::error::Error>> {
    let enabled = matches!(action, Toggle::On);
    let resp = client::call(&instance.socket_path(), &IpcRequest::TransitCapable { enabled }).await?;
    if matches!(resp, wireserve_agent::ipc::IpcResponse::Ok) {
        if enabled {
            println!(
                "ok — transit enabled; this node carries traffic only once an admin approves \
                 it (`wireserve-admin transit approve <node>`), from the next poll after that"
            );
            if !firewall::ip_forward::ipv6_per_interface_supported() {
                println!(
                    "note: this kernel cannot forward IPv6 on one interface alone \
                     (force_forwarding needs Linux 6.17), so this node carries IPv4 only"
                );
            }
        } else {
            println!("ok — transit disabled; takes effect on the next poll");
        }
        return Ok(());
    }
    print_response(resp);
    Ok(())
}

async fn cmd_exit(instance: &Instance, action: Toggle) -> Result<(), Box<dyn std::error::Error>> {
    let enabled = matches!(action, Toggle::On);
    let resp = client::call(&instance.socket_path(), &IpcRequest::ExitCapable { enabled }).await?;
    if matches!(resp, wireserve_agent::ipc::IpcResponse::Ok) {
        if enabled {
            println!(
                "ok — exit enabled; devices exported with `wireserve-admin device create --exit` \
                 through this node will send their internet traffic out from here, under this \
                 host's own address, from the next poll. IPv4 only: their IPv6 is dropped here."
            );
        } else {
            println!("ok — exit disabled; takes effect on the next poll");
        }
        return Ok(());
    }
    print_response(resp);
    Ok(())
}

async fn cmd_status(instance: &Instance, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client::call(&instance.socket_path(), &IpcRequest::List).await?;
    match resp {
        wireserve_agent::ipc::IpcResponse::List(view) if json => {
            println!("{}", serde_json::to_string_pretty(&view)?);
        }
        wireserve_agent::ipc::IpcResponse::List(view) => {
            print!("{}", wireserve_agent::ipc::render::render(&view, chrono::Utc::now()));
        }
        other => print_response(other),
    }
    Ok(())
}

async fn cmd_leave(instance: &Instance) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client::call(&instance.socket_path(), &IpcRequest::Leave).await?;
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

#[cfg(target_os = "linux")]
fn start_interop(
    ifname: &str,
    forward_wanted: firewall::ForwardWanted,
    own_table: firewall::nftables::SharedRuleset,
) -> firewall::host_interop::HostInterop {
    firewall::host_interop::HostInterop::start(ifname, forward_wanted, own_table)
}

#[cfg(not(target_os = "linux"))]
fn start_interop(_ifname: &str, _forward_wanted: firewall::ForwardWanted, _own_table: ()) -> firewall::NoopInterop {
    firewall::NoopInterop
}

/// Used only on non-Linux targets, where there is no nftables backend —
/// never a supported production configuration, just keeps `daemon`
/// linkable there.
#[cfg(not(target_os = "linux"))]
struct NoopFirewall;

#[cfg(not(target_os = "linux"))]
impl FirewallBackend for NoopFirewall {
    type Error = std::convert::Infallible;
    fn apply(
        &mut self,
        _rules: &[wireserve_types::ServiceRule],
        _forwarding: &wireserve_types::Forwarding,
    ) -> Result<(), Self::Error> {
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
    use wireserve_types::Proto;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_string()).collect()
    }

    fn service(words: &[&str]) -> ServiceArgs {
        ServiceArgs::try_parse_from(words).unwrap()
    }

    fn top(words: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("wireserve").chain(words.iter().copied())).unwrap().command
    }

    #[test]
    fn the_cli_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        ServiceArgs::command().debug_assert();
    }

    #[test]
    fn a_word_that_is_no_command_is_a_service() {
        let Command::Service(words) = top(&["web", "80:5080", "--group", "g"]) else { panic!("not a service") };
        assert_eq!(words, args(&["web", "80:5080", "--group", "g"]));
        let s = service(&["web", "80:5080", "--group", "g"]);
        assert_eq!(
            s.action().unwrap(),
            ServiceAction::Declare { ports: args(&["80:5080"]), group: Some("g".into()) }
        );
    }

    #[test]
    fn off_withdraws_and_no_ports_shows() {
        assert_eq!(service(&["web", "off"]).action().unwrap(), ServiceAction::Withdraw);
        assert_eq!(service(&["web"]).action().unwrap(), ServiceAction::Show);
    }

    #[test]
    fn off_goes_alone() {
        assert!(service(&["web", "80", "off"]).action().is_err());
        assert!(service(&["web", "off", "--group", "g"]).action().is_err());
        assert!(service(&["web", "--group", "g"]).action().is_err());
    }

    #[test]
    fn the_instance_can_follow_the_service_name() {
        let s = service(&["web", "80", "--instance", "work"]);
        assert_eq!(s.instance.unwrap().name(), "work");
    }

    #[test]
    fn commands_still_win_over_services() {
        assert!(matches!(top(&["exit", "on"]), Command::Exit { action: Toggle::On }));
        assert!(matches!(top(&["status"]), Command::Status { json: false }));
        assert!(matches!(top(&["tls-serve"]), Command::TlsDaemon { .. }));
    }

    #[test]
    fn every_command_is_a_reserved_service_name() {
        use clap::CommandFactory;
        for sub in Cli::command().get_subcommands() {
            for name in std::iter::once(sub.get_name()).chain(sub.get_all_aliases()) {
                assert!(
                    wireserve_agent::RESERVED_SERVICE_NAMES.contains(&name),
                    "`{name}` can be declared as a service but `wireserve {name}` runs the command"
                );
            }
        }
    }

    #[test]
    fn serve_takes_port_mappings() {
        assert_eq!(
            parse_service_ports(&args(&["53/udp", "53/tcp", "8080:8000"])).unwrap(),
            vec![
                PortMap { public: 53, target: 53, proto: Proto::Udp, addr: None },
                PortMap { public: 53, target: 53, proto: Proto::Tcp, addr: None },
                PortMap { public: 8080, target: 8000, proto: Proto::Tcp, addr: None },
            ]
        );
        assert_eq!(parse_service_ports(&args(&["80:5080"])).unwrap(), vec!["80:5080".parse().unwrap()]);
    }

    #[test]
    fn serve_rejects_a_bad_mapping() {
        assert!(parse_service_ports(&args(&["80:5080", "nope"])).is_err());
    }

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
