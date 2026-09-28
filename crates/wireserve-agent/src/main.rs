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
#[command(name = "wireserve")]
struct Cli {
    /// Which agent instance to act on. Each instance is a separate node
    /// with its own state, interface, firewall rules and hosts-file block,
    /// so one host can run several agents side by side (one per mesh, for
    /// instance). The default instance uses the paths a single agent
    /// always has.
    #[arg(long, global = true, env = "WIRESERVE_INSTANCE", default_value = paths::DEFAULT_INSTANCE, value_parser = parse_instance)]
    instance: Instance,
    #[command(subcommand)]
    command: Command,
}

/// Shared by `join` and `install` — the latter does everything the former
/// does, plus installs the binary and systemd unit around it, so both
/// take exactly the same bootstrap arguments.
#[derive(clap::Args)]
struct JoinArgs {
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
    /// The UDP port WireGuard listens on. Without it: this instance's
    /// previous port on a re-join, otherwise the first free one from
    /// 51820 up that no other instance on this host has.
    #[arg(long)]
    listen_port: Option<u16>,
    #[arg(long)]
    endpoint_addr: Option<String>,
    /// Allow a plain http:// coordinator URL to a non-loopback host.
    /// Refused otherwise: the join token, this node's bearer token and
    /// the peer directory would all cross the network unprotected. Only
    /// for a coordinator reached over a network you trust end to end;
    /// remembered for the daemon.
    #[arg(long)]
    allow_plaintext_http: bool,
}

#[derive(Subcommand)]
enum Command {
    /// One-time bootstrap: redeem a join token issued by `wireserve-admin
    /// create-node`, generating this node's keypair locally.
    Join(JoinArgs),
    /// Installs the binary to /usr/local/bin, installs and enables the
    /// right systemd unit for this instance (plain, or the `@.service`
    /// template for a named instance), then joins — everything
    /// `wireserve-admin create-node`'s printed command needs, in one
    /// step. Also creates the `wireserve` group whose members can run the
    /// other commands without sudo. Needs root, and Linux/systemd
    /// (Quadlet/podman deployments install by hand, per `deploy/quadlet/`).
    Install(JoinArgs),
    /// Runs the poll loop and IPC server. This is the long-running daemon.
    Daemon {
        #[arg(long, default_value_t = 20)]
        poll_interval_secs: u64,
        /// The WireGuard interface to run on. Without it, the instance
        /// keeps the name it used last, or picks the first free one of
        /// wireserve0..wireserve15. A name given here is pinned: used
        /// exactly, on this and every later start, or the daemon refuses
        /// to start. `auto` removes a pin.
        #[arg(long, value_parser = parse_ifname_flag)]
        ifname: Option<ifname::Flag>,
    },
    /// Queues a local service declaration, applied on the next poll.
    ///
    /// Each PORT is `[PUBLIC:][ADDRESS:]TARGET[/tcp|/udp]`:
    /// `<name>.wg:PUBLIC` reaches TARGET on this node, or on ADDRESS when
    /// given — an IPv4 address this node reaches, such as a router on its
    /// LAN, which then sees the connection come from this node (TCP unless
    /// given; a bare port maps to itself). `serve web 80:5080`,
    /// `serve dns 53/udp 53/tcp 8080:8000`, `serve myrouter 443:192.168.178.1:80`.
    Serve {
        name: String,
        #[arg(required = true, value_name = "PORT")]
        ports: Vec<String>,
    },
    /// Queues a local service withdrawal, applied on the next poll.
    Unserve { name: String },
    /// Opts this node in or out of carrying transit traffic for other mesh
    /// peers that can't reach each other directly (PLAN.md M23) — a live
    /// operational toggle, same shape as `serve`/`unserve`: takes effect
    /// next poll, no rejoin. Off by default; a node with metered/capped
    /// traffic should simply never turn it on. Opting in is only half:
    /// the coordinator ignores the offer until an admin also approves
    /// this node with `wireserve-admin approve-transit`.
    Transit {
        #[command(subcommand)]
        action: TransitAction,
    },
    /// Opts this node in or out of being the exit for the devices that use
    /// it as their gateway (PLAN.md M27): their full-tunnel profile sends
    /// all of their internet traffic here, and it leaves under this host's
    /// own public address. Off by default. Only half the consent: a device
    /// uses it only once an admin exports it with
    /// `wireserve-admin export-config --exit`, and the node must already be
    /// a gateway (`transit on`, approved).
    Exit {
        #[command(subcommand)]
        action: TransitAction,
    },
    /// Shows this node's services, peers and anything not published, from
    /// the daemon's cache of the last poll — no network call.
    List {
        /// Print the cached view as JSON instead, for scripts.
        #[arg(long)]
        json: bool,
    },
    /// Tears down the interface, firewall, and hosts-file block.
    Leave,
    /// Runs this node's TLS terminator (PLAN.md M33): serves each of its
    /// services published on TCP 443 with TLS on the service's own address,
    /// with a certificate it obtains itself. Run by the `wireserve-tls`
    /// unit, as its own unprivileged user, beside the daemon.
    TlsServe {
        /// Where certificates and the ACME account are kept. Defaults to
        /// the unit's state directory.
        #[arg(long, value_name = "DIR", env = "STATE_DIRECTORY")]
        state_dir: Option<std::path::PathBuf>,
        /// Trust this CA for the ACME server itself — a test CA such as
        /// Pebble. Never needed for Let's Encrypt.
        #[arg(long, value_name = "PEM", env = "WIRESERVE_ACME_CA_FILE", hide = true)]
        acme_ca_file: Option<std::path::PathBuf>,
        /// Trust this CA too when checking the sign-in provider's
        /// certificate — a test CA. Never needed with a public CA.
        #[arg(long, value_name = "PEM", env = "WIRESERVE_TLS_TRUST_FILE", hide = true)]
        trust_file: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = 5, hide = true)]
        check_in_secs: u64,
    },
}

#[derive(Subcommand)]
enum TransitAction {
    On,
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
        Command::TlsServe { state_dir, acme_ca_file, trust_file, check_in_secs } => {
            // systemd may list several colon-separated state directories;
            // the unit names exactly one.
            let state_dir = state_dir
                .and_then(|d| d.to_str().and_then(|s| s.split(':').next()).map(std::path::PathBuf::from))
                .unwrap_or_else(|| instance.tls_state_dir());
            wireserve_tls::run(wireserve_tls::Options {
                socket: instance.tls_socket_path(),
                state_dir,
                ca_file: acme_ca_file,
                trust_file,
                check_in_every: Duration::from_secs(check_in_secs.max(1)),
            })
            .await
            .map_err(Into::into)
        }
        Command::Serve { name, ports } => cmd_serve(&instance, name, &ports).await,
        Command::Unserve { name } => cmd_unserve(&instance, name).await,
        Command::Transit { action } => cmd_transit(&instance, action).await,
        Command::Exit { action } => cmd_exit(&instance, action).await,
        Command::List { json } => cmd_list(&instance, json).await,
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
async fn cmd_install(instance: &Instance, args: JoinArgs) -> Result<(), Box<dyn std::error::Error>> {
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
    let tls_unit = wireserve_agent::install::install_tls_unit(instance)?;
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
    wireserve_agent::install::systemctl_enable_now(&tls_unit)?;
    let instance_flag = if instance.is_default() { String::new() } else { format!(" --instance {}", instance.name()) };
    println!();
    println!("{unit} is running — `wireserve{instance_flag} list` shows its services and peers");
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
    let own_reflexive_addr =
        wireserve_agent::reflexive::learn_reflexive_addr(&coordinator_url, listen_port, wireserve_agent::reflexive::PROBE_TIMEOUT).await;
    tracing::info!(reflexive_addr = ?own_reflexive_addr, "one-shot reflexive-address probe");

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
        || start_interop(&ifname, firewall::ForwardWanted::of(&state), own_table),
        |wg| {
            wg.bring_up(&private_key, ip4, ip6, listen_port)
                .map_err(Into::<Box<dyn std::error::Error>>::into)
        },
    )?;

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
    // F1 (security review, round 2): exactly ONE in-memory copy of the
    // agent state, shared by the poll loop and the IPC server. The
    // previous design kept two copies and re-synced them at cycle
    // boundaries, which still silently dropped any `serve`/`unserve`
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
            _ = interval.tick() => {
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
                };
                let result = poll_loop::run_once(&mut ctx, &shared_state).await;
                // Safety net for host-firewall changes the interop's own
                // change monitor can't see (legacy iptables, firewalld) —
                // and the place the transit opt-in and target-address
                // services are re-read, since `transit on` and `serve`
                // mutate a running daemon and the host firewall's FORWARD
                // hook has to follow them.
                interop.tick(firewall::ForwardWanted::of(&*shared_state.lock().await));

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
                        // `wireserve-admin rejoin` overwrites it anyway.
                        tracing::error!(
                            "poll rejected with 401 {} times in a row — this node has been \
                             revoked; tearing down and stopping (run `wireserve join` \
                             again with a fresh token from `wireserve-admin rejoin` to rejoin)",
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
        drop(claim);
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

/// `serve`'s port arguments, each a [`PortMap`].
fn parse_serve_ports(args: &[String]) -> Result<Vec<PortMap>, String> {
    args.iter().map(|a| a.parse::<PortMap>()).collect()
}

async fn cmd_serve(instance: &Instance, name: String, ports: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let ports = parse_serve_ports(ports)?;
    wireserve_types::validate_service_ports(&ports)?;
    let resp = client::call(&instance.socket_path(), &IpcRequest::Serve { name, ports }).await?;
    // "ok" alone overstates what just happened: the declaration is queued
    // locally and only reaches the coordinator on the next poll, and if
    // that coordinator requires approval it will sit pending until an
    // admin acts. The agent cannot know which until it polls, so say what
    // is actually true and point at where the answer shows up.
    if matches!(resp, wireserve_agent::ipc::IpcResponse::Ok) {
        println!("ok — queued; takes effect on the next poll");
        println!(
            "  if this coordinator requires admin approval, `wireserve list` will show \
             it as pending until an admin approves it"
        );
        return Ok(());
    }
    print_response(resp);
    Ok(())
}

async fn cmd_unserve(instance: &Instance, name: String) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client::call(&instance.socket_path(), &IpcRequest::Unserve { name }).await?;
    print_response(resp);
    Ok(())
}

async fn cmd_transit(instance: &Instance, action: TransitAction) -> Result<(), Box<dyn std::error::Error>> {
    let enabled = matches!(action, TransitAction::On);
    let resp = client::call(&instance.socket_path(), &IpcRequest::TransitCapable { enabled }).await?;
    if matches!(resp, wireserve_agent::ipc::IpcResponse::Ok) {
        if enabled {
            println!(
                "ok — transit enabled; this node carries traffic only once an admin approves \
                 it (`wireserve-admin approve-transit <node>`), from the next poll after that"
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

async fn cmd_exit(instance: &Instance, action: TransitAction) -> Result<(), Box<dyn std::error::Error>> {
    let enabled = matches!(action, TransitAction::On);
    let resp = client::call(&instance.socket_path(), &IpcRequest::ExitCapable { enabled }).await?;
    if matches!(resp, wireserve_agent::ipc::IpcResponse::Ok) {
        if enabled {
            println!(
                "ok — exit enabled; devices exported with `wireserve-admin export-config --exit` \
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

async fn cmd_list(instance: &Instance, json: bool) -> Result<(), Box<dyn std::error::Error>> {
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

    #[test]
    fn serve_takes_port_mappings() {
        assert_eq!(
            parse_serve_ports(&args(&["53/udp", "53/tcp", "8080:8000"])).unwrap(),
            vec![
                PortMap { public: 53, target: 53, proto: Proto::Udp, addr: None },
                PortMap { public: 53, target: 53, proto: Proto::Tcp, addr: None },
                PortMap { public: 8080, target: 8000, proto: Proto::Tcp, addr: None },
            ]
        );
        assert_eq!(parse_serve_ports(&args(&["80:5080"])).unwrap(), vec!["80:5080".parse().unwrap()]);
    }

    #[test]
    fn serve_rejects_a_bad_mapping() {
        assert!(parse_serve_ports(&args(&["80:5080", "nope"])).is_err());
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
