use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use wireserve_coordinator::{build_state_with_dns, config, dns, db::Db, rate_limit, reflexive, routes, Config};

/// Initialises logging with `info` as the floor rather than tracing's own
/// default.
///
/// `tracing_subscriber::fmt::init()` builds an `EnvFilter` from `RUST_LOG`,
/// and an unset `RUST_LOG` yields a filter that passes `ERROR` only. That
/// is a reasonable default for a library and the wrong one here: spec §7
/// requires an audit log of node creation, registration, revoke, rejoin
/// and service declare/withdraw, and every one of those is emitted at
/// `INFO`. Shipping with them filtered out means the audit log exists in
/// the source and produces nothing on a real deployment — along with every
/// startup warning about listener binding and mesh addressing. `RUST_LOG`
/// still overrides this in either direction.
fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "wireserve-coordinator",
    version,
    about = "The WireServe coordinator. With no command, runs the server."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Sets the coordinator up on this machine: asks a few questions,
    /// installs this binary (and the wireserve-admin next to it), creates
    /// the wireserve-coordinator user, and starts the service. On a machine
    /// where it is already installed, upgrades it instead. Needs root.
    Install(Box<wireserve_coordinator::install::InstallArgs>),
    /// Used by `install`, as the admin user, to save wireserve-admin's
    /// settings in their home.
    #[command(hide = true)]
    SaveAdminConfig,
}

fn main() {
    match Cli::parse().command {
        None => serve(),
        Some(Command::Install(args)) => {
            if let Err(err) = wireserve_coordinator::install::run(*args) {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        }
        Some(Command::SaveAdminConfig) => {
            if let Err(err) = wireserve_coordinator::install::admin_config::save_from_env() {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        }
    }
}

#[tokio::main]
async fn serve() {
    init_logging();

    let loaded = Config::load().unwrap_or_else(|err| {
        eprintln!("configuration error: {err}");
        std::process::exit(1);
    });
    let config = loaded.config;

    if !loaded.generated.is_empty() {
        eprint!("{}", first_run_banner(&loaded.generated, &config, &loaded.secrets_path));
    }

    let db = Db::open(&config.db_path).unwrap_or_else(|err| {
        eprintln!("failed to open database: {err}");
        std::process::exit(1);
    });

    let listen_addr = config.listen_addr;
    let admin_listen_addr = config.admin_listen_addr;
    let net_v4_cidr = config.net_v4_cidr.clone();
    let net_v6_prefix = config.net_v6_prefix.clone();
    let reflexive_rate_limit_max = config.reflexive_rate_limit_max;
    let reflexive_rate_limit_window_secs = config.reflexive_rate_limit_window_secs;
    let dns_writer = config.dns.as_ref().map(|cfg| {
        let provider = dns::provider::Provider::connect(cfg).unwrap_or_else(|err| {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        });
        tracing::info!(provider = cfg.provider.name(), zone = %cfg.zone, "publishing service names to public DNS");
        std::sync::Arc::new(provider) as std::sync::Arc<dyn dns::provider::DnsWriter>
    });
    let state = build_state_with_dns(config, db, dns_writer);
    if let Some(dns) = state.dns.clone() {
        tokio::spawn(dns::sync::run(state.clone(), dns));
    }
    if let Some(oidc) = state.oidc.clone() {
        tracing::info!(issuer = %oidc.config.issuer, "device owners sign in through the identity provider");
        tokio::spawn(wireserve_coordinator::oidc::refresh::run(state.clone(), oidc));
    }

    let node_app = routes::node_router(state.clone())
        .into_make_service_with_connect_info::<SocketAddr>();
    let admin_app = routes::admin_router(state).into_make_service_with_connect_info::<SocketAddr>();

    let node_listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .unwrap_or_else(|err| {
            eprintln!("failed to bind node-facing listener on {listen_addr}: {err}");
            std::process::exit(1);
        });
    let admin_listener = tokio::net::TcpListener::bind(admin_listen_addr)
        .await
        .unwrap_or_else(|err| {
            eprintln!("failed to bind admin listener on {admin_listen_addr}: {err}");
            std::process::exit(1);
        });
    // Same port NUMBER as the node-facing HTTP listener, just UDP — TCP
    // and UDP are independent port namespaces, so this has never
    // conflicted with the listener above (PLAN.md M22). Always bound to
    // every interface regardless of what host `listen_addr` itself uses:
    // that TCP side is commonly scoped to loopback/private on purpose (a
    // reverse proxy in front, spec §7), but this responder's whole job
    // is being directly reachable by NAT'd agents on the internet, so it
    // must never inherit a narrower bind.
    let reflexive_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_addr.port());
    let reflexive_socket = tokio::net::UdpSocket::bind(reflexive_addr)
        .await
        .unwrap_or_else(|err| {
            eprintln!("failed to bind reflexive UDP responder on {reflexive_addr}: {err}");
            std::process::exit(1);
        });

    if !config::is_loopback_or_private(listen_addr.ip()) {
        tracing::warn!(
            %listen_addr,
            "node-facing listener is bound to a non-loopback, non-private address — spec §7 \
             requires this to sit behind a TLS-terminating reverse proxy and never be directly \
             reachable from an untrusted network; confirm nothing routes to this port except \
             that proxy"
        );
    }

    if config::v4_cidr_overlaps_cgnat(&net_v4_cidr) {
        tracing::warn!(
            mesh_v4_cidr = %net_v4_cidr,
            "mesh IPv4 range overlaps 100.64.0.0/10, the carrier-grade-NAT block that \
             Tailscale (and some ISPs) allocate from. If any node also runs such an \
             overlay, that overlay's route for 100.64.0.0/10 covers these mesh addresses, \
             and traffic meant for a WireServe peer can leave over the wrong interface. \
             Set WIRESERVE_NET_V4_CIDR to a range you control (e.g. 10.90.0.0/24) before \
             the first node registers — existing nodes keep the address they were already \
             allocated, so changing it later only affects new ones"
        );
    }

    if config::v6_prefix_has_nonrandom_global_id(&net_v6_prefix) {
        tracing::warn!(
            mesh_v6_prefix = %net_v6_prefix,
            "mesh IPv6 prefix is inside fd00::/16, so its RFC 4193 Global ID is a \
             hand-picked round number rather than the 40 pseudo-random bits the standard \
             calls for. That randomness is what stops two independently-built networks \
             from colliding, and fd00:: prefixes are among the most commonly chosen by \
             hand, so this is the ULA most likely to clash with something else on the \
             same host. Generate one with: python3 -c \"import secrets; \
             h=secrets.token_bytes(5).hex(); print(f'fd{{h[0:2]}}:{{h[2:6]}}:{{h[6:10]}}::/64')\" \
             and set WIRESERVE_NET_V6_PREFIX before the first node registers"
        );
    }

    eprintln!("========================================================================");
    eprintln!("wireserve-coordinator is up.");
    eprintln!();
    eprintln!(
        "  Point your reverse proxy at:  http://{}",
        proxy_target(listen_addr)
    );
    eprintln!("  (it must terminate TLS — the coordinator itself never speaks TLS, §7)");
    if let Some(url) = std::env::var("WIRESERVE_PUBLIC_URL").ok().filter(|u| !u.is_empty()) {
        eprintln!("  Machines reach it at:         {url}");
    }
    eprintln!();
    eprintln!(
        "  Reflexive UDP responder (NAT-traversal step 2) is on port {} too — but that \
         one your proxy can't forward: it needs its own direct UDP forward at your \
         firewall/router, since a reverse proxy only speaks HTTP.",
        listen_addr.port()
    );
    eprintln!();
    eprintln!("  Next: add a node —  wireserve-admin create-node <name>");
    eprintln!("========================================================================");

    tracing::info!(%listen_addr, %admin_listen_addr, %reflexive_addr, "wireserve-coordinator starting");

    let reflexive_limiter = std::sync::Arc::new(rate_limit::SlidingWindowLimiter::new(
        reflexive_rate_limit_max,
        reflexive_rate_limit_window_secs,
    ));
    tokio::spawn(reflexive::serve(reflexive_socket, reflexive_limiter));

    let node_server = axum::serve(node_listener, node_app);
    let admin_server = axum::serve(admin_listener, admin_app);

    if let Err(err) = tokio::try_join!(node_server, admin_server) {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}

/// The one-time notice printed when first-run values were generated.
///
/// Names the admin token but never prints it (security review finding
/// #5): stderr is the journal under systemd, readable by every member of
/// `systemd-journal`/`adm` and kept for as long as the journal is, and
/// the token controls the whole mesh. The mesh ranges are not secret and
/// stay inline. The file itself is mode 600.
fn first_run_banner(generated: &[&str], config: &Config, secrets_path: &std::path::Path) -> String {
    use std::fmt::Write;
    let rule = "======================================================================";
    let path = secrets_path.display();
    let mut out = String::new();
    let _ = writeln!(out, "{rule}");
    let _ = writeln!(out, "wireserve-coordinator: first run — generated the following and saved");
    let _ = writeln!(out, "them to {path}:");
    for key in generated {
        match *key {
            "WIRESERVE_ADMIN_TOKEN" => {
                let _ = writeln!(out, "  WIRESERVE_ADMIN_TOKEN   (not shown here, so it stays out of the logs)");
            }
            "WIRESERVE_NET_V4_CIDR" => {
                let _ = writeln!(out, "  WIRESERVE_NET_V4_CIDR = {}", config.net_v4_cidr);
            }
            "WIRESERVE_NET_V6_PREFIX" => {
                let _ = writeln!(out, "  WIRESERVE_NET_V6_PREFIX = {}", config.net_v6_prefix);
            }
            _ => {}
        }
    }
    if generated.contains(&"WIRESERVE_ADMIN_TOKEN") {
        let _ = writeln!(out, "Read the admin token with:  sudo grep WIRESERVE_ADMIN_TOKEN {path}");
    }
    let _ = writeln!(
        out,
        "These are kept for the life of this mesh — nothing else needs to be done, and \
         `sudo cat {path}` retrieves them again any time. Set any of these as an environment \
         variable yourself if you'd rather manage it your own way; an explicit value \
         always overrides what's stored here."
    );
    let _ = writeln!(out, "{rule}");
    out
}

/// Resolves a listen address to the one a reverse proxy on the same host
/// should actually be told to connect to. A wildcard bind (`0.0.0.0` or
/// `::`) is not itself a connectable address — nothing dials `0.0.0.0` —
/// but a proxy on the same host reaches it via loopback regardless of
/// what it bound to, so that's what gets printed instead. An address the
/// operator explicitly set to something else (a specific interface, a
/// container-network address) is left as-is, since that's what actually
/// matters for whatever topology led them to set it.
fn proxy_target(addr: SocketAddr) -> SocketAddr {
    if !addr.ip().is_unspecified() {
        return addr;
    }
    let loopback = match addr {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    SocketAddr::new(loopback, addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_run_banner_never_contains_the_admin_token() {
        let config = Config {
            listen_addr: "127.0.0.1:47820".parse().unwrap(),
            admin_listen_addr: "127.0.0.1:47821".parse().unwrap(),
            admin_token: "s3cr3t-admin-token-value".into(),
            db_path: "x.db".into(),
            net_v4_cidr: "10.1.2.0/24".into(),
            net_v6_prefix: "fdab:cdef:1234::/64".into(),
            service_domain: None,
            dns: None,
            acme: config::acme_from_lookup(|_| None).unwrap(),
            sign_in: None,
            identity_headers: Default::default(),
            public_url: None,
            oidc: None,
            online_threshold_secs: 180,
            relay_port_base: wireserve_types::DEFAULT_RELAY_PORT_BASE,
            rate_limit_max: 10,
            rate_limit_window_secs: 60,
            trust_proxy_headers: false,
            trusted_proxy: None,
            join_token_ttl_secs: 1800,
            global_auth_failure_max: 20,
            global_auth_failure_window_secs: 60,
            require_service_approval: true,
            reflexive_rate_limit_max: 20,
            reflexive_rate_limit_window_secs: 10,
            poll_rate_burst: 20,
            poll_rate_per_min: 0,
            reserved_service_names: Vec::new(),
            strip_headers: Vec::new(),
        };
        let generated = ["WIRESERVE_ADMIN_TOKEN", "WIRESERVE_NET_V4_CIDR", "WIRESERVE_NET_V6_PREFIX"];
        let path = std::path::Path::new("/var/lib/wireserve-coordinator/coordinator-secrets.env");
        let banner = first_run_banner(&generated, &config, path);
        assert!(!banner.contains("s3cr3t-admin-token-value"), "{banner}");
        assert!(banner.contains("sudo grep WIRESERVE_ADMIN_TOKEN /var/lib/wireserve-coordinator/coordinator-secrets.env"));
        assert!(banner.contains("10.1.2.0/24") && banner.contains("fdab:cdef:1234::/64"));
    }

    #[test]
    fn wildcard_v4_resolves_to_loopback() {
        let addr: SocketAddr = "0.0.0.0:47820".parse().unwrap();
        assert_eq!(proxy_target(addr), "127.0.0.1:47820".parse().unwrap());
    }

    #[test]
    fn wildcard_v6_resolves_to_loopback() {
        let addr: SocketAddr = "[::]:47820".parse().unwrap();
        assert_eq!(proxy_target(addr), "[::1]:47820".parse().unwrap());
    }

    #[test]
    fn explicit_address_is_left_alone() {
        let addr: SocketAddr = "10.0.0.5:47820".parse().unwrap();
        assert_eq!(proxy_target(addr), addr);
    }
}
