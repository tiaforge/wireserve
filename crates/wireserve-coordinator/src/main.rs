use std::net::SocketAddr;

use wireserve_coordinator::{build_state, config, db::Db, routes, Config};

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

#[tokio::main]
async fn main() {
    init_logging();

    let loaded = Config::load().unwrap_or_else(|err| {
        eprintln!("configuration error: {err}");
        std::process::exit(1);
    });
    let config = loaded.config;

    if !loaded.generated.is_empty() {
        eprintln!("======================================================================");
        eprintln!("wireserve-coordinator: first run — generated the following and saved");
        eprintln!("them to {}:", loaded.secrets_path.display());
        for key in &loaded.generated {
            match *key {
                "WIRESERVE_ADMIN_TOKEN" => {
                    eprintln!("  WIRESERVE_ADMIN_TOKEN = {}", config.admin_token);
                }
                "WIRESERVE_NET_V4_CIDR" => {
                    eprintln!("  WIRESERVE_NET_V4_CIDR = {}", config.net_v4_cidr);
                }
                "WIRESERVE_NET_V6_PREFIX" => {
                    eprintln!("  WIRESERVE_NET_V6_PREFIX = {}", config.net_v6_prefix);
                }
                _ => {}
            }
        }
        eprintln!(
            "These are kept for the life of this mesh — nothing else needs to be done, and \
             `sudo cat {}` retrieves them again any time. Set any of these as an environment \
             variable yourself if you'd rather manage it your own way; an explicit value \
             always overrides what's stored here.",
            loaded.secrets_path.display()
        );
        eprintln!("======================================================================");
    }

    let db = Db::open(&config.db_path).unwrap_or_else(|err| {
        eprintln!("failed to open database: {err}");
        std::process::exit(1);
    });

    let listen_addr = config.listen_addr;
    let admin_listen_addr = config.admin_listen_addr;
    let net_v4_cidr = config.net_v4_cidr.clone();
    let net_v6_prefix = config.net_v6_prefix.clone();
    let state = build_state(config, db);

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

    tracing::info!(%listen_addr, %admin_listen_addr, "wireserve-coordinator starting");

    let node_server = axum::serve(node_listener, node_app);
    let admin_server = axum::serve(admin_listener, admin_app);

    if let Err(err) = tokio::try_join!(node_server, admin_server) {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}
