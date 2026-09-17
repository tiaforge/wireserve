use std::net::SocketAddr;

use wireserve_coordinator::{build_state, config, db::Db, routes, Config};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = Config::from_env().unwrap_or_else(|err| {
        eprintln!("configuration error: {err}");
        std::process::exit(1);
    });

    let db = Db::open(&config.db_path).unwrap_or_else(|err| {
        eprintln!("failed to open database: {err}");
        std::process::exit(1);
    });

    let listen_addr = config.listen_addr;
    let admin_listen_addr = config.admin_listen_addr;
    let net_v4_cidr = config.net_v4_cidr.clone();
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

    tracing::info!(%listen_addr, %admin_listen_addr, "wireserve-coordinator starting");

    let node_server = axum::serve(node_listener, node_app);
    let admin_server = axum::serve(admin_listener, admin_app);

    if let Err(err) = tokio::try_join!(node_server, admin_server) {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}
