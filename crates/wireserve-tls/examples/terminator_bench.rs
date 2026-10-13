//! The terminator alone, in front of `count` backends, for load tests
//! against another proxy given the same certificate and backends.
//!
//! `terminator_bench <count> <cert dir> [port]`: service `i` (1-based) is
//! `s<i>.bench.test` on 127.0.0.<10 + i>, proxied to 127.0.0.1:<9000 + i>.
//! The wildcard certificate and key are written to `<cert dir>` as
//! `cert.pem` and `key.pem` for the other proxy to use.
//!
//! Load comes from one address, so `BENCH_MAX_PER_SOURCE` raises the
//! per-source connection limit past what the load generator opens.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rustls::sign::CertifiedKey;
use wireserve_tls::serve::{self, Certs, Policy, Route, Shared};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let count: u8 = args.next().and_then(|a| a.parse().ok()).expect("count");
    let dir = std::path::PathBuf::from(args.next().expect("cert dir"));
    let port: u16 = args.next().and_then(|a| a.parse().ok()).unwrap_or(11443);
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let key = rcgen::generate_simple_self_signed(vec!["*.bench.test".into()]).unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), key.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.signing_key.serialize_pem()).unwrap();
    let private =
        rustls_pki_types::PrivateKeyDer::try_from(key.signing_key.serialize_der()).unwrap();
    let certified = Arc::new(CertifiedKey::new(
        vec![key.cert.der().clone()],
        rustls::crypto::aws_lc_rs::sign::any_supported_type(&private).unwrap(),
    ));

    let certs = Arc::new(Certs::default());
    let shared = Shared::default();
    for i in 1..=count {
        let fqdn = format!("s{i}.bench.test");
        let vip = Ipv4Addr::new(127, 0, 0, 10 + i);
        certs.set(&fqdn, Arc::clone(&certified));
        let upstream = SocketAddr::from((Ipv4Addr::LOCALHOST, 9000 + u16::from(i)));
        shared
            .routes
            .write()
            .unwrap()
            .insert(vip, Arc::new(Route::new(upstream)));
        let access = wireserve_types::ServiceAccess {
            open: true,
            ..Default::default()
        };
        shared.policies.write().unwrap().insert(
            vip,
            Arc::new(Policy {
                fqdn,
                aliases: vec![],
                access,
                cross_site: false,
            }),
        );
    }
    let listener = serve::listener(port).unwrap();
    eprintln!("serving {count} services on :{port}");
    // Every load generator calls from one address, unlike a mesh.
    let mut limits = serve::Limits::default();
    if let Some(n) = std::env::var("BENCH_MAX_PER_SOURCE")
        .ok()
        .and_then(|n| n.parse().ok())
    {
        limits.max_per_source = n;
    }
    serve::spawn_with_limits(listener, serve::server_config(certs), shared, limits)
        .await
        .unwrap();
}
