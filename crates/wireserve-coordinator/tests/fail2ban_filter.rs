//! The fail2ban filter that ships in `deploy/fail2ban/` must match what the
//! coordinator really logs on a failed authentication. It once did not — the
//! filter expected the address in quotes and the log has none — so the jail
//! matched nothing and banned nobody, silently.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::connect_info::ConnectInfo;
use axum::http::Request;
use tower::ServiceExt;
use wireserve_coordinator::{build_state_with_dns, db::Db, routes};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
    type Writer = Buf;
    fn make_writer(&'a self) -> Buf {
        self.clone()
    }
}

/// The filter's `failregex`, as a Rust regex: `<HOST>` becomes an address.
fn failregex() -> regex::Regex {
    let conf = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/fail2ban/wireserve.conf")).unwrap();
    let line = conf.lines().find_map(|l| l.strip_prefix("failregex = ")).expect("a failregex");
    regex::Regex::new(&line.replace("<HOST>", "(?P<host>[0-9A-Fa-f:.]+)")).unwrap()
}

fn request(method: &str, uri: &str, bearer: &str, from: &str) -> Request<Body> {
    let mut r = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(Body::from(if uri == "/register" { r#"{"join_token":"jtk_nope","pubkey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","listen_port":1}"# } else { "{}" }))
        .unwrap();
    r.extensions_mut().insert(ConnectInfo(from.parse::<std::net::SocketAddr>().unwrap()));
    r
}

#[tokio::test]
async fn the_shipped_filter_matches_every_failed_authentication_the_coordinator_logs() {
    let buf = Buf::default();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(buf.clone()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let file = tempfile::NamedTempFile::new().unwrap();
    let path = file.path().to_str().unwrap().to_string();
    let config = wireserve_coordinator::Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_listen_addr: "127.0.0.1:0".parse().unwrap(),
        admin_token: "the-admin-token".into(),
        db_path: path.clone(),
        net_v4_cidr: "100.90.0.0/24".into(),
        net_v6_prefix: "fd00:90::/64".into(),
        service_domain: None,
        sign_in: None,
        identity_headers: Default::default(),
        strip_headers: Vec::new(),
        forwarding_nodes: Vec::new(),
        cross_site_services: Vec::new(),
        public_url: None,
        oidc: None,
        dns: None,
        acme: wireserve_coordinator::config::acme_from_lookup(|_| None).unwrap(),
        online_threshold_secs: 180,
        relay_port_base: wireserve_types::DEFAULT_RELAY_PORT_BASE,
        rate_limit_max: 1000,
        rate_limit_window_secs: 60,
        trust_proxy_headers: false,
        trusted_proxy: None,
        join_token_ttl_secs: 1800,
        global_auth_failure_max: u32::MAX,
        global_auth_failure_window_secs: 60,
        require_service_approval: true,
        reflexive_rate_limit_max: 1000,
        reflexive_rate_limit_window_secs: 60,
        poll_rate_burst: 20,
        poll_rate_per_min: 0,
        reserved_service_names: Vec::new(),
    };
    let state = build_state_with_dns(config, Db::open(&path).unwrap(), None);
    let router = routes::node_router(state.clone()).merge(routes::admin_router(state));

    let cases = [
        ("POST", "/poll", "brt_wrong", "203.0.113.9:4000", "203.0.113.9"),
        ("POST", "/register", "unused", "198.51.100.20:4000", "198.51.100.20"),
        ("GET", "/admin/peers", "not-the-admin-token", "192.0.2.77:4000", "192.0.2.77"),
        ("POST", "/poll", "brt_wrong", "[2001:db8::7]:4000", "2001:db8::7"),
    ];
    for (method, uri, bearer, from, _) in cases {
        let _ = router.clone().oneshot(request(method, uri, bearer, from)).await.unwrap();
    }

    let log = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = log.lines().filter(|l| l.contains("auth_failure")).collect();
    assert_eq!(lines.len(), cases.len(), "one line per failure:\n{log}");
    let re = failregex();
    for (line, (_, uri, _, _, want)) in lines.iter().zip(cases) {
        let caps = re.captures(line).unwrap_or_else(|| panic!("the filter does not match {uri}'s line: {line}"));
        assert_eq!(&caps["host"], want, "{line}");
    }
    // And nothing else the coordinator says is taken for a failure.
    assert!(!re.is_match("2026-09-29T16:23:04Z  INFO wireserve_coordinator: node registered client_ip=203.0.113.9"));
}
