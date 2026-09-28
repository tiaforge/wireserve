//! Serving the services (PLAN.md M33): one TLS listener on an unprivileged
//! port of every address (PLAN.md M35), to which the agent rewrites each
//! service address's 443; each connection goes to the service whose
//! address it arrived on, and each request to its backend in plain HTTP.
//!
//! The proxying itself is `axum-reverse-proxy` over hyper — hop-by-hop
//! headers, WebSocket upgrades, HTTP/2, trailers. What is ours is only
//! the edge of it: which headers a backend may believe.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Request};
use axum_reverse_proxy::{HostBehaviour, ProxyPolicy, ReverseProxy, XForwardedFor};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower::ServiceExt as _;
use wireserve_types::tls::NODE_HEADER;

/// Mesh address → node name, shared by every listener and replaced on each
/// check-in.
pub type Callers = Arc<RwLock<HashMap<Ipv4Addr, String>>>;

/// The sign-in (PLAN.md M34), shared by every listener and replaced when
/// the provider moves. `None`: no provider reachable, and a marked service
/// refuses every request rather than serve one unchecked.
pub type SharedSignIn = Arc<RwLock<Option<crate::sign_in::SignIn>>>;

/// How one listener treats its requests.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Behind the sign-in.
    pub marked: bool,
    /// The name this listener serves. When it is the sign-in provider's —
    /// decided per request, since the provider can appear after its own
    /// listener started — its session cookie is its own, and stays.
    pub fqdn: String,
}

/// The certificate each name is served with, chosen by SNI. A handshake
/// for any other name — or none — fails: a service address answers for its
/// own name only.
#[derive(Debug, Default)]
pub struct Certs {
    by_name: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl Certs {
    pub fn set(&self, fqdn: &str, key: Arc<CertifiedKey>) {
        self.by_name.write().unwrap_or_else(std::sync::PoisonError::into_inner).insert(fqdn.to_ascii_lowercase(), key);
    }

    pub fn remove(&self, fqdn: &str) {
        self.by_name.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&fqdn.to_ascii_lowercase());
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.to_ascii_lowercase();
        self.by_name.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(&name).cloned()
    }
}

/// The TLS configuration every listener shares.
pub fn server_config(certs: Arc<Certs>) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the default provider supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(certs);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    // Resumption without a server-side cache: the default one holds 256
    // sessions for every service and client together, and each handshake
    // issues two, so with more than a few clients a returning phone finds
    // its session gone and pays for a full handshake. The ticket keys
    // rotate every few hours and never leave memory.
    if let Ok(ticketer) = rustls::crypto::aws_lc_rs::Ticketer::new() {
        config.ticketer = ticketer;
    }
    Arc::new(config)
}

/// One service, as the listener finds it by the address a connection
/// arrived on.
#[derive(Clone)]
pub struct Route {
    router: axum::Router,
    policy: Policy,
}

impl Route {
    /// Proxies to `upstream` in plain HTTP.
    pub fn new(upstream: SocketAddr, policy: Policy) -> Self {
        let proxy_policy = ProxyPolicy::new()
            // The backend sees the name it is served under, as it would behind
            // any reverse proxy; its configured base URL depends on it.
            .with_host_behaviour(HostBehaviour::Preserve)
            .with_x_forwarded_for(XForwardedFor::Append)
            .with_public_scheme("https");
        let router = ReverseProxy::new("/", format!("http://{upstream}")).with_policy(proxy_policy).into();
        Self { router, policy }
    }
}

/// Service address → its service, shared by the listener and replaced as
/// services come and go. An address not in it is nobody's: its connections
/// are closed unanswered.
pub type Routes = Arc<RwLock<HashMap<Ipv4Addr, Arc<Route>>>>;

/// The one listening socket (PLAN.md M35): the one systemd passed us when
/// `wireserve-tls.socket` started this process — held by systemd across
/// restarts, so no other local user can take the port in between — or,
/// run outside systemd, `0.0.0.0:port` bound here.
pub fn listener(port: u16) -> std::io::Result<TcpListener> {
    use std::os::fd::FromRawFd;
    let pid = std::process::id();
    let passed = listen_fd(pid, std::env::var("LISTEN_PID").ok().as_deref(), std::env::var("LISTEN_FDS").ok().as_deref());
    // Left in the environment: the runtime's other threads may read it, and
    // a child could never mistake them for its own, `LISTEN_PID` being ours.
    let std_listener = match passed {
        // SAFETY: systemd passed this descriptor to this very process
        // (LISTEN_PID), and nothing else in it has taken ownership of it.
        Some(fd) => unsafe { std::net::TcpListener::from_raw_fd(fd) },
        None => {
            use socket2::{Domain, Protocol, Socket, Type};
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.set_reuse_address(true)?;
            socket.bind(&SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port).into())?;
            socket.listen(1024)?;
            socket.into()
        }
    };
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

/// The descriptor systemd's socket activation passed this process, if it
/// passed one: `LISTEN_PID` names us, and `LISTEN_FDS` counts at least
/// one, starting at 3.
fn listen_fd(pid: u32, listen_pid: Option<&str>, listen_fds: Option<&str>) -> Option<std::os::fd::RawFd> {
    const SD_LISTEN_FDS_START: std::os::fd::RawFd = 3;
    let for_us = listen_pid?.parse::<u32>().ok()? == pid;
    let count = listen_fds?.parse::<u32>().ok()?;
    (for_us && count >= 1).then_some(SD_LISTEN_FDS_START)
}

/// Accepts on `listener` until aborted, handing each connection to the
/// service whose address it arrived on.
pub fn spawn(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    routes: Routes,
    callers: Callers,
    sign_in: SharedSignIn,
) -> JoinHandle<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            // The address the agent rewrote 443 to this port on. Anything
            // else — the host's own addresses, a service no longer served
            // — is nobody's to answer.
            let route = tcp.local_addr().ok().and_then(|a| local_v4(a.ip())).and_then(|vip| {
                routes.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(&vip).cloned()
            });
            let Some(route) = route else {
                continue;
            };
            // Without it, Nagle holds back the tail of a response written in
            // more than one TLS record until the client ACKs the head — which
            // its delayed ACK puts off by up to 40ms here, and on a phone's
            // link by a round trip on top.
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let callers = callers.clone();
            let sign_in = sign_in.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let caller = match peer.ip() {
                    std::net::IpAddr::V4(v4) => {
                        callers.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(&v4).cloned()
                    }
                    std::net::IpAddr::V6(_) => None,
                };
                let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                    let router = route.router.clone();
                    let sign_in = sign_in.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                    let route = route.clone();
                    prepare(req.headers_mut(), caller.as_deref());
                    req.extensions_mut().insert(ConnectInfo(peer));
                    async move {
                        let mut req = req.map(Body::new);
                        match guard(&mut req, sign_in.as_ref(), &route.policy).await {
                            Some(denied) => Ok(denied),
                            None => router.oneshot(req).await,
                        }
                    }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await;
            });
        }
    })
}

/// An IPv4 local address, also when a dual-stack socket reports it mapped.
fn local_v4(ip: std::net::IpAddr) -> Option<Ipv4Addr> {
    match ip {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// The sign-in's part of a request (PLAN.md M34): `Some` is the answer to
/// send instead of passing it on.
async fn guard(
    req: &mut Request<Body>,
    sign_in: Option<&crate::sign_in::SignIn>,
    policy: &Policy,
) -> Option<axum::response::Response> {
    if let Some(si) = sign_in {
        crate::sign_in::strip_identity(req.headers_mut(), &si.target.copy_headers);
    }
    if policy.marked {
        let Some(si) = sign_in else {
            return Some(crate::sign_in::plain(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "this service is behind a sign-in that cannot be reached",
            ));
        };
        let (method, uri, headers) = (req.method().clone(), req.uri().clone(), req.headers().clone());
        match si.check(&method, &uri, &headers).await {
            crate::sign_in::Verdict::Allow(identity) => req.headers_mut().extend(identity),
            crate::sign_in::Verdict::Deny(answer) => return Some(answer),
        }
    }
    if let Some(si) = sign_in {
        if !si.target.fqdn.eq_ignore_ascii_case(&policy.fqdn) {
            crate::sign_in::strip_cookie(req.headers_mut(), &si.target.session_cookie);
        }
    }
    None
}

/// Strips every header a client could use to claim to be someone else, and
/// names the calling node. The forwarding headers are then set afresh by
/// the proxy from the connection itself — never appended to what the client
/// sent.
pub fn prepare(headers: &mut HeaderMap, caller: Option<&str>) {
    for name in ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "x-real-ip", NODE_HEADER] {
        headers.remove(name);
    }
    if let Some(node) = caller.and_then(|n| HeaderValue::from_str(n).ok()) {
        headers.insert(NODE_HEADER, node);
    }
    join_cookies(headers);
}

/// Browsers speaking HTTP/2 send each cookie as a header of its own, and the
/// backend is spoken to in HTTP/1.1, where there may be only one: many
/// backends read the first and never see the rest — a session cookie among
/// them. RFC 9113 §8.2.3 has the proxy join them with "; ".
fn join_cookies(headers: &mut HeaderMap) {
    use axum::http::header::COOKIE;
    if headers.get_all(COOKIE).iter().nth(1).is_none() {
        return;
    }
    let crumbs: Vec<&[u8]> = headers.get_all(COOKIE).iter().map(HeaderValue::as_bytes).collect();
    let joined = crumbs.join(&b"; "[..]);
    if let Ok(value) = HeaderValue::from_bytes(&joined) {
        headers.insert(COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_in() -> crate::sign_in::SignIn {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        crate::sign_in::SignIn::new(
            wireserve_types::tls::SignInTarget {
                fqdn: "auth.int.test".into(),
                vip: "10.9.0.60".parse().unwrap(),
                verify_path: "/verify".into(),
                copy_headers: vec!["x-auth-user".into()],
                session_cookie: "authward_session".into(),
            },
            &[],
        )
    }

    fn request() -> Request<Body> {
        Request::builder()
            .header("cookie", "theme=dark; authward_session=s3cret")
            .header("x-auth-user", "mallory")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn a_marked_service_without_a_reachable_sign_in_refuses() {
        let mut req = request();
        let answer = guard(&mut req, None, &Policy { marked: true, fqdn: "jellyfin.int.test".into() }).await;
        assert_eq!(answer.expect("refused").status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn every_backend_but_the_providers_loses_the_cookie_and_forged_identity() {
        let si = sign_in();
        let mut req = request();
        assert!(guard(&mut req, Some(&si), &Policy { marked: false, fqdn: "grafana.int.test".into() }).await.is_none());
        assert_eq!(req.headers().get("cookie").unwrap(), "theme=dark");
        assert!(req.headers().get("x-auth-user").is_none());

        // The provider's own service keeps its session cookie — decided per
        // request, whatever the listener was started with.
        let mut req = request();
        assert!(guard(&mut req, Some(&si), &Policy { marked: false, fqdn: "Auth.int.test".into() }).await.is_none());
        assert_eq!(req.headers().get("cookie").unwrap(), "theme=dark; authward_session=s3cret");
        assert!(req.headers().get("x-auth-user").is_none(), "a forged identity is removed there too");
    }

    #[tokio::test]
    async fn without_a_sign_in_nothing_is_touched() {
        let mut req = request();
        assert!(guard(&mut req, None, &Policy { marked: false, fqdn: "grafana.int.test".into() }).await.is_none());
        assert_eq!(req.headers().get("cookie").unwrap(), "theme=dark; authward_session=s3cret");
    }

    #[test]
    fn only_a_socket_passed_to_this_very_process_is_taken() {
        assert_eq!(listen_fd(42, Some("42"), Some("1")), Some(3));
        assert_eq!(listen_fd(42, Some("41"), Some("1")), None, "meant for another process");
        assert_eq!(listen_fd(42, Some("42"), Some("0")), None);
        assert_eq!(listen_fd(42, None, Some("1")), None);
        assert_eq!(listen_fd(42, Some("42"), None), None);
        assert_eq!(listen_fd(42, Some("x"), Some("1")), None);
    }

    #[tokio::test]
    async fn a_connection_goes_to_the_service_whose_address_it_arrived_on() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|| async { "from the backend" });
            axum::serve(backend, app).await.unwrap();
        });

        let key = rcgen::generate_simple_self_signed(vec!["svc.test".into()]).unwrap();
        let der = key.cert.der().clone();
        let private = rustls_pki_types::PrivateKeyDer::try_from(key.signing_key.serialize_der()).unwrap();
        let certs = Arc::new(Certs::default());
        certs.set("svc.test", Arc::new(CertifiedKey::new(vec![der.clone()], rustls::crypto::aws_lc_rs::sign::any_supported_type(&private).unwrap())));
        let listener = listener(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes: Routes = Arc::default();
        routes.write().unwrap().insert(
            Ipv4Addr::LOCALHOST,
            Arc::new(Route::new(upstream, Policy { marked: false, fqdn: "svc.test".into() })),
        );
        spawn(listener, server_config(certs), routes, Arc::default(), Arc::default());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let client = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
        ));
        let connect = |ip: &str| {
            let (client, addr) = (client.clone(), format!("{ip}:{port}"));
            async move {
                let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
                client.connect(rustls_pki_types::ServerName::try_from("svc.test").unwrap(), tcp).await
            }
        };

        let mut tls = connect("127.0.0.1").await.expect("routed: served");
        tls.write_all(b"GET / HTTP/1.1\r\nhost: svc.test\r\nconnection: close\r\n\r\n").await.unwrap();
        let mut answer = String::new();
        tls.read_to_string(&mut answer).await.unwrap();
        assert!(answer.ends_with("from the backend"), "{answer}");

        assert!(connect("127.0.0.2").await.is_err(), "an address nobody is routed to is closed unanswered");
    }

    #[test]
    fn forged_headers_are_removed_and_the_caller_named() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        h.insert("forwarded", HeaderValue::from_static("for=1.2.3.4"));
        h.insert(NODE_HEADER, HeaderValue::from_static("admin-laptop"));
        h.insert("cookie", HeaderValue::from_static("a=b"));
        prepare(&mut h, Some("phone"));
        assert!(h.get("x-forwarded-for").is_none() && h.get("forwarded").is_none());
        assert_eq!(h.get(NODE_HEADER).unwrap(), "phone");
        assert_eq!(h.get("cookie").unwrap(), "a=b");

        prepare(&mut h, None);
        assert!(h.get(NODE_HEADER).is_none(), "an unknown caller is named by nobody");
    }

    #[tokio::test]
    async fn cookies_sent_one_per_header_reach_the_backend_as_one() {
        let mut req = request();
        req.headers_mut().remove("cookie");
        for crumb in ["theme=dark", "authward_session=s3cret", "auth_tokens=abc"] {
            req.headers_mut().append("cookie", HeaderValue::from_static(crumb));
        }
        prepare(req.headers_mut(), None);
        let cookies: Vec<_> = req.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies, ["theme=dark; authward_session=s3cret; auth_tokens=abc"]);

        // And the sign-in's cookie still comes out of the joined header.
        assert!(guard(&mut req, Some(&sign_in()), &Policy { marked: false, fqdn: "observe.int.test".into() }).await.is_none());
        let cookies: Vec<_> = req.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies, ["theme=dark; auth_tokens=abc"]);
    }
}
