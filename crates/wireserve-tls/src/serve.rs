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

/// A calling node: its name, and its owner (PLAN.md M38) if it has one.
#[derive(Debug, Clone)]
pub struct CallerInfo {
    pub node: String,
    pub owner: Option<wireserve_types::CallerIdentity>,
}

/// Mesh address → the node calling from it, shared by every listener and
/// replaced on each check-in.
pub type Callers = Arc<RwLock<HashMap<Ipv4Addr, CallerInfo>>>;

/// The sign-in (PLAN.md M34), shared by every listener and replaced when
/// the provider moves. `None`: no provider reachable, and nobody gets in by
/// signing in.
pub type SharedSignIn = Arc<RwLock<Option<crate::sign_in::SignIn>>>;

/// How one service treats its requests.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The name this service is served under. When it is the sign-in
    /// provider's — decided per request, since the provider can appear after
    /// its own service started — its session cookie is its own, and stays.
    pub fqdn: String,
    /// Who may in (PLAN.md M36).
    pub access: wireserve_types::ServiceAccess,
}

/// Service address → how it treats requests. Read on every request, and
/// replaced in place on every check-in, so a changed grant applies to the
/// next request on a connection already open.
pub type Policies = Arc<RwLock<HashMap<Ipv4Addr, Arc<Policy>>>>;

/// Everything the listener reads per request, each part replaced on its own
/// as check-ins bring changes.
#[derive(Clone, Default)]
pub struct Shared {
    pub routes: Routes,
    pub policies: Policies,
    pub callers: Callers,
    pub sign_in: SharedSignIn,
    pub identity: Arc<RwLock<wireserve_types::IdentityHeaders>>,
}

impl Shared {
    /// Stops answering on `vip`: its connections close, and requests on
    /// ones already open are refused.
    pub fn unroute(&self, vip: Ipv4Addr) {
        self.routes.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&vip);
        self.policies.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&vip);
    }
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

/// One service's backend, as the listener finds it by the address a
/// connection arrived on.
#[derive(Clone)]
pub struct Route {
    router: axum::Router,
}

impl Route {
    /// Proxies to `upstream` in plain HTTP.
    pub fn new(upstream: SocketAddr) -> Self {
        let proxy_policy = ProxyPolicy::new()
            // The backend sees the name it is served under, as it would behind
            // any reverse proxy; its configured base URL depends on it.
            .with_host_behaviour(HostBehaviour::Preserve)
            .with_x_forwarded_for(XForwardedFor::Append)
            .with_public_scheme("https");
        let router = ReverseProxy::new("/", format!("http://{upstream}")).with_policy(proxy_policy).into();
        Self { router }
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
///
/// The service's policy and the caller's name are looked up for every
/// request, not once per connection: a grant taken away, or a node
/// revoked, reaches a keep-alive or HTTP/2 connection at its next request.
/// A WebSocket, once upgraded, is past every request and keeps going.
pub fn spawn(listener: TcpListener, tls: Arc<rustls::ServerConfig>, shared: Shared) -> JoinHandle<()> {
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
            let Some(vip) = tcp.local_addr().ok().and_then(|a| local_v4(a.ip())) else {
                continue;
            };
            let route = shared.routes.read().unwrap_or_else(std::sync::PoisonError::into_inner).get(&vip).cloned();
            let Some(route) = route else {
                continue;
            };
            // Without it, Nagle holds back the tail of a response written in
            // more than one TLS record until the client ACKs the head — which
            // its delayed ACK puts off by up to 40ms here, and on a phone's
            // link by a round trip on top.
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let shared = shared.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let caller_addr = local_v4(peer.ip());
                let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                    let router = route.router.clone();
                    let policy = read(&shared.policies).get(&vip).cloned();
                    let caller = caller_addr.and_then(|a| read(&shared.callers).get(&a).cloned());
                    let sign_in = read(&shared.sign_in).clone();
                    let identity = read(&shared.identity).clone();
                    let misdirected = policy.as_ref().is_some_and(|p| !for_this_service(&req, &p.fqdn));
                    if misdirected {
                        tracing::info!(
                            service = policy.as_ref().map(|p| p.fqdn.as_str()).unwrap_or_default(),
                            authority = req.uri().authority().map(|a| a.as_str()).unwrap_or_default(),
                            host = ?req.headers().get(axum::http::header::HOST),
                            version = ?req.version(),
                            "misdirected request: it names another host"
                        );
                    }
                    prepare(req.headers_mut(), caller.as_ref().map(|c| c.node.as_str()));
                    req.extensions_mut().insert(ConnectInfo(peer));
                    async move {
                        let Some(policy) = policy else {
                            return Ok(crate::sign_in::plain(
                                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                "this service is no longer served here",
                            ));
                        };
                        if misdirected {
                            return Ok(crate::sign_in::plain(
                                axum::http::StatusCode::MISDIRECTED_REQUEST,
                                "this address serves another name",
                            ));
                        }
                        let mut req = req.map(Body::new);
                        let owner = caller.and_then(|c| c.owner);
                        match guard(&mut req, sign_in.as_ref(), &policy, caller_addr, owner.as_ref(), &identity).await {
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

fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An IPv4 local address, also when a dual-stack socket reports it mapped.
fn local_v4(ip: std::net::IpAddr) -> Option<Ipv4Addr> {
    match ip {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// Whether a request names the service its connection was routed to, in
/// its `Host` and, over HTTP/2 or in absolute form, its authority. The
/// routing is by address; a request naming another host would otherwise
/// reach this backend — and the sign-in — under a name it does not have.
fn for_this_service<B>(req: &Request<B>, fqdn: &str) -> bool {
    let same = |host: &str| {
        let host = host.strip_suffix('.').unwrap_or(host);
        host.eq_ignore_ascii_case(fqdn)
    };
    let authority = req.uri().host();
    let header = match req.headers().get(axum::http::header::HOST) {
        Some(v) => match v.to_str() {
            Ok(h) => Some(without_port(h)),
            Err(_) => return false,
        },
        None => None,
    };
    if authority.is_none() && header.is_none() {
        return false;
    }
    authority.is_none_or(same) && header.is_none_or(same)
}

/// `name:port` without the port; anything else as it is.
fn without_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Who gets in (PLAN.md M34, M36): `Some` is the answer to send instead of
/// passing the request on.
///
/// 1. Identity headers a client sent are removed, always.
/// 2. An open service, or a caller whose node the grants name, goes on —
///    with its owner named, if it has one (PLAN.md M38).
/// 3. Anyone else, where the grants name groups a sign-in can prove, is
///    asked about: signed in with one of them, on — with who they are;
///    signed in without, 403; not signed in, sent to sign in.
/// 4. Anyone else is refused with 403.
///
/// The provider's session cookie leaves every request but the provider's
/// own.
async fn guard(
    req: &mut Request<Body>,
    sign_in: Option<&crate::sign_in::SignIn>,
    policy: &Policy,
    caller: Option<Ipv4Addr>,
    owner: Option<&wireserve_types::CallerIdentity>,
    identity: &wireserve_types::IdentityHeaders,
) -> Option<axum::response::Response> {
    use axum::http::StatusCode;
    crate::sign_in::strip_identity(req.headers_mut(), identity);
    let access = &policy.access;
    let by_device = access.open || caller.is_some_and(|c| access.sources.contains(&c));
    if by_device {
        if let Some(owner) = owner {
            name_owner(req.headers_mut(), owner, identity);
        }
    } else {
        if !access.sign_in {
            return Some(crate::sign_in::plain(StatusCode::FORBIDDEN, "this device may not reach this service"));
        }
        let Some(si) = sign_in else {
            return Some(crate::sign_in::plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "this service is behind a sign-in that cannot be reached",
            ));
        };
        let (method, uri, headers) = (req.method().clone(), req.uri().clone(), req.headers().clone());
        match si.check(&method, &uri, &headers, &policy.fqdn, identity).await {
            crate::sign_in::Verdict::Allow { headers, groups } => {
                if !groups.iter().any(|g| access.sign_in_groups.contains(g)) {
                    return Some(crate::sign_in::plain(StatusCode::FORBIDDEN, "signed in, but not allowed here"));
                }
                req.headers_mut().extend(headers);
            }
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

/// Tells the backend who the calling device belongs to, in the same
/// headers a sign-in fills.
fn name_owner(headers: &mut HeaderMap, owner: &wireserve_types::CallerIdentity, identity: &wireserve_types::IdentityHeaders) {
    let mut set = |name: &str, value: &str| {
        if let (Ok(n), Ok(v)) = (axum::http::HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            headers.insert(n, v);
        }
    };
    set(&identity.user, &owner.user);
    if let Some(email) = &owner.email {
        set(&identity.email, email);
    }
    set(&identity.groups, &owner.groups.join(","));
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
                session_cookie: "authward_session".into(),
            },
            &[],
        )
    }

    fn open(fqdn: &str) -> Policy {
        Policy { fqdn: fqdn.into(), access: wireserve_types::ServiceAccess { open: true, ..Default::default() } }
    }

    /// Reached by 10.9.0.2 alone; anyone else may sign in with `family`.
    fn restricted(fqdn: &str, sign_in: bool) -> Policy {
        Policy {
            fqdn: fqdn.into(),
            access: wireserve_types::ServiceAccess {
                sources: vec!["10.9.0.2".parse().unwrap()],
                sign_in,
                sign_in_groups: vec!["family".into()],
                ..Default::default()
            },
        }
    }

    fn ids() -> wireserve_types::IdentityHeaders {
        wireserve_types::IdentityHeaders::default()
    }

    fn request() -> Request<Body> {
        Request::builder()
            .header("cookie", "theme=dark; authward_session=s3cret")
            .header("x-auth-user", "mallory")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn a_granted_device_goes_on_and_anyone_else_is_refused_or_asked() {
        use axum::http::StatusCode;
        let granted = Some("10.9.0.2".parse().unwrap());
        let other = Some("10.9.0.3".parse().unwrap());
        let mut req = request();
        assert!(guard(&mut req, None, &restricted("jf.int.test", false), granted, None, &ids()).await.is_none());
        assert!(req.headers().get("x-auth-user").is_none(), "a forged identity is removed for a device too");

        let answer = guard(&mut request(), None, &restricted("jf.int.test", false), other, None, &ids()).await;
        assert_eq!(answer.expect("refused").status(), StatusCode::FORBIDDEN, "no sign-in to try");
        let answer = guard(&mut request(), None, &restricted("jf.int.test", false), None, None, &ids()).await;
        assert_eq!(answer.expect("refused").status(), StatusCode::FORBIDDEN, "an unknown caller neither");

        let answer = guard(&mut request(), None, &restricted("jf.int.test", true), other, None, &ids()).await;
        assert_eq!(answer.expect("refused").status(), StatusCode::SERVICE_UNAVAILABLE, "the sign-in is unreachable");
    }

    #[tokio::test]
    async fn every_backend_but_the_providers_loses_the_cookie_and_forged_identity() {
        let si = sign_in();
        let mut req = request();
        assert!(guard(&mut req, Some(&si), &open("grafana.int.test"), None, None, &ids()).await.is_none());
        assert_eq!(req.headers().get("cookie").unwrap(), "theme=dark");
        assert!(req.headers().get("x-auth-user").is_none());

        // The provider's own service keeps its session cookie — decided per
        // request, whatever the listener was started with.
        let mut req = request();
        assert!(guard(&mut req, Some(&si), &open("Auth.int.test"), None, None, &ids()).await.is_none());
        assert_eq!(req.headers().get("cookie").unwrap(), "theme=dark; authward_session=s3cret");
        assert!(req.headers().get("x-auth-user").is_none(), "a forged identity is removed there too");
    }

    #[tokio::test]
    async fn a_granted_devices_owner_is_named_and_nobody_elses() {
        let owner = wireserve_types::CallerIdentity {
            addr: "10.9.0.2".parse().unwrap(),
            user: "sub-alice".into(),
            email: Some("alice@example.com".into()),
            groups: vec!["family".into(), "admins".into()],
        };
        let granted = Some("10.9.0.2".parse().unwrap());
        let mut req = request();
        assert!(guard(&mut req, None, &restricted("jf.int.test", false), granted, Some(&owner), &ids()).await.is_none());
        assert_eq!(req.headers()["x-auth-user"], "sub-alice", "not mallory");
        assert_eq!(req.headers()["x-auth-email"], "alice@example.com");
        assert_eq!(req.headers()["x-auth-groups"], "family,admins");

        // A device the grants do not name gets no one's identity.
        let other = Some("10.9.0.3".parse().unwrap());
        let mut req = request();
        assert!(guard(&mut req, None, &restricted("jf.int.test", false), other, Some(&owner), &ids()).await.is_some());
    }

    #[tokio::test]
    async fn without_a_sign_in_the_cookie_stays_but_a_forged_identity_does_not() {
        let mut req = request();
        assert!(guard(&mut req, None, &open("grafana.int.test"), None, None, &ids()).await.is_none());
        assert_eq!(req.headers().get("cookie").unwrap(), "theme=dark; authward_session=s3cret");
        assert!(req.headers().get("x-auth-user").is_none());
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
        let shared = Shared::default();
        shared.routes.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(Route::new(upstream)));
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(open("svc.test")));
        spawn(listener, server_config(certs), shared.clone());

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

        let mut tls = connect("127.0.0.1").await.expect("routed: served");
        tls.write_all(b"GET / HTTP/1.1\r\nhost: other.test\r\nconnection: close\r\n\r\n").await.unwrap();
        let mut answer = String::new();
        tls.read_to_string(&mut answer).await.unwrap();
        assert!(answer.starts_with("HTTP/1.1 421"), "{answer}");
        assert!(!answer.contains("from the backend"));

        // A grant taken away applies to the next request on a connection
        // already open.
        let mut tls = connect("127.0.0.1").await.expect("routed: served");
        let get = b"GET / HTTP/1.1\r\nhost: svc.test\r\n\r\n";
        tls.write_all(get).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tls.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default() };
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(closed));
        tls.write_all(get).await.unwrap();
        let n = tls.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 403"), "{}", String::from_utf8_lossy(&buf[..n]));

        assert!(connect("127.0.0.2").await.is_err(), "an address nobody is routed to is closed unanswered");
    }

    #[test]
    fn a_request_must_name_the_service_it_was_routed_to() {
        let req = |uri: &str, host: Option<&str>| {
            let mut b = Request::builder().uri(uri);
            if let Some(h) = host {
                b = b.header("host", h);
            }
            b.body(()).unwrap()
        };
        let fqdn = "jellyfin.int.test";
        assert!(for_this_service(&req("/", Some("jellyfin.int.test")), fqdn));
        assert!(for_this_service(&req("/", Some("Jellyfin.INT.test:443")), fqdn));
        assert!(for_this_service(&req("/", Some("jellyfin.int.test.")), fqdn));
        assert!(for_this_service(&req("https://jellyfin.int.test/x", None), fqdn), "HTTP/2's authority");
        assert!(!for_this_service(&req("/", Some("grafana.int.test")), fqdn));
        assert!(!for_this_service(&req("/", Some("jellyfin.int.test.evil")), fqdn));
        assert!(!for_this_service(&req("/", None), fqdn), "no name at all");
        assert!(
            !for_this_service(&req("https://jellyfin.int.test/", Some("grafana.int.test")), fqdn),
            "authority and Host disagreeing"
        );
        assert!(!for_this_service(&req("https://grafana.int.test/", Some("jellyfin.int.test")), fqdn));
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
        assert!(guard(&mut req, Some(&sign_in()), &open("observe.int.test"), None, None, &ids()).await.is_none());
        let cookies: Vec<_> = req.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies, ["theme=dark; auth_tokens=abc"]);
    }
}
