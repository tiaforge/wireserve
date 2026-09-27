//! Serving one service (PLAN.md M33): a TLS listener on its own address,
//! port 443, handing each request to its backend in plain HTTP.
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
    Arc::new(config)
}

/// Binds `vip:443`. `IP_FREEBIND` lets the bind happen before the agent has
/// made the address local; nothing arrives until it has.
pub fn bind(vip: Ipv4Addr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_freebind_v4(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(vip.into(), wireserve_types::TLS_PUBLIC_PORT).into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Accepts on `listener` until aborted, proxying every request to
/// `upstream` in plain HTTP.
pub fn spawn(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    upstream: SocketAddr,
    callers: Callers,
    sign_in: SharedSignIn,
    policy: Policy,
) -> JoinHandle<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let proxy_policy = ProxyPolicy::new()
        // The backend sees the name it is served under, as it would behind
        // any reverse proxy; its configured base URL depends on it.
        .with_host_behaviour(HostBehaviour::Preserve)
        .with_x_forwarded_for(XForwardedFor::Append)
        .with_public_scheme("https");
    let router: axum::Router = ReverseProxy::new("/", format!("http://{upstream}")).with_policy(proxy_policy).into();
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
            let acceptor = acceptor.clone();
            let router = router.clone();
            let callers = callers.clone();
            let sign_in = sign_in.clone();
            let policy = policy.clone();
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
                    let router = router.clone();
                    let sign_in = sign_in.read().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                    let policy = policy.clone();
                    prepare(req.headers_mut(), caller.as_deref());
                    req.extensions_mut().insert(ConnectInfo(peer));
                    async move {
                        let mut req = req.map(Body::new);
                        match guard(&mut req, sign_in.as_ref(), &policy).await {
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
}
