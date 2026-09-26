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
) -> JoinHandle<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let policy = ProxyPolicy::new()
        // The backend sees the name it is served under, as it would behind
        // any reverse proxy; its configured base URL depends on it.
        .with_host_behaviour(HostBehaviour::Preserve)
        .with_x_forwarded_for(XForwardedFor::Append)
        .with_public_scheme("https");
    let router: axum::Router = ReverseProxy::new("/", format!("http://{upstream}")).with_policy(policy).into();
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
                    prepare(req.headers_mut(), caller.as_deref());
                    req.extensions_mut().insert(ConnectInfo(peer));
                    async move { router.oneshot(req.map(Body::new)).await }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls), service)
                    .await;
            });
        }
    })
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
