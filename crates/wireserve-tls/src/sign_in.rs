//! The sign-in in front of marked services (PLAN.md M34): Caddy's
//! `forward_auth`, built in.
//!
//! Before a request to a marked service goes anywhere, a copy of it —
//! headers only — goes to the provider's verify endpoint, over verified TLS
//! on the provider service's own address, with `X-Forwarded-Method` and
//! `X-Forwarded-Uri`, and the service's own name — never the client's — in
//! `Host` and `X-Forwarded-Host`. Then:
//! * **2xx:** the request goes on, with the provider's identity headers
//!   (`copy_headers`) copied onto it. Every one of them was removed from the
//!   client's request first, so a client can never supply its own.
//! * **401 carrying `X-Login-Url`, for a GET or HEAD:** the browser is sent
//!   there with a 302 — it can come back to the same URL after signing in.
//! * **anything else:** the provider's answer goes back as it is (a 401
//!   without a login URL is authward's "please resubmit" page for a POST).
//!
//! The provider's session cookie is scoped to the whole domain, so the
//! browser sends it to every service; no backend needs it, and none gets it
//! — except the provider itself, whose cookie it is.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt as _;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use wireserve_types::tls::SignInTarget;

/// How long the provider may take to answer.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Resolves every name to one address: the provider's own.
#[derive(Clone, Copy)]
struct Fixed(SocketAddr);

impl tower::Service<Name> for Fixed {
    type Response = std::iter::Once<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Name) -> Self::Future {
        std::future::ready(Ok(std::iter::once(self.0)))
    }
}

/// The provider, resolved to one address, and a pooled client for it.
#[derive(Clone)]
pub struct SignIn {
    pub target: SignInTarget,
    client: Client<hyper_rustls::HttpsConnector<HttpConnector<Fixed>>, Body>,
}

/// What the check decided.
pub enum Verdict {
    /// Go on, with these identity headers set.
    Allow(HeaderMap),
    /// Answer the client with this instead.
    Deny(Response<Body>),
}

impl SignIn {
    /// A client that reaches `target.fqdn` at `target.vip:443` and nowhere
    /// else, trusting Mozilla's roots plus `extra_roots` (a test CA).
    pub fn new(target: SignInTarget, extra_roots: &[rustls_pki_types::CertificateDer<'static>]) -> Self {
        let vip: Ipv4Addr = target.vip;
        let mut http =
            HttpConnector::new_with_resolver(Fixed(SocketAddr::new(vip.into(), wireserve_types::TLS_PUBLIC_PORT)));
        http.enforce_http(false);
        http.set_connect_timeout(Some(TIMEOUT));
        let mut roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        for cert in extra_roots {
            let _ = roots.add(cert.clone());
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("the default provider supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .wrap_connector(http);
        let client = Client::builder(TokioExecutor::new()).pool_idle_timeout(Duration::from_secs(60)).build(https);
        Self { target, client }
    }

    /// Asks the provider about a request to the service `fqdn`. `headers`
    /// are the client's, already cleaned of forwarding headers. Taken apart
    /// rather than as the request itself, whose body could not be held
    /// across the check.
    ///
    /// The provider is told the service's own name — the one the connection
    /// was routed by — never the client's `Host`: providers choose their
    /// per-host rules by it, and a client could otherwise have another
    /// host's rules applied to this service.
    pub async fn check(&self, method: &Method, uri: &Uri, headers: &HeaderMap, fqdn: &str) -> Verdict {
        let Ok(host) = HeaderValue::from_str(fqdn) else {
            return Verdict::Deny(plain(StatusCode::INTERNAL_SERVER_ERROR, "bad service name"));
        };
        let verify: Uri = match format!("https://{}{}", self.target.fqdn, self.target.verify_path).parse() {
            Ok(u) => u,
            Err(_) => return Verdict::Deny(plain(StatusCode::INTERNAL_SERVER_ERROR, "bad sign-in address")),
        };
        let mut check = Request::builder().method(Method::GET).uri(verify).body(Body::empty()).expect("valid parts");
        for (name, value) in headers {
            if !is_hop_by_hop(name) && name != header::CONTENT_LENGTH && name != header::HOST && name != "x-forwarded-host" {
                check.headers_mut().append(name.clone(), value.clone());
            }
        }
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let h = check.headers_mut();
        h.insert(header::HOST, host.clone());
        h.insert("x-forwarded-host", host);
        h.insert("x-forwarded-method", HeaderValue::from_str(method.as_str()).expect("a method is a token"));
        if let Ok(v) = HeaderValue::from_str(path) {
            h.insert("x-forwarded-uri", v);
        }
        h.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        let resp = match tokio::time::timeout(TIMEOUT, self.client.request(check)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!(provider = %self.target.fqdn, error = %e, "sign-in unreachable");
                return Verdict::Deny(plain(StatusCode::BAD_GATEWAY, "sign-in unreachable"));
            }
            Err(_) => {
                tracing::warn!(provider = %self.target.fqdn, "sign-in did not answer in time");
                return Verdict::Deny(plain(StatusCode::GATEWAY_TIMEOUT, "sign-in did not answer"));
            }
        };
        let status = resp.status();
        if status.is_success() {
            let mut identity = HeaderMap::new();
            for name in &self.target.copy_headers {
                if let (Ok(n), Some(v)) = (HeaderName::from_bytes(name.as_bytes()), resp.headers().get(name.as_str())) {
                    identity.insert(n, v.clone());
                }
            }
            return Verdict::Allow(identity);
        }
        let login = resp.headers().get("x-login-url").cloned();
        let replayable = matches!(*method, Method::GET | Method::HEAD);
        if status == StatusCode::UNAUTHORIZED && replayable {
            if let Some(url) = login {
                let mut r = Response::new(Body::empty());
                *r.status_mut() = StatusCode::FOUND;
                r.headers_mut().insert(header::LOCATION, url);
                return Verdict::Deny(r);
            }
        }
        // The provider's own answer, as it is.
        let (parts, body) = resp.into_parts();
        let body = match body.collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return Verdict::Deny(plain(StatusCode::BAD_GATEWAY, "sign-in answer cut short")),
        };
        let mut r = Response::new(Body::from(body));
        *r.status_mut() = parts.status;
        for (name, value) in &parts.headers {
            if !is_hop_by_hop(name) && name != header::CONTENT_LENGTH {
                r.headers_mut().append(name.clone(), value.clone());
            }
        }
        Verdict::Deny(r)
    }
}

/// Removes every identity header the provider may send, so none a client
/// supplied survives, whether or not the provider sends it back.
pub fn strip_identity(headers: &mut HeaderMap, copy_headers: &[String]) {
    for name in copy_headers {
        headers.remove(name.as_str());
    }
}

/// Removes the provider's session cookie from the `Cookie` headers, leaving
/// every other cookie as it was.
pub fn strip_cookie(headers: &mut HeaderMap, cookie: &str) {
    let values: Vec<HeaderValue> = headers.get_all(header::COOKIE).iter().cloned().collect();
    if values.is_empty() {
        return;
    }
    headers.remove(header::COOKIE);
    let prefix = format!("{cookie}=");
    for value in values {
        let Ok(text) = value.to_str() else {
            // Not text; not ours to rewrite, and it cannot be our cookie
            // in a form we would recognise either.
            headers.append(header::COOKIE, value);
            continue;
        };
        let kept: Vec<&str> =
            text.split(';').map(str::trim).filter(|c| !c.is_empty() && !c.starts_with(&prefix)).collect();
        if !kept.is_empty() {
            if let Ok(v) = HeaderValue::from_str(&kept.join("; ")) {
                headers.append(header::COOKIE, v);
            }
        }
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "te" | "trailer" | "upgrade"
            | "proxy-authorization" | "proxy-authenticate"
    )
}

pub fn plain(status: StatusCode, text: &'static str) -> Response<Body> {
    let mut r = Response::new(Body::from(text));
    *r.status_mut() = status;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_session_cookie_is_removed() {
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_static("theme=dark; authward_session=abc; lang=de"));
        h.append(header::COOKIE, HeaderValue::from_static("authward_session=def"));
        strip_cookie(&mut h, "authward_session");
        let all: Vec<&str> = h.get_all(header::COOKIE).iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(all, vec!["theme=dark; lang=de"]);

        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("authward_session_x=1"));
        strip_cookie(&mut h, "authward_session");
        assert_eq!(h.get(header::COOKIE).unwrap(), "authward_session_x=1", "a longer name is someone else's");
    }

    #[test]
    fn identity_headers_a_client_sent_are_removed() {
        let mut h = HeaderMap::new();
        h.insert("x-auth-user", HeaderValue::from_static("admin"));
        h.insert("x-other", HeaderValue::from_static("kept"));
        strip_identity(&mut h, &["x-auth-user".into(), "x-auth-email".into()]);
        assert!(h.get("x-auth-user").is_none());
        assert_eq!(h.get("x-other").unwrap(), "kept");
    }
}
