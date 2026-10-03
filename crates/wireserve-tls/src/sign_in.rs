//! The sign-in in front of marked services (PLAN.md M34): Caddy's
//! `forward_auth`, built in.
//!
//! Before a request to a marked service goes anywhere, a copy of it —
//! headers only — goes to the provider's verify endpoint, over verified TLS
//! on the provider service's own address, with `X-Forwarded-Method` and
//! `X-Forwarded-Uri`, and the service's own name — never the client's — in
//! `X-Forwarded-Host`. `Host` is the provider's own name: it sits behind its
//! own node's terminator, which answers for that name only. Then:
//! * **2xx:** the provider knows who it is; the terminator decides whether
//!   they may in (PLAN.md M36), and if so the request goes on with the
//!   provider's identity headers copied onto it. Every one of them was
//!   removed from the client's request first, so a client can never supply
//!   its own.
//! * **401 carrying `X-Login-Url`, for a GET or HEAD:** the browser is sent
//!   there with a 302 — it can come back to the same URL after signing in.
//! * **anything else:** the provider's answer goes back as it is (a 401
//!   without a login URL is authward's "please resubmit" page for a POST).
//!
//! The provider's session cookie is scoped to the whole domain, so the
//! browser sends it to every service; no backend needs it, and none gets it
//! — except the provider itself, whose cookie it is.
//!
//! A 2xx naming someone is reused while the provider says it may be (PLAN.md
//! M37): `Cache-Control: max-age`, and a `Vary` naming the request headers
//! the answer depends on — which must include the cookie or
//! `Authorization`, or one person's answer could reach another. Nothing
//! else is kept, and nothing is kept without the provider asking: plain
//! forward_auth providers are asked every time, as before.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt as _;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use wireserve_types::tls::SignInTarget;
use wireserve_types::IdentityHeaders;

/// How long the provider may take to answer.
const TIMEOUT: Duration = Duration::from_secs(10);

/// The longest an answer is reused fresh, or kept for a provider that is
/// down, whatever the provider says.
const MAX_CACHE_AGE: Duration = Duration::from_secs(3600);

/// At most this many answers are kept.
const CACHE_ENTRIES: usize = 10_000;

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
    cache: Arc<Mutex<Cache>>,
}

/// How long an answer may be reused, and what it depends on — from the
/// provider's own `Cache-Control` and `Vary`.
#[derive(Debug, PartialEq, Eq)]
struct Caching {
    max_age: Duration,
    stale_if_error: Duration,
    vary: Vec<HeaderName>,
}

/// The answers kept (PLAN.md M37), for one provider.
#[derive(Default)]
struct Cache {
    /// Per service name: the request headers the provider's last cacheable
    /// answer said it depends on — what a request is looked up by.
    vary: HashMap<String, Vec<HeaderName>>,
    entries: HashMap<[u8; 32], Entry>,
}

struct Entry {
    headers: HeaderMap,
    groups: Vec<String>,
    fresh_until: Instant,
    /// Past `fresh_until`, still used while the provider cannot be asked.
    usable_until: Instant,
}

impl Cache {
    fn lookup(&self, fqdn: &str, sent: &HeaderMap, now: Instant, provider_down: bool) -> Option<Verdict> {
        let vary = self.vary.get(fqdn)?;
        let e = self.entries.get(&key(fqdn, vary, sent))?;
        let usable = now < e.fresh_until || (provider_down && now < e.usable_until);
        usable.then(|| Verdict::Allow { headers: e.headers.clone(), groups: e.groups.clone() })
    }

    fn store(&mut self, fqdn: &str, sent: &HeaderMap, c: Caching, headers: &HeaderMap, groups: &[String], now: Instant) {
        if self.entries.len() >= CACHE_ENTRIES {
            self.entries.retain(|_, e| e.usable_until > now);
        }
        if self.entries.len() >= CACHE_ENTRIES {
            if let Some(oldest) = self.entries.iter().min_by_key(|(_, e)| e.usable_until).map(|(k, _)| *k) {
                self.entries.remove(&oldest);
            }
        }
        let fresh_until = now + c.max_age;
        let entry = Entry {
            headers: headers.clone(),
            groups: groups.to_vec(),
            fresh_until,
            usable_until: fresh_until + c.stale_if_error,
        };
        self.entries.insert(key(fqdn, &c.vary, sent), entry);
        self.vary.insert(fqdn.to_string(), c.vary);
    }
}

/// The request a cached answer stands for: the service, and the value of
/// every header the provider varies on, exactly as sent — hashed, so no
/// cookie is ever kept.
fn key(fqdn: &str, vary: &[HeaderName], sent: &HeaderMap) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(fqdn.as_bytes());
    for name in vary {
        h.update([0]);
        h.update(name.as_str().as_bytes());
        for value in sent.get_all(name) {
            h.update([1]);
            h.update(value.as_bytes());
        }
    }
    h.finalize().into()
}

/// Whether, and for how long, a 2xx may be reused: `max-age` above zero,
/// neither `no-store` nor `no-cache`, and a `Vary` that is not `*` and names
/// the cookie or `Authorization` — an answer that does not depend on who is
/// asking must never be kept per person.
fn caching(headers: &HeaderMap) -> Option<Caching> {
    let directives: Vec<String> = headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|d| d.trim().to_ascii_lowercase())
        .collect();
    let seconds = |name: &str| {
        directives.iter().find_map(|d| d.strip_prefix(name)?.strip_prefix('=')?.trim_matches('"').parse::<u64>().ok())
    };
    if directives.iter().any(|d| d == "no-store" || d == "no-cache") {
        return None;
    }
    let max_age = Duration::from_secs(seconds("max-age").filter(|s| *s > 0)?).min(MAX_CACHE_AGE);
    let stale_if_error = Duration::from_secs(seconds("stale-if-error").unwrap_or(0)).min(MAX_CACHE_AGE);
    let mut vary = Vec::new();
    for value in headers.get_all(header::VARY) {
        for name in value.to_str().ok()?.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            if name == "*" {
                return None;
            }
            vary.push(HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()).ok()?);
        }
    }
    if !vary.iter().any(|n| n == header::COOKIE || n == header::AUTHORIZATION) {
        return None;
    }
    vary.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    vary.dedup();
    Some(Caching { max_age, stale_if_error, vary })
}

/// What the check decided.
pub enum Verdict {
    /// Signed in: these identity headers, and the groups they name.
    Allow { headers: HeaderMap, groups: Vec<String> },
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
        Self { target, client, cache: Arc::default() }
    }

    /// The header-only copy of the client's request that goes to the
    /// provider. `client` is the mesh address of the device that made it —
    /// the TCP peer, so never something the client wrote — sent as the one
    /// `X-Forwarded-For` value, which is what a `forward_auth` provider
    /// reads the client address from (and may bind a session to).
    fn check_request(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        fqdn: &str,
        client: Option<Ipv4Addr>,
    ) -> Result<Request<Body>, Verdict> {
        let Ok(host) = HeaderValue::from_str(fqdn) else {
            return Err(Verdict::Deny(plain(StatusCode::INTERNAL_SERVER_ERROR, "bad service name")));
        };
        let verify: Uri = match format!("https://{}{}", self.target.fqdn, self.target.verify_path).parse() {
            Ok(u) => u,
            Err(_) => return Err(Verdict::Deny(plain(StatusCode::INTERNAL_SERVER_ERROR, "bad sign-in address"))),
        };
        let mut check = Request::builder().method(Method::GET).uri(verify).body(Body::empty()).expect("valid parts");
        for (name, value) in headers {
            if !is_hop_by_hop(name) && name != header::CONTENT_LENGTH && name != header::HOST && name != "x-forwarded-host" {
                check.headers_mut().append(name.clone(), value.clone());
            }
        }
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let h = check.headers_mut();
        if let Ok(provider) = HeaderValue::from_str(&self.target.fqdn) {
            h.insert(header::HOST, provider);
        }
        h.insert("x-forwarded-host", host);
        h.insert("x-forwarded-method", HeaderValue::from_str(method.as_str()).expect("a method is a token"));
        if let Ok(v) = HeaderValue::from_str(path) {
            h.insert("x-forwarded-uri", v);
        }
        h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        // Replaced, never appended to: one address, the device's.
        h.remove("x-forwarded-for");
        if let Some(addr) = client {
            if let Ok(v) = HeaderValue::from_str(&addr.to_string()) {
                h.insert("x-forwarded-for", v);
            }
        }
        Ok(check)
    }

    /// Asks the provider about a request to the service `fqdn`. `headers`
    /// are the client's, already cleaned of forwarding headers. Taken apart
    /// rather than as the request itself, whose body could not be held
    /// across the check.
    ///
    /// The provider is told the service's own name — the one the connection
    /// was routed by — in `X-Forwarded-Host`, never the client's `Host`:
    /// providers choose their per-host rules by it, and a client could
    /// otherwise have another host's rules applied to this service. `Host`
    /// is the provider's own name, as for any request to it.
    /// `X-Forwarded-For` is the calling device's address, `client`.
    pub async fn check(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        fqdn: &str,
        identity: &IdentityHeaders,
        client: Option<Ipv4Addr>,
    ) -> Verdict {
        let check = match self.check_request(method, uri, headers, fqdn, client) {
            Ok(r) => r,
            Err(v) => return v,
        };
        let sent = check.headers().clone();
        let cached = |provider_down: bool| {
            self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).lookup(fqdn, &sent, Instant::now(), provider_down)
        };
        if let Some(hit) = cached(false) {
            return hit;
        }
        let resp = match tokio::time::timeout(TIMEOUT, self.client.request(check)).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!(provider = %self.target.fqdn, error = %e, "sign-in unreachable");
                return cached(true).unwrap_or_else(|| Verdict::Deny(plain(StatusCode::BAD_GATEWAY, "sign-in unreachable")));
            }
            Err(_) => {
                tracing::warn!(provider = %self.target.fqdn, "sign-in did not answer in time");
                return cached(true)
                    .unwrap_or_else(|| Verdict::Deny(plain(StatusCode::GATEWAY_TIMEOUT, "sign-in did not answer")));
            }
        };
        if resp.status().is_server_error() {
            if let Some(hit) = cached(true) {
                tracing::warn!(provider = %self.target.fqdn, status = %resp.status(), "sign-in failed; using its last answer");
                return hit;
            }
        }
        let status = resp.status();
        if status.is_success() {
            let mut copied = HeaderMap::new();
            for name in identity.names() {
                if let (Ok(n), Some(v)) = (HeaderName::from_bytes(name.as_bytes()), resp.headers().get(name)) {
                    copied.insert(n, v.clone());
                }
            }
            let groups = copied
                .get(identity.groups.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|v| identity.split_groups(v))
                .unwrap_or_default();
            // Only an answer naming someone: a 2xx for a path the provider
            // lets anyone through says nothing about who is asking.
            let named = copied.get(identity.user.as_str()).is_some_and(|v| !v.is_empty());
            if let (true, Some(c)) = (named, caching(resp.headers())) {
                self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).store(
                    fqdn,
                    &sent,
                    c,
                    &copied,
                    &groups,
                    Instant::now(),
                );
            }
            return Verdict::Allow { headers: copied, groups };
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

/// Removes every identity header, so none a client supplied survives —
/// on every request, whether or not anything fills them in again.
pub fn strip_identity(headers: &mut HeaderMap, identity: &IdentityHeaders) {
    for name in identity.names() {
        headers.remove(name);
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
    fn the_provider_is_told_the_callers_address_and_nothing_a_client_wrote() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let si = SignIn::new(
            SignInTarget {
                fqdn: "auth.int.test".into(),
                vip: "10.9.0.60".parse().unwrap(),
                verify_path: "/verify".into(),
                session_cookie: "authward_session".into(),
            },
            &[],
        );
        let mut sent = HeaderMap::new();
        sent.insert("cookie", HeaderValue::from_static("authward_session=s"));
        sent.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6, 7.7.7.7"));
        let uri: Uri = "/x?y=1".parse().unwrap();
        let req = si.check_request(&Method::POST, &uri, &sent, "jf.int.test", Some("10.9.0.3".parse().unwrap())).ok().unwrap();
        let all: Vec<_> = req.headers().get_all("x-forwarded-for").iter().collect();
        assert_eq!(all, ["10.9.0.3"], "one value, the device's");
        assert_eq!(req.headers()["x-forwarded-host"], "jf.int.test");
        assert_eq!(req.headers()["host"], "auth.int.test");
        assert_eq!(req.headers()["x-forwarded-method"], "POST");
        assert_eq!(req.headers()["x-forwarded-uri"], "/x?y=1");

        let req = si.check_request(&Method::GET, &uri, &sent, "jf.int.test", None).ok().unwrap();
        assert!(req.headers().get("x-forwarded-for").is_none(), "unknown caller: nothing, not the client's");
    }

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
        strip_identity(&mut h, &IdentityHeaders::default());
        assert!(h.get("x-auth-user").is_none());
        assert_eq!(h.get("x-other").unwrap(), "kept");
    }

    fn answer(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn only_what_the_provider_allows_per_person_is_kept() {
        let authward = answer(&[("cache-control", "max-age=60"), ("vary", "cookie, host, x-forwarded-host")]);
        let c = caching(&authward).expect("authward's answer is cacheable");
        assert_eq!(c.max_age, Duration::from_secs(60));
        assert_eq!(c.stale_if_error, Duration::ZERO);
        assert_eq!(c.vary.iter().map(HeaderName::as_str).collect::<Vec<_>>(), ["cookie", "host", "x-forwarded-host"]);

        let stale = answer(&[("cache-control", "private, max-age=30, stale-if-error=300"), ("vary", "Authorization")]);
        assert_eq!(caching(&stale).unwrap().stale_if_error, Duration::from_secs(300));
        let long = answer(&[("cache-control", "max-age=999999"), ("vary", "cookie")]);
        assert_eq!(caching(&long).unwrap().max_age, MAX_CACHE_AGE, "capped");

        for refused in [
            answer(&[]),
            answer(&[("cache-control", "max-age=60")]),
            answer(&[("cache-control", "max-age=60"), ("vary", "host")]),
            answer(&[("cache-control", "max-age=60"), ("vary", "*")]),
            answer(&[("cache-control", "max-age=60, no-store"), ("vary", "cookie")]),
            answer(&[("cache-control", "no-cache, max-age=60"), ("vary", "cookie")]),
            answer(&[("cache-control", "max-age=0"), ("vary", "cookie")]),
            answer(&[("vary", "cookie")]),
        ] {
            assert!(caching(&refused).is_none(), "{refused:?}");
        }
    }

    #[test]
    fn an_answer_is_reused_for_the_same_person_only_and_stale_only_while_the_provider_is_down() {
        let mut cache = Cache::default();
        let now = Instant::now();
        let alice = answer(&[("cookie", "authward_session=a; theme=dark"), ("host", "jf.int.test")]);
        let bob = answer(&[("cookie", "authward_session=b; theme=dark"), ("host", "jf.int.test")]);
        let c = caching(&answer(&[("cache-control", "max-age=60, stale-if-error=60"), ("vary", "cookie, host")])).unwrap();
        let who = answer(&[("x-auth-user", "alice")]);
        assert!(cache.lookup("jf.int.test", &alice, now, false).is_none(), "nothing learnt yet");
        cache.store("jf.int.test", &alice, c, &who, &["family".into()], now);

        let Some(Verdict::Allow { headers, groups }) = cache.lookup("jf.int.test", &alice, now, false) else {
            panic!("alice's answer is kept");
        };
        assert_eq!((headers.get("x-auth-user").unwrap(), groups.as_slice()), (&HeaderValue::from_static("alice"), &["family".to_string()][..]));
        assert!(cache.lookup("jf.int.test", &bob, now, false).is_none(), "never bob's");
        assert!(cache.lookup("other.int.test", &alice, now, false).is_none(), "nor another service's");

        let later = now + Duration::from_secs(90);
        assert!(cache.lookup("jf.int.test", &alice, later, false).is_none(), "stale: asked again");
        assert!(cache.lookup("jf.int.test", &alice, later, true).is_some(), "unless the provider is down");
        assert!(cache.lookup("jf.int.test", &alice, now + Duration::from_secs(121), true).is_none(), "and not for ever");
    }

    #[test]
    fn the_cache_stays_bounded() {
        let mut cache = Cache::default();
        let now = Instant::now();
        for i in 0..CACHE_ENTRIES + 5 {
            let sent = answer(&[]);
            let mut sent = sent;
            sent.insert("cookie", HeaderValue::from_str(&format!("s={i}")).unwrap());
            let c = Caching { max_age: Duration::from_secs(60), stale_if_error: Duration::ZERO, vary: vec![header::COOKIE] };
            cache.store("jf.int.test", &sent, c, &HeaderMap::new(), &[], now);
        }
        assert!(cache.entries.len() <= CACHE_ENTRIES);
    }
}
