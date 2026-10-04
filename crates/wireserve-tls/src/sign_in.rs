//! The sign-in in front of restricted services (PLAN.md M36, M48), as the
//! terminator sees it.
//!
//! The coordinator signs people in; this side only checks what it signed.
//! A request the grants don't let in by its device needs a session cookie
//! for this very service: a token the coordinator signed, made out to this
//! service's name, not yet past its time. That is checked here, with the
//! coordinator's public key — no one is asked. Then:
//! * **a valid token** whose groups include one the grants name: through,
//!   with who it is in the identity headers;
//! * **a token past its time:** renewed through the agent, which asks the
//!   coordinator — one renewal per session at a time, its answer shared by
//!   every request waiting on it — and the fresh one set on the response;
//! * **none, or one the coordinator ended:** a GET or HEAD is sent to sign
//!   in at the coordinator; anything else gets a 401.
//!
//! Two paths on every service's name are the sign-in's own: the coordinator
//! sends the browser back to [`CALLBACK_PATH`] with a ticket, which the
//! agent redeems for a token; and [`SIGN_OUT_PATH`] ends the session.
//!
//! The cookie is `__Host-`: this service's own, never sent to a sibling
//! under the same domain, so whoever runs one service never sees the
//! session of another. It is removed from every request before a backend
//! sees it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, Method, Response, StatusCode, Uri};
use wireserve_types::session::{self, Session, VerifyingKey, CALLBACK_PATH, COOKIE, SIGN_OUT_PATH};
use wireserve_types::IdentityHeaders;

use crate::link::{Link, LinkError};

/// How long the browser keeps the cookie: as long as the coordinator keeps
/// an unused session. The token in it is renewed long before.
const COOKIE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 3600);

/// Sessions renewed recently, kept to answer the requests that were already
/// on their way with the old token.
const MAX_RENEWED: usize = 10_000;

/// One session's renewal at a service: held while it runs, and its result
/// — the token and what it says — kept for the requests that waited.
type Renewed = Arc<tokio::sync::Mutex<Option<(String, Session)>>>;

/// The sign-in as one check-in configured it.
pub struct SignIn {
    pub settings: wireserve_types::SignIn,
    key: VerifyingKey,
    link: Link,
    /// Per session and service: one renewal at a time, and its result.
    renewed: Mutex<HashMap<(String, String), Renewed>>,
}

/// What a request's session says.
pub enum Verdict {
    /// Signed in as this. `set_cookie`: the token was renewed, and the
    /// browser is to keep the new one.
    Allow { session: Session, set_cookie: Option<HeaderValue> },
    /// Answer the client with this instead.
    Deny(Response<Body>),
}

impl SignIn {
    /// `None` when the coordinator's key cannot be read.
    #[must_use]
    pub fn new(settings: wireserve_types::SignIn, link: Link) -> Option<Self> {
        let key = session::parse_public_key(&settings.public_key)?;
        Some(Self { settings, key, link, renewed: Mutex::default() })
    }

    /// Checks the session a request to the service `fqdn` carries.
    pub async fn check(&self, method: &Method, uri: &Uri, headers: &HeaderMap, fqdn: &str) -> Verdict {
        let now = unix_now();
        let mut expired = None;
        for token in cookies(headers, COOKIE) {
            let Ok(s) = session::verify(&self.key, token) else { continue };
            if !s.aud.eq_ignore_ascii_case(fqdn) {
                continue;
            }
            if s.exp > now {
                return Verdict::Allow { session: s, set_cookie: None };
            }
            expired = Some((token.to_string(), s));
        }
        let Some((token, s)) = expired else {
            return self.to_sign_in(method, uri, fqdn, false);
        };
        match self.renew(fqdn, &token, &s).await {
            Ok((fresh, s)) => Verdict::Allow { session: s, set_cookie: Some(set_cookie(&fresh)) },
            Err(Renewal::SignedOut) => self.to_sign_in(method, uri, fqdn, true),
            Err(Renewal::Failed(e)) => {
                tracing::warn!(service = %fqdn, error = %e, "could not renew a sign-in session");
                Verdict::Deny(plain(StatusCode::SERVICE_UNAVAILABLE, "the sign-in cannot be reached right now; try again shortly"))
            }
        }
    }

    /// A fresh token for an expired one: the one another request already
    /// got for the same session, if it is still good, or the coordinator's.
    async fn renew(&self, fqdn: &str, token: &str, s: &Session) -> Result<(String, Session), Renewal> {
        let slot = {
            let mut all = self.renewed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if all.len() >= MAX_RENEWED {
                let now = unix_now();
                all.retain(|_, slot| Arc::strong_count(slot) > 1 || slot.try_lock().is_ok_and(|g| g.as_ref().is_some_and(|(_, s)| s.exp > now)));
                if all.len() >= MAX_RENEWED {
                    all.clear();
                }
            }
            all.entry((s.sid.clone(), fqdn.to_ascii_lowercase())).or_default().clone()
        };
        let mut held = slot.lock().await;
        if let Some((fresh, s)) = held.as_ref() {
            if s.exp > unix_now() {
                return Ok((fresh.clone(), s.clone()));
            }
        }
        match self.link.renew(fqdn, token).await {
            Ok(fresh) => {
                let s = self.accept(&fresh, fqdn).map_err(Renewal::Failed)?;
                *held = Some((fresh.clone(), s.clone()));
                Ok((fresh, s))
            }
            Err(LinkError::SignedOut) => Err(Renewal::SignedOut),
            Err(e) => Err(Renewal::Failed(e.to_string())),
        }
    }

    /// A token the coordinator just handed over, checked like any other.
    fn accept(&self, token: &str, fqdn: &str) -> Result<Session, String> {
        let s = session::verify(&self.key, token).map_err(|e| format!("the coordinator's token: {e}"))?;
        if !s.aud.eq_ignore_ascii_case(fqdn) {
            return Err("the coordinator's token is for another service".into());
        }
        Ok(s)
    }

    /// Off to sign in, for a GET or HEAD; a 401 for anything else, which a
    /// redirect would lose the body of. `clear`: the cookie held a session
    /// that is over.
    fn to_sign_in(&self, method: &Method, uri: &Uri, fqdn: &str, clear: bool) -> Verdict {
        let mut r = if matches!(*method, Method::GET | Method::HEAD) {
            let to = uri.path_and_query().map_or("/", |p| p.as_str());
            let to = if session::is_local_path(to) { to } else { "/" };
            let url = format!(
                "{}/sign-in?service={}&to={}",
                self.settings.login_url.trim_end_matches('/'),
                session::encode_query_value(fqdn),
                session::encode_query_value(to),
            );
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::FOUND;
            if let Ok(v) = HeaderValue::from_str(&url) {
                r.headers_mut().insert(header::LOCATION, v);
            }
            r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            r
        } else {
            plain(StatusCode::UNAUTHORIZED, "sign in first: open this service's page in your browser")
        };
        if clear {
            r.headers_mut().insert(header::SET_COOKIE, clear_cookie());
        }
        Verdict::Deny(r)
    }

    /// `GET /.wireserve/callback?ticket=…`: back from the coordinator. The
    /// agent redeems the ticket; the browser keeps the token, and goes on
    /// to where it was.
    pub async fn callback(&self, uri: &Uri, fqdn: &str) -> Response<Body> {
        let ticket = uri
            .query()
            .unwrap_or_default()
            .split('&')
            .find_map(|kv| kv.strip_prefix("ticket="))
            .filter(|t| !t.is_empty() && t.len() <= session::MAX_TICKET_LEN && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
        let Some(ticket) = ticket else {
            return page(StatusCode::BAD_REQUEST, "This is not a sign-in link.", fqdn);
        };
        match self.link.redeem(fqdn, ticket).await {
            Ok((token, to)) => match self.accept(&token, fqdn) {
                Ok(s) => {
                    tracing::info!(service = %fqdn, sub = %s.sub, "signed in");
                    let to = to.filter(|t| session::is_local_path(t)).unwrap_or_else(|| "/".into());
                    let mut r = Response::new(Body::empty());
                    *r.status_mut() = StatusCode::FOUND;
                    if let Ok(v) = HeaderValue::from_str(&to) {
                        r.headers_mut().insert(header::LOCATION, v);
                    }
                    r.headers_mut().insert(header::SET_COOKIE, set_cookie(&token));
                    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
                    r.headers_mut().insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
                    r
                }
                Err(e) => {
                    tracing::warn!(service = %fqdn, error = %e, "a redeemed sign-in did not check out");
                    page(StatusCode::BAD_GATEWAY, "The sign-in did not work. Open the page again to retry.", fqdn)
                }
            },
            Err(LinkError::SignedOut) => {
                page(StatusCode::GONE, "This sign-in link was used already, or is too old. Open the page again to sign in.", fqdn)
            }
            Err(e) => {
                tracing::warn!(service = %fqdn, error = %e, "could not redeem a sign-in ticket");
                page(StatusCode::BAD_GATEWAY, "The sign-in cannot be reached right now. Open the page again shortly.", fqdn)
            }
        }
    }

    /// `/.wireserve/sign-out`: a GET shows a button; its POST — from this
    /// service's own page, as the cross-site check makes sure — ends the
    /// session at the coordinator, and the browser goes on to the
    /// coordinator, which forgets its own login there too.
    pub async fn sign_out(&self, method: &Method, headers: &HeaderMap, fqdn: &str) -> Response<Body> {
        if *method != Method::POST {
            let mut r = Response::new(Body::from(SIGN_OUT_PAGE));
            r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
            page_headers(r.headers_mut());
            return r;
        }
        for token in cookies(headers, COOKIE) {
            let Ok(s) = session::verify(&self.key, token) else { continue };
            if !s.aud.eq_ignore_ascii_case(fqdn) {
                continue;
            }
            match self.link.end(fqdn, token).await {
                Ok(()) => tracing::info!(service = %fqdn, sub = %s.sub, "signed out"),
                Err(e) => tracing::warn!(service = %fqdn, error = %e, "could not end a session at the coordinator"),
            }
        }
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::SEE_OTHER;
        if let Ok(v) = HeaderValue::from_str(&format!("{}/signed-out", self.settings.login_url.trim_end_matches('/'))) {
            r.headers_mut().insert(header::LOCATION, v);
        }
        r.headers_mut().insert(header::SET_COOKIE, clear_cookie());
        r
    }
}

enum Renewal {
    SignedOut,
    Failed(String),
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The values of every cookie called `name`, across every `Cookie` header.
fn cookies<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(move |c| c.trim().strip_prefix(name)?.strip_prefix('='))
}

fn set_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        COOKIE_MAX_AGE.as_secs()
    ))
    .unwrap_or_else(|_| clear_cookie())
}

fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static("__Host-wireserve-session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Whether `path` is the sign-in's own, on any service's name.
#[must_use]
pub fn is_own_path(path: &str) -> bool {
    path == CALLBACK_PATH || path == SIGN_OUT_PATH
}

const SIGN_OUT_PAGE: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Sign out</title>\
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;line-height:1.5}\
button{font-size:1rem;padding:.5rem 1rem}@media(prefers-color-scheme:dark){body{color:#e8e8e8;background:#161616}}</style>\
</head><body><h1>Sign out</h1><p>This signs you out of every service on this mesh, in this browser.</p>\
<form method=\"post\"><button type=\"submit\">Sign out</button></form></body></html>";

/// The headers every page of the sign-in's carries: never framed, cached,
/// or scripted.
fn page_headers(h: &mut HeaderMap) {
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
}

/// A short page saying what happened, with a way back to the service.
fn page(status: StatusCode, message: &'static str, fqdn: &str) -> Response<Body> {
    let home = format!("https://{fqdn}/");
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Sign-in</title></head><body>\
         <p>{message}</p><p><a href=\"/\">{}</a></p></body></html>",
        home.replace(['<', '>', '"', '&'], "")
    );
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    page_headers(r.headers_mut());
    r
}

/// Removes every identity header, so none a client supplied survives —
/// on every request, whether or not anything fills them in again.
pub fn strip_identity(headers: &mut HeaderMap, identity: &IdentityHeaders) {
    for name in identity.names() {
        headers.remove(name);
    }
}

/// Removes the cookie `cookie` from the `Cookie` headers, leaving every
/// other cookie as it was.
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

pub fn plain(status: StatusCode, text: &'static str) -> Response<Body> {
    let mut r = Response::new(Body::from(text));
    *r.status_mut() = status;
    r
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use wireserve_types::tls::{TlsRequest, TlsResponse};

    pub(crate) const SEED: [u8; 32] = [5; 32];

    pub(crate) fn token(fqdn: &str, exp_in: i64, groups: &[&str]) -> String {
        session::sign(
            &session::signing_key(&SEED),
            &Session {
                sid: "sid-1".into(),
                sub: "anna".into(),
                email: Some("anna@example.com".into()),
                groups: groups.iter().map(|g| (*g).to_string()).collect(),
                aud: fqdn.into(),
                exp: unix_now() + exp_in,
            },
        )
    }

    /// A stand-in agent on a socket of its own: renews any token to one
    /// good for a minute (counting how often it was asked), redeems the
    /// ticket `good`, and says anything else is signed out.
    pub(crate) fn fake_agent(dir: &std::path::Path) -> (Link, Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let path = dir.join("tls.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut line = String::new();
                    tokio::io::BufReader::new(read).read_line(&mut line).await.unwrap();
                    let answer = match serde_json::from_str::<TlsRequest>(line.trim_end()).unwrap() {
                        TlsRequest::Renew { fqdn, token: old } if old.contains("wst1.") => {
                            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            TlsResponse::Session { token: token(&fqdn, 60, &["family"]), to: None }
                        }
                        TlsRequest::Redeem { fqdn, ticket } if ticket == "good" => {
                            TlsResponse::Session { token: token(&fqdn, 60, &["family"]), to: Some("/dashboard?x=1".into()) }
                        }
                        TlsRequest::End { .. } => TlsResponse::Ok,
                        _ => TlsResponse::SignedOut,
                    };
                    let mut out = serde_json::to_string(&answer).unwrap();
                    out.push('\n');
                    write.write_all(out.as_bytes()).await.unwrap();
                });
            }
        });
        (Link::new(path), asked)
    }

    pub(crate) fn settings() -> wireserve_types::SignIn {
        wireserve_types::SignIn {
            public_key: session::public_key(&session::signing_key(&SEED)),
            login_url: "https://mesh.test".into(),
        }
    }

    fn with_cookie(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_str(&format!("theme=dark; {COOKIE}={token}")).unwrap());
        h
    }

    #[tokio::test]
    async fn a_valid_token_for_this_service_lets_in_and_nothing_else_does() {
        let dir = tempfile::tempdir().unwrap();
        let (link, asked) = fake_agent(dir.path());
        let si = SignIn::new(settings(), link).unwrap();
        let uri: Uri = "/x?y=1".parse().unwrap();
        let Verdict::Allow { session, set_cookie } = si.check(&Method::GET, &uri, &with_cookie(&token("jf.int.test", 60, &["family"])), "jf.int.test").await else {
            panic!("a valid token");
        };
        assert_eq!((session.sub.as_str(), set_cookie), ("anna", None));

        // Another service's token, or one another key signed: off to sign in.
        let theirs = with_cookie(&token("vault.int.test", 60, &["family"]));
        let Verdict::Deny(r) = si.check(&Method::GET, &uri, &theirs, "jf.int.test").await else { panic!("another service's") };
        assert_eq!(r.status(), StatusCode::FOUND);
        assert_eq!(r.headers()["location"], "https://mesh.test/sign-in?service=jf.int.test&to=%2Fx%3Fy%3D1");
        let forged = session::sign(&session::signing_key(&[6; 32]), &session::verify(&si.key, &token("jf.int.test", 60, &[])).unwrap());
        let Verdict::Deny(r) = si.check(&Method::POST, &uri, &with_cookie(&forged), "jf.int.test").await else { panic!("forged") };
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "a POST is not redirected");
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 0, "nobody was asked");
    }

    #[tokio::test]
    async fn an_expired_token_is_renewed_once_for_every_request_waiting_on_it() {
        let dir = tempfile::tempdir().unwrap();
        let (link, asked) = fake_agent(dir.path());
        let si = Arc::new(SignIn::new(settings(), link).unwrap());
        let old = with_cookie(&token("jf.int.test", -5, &["family"]));
        let uri: Uri = "/".parse().unwrap();
        let checks = (0..10).map(|_| {
            let (si, old, uri) = (Arc::clone(&si), old.clone(), uri.clone());
            tokio::spawn(async move { si.check(&Method::GET, &uri, &old, "jf.int.test").await })
        });
        for c in checks {
            let Verdict::Allow { set_cookie: Some(c), .. } = c.await.unwrap() else { panic!("renewed") };
            assert!(c.to_str().unwrap().starts_with("__Host-wireserve-session=wst1."));
        }
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1, "one renewal, shared");
    }

    #[tokio::test]
    async fn a_ticket_is_redeemed_into_a_cookie_and_the_way_back() {
        let dir = tempfile::tempdir().unwrap();
        let (link, _) = fake_agent(dir.path());
        let si = SignIn::new(settings(), link).unwrap();
        let r = si.callback(&"/.wireserve/callback?ticket=good".parse().unwrap(), "jf.int.test").await;
        assert_eq!(r.status(), StatusCode::FOUND);
        assert_eq!(r.headers()["location"], "/dashboard?x=1");
        let cookie = r.headers()["set-cookie"].to_str().unwrap();
        assert!(cookie.starts_with("__Host-wireserve-session=wst1.") && cookie.contains("HttpOnly") && cookie.contains("Secure"), "{cookie}");

        let r = si.callback(&"/.wireserve/callback?ticket=used".parse().unwrap(), "jf.int.test").await;
        assert_eq!(r.status(), StatusCode::GONE);
        let r = si.callback(&"/.wireserve/callback?ticket=<script>".parse().unwrap_or_else(|_| "/.wireserve/callback".parse().unwrap()), "jf.int.test").await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn signing_out_clears_the_cookie_and_goes_to_the_coordinator() {
        let dir = tempfile::tempdir().unwrap();
        let (link, _) = fake_agent(dir.path());
        let si = SignIn::new(settings(), link).unwrap();
        let r = si.sign_out(&Method::GET, &HeaderMap::new(), "jf.int.test").await;
        assert_eq!(r.status(), StatusCode::OK, "a GET only asks");
        let r = si.sign_out(&Method::POST, &with_cookie(&token("jf.int.test", 60, &[])), "jf.int.test").await;
        assert_eq!(r.status(), StatusCode::SEE_OTHER);
        assert_eq!(r.headers()["location"], "https://mesh.test/signed-out");
        assert!(r.headers()["set-cookie"].to_str().unwrap().contains("Max-Age=0"));
    }

    #[test]
    fn only_the_session_cookie_is_removed() {
        let mut h = HeaderMap::new();
        h.append(header::COOKIE, HeaderValue::from_static("theme=dark; __Host-wireserve-session=abc; lang=de"));
        h.append(header::COOKIE, HeaderValue::from_static("__Host-wireserve-session=def"));
        strip_cookie(&mut h, COOKIE);
        let all: Vec<&str> = h.get_all(header::COOKIE).iter().map(|v| v.to_str().unwrap()).collect();
        assert_eq!(all, vec!["theme=dark; lang=de"]);

        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("__Host-wireserve-session_x=1"));
        strip_cookie(&mut h, COOKIE);
        assert_eq!(h.get(header::COOKIE).unwrap(), "__Host-wireserve-session_x=1", "a longer name is someone else's");
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
}
