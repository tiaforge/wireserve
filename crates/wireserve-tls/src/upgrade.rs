//! Upgraded connections — WebSockets — proxied as bytes (PLAN.md M42).
//!
//! An HTTP/1.1 request asking to upgrade to a WebSocket goes to the backend
//! on a connection of its own, and the backend's answer comes back as it
//! is: its 101 with every header it set (subprotocol, extensions, cookies),
//! or its refusal — a 401, a 403, a redirect — with its body. Once both
//! sides have switched, what one sends the other gets, byte for byte:
//! nothing is re-framed, so a compression extension the two agree on just
//! works.
//!
//! Only a WebSocket (PLAN.md #271). Past a 101 nothing the client sends is
//! looked at again, so a protocol that carries further requests — `h2c`
//! above all — would take each of them past `prepare` and `guard`: forged
//! identity headers, and any path, with the sign-in never asked. Any other
//! upgrade is ignored, as RFC 9110 §7.8 lets a server do, and the request
//! goes on as a plain one. A backend's 101 counts only when it is a
//! WebSocket's own answer to this very request: `Upgrade: websocket` and
//! the `Sec-WebSocket-Accept` the key calls for.
//!
//! The terminator's own rules stay where they are: the request has been
//! through `prepare` and `guard` before it gets here, and while the
//! connection is open, whether its caller is still let in is asked again
//! every `Limits::recheck` — a grant taken away, a node revoked or a
//! service no longer served closes it.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::TokioIo;

/// How long the backend has to answer an upgrade, from connecting to its
/// status line.
const ANSWER: Duration = Duration::from_secs(30);

/// Headers that belong to one hop alone, besides those `Connection` names.
const HOP_BY_HOP: &[HeaderName] = &[
    header::CONNECTION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::PROXY_AUTHORIZATION,
    header::PROXY_AUTHENTICATE,
];
const HOP_BY_HOP_NAMED: &[&str] = &["keep-alive", "proxy-connection"];

/// The GUID RFC 6455 §1.3 appends to a WebSocket key.
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Whether `req` asks for a WebSocket: HTTP/1.1, `Upgrade: websocket` and
/// nothing else, `upgrade` among its `Connection` tokens, version 13 and a
/// key of 16 bytes (RFC 6455 §4.1). HTTP/2 has no such request (RFC 9113
/// §8.6), and this terminator does not offer RFC 8441's extended CONNECT:
/// a browser opens an HTTP/1.1 connection of its own for a WebSocket.
pub(crate) fn wanted<B>(req: &Request<B>) -> bool {
    let h = req.headers();
    let mut upgrades = h.get_all(header::UPGRADE).iter();
    let websocket = match (upgrades.next(), upgrades.next()) {
        (Some(v), None) => v.to_str().is_ok_and(|v| v.trim().eq_ignore_ascii_case("websocket")),
        _ => false,
    };
    req.version() == Version::HTTP_11
        && websocket
        && connection_tokens(h).any(|t| t == "upgrade")
        && h.get(header::SEC_WEBSOCKET_VERSION).is_some_and(|v| v.as_bytes() == b"13")
        && key(h).is_some()
}

/// The request's `Sec-WebSocket-Key`, if it is one: base64 of 16 bytes.
fn key(headers: &HeaderMap) -> Option<&str> {
    use base64::Engine as _;
    let mut keys = headers.get_all(header::SEC_WEBSOCKET_KEY).iter();
    let (Some(k), None) = (keys.next(), keys.next()) else {
        return None;
    };
    let k = k.to_str().ok()?.trim();
    let raw = base64::engine::general_purpose::STANDARD.decode(k).ok()?;
    (raw.len() == 16).then_some(k)
}

/// The `Sec-WebSocket-Accept` a backend must answer `key` with (RFC 6455
/// §4.2.2).
fn accept_for(key: &str) -> String {
    use base64::Engine as _;
    use sha1::Digest as _;
    let mut h = sha1::Sha1::new();
    h.update(key.as_bytes());
    h.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Whether `answer` is a WebSocket backend's switch for the key it was
/// asked with: `Upgrade: websocket`, `upgrade` among its `Connection`
/// tokens, and the accept value the key calls for.
fn switched_to_websocket(answer: &HeaderMap, expected_accept: &str) -> bool {
    let mut upgrades = answer.get_all(header::UPGRADE).iter();
    let websocket = match (upgrades.next(), upgrades.next()) {
        (Some(v), None) => v.to_str().is_ok_and(|v| v.trim().eq_ignore_ascii_case("websocket")),
        _ => false,
    };
    let mut accepts = answer.get_all(header::SEC_WEBSOCKET_ACCEPT).iter();
    let accepted = match (accepts.next(), accepts.next()) {
        (Some(v), None) => v.to_str().is_ok_and(|v| v.trim() == expected_accept),
        _ => false,
    };
    websocket && accepted && connection_tokens(answer).any(|t| t == "upgrade")
}

/// Turns any upgrade other than a WebSocket into a plain request (PLAN.md
/// #271): `Upgrade` goes, and so does `upgrade` among the `Connection`
/// tokens. The other tokens stay, so what they name — `HTTP2-Settings` —
/// is still removed as hop-by-hop on the way on.
pub(crate) fn ignore(headers: &mut HeaderMap) {
    if !headers.contains_key(header::UPGRADE) {
        return;
    }
    headers.remove(header::UPGRADE);
    let rest: Vec<String> = connection_tokens(headers).filter(|t| t != "upgrade").collect();
    headers.remove(header::CONNECTION);
    if !rest.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&rest.join(", ")) {
            headers.insert(header::CONNECTION, v);
        }
    }
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = String> + '_ {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
}

/// Removes what belongs to one hop: the fixed list, and whatever
/// `Connection` names — but `upgrade` stays when `keep_upgrade`, with a
/// `Connection: upgrade` of our own, since the next hop must see both.
fn strip_hop_by_hop(headers: &mut HeaderMap, keep_upgrade: bool) {
    let named: Vec<String> = connection_tokens(headers).filter(|t| t != "upgrade").collect();
    for name in named {
        headers.remove(name.as_str());
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    for name in HOP_BY_HOP_NAMED {
        headers.remove(*name);
    }
    if keep_upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(header::UPGRADE);
    }
}

/// The forwarding headers the ordinary proxy sets, set the same way: the
/// peer appended to `X-Forwarded-For`, and `X-Forwarded-Host` kept if
/// there. `prepare` removed a client's copies, unless it is a forwarding
/// node (PLAN.md M43).
fn set_forwarded(headers: &mut HeaderMap, peer: SocketAddr) {
    let xff = HeaderName::from_static("x-forwarded-for");
    let peer = peer.ip().to_canonical().to_string();
    let before: Vec<&str> = headers.get_all(&xff).iter().filter_map(|v| v.to_str().ok()).collect();
    let chain = if before.is_empty() { peer } else { format!("{}, {peer}", before.join(", ")) };
    if let Ok(v) = HeaderValue::from_str(&chain) {
        headers.insert(xff, v);
    }
    headers.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("https"));
    let xfh = HeaderName::from_static("x-forwarded-host");
    if !headers.contains_key(&xfh) {
        if let Some(host) = headers.get(header::HOST).cloned() {
            headers.insert(xfh, host);
        }
    }
}

fn bad_gateway(text: &'static str) -> Response<Body> {
    crate::sign_in::plain(StatusCode::BAD_GATEWAY, text)
}

/// Proxies the upgrade `req` to `upstream`, and once both sides have
/// switched, keeps the bytes flowing while `still_admitted`, asked every
/// `recheck`, says yes. `hold` is kept for as long as the bytes flow — a
/// place in a limit, given back when they stop.
pub(crate) async fn proxy<F, Fut, H>(
    mut req: Request<Body>,
    upstream: SocketAddr,
    peer: SocketAddr,
    recheck: Duration,
    still_admitted: F,
    hold: H,
) -> Response<Body>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send,
    H: Send + 'static,
{
    // `wanted` checked the key; without one nothing can be accepted.
    let Some(expected_accept) = key(req.headers()).map(accept_for) else {
        return crate::sign_in::plain(StatusCode::BAD_REQUEST, "not a WebSocket request");
    };
    let client_side = hyper::upgrade::on(&mut req);
    strip_hop_by_hop(req.headers_mut(), true);
    set_forwarded(req.headers_mut(), peer);
    // The backend gets the origin form; `Host` carries the name.
    let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_owned();
    *req.uri_mut() = path.parse::<Uri>().unwrap_or_else(|_| Uri::from_static("/"));

    let asked = async {
        let tcp = tokio::net::TcpStream::connect(upstream).await?;
        let _ = tcp.set_nodelay(true);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await.map_err(std::io::Error::other)?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        sender.send_request(req).await.map_err(std::io::Error::other)
    };
    let mut answer = match tokio::time::timeout(ANSWER, asked).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::warn!(%upstream, error = %e, "backend refused the upgrade request");
            return bad_gateway("the backend could not be reached");
        }
        Err(_) => {
            tracing::warn!(%upstream, "backend did not answer the upgrade request in time");
            return crate::sign_in::plain(StatusCode::GATEWAY_TIMEOUT, "the backend did not answer");
        }
    };

    if answer.status() != StatusCode::SWITCHING_PROTOCOLS {
        // Its refusal, or a plain answer, as it is.
        strip_hop_by_hop(answer.headers_mut(), false);
        return answer.map(Body::new);
    }

    // A switch to anything but this WebSocket would carry requests past
    // every check here; the backend connection is dropped with `answer`.
    if !switched_to_websocket(answer.headers(), &expected_accept) {
        tracing::warn!(%upstream, "backend switched protocols, but not as a WebSocket answering this request; refused");
        return bad_gateway("the backend's answer to the WebSocket request was not a WebSocket");
    }

    let backend_side = hyper::upgrade::on(&mut answer);
    tokio::spawn(async move {
        let _hold = hold;
        let (client, backend) = match tokio::join!(client_side, backend_side) {
            (Ok(c), Ok(b)) => (c, b),
            (Err(e), _) | (_, Err(e)) => {
                tracing::debug!(error = %e, "upgrade not completed");
                return;
            }
        };
        let (mut client, mut backend) = (TokioIo::new(client), TokioIo::new(backend));
        let watch = async {
            let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + recheck, recheck);
            loop {
                tick.tick().await;
                if !still_admitted().await {
                    return;
                }
            }
        };
        tokio::select! {
            _ = tokio::io::copy_bidirectional(&mut client, &mut backend) => {}
            () = watch => tracing::info!(peer = %peer.ip(), "closing an upgraded connection: its caller is no longer let in"),
        }
    });

    // The backend's 101 as it sent it, `Connection` and `Upgrade` included:
    // they are this hop's too.
    let (parts, _) = answer.into_parts();
    Response::from_parts(parts, Body::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(version: Version, headers: &[(&str, &str)]) -> Request<()> {
        let mut b = Request::builder().version(version);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap()
    }

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    #[test]
    fn only_a_websocket_request_is_an_upgrade() {
        let ws = [("upgrade", "websocket"), ("connection", "keep-alive, Upgrade"), ("sec-websocket-version", "13"), ("sec-websocket-key", KEY)];
        assert!(wanted(&req(Version::HTTP_11, &ws)));
        assert!(!wanted(&req(Version::HTTP_2, &ws)), "no such thing in HTTP/2");
        assert!(!wanted(&req(Version::HTTP_10, &ws)));
        let without = |name: &str| -> Vec<(&str, &str)> { ws.iter().copied().filter(|(k, _)| *k != name).collect() };
        assert!(!wanted(&req(Version::HTTP_11, &without("connection"))), "Connection must name it");
        assert!(!wanted(&req(Version::HTTP_11, &without("upgrade"))));
        assert!(!wanted(&req(Version::HTTP_11, &without("sec-websocket-key"))));
        assert!(!wanted(&req(Version::HTTP_11, &without("sec-websocket-version"))));
        let with = |name: &'static str, value: &'static str| -> Vec<(&'static str, &'static str)> {
            ws.iter().copied().map(|(k, v)| if k == name { (k, value) } else { (k, v) }).collect()
        };
        assert!(!wanted(&req(Version::HTTP_11, &with("upgrade", "h2c"))), "any other protocol is no upgrade here");
        assert!(!wanted(&req(Version::HTTP_11, &with("upgrade", "websocket, h2c"))));
        assert!(!wanted(&req(Version::HTTP_11, &with("sec-websocket-version", "8"))));
        assert!(!wanted(&req(Version::HTTP_11, &with("sec-websocket-key", "c2hvcnQ="))), "not 16 bytes");
    }

    #[test]
    fn the_accept_value_is_rfc_6455s() {
        // RFC 6455 §1.3's own example.
        assert_eq!(accept_for(KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        let answer = |pairs: &[(&'static str, &'static str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.append(*k, HeaderValue::from_static(v));
            }
            h
        };
        let good = [("upgrade", "websocket"), ("connection", "Upgrade"), ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")];
        assert!(switched_to_websocket(&answer(&good), &accept_for(KEY)));
        assert!(!switched_to_websocket(&answer(&good[..2]), &accept_for(KEY)), "no accept value");
        assert!(!switched_to_websocket(&answer(&[good[0], good[1], ("sec-websocket-accept", "AAAA")]), &accept_for(KEY)));
        assert!(!switched_to_websocket(&answer(&[("upgrade", "h2c"), good[1], good[2]]), &accept_for(KEY)));
        assert!(!switched_to_websocket(&answer(&[good[0], good[2]]), &accept_for(KEY)), "Connection must name it");
    }

    #[test]
    fn another_upgrade_becomes_a_plain_request() {
        let mut h = HeaderMap::new();
        h.insert("upgrade", HeaderValue::from_static("h2c"));
        h.insert("connection", HeaderValue::from_static("Upgrade, HTTP2-Settings"));
        h.insert("http2-settings", HeaderValue::from_static("AAMAAABkAAQAoAAAAAIAAAAA"));
        ignore(&mut h);
        assert!(!h.contains_key("upgrade"));
        assert_eq!(h["connection"], "http2-settings", "still named, so still removed on the way on");

        let mut h = HeaderMap::new();
        h.insert("upgrade", HeaderValue::from_static("tcp"));
        h.insert("connection", HeaderValue::from_static("upgrade"));
        ignore(&mut h);
        assert!(h.is_empty());
    }

    #[test]
    fn what_belongs_to_one_hop_goes_and_the_upgrade_stays() {
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("Upgrade, x-hop"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        h.insert("x-hop", HeaderValue::from_static("1"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("te", HeaderValue::from_static("trailers"));
        h.insert("sec-websocket-extensions", HeaderValue::from_static("permessage-deflate"));
        strip_hop_by_hop(&mut h, true);
        let mut left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["connection", "sec-websocket-extensions", "upgrade"]);
        assert_eq!(h["connection"], "upgrade");

        h.insert("x-hop", HeaderValue::from_static("1"));
        h.insert("connection", HeaderValue::from_static("x-hop"));
        strip_hop_by_hop(&mut h, false);
        let left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        assert_eq!(left, ["sec-websocket-extensions"], "a refusal upgrades nothing");
    }

    #[test]
    fn the_forwarding_headers_come_from_the_connection() {
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("chat.int.test"));
        set_forwarded(&mut h, "[::ffff:10.9.0.7]:5555".parse().unwrap());
        assert_eq!(h["x-forwarded-for"], "10.9.0.7");
        assert_eq!(h["x-forwarded-proto"], "https");
        assert_eq!(h["x-forwarded-host"], "chat.int.test");

        // What a forwarding node said stays, the peer after its client.
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("chat.int.test"));
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        h.insert("x-forwarded-host", HeaderValue::from_static("chat.example.com"));
        set_forwarded(&mut h, "10.9.0.7:5555".parse().unwrap());
        assert_eq!(h["x-forwarded-for"], "203.0.113.9, 10.9.0.7");
        assert_eq!(h["x-forwarded-host"], "chat.example.com");
    }
}
