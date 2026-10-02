//! Upgraded connections — WebSockets — proxied as bytes (PLAN.md M42).
//!
//! An HTTP/1.1 request asking to upgrade goes to the backend on a
//! connection of its own, and the backend's answer comes back as it is:
//! its 101 with every header it set (subprotocol, extensions, cookies), or
//! its refusal — a 401, a 403, a redirect — with its body. Once both sides
//! have switched, what one sends the other gets, byte for byte: nothing is
//! re-framed, so a compression extension the two agree on just works.
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

/// Whether `req` asks to switch protocols: HTTP/1.1, an `Upgrade` header,
/// and `upgrade` among its `Connection` tokens. HTTP/2 has no such
/// request (RFC 9113 §8.6), and this terminator does not offer RFC 8441's
/// extended CONNECT: a browser opens an HTTP/1.1 connection of its own for
/// a WebSocket.
pub(crate) fn wanted<B>(req: &Request<B>) -> bool {
    req.version() == Version::HTTP_11 && req.headers().contains_key(header::UPGRADE) && connection_tokens(req.headers()).any(|t| t == "upgrade")
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

/// The forwarding headers the ordinary proxy sets, set the same way: from
/// the connection, never from the client, whose copies `prepare` removed.
fn set_forwarded(headers: &mut HeaderMap, peer: SocketAddr) {
    if let Ok(v) = HeaderValue::from_str(&peer.ip().to_canonical().to_string()) {
        headers.insert(HeaderName::from_static("x-forwarded-for"), v);
    }
    headers.insert(HeaderName::from_static("x-forwarded-proto"), HeaderValue::from_static("https"));
    if let Some(host) = headers.get(header::HOST).cloned() {
        headers.insert(HeaderName::from_static("x-forwarded-host"), host);
    }
}

fn bad_gateway(text: &'static str) -> Response<Body> {
    crate::sign_in::plain(StatusCode::BAD_GATEWAY, text)
}

/// Proxies the upgrade `req` to `upstream`, and once both sides have
/// switched, keeps the bytes flowing while `still_admitted`, asked every
/// `recheck`, says yes.
pub(crate) async fn proxy<F, Fut>(
    mut req: Request<Body>,
    upstream: SocketAddr,
    peer: SocketAddr,
    recheck: Duration,
    still_admitted: F,
) -> Response<Body>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = bool> + Send,
{
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

    let backend_side = hyper::upgrade::on(&mut answer);
    tokio::spawn(async move {
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

    #[test]
    fn an_upgrade_is_http11_with_both_headers() {
        let ws = [("upgrade", "websocket"), ("connection", "keep-alive, Upgrade")];
        assert!(wanted(&req(Version::HTTP_11, &ws)));
        assert!(!wanted(&req(Version::HTTP_2, &ws)), "no such thing in HTTP/2");
        assert!(!wanted(&req(Version::HTTP_10, &ws)));
        assert!(!wanted(&req(Version::HTTP_11, &[("upgrade", "websocket")])), "Connection must name it");
        assert!(!wanted(&req(Version::HTTP_11, &[("connection", "upgrade")])));
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
    }
}
