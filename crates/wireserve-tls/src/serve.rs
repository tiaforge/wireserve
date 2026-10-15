//! Serving the services (PLAN.md M33): one TLS listener on an unprivileged
//! port of every address (PLAN.md M35), to which the agent rewrites each
//! service address's 443; each connection goes to the service whose
//! address it arrived on, and each request to its backend in plain HTTP.
//!
//! The proxying itself is hyper's pooled client, with each request's headers
//! edited in place ([`Route::forward`], PLAN.md #329). What is ours is the
//! edge of it — which headers a backend may believe — and upgrades: a
//! WebSocket goes to its backend as bytes, through [`crate::upgrade`]
//! (PLAN.md M42).

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use hyper_util::server::conn::auto;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use wireserve_types::tls::NODE_HEADER;

/// A calling node.
#[derive(Debug, Clone)]
pub struct CallerInfo {
    pub node: String,
}

/// Mesh address → the node calling from it, shared by every listener and
/// replaced on each check-in.
pub type Callers = Arc<RwLock<HashMap<Ipv4Addr, CallerInfo>>>;

/// The sign-in (PLAN.md M48), shared by every listener and replaced when the
/// coordinator's settings change. `None`: there is none, and nobody gets in
/// by signing in.
pub type SharedSignIn = Arc<RwLock<Option<Arc<crate::sign_in::SignIn>>>>;

/// How one service treats its requests.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// The name this service is served under: the one its requests must
    /// name, and its sign-in cookies be made out to.
    pub fqdn: String,
    /// Other hosts its requests may name: on plain HTTP (PLAN.md #328), the
    /// service's address, typed as it is. None over TLS, where a request's
    /// name is its certificate's.
    pub aliases: Vec<String>,
    /// Who may in (PLAN.md M36).
    pub access: wireserve_types::ServiceAccess,
    /// Takes requests other sites start (PLAN.md #276,
    /// `WIRESERVE_CROSS_SITE_SERVICES`).
    pub cross_site: bool,
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
    /// Further headers removed from every request (`WIRESERVE_STRIP_HEADERS`).
    pub strip: Arc<RwLock<Vec<String>>>,
    /// Calling nodes, by name, whose `X-Forwarded-For` and
    /// `X-Forwarded-Host` are kept (`WIRESERVE_FORWARDING_NODES`, PLAN.md M43).
    pub forwarders: Arc<RwLock<Vec<String>>>,
    /// The services answered in plain HTTP on their port 80 (PLAN.md #328),
    /// by address, as `routes` and `policies` are for 443.
    pub http_routes: Routes,
    pub http_policies: Policies,
}

impl Shared {
    /// The forwarding node (PLAN.md M43) calling from `addr`, if it is one.
    pub fn forwarding_node(&self, addr: IpAddr) -> Option<String> {
        let node = read(&self.callers).get(&local_v4(addr)?)?.node.clone();
        read(&self.forwarders).iter().any(|f| f.eq_ignore_ascii_case(&node)).then_some(node)
    }

    /// Stops answering on `vip`: its connections close, and requests on
    /// ones already open are refused.
    pub fn unroute(&self, vip: Ipv4Addr) {
        self.routes.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&vip);
        self.policies.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&vip);
    }

    /// [`Self::unroute`], for `vip`'s plain HTTP.
    pub fn unroute_http(&self, vip: Ipv4Addr) {
        self.http_routes.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&vip);
        self.http_policies.write().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&vip);
    }

    /// The routes and policies of one listener.
    fn of(&self, http: bool) -> (&Routes, &Policies) {
        if http {
            (&self.http_routes, &self.http_policies)
        } else {
            (&self.routes, &self.policies)
        }
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

/// What keeps one client — any node of the mesh, a phone included — from
/// holding the terminator's sockets. The terminator parses TLS and HTTP from
/// everyone who can reach the mesh, so none of it may wait for a client
/// without end.
#[derive(Debug, Clone)]
pub struct Limits {
    /// The TLS handshake, from accept to done.
    pub handshake: Duration,
    /// After the handshake, the first request must have begun by then.
    pub first_request: Duration,
    /// A connection with no request being served, and nothing read or
    /// written for this long, is closed: an idle keep-alive, or an HTTP/2
    /// connection that never says anything. A streaming answer or a slow
    /// backend is not idle by this, and an upgraded connection — a
    /// WebSocket — never is: an app may leave one quiet for as long as it
    /// likes. TCP keepalives find a client that has gone.
    pub idle: Duration,
    /// A whole request's headers, once they have started (HTTP/1).
    pub header_read: Duration,
    /// Connections open at once, all clients together. Each holds a socket
    /// here and, while a request runs, one to its backend.
    pub max_total: usize,
    /// Connections open at once from one address. A browser needs a
    /// handful; this is far above that.
    pub max_per_source: usize,
    /// The same for a forwarding node (PLAN.md M43), whose one address is
    /// everyone its proxy serves: a quarter of `max_total`, so whatever
    /// comes through it, every other caller keeps the rest.
    pub max_per_forwarder: usize,
    /// WebSockets (any upgrade) open at once for one client of a forwarding
    /// node, by the address it vouched for: its share of the node's
    /// connections. A person with a few tabs needs a handful.
    pub max_upgrades_per_forwarded_client: usize,
    /// How often an upgraded connection's caller is asked about again
    /// (PLAN.md M42): what a grant taken away waits at most to close it.
    pub recheck: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            first_request: Duration::from_secs(30),
            idle: Duration::from_secs(300),
            header_read: Duration::from_secs(20),
            max_total: 4096,
            max_per_source: 128,
            max_per_forwarder: 1024,
            max_upgrades_per_forwarded_client: 32,
            recheck: Duration::from_secs(30),
        }
    }
}

/// The open connections, in all and per source address.
#[derive(Default)]
struct Conns {
    counts: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

/// One open connection's place in [`Conns`], given back on drop.
struct Permit {
    conns: Arc<Conns>,
    source: IpAddr,
}

impl Conns {
    /// A place for one more connection from `source`, if it has fewer than
    /// `per_source` open and all together fewer than `limits.max_total`.
    fn acquire(self: &Arc<Self>, source: IpAddr, per_source: usize, limits: &Limits) -> Option<Permit> {
        let source = source.to_canonical();
        let mut counts = self.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mine = counts.1.get(&source).copied().unwrap_or(0);
        if counts.0 >= limits.max_total || mine >= per_source {
            return None;
        }
        counts.0 += 1;
        counts.1.insert(source, mine + 1);
        Some(Permit { conns: Arc::clone(self), source })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut counts = self.conns.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        counts.0 = counts.0.saturating_sub(1);
        if let Some(n) = counts.1.get_mut(&self.source) {
            *n -= 1;
            if *n == 0 {
                counts.1.remove(&self.source);
            }
        }
    }
}

/// Upgraded connections open per client of a forwarding node (PLAN.md M43),
/// by the address the node vouched for.
#[derive(Default)]
struct UpgradeSlots {
    by_client: Mutex<HashMap<IpAddr, usize>>,
}

/// One upgraded connection's place in [`UpgradeSlots`], given back on drop.
struct UpgradeSlot {
    slots: Arc<UpgradeSlots>,
    client: IpAddr,
}

impl UpgradeSlots {
    fn acquire(self: &Arc<Self>, client: IpAddr, max: usize) -> Option<UpgradeSlot> {
        let client = client.to_canonical();
        let mut by_client = self.by_client.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let open = by_client.entry(client).or_insert(0);
        if *open >= max {
            if *open == 0 {
                by_client.remove(&client);
            }
            return None;
        }
        *open += 1;
        Some(UpgradeSlot { slots: Arc::clone(self), client })
    }
}

impl Drop for UpgradeSlot {
    fn drop(&mut self) {
        let mut by_client = self.slots.by_client.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = by_client.get_mut(&self.client) {
            *n -= 1;
            if *n == 0 {
                by_client.remove(&self.client);
            }
        }
    }
}

/// What a connection's wrapper needs to know about the requests on it.
#[derive(Default)]
struct ConnStats {
    /// A request has begun on it.
    started: AtomicBool,
    /// Requests being served: begun, no response yet.
    in_flight: AtomicUsize,
    /// It switched protocols (PLAN.md M42): no more requests, and never idle.
    upgraded: AtomicBool,
}

/// Counts one request while it is being served.
struct InFlight(Arc<ConnStats>);

impl InFlight {
    fn begin(stats: &Arc<ConnStats>) -> Self {
        stats.started.store(true, Ordering::Relaxed);
        stats.in_flight.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(stats))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A connection that gives up on a client that says nothing: no request
/// within `first_request` of opening, or nothing read or written for `idle`
/// while none is being served and it has not been upgraded. hyper's own
/// timers cover an HTTP/1 request's headers once they have started; this
/// covers what they cannot — an HTTP/2 connection that never speaks, a
/// protocol sniff that never finishes, a keep-alive left open.
///
/// It holds the connection's place in the limits: hyper hands it on to an
/// upgraded connection, so a WebSocket counts for as long as it is open.
struct Watched<S> {
    inner: S,
    stats: Arc<ConnStats>,
    _permit: Permit,
    first_request: Duration,
    idle: Duration,
    opened: Instant,
    last_activity: Instant,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<S> Watched<S> {
    fn new(inner: S, stats: Arc<ConnStats>, permit: Permit, limits: &Limits) -> Self {
        let now = Instant::now();
        Self {
            inner,
            stats,
            _permit: permit,
            first_request: limits.first_request,
            idle: limits.idle,
            opened: now,
            last_activity: now,
            sleep: Box::pin(tokio::time::sleep(limits.first_request)),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        if let Poll::Ready(r) = Pin::new(&mut this.inner).poll_read(cx, buf) {
            if buf.filled().len() > before {
                this.last_activity = Instant::now();
            }
            return Poll::Ready(r);
        }
        let deadline = if this.stats.upgraded.load(Ordering::Relaxed) {
            None
        } else if !this.stats.started.load(Ordering::Relaxed) {
            Some(this.opened + this.first_request)
        } else if this.stats.in_flight.load(Ordering::Relaxed) == 0 {
            Some(this.last_activity + this.idle)
        } else {
            None
        };
        let Some(deadline) = deadline else {
            return Poll::Pending;
        };
        this.sleep.as_mut().reset(tokio::time::Instant::from_std(deadline));
        match this.sleep.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connection idle"))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            this.last_activity = Instant::now();
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// One service's backend, as the listener finds it by the address a
/// connection arrived on.
#[derive(Clone)]
pub struct Route {
    upstream: SocketAddr,
    /// `Host` for a request that named none (HTTP/1.0).
    authority: HeaderValue,
    pool: Arc<Pool>,
}

/// How long a backend connection may wait unused, and how many may.
const POOL_IDLE: Duration = Duration::from_secs(60);
const POOL_MAX_IDLE: usize = 32;
/// A backend on another machine (PLAN.md M26) that is off answers nothing
/// at all; without a limit a request waits out the kernel.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

type BackendConn = hyper::client::conn::http1::Connection<TokioIo<tokio::net::TcpStream>, Body>;

/// One backend connection: the half requests go in by, and the connection
/// itself, which whoever holds it drives (PLAN.md #331).
struct Lease {
    send: hyper::client::conn::http1::SendRequest<Body>,
    conn: BackendConn,
    /// Not yet closed: the connection's future has not finished.
    open: bool,
}

impl Lease {
    /// Drives the connection as far as it goes now; whether it is still
    /// open.
    fn drive(&mut self, cx: &mut Context<'_>) -> bool {
        if self.open && Pin::new(&mut self.conn).poll(cx).is_ready() {
            self.open = false;
        }
        self.open
    }

    /// Whether another request may go in now.
    fn reusable(&mut self, cx: &mut Context<'_>) -> bool {
        self.drive(cx) && matches!(self.send.poll_ready(cx), Poll::Ready(Ok(())))
    }
}

/// A backend's idle connections, the most recently used on top.
#[derive(Default)]
struct Pool {
    idle: std::sync::Mutex<Vec<(Lease, Instant)>>,
    reaping: std::sync::atomic::AtomicBool,
}

impl Pool {
    fn idle(&self) -> std::sync::MutexGuard<'_, Vec<(Lease, Instant)>> {
        self.idle.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// An idle connection a request can go in by now, if there is one.
    fn take(&self, cx: &mut Context<'_>) -> Option<Lease> {
        loop {
            let (mut lease, since) = self.idle().pop()?;
            // One the backend closed meanwhile is seen closed here.
            if since.elapsed() < POOL_IDLE && lease.reusable(cx) {
                return Some(lease);
            }
        }
    }

    /// Keeps `lease` for the next request, if it can take one.
    fn give_back(self: &Arc<Self>, mut lease: Lease, cx: &mut Context<'_>) {
        if !lease.reusable(cx) {
            return;
        }
        {
            let mut idle = self.idle();
            if idle.len() >= POOL_MAX_IDLE {
                return;
            }
            idle.push((lease, Instant::now()));
        }
        self.reap_idle();
    }

    /// Closes, every half `POOL_IDLE`, what waited too long or the backend
    /// closed — while the route lasts, from the first connection kept.
    fn reap_idle(self: &Arc<Self>) {
        if self.reaping.swap(true, Ordering::Relaxed) {
            return;
        }
        let pool = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(POOL_IDLE / 2);
            tick.tick().await;
            loop {
                tick.tick().await;
                let Some(pool) = pool.upgrade() else { return };
                let mut idle = std::mem::take(&mut *pool.idle());
                std::future::poll_fn(|cx| {
                    idle.retain_mut(|(lease, since)| since.elapsed() < POOL_IDLE && lease.drive(cx));
                    Poll::Ready(())
                })
                .await;
                // Those given back meanwhile are newer: they stay on top.
                let mut now = pool.idle();
                idle.append(&mut now);
                *now = idle;
            }
        });
    }
}

/// A backend's response body, driving its connection as it is read, and
/// giving the connection back once the body is done.
struct Driven {
    body: hyper::body::Incoming,
    lease: Option<Lease>,
    pool: Arc<Pool>,
}

impl Driven {
    fn done(&mut self, cx: &mut Context<'_>) {
        if let Some(lease) = self.lease.take() {
            self.pool.give_back(lease, cx);
        }
    }
}

impl hyper::body::Body for Driven {
    type Data = <hyper::body::Incoming as hyper::body::Body>::Data;
    type Error = hyper::Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        // The connection reads what the body is given.
        if let Some(lease) = &mut this.lease {
            lease.drive(cx);
        }
        let frame = std::task::ready!(Pin::new(&mut this.body).poll_frame(cx));
        match &frame {
            None => this.done(cx),
            Some(Ok(_)) if this.body.is_end_stream() => this.done(cx),
            // Cut short: the connection is in no state for another.
            Some(Err(_)) => this.lease = None,
            Some(Ok(_)) => {}
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

impl Route {
    /// Proxies to `upstream` in plain HTTP.
    pub fn new(upstream: SocketAddr) -> Self {
        let authority = HeaderValue::from_str(&upstream.to_string()).expect("a socket address is a header value");
        Self { upstream, authority, pool: Arc::default() }
    }

    async fn connect(&self) -> Result<Lease, Box<dyn std::error::Error + Send + Sync>> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(self.upstream))
            .await
            .map_err(|_| "connecting timed out")??;
        tcp.set_nodelay(true)?;
        socket2::SockRef::from(&tcp).set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)))?;
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        Ok(Lease { send, conn, open: true })
    }

    /// Passes `req` on to the backend, edited in place: its hop-by-hop
    /// headers gone, the backend told where it came from, and the name it
    /// asked for kept. It goes by a connection of the route's own, driven
    /// by this very request rather than a task of its own (PLAN.md #331).
    async fn forward(&self, mut req: Request<Body>, peer: SocketAddr, scheme: &'static str) -> axum::response::Response {
        use axum::http::header::{HOST, TE};
        // A tunnel has no meaning to one fixed backend.
        if req.method() == axum::http::Method::CONNECT {
            return crate::sign_in::plain(axum::http::StatusCode::NOT_IMPLEMENTED, "CONNECT is not supported");
        }
        let host = match req.headers().get(HOST) {
            Some(h) => Some(h.clone()),
            // HTTP/2 names it in its authority alone.
            None => req.uri().authority().and_then(|a| HeaderValue::from_str(a.as_str()).ok()),
        };
        // The origin form: the backend is the connection's other end.
        let path = req.uri().path_and_query().cloned().unwrap_or_else(|| axum::http::uri::PathAndQuery::from_static("/"));
        let Ok(uri) = axum::http::Uri::builder().path_and_query(path).build() else {
            return crate::sign_in::plain(axum::http::StatusCode::BAD_REQUEST, "bad request target");
        };
        *req.uri_mut() = uri;
        *req.version_mut() = axum::http::Version::HTTP_11;
        let headers = req.headers_mut();
        // gRPC needs `TE: trailers` end to end; any other `TE` is the hop's.
        let trailers = headers.get(TE).is_some_and(|v| v.to_str().is_ok_and(|v| v.trim().eq_ignore_ascii_case("trailers")));
        crate::upgrade::strip_hop_by_hop(headers, false);
        if trailers {
            headers.insert(TE, HeaderValue::from_static("trailers"));
        }
        headers.insert(HOST, host.unwrap_or_else(|| self.authority.clone()));
        crate::upgrade::set_forwarded(headers, peer, scheme);

        let mut pooled = true;
        loop {
            let lease = match pooled.then(|| std::future::poll_fn(|cx| Poll::Ready(self.pool.take(cx)))) {
                Some(take) => take.await,
                None => None,
            };
            let reused = lease.is_some();
            let lease = match lease {
                Some(lease) => lease,
                None => match self.connect().await {
                    Ok(lease) => lease,
                    Err(e) => return self.unreachable(&*e),
                },
            };
            match self.exchange(lease, req).await {
                Ok(answer) => return answer,
                Err(mut e) => match e.take_message() {
                    // Closed before the request went out: one a backend
                    // closed as it was taken. Again, on a new connection.
                    Some(back) if reused => {
                        req = back;
                        pooled = false;
                    }
                    _ => return self.unreachable(&(*e).into_error()),
                },
            }
        }
    }

    /// Sends `req` by `lease`, driving the connection until the backend
    /// answers; the answer's body drives it on.
    async fn exchange(
        &self,
        mut lease: Lease,
        req: Request<Body>,
    ) -> Result<axum::response::Response, Box<hyper::client::conn::TrySendError<Request<Body>>>> {
        let mut answer = std::pin::pin!(lease.send.try_send_request(req));
        let res = std::future::poll_fn(|cx| {
            lease.drive(cx);
            answer.as_mut().poll(cx)
        })
        .await
        .map_err(Box::new)?;
        let (mut parts, body) = res.into_parts();
        crate::upgrade::strip_hop_by_hop(&mut parts.headers, false);
        let mut body = Driven { body, lease: Some(lease), pool: Arc::clone(&self.pool) };
        // Nothing to read (HEAD, 204, 304): the connection is free now.
        if hyper::body::Body::is_end_stream(&body.body) {
            std::future::poll_fn(|cx| {
                body.done(cx);
                Poll::Ready(())
            })
            .await;
        }
        Ok(axum::response::Response::from_parts(parts, Body::new(body)))
    }

    fn unreachable(&self, e: &(dyn std::error::Error + 'static)) -> axum::response::Response {
        // The client's own error says little more than that it failed.
        let mut error = e.to_string();
        let mut source = e.source();
        while let Some(inner) = source {
            error.push_str(": ");
            error.push_str(&inner.to_string());
            source = inner.source();
        }
        tracing::warn!(upstream = %self.upstream, %error, "backend unreachable");
        crate::sign_in::plain(axum::http::StatusCode::BAD_GATEWAY, "Bad Gateway")
    }
}

/// Service address → its service, shared by the listener and replaced as
/// services come and go. An address not in it is nobody's: its connections
/// are closed unanswered.
pub type Routes = Arc<RwLock<HashMap<Ipv4Addr, Arc<Route>>>>;

/// The TLS listening socket (PLAN.md M35): the first one systemd passed us
/// when `wireserve-tls.socket` started this process — held by systemd
/// across restarts, so no other local user can take the port in between —
/// or, run outside systemd, `0.0.0.0:port` bound here.
pub fn listener(port: u16) -> std::io::Result<TcpListener> {
    listener_at(0, port)
}

/// The plain-HTTP listening socket (PLAN.md #328): the second one systemd
/// passed, or `0.0.0.0:port` bound here outside systemd. `None` when systemd
/// passed only one — a socket unit from before there was one — and port 80
/// is then not answered here.
pub fn http_listener(port: u16) -> std::io::Result<Option<TcpListener>> {
    let fds = passed_fds(std::process::id(), std::env::var("LISTEN_PID").ok().as_deref(), std::env::var("LISTEN_FDS").ok().as_deref());
    if fds == Some(1) {
        return Ok(None);
    }
    listener_at(1, port).map(Some)
}

/// The `index`th socket systemd passed, or one bound to `port`.
fn listener_at(index: u32, port: u16) -> std::io::Result<TcpListener> {
    use std::os::fd::FromRawFd;
    let pid = std::process::id();
    let passed = listen_fd(pid, std::env::var("LISTEN_PID").ok().as_deref(), std::env::var("LISTEN_FDS").ok().as_deref(), index);
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

/// The `index`th descriptor systemd's socket activation passed this
/// process, if it passed that many: `LISTEN_PID` names us, and they count
/// up from 3, in the order the socket unit lists them.
fn listen_fd(pid: u32, listen_pid: Option<&str>, listen_fds: Option<&str>, index: u32) -> Option<std::os::fd::RawFd> {
    const SD_LISTEN_FDS_START: std::os::fd::RawFd = 3;
    let count = passed_fds(pid, listen_pid, listen_fds)?;
    (index < count).then(|| SD_LISTEN_FDS_START + std::os::fd::RawFd::try_from(index).unwrap_or(0))
}

/// How many descriptors systemd passed this process; `None` when it was
/// not started by its socket.
fn passed_fds(pid: u32, listen_pid: Option<&str>, listen_fds: Option<&str>) -> Option<u32> {
    (listen_pid?.parse::<u32>().ok()? == pid).then_some(())?;
    listen_fds?.parse::<u32>().ok().filter(|n| *n >= 1)
}

/// Accepts on `listener` until aborted, handing each connection to the
/// service whose address it arrived on.
///
/// The service's policy and the caller's name are looked up for every
/// request, not once per connection: a grant taken away, or a node
/// revoked, reaches a keep-alive or HTTP/2 connection at its next request,
/// and an upgraded one — a WebSocket — within [`Limits::recheck`].
pub fn spawn(listener: TcpListener, tls: Arc<rustls::ServerConfig>, shared: Shared) -> JoinHandle<()> {
    spawn_with_limits(listener, tls, shared, Limits::default())
}

/// [`spawn`], with the connection limits given.
pub fn spawn_with_limits(listener: TcpListener, tls: Arc<rustls::ServerConfig>, shared: Shared, limits: Limits) -> JoinHandle<()> {
    accept(listener, Some(tokio_rustls::TlsAcceptor::from(tls)), shared, limits)
}

/// The plain-HTTP listener (PLAN.md #328): each service's port 80, answered
/// by the same rules as its 443 but for the sign-in, which needs TLS to keep
/// a session in.
pub fn spawn_http(listener: TcpListener, shared: Shared) -> JoinHandle<()> {
    spawn_http_with_limits(listener, shared, Limits::default())
}

/// [`spawn_http`], with the connection limits given.
pub fn spawn_http_with_limits(listener: TcpListener, shared: Shared, limits: Limits) -> JoinHandle<()> {
    accept(listener, None, shared, limits)
}

/// One listener's accept loop: TLS when `tls` is given, plain HTTP without.
fn accept(listener: TcpListener, tls: Option<tokio_rustls::TlsAcceptor>, shared: Shared, limits: Limits) -> JoinHandle<()> {
    let http = tls.is_none();
    let conns = Arc::new(Conns::default());
    let upgrade_slots = Arc::new(UpgradeSlots::default());
    tokio::spawn(async move {
        let mut last_refusal_logged: Option<Instant> = None;
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            // The address the agent rewrote 443 (or 80) to this port on.
            // Anything else — the host's own addresses, a service no longer
            // served — is nobody's to answer.
            let Some(vip) = tcp.local_addr().ok().and_then(|a| local_v4(a.ip())) else {
                continue;
            };
            let route = read(shared.of(http).0).get(&vip).cloned();
            let Some(route) = route else {
                continue;
            };
            // Only what would be answered counts against the limits, and
            // what is over them is closed unanswered, before any TLS work.
            let forwarding_node = shared.forwarding_node(peer.ip());
            let per_source = if forwarding_node.is_some() { limits.max_per_forwarder } else { limits.max_per_source };
            let Some(permit) = conns.acquire(peer.ip(), per_source, &limits) else {
                if last_refusal_logged.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                    last_refusal_logged = Some(Instant::now());
                    tracing::warn!(
                        peer = %peer.ip(),
                        forwarding_node = forwarding_node.as_deref().unwrap_or_default(),
                        "too many open connections; closing new ones (logged once a minute)"
                    );
                }
                continue;
            };
            // Without it, Nagle holds back the tail of a response written in
            // more than one TLS record until the client ACKs the head — which
            // its delayed ACK puts off by up to 40ms here, and on a phone's
            // link by a round trip on top.
            let _ = tcp.set_nodelay(true);
            // What finds a client gone without a word — a phone off the
            // mesh — once nothing else would: an upgraded connection is
            // never idle by our own timer.
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(15))
                .with_retries(4);
            let _ = socket2::SockRef::from(&tcp).set_tcp_keepalive(&keepalive);
            let conn = Conn { shared: shared.clone(), limits: limits.clone(), upgrade_slots: Arc::clone(&upgrade_slots), vip, peer, route, http };
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    Some(acceptor) => {
                        let Ok(Ok(tls)) = tokio::time::timeout(conn.limits.handshake, acceptor.accept(tcp)).await else {
                            return;
                        };
                        conn.serve(tls, permit).await;
                    }
                    None => conn.serve(tcp, permit).await,
                }
            });
        }
    })
}

/// One accepted connection, and what serving it needs.
struct Conn {
    shared: Shared,
    limits: Limits,
    upgrade_slots: Arc<UpgradeSlots>,
    vip: Ipv4Addr,
    peer: SocketAddr,
    route: Arc<Route>,
    /// The plain-HTTP listener's (PLAN.md #328): no sign-in.
    http: bool,
}

impl Conn {
    async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(self, io: S, permit: Permit) {
        let Conn { shared, limits, upgrade_slots, vip, peer, route, http } = self;
        let stats = Arc::new(ConnStats::default());
        let watched = Watched::new(io, Arc::clone(&stats), permit, &limits);
        let caller_addr = local_v4(peer.ip());
        let scheme = if http { "http" } else { "https" };
        let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
            let in_flight = InFlight::begin(&stats);
            let stats = Arc::clone(&stats);
            let policy = read(shared.of(http).1).get(&vip).cloned();
            let caller = caller_addr.and_then(|a| read(&shared.callers).get(&a).cloned());
            // No sign-in without TLS: no session can be kept safe there.
            let sign_in = if http { None } else { read(&shared.sign_in).clone() };
            let identity = read(&shared.identity).clone();
            let strip = read(&shared.strip).clone();
            let forwarder = shared.forwarding_node(peer.ip()).is_some();
            let misdirected = match &policy {
                Some(p) if !for_this_service(&req, &p.hosts()) => !(forwarder && take_public_name(&mut req, &p.fqdn)),
                _ => false,
            };
            if misdirected {
                tracing::info!(
                    service = policy.as_ref().map(|p| p.fqdn.as_str()).unwrap_or_default(),
                    authority = req.uri().authority().map(|a| a.as_str()).unwrap_or_default(),
                    host = ?req.headers().get(axum::http::header::HOST),
                    version = ?req.version(),
                    "misdirected request: it names another host"
                );
            }
            let route = Arc::clone(&route);
            let (upstream, recheck) = (route.upstream, limits.recheck);
            let max_upgrades = limits.max_upgrades_per_forwarded_client;
            let upgrade_slots = Arc::clone(&upgrade_slots);
            let upgrade = crate::upgrade::wanted(&req);
            // Anything else asking to switch goes on as a plain
            // request (PLAN.md #271).
            if !upgrade {
                crate::upgrade::ignore(req.headers_mut());
            }
            prepare(req.headers_mut(), caller.as_ref().map(|c| c.node.as_str()), forwarder, &strip);
            let shared = shared.clone();
            async move {
                let _in_flight = in_flight;
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
                // A page on another site may not act here as the
                // device it runs on (PLAN.md #276).
                if !policy.cross_site && started_elsewhere(&req, &policy.hosts(), scheme, upgrade, forwarder) {
                    tracing::info!(
                        service = %policy.fqdn,
                        peer = %peer.ip(),
                        method = %req.method(),
                        origin = ?req.headers().get(axum::http::header::ORIGIN),
                        site = ?req.headers().get("sec-fetch-site"),
                        "refused a request another site started"
                    );
                    return Ok(crate::sign_in::plain(
                        axum::http::StatusCode::FORBIDDEN,
                        "a page on another site may not do this here",
                    ));
                }
                // The sign-in's own pages, on every service's name
                // (PLAN.md M48).
                if let Some(si) = sign_in.as_ref().filter(|_| crate::sign_in::is_own_path(req.uri().path())) {
                    return Ok(if req.uri().path() == wireserve_types::session::CALLBACK_PATH {
                        si.callback(req.uri(), req.headers(), &policy.fqdn, peer.ip()).await
                    } else {
                        si.sign_out(req.method(), req.headers(), &policy.fqdn).await
                    });
                }
                let mut req = req.map(Body::new);
                // As the client asked, for asking again while it is open.
                let asked = upgrade.then(|| Arc::new(as_asked(&req)));
                let set_cookie = match guard(&mut req, sign_in.as_deref(), &policy, caller_addr, &identity).await {
                    Err(denied) => return Ok(*denied),
                    Ok(set_cookie) => set_cookie,
                };
                let answer: Result<axum::response::Response, std::convert::Infallible> = match asked {
                    Some(asked) => {
                        // A forwarding node's client, by the address it
                        // vouched for — or, without one, the node's own.
                        let slot = if forwarder {
                            let client = req
                                .headers()
                                .get("x-forwarded-for")
                                .and_then(|v| v.to_str().ok())
                                .and_then(|v| v.parse::<IpAddr>().ok())
                                .unwrap_or(peer.ip());
                            let Some(slot) = upgrade_slots.acquire(client, max_upgrades) else {
                                tracing::info!(%client, "too many WebSockets open for one client of a forwarding node");
                                return Ok(crate::sign_in::plain(
                                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                                    "too many connections open from your address",
                                ));
                            };
                            Some(slot)
                        } else {
                            None
                        };
                        let again = move || {
                            let (shared, asked) = (shared.clone(), Arc::clone(&asked));
                            async move { still_admitted(&shared, http, vip, caller_addr, &asked).await }
                        };
                        let answer = crate::upgrade::proxy(req, upstream, peer, scheme, recheck, again, slot).await;
                        if answer.status() == axum::http::StatusCode::SWITCHING_PROTOCOLS {
                            stats.upgraded.store(true, Ordering::Relaxed);
                        }
                        Ok(answer)
                    }
                    None => Ok(route.forward(req, peer, scheme).await),
                };
                // A renewed session goes back to the browser with
                // whatever the backend answered.
                answer.map(|mut a| {
                    if let Some(c) = set_cookie {
                        a.headers_mut().append(axum::http::header::SET_COOKIE, c);
                    }
                    a
                })
            }
        });
        let mut builder = auto::Builder::new(TokioExecutor::new());
        builder.http1().timer(TokioTimer::new()).header_read_timeout(limits.header_read);
        builder.http2().timer(TokioTimer::new()).keep_alive_interval(Some(Duration::from_secs(30))).keep_alive_timeout(Duration::from_secs(20));
        // Plain HTTP is HTTP/1 — browsers speak HTTP/2 only over TLS — and
        // what tries cleartext HTTP/2 here is not one.
        let builder = if http { builder.http1_only() } else { builder };
        let _ = builder.serve_connection_with_upgrades(TokioIo::new(watched), service).await;
    }
}

impl Policy {
    /// Every host a request may name.
    fn hosts(&self) -> Vec<&str> {
        std::iter::once(self.fqdn.as_str()).chain(self.aliases.iter().map(String::as_str)).collect()
    }
}

/// A request's method, target, version and headers, without its body.
fn as_asked<B>(req: &Request<B>) -> Request<()> {
    let mut asked = Request::new(());
    *asked.method_mut() = req.method().clone();
    *asked.uri_mut() = req.uri().clone();
    *asked.version_mut() = req.version();
    *asked.headers_mut() = req.headers().clone();
    asked
}

/// Whether the caller of an upgraded connection would still be let in,
/// asked as its request was (PLAN.md M42): its service still served here
/// under the name it asked for, and `guard` still letting it through. A
/// sign-in that cannot be renewed right now closes nothing — its trouble is
/// not the caller's; a refusal does.
async fn still_admitted(shared: &Shared, http: bool, vip: Ipv4Addr, caller_addr: Option<Ipv4Addr>, asked: &Request<()>) -> bool {
    let (routes, policies) = shared.of(http);
    if read(routes).get(&vip).is_none() {
        return false;
    }
    let Some(policy) = read(policies).get(&vip).cloned() else {
        return false;
    };
    if !for_this_service(asked, &policy.hosts()) {
        return false;
    }
    let sign_in = if http { None } else { read(&shared.sign_in).clone() };
    let identity = read(&shared.identity).clone();
    let mut req = as_asked(asked).map(|()| Body::empty());
    match guard(&mut req, sign_in.as_deref(), &policy, caller_addr, &identity).await {
        Ok(_) => true,
        Err(denied) => denied.status().is_server_error(),
    }
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
fn for_this_service<B>(req: &Request<B>, hosts: &[&str]) -> bool {
    let same = |host: &str| {
        let host = host.strip_suffix('.').unwrap_or(host);
        hosts.iter().any(|h| host.eq_ignore_ascii_case(h))
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

/// A forwarding node's request naming the public name its proxy was asked
/// for (PLAN.md #335): that name goes to `X-Forwarded-Host`, unless the
/// node named one there itself, and the request names the service's own
/// `fqdn` instead — what the backend sees when the proxy sends it as `Host`
/// (Caddy's `header_up Host {upstream_hostport}`). The `Host` check keeps a
/// rebound name in a browser out, and a forwarding node is a proxy, not a
/// browser: naming one says nobody browses there. `prepare` then checks the
/// public name as it does any the node vouches for. False when `fqdn` is
/// not a header value, and the request is refused as before.
fn take_public_name<B>(req: &mut Request<B>, fqdn: &str) -> bool {
    use axum::http::header::HOST;
    let Ok(own) = HeaderValue::from_str(fqdn) else {
        return false;
    };
    let xfh = axum::http::HeaderName::from_static("x-forwarded-host");
    let public = match req.headers().get(HOST) {
        Some(h) => Some(h.clone()),
        // HTTP/2 names it in its authority alone.
        None => req.uri().authority().and_then(|a| HeaderValue::from_str(a.as_str()).ok()),
    };
    if let Some(public) = public.filter(|_| !req.headers().contains_key(&xfh)) {
        req.headers_mut().insert(xfh, public);
    }
    req.headers_mut().insert(HOST, own);
    // The origin form: the authority named the public name too.
    if req.uri().authority().is_some() {
        let path = req.uri().path_and_query().cloned().unwrap_or_else(|| axum::http::uri::PathAndQuery::from_static("/"));
        *req.uri_mut() = axum::http::Uri::from(path);
    }
    true
}

/// `name:port` without the port; anything else as it is.
fn without_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Who gets in (PLAN.md M36, M48): `Err` is the answer to send instead of
/// passing the request on; `Ok` may carry a renewed session's cookie for
/// the browser.
///
/// 1. Identity headers a client sent are removed, always, and so are the
///    sign-in's cookies, the session and the bind cookie: no backend needs
///    them.
/// 2. An open service, or a caller whose node the grants name, goes on —
///    unnamed: a device says nothing about who is using it. Not on a
///    service that is for people only (`always_sign_in`, PLAN.md #326).
/// 3. Anyone else, where the grants name groups a sign-in can prove, is
///    asked about: signed in with one of them, on; signed in without, 403;
///    not signed in, sent to sign in. Who they are goes to the backend in
///    the identity headers only on a service for people only, whose node
///    said its backend reads them.
/// 4. Anyone else is refused with 403.
async fn guard(
    req: &mut Request<Body>,
    sign_in: Option<&crate::sign_in::SignIn>,
    policy: &Policy,
    caller: Option<Ipv4Addr>,
    identity: &wireserve_types::IdentityHeaders,
) -> Result<Option<HeaderValue>, Box<axum::response::Response>> {
    use axum::http::StatusCode;
    crate::sign_in::strip_identity(req.headers_mut(), identity);
    let access = &policy.access;
    let by_device = !access.always_sign_in && (access.open || caller.is_some_and(|c| access.sources.contains(&c)));
    let mut set_cookie = None;
    if !by_device {
        if !access.sign_in {
            let why = if access.always_sign_in {
                "this service is for people who sign in, and no sign-in is offered for it"
            } else {
                "this device may not reach this service"
            };
            return Err(Box::new(crate::sign_in::plain(StatusCode::FORBIDDEN, why)));
        }
        let Some(si) = sign_in else {
            return Err(Box::new(crate::sign_in::plain(StatusCode::SERVICE_UNAVAILABLE, "this service's sign-in is not set up here yet")));
        };
        match si.check(req.method(), req.uri(), req.headers(), &policy.fqdn).await {
            crate::sign_in::Verdict::Allow { session, set_cookie: renewed } => {
                if !session.groups.iter().any(|g| access.sign_in_groups.contains(g)) {
                    return Err(Box::new(crate::sign_in::plain(StatusCode::FORBIDDEN, "signed in, but not allowed here")));
                }
                // Only to a backend its node said reads them (PLAN.md #326):
                // any other is told nothing it has no use for.
                if access.always_sign_in {
                    name(req.headers_mut(), &session.sub, session.email.as_deref(), &session.groups, identity);
                }
                set_cookie = renewed;
            }
            crate::sign_in::Verdict::Deny(answer) => return Err(Box::new(answer)),
        }
    }
    crate::sign_in::strip_cookie(req.headers_mut(), wireserve_types::session::COOKIE);
    crate::sign_in::strip_cookie(req.headers_mut(), wireserve_types::session::BIND_COOKIE);
    Ok(set_cookie)
}

/// Tells the backend who signed in, in the identity headers.
fn name(headers: &mut HeaderMap, user: &str, email: Option<&str>, groups: &[String], identity: &wireserve_types::IdentityHeaders) {
    let mut set = |name: &str, value: &str| {
        if let (Ok(n), Ok(v)) = (axum::http::HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            headers.insert(n, v);
        }
    };
    set(&identity.user, user);
    if let Some(email) = email {
        set(&identity.email, email);
    }
    set(&identity.groups, &identity.join_groups(groups));
}

/// Headers a proxy or an identity-aware front end sets and a backend may
/// believe, so none may arrive from a client: where the request came from,
/// which URL it asked for, and who is calling, in the spellings the common
/// proxies and providers use. (The identity headers of *this* deployment are
/// removed separately, whatever their names, and set again only from a
/// sign-in.)
const UNTRUSTED_EXACT: &[&str] = &[
    "forwarded", "x-real-ip", "true-client-ip", "cf-connecting-ip", "x-client-ip", "x-cluster-client-ip",
    "x-url-scheme", "front-end-https", "x-rewrite-url", "x-http-host-override",
    "remote-user", "remote-email", "remote-groups", "remote-name",
];
/// The same, for families of names.
const UNTRUSTED_PREFIX: &[&str] = &["x-forwarded-", "x-original-", "x-remote-", "x-auth-request-", "x-webauth-", "x-authentik-", "x-authelia-"];
/// What a forwarding node — the operator's own reverse proxy — says about
/// its client (PLAN.md M43): where the client is, the name it asked for,
/// and whether it came over HTTP or HTTPS (#334). Never who it is.
const FORWARDER_KEEPS: &[&str] = &["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"];

/// `name` is lowercase, as hyper hands it over. A name with an underscore is
/// never passed on, whatever it says: WSGI, Rack and Django's ASGI handler
/// give `X_Auth_User` and `X-Auth-User` one and the same name, so every
/// header removed here would otherwise come through in that spelling
/// (CVE-2026-3902, CVE-2025-64484). nginx drops them by default too.
fn is_untrusted(name: &str, forwarder: bool, extra: &[String]) -> bool {
    if name.contains('_') || name == NODE_HEADER {
        return true;
    }
    if extra.iter().any(|e| crate::sign_in::same_header(e, name)) {
        return true;
    }
    if forwarder && FORWARDER_KEEPS.contains(&name) {
        return false;
    }
    UNTRUSTED_EXACT.contains(&name) || UNTRUSTED_PREFIX.iter().any(|p| name.starts_with(p))
}

/// Whether `req` was started by a page on another site, and asks for more
/// than a look (PLAN.md #276): a POST, PUT, DELETE or the like, or a
/// WebSocket (`websocket`, as [`crate::upgrade::wanted`] found it).
///
/// Admission here is by device, and a browser sends whatever any open page
/// asks for through the device's tunnel — the device's grants and owner
/// with it, which no SameSite rule holds back, since no cookie is
/// involved. The browser does say who started a request: `Sec-Fetch-Site`
/// (every current browser) or, without it, `Origin`. `same-site` counts as
/// another site: every service shares the parent domain, a node's own
/// among them. Following a link stays allowed, and so do reads, which the
/// browser keeps from the other page. A client that is not a browser
/// sends neither header, and is never refused here.
///
/// `forwarder`: the caller is a forwarding node (PLAN.md M43), whose
/// browsers are on the public name it was asked for — the
/// `X-Forwarded-Host` it vouched for, which `prepare` kept only then — so
/// that name's pages are the service's own too, at the scheme it vouched
/// for in `X-Forwarded-Proto`, or `https` without one (#334).
fn started_elsewhere<B>(req: &Request<B>, hosts: &[&str], scheme: &str, websocket: bool, forwarder: bool) -> bool {
    use axum::http::Method;
    let headers = req.headers();
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(|v| v.trim().to_ascii_lowercase());
    let public = header("x-forwarded-host").filter(|_| forwarder);
    let public_scheme = header("x-forwarded-proto").filter(|_| forwarder).unwrap_or_else(|| "https".to_owned());
    let own_origin = |origin: &str| {
        let ours = origin
            .strip_prefix(scheme)
            .and_then(|rest| rest.strip_prefix("://"))
            .is_some_and(|host| hosts.iter().any(|h| host.eq_ignore_ascii_case(h)));
        ours || origin
            .strip_prefix(public_scheme.as_str())
            .and_then(|rest| rest.strip_prefix("://"))
            .is_some_and(|host| public.as_deref().is_some_and(|p| host.eq_ignore_ascii_case(p)))
    };
    let origin = header("origin");
    let elsewhere = match header("sec-fetch-site").as_deref() {
        Some("cross-site" | "same-site") => true,
        Some(_) => false,
        None => origin.as_deref().is_some_and(|o| !own_origin(o)),
    };
    // A WebSocket must come from this service's own pages, whatever else
    // the browser says.
    let foreign_socket = websocket && origin.as_deref().is_some_and(|o| !own_origin(o));
    let acts = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    (elsewhere && (acts || websocket)) || foreign_socket
}

/// Strips every header a client could use to claim to be someone else, and
/// names the calling node. The forwarding headers are then set afresh by
/// the proxy from the connection itself — never appended to what the client
/// sent. `extra` is the operator's own list on top of the built-in one.
/// First of all, what the client's `Connection` names goes
/// ([`take_connection_options`]), so nothing set from here on can be named
/// away; and any name with an underscore goes too ([`is_untrusted`]).
///
/// `forwarder`: the caller is a node named in `WIRESERVE_FORWARDING_NODES`
/// (PLAN.md M43), whose `X-Forwarded-For`, `-Host` and `-Proto` stay, cut
/// down to what the node itself can vouch for ([`vouched_for`]): the proxy
/// appends this connection's peer to the first and keeps the others, so the
/// backend sees the client the forwarding node saw, the name it was asked
/// for and the scheme it was asked over (#334). The operator's own `extra`
/// list still removes them.
pub fn prepare(headers: &mut HeaderMap, caller: Option<&str>, forwarder: bool, extra: &[String]) {
    take_connection_options(headers);
    let doomed: Vec<axum::http::HeaderName> =
        headers.keys().filter(|n| is_untrusted(n.as_str(), forwarder, extra)).cloned().collect();
    for name in doomed {
        headers.remove(name);
    }
    if forwarder {
        vouched_for(headers);
    }
    if let Some(node) = caller.and_then(|n| HeaderValue::from_str(n).ok()) {
        headers.insert(NODE_HEADER, node);
    }
    join_cookies(headers);
}

/// The options of `Connection` that are not header names. Everything else in
/// it names a header of the client's own hop.
const CONNECTION_OPTIONS: [&str; 3] = ["close", "keep-alive", "upgrade"];

/// Removes the headers a client's `Connection` names (RFC 9110 §7.6.1),
/// here and now, and leaves `Connection` holding only
/// [`CONNECTION_OPTIONS`]. The proxy further on removes whatever
/// `Connection` names too, and does it after `prepare` has named the calling
/// node and `guard` the person: left to it, `Connection: x-auth-user` took
/// the terminator's own identity headers away, and a client's underscore
/// spelling of them reached the backend as the only one. `Host` is not the
/// client's to drop: the request is routed and checked by it.
fn take_connection_options(headers: &mut HeaderMap) {
    use axum::http::header::{CONNECTION, HOST};
    if !headers.contains_key(CONNECTION) {
        return;
    }
    let tokens: Vec<String> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    headers.remove(CONNECTION);
    let (options, named): (Vec<&str>, Vec<&str>) =
        tokens.iter().map(String::as_str).partition(|t| CONNECTION_OPTIONS.contains(t));
    for name in named {
        if let Ok(name) = axum::http::HeaderName::from_bytes(name.as_bytes()) {
            if name != HOST {
                headers.remove(name);
            }
        }
    }
    if !options.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&options.join(", ")) {
            headers.insert(CONNECTION, v);
        }
    }
}

/// What a forwarding node can vouch for, and nothing it merely passed on
/// (PLAN.md M43):
///
/// - `X-Forwarded-For`: only its last entry — the client the node's proxy
///   saw. Whatever came before it, a proxy that appends (nginx's
///   `$proxy_add_x_forwarded_for`) took from the client unchecked, and
///   backends believe the first entry. Not an IP address: dropped, and the
///   backend sees the node alone.
/// - `X-Forwarded-Host`: one value, a host name with an optional port, as
///   `Host` may carry; anything else is dropped, and the proxy names the
///   request's own `Host` instead.
/// - `X-Forwarded-Proto`: one value, `http` or `https` in any case, written
///   lowercase; anything else is dropped, and the proxy names the scheme
///   this request came over (#334). The node's proxy terminated the
///   client's TLS, so only it knows: a public Caddy taking HTTPS and
///   forwarding to the service's port 80 had the backend told `http`, and
///   an app that insists on HTTPS redirected in a loop.
fn vouched_for(headers: &mut HeaderMap) {
    let xff = axum::http::HeaderName::from_static("x-forwarded-for");
    let last = headers
        .get_all(&xff)
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map(str::trim)
        .and_then(|ip| ip.parse::<IpAddr>().ok());
    headers.remove(&xff);
    if let Some(ip) = last.and_then(|ip| HeaderValue::from_str(&ip.to_string()).ok()) {
        headers.insert(xff, ip);
    }

    let xfh = axum::http::HeaderName::from_static("x-forwarded-host");
    let mut values = headers.get_all(&xfh).iter();
    let single = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok().filter(|v| is_host(v)).map(str::to_owned),
        _ => None,
    };
    headers.remove(&xfh);
    if let Some(v) = single.and_then(|v| HeaderValue::from_str(&v).ok()) {
        headers.insert(xfh, v);
    }

    let xfp = axum::http::HeaderName::from_static("x-forwarded-proto");
    let mut values = headers.get_all(&xfp).iter();
    let scheme = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok().map(str::trim).and_then(|v| {
            ["http", "https"].into_iter().find(|s| v.eq_ignore_ascii_case(s))
        }),
        _ => None,
    };
    headers.remove(&xfp);
    if let Some(scheme) = scheme {
        headers.insert(xfp, HeaderValue::from_static(scheme));
    }
}

/// A host name, with an optional port: letters, digits and hyphens in
/// labels of 1 to 63, none starting or ending with a hyphen, 253 in all.
fn is_host(value: &str) -> bool {
    let (name, port) = match value.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (value, None),
    };
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok());
    let label_ok = |l: &str| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    port_ok && !name.is_empty() && name.len() <= 253 && name.split('.').all(label_ok)
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

    /// The sign-in, with a stand-in agent in `dir`.
    fn sign_in(dir: &std::path::Path) -> crate::sign_in::SignIn {
        let (link, _) = crate::sign_in::tests::fake_agent(dir);
        crate::sign_in::SignIn::new(crate::sign_in::tests::settings(), link).unwrap()
    }

    fn open(fqdn: &str) -> Policy {
        Policy { fqdn: fqdn.into(), access: wireserve_types::ServiceAccess { open: true, ..Default::default() }, cross_site: false, aliases: vec![] }
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
            cross_site: false,
            aliases: vec![],
        }
    }

    fn ids() -> wireserve_types::IdentityHeaders {
        wireserve_types::IdentityHeaders::default()
    }

    fn request() -> Request<Body> {
        Request::builder()
            .header("cookie", "theme=dark; __Host-wireserve-session=s3cret; __Host-wireserve-bind=b1nd")
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
        assert!(guard(&mut req, None, &restricted("jf.int.test", false), granted, &ids()).await.is_ok());
        assert!(req.headers().get("x-auth-user").is_none(), "a forged identity is removed for a device too");

        let answer = guard(&mut request(), None, &restricted("jf.int.test", false), other, &ids()).await;
        assert_eq!(answer.expect_err("refused").status(), StatusCode::FORBIDDEN, "no sign-in to try");
        let answer = guard(&mut request(), None, &restricted("jf.int.test", false), None, &ids()).await;
        assert_eq!(answer.expect_err("refused").status(), StatusCode::FORBIDDEN, "an unknown caller neither");

        let answer = guard(&mut request(), None, &restricted("jf.int.test", true), other, &ids()).await;
        assert_eq!(answer.expect_err("refused").status(), StatusCode::SERVICE_UNAVAILABLE, "no sign-in here yet");
    }

    #[tokio::test]
    async fn every_backend_loses_the_session_cookie_and_forged_identity() {
        let dir = tempfile::tempdir().unwrap();
        let si = sign_in(dir.path());
        for si in [Some(&si), None] {
            let mut req = request();
            assert!(guard(&mut req, si, &open("grafana.int.test"), None, &ids()).await.is_ok());
            assert_eq!(req.headers().get("cookie").unwrap(), "theme=dark");
            assert!(req.headers().get("x-auth-user").is_none());
        }
    }

    #[tokio::test]
    async fn someone_signed_in_with_a_granted_group_gets_in_as_themselves() {
        use axum::http::StatusCode;
        let dir = tempfile::tempdir().unwrap();
        let si = sign_in(dir.path());
        let other = Some("10.9.0.3".parse().unwrap());
        let with = |token: &str| {
            let mut req = request();
            req.headers_mut().insert("cookie", HeaderValue::from_str(&format!("theme=dark; __Host-wireserve-session={token}")).unwrap());
            req
        };
        let token = crate::sign_in::tests::token;

        let mut req = with(&token("jf.int.test", 60, &["family", "admins"]));
        assert_eq!(guard(&mut req, Some(&si), &restricted("jf.int.test", true), other, &ids()).await.ok(), Some(None));
        assert!(req.headers().get("x-auth-user").is_none(), "in, and named to nobody: its backend reads no names");
        assert_eq!(req.headers()["cookie"], "theme=dark", "the session stays with the terminator");

        // A backend its node said reads them is told who it is.
        let mut people = restricted("jf.int.test", true);
        people.access.always_sign_in = true;
        let mut req = with(&token("jf.int.test", 60, &["family", "admins"]));
        assert_eq!(guard(&mut req, Some(&si), &people, other, &ids()).await.ok(), Some(None));
        assert_eq!(req.headers()["x-auth-user"], "anna", "not mallory");
        assert_eq!(req.headers()["x-auth-email"], "anna@example.com");
        assert_eq!(req.headers()["x-auth-groups"], "family,admins");
        assert_eq!(req.headers()["cookie"], "theme=dark", "the session stays with the terminator");

        let answer = guard(&mut with(&token("jf.int.test", 60, &["admins"])), Some(&si), &restricted("jf.int.test", true), other, &ids()).await;
        assert_eq!(answer.expect_err("not granted").status(), StatusCode::FORBIDDEN);
        let answer = guard(&mut with(&token("vault.int.test", 60, &["family"])), Some(&si), &restricted("jf.int.test", true), other, &ids()).await;
        assert_eq!(answer.expect_err("another service's").status(), StatusCode::FOUND, "off to sign in");
        let answer = guard(&mut request(), Some(&si), &restricted("jf.int.test", false), other, &ids()).await;
        assert_eq!(answer.expect_err("no group to prove").status(), StatusCode::FORBIDDEN);

        // Past its time: renewed, and the browser told.
        let renewed = guard(&mut with(&token("jf.int.test", -1, &["family"])), Some(&si), &restricted("jf.int.test", true), other, &ids()).await;
        assert!(renewed.expect("renewed").is_some_and(|c| c.to_str().unwrap().starts_with("__Host-wireserve-session=wst1.")));
    }

    #[tokio::test]
    async fn a_device_names_nobody_and_a_service_for_people_asks_every_device_to_sign_in() {
        use axum::http::StatusCode;
        let dir = tempfile::tempdir().unwrap();
        let si = sign_in(dir.path());
        let granted = Some("10.9.0.2".parse().unwrap());
        let mut req = request();
        assert!(guard(&mut req, Some(&si), &restricted("jf.int.test", true), granted, &ids()).await.is_ok());
        assert!(req.headers().get("x-auth-user").is_none(), "a device's grants say nobody's name");

        // For people only: the granted device is asked to sign in like any other.
        let mut people = restricted("jf.int.test", true);
        people.access.always_sign_in = true;
        let answer = guard(&mut request(), Some(&si), &people, granted, &ids()).await;
        assert_eq!(answer.expect_err("asked").status(), StatusCode::FOUND, "off to sign in");
        let mut req = request();
        let token = crate::sign_in::tests::token("jf.int.test", 60, &["family"]);
        req.headers_mut().insert("cookie", HeaderValue::from_str(&format!("__Host-wireserve-session={token}")).unwrap());
        assert!(guard(&mut req, Some(&si), &people, granted, &ids()).await.is_ok());
        assert_eq!(req.headers()["x-auth-user"], "anna");

        // And with no sign-in offered for it, nobody gets in at all.
        let mut closed = restricted("jf.int.test", false);
        closed.access.always_sign_in = true;
        let answer = guard(&mut request(), Some(&si), &closed, granted, &ids()).await;
        assert_eq!(answer.expect_err("refused").status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn only_a_socket_passed_to_this_very_process_is_taken() {
        assert_eq!(listen_fd(42, Some("42"), Some("1"), 0), Some(3));
        assert_eq!(listen_fd(42, Some("41"), Some("1"), 0), None, "meant for another process");
        assert_eq!(listen_fd(42, Some("42"), Some("0"), 0), None);
        assert_eq!(listen_fd(42, None, Some("1"), 0), None);
        assert_eq!(listen_fd(42, Some("42"), None, 0), None);
        assert_eq!(listen_fd(42, Some("x"), Some("1"), 0), None);
        // The plain-HTTP socket is the second (PLAN.md #328).
        assert_eq!(listen_fd(42, Some("42"), Some("2"), 1), Some(4));
        assert_eq!(listen_fd(42, Some("42"), Some("1"), 1), None, "a socket unit from before it");
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
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default(), cross_site: false, aliases: vec![] };
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
        assert!(for_this_service(&req("/", Some("jellyfin.int.test")), &[fqdn]));
        assert!(for_this_service(&req("/", Some("Jellyfin.INT.test:443")), &[fqdn]));
        assert!(for_this_service(&req("/", Some("jellyfin.int.test.")), &[fqdn]));
        assert!(for_this_service(&req("https://jellyfin.int.test/x", None), &[fqdn]), "HTTP/2's authority");
        assert!(!for_this_service(&req("/", Some("grafana.int.test")), &[fqdn]));
        assert!(!for_this_service(&req("/", Some("jellyfin.int.test.evil")), &[fqdn]));
        assert!(!for_this_service(&req("/", None), &[fqdn]), "no name at all");
        assert!(
            !for_this_service(&req("https://jellyfin.int.test/", Some("grafana.int.test")), &[fqdn]),
            "authority and Host disagreeing"
        );
        assert!(!for_this_service(&req("https://grafana.int.test/", Some("jellyfin.int.test")), &[fqdn]));
    }

    #[test]
    fn what_a_backend_might_believe_about_who_or_where_never_arrives_from_a_client() {
        let spoof = [
            "x-forwarded-uri", "x-forwarded-user", "x-forwarded-email", "x-forwarded-port", "x-forwarded-prefix",
            "x-original-url", "x-original-uri", "x-original-host", "x-rewrite-url", "remote-user", "remote-groups",
            "x-remote-user", "x-auth-request-user", "x-auth-request-email", "x-webauth-user", "x-authentik-username",
            "x-authelia-username", "true-client-ip", "cf-connecting-ip", "x-client-ip", "x-cluster-client-ip",
            "x-url-scheme", "front-end-https", "x-corp-user",
        ];
        let mut h = HeaderMap::new();
        for name in spoof {
            h.insert(axum::http::HeaderName::from_static(name), HeaderValue::from_static("admin"));
        }
        for keep in ["authorization", "user-agent", "accept", "x-request-id", "x-custom"] {
            h.insert(axum::http::HeaderName::from_static(keep), HeaderValue::from_static("kept"));
        }
        // `x-corp-user` is the operator's own addition.
        prepare(&mut h, None, false, &["x-corp-user".to_string()]);
        let left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        assert!(left.iter().all(|k| !spoof.contains(k)), "still there: {left:?}");
        assert_eq!(h.len(), 5, "everything else is untouched: {left:?}");

        // Without the operator's addition, that one passes.
        let mut h = HeaderMap::new();
        for name in ["x-corp-user", "x-forwarded-host", "x-forwarded-for", "x-forwarded-uri", "x-forwarded-method", "remote-user"] {
            h.insert(axum::http::HeaderName::from_static(name), HeaderValue::from_static("v"));
        }
        prepare(&mut h, None, false, &[]);
        let left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        assert_eq!(left, ["x-corp-user"]);
    }

    #[test]
    fn forged_headers_are_removed_and_the_caller_named() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        h.insert("forwarded", HeaderValue::from_static("for=1.2.3.4"));
        h.insert(NODE_HEADER, HeaderValue::from_static("admin-laptop"));
        h.insert("cookie", HeaderValue::from_static("a=b"));
        h.insert("x-forwarded-host", HeaderValue::from_static("jellyfin.int.test"));
        prepare(&mut h, Some("phone"), false, &[]);
        assert!(h.get("x-forwarded-host").is_none());
        assert!(h.get("x-forwarded-for").is_none() && h.get("forwarded").is_none());
        assert_eq!(h.get(NODE_HEADER).unwrap(), "phone");
        assert_eq!(h.get("cookie").unwrap(), "a=b");

        h.insert("x-forwarded-for", HeaderValue::from_static("10.9.0.3"));
        prepare(&mut h, None, false, &[]);
        assert!(h.get("x-forwarded-for").is_none(), "a client's is removed");
        assert!(h.get(NODE_HEADER).is_none(), "an unknown caller is named by nobody");
    }

    #[test]
    fn an_underscore_spelling_never_arrives_and_connection_names_nothing_added_later() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("x_auth_user", "admin"),
            ("remote_user", "admin"),
            ("x_forwarded_for", "10.0.0.1"),
            ("x_wireserve_node", "admin-laptop"),
            ("x_corp-user", "admin"),
            ("host", "svc.test"),
            ("x-nominated", "gone"),
            ("x-custom", "kept"),
        ] {
            h.insert(axum::http::HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        h.insert("connection", HeaderValue::from_static("keep-alive, X-Auth-User, x-wireserve-node, host, x-nominated, upgrade"));
        // The operator's addition, spelled with an underscore.
        prepare(&mut h, Some("phone"), false, &["x_corp_user".to_string()]);
        let mut left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["connection", "host", "x-custom", NODE_HEADER]);
        assert_eq!(h["connection"], "keep-alive, upgrade", "only the options stay");
        assert_eq!(h[NODE_HEADER], "phone", "named after `Connection` was dealt with");

        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("x-auth-user"));
        prepare(&mut h, None, false, &[]);
        assert!(h.get("connection").is_none(), "nothing left to say");
    }

    #[test]
    fn a_forwarding_node_may_name_its_client_and_nothing_more() {
        let sent = |h: &mut HeaderMap| {
            for (k, v) in [
                ("x-forwarded-for", "203.0.113.9"),
                ("x-forwarded-host", "files.example.com"),
                ("x-forwarded-proto", "http"),
                ("x-real-ip", "6.6.6.6"),
                ("remote-user", "admin"),
            ] {
                h.insert(axum::http::HeaderName::from_static(k), HeaderValue::from_static(v));
            }
        };
        let mut h = HeaderMap::new();
        sent(&mut h);
        prepare(&mut h, Some("edge"), true, &[]);
        let mut left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", NODE_HEADER]);
        assert_eq!(h["x-forwarded-proto"], "http");

        // Anyone else's go, and the operator's own list wins over the forwarding node.
        let mut h = HeaderMap::new();
        sent(&mut h);
        prepare(&mut h, Some("laptop"), false, &[]);
        assert!(h.get("x-forwarded-for").is_none() && h.get("x-forwarded-host").is_none() && h.get("x-forwarded-proto").is_none());
        let mut h = HeaderMap::new();
        sent(&mut h);
        prepare(&mut h, Some("edge"), true, &["X-Forwarded-Proto".to_string()]);
        assert!(h.get("x-forwarded-proto").is_none());
        let mut h = HeaderMap::new();
        sent(&mut h);
        prepare(&mut h, Some("edge"), true, &["x-forwarded-host".to_string()]);
        assert!(h.get("x-forwarded-host").is_none());
        assert_eq!(h["x-forwarded-for"], "203.0.113.9");
    }

    #[test]
    fn a_forwarding_node_vouches_only_for_the_client_it_saw() {
        let forwarded = |pairs: &[(&'static str, &'static str)]| {
            let mut h = HeaderMap::new();
            for (k, v) in pairs {
                h.append(axum::http::HeaderName::from_static(k), HeaderValue::from_static(v));
            }
            prepare(&mut h, Some("edge"), true, &[]);
            let get = |n: &str| h.get_all(n).iter().map(|v| v.to_str().unwrap().to_string()).collect::<Vec<_>>();
            (get("x-forwarded-for"), get("x-forwarded-host"), get("x-forwarded-proto"))
        };
        // A proxy that appends: the client's own claim goes, what the proxy saw stays.
        assert_eq!(forwarded(&[("x-forwarded-for", "1.2.3.4, 203.0.113.9")]).0, ["203.0.113.9"]);
        assert_eq!(forwarded(&[("x-forwarded-for", "1.2.3.4"), ("x-forwarded-for", " 2001:db8::7 ")]).0, ["2001:db8::7"]);
        for junk in ["", "unknown", "203.0.113.9:4444", "1.2.3.4, ", "<script>"] {
            assert!(forwarded(&[("x-forwarded-for", junk)]).0.is_empty(), "{junk:?}");
        }

        assert_eq!(forwarded(&[("x-forwarded-host", "files.example.com")]).1, ["files.example.com"]);
        assert_eq!(forwarded(&[("x-forwarded-host", "files.example.com:8443")]).1, ["files.example.com:8443"]);
        for junk in [
            "files.example.com, evil.example", "evil.example/path", "files.example.com:", "files.example.com:99999",
            "-bad.example", "a..b", "files.example.com.", "[::1]:443", "user@evil.example", "",
        ] {
            assert!(forwarded(&[("x-forwarded-host", junk)]).1.is_empty(), "{junk:?}");
        }
        assert!(forwarded(&[("x-forwarded-host", "a.example"), ("x-forwarded-host", "b.example")]).1.is_empty(), "two of them");

        assert_eq!(forwarded(&[("x-forwarded-proto", "https")]).2, ["https"]);
        assert_eq!(forwarded(&[("x-forwarded-proto", " HTTP ")]).2, ["http"]);
        for junk in ["", "ftp", "https, http", "wss", "https://", "httpsx"] {
            assert!(forwarded(&[("x-forwarded-proto", junk)]).2.is_empty(), "{junk:?}");
        }
        assert!(forwarded(&[("x-forwarded-proto", "https"), ("x-forwarded-proto", "http")]).2.is_empty(), "two of them");
    }

    #[tokio::test]
    async fn a_forwarding_nodes_client_reaches_the_backend_and_anyone_elses_claim_does_not() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|h: HeaderMap| async move {
                let get = |n: &str| h.get(n).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                format!(
                    "xff={} xfh={} xfp={} fwd={}",
                    get("x-forwarded-for"),
                    get("x-forwarded-host"),
                    get("x-forwarded-proto"),
                    get("forwarded")
                )
            });
            axum::serve(backend, app).await.unwrap();
        });
        let (port, client, shared) = in_front_of(upstream, quick());
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "edge".into() });
        let ask = || async {
            let mut c = tls(port, &client).await;
            c.write_all(
                b"GET / HTTP/1.1\r\nhost: svc.test\r\nx-forwarded-for: 203.0.113.9\r\nx-forwarded-host: files.example.com\r\n\
                  x-forwarded-proto: http\r\nforwarded: for=6.6.6.6\r\nconnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut answer = String::new();
            c.read_to_string(&mut answer).await.unwrap();
            answer
        };
        let answer = ask().await;
        assert!(
            answer.ends_with("xff=127.0.0.1 xfh=svc.test xfp=https fwd=for=127.0.0.1;host=\"svc.test\";proto=https"),
            "not yet a forwarding node: {answer}"
        );

        shared.forwarders.write().unwrap().push("Edge".into());
        let answer = ask().await;
        assert!(
            answer.ends_with(
                "xff=203.0.113.9, 127.0.0.1 xfh=files.example.com xfp=http \
                 fwd=for=203.0.113.9;host=\"files.example.com\";proto=http, for=127.0.0.1;host=\"svc.test\";proto=https"
            ),
            "{answer}"
        );

        // Port 80 (#334): the visitor came over HTTPS to the node's proxy,
        // which forwards over plain HTTP; the backend hears `https`.
        let own = Policy {
            fqdn: "svc.wg".into(),
            aliases: vec![],
            access: wireserve_types::ServiceAccess { open: true, ..Default::default() },
            cross_site: false,
        };
        let (port, shared) = http_in_front_of(upstream, own);
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "edge".into() });
        let request = "GET / HTTP/1.1\r\nhost: svc.wg\r\nx-forwarded-proto: https\r\nconnection: close\r\n\r\n";
        let answer = plain_http(port, request).await;
        assert!(answer.contains("xfp=http fwd=for=127.0.0.1;host=\"svc.wg\";proto=http"), "not yet a forwarding node: {answer}");
        shared.forwarders.write().unwrap().push("edge".into());
        let answer = plain_http(port, request).await;
        assert!(answer.ends_with("xfp=https fwd=proto=https, for=127.0.0.1;host=\"svc.wg\";proto=http"), "{answer}");
    }

    /// A backend that answers with every header it got, sorted, one a line.
    async fn header_echo() -> SocketAddr {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|h: HeaderMap| async move {
                let mut out: Vec<String> = h.iter().map(|(k, v)| format!("{k}={}", v.to_str().unwrap_or("?"))).collect();
                out.sort();
                format!("\n{}\n", out.join("\n"))
            });
            axum::serve(backend, app).await.unwrap();
        });
        upstream
    }

    #[tokio::test]
    async fn a_device_cannot_name_anyone_or_another_node() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (port, client, shared) = in_front_of(header_echo().await, quick());
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "phone".into() });
        let mut c = tls(port, &client).await;
        c.write_all(
            b"GET / HTTP/1.1\r\nhost: svc.test\r\nconnection: close, x-auth-user, x-auth-groups, x-wireserve-node\r\n\
              X_Auth_User: admin\r\nX_Auth_Email: boss@example.com\r\nX_Auth_Groups: admins\r\nRemote_User: admin\r\n\
              X_Forwarded_For: 10.0.0.1\r\nX_Wireserve_Node: admin-laptop\r\n\r\n",
        )
        .await
        .unwrap();
        let mut answer = String::new();
        c.read_to_string(&mut answer).await.unwrap();
        assert!(!answer.contains('_'), "no underscore spelling reaches the backend: {answer}");
        assert!(answer.contains("\nx-wireserve-node=phone\n"), "{answer}");
        assert!(!answer.contains("x-auth-"), "nobody is named: {answer}");
    }

    #[tokio::test]
    async fn the_backend_is_told_where_a_request_came_from_and_nothing_of_its_hop() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (port, client, _) = in_front_of(header_echo().await, quick());
        let mut c = tls(port, &client).await;
        c.write_all(
            b"GET /a/b?c=d HTTP/1.1\r\nhost: svc.test\r\nconnection: close, x-hop\r\nx-hop: 1\r\nkeep-alive: timeout=5\r\n\
              proxy-connection: keep-alive\r\nte: trailers\r\ntrailer: x-sum\r\nforwarded: for=10.0.0.1\r\n\
              x-forwarded-proto: http\r\nx-app: kept\r\n\r\n",
        )
        .await
        .unwrap();
        let mut answer = String::new();
        c.read_to_string(&mut answer).await.unwrap();
        for line in [
            "host=svc.test",
            "x-forwarded-for=127.0.0.1",
            "x-forwarded-host=svc.test",
            "x-forwarded-proto=https",
            "forwarded=for=127.0.0.1;host=\"svc.test\";proto=https",
            "te=trailers",
            "x-app=kept",
        ] {
            assert!(answer.contains(&format!("\n{line}\n")), "{line}: {answer}");
        }
        for gone in ["x-hop=", "keep-alive=", "proxy-connection=", "trailer=", "10.0.0.1", "proto=http\n"] {
            assert!(!answer.contains(gone), "{gone}: {answer}");
        }
    }

    #[tokio::test]
    async fn an_http2_request_reaches_the_backend_with_the_name_it_asked_for() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let key = rcgen::generate_simple_self_signed(vec!["svc.test".into()]).unwrap();
        let der = key.cert.der().clone();
        let private = rustls_pki_types::PrivateKeyDer::try_from(key.signing_key.serialize_der()).unwrap();
        let certs = Arc::new(Certs::default());
        certs.set("svc.test", Arc::new(CertifiedKey::new(vec![der.clone()], rustls::crypto::aws_lc_rs::sign::any_supported_type(&private).unwrap())));
        let listener = listener(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Shared::default();
        let upstream = header_echo().await;
        shared.routes.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(Route::new(upstream)));
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(open("svc.test")));
        spawn_with_limits(listener, server_config(certs), shared, quick());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let c = tls(port, &tokio_rustls::TlsConnector::from(Arc::new(config))).await;
        assert_eq!(c.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(c)).await.unwrap();
        tokio::spawn(conn);
        let req = Request::get("https://svc.test/x").body(Body::empty()).unwrap();
        let res = send.send_request(req).await.unwrap();
        assert_eq!(res.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(Body::new(res.into_body()), 1 << 16).await.unwrap();
        let answer = String::from_utf8_lossy(&body);
        assert!(answer.contains("\nhost=svc.test\n"), "{answer}");
        assert!(answer.contains("\nforwarded=for=127.0.0.1;host=\"svc.test\";proto=https\n"), "{answer}");
    }

    #[tokio::test]
    async fn the_client_hears_nothing_of_the_backends_hop() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = backend.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await.unwrap();
            s.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: x-hop\r\nx-hop: 1\r\nkeep-alive: timeout=5\r\n\
                  proxy-connection: keep-alive\r\nx-app: kept\r\n\r\nok",
            )
            .await
            .unwrap();
        });
        let (port, client, _) = in_front_of(upstream, quick());
        let mut c = tls(port, &client).await;
        c.write_all(b"GET / HTTP/1.1\r\nhost: svc.test\r\nconnection: close\r\n\r\n").await.unwrap();
        let mut answer = String::new();
        c.read_to_string(&mut answer).await.unwrap();
        let answer = answer.to_ascii_lowercase();
        assert!(answer.starts_with("http/1.1 200") && answer.contains("x-app: kept"), "{answer}");
        for gone in ["x-hop", "keep-alive", "proxy-connection"] {
            assert!(!answer.contains(gone), "{gone}: {answer}");
        }
    }

    /// A backend counting the connections it accepted: `/empty` is a 204,
    /// anything else answers with its method and how long its body was.
    async fn counting_backend(keep_alive: bool) -> (SocketAddr, Arc<AtomicUsize>) {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (s, _) = backend.accept().await.unwrap();
                count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(|req: Request<hyper::body::Incoming>| async move {
                        let method = req.method().clone();
                        let empty = req.uri().path() == "/empty";
                        let body = axum::body::to_bytes(Body::new(req.into_body()), 1 << 16).await.unwrap();
                        let res = if empty {
                            axum::response::Response::builder().status(204).body(Body::empty()).unwrap()
                        } else {
                            axum::response::Response::new(Body::from(format!("{method} {}", body.len())))
                        };
                        Ok::<_, std::convert::Infallible>(res)
                    });
                    let _ = hyper::server::conn::http1::Builder::new().keep_alive(keep_alive).serve_connection(TokioIo::new(s), svc).await;
                });
            }
        });
        (upstream, accepted)
    }

    /// One kept-open client connection to the terminator.
    async fn kept_open(port: u16, client: &tokio_rustls::TlsConnector) -> hyper::client::conn::http1::SendRequest<Body> {
        let (send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls(port, client).await)).await.unwrap();
        tokio::spawn(conn);
        send
    }

    async fn ask(send: &mut hyper::client::conn::http1::SendRequest<Body>, method: &str, path: &str, body: &'static str) -> (u16, String) {
        send.ready().await.unwrap();
        let req = Request::builder().method(method).uri(path).header("host", "svc.test").body(Body::from(body)).unwrap();
        let res = send.send_request(req).await.unwrap();
        let status = res.status().as_u16();
        let body = axum::body::to_bytes(Body::new(res.into_body()), 1 << 16).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn requests_one_after_another_share_one_backend_connection() {
        let (upstream, accepted) = counting_backend(true).await;
        let (port, client, _) = in_front_of(upstream, quick());
        let mut send = kept_open(port, &client).await;
        assert_eq!(ask(&mut send, "GET", "/", "").await, (200, "GET 0".into()));
        assert_eq!(ask(&mut send, "POST", "/", "hello").await, (200, "POST 5".into()));
        assert_eq!(ask(&mut send, "GET", "/empty", "").await, (204, String::new()), "nothing to read");
        assert_eq!(ask(&mut send, "HEAD", "/", "").await.0, 200);
        // Another client's connection takes the same one, now idle.
        let mut other = kept_open(port, &client).await;
        assert_eq!(ask(&mut other, "GET", "/", "").await, (200, "GET 0".into()));
        assert_eq!(accepted.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_backend_closing_every_connection_gets_a_new_one_each_time() {
        let (upstream, accepted) = counting_backend(false).await;
        let (port, client, _) = in_front_of(upstream, quick());
        let mut send = kept_open(port, &client).await;
        for _ in 0..3 {
            assert_eq!(ask(&mut send, "GET", "/", "").await, (200, "GET 0".into()));
        }
        assert_eq!(accepted.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn a_connection_the_backend_closed_while_idle_is_not_used_again() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Keeps the connection open after answering, as if for more, then
        // closes it a moment later — as a backend's idle timeout does.
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = backend.accept().await.unwrap();
                count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await.unwrap();
                    s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok").await.unwrap();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                });
            }
        });
        let (port, client, _) = in_front_of(upstream, quick());
        let mut send = kept_open(port, &client).await;
        assert_eq!(ask(&mut send, "GET", "/", "").await, (200, "ok".into()));
        tokio::time::sleep(Duration::from_millis(200)).await;
        // A request sent on the dead connection would wait forever.
        let again = tokio::time::timeout(Duration::from_secs(3), ask(&mut send, "GET", "/", "")).await.expect("answered");
        assert_eq!(again, (200, "ok".into()));
        assert_eq!(accepted.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn an_unreachable_backend_is_a_bad_gateway() {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let (port, client, _) = in_front_of(unused, quick());
        let mut send = kept_open(port, &client).await;
        assert_eq!(ask(&mut send, "GET", "/", "").await.0, 502);
    }

    /// How a backend saw one request: what framed it, and what it read.
    #[derive(Debug, Clone, PartialEq)]
    struct Seen {
        method: String,
        path: String,
        content_length: Option<String>,
        transfer_encoding: Option<String>,
        body: Result<usize, String>,
    }

    /// A body sent a piece at a time, `pause` apart.
    struct Trickle {
        left: usize,
        pause: Duration,
        sleep: Pin<Box<tokio::time::Sleep>>,
    }

    impl hyper::body::Body for Trickle {
        type Data = axum::body::Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            if self.left == 0 {
                return Poll::Ready(None);
            }
            std::task::ready!(self.sleep.as_mut().poll(cx));
            self.left -= 1;
            let next = tokio::time::Instant::now() + self.pause;
            self.sleep.as_mut().reset(next);
            Poll::Ready(Some(Ok(hyper::body::Frame::data(axum::body::Bytes::from(vec![b'x'; 16 * 1024])))))
        }
    }

    /// A backend that records every request as it saw it, and counts the
    /// connections it accepted and those that have closed. It answers
    /// `<method> <path> <body length>`; `/big` is a slow 1 MiB answer.
    struct Recording {
        addr: SocketAddr,
        seen: Arc<std::sync::Mutex<Vec<Seen>>>,
        accepted: Arc<AtomicUsize>,
        closed: Arc<AtomicUsize>,
    }

    async fn recording_backend() -> Recording {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rec = Recording {
            addr: backend.local_addr().unwrap(),
            seen: Arc::default(),
            accepted: Arc::default(),
            closed: Arc::default(),
        };
        let (seen, accepted, closed) = (Arc::clone(&rec.seen), Arc::clone(&rec.accepted), Arc::clone(&rec.closed));
        tokio::spawn(async move {
            loop {
                let (s, _) = backend.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let (seen, closed) = (Arc::clone(&seen), Arc::clone(&closed));
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        let seen = Arc::clone(&seen);
                        async move {
                            let header = |n: &str| req.headers().get(n).map(|v| v.to_str().unwrap_or("?").to_owned());
                            let (method, path) = (req.method().to_string(), req.uri().path().to_owned());
                            let (content_length, transfer_encoding) = (header("content-length"), header("transfer-encoding"));
                            let body = axum::body::to_bytes(Body::new(req.into_body()), 1 << 20).await.map(|b| b.len()).map_err(|e| e.to_string());
                            seen.lock().unwrap().push(Seen { method: method.clone(), path: path.clone(), content_length, transfer_encoding, body: body.clone() });
                            let res = if path == "/big" {
                                Body::new(Trickle { left: 64, pause: Duration::from_millis(20), sleep: Box::pin(tokio::time::sleep(Duration::ZERO)) })
                            } else {
                                Body::from(format!("{method} {path} {}", body.unwrap_or(0)))
                            };
                            Ok::<_, std::convert::Infallible>(axum::response::Response::new(res))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
                    closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        rec
    }

    /// Waits up to two seconds for `cond`.
    async fn eventually(cond: impl Fn() -> bool) -> bool {
        let end = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < end {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    /// Everything the terminator says on `s` until it closes, at most five
    /// seconds.
    async fn read_all<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> String {
        use tokio::io::AsyncReadExt;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn a_client_gone_mid_answer_leaves_its_backend_connection_unused() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rec = recording_backend().await;
        let (port, client, _) = in_front_of(rec.addr, quick());
        let mut c = tls(port, &client).await;
        c.write_all(b"GET /big HTTP/1.1\r\nhost: svc.test\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 4096];
        let n = c.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
        drop(c);
        assert!(eventually(|| rec.closed.load(Ordering::SeqCst) == 1).await, "the half-read answer's connection is closed");
        let mut send = kept_open(port, &client).await;
        assert_eq!(ask(&mut send, "GET", "/after", "").await, (200, "GET /after 0".into()));
        assert_eq!(rec.accepted.load(Ordering::SeqCst), 2, "never the one cut short");
    }

    #[tokio::test]
    async fn an_http2_stream_reset_mid_answer_leaves_its_backend_connection_unused() {
        let rec = recording_backend().await;
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let key = rcgen::generate_simple_self_signed(vec!["svc.test".into()]).unwrap();
        let der = key.cert.der().clone();
        let private = rustls_pki_types::PrivateKeyDer::try_from(key.signing_key.serialize_der()).unwrap();
        let certs = Arc::new(Certs::default());
        certs.set("svc.test", Arc::new(CertifiedKey::new(vec![der.clone()], rustls::crypto::aws_lc_rs::sign::any_supported_type(&private).unwrap())));
        let listener = listener(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Shared::default();
        shared.routes.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(Route::new(rec.addr)));
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(open("svc.test")));
        spawn_with_limits(listener, server_config(certs), shared, quick());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let c = tls(port, &tokio_rustls::TlsConnector::from(Arc::new(config))).await;
        let (mut send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(c)).await.unwrap();
        tokio::spawn(conn);

        let res = send.send_request(Request::get("https://svc.test/big").body(Body::empty()).unwrap()).await.unwrap();
        let mut body = res.into_body();
        let first = std::future::poll_fn(|cx| hyper::body::Body::poll_frame(Pin::new(&mut body), cx)).await;
        assert!(matches!(first, Some(Ok(_))), "the answer began");
        drop(body); // RST_STREAM; the client's connection stays open.
        assert!(eventually(|| rec.closed.load(Ordering::SeqCst) == 1).await, "the half-read answer's connection is closed");

        let res = send.send_request(Request::get("https://svc.test/after").body(Body::empty()).unwrap()).await.unwrap();
        let body = axum::body::to_bytes(Body::new(res.into_body()), 1 << 16).await.unwrap();
        assert_eq!(&body[..], b"GET /after 0");
        assert_eq!(rec.accepted.load(Ordering::SeqCst), 2, "never the one cut short");
    }

    #[tokio::test]
    async fn a_client_gone_mid_request_body_leaves_its_backend_connection_unused() {
        use tokio::io::AsyncWriteExt;
        let rec = recording_backend().await;
        let (port, client, _) = in_front_of(rec.addr, quick());
        let mut c = tls(port, &client).await;
        c.write_all(b"POST /cut HTTP/1.1\r\nhost: svc.test\r\ncontent-length: 100000\r\n\r\n0123456789").await.unwrap();
        assert!(eventually(|| rec.accepted.load(Ordering::SeqCst) == 1).await, "the request reached the backend");
        drop(c);
        assert!(eventually(|| rec.closed.load(Ordering::SeqCst) == 1).await, "the half-sent request's connection is closed");
        let mut send = kept_open(port, &client).await;
        assert_eq!(ask(&mut send, "GET", "/after", "").await, (200, "GET /after 0".into()));
        assert_eq!(rec.accepted.load(Ordering::SeqCst), 2);
        let seen = rec.seen.lock().unwrap().clone();
        assert!(seen.iter().any(|s| s.path == "/cut" && s.body.is_err()), "the backend saw the body end early: {seen:?}");
    }

    #[tokio::test]
    async fn a_chunked_request_body_arrives_whole_and_the_connection_goes_on() {
        use tokio::io::AsyncWriteExt;
        let rec = recording_backend().await;
        let (port, client, _) = in_front_of(rec.addr, quick());
        let mut c = tls(port, &client).await;
        c.write_all(
            b"POST /chunked HTTP/1.1\r\nhost: svc.test\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n\
              GET /next HTTP/1.1\r\nhost: svc.test\r\nconnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let answer = read_all(&mut c).await;
        let (first, second) = (answer.find("POST /chunked 11"), answer.find("GET /next 0"));
        assert!(first.is_some() && second.is_some() && first < second, "both answered, in order: {answer}");
        assert_eq!(rec.accepted.load(Ordering::SeqCst), 1);
        for s in rec.seen.lock().unwrap().iter() {
            assert!(!(s.content_length.is_some() && s.transfer_encoding.is_some()), "one framing only: {s:?}");
        }
    }

    #[tokio::test]
    async fn a_client_that_expects_100_continue_is_told_to_go_on() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rec = recording_backend().await;
        let (port, client, _) = in_front_of(rec.addr, quick());
        let mut c = tls(port, &client).await;
        c.write_all(b"POST /expect HTTP/1.1\r\nhost: svc.test\r\nexpect: 100-continue\r\ncontent-length: 5\r\nconnection: close\r\n\r\n").await.unwrap();
        // curl waits a second for this before it sends the body anyway.
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_millis(900), c.read(&mut buf)).await.expect("100 Continue within a second").unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 100 Continue"), "{}", String::from_utf8_lossy(&buf[..n]));
        c.write_all(b"hello").await.unwrap();
        let answer = read_all(&mut c).await;
        assert!(answer.contains("POST /expect 5"), "{answer}");
    }

    #[tokio::test]
    async fn an_answer_before_the_body_is_read_does_not_desynchronise_the_backend_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // A backend that refuses `/early` from its headers alone, then reads
        // the body it was sent and goes on — as a correct one does without
        // closing — and answers anything else with its path.
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = backend.accept().await.unwrap();
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    loop {
                        let end = loop {
                            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break i + 4;
                            }
                            let mut chunk = [0u8; 4096];
                            match s.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        };
                        let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
                        let line = head.lines().next().unwrap_or_default().to_owned();
                        log.lock().unwrap().push(line.clone());
                        let length: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        buf.drain(..end);
                        let path = line.split(' ').nth(1).unwrap_or("?").to_owned();
                        if path == "/early" {
                            let _ = s.write_all(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 4\r\n\r\nnope").await;
                        }
                        while buf.len() < length {
                            let mut chunk = [0u8; 16384];
                            match s.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        }
                        buf.drain(..length);
                        if path != "/early" {
                            let body = format!("ok {path}");
                            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes()).await;
                        }
                    }
                });
            }
        });
        let (port, client, _) = in_front_of(upstream, quick());
        let mut send = kept_open(port, &client).await;
        static BIG: [u8; 200_000] = [b'y'; 200_000];
        send.ready().await.unwrap();
        let req = Request::post("/early").header("host", "svc.test").body(Body::from(&BIG[..])).unwrap();
        let res = send.send_request(req).await.unwrap();
        assert_eq!(res.status().as_u16(), 413);
        let _ = axum::body::to_bytes(Body::new(res.into_body()), 1 << 16).await;
        let mut other = kept_open(port, &client).await;
        for path in ["/a", "/b", "/c"] {
            let (status, body) = tokio::time::timeout(Duration::from_secs(3), ask(&mut other, "GET", path, "")).await.expect("answered");
            assert_eq!((status, body), (200, format!("ok {path}")));
        }
        let lines = requests.lock().unwrap().clone();
        assert!(lines.iter().all(|l| l.starts_with("post /early ") || l.starts_with("get /")), "only requests the clients sent: {lines:?}");
    }

    #[tokio::test]
    async fn an_answer_that_ends_when_its_connection_closes_arrives_whole() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = backend.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = s.read(&mut buf).await;
                    // No length and no chunks: the answer is all there is until the close.
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\n").await;
                    for part in ["all of it, ", "until ", "the close"] {
                        let _ = s.write_all(part.as_bytes()).await;
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                });
            }
        });
        let (port, client, _) = in_front_of(upstream, quick());
        let mut send = kept_open(port, &client).await;
        for _ in 0..2 {
            assert_eq!(ask(&mut send, "GET", "/", "").await, (200, "all of it, until the close".into()));
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 2, "a connection that ended its answer by closing is not used again");
    }

    #[tokio::test]
    async fn requests_framed_two_ways_never_reach_the_backend_as_something_else() {
        use tokio::io::AsyncWriteExt;
        let rec = recording_backend().await;
        let (port, client, _) = in_front_of(rec.addr, quick());

        // Both lengths: `Transfer-Encoding` wins (RFC 9112 §6.3), or the
        // request is refused; either way the backend sees one framing.
        let mut c = tls(port, &client).await;
        c.write_all(
            b"POST /both HTTP/1.1\r\nhost: svc.test\r\ncontent-length: 4\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n\
              GET /second HTTP/1.1\r\nhost: svc.test\r\nconnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let answer = read_all(&mut c).await;
        let seen = rec.seen.lock().unwrap().clone();
        for s in &seen {
            assert!(!(s.content_length.is_some() && s.transfer_encoding.is_some()), "one framing only: {s:?}");
            assert!(matches!(s.path.as_str(), "/both" | "/second"), "nothing the client did not ask: {seen:?}");
            assert_eq!(s.body, Ok(0), "{seen:?}");
        }
        assert!(answer.matches("HTTP/1.1 ").count() >= seen.len(), "an answer per request that went on: {answer}");

        // Lengths that disagree, or an encoding that does not end in
        // `chunked`: refused, and nothing reaches the backend.
        let before = rec.seen.lock().unwrap().len();
        for head in [
            "POST /dup HTTP/1.1\r\nhost: svc.test\r\ncontent-length: 4\r\ncontent-length: 40\r\nconnection: close\r\n\r\nabcd",
            "POST /gzip HTTP/1.1\r\nhost: svc.test\r\ntransfer-encoding: gzip\r\nconnection: close\r\n\r\nabcd",
            "POST /space HTTP/1.1\r\nhost: svc.test\r\ntransfer-encoding : chunked\r\ncontent-length: 4\r\nconnection: close\r\n\r\nabcd",
        ] {
            let mut c = tls(port, &client).await;
            c.write_all(head.as_bytes()).await.unwrap();
            let answer = read_all(&mut c).await;
            let status = answer.get(9..12).unwrap_or("");
            assert!(answer.is_empty() || status.starts_with('4') || status.starts_with('5'), "refused: {head:?} -> {answer}");
        }
        assert_eq!(rec.seen.lock().unwrap().len(), before, "none reached the backend: {:?}", rec.seen.lock().unwrap());
    }

    #[tokio::test]
    async fn pipelined_requests_are_answered_in_order() {
        use tokio::io::AsyncWriteExt;
        let rec = recording_backend().await;
        let (port, client, _) = in_front_of(rec.addr, quick());
        let mut c = tls(port, &client).await;
        c.write_all(
            b"GET /one HTTP/1.1\r\nhost: svc.test\r\n\r\nPOST /two HTTP/1.1\r\nhost: svc.test\r\ncontent-length: 3\r\n\r\nabc\
              GET /three HTTP/1.1\r\nhost: svc.test\r\nconnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let answer = read_all(&mut c).await;
        let at = |s: &str| answer.find(s).unwrap_or_else(|| panic!("{s}: {answer}"));
        assert!(at("GET /one 0") < at("POST /two 3") && at("POST /two 3") < at("GET /three 0"), "{answer}");
    }

    #[tokio::test]
    async fn cookies_sent_one_per_header_reach_the_backend_as_one() {
        let mut req = request();
        req.headers_mut().remove("cookie");
        for crumb in ["theme=dark", "__Host-wireserve-session=s3cret", "auth_tokens=abc"] {
            req.headers_mut().append("cookie", HeaderValue::from_static(crumb));
        }
        prepare(req.headers_mut(), None, false, &[]);
        let cookies: Vec<_> = req.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies, ["theme=dark; __Host-wireserve-session=s3cret; auth_tokens=abc"]);

        // And the sign-in's cookie still comes out of the joined header.
        assert!(guard(&mut req, None, &open("observe.int.test"), None, &ids()).await.is_ok());
        let cookies: Vec<_> = req.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies, ["theme=dark; auth_tokens=abc"]);
    }

    // ---- connection limits ----

    /// A terminator for `svc.test` on 127.0.0.1 with these limits, in front
    /// of a backend that answers `/` at once, `/slow` after 1.5s, and `/drip`
    /// a chunk every 200ms for 1.5s. Returns its port and a TLS connector.
    async fn limited(limits: Limits) -> (u16, tokio_rustls::TlsConnector) {
        let (port, client, _) = limited_shared(limits).await;
        (port, client)
    }

    async fn limited_shared(limits: Limits) -> (u16, tokio_rustls::TlsConnector, Shared) {
        use std::convert::Infallible;

        struct Drip {
            left: u8,
            sleep: Pin<Box<tokio::time::Sleep>>,
        }
        impl hyper::body::Body for Drip {
            type Data = axum::body::Bytes;
            type Error = Infallible;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
                if self.left == 0 {
                    return Poll::Ready(None);
                }
                if self.sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.left -= 1;
                let next = tokio::time::Instant::now() + Duration::from_millis(200);
                self.sleep.as_mut().reset(next);
                Poll::Ready(Some(Ok(hyper::body::Frame::data(axum::body::Bytes::from_static(b"x")))))
            }
        }

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new()
                .route("/slow", axum::routing::get(|| async {
                    tokio::time::sleep(Duration::from_millis(1500)).await;
                    "slow done"
                }))
                .route("/drip", axum::routing::get(|| async {
                    Body::new(Drip { left: 8, sleep: Box::pin(tokio::time::sleep(Duration::from_millis(200))) })
                }))
                .fallback(|| async { "ok" });
            axum::serve(backend, app).await.unwrap();
        });
        in_front_of(upstream, limits)
    }

    /// A terminator for `svc.test` on 127.0.0.1 with these limits, in front
    /// of `upstream`.
    fn in_front_of(upstream: SocketAddr, limits: Limits) -> (u16, tokio_rustls::TlsConnector, Shared) {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
        spawn_with_limits(listener, server_config(certs), shared.clone(), limits);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let client = tokio_rustls::TlsConnector::from(Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()));
        (port, client, shared)
    }

    /// The plain-HTTP listener (PLAN.md #328) for `svc.wg` on 127.0.0.1, in
    /// front of `upstream`: its port, and what it reads.
    fn http_in_front_of(upstream: SocketAddr, policy: Policy) -> (u16, Shared) {
        let listener = listener(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Shared::default();
        shared.http_routes.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(Route::new(upstream)));
        shared.http_policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(policy));
        spawn_http_with_limits(listener, shared.clone(), quick());
        (port, shared)
    }

    /// One plain-HTTP request, written as given; the whole answer.
    async fn plain_http(port: u16, request: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        c.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        let _ = c.read_to_string(&mut answer).await;
        answer
    }

    #[tokio::test]
    async fn a_forwarding_node_may_name_the_public_name_as_host() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let echo = header_echo().await;
        let own = Policy {
            fqdn: "svc.wg".into(),
            aliases: vec![],
            access: wireserve_types::ServiceAccess { open: true, ..Default::default() },
            cross_site: false,
        };
        let (port, shared) = http_in_front_of(echo, own);
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "edge".into() });
        let get = |extra: &str| format!("GET / HTTP/1.1\r\nhost: files.example.com\r\nconnection: close\r\n{extra}\r\n");

        let answer = plain_http(port, &get("")).await;
        assert!(answer.starts_with("HTTP/1.1 421"), "not yet a forwarding node: {answer}");
        shared.forwarders.write().unwrap().push("edge".into());

        // Caddy's `reverse_proxy http://svc.wg` as it comes, `Host` the
        // public name: the backend sees what `header_up Host` would give it.
        let answer = plain_http(port, &get("")).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.contains("\nhost=svc.wg\n"), "{answer}");
        assert!(answer.contains("\nx-forwarded-host=files.example.com\n"), "{answer}");
        // The node's own wins, and is checked as ever.
        let answer = plain_http(port, &get("x-forwarded-host: www.example.com\r\n")).await;
        assert!(answer.contains("\nhost=svc.wg\n") && answer.contains("\nx-forwarded-host=www.example.com\n"), "{answer}");
        let answer = plain_http(port, &get("x-forwarded-host: a.example, b.example\r\n")).await;
        assert!(answer.contains("\nx-forwarded-host=svc.wg\n"), "{answer}");
        // A port, as `Host` may carry; a public name that isn't one is not kept.
        let answer = plain_http(port, "GET / HTTP/1.1\r\nhost: files.example.com:8080\r\nconnection: close\r\n\r\n").await;
        assert!(answer.contains("\nx-forwarded-host=files.example.com:8080\n"), "{answer}");
        let answer = plain_http(port, "GET / HTTP/1.1\r\nhost: files_example.com\r\nconnection: close\r\n\r\n").await;
        assert!(answer.contains("\nhost=svc.wg\n") && answer.contains("\nx-forwarded-host=svc.wg\n"), "{answer}");
        // Its pages are the service's own; another site's still are not.
        let post = |origin: &str| {
            format!(
                "POST / HTTP/1.1\r\nhost: files.example.com\r\nx-forwarded-proto: https\r\norigin: {origin}\r\n\
                 content-length: 0\r\nconnection: close\r\n\r\n"
            )
        };
        assert!(plain_http(port, &post("https://files.example.com")).await.starts_with("HTTP/1.1 200"));
        assert!(plain_http(port, &post("https://evil.example")).await.starts_with("HTTP/1.1 403"));
        // Anyone else is refused, as before.
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "phone".into() });
        assert!(plain_http(port, &get("")).await.starts_with("HTTP/1.1 421"));

        // And over TLS, absolute form naming the public name too.
        let (port, client, shared) = in_front_of(echo, quick());
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "edge".into() });
        shared.forwarders.write().unwrap().push("edge".into());
        let mut c = tls(port, &client).await;
        c.write_all(b"GET https://files.example.com/x HTTP/1.1\r\nhost: files.example.com\r\nconnection: close\r\n\r\n").await.unwrap();
        let mut answer = String::new();
        c.read_to_string(&mut answer).await.unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.contains("\nhost=svc.test\n") && answer.contains("\nx-forwarded-host=files.example.com\n"), "{answer}");
    }

    #[tokio::test]
    async fn port_80_answers_only_its_own_names_and_pages_and_never_signs_anyone_in() {
        let own = Policy {
            fqdn: "svc.wg".into(),
            aliases: vec!["127.0.0.1".into()],
            access: wireserve_types::ServiceAccess { open: true, ..Default::default() },
            cross_site: false,
        };
        let (port, shared) = http_in_front_of(header_echo().await, own);
        let get = |host: &str, extra: &str| format!("GET / HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n{extra}\r\n");

        let answer = plain_http(port, &get("svc.wg", "x-auth-user: mallory\r\nx-forwarded-for: 10.0.0.1\r\n")).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.contains("\nx-forwarded-for=127.0.0.1\n"), "the caller, not what it claimed: {answer}");
        assert!(!answer.contains("mallory") && !answer.contains("10.0.0.1"), "{answer}");
        // A backend told https would send cookies and links no browser
        // keeps over plain HTTP.
        assert!(answer.contains("\nx-forwarded-proto=http\n"), "{answer}");
        assert!(answer.contains("\nforwarded=for=127.0.0.1;host=\"svc.wg\";proto=http\n"), "{answer}");
        assert!(plain_http(port, &get("127.0.0.1", "")).await.starts_with("HTTP/1.1 200"), "its address, typed as it is");

        // DNS rebinding: someone's name pointed at the address.
        let answer = plain_http(port, &get("evil.example", "")).await;
        assert!(answer.starts_with("HTTP/1.1 421"), "{answer}");
        assert!(!answer.contains("host=evil.example"), "no backend saw it: {answer}");

        // A page on another site may not act here; the service's own may.
        let post = |origin: &str, site: &str| {
            format!("POST / HTTP/1.1\r\nhost: svc.wg\r\norigin: {origin}\r\nsec-fetch-site: {site}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        };
        assert!(plain_http(port, &post("https://evil.example", "cross-site")).await.starts_with("HTTP/1.1 403"));
        assert!(plain_http(port, &post("http://svc.wg", "same-origin")).await.starts_with("HTTP/1.1 200"));
        let older = "POST / HTTP/1.1\r\nhost: svc.wg\r\norigin: https://svc.wg\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
        assert!(plain_http(port, older).await.starts_with("HTTP/1.1 403"), "its https origin is another site's to its http");

        // Restricted: the grants decide, and there is no sign-in to try.
        let restricted = Policy {
            fqdn: "svc.wg".into(),
            access: wireserve_types::ServiceAccess {
                sources: vec!["10.9.0.2".parse().unwrap()],
                sign_in_groups: vec!["family".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        shared.http_policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(restricted));
        let answer = plain_http(port, &get("svc.wg", "")).await;
        assert!(answer.starts_with("HTTP/1.1 403"), "not sent to sign in: {answer}");

        // Not answered on port 80, closed unanswered.
        shared.unroute_http(Ipv4Addr::LOCALHOST);
        assert!(plain_http(port, &get("svc.wg", "")).await.is_empty());
    }

    fn quick() -> Limits {
        Limits {
            handshake: Duration::from_millis(300),
            first_request: Duration::from_millis(400),
            idle: Duration::from_millis(500),
            header_read: Duration::from_millis(300),
            max_total: 100,
            max_per_source: 100,
            max_per_forwarder: 100,
            max_upgrades_per_forwarded_client: 100,
            recheck: Duration::from_millis(300),
        }
    }

    type Tls = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

    async fn tls(port: u16, client: &tokio_rustls::TlsConnector) -> Tls {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.connect(rustls_pki_types::ServerName::try_from("svc.test").unwrap(), tcp).await.unwrap()
    }

    /// Whether the server closes the connection within `within`.
    async fn closed_within<S: tokio::io::AsyncRead + Unpin>(s: &mut S, within: Duration) -> bool {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 256];
        let end = tokio::time::Instant::now() + within;
        loop {
            match tokio::time::timeout_at(end, s.read(&mut buf)).await {
                Err(_) => return false,
                Ok(Ok(0) | Err(_)) => return true,
                Ok(Ok(_)) => {}
            }
        }
    }

    async fn get<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        s.write_all(format!("GET {path} HTTP/1.1\r\nhost: svc.test\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        let end = tokio::time::Instant::now() + Duration::from_secs(5);
        // Until the answer's end: these bodies are short, and end in a fixed word or a chunk trailer.
        loop {
            let n = tokio::time::timeout_at(end, s.read(&mut buf)).await.expect("an answer").unwrap();
            out.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&out);
            if n == 0 || text.ends_with("ok") || text.ends_with("slow done") || text.ends_with("0\r\n\r\n") {
                return text.to_string();
            }
        }
    }

    #[tokio::test]
    async fn a_client_that_never_finishes_the_handshake_is_dropped() {
        use tokio::io::AsyncWriteExt;
        let (port, _) = limited(quick()).await;
        let mut silent = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut partial = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        partial.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        assert!(closed_within(&mut silent, Duration::from_secs(3)).await, "no bytes at all");
        assert!(closed_within(&mut partial, Duration::from_secs(3)).await, "a record header, then nothing");
    }

    #[tokio::test]
    async fn a_connection_that_never_sends_a_request_is_dropped() {
        let (port, client) = limited(quick()).await;
        let mut quiet = tls(port, &client).await;
        assert!(closed_within(&mut quiet, Duration::from_secs(3)).await);
    }

    #[tokio::test]
    async fn a_request_whose_headers_never_end_is_dropped_by_the_header_timeout() {
        use tokio::io::AsyncWriteExt;
        // The first-request deadline is out of the way: it is hyper's timer.
        let (port, client) = limited(Limits { first_request: Duration::from_secs(60), ..quick() }).await;
        let mut slow = tls(port, &client).await;
        slow.write_all(b"GET / HTTP/1.1\r\nhost: svc.test\r\nx-slow: 1\r\n").await.unwrap();
        assert!(closed_within(&mut slow, Duration::from_secs(3)).await);
    }

    #[tokio::test]
    async fn a_keep_alive_left_idle_is_dropped_and_a_busy_one_is_not() {
        let (port, client) = limited(quick()).await;
        let mut c = tls(port, &client).await;
        assert!(get(&mut c, "/").await.ends_with("ok"));
        assert!(closed_within(&mut c, Duration::from_secs(3)).await, "idle after its answer");

        // A backend slower than the idle limit is not idle: a request is being served.
        let mut c = tls(port, &client).await;
        assert!(get(&mut c, "/slow").await.ends_with("slow done"));
        // An answer still streaming, with pauses shorter than the limit, keeps going.
        let mut c = tls(port, &client).await;
        let answer = get(&mut c, "/drip").await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    }

    #[tokio::test]
    async fn one_source_cannot_hold_more_than_its_share_and_others_are_not_affected() {
        let (port, client) = limited(Limits { max_per_source: 2, first_request: Duration::from_secs(30), idle: Duration::from_secs(30), ..quick() }).await;
        let a = tls(port, &client).await;
        let _b = tls(port, &client).await;
        // The third from the same address is closed before any TLS.
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let refused = client.connect(rustls_pki_types::ServerName::try_from("svc.test").unwrap(), tcp).await;
        assert!(refused.is_err(), "over its share");
        // Giving one back makes room again.
        drop(a);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut again = tls(port, &client).await;
        assert!(get(&mut again, "/").await.ends_with("ok"));
    }

    #[tokio::test]
    async fn every_connection_together_is_capped_too() {
        let (port, client) = limited(Limits { max_total: 2, first_request: Duration::from_secs(30), idle: Duration::from_secs(30), ..quick() }).await;
        let _a = tls(port, &client).await;
        let _b = tls(port, &client).await;
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(client.connect(rustls_pki_types::ServerName::try_from("svc.test").unwrap(), tcp).await.is_err());
    }

    // ---- WebSockets (PLAN.md M42) ----

    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::{self, Message};

    /// A WebSocket backend: its first message tells what reached it — the
    /// forwarding headers, the caller's name and any cookie — and after that
    /// it echoes. It picks the `chat` subprotocol when offered and sets a
    /// cookie on its 101; `/deny` it refuses with a 403 of its own.
    async fn ws_backend() -> SocketAddr {
        use tungstenite::handshake::server::{ErrorResponse, Request as WsRequest, Response as WsResponse};
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = backend.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut seen = String::new();
                    #[allow(clippy::result_large_err)] // tungstenite's own type
                    let callback = |req: &WsRequest, mut resp: WsResponse| -> Result<WsResponse, ErrorResponse> {
                        if req.uri().path() == "/deny" {
                            let mut no = ErrorResponse::new(Some("not you".into()));
                            *no.status_mut() = tungstenite::http::StatusCode::FORBIDDEN;
                            return Err(no);
                        }
                        for name in ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-wireserve-node", "x_wireserve_node", "cookie", "host"] {
                            let values: Vec<&str> = req.headers().get_all(name).iter().map(|v| v.to_str().unwrap()).collect();
                            seen.push_str(&format!("{name}={}\n", values.join("|")));
                        }
                        let offered = req.headers().get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).unwrap_or("");
                        if offered.split(',').any(|p| p.trim() == "chat") {
                            resp.headers_mut().insert("sec-websocket-protocol", "chat".parse().unwrap());
                        }
                        resp.headers_mut().insert("set-cookie", "ws=1; Secure".parse().unwrap());
                        Ok(resp)
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(tcp, callback).await else {
                        return;
                    };
                    ws.send(Message::text(seen)).await.unwrap();
                    while let Some(Ok(msg)) = ws.next().await {
                        if (msg.is_text() || msg.is_binary()) && ws.send(msg).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        upstream
    }

    type Ws = tokio_tungstenite::WebSocketStream<Tls>;

    /// A WebSocket to `path` on the terminator, offering `chat`.
    async fn ws(port: u16, client: &tokio_rustls::TlsConnector, path: &str) -> Result<(Ws, tungstenite::handshake::client::Response), tungstenite::Error> {
        ws_for(port, client, path, "6.6.6.6").await
    }

    /// [`ws`], claiming to be for `xff`.
    async fn ws_for(
        port: u16,
        client: &tokio_rustls::TlsConnector,
        path: &str,
        xff: &str,
    ) -> Result<(Ws, tungstenite::handshake::client::Response), tungstenite::Error> {
        use tungstenite::client::IntoClientRequest;
        let mut req = format!("wss://svc.test{path}").into_client_request().unwrap();
        req.headers_mut().insert("sec-websocket-protocol", "chat, superchat".parse().unwrap());
        req.headers_mut().insert("x-forwarded-for", xff.parse().unwrap());
        req.headers_mut().insert("cookie", "theme=dark".parse().unwrap());
        tokio_tungstenite::client_async(req, tls(port, client).await).await
    }

    async fn next_text(ws: &mut Ws) -> String {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("a message").expect("open").expect("no error");
        msg.to_text().unwrap().to_owned()
    }

    /// Whether the server ends the WebSocket within `within`.
    async fn ws_closed_within(ws: &mut Ws, within: Duration) -> bool {
        let end = tokio::time::Instant::now() + within;
        loop {
            match tokio::time::timeout_at(end, ws.next()).await {
                Err(_) => return false,
                Ok(None | Some(Err(_)) | Some(Ok(Message::Close(_)))) => return true,
                Ok(Some(Ok(_))) => {}
            }
        }
    }

    #[tokio::test]
    async fn a_websocket_reaches_its_backend_with_the_backends_own_answer() {
        let (port, client, _) = in_front_of(ws_backend().await, quick());
        let (mut ws, answer) = ws(port, &client, "/socket?room=1").await.expect("upgraded");
        assert_eq!(answer.headers()["sec-websocket-protocol"], "chat", "the backend's choice");
        assert_eq!(answer.headers()["set-cookie"], "ws=1; Secure", "the backend's own 101 headers");
        let seen = next_text(&mut ws).await;
        assert!(seen.contains("x-forwarded-for=127.0.0.1\n"), "from the connection, not 6.6.6.6: {seen}");
        assert!(seen.contains("x-forwarded-proto=https\n"), "{seen}");
        assert!(seen.contains("x-forwarded-host=svc.test\n"), "{seen}");
        assert!(seen.contains("host=svc.test\n"), "{seen}");
        assert!(seen.contains("cookie=theme=dark\n"), "{seen}");

        ws.send(Message::text("hello")).await.unwrap();
        assert_eq!(next_text(&mut ws).await, "hello");
        ws.send(Message::binary(vec![0u8, 1, 2, 255])).await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(back.into_data().as_ref(), &[0u8, 1, 2, 255]);
    }

    #[tokio::test]
    async fn a_websocket_cannot_swap_the_callers_name_for_one_of_its_own() {
        use tungstenite::client::IntoClientRequest;
        let (port, client, shared) = in_front_of(ws_backend().await, quick());
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "phone".into() });
        let mut req = "wss://svc.test/socket".into_client_request().unwrap();
        req.headers_mut().insert("connection", "Upgrade, x-wireserve-node".parse().unwrap());
        req.headers_mut().insert("x_wireserve_node", "admin-laptop".parse().unwrap());
        let (mut ws, _) = tokio_tungstenite::client_async(req, tls(port, &client).await).await.expect("upgraded");
        let seen = next_text(&mut ws).await;
        assert!(seen.contains("x-wireserve-node=phone\n"), "{seen}");
        assert!(seen.contains("x_wireserve_node=\n"), "{seen}");
    }

    #[tokio::test]
    async fn a_backends_refusal_reaches_the_client_as_it_is() {
        let (port, client, _) = in_front_of(ws_backend().await, quick());
        match ws(port, &client, "/deny").await {
            Err(tungstenite::Error::Http(resp)) => {
                assert_eq!(resp.status(), 403, "not a 502");
                // Its body as sent; tungstenite reads it raw, chunked or not.
                let body = String::from_utf8_lossy(resp.body().as_deref().unwrap_or_default()).into_owned();
                assert!(body.contains("not you"), "{body}");
            }
            other => panic!("expected the backend's 403, got {:?}", other.map(|(_, r)| r.status())),
        }
    }

    #[tokio::test]
    async fn a_quiet_websocket_is_not_idle() {
        let (port, client, _) = in_front_of(ws_backend().await, quick());
        let (mut ws, _) = ws(port, &client, "/").await.expect("upgraded");
        next_text(&mut ws).await;
        // Three times the idle limit without a byte either way.
        assert!(!ws_closed_within(&mut ws, Duration::from_millis(1500)).await, "closed as idle");
        ws.send(Message::text("still here")).await.unwrap();
        assert_eq!(next_text(&mut ws).await, "still here");
    }

    #[tokio::test]
    async fn an_open_websocket_holds_its_place_in_the_limits() {
        let limits = Limits { max_per_source: 2, ..quick() };
        let (port, client, _) = in_front_of(ws_backend().await, limits);
        let (mut a, _) = ws(port, &client, "/").await.expect("upgraded");
        next_text(&mut a).await;
        let _b = tls(port, &client).await;
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let refused = client.connect(rustls_pki_types::ServerName::try_from("svc.test").unwrap(), tcp).await;
        assert!(refused.is_err(), "the WebSocket still counts once upgraded");
    }

    #[tokio::test]
    async fn a_device_not_let_in_never_reaches_a_websocket_backend() {
        let (port, client, shared) = in_front_of(ws_backend().await, quick());
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default(), cross_site: false, aliases: vec![] };
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(closed));
        match ws(port, &client, "/").await {
            Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 403),
            other => panic!("expected 403, got {:?}", other.map(|(_, r)| r.status())),
        }
    }

    #[tokio::test]
    async fn an_open_websocket_closes_once_its_caller_is_no_longer_let_in() {
        let granted = Policy {
            fqdn: "svc.test".into(),
            access: wireserve_types::ServiceAccess { sources: vec![Ipv4Addr::LOCALHOST], ..Default::default() },
            cross_site: false,
            aliases: vec![],
        };
        let (port, client, shared) = in_front_of(ws_backend().await, quick());
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(granted.clone()));
        let (mut ws1, _) = ws(port, &client, "/").await.expect("granted");
        next_text(&mut ws1).await;
        assert!(!ws_closed_within(&mut ws1, Duration::from_millis(800)).await, "still granted: stays open");

        // The grant taken away.
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default(), cross_site: false, aliases: vec![] };
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(closed));
        assert!(ws_closed_within(&mut ws1, Duration::from_secs(3)).await, "the grant is gone");

        // The service no longer served here.
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(granted));
        let (mut ws2, _) = ws(port, &client, "/").await.expect("granted again");
        next_text(&mut ws2).await;
        shared.unroute(Ipv4Addr::LOCALHOST);
        assert!(ws_closed_within(&mut ws2, Duration::from_secs(3)).await, "unrouted");
    }

    fn forwarding(shared: &Shared) {
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "edge".into() });
        shared.forwarders.write().unwrap().push("edge".into());
    }

    #[tokio::test]
    async fn a_forwarding_node_has_a_larger_share_of_the_connections() {
        let limits = Limits { max_per_source: 2, max_per_forwarder: 4, first_request: Duration::from_secs(30), idle: Duration::from_secs(30), ..quick() };
        let (port, client, shared) = limited_shared(limits).await;
        forwarding(&shared);
        let mut open = Vec::new();
        for _ in 0..4 {
            open.push(tls(port, &client).await);
        }
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let refused = client.connect(rustls_pki_types::ServerName::try_from("svc.test").unwrap(), tcp).await;
        assert!(refused.is_err(), "over even a forwarding node's share");
    }

    #[tokio::test]
    async fn one_client_of_a_forwarding_node_cannot_hold_all_its_websockets() {
        let limits = Limits { max_upgrades_per_forwarded_client: 2, ..quick() };
        let (port, client, shared) = in_front_of(ws_backend().await, limits);
        forwarding(&shared);
        let (mut a, _) = ws_for(port, &client, "/", "203.0.113.9").await.expect("first");
        next_text(&mut a).await;
        let (_b, _) = ws_for(port, &client, "/", "198.51.100.1, 203.0.113.9").await.expect("second, same client");
        match ws_for(port, &client, "/", "203.0.113.9").await {
            Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 429),
            other => panic!("expected 429, got {:?}", other.map(|(_, r)| r.status())),
        }
        let (mut other, _) = ws_for(port, &client, "/", "203.0.113.10").await.expect("another client is not affected");
        next_text(&mut other).await;

        // A socket closed gives its place back.
        a.close(None).await.unwrap();
        drop(a);
        tokio::time::sleep(Duration::from_millis(300)).await;
        ws_for(port, &client, "/", "203.0.113.9").await.expect("room again");

        // Without a forwarding node there is no such cap: its own share decides.
        shared.forwarders.write().unwrap().clear();
        let mut open = Vec::new();
        for _ in 0..3 {
            let (mut ws, _) = ws_for(port, &client, "/", "203.0.113.9").await.expect("an ordinary caller");
            next_text(&mut ws).await;
            open.push(ws);
        }
    }

    /// A backend that switches protocols for anything asking — and answers
    /// `101` with `accept` as its `Sec-WebSocket-Accept`, if given — and then
    /// echoes whatever request arrives inside the switched connection as its
    /// body. A plain request it answers `plain` with the request's head.
    async fn switching_backend(accept: Option<&'static str>) -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn head(tcp: &mut tokio::net::TcpStream) -> Option<String> {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tcp.read(&mut buf).await.ok()?;
                if n == 0 {
                    return None;
                }
                got.extend_from_slice(&buf[..n]);
            }
            Some(String::from_utf8_lossy(&got).to_lowercase())
        }
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut tcp, _) = backend.accept().await.unwrap();
                tokio::spawn(async move {
                    while let Some(first) = head(&mut tcp).await {
                        if !first.contains("\r\nupgrade:") {
                            let body = format!("plain\n{first}");
                            let answer = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}", body.len());
                            tcp.write_all(answer.as_bytes()).await.unwrap();
                            continue;
                        }
                        let accept = accept.map(|a| format!("sec-websocket-accept: {a}\r\n")).unwrap_or_default();
                        let switch = format!("HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: websocket\r\n{accept}\r\n");
                        tcp.write_all(switch.as_bytes()).await.unwrap();
                        if let Some(inside) = head(&mut tcp).await {
                            let body = format!("tunnelled\n{inside}");
                            let answer = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}", body.len());
                            let _ = tcp.write_all(answer.as_bytes()).await;
                        }
                        return;
                    }
                });
            }
        });
        upstream
    }

    /// Reads from `s` until `done` holds for what came, it closes, or 3s pass.
    async fn read_until<S: tokio::io::AsyncRead + Unpin>(s: &mut S, done: impl Fn(&str) -> bool) -> String {
        use tokio::io::AsyncReadExt;
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        let end = tokio::time::Instant::now() + Duration::from_secs(3);
        while let Ok(Ok(n)) = tokio::time::timeout_at(end, s.read(&mut buf)).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            if done(&String::from_utf8_lossy(&out)) {
                break;
            }
        }
        String::from_utf8_lossy(&out).to_string()
    }

    #[tokio::test]
    async fn another_upgrade_reaches_the_backend_as_a_plain_request_and_tunnels_nothing() {
        use tokio::io::AsyncWriteExt;
        let (port, client, _) = in_front_of(switching_backend(None).await, quick());
        let mut s = tls(port, &client).await;
        s.write_all(
            b"GET /public HTTP/1.1\r\nhost: svc.test\r\nupgrade: h2c\r\nconnection: Upgrade, HTTP2-Settings\r\n\
              http2-settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n",
        )
        .await
        .unwrap();
        let answer = read_until(&mut s, |t| t.contains("\r\n\r\n") && t.ends_with("\r\n\r\n") && t.contains("plain")).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "a plain answer, no switch: {answer}");
        assert!(answer.contains("plain\n"), "{answer}");
        assert!(!answer.contains("upgrade:") && !answer.contains("http2-settings"), "neither reached the backend: {answer}");

        // The connection is still an ordinary one: the next request is
        // looked at like any other, its forged identity removed.
        s.write_all(b"GET /admin HTTP/1.1\r\nhost: svc.test\r\nremote-user: admin\r\nx-wireserve-node: someone-else\r\n\r\n").await.unwrap();
        let next = read_until(&mut s, |t| t.contains("get /admin") && t.ends_with("\r\n\r\n")).await;
        assert!(next.contains("plain\n"), "{next}");
        assert!(!next.contains("tunnelled"), "{next}");
        assert!(!next.contains("remote-user: admin") && !next.contains("someone-else"), "{next}");
    }

    #[tokio::test]
    async fn a_switch_that_is_not_this_websockets_answer_is_refused() {
        use tokio::io::AsyncWriteExt;
        const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
        for accept in [None, Some("bm90IHRoZSByaWdodCBhbnN3ZXI=")] {
            let (port, client, _) = in_front_of(switching_backend(accept).await, quick());
            let mut s = tls(port, &client).await;
            let ask = format!(
                "GET / HTTP/1.1\r\nhost: svc.test\r\nupgrade: websocket\r\nconnection: upgrade\r\n\
                 sec-websocket-version: 13\r\nsec-websocket-key: {KEY}\r\n\r\n"
            );
            s.write_all(ask.as_bytes()).await.unwrap();
            let answer = read_until(&mut s, |t| t.contains("\r\n\r\n")).await;
            assert!(answer.starts_with("HTTP/1.1 502"), "{accept:?}: {answer}");
            s.write_all(b"GET /admin HTTP/1.1\r\nhost: svc.test\r\nremote-user: admin\r\n\r\n").await.unwrap();
            let next = read_until(&mut s, |t| t.contains("tunnelled") || t.ends_with("\r\n\r\n")).await;
            assert!(!next.contains("tunnelled"), "{accept:?}: nothing passes through: {next}");
        }
        // The right answer does switch.
        let (port, client, _) = in_front_of(switching_backend(Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")).await, quick());
        let mut s = tls(port, &client).await;
        let ask = format!(
            "GET / HTTP/1.1\r\nhost: svc.test\r\nupgrade: websocket\r\nconnection: upgrade\r\n\
             sec-websocket-version: 13\r\nsec-websocket-key: {KEY}\r\n\r\n"
        );
        s.write_all(ask.as_bytes()).await.unwrap();
        let answer = read_until(&mut s, |t| t.contains("\r\n\r\n")).await;
        assert!(answer.starts_with("HTTP/1.1 101"), "{answer}");
    }

    // ---- requests another site starts (PLAN.md #276) ----

    /// A WebSocket to `path`, as a browser on another site would open it:
    /// with `origin`, and `Sec-Fetch-Site` when given.
    async fn ws_from(
        port: u16,
        client: &tokio_rustls::TlsConnector,
        origin: &str,
        site: Option<&str>,
    ) -> Result<(Ws, tungstenite::handshake::client::Response), tungstenite::Error> {
        use tungstenite::client::IntoClientRequest;
        let mut req = "wss://svc.test/".into_client_request().unwrap();
        req.headers_mut().insert("origin", origin.parse().unwrap());
        if let Some(site) = site {
            req.headers_mut().insert("sec-fetch-site", site.parse().unwrap());
            req.headers_mut().insert("sec-fetch-mode", "websocket".parse().unwrap());
        }
        tokio_tungstenite::client_async(req, tls(port, client).await).await
    }

    #[tokio::test]
    async fn a_websocket_another_site_opens_is_refused_and_the_services_own_page_is_not() {
        let (port, client, _) = in_front_of(ws_backend().await, quick());
        for (origin, site) in [
            ("https://evil.example", Some("cross-site")),
            ("https://evil.svc.test", Some("same-site")),
            ("https://evil.example", None),
            ("null", None),
        ] {
            let refused = ws_from(port, &client, origin, site).await;
            assert!(refused.is_err(), "{origin} {site:?}: must not reach the backend");
        }
        let (mut own, _) = ws_from(port, &client, "https://svc.test", Some("same-origin")).await.expect("its own page");
        next_text(&mut own).await;
        let (mut program, _) = ws(port, &client, "/").await.expect("no browser headers at all: a program, not a page");
        next_text(&mut program).await;
    }

    #[test]
    fn what_another_site_may_start_here() {
        let req = |method: &str, headers: &[(&str, &str)]| {
            let mut b = Request::builder().method(method).uri("/");
            for (k, v) in headers {
                b = b.header(*k, *v);
            }
            b.body(()).unwrap()
        };
        let own = "svc.test";
        let refused = |method: &str, headers: &[(&str, &str)], ws: bool| started_elsewhere(&req(method, headers), &[own], "https", ws, false);
        // A form another site submits, or its fetch.
        assert!(refused("POST", &[("sec-fetch-site", "cross-site")], false));
        assert!(refused("DELETE", &[("sec-fetch-site", "same-site")], false), "another service on the domain is another site");
        assert!(refused("POST", &[("origin", "https://evil.example")], false), "an older browser: Origin alone");
        assert!(refused("POST", &[("origin", "null")], false));
        // A WebSocket from anywhere but the service's own pages.
        assert!(refused("GET", &[("sec-fetch-site", "cross-site")], true));
        assert!(refused("GET", &[("origin", "https://evil.svc.test")], true));
        assert!(refused("GET", &[("sec-fetch-site", "same-origin"), ("origin", "https://evil.example")], true), "the origin decides a socket");
        // Allowed: following a link, a look, the service's own pages, a program.
        assert!(!refused("GET", &[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "navigate")], false));
        assert!(!refused("HEAD", &[("sec-fetch-site", "cross-site")], false));
        assert!(!refused("OPTIONS", &[("sec-fetch-site", "cross-site")], false), "a preflight asks the backend, it changes nothing");
        assert!(!refused("POST", &[("sec-fetch-site", "same-origin"), ("origin", "https://svc.test")], false));
        assert!(!refused("POST", &[("sec-fetch-site", "none")], false), "typed in, or a bookmark");
        assert!(!refused("POST", &[("origin", "https://SVC.test")], false));
        assert!(!refused("POST", &[], false), "no browser headers: a program");
        assert!(!refused("GET", &[("sec-fetch-site", "same-origin"), ("origin", "https://svc.test")], true));
        assert!(!refused("GET", &[], true));

        // Through a forwarding node (PLAN.md M43): the public name it
        // vouched for is the service's own origin, and nobody else's is.
        let public = [("x-forwarded-host", "files.example.com"), ("origin", "https://files.example.com")];
        assert!(!started_elsewhere(&req("GET", &public), &[own], "https", true, true), "the public page's WebSocket");
        assert!(!started_elsewhere(&req("POST", &public), &[own], "https", false, true), "an older browser's POST from it");
        assert!(started_elsewhere(&req("GET", &public), &[own], "https", true, false), "only a forwarding node's word counts");
        let elsewhere = [("x-forwarded-host", "files.example.com"), ("origin", "https://evil.example")];
        assert!(started_elsewhere(&req("GET", &elsewhere), &[own], "https", true, true));
        assert!(started_elsewhere(&req("POST", &[("sec-fetch-site", "cross-site"), public[0], public[1]]), &[own], "https", false, true));
        // The scheme it vouched for is the public page's (#334); none means https.
        let plain = [("x-forwarded-host", "files.example.com"), ("x-forwarded-proto", "http"), ("origin", "http://files.example.com")];
        assert!(!started_elsewhere(&req("GET", &plain), &[own], "https", true, true));
        assert!(started_elsewhere(&req("GET", &plain[1..]), &[own], "https", true, true), "no public name");
        assert!(started_elsewhere(&req("GET", &[public[0], public[1], plain[1]]), &[own], "https", true, true), "another scheme");
        assert!(started_elsewhere(&req("GET", &[public[0], plain[2]]), &[own], "https", true, true), "http without its word");
    }

    /// Sends `method` to `/` with `headers` and a small body; the status line.
    async fn send<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, method: &str, headers: &[(&str, &str)]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut head = format!("{method} / HTTP/1.1\r\nhost: svc.test\r\ncontent-length: 2\r\n");
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\nhi");
        s.write_all(head.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.expect("an answer").unwrap();
        String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or_default().to_string()
    }

    #[tokio::test]
    async fn a_form_another_site_submits_never_reaches_the_backend() {
        let (port, client) = limited(quick()).await;
        let mut s = tls(port, &client).await;
        let cross = [("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "navigate"), ("origin", "https://evil.example")];
        assert!(send(&mut s, "POST", &cross).await.starts_with("HTTP/1.1 403"));
        assert!(send(&mut s, "POST", &[("sec-fetch-site", "same-site"), ("origin", "https://evil.svc.test")]).await.starts_with("HTTP/1.1 403"));
        assert!(send(&mut s, "GET", &cross[..2]).await.starts_with("HTTP/1.1 200"), "following a link from elsewhere");
        assert!(send(&mut s, "POST", &[("sec-fetch-site", "same-origin"), ("origin", "https://svc.test")]).await.starts_with("HTTP/1.1 200"));
        assert!(send(&mut s, "POST", &[]).await.starts_with("HTTP/1.1 200"), "a program");
    }

    #[tokio::test]
    async fn a_service_let_open_to_other_sites_takes_them() {
        let (port, client, shared) = limited_shared(quick()).await;
        let cross = [("sec-fetch-site", "cross-site"), ("origin", "https://idp.example")];
        let mut s = tls(port, &client).await;
        assert!(send(&mut s, "POST", &cross).await.starts_with("HTTP/1.1 403"));

        // WIRESERVE_CROSS_SITE_SERVICES names it.
        let mut opened = open("svc.test");
        opened.cross_site = true;
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(opened));
        assert!(send(&mut s, "POST", &cross).await.starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn the_sign_ins_own_pages_are_the_terminators_once_there_is_a_sign_in() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (port, client, shared) = limited_shared(quick()).await;
        let ask = || async {
            let mut c = tls(port, &client).await;
            c.write_all(b"GET /.wireserve/sign-out HTTP/1.1\r\nhost: svc.test\r\nconnection: close\r\n\r\n").await.unwrap();
            let mut answer = String::new();
            c.read_to_string(&mut answer).await.unwrap();
            answer
        };
        assert!(!ask().await.contains("<h1>Sign out</h1>"), "no sign-in: the backend's path like any other");
        let dir = tempfile::tempdir().unwrap();
        *shared.sign_in.write().unwrap() = Some(Arc::new(sign_in(dir.path())));
        let answer = ask().await;
        assert!(answer.starts_with("HTTP/1.1 200") && answer.contains("<h1>Sign out</h1>"), "{answer}");
    }

    #[tokio::test]
    async fn a_websocket_from_the_public_page_a_forwarding_node_serves_is_its_own() {
        // A Caddy on files.example.com proxying to svc.test (PLAN.md M43):
        // the browser's Origin is the public name.
        use tungstenite::client::IntoClientRequest;
        let (port, client, shared) = in_front_of(ws_backend().await, quick());
        let open = |origin: &'static str| {
            let mut req = "wss://svc.test/".into_client_request().unwrap();
            req.headers_mut().insert("origin", origin.parse().unwrap());
            req.headers_mut().insert("x-forwarded-host", "files.example.com".parse().unwrap());
            req
        };
        let refused = tokio_tungstenite::client_async(open("https://files.example.com"), tls(port, &client).await).await;
        assert!(refused.is_err(), "not a forwarding node: its X-Forwarded-Host is removed, and the origin is foreign");
        forwarding(&shared);
        let (mut ws, _) = tokio_tungstenite::client_async(open("https://files.example.com"), tls(port, &client).await)
            .await
            .expect("the public page's own WebSocket");
        next_text(&mut ws).await;
        let elsewhere = tokio_tungstenite::client_async(open("https://evil.example"), tls(port, &client).await).await;
        assert!(elsewhere.is_err(), "anyone else's page still is not");
    }
}
