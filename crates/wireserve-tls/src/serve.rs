//! Serving the services (PLAN.md M33): one TLS listener on an unprivileged
//! port of every address (PLAN.md M35), to which the agent rewrites each
//! service address's 443; each connection goes to the service whose
//! address it arrived on, and each request to its backend in plain HTTP.
//!
//! The proxying itself is `axum-reverse-proxy` over hyper — hop-by-hop
//! headers, HTTP/2, trailers. What is ours is the edge of it — which
//! headers a backend may believe — and upgrades: a WebSocket goes to its
//! backend as bytes, through [`crate::upgrade`] (PLAN.md M42).

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Request};
use axum_reverse_proxy::{HostBehaviour, ProxyPolicy, ReverseProxy, XForwardedFor};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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

/// The sign-in (PLAN.md M48), shared by every listener and replaced when the
/// coordinator's settings change. `None`: there is none, and nobody gets in
/// by signing in.
pub type SharedSignIn = Arc<RwLock<Option<Arc<crate::sign_in::SignIn>>>>;

/// How one service treats its requests.
#[derive(Debug, Clone)]
pub struct Policy {
    /// The name this service is served under: the one its requests must
    /// name, and its sign-in cookies be made out to.
    pub fqdn: String,
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
    /// Known devices that connected since the last check-in (PLAN.md M38):
    /// what the agent tells the coordinator, which then names their owners
    /// to this node and nobody else's.
    pub seen: Arc<Mutex<std::collections::BTreeSet<Ipv4Addr>>>,
}

impl Shared {
    /// Takes the devices seen since the last call.
    pub fn take_seen(&self) -> Vec<Ipv4Addr> {
        std::mem::take(&mut *self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner)).into_iter().collect()
    }

    /// Records devices as seen, up to a cap: a mesh has far fewer devices
    /// than this.
    pub fn note_seen(&self, addrs: impl IntoIterator<Item = Ipv4Addr>) {
        let mut seen = self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        for a in addrs {
            if seen.len() >= wireserve_types::MAX_CALLERS_SEEN_PER_POLL {
                break;
            }
            seen.insert(a);
        }
    }

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
        Self { upstream, router }
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
/// revoked, reaches a keep-alive or HTTP/2 connection at its next request,
/// and an upgraded one — a WebSocket — within [`Limits::recheck`].
pub fn spawn(listener: TcpListener, tls: Arc<rustls::ServerConfig>, shared: Shared) -> JoinHandle<()> {
    spawn_with_limits(listener, tls, shared, Limits::default())
}

/// [`spawn`], with the connection limits given.
pub fn spawn_with_limits(listener: TcpListener, tls: Arc<rustls::ServerConfig>, shared: Shared, limits: Limits) -> JoinHandle<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
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
            let acceptor = acceptor.clone();
            let upgrade_slots = Arc::clone(&upgrade_slots);
            let shared = shared.clone();
            let limits = limits.clone();
            tokio::spawn(async move {
                let Ok(Ok(tls)) = tokio::time::timeout(limits.handshake, acceptor.accept(tcp)).await else {
                    return;
                };
                let stats = Arc::new(ConnStats::default());
                let watched = Watched::new(tls, Arc::clone(&stats), permit, &limits);
                let caller_addr = local_v4(peer.ip());
                let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                    let in_flight = InFlight::begin(&stats);
                    let stats = Arc::clone(&stats);
                    let policy = read(&shared.policies).get(&vip).cloned();
                    let caller = caller_addr.and_then(|a| read(&shared.callers).get(&a).cloned());
                    if let (Some(addr), Some(_)) = (caller_addr, &caller) {
                        shared.note_seen([addr]);
                    }
                    let sign_in = read(&shared.sign_in).clone();
                    let identity = read(&shared.identity).clone();
                    let strip = read(&shared.strip).clone();
                    let forwarder = shared.forwarding_node(peer.ip()).is_some();
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
                    let router = route.router.clone();
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
                    req.extensions_mut().insert(ConnectInfo(peer));
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
                        if !policy.cross_site && started_elsewhere(&req, &policy.fqdn, upgrade, forwarder) {
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
                        // A forwarding node speaks for someone else: its owner
                        // says nothing about who is calling (PLAN.md M43).
                        let owner = if forwarder { None } else { caller.and_then(|c| c.owner) };
                        let set_cookie = match guard(&mut req, sign_in.as_deref(), &policy, caller_addr, owner.as_ref(), &identity).await {
                            Err(denied) => return Ok(*denied),
                            Ok(set_cookie) => set_cookie,
                        };
                        let answer = match asked {
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
                                        async move { still_admitted(&shared, vip, caller_addr, &asked).await }
                                    };
                                    let answer = crate::upgrade::proxy(req, upstream, peer, recheck, again, slot).await;
                                    if answer.status() == axum::http::StatusCode::SWITCHING_PROTOCOLS {
                                        stats.upgraded.store(true, Ordering::Relaxed);
                                    }
                                    Ok(answer)
                                }
                                None => router.oneshot(req).await,
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
                let _ = builder.serve_connection_with_upgrades(TokioIo::new(watched), service).await;
            });
        }
    })
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
async fn still_admitted(shared: &Shared, vip: Ipv4Addr, caller_addr: Option<Ipv4Addr>, asked: &Request<()>) -> bool {
    if read(&shared.routes).get(&vip).is_none() {
        return false;
    }
    let Some(policy) = read(&shared.policies).get(&vip).cloned() else {
        return false;
    };
    if !for_this_service(asked, &policy.fqdn) {
        return false;
    }
    let owner = caller_addr.and_then(|a| read(&shared.callers).get(&a).cloned()).and_then(|c| c.owner);
    let sign_in = read(&shared.sign_in).clone();
    let identity = read(&shared.identity).clone();
    let mut req = as_asked(asked).map(|()| Body::empty());
    match guard(&mut req, sign_in.as_deref(), &policy, caller_addr, owner.as_ref(), &identity).await {
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

/// Who gets in (PLAN.md M36, M48): `Err` is the answer to send instead of
/// passing the request on; `Ok` may carry a renewed session's cookie for
/// the browser.
///
/// 1. Identity headers a client sent are removed, always, and so is the
///    sign-in's cookie: no backend needs it.
/// 2. An open service, or a caller whose node the grants name, goes on —
///    with its owner named, if it has one (PLAN.md M38).
/// 3. Anyone else, where the grants name groups a sign-in can prove, is
///    asked about: signed in with one of them, on — with who they are;
///    signed in without, 403; not signed in, sent to sign in.
/// 4. Anyone else is refused with 403.
async fn guard(
    req: &mut Request<Body>,
    sign_in: Option<&crate::sign_in::SignIn>,
    policy: &Policy,
    caller: Option<Ipv4Addr>,
    owner: Option<&wireserve_types::CallerIdentity>,
    identity: &wireserve_types::IdentityHeaders,
) -> Result<Option<HeaderValue>, Box<axum::response::Response>> {
    use axum::http::StatusCode;
    crate::sign_in::strip_identity(req.headers_mut(), identity);
    let access = &policy.access;
    let by_device = access.open || caller.is_some_and(|c| access.sources.contains(&c));
    let mut set_cookie = None;
    if by_device {
        if let Some(owner) = owner {
            name(req.headers_mut(), &owner.user, owner.email.as_deref(), &owner.groups, identity);
        }
    } else {
        if !access.sign_in {
            return Err(Box::new(crate::sign_in::plain(StatusCode::FORBIDDEN, "this device may not reach this service")));
        }
        let Some(si) = sign_in else {
            return Err(Box::new(crate::sign_in::plain(StatusCode::SERVICE_UNAVAILABLE, "this service's sign-in is not set up here yet")));
        };
        match si.check(req.method(), req.uri(), req.headers(), &policy.fqdn).await {
            crate::sign_in::Verdict::Allow { session, set_cookie: renewed } => {
                if !session.groups.iter().any(|g| access.sign_in_groups.contains(g)) {
                    return Err(Box::new(crate::sign_in::plain(StatusCode::FORBIDDEN, "signed in, but not allowed here")));
                }
                name(req.headers_mut(), &session.sub, session.email.as_deref(), &session.groups, identity);
                set_cookie = renewed;
            }
            crate::sign_in::Verdict::Deny(answer) => return Err(Box::new(answer)),
        }
    }
    crate::sign_in::strip_cookie(req.headers_mut(), wireserve_types::session::COOKIE);
    Ok(set_cookie)
}

/// Tells the backend who is calling — the device's owner, or whoever
/// signed in — in the identity headers.
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
/// removed separately, whatever their names, and set again only from the
/// sign-in or the device's owner.)
const UNTRUSTED_EXACT: &[&str] = &[
    "forwarded", "x-real-ip", "true-client-ip", "cf-connecting-ip", "x-client-ip", "x-cluster-client-ip",
    "x-url-scheme", "front-end-https", "x-rewrite-url", "x-http-host-override",
    "remote-user", "remote-email", "remote-groups", "remote-name",
];
/// The same, for families of names.
const UNTRUSTED_PREFIX: &[&str] = &["x-forwarded-", "x-original-", "x-remote-", "x-auth-request-", "x-webauth-", "x-authentik-", "x-authelia-"];
/// What a forwarding node — the operator's own reverse proxy — says about
/// its client (PLAN.md M43): where the client is, and the name it asked
/// for. Never who it is.
const FORWARDER_KEEPS: &[&str] = &["x-forwarded-for", "x-forwarded-host"];

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
/// that name's pages are the service's own too.
fn started_elsewhere<B>(req: &Request<B>, fqdn: &str, websocket: bool, forwarder: bool) -> bool {
    use axum::http::Method;
    let headers = req.headers();
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(|v| v.trim().to_ascii_lowercase());
    let public = header("x-forwarded-host").filter(|_| forwarder);
    let own_origin = |origin: &str| {
        origin
            .strip_prefix("https://")
            .is_some_and(|host| host.eq_ignore_ascii_case(fqdn) || public.as_deref().is_some_and(|p| host.eq_ignore_ascii_case(p)))
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
/// (PLAN.md M43), whose `X-Forwarded-For` and `X-Forwarded-Host` stay, cut
/// down to what the node itself can vouch for ([`vouched_for`]): the proxy
/// appends this connection's peer to the first and keeps the second, so the
/// backend sees the client the forwarding node saw, and the name it was
/// asked for. The operator's own `extra` list still removes them.
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
        Policy { fqdn: fqdn.into(), access: wireserve_types::ServiceAccess { open: true, ..Default::default() }, cross_site: false }
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
        }
    }

    fn ids() -> wireserve_types::IdentityHeaders {
        wireserve_types::IdentityHeaders::default()
    }

    fn request() -> Request<Body> {
        Request::builder()
            .header("cookie", "theme=dark; __Host-wireserve-session=s3cret")
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
        assert!(guard(&mut req, None, &restricted("jf.int.test", false), granted, None, &ids()).await.is_ok());
        assert!(req.headers().get("x-auth-user").is_none(), "a forged identity is removed for a device too");

        let answer = guard(&mut request(), None, &restricted("jf.int.test", false), other, None, &ids()).await;
        assert_eq!(answer.expect_err("refused").status(), StatusCode::FORBIDDEN, "no sign-in to try");
        let answer = guard(&mut request(), None, &restricted("jf.int.test", false), None, None, &ids()).await;
        assert_eq!(answer.expect_err("refused").status(), StatusCode::FORBIDDEN, "an unknown caller neither");

        let answer = guard(&mut request(), None, &restricted("jf.int.test", true), other, None, &ids()).await;
        assert_eq!(answer.expect_err("refused").status(), StatusCode::SERVICE_UNAVAILABLE, "no sign-in here yet");
    }

    #[tokio::test]
    async fn every_backend_loses_the_session_cookie_and_forged_identity() {
        let dir = tempfile::tempdir().unwrap();
        let si = sign_in(dir.path());
        for si in [Some(&si), None] {
            let mut req = request();
            assert!(guard(&mut req, si, &open("grafana.int.test"), None, None, &ids()).await.is_ok());
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
        assert_eq!(guard(&mut req, Some(&si), &restricted("jf.int.test", true), other, None, &ids()).await.ok(), Some(None));
        assert_eq!(req.headers()["x-auth-user"], "anna", "not mallory");
        assert_eq!(req.headers()["x-auth-email"], "anna@example.com");
        assert_eq!(req.headers()["x-auth-groups"], "family,admins");
        assert_eq!(req.headers()["cookie"], "theme=dark", "the session stays with the terminator");

        let answer = guard(&mut with(&token("jf.int.test", 60, &["admins"])), Some(&si), &restricted("jf.int.test", true), other, None, &ids()).await;
        assert_eq!(answer.expect_err("not granted").status(), StatusCode::FORBIDDEN);
        let answer = guard(&mut with(&token("vault.int.test", 60, &["family"])), Some(&si), &restricted("jf.int.test", true), other, None, &ids()).await;
        assert_eq!(answer.expect_err("another service's").status(), StatusCode::FOUND, "off to sign in");
        let answer = guard(&mut request(), Some(&si), &restricted("jf.int.test", false), other, None, &ids()).await;
        assert_eq!(answer.expect_err("no group to prove").status(), StatusCode::FORBIDDEN);

        // Past its time: renewed, and the browser told.
        let renewed = guard(&mut with(&token("jf.int.test", -1, &["family"])), Some(&si), &restricted("jf.int.test", true), other, None, &ids()).await;
        assert!(renewed.expect("renewed").is_some_and(|c| c.to_str().unwrap().starts_with("__Host-wireserve-session=wst1.")));
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
        assert!(guard(&mut req, None, &restricted("jf.int.test", false), granted, Some(&owner), &ids()).await.is_ok());
        assert_eq!(req.headers()["x-auth-user"], "sub-alice", "not mallory");
        assert_eq!(req.headers()["x-auth-email"], "alice@example.com");
        assert_eq!(req.headers()["x-auth-groups"], "family,admins");

        // A device the grants do not name gets no one's identity.
        let other = Some("10.9.0.3".parse().unwrap());
        let mut req = request();
        assert!(guard(&mut req, None, &restricted("jf.int.test", false), other, Some(&owner), &ids()).await.is_err());
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
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default(), cross_site: false };
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
        assert_eq!(left, ["x-forwarded-for", "x-forwarded-host", NODE_HEADER]);

        // Anyone else's go, and the operator's own list wins over the forwarding node.
        let mut h = HeaderMap::new();
        sent(&mut h);
        prepare(&mut h, Some("laptop"), false, &[]);
        assert!(h.get("x-forwarded-for").is_none() && h.get("x-forwarded-host").is_none());
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
            (get("x-forwarded-for"), get("x-forwarded-host"))
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
    }

    #[tokio::test]
    async fn a_forwarding_nodes_owner_is_never_named() {
        let owner = wireserve_types::CallerIdentity {
            addr: Ipv4Addr::LOCALHOST,
            user: "sub-tia".into(),
            email: Some("tia@example.com".into()),
            groups: vec!["admins".into()],
        };
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|h: HeaderMap| async move {
                format!("user={}", h.get("x-auth-user").map(|v| v.to_str().unwrap()).unwrap_or(""))
            });
            axum::serve(backend, app).await.unwrap();
        });
        let (port, client, shared) = in_front_of(upstream, quick());
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "edge".into(), owner: Some(owner) });
        let ask = || async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut c = tls(port, &client).await;
            c.write_all(b"GET / HTTP/1.1\r\nhost: svc.test\r\nconnection: close\r\n\r\n").await.unwrap();
            let mut answer = String::new();
            c.read_to_string(&mut answer).await.unwrap();
            answer
        };
        assert!(ask().await.ends_with("user=sub-tia"), "an ordinary node is named by its owner");
        shared.forwarders.write().unwrap().push("edge".into());
        let answer = ask().await;
        assert!(answer.ends_with("user="), "a forwarding node speaks for someone else: {answer}");
    }

    #[tokio::test]
    async fn a_forwarding_nodes_client_reaches_the_backend_and_anyone_elses_claim_does_not() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|h: HeaderMap| async move {
                let get = |n: &str| h.get(n).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                format!("xff={} xfh={}", get("x-forwarded-for"), get("x-forwarded-host"))
            });
            axum::serve(backend, app).await.unwrap();
        });
        let (port, client, shared) = in_front_of(upstream, quick());
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "edge".into(), owner: None });
        let ask = || async {
            let mut c = tls(port, &client).await;
            c.write_all(b"GET / HTTP/1.1\r\nhost: svc.test\r\nx-forwarded-for: 203.0.113.9\r\nx-forwarded-host: files.example.com\r\nconnection: close\r\n\r\n").await.unwrap();
            let mut answer = String::new();
            c.read_to_string(&mut answer).await.unwrap();
            answer
        };
        let answer = ask().await;
        assert!(answer.ends_with("xff=127.0.0.1 xfh=svc.test"), "not yet a forwarding node: {answer}");

        shared.forwarders.write().unwrap().push("Edge".into());
        let answer = ask().await;
        assert!(answer.ends_with("xff=203.0.113.9, 127.0.0.1 xfh=files.example.com"), "{answer}");
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
    async fn a_device_cannot_swap_its_owners_identity_for_one_of_its_own() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (port, client, shared) = in_front_of(header_echo().await, quick());
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo {
            node: "phone".into(),
            owner: Some(wireserve_types::CallerIdentity {
                addr: Ipv4Addr::LOCALHOST,
                user: "anna".into(),
                email: None,
                groups: vec!["family".into()],
            }),
        });
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
        for line in ["\nx-auth-user=anna\n", "\nx-auth-groups=family\n", "\nx-wireserve-node=phone\n"] {
            assert!(answer.contains(line), "{line:?} in {answer}");
        }
        assert!(!answer.contains("x-auth-email"), "anna has no email to name: {answer}");
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
        assert!(guard(&mut req, None, &open("observe.int.test"), None, None, &ids()).await.is_ok());
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

    #[tokio::test]
    async fn only_known_devices_that_connected_are_reported_as_seen() {
        let (port, client, shared) = limited_shared(quick()).await;
        // 127.0.0.1 is nobody the agent named: not a device to report.
        let mut c = tls(port, &client).await;
        assert!(get(&mut c, "/").await.ends_with("ok"));
        assert!(shared.take_seen().is_empty());

        shared.callers.write().unwrap().insert(
            Ipv4Addr::LOCALHOST,
            CallerInfo { node: "laptop".into(), owner: None },
        );
        let mut c = tls(port, &client).await;
        assert!(get(&mut c, "/").await.ends_with("ok"));
        assert_eq!(shared.take_seen(), vec![Ipv4Addr::LOCALHOST]);
        assert!(shared.take_seen().is_empty(), "taken once");

        shared.note_seen((0..=255u8).flat_map(|a| (0..=3u8).map(move |b| Ipv4Addr::new(10, 9, b, a))));
        assert_eq!(shared.take_seen().len(), wireserve_types::MAX_CALLERS_SEEN_PER_POLL, "capped");
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
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "phone".into(), owner: None });
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
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default(), cross_site: false };
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
        };
        let (port, client, shared) = in_front_of(ws_backend().await, quick());
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(granted.clone()));
        let (mut ws1, _) = ws(port, &client, "/").await.expect("granted");
        next_text(&mut ws1).await;
        assert!(!ws_closed_within(&mut ws1, Duration::from_millis(800)).await, "still granted: stays open");

        // The grant taken away.
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default(), cross_site: false };
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
        shared.callers.write().unwrap().insert(Ipv4Addr::LOCALHOST, CallerInfo { node: "edge".into(), owner: None });
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
        let refused = |method: &str, headers: &[(&str, &str)], ws: bool| started_elsewhere(&req(method, headers), own, ws, false);
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
        assert!(!started_elsewhere(&req("GET", &public), own, true, true), "the public page's WebSocket");
        assert!(!started_elsewhere(&req("POST", &public), own, false, true), "an older browser's POST from it");
        assert!(started_elsewhere(&req("GET", &public), own, true, false), "only a forwarding node's word counts");
        let elsewhere = [("x-forwarded-host", "files.example.com"), ("origin", "https://evil.example")];
        assert!(started_elsewhere(&req("GET", &elsewhere), own, true, true));
        assert!(started_elsewhere(&req("POST", &[("sec-fetch-site", "cross-site"), public[0], public[1]]), own, false, true));
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
