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
    fn acquire(self: &Arc<Self>, source: IpAddr, limits: &Limits) -> Option<Permit> {
        let source = source.to_canonical();
        let mut counts = self.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mine = counts.1.get(&source).copied().unwrap_or(0);
        if counts.0 >= limits.max_total || mine >= limits.max_per_source {
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
    /// For the provider's verify path: the calling terminator's
    /// `X-Forwarded-For` (the device's address) goes to the provider as it
    /// is, without this node's own peer appended after it.
    verify_router: axum::Router,
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
        let verify_policy = proxy_policy.clone().with_x_forwarded_for(XForwardedFor::Preserve);
        let router = ReverseProxy::new("/", format!("http://{upstream}")).with_policy(proxy_policy).into();
        let verify_router = ReverseProxy::new("/", format!("http://{upstream}")).with_policy(verify_policy).into();
        Self { upstream, router, verify_router }
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
            let Some(permit) = conns.acquire(peer.ip(), &limits) else {
                if last_refusal_logged.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                    last_refusal_logged = Some(Instant::now());
                    tracing::warn!(peer = %peer.ip(), "too many open connections; closing new ones (logged once a minute)");
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
                    let forwarder = caller.as_ref().is_some_and(|c| read(&shared.forwarders).iter().any(|f| f.eq_ignore_ascii_case(&c.node)));
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
                    // The provider's own verify endpoint is asked by the other
                    // terminators, which name the service in X-Forwarded-Host;
                    // everywhere else a client's copy is removed.
                    let verify = sign_in.as_ref().is_some_and(|si| {
                        policy.as_ref().is_some_and(|p| p.fqdn.eq_ignore_ascii_case(&si.target.fqdn))
                            && req.uri().path() == si.target.verify_path
                    });
                    let router = if verify { route.verify_router.clone() } else { route.router.clone() };
                    let (upstream, recheck) = (route.upstream, limits.recheck);
                    let upgrade = !verify && crate::upgrade::wanted(&req);
                    prepare(req.headers_mut(), caller.as_ref().map(|c| c.node.as_str()), verify, forwarder, &strip);
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
                        let mut req = req.map(Body::new);
                        // As the client asked, for asking again while it is open.
                        let asked = upgrade.then(|| Arc::new(as_asked(&req)));
                        let owner = caller.and_then(|c| c.owner);
                        match guard(&mut req, sign_in.as_ref(), &policy, caller_addr, owner.as_ref(), &identity).await {
                            Some(denied) => Ok(denied),
                            None => match asked {
                                Some(asked) => {
                                    let again = move || {
                                        let (shared, asked) = (shared.clone(), Arc::clone(&asked));
                                        async move { still_admitted(&shared, vip, caller_addr, &asked).await }
                                    };
                                    let answer = crate::upgrade::proxy(req, upstream, peer, recheck, again).await;
                                    if answer.status() == axum::http::StatusCode::SWITCHING_PROTOCOLS {
                                        stats.upgraded.store(true, Ordering::Relaxed);
                                    }
                                    Ok(answer)
                                }
                                None => router.oneshot(req).await,
                            },
                        }
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
/// sign-in provider that cannot answer right now closes nothing — its
/// trouble is not the caller's; a refusal does.
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
    match guard(&mut req, sign_in.as_ref(), &policy, caller_addr, owner.as_ref(), &identity).await {
        None => true,
        Some(denied) => denied.status().is_server_error(),
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
        match si.check(&method, &uri, &headers, &policy.fqdn, identity, caller).await {
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
/// What only the calling terminator sets, and the provider's own reads.
const VERIFY_KEEPS: &[&str] = &["x-forwarded-host", "x-forwarded-for", "x-forwarded-uri", "x-forwarded-method"];
/// What a forwarding node — the operator's own reverse proxy — says about
/// its client (PLAN.md M43): where the client is, and the name it asked
/// for. Never who it is.
const FORWARDER_KEEPS: &[&str] = &["x-forwarded-for", "x-forwarded-host"];

fn is_untrusted(name: &str, verify: bool, forwarder: bool, extra: &[String]) -> bool {
    if name == NODE_HEADER {
        return true;
    }
    if verify && VERIFY_KEEPS.contains(&name) {
        return false;
    }
    if extra.iter().any(|e| e == name) {
        return true;
    }
    if forwarder && FORWARDER_KEEPS.contains(&name) {
        return false;
    }
    UNTRUSTED_EXACT.contains(&name) || UNTRUSTED_PREFIX.iter().any(|p| name.starts_with(p))
}

/// Strips every header a client could use to claim to be someone else, and
/// names the calling node. The forwarding headers are then set afresh by
/// the proxy from the connection itself — never appended to what the client
/// sent. `extra` is the operator's own list on top of the built-in one.
///
/// `verify`: this is the sign-in provider's own verify endpoint, where the
/// other terminators name the service they ask about in `X-Forwarded-Host`
/// (PLAN.md M34) and the device calling it in `X-Forwarded-For`, which a
/// provider may bind a session to. Both stay there. Anyone may send it, but asking `/verify`
/// directly only ever answers the asker — it opens no backend — so there is
/// nothing to borrow.
///
/// `forwarder`: the caller is a node named in `WIRESERVE_FORWARDING_NODES`
/// (PLAN.md M43), whose `X-Forwarded-For` and `X-Forwarded-Host` stay: the
/// proxy appends this connection's peer to the first and keeps the second,
/// so the backend sees the client the forwarding node saw, and the name
/// it was asked for. The operator's own `extra` list still removes them.
pub fn prepare(headers: &mut HeaderMap, caller: Option<&str>, verify: bool, forwarder: bool, extra: &[String]) {
    let doomed: Vec<axum::http::HeaderName> =
        headers.keys().filter(|n| is_untrusted(n.as_str(), verify, forwarder, extra)).cloned().collect();
    for name in doomed {
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

    #[tokio::test]
    async fn the_verify_path_passes_the_devices_address_on_alone_and_other_paths_get_the_peer() {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = backend.local_addr().unwrap();
        tokio::spawn(async move {
            let app = axum::Router::new().fallback(|h: HeaderMap| async move {
                h.get_all("x-forwarded-for").iter().map(|v| v.to_str().unwrap().to_string()).collect::<Vec<_>>().join("|")
            });
            axum::serve(backend, app).await.unwrap();
        });
        let route = Route::new(upstream);
        let ask = |router: axum::Router| async move {
            let mut req = Request::builder().uri("/verify").header("host", "auth.int.test").header("x-forwarded-for", "10.9.0.3").body(Body::empty()).unwrap();
            req.extensions_mut().insert(ConnectInfo("10.9.0.7:5555".parse::<SocketAddr>().unwrap()));
            let resp = router.oneshot(req).await.unwrap();
            String::from_utf8(axum::body::to_bytes(resp.into_body(), 4096).await.unwrap().to_vec()).unwrap()
        };
        assert_eq!(ask(route.verify_router.clone()).await, "10.9.0.3", "the device's address, not followed by the calling node's");
        assert_eq!(ask(route.router.clone()).await, "10.9.0.3, 10.9.0.7", "an ordinary request gets its peer appended");
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
        prepare(&mut h, None, false, false, &["x-corp-user".to_string()]);
        let left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        assert!(left.iter().all(|k| !spoof.contains(k)), "still there: {left:?}");
        assert_eq!(h.len(), 5, "everything else is untouched: {left:?}");

        // Without the operator's addition, that one passes; and the provider's verify path keeps
        // exactly what the calling terminator set on it.
        let mut h = HeaderMap::new();
        for name in ["x-corp-user", "x-forwarded-host", "x-forwarded-for", "x-forwarded-uri", "x-forwarded-method", "x-forwarded-proto", "x-forwarded-user", "remote-user"] {
            h.insert(axum::http::HeaderName::from_static(name), HeaderValue::from_static("v"));
        }
        prepare(&mut h, None, true, false, &[]);
        let mut left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["x-corp-user", "x-forwarded-for", "x-forwarded-host", "x-forwarded-method", "x-forwarded-uri"]);
    }

    #[test]
    fn forged_headers_are_removed_and_the_caller_named() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        h.insert("forwarded", HeaderValue::from_static("for=1.2.3.4"));
        h.insert(NODE_HEADER, HeaderValue::from_static("admin-laptop"));
        h.insert("cookie", HeaderValue::from_static("a=b"));
        h.insert("x-forwarded-host", HeaderValue::from_static("jellyfin.int.test"));
        prepare(&mut h, Some("phone"), false, false, &[]);
        assert!(h.get("x-forwarded-host").is_none());
        assert!(h.get("x-forwarded-for").is_none() && h.get("forwarded").is_none());
        assert_eq!(h.get(NODE_HEADER).unwrap(), "phone");
        assert_eq!(h.get("cookie").unwrap(), "a=b");

        h.insert("x-forwarded-host", HeaderValue::from_static("jellyfin.int.test"));
        prepare(&mut h, None, true, false, &[]);
        assert_eq!(h.get("x-forwarded-host").unwrap(), "jellyfin.int.test", "kept for the provider's verify endpoint");
        h.insert("x-forwarded-for", HeaderValue::from_static("10.9.0.3"));
        prepare(&mut h, None, true, false, &[]);
        assert_eq!(h.get("x-forwarded-for").unwrap(), "10.9.0.3", "the calling device, for the provider's verify endpoint");
        prepare(&mut h, None, false, false, &[]);
        assert!(h.get("x-forwarded-for").is_none(), "anywhere else a client's is removed");
        assert!(h.get(NODE_HEADER).is_none(), "an unknown caller is named by nobody");
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
        prepare(&mut h, Some("edge"), false, true, &[]);
        let mut left: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["x-forwarded-for", "x-forwarded-host", NODE_HEADER]);

        // Anyone else's go, and the operator's own list wins over the forwarding node.
        let mut h = HeaderMap::new();
        sent(&mut h);
        prepare(&mut h, Some("laptop"), false, false, &[]);
        assert!(h.get("x-forwarded-for").is_none() && h.get("x-forwarded-host").is_none());
        let mut h = HeaderMap::new();
        sent(&mut h);
        prepare(&mut h, Some("edge"), false, true, &["x-forwarded-host".to_string()]);
        assert!(h.get("x-forwarded-host").is_none());
        assert_eq!(h["x-forwarded-for"], "203.0.113.9");
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

    #[tokio::test]
    async fn cookies_sent_one_per_header_reach_the_backend_as_one() {
        let mut req = request();
        req.headers_mut().remove("cookie");
        for crumb in ["theme=dark", "authward_session=s3cret", "auth_tokens=abc"] {
            req.headers_mut().append("cookie", HeaderValue::from_static(crumb));
        }
        prepare(req.headers_mut(), None, false, false, &[]);
        let cookies: Vec<_> = req.headers().get_all("cookie").iter().collect();
        assert_eq!(cookies, ["theme=dark; authward_session=s3cret; auth_tokens=abc"]);

        // And the sign-in's cookie still comes out of the joined header.
        assert!(guard(&mut req, Some(&sign_in()), &open("observe.int.test"), None, None, &ids()).await.is_none());
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
                        for name in ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-wireserve-node", "cookie", "host"] {
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
        use tungstenite::client::IntoClientRequest;
        let mut req = format!("wss://svc.test{path}").into_client_request().unwrap();
        req.headers_mut().insert("sec-websocket-protocol", "chat, superchat".parse().unwrap());
        req.headers_mut().insert("x-forwarded-for", "6.6.6.6".parse().unwrap());
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
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default() };
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
        };
        let (port, client, shared) = in_front_of(ws_backend().await, quick());
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(granted.clone()));
        let (mut ws1, _) = ws(port, &client, "/").await.expect("granted");
        next_text(&mut ws1).await;
        assert!(!ws_closed_within(&mut ws1, Duration::from_millis(800)).await, "still granted: stays open");

        // The grant taken away.
        let closed = Policy { fqdn: "svc.test".into(), access: wireserve_types::ServiceAccess::default() };
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(closed));
        assert!(ws_closed_within(&mut ws1, Duration::from_secs(3)).await, "the grant is gone");

        // The service no longer served here.
        shared.policies.write().unwrap().insert(Ipv4Addr::LOCALHOST, Arc::new(granted));
        let (mut ws2, _) = ws(port, &client, "/").await.expect("granted again");
        next_text(&mut ws2).await;
        shared.unroute(Ipv4Addr::LOCALHOST);
        assert!(ws_closed_within(&mut ws2, Duration::from_secs(3)).await, "unrouted");
    }
}
