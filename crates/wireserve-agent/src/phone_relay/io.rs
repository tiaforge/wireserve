//! The sorter's thread (PLAN.md #338, #339, #341): the sockets the firewall
//! and the relayed nodes deliver to, and what the sorter's answers become.
//!
//! - The divert socket, transparent, gets what `phone-pre` diverts: a
//!   phone's packet as it was sent, its original destination (this host's
//!   address and WireGuard port) beside it.
//! - The mesh sockets, on this node's mesh address, are what relayed nodes
//!   see as the phone's address, and answer: a port of the pool for each
//!   address a phone sends from, and the main one for a phone that has
//!   none (`sorter`).
//! - A packet for a phone leaves a raw socket, from the address and port
//!   the phone dialled: the kernel's WireGuard holds that port, so no
//!   ordinary socket can send from it.
//! - A packet that is not a relayed session's goes back to the kernel from
//!   a transparent socket bound to the phone's own address, so WireGuard
//!   sees it come from the phone.
//!
//! One thread, blocking in `poll(2)` on all of them; it stops when told,
//! within [`TICK`].

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::ops::RangeInclusive;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::sorter::{Action, Sorter, Via};

/// How often the thread looks up from its sockets: to stop when told, and
/// to forget quiet sessions.
const TICK: Duration = Duration::from_millis(500);
/// How often quiet sessions are forgotten.
const EXPIRE_EVERY: Duration = Duration::from_secs(5);

/// What the sorter is told by each poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// This node's WireGuard listen port: only what was sent to it is
    /// taken from the divert socket.
    pub listen_port: u16,
    /// The divert socket's port, on every address.
    pub divert_port: u16,
    /// The main mesh socket: this node's mesh address and the port relayed
    /// nodes answer a phone that has no port of its own at.
    pub mesh: SocketAddrV4,
    /// The pool's ports, on the same address: none where they would not
    /// fit below 65536.
    pub pool: Option<RangeInclusive<u16>>,
    /// Each relayed node's mesh address and WireGuard port, and its public
    /// key.
    pub nodes: Vec<(SocketAddrV4, [u8; 32])>,
    /// The devices' public keys.
    pub devices: Vec<[u8; 32]>,
}

/// Where the firewall learns of the sessions to divert.
pub trait Divert: Send + Sync {
    /// Divert this node index from now on.
    fn add(&self, index: u32);
    /// Keep diverting only these.
    fn retain(&self, live: &[u32]);
}

impl Divert for crate::firewall::nftables::PhoneDivert {
    fn add(&self, index: u32) {
        Self::add(self, index);
    }

    fn retain(&self, live: &[u32]) {
        Self::retain(self, live);
    }
}

/// What a relay's sockets were opened for: a change reopens them.
type SocketsFor = (u16, u16, SocketAddrV4, Option<RangeInclusive<u16>>);

struct Running {
    sockets: SocketsFor,
    sorter: Arc<Mutex<Sorter>>,
    /// The pool's sockets, once open. A pool that could not be opened (its
    /// ports taken) leaves the relay working from the main socket alone,
    /// and is tried again on each poll.
    pool: Arc<OnceLock<Vec<UdpSocket>>>,
    /// Whether the sorter has the pool: once the firewall lets the nodes
    /// answer there. Never taken back while the relay runs.
    pool_in_use: bool,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The phone relay of one agent: stopped until a poll says this node
/// relays phones, and stopped again when it no longer does.
#[derive(Default)]
pub struct PhoneRelay {
    running: Mutex<Option<Running>>,
    tried: Mutex<Tried>,
}

/// Whether the relay could open what it needs, the last time it tried.
#[derive(Default)]
struct Tried {
    /// `None` before the first try.
    opened: Option<bool>,
    /// The divert port and mesh address last tried, once a poll named them.
    at: Option<(u16, SocketAddrV4)>,
}

impl PhoneRelay {
    /// Starts, updates or stops the sorter. A failure to open the sockets
    /// (a port another program holds) leaves it stopped, to be tried again
    /// on the next poll.
    pub fn configure(&self, config: Option<Config>, divert: &Arc<dyn Divert>) -> io::Result<()> {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let Some(config) = config else {
            if running.take().is_some() {
                tracing::info!("no longer relaying phones");
            }
            divert.retain(&[]);
            // Not asked to relay, and could not the last time: tried again
            // as that time, so the capability comes back once whatever held
            // a port lets go of it, or the raw socket is allowed.
            let mut tried = self.tried.lock().unwrap_or_else(|e| e.into_inner());
            if tried.opened == Some(false) {
                let opened = match tried.at {
                    Some((divert_port, mesh)) => Sockets::open(divert_port, mesh).map(drop),
                    None => Sockets::probe(),
                };
                tried.opened = Some(opened.is_ok());
            }
            return Ok(());
        };
        let sockets = (config.listen_port, config.divert_port, config.mesh, config.pool.clone());
        if let Some(r) = running.as_ref().filter(|r| r.sockets == sockets) {
            r.sorter.lock().unwrap_or_else(|e| e.into_inner()).set_peers(&config.nodes, &config.devices);
            if r.pool.get().is_none() {
                if let Some(ports) = &config.pool {
                    if let Ok(pool) = open_pool(*config.mesh.ip(), ports) {
                        tracing::info!(?ports, "the phone relay's port pool is open");
                        let _ = r.pool.set(pool);
                    }
                }
            }
            return Ok(());
        }
        // Closed before the new ones open: they may want the same ports.
        running.take();
        let opened = Sockets::open(config.divert_port, config.mesh);
        {
            let mut tried = self.tried.lock().unwrap_or_else(|e| e.into_inner());
            *tried = Tried { opened: Some(opened.is_ok()), at: Some((config.divert_port, config.mesh)) };
        }
        let io = opened?;
        // Without the pool the relay still works, from the main socket, as
        // relays did before there was one: a phone that moves is answered
        // there only after its next handshake.
        let pool = Arc::new(OnceLock::new());
        if let Some(ports) = &config.pool {
            match open_pool(*config.mesh.ip(), ports) {
                Ok(sockets) => {
                    let _ = pool.set(sockets);
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    ?ports,
                    "cannot open the phone relay's port pool; until it can, a phone that changes network is answered there only after its next handshake"
                ),
            }
        }
        // A new sorter: nothing of an earlier run's sessions or ports is
        // kept.
        let mut sorter = Sorter::default();
        sorter.set_peers(&config.nodes, &config.devices);
        let sorter = Arc::new(Mutex::new(sorter));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (sorter, stop, divert, pool) = (Arc::clone(&sorter), Arc::clone(&stop), Arc::clone(divert), Arc::clone(&pool));
            std::thread::Builder::new()
                .name("phone-relay".into())
                .spawn(move || run(&io, &pool, config.listen_port, &sorter, &stop, divert.as_ref()))
        };
        let thread = thread.inspect_err(|_| self.tried.lock().unwrap_or_else(|e| e.into_inner()).opened = Some(false))?;
        tracing::info!(divert_port = sockets.1, mesh = %sockets.2, pool = ?pool.get().and(sockets.3.clone()), "relaying phones on this node's WireGuard port");
        *running = Some(Running { sockets, sorter, pool, pool_in_use: false, stop, thread: Some(thread) });
        Ok(())
    }

    /// The pool's ports while they are open: what the firewall must let the
    /// relayed nodes answer at.
    #[must_use]
    pub fn pool(&self) -> Option<RangeInclusive<u16>> {
        let running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let r = running.as_ref()?;
        r.pool.get().and(r.sockets.3.clone())
    }

    /// The firewall now lets the relayed nodes answer at the pool's ports
    /// ([`PhoneRelay::pool`]), so the sorter may send from them. Until then
    /// a node's answer there would be dropped, and everything leaves from
    /// the main socket.
    pub fn pool_allowed(&self) {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let Some(r) = running.as_mut().filter(|r| !r.pool_in_use) else { return };
        if let Some(pool) = r.pool.get() {
            r.sorter.lock().unwrap_or_else(|e| e.into_inner()).set_pool(pool.len());
            r.pool_in_use = true;
        }
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Whether this agent can relay phones (PLAN.md M49): running, or its
    /// sockets opened the last time they were tried — at the first call, a
    /// raw socket and a transparent one opened and closed again, which a
    /// daemon without `CAP_NET_RAW` cannot do. What the coordinator is told,
    /// so it never sends phones to a carrier that would drop them.
    #[must_use]
    pub fn capable(&self) -> bool {
        if self.is_running() {
            return true;
        }
        let mut tried = self.tried.lock().unwrap_or_else(|e| e.into_inner());
        *tried.opened.get_or_insert_with(|| match Sockets::probe() {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, "cannot open the phone relay's raw and transparent sockets (CAP_NET_RAW?); not offering to relay phones");
                false
            }
        })
    }
}

struct Sockets {
    divert: OwnedFd,
    mesh: UdpSocket,
    raw: OwnedFd,
}

impl Sockets {
    fn open(divert_port: u16, mesh: SocketAddrV4) -> io::Result<Self> {
        let divert = udp_socket()?;
        set_int(&divert, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
        set_int(&divert, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1)?;
        bind(&divert, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, divert_port))?;
        let mesh = UdpSocket::bind(mesh)?;
        let raw = raw_socket()?;
        Ok(Self { divert, mesh, raw })
    }

    /// What [`Sockets::open`] needs of this daemon's privileges, before any
    /// poll has named the ports: a transparent socket and a raw one.
    fn probe() -> io::Result<()> {
        set_int(&udp_socket()?, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
        raw_socket().map(drop)
    }
}

/// A socket on `ip` at each of `ports`, or none: a pool with a gap would
/// not be the range the firewall lets through.
fn open_pool(ip: Ipv4Addr, ports: &RangeInclusive<u16>) -> io::Result<Vec<UdpSocket>> {
    ports.clone().map(|port| UdpSocket::bind(SocketAddrV4::new(ip, port))).collect()
}

fn raw_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the result is checked before use.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a socket this function just opened and owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn run(io: &Sockets, pool: &OnceLock<Vec<UdpSocket>>, listen_port: u16, sorter: &Mutex<Sorter>, stop: &AtomicBool, divert: &dyn Divert) {
    let mut buf = vec![0u8; 65536];
    let mut expired = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let pool = pool.get().map_or(&[][..], Vec::as_slice);
        let mut fds: Vec<libc::pollfd> = [io.divert.as_raw_fd(), io.mesh.as_raw_fd()]
            .into_iter()
            .chain(pool.iter().map(AsRawFd::as_raw_fd))
            .map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
            .collect();
        let count = libc::nfds_t::try_from(fds.len()).expect("a few dozen sockets");
        // SAFETY: `fds` is a valid array of `count` pollfds.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), count, i32::try_from(TICK.as_millis()).unwrap_or(500)) };
        let now = Instant::now();
        if ready > 0 && fds[0].revents & libc::POLLIN != 0 {
            match recv_diverted(&io.divert, &mut buf) {
                // Only what was sent to the WireGuard port: the socket is
                // bound on every address, and something sent to it directly
                // is no phone's.
                Ok((len, phone, local)) if local.port() == listen_port => {
                    let packet = &buf[..len];
                    let action = sorter.lock().unwrap_or_else(|e| e.into_inner()).from_phone(now, phone, local, packet);
                    carry_out(io, pool, action, packet, Some((phone, local)));
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, "phone relay: divert socket"),
            }
        }
        let mesh = std::iter::once((&io.mesh, Via::Main)).chain(pool.iter().enumerate().map(|(i, s)| (s, Via::Pool(i))));
        for ((socket, on), fd) in mesh.zip(&fds[1..]) {
            if ready <= 0 || fd.revents & libc::POLLIN == 0 {
                continue;
            }
            match socket.recv_from(&mut buf) {
                Ok((len, std::net::SocketAddr::V4(node))) => {
                    let packet = &buf[..len];
                    let (action, new) = {
                        let mut sorter = sorter.lock().unwrap_or_else(|e| e.into_inner());
                        let action = sorter.from_node(now, node, on, packet);
                        (action, sorter.take_new_indexes())
                    };
                    // A node index learned from this packet is diverted
                    // before the packet goes on: the phone's answer to it
                    // would otherwise beat its rule to the kernel's own
                    // WireGuard, which drops it. Outside the sorter's lock:
                    // this takes the firewall's.
                    for index in new {
                        divert.add(index);
                    }
                    carry_out(io, pool, action, packet, None);
                }
                Ok(_) => {}
                Err(e) => tracing::debug!(error = %e, ?on, "phone relay: mesh socket"),
            }
        }
        let (new, live) = {
            let mut sorter = sorter.lock().unwrap_or_else(|e| e.into_inner());
            let new = sorter.take_new_indexes();
            let live = (now.duration_since(expired) >= EXPIRE_EVERY).then(|| {
                sorter.expire(now);
                sorter.node_indexes()
            });
            (new, live)
        };
        // Outside the sorter's lock: these take the firewall's.
        for index in new {
            divert.add(index);
        }
        if let Some(live) = live {
            divert.retain(&live);
            expired = now;
        }
    }
}

fn carry_out(io: &Sockets, pool: &[UdpSocket], action: Action, packet: &[u8], from_phone: Option<(SocketAddrV4, SocketAddrV4)>) {
    let sent = match action {
        Action::ToNode(node, via) => {
            let socket = match via {
                Via::Pool(i) => pool.get(i).unwrap_or(&io.mesh),
                Via::Main => &io.mesh,
            };
            socket.send_to(packet, node).map(drop)
        }
        Action::ToPhone { phone, from } => send_raw(&io.raw, from, phone, packet),
        Action::ToKernel => match from_phone {
            Some((phone, local)) => reinject(phone, local, packet),
            None => Ok(()),
        },
        Action::Drop => Ok(()),
    };
    if let Err(e) = sent {
        tracing::debug!(error = %e, ?action, "phone relay: could not send");
    }
}

pub(crate) fn udp_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the result is checked before use.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a socket this function just opened and owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub(crate) fn set_int(fd: &OwnedFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // SAFETY: `value` outlives the call, and its size is passed with it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            libc::socklen_t::try_from(size_of::<libc::c_int>()).expect("an int's size fits"),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn sockaddr(addr: SocketAddrV4) -> libc::sockaddr_in {
    // SAFETY: an all-zero sockaddr_in is valid; the fields that matter are
    // set below.
    let mut sa: libc::sockaddr_in = unsafe { zeroed() };
    sa.sin_family = libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET fits");
    sa.sin_port = addr.port().to_be();
    sa.sin_addr = libc::in_addr { s_addr: u32::from(*addr.ip()).to_be() };
    sa
}

const SOCKADDR_IN_LEN: libc::socklen_t = size_of::<libc::sockaddr_in>() as libc::socklen_t;

pub(crate) fn bind(fd: &OwnedFd, addr: SocketAddrV4) -> io::Result<()> {
    let sa = sockaddr(addr);
    // SAFETY: `sa` is a valid sockaddr_in of the length passed.
    let rc = unsafe { libc::bind(fd.as_raw_fd(), std::ptr::from_ref(&sa).cast(), SOCKADDR_IN_LEN) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn send_to(fd: RawFd, packet: &[u8], to: SocketAddrV4) -> io::Result<()> {
    let sa = sockaddr(to);
    // SAFETY: `packet` and `sa` are valid for the lengths passed.
    let rc = unsafe { libc::sendto(fd, packet.as_ptr().cast(), packet.len(), 0, std::ptr::from_ref(&sa).cast(), SOCKADDR_IN_LEN) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn from_sockaddr(sa: &libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)), u16::from_be(sa.sin_port))
}

/// One diverted packet: its length in `buf`, who sent it, and where to.
pub(crate) fn recv_diverted(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV4, SocketAddrV4)> {
    // SAFETY: all-zero is a valid value for each of these C structs; every
    // pointer set below outlives the call.
    let mut from: libc::sockaddr_in = unsafe { zeroed() };
    let mut control = [0u64; 16];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = std::ptr::from_mut(&mut from).cast();
    msg.msg_namelen = SOCKADDR_IN_LEN;
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of::<[u64; 16]>();
    // SAFETY: `msg` describes buffers valid for their stated lengths.
    let len = unsafe { libc::recvmsg(fd.as_raw_fd(), &raw mut msg, 0) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut original = None;
    // SAFETY: the CMSG_* walk stays within the control buffer recvmsg
    // filled, as its length now says.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == libc::IP_ORIGDSTADDR {
                let sa: libc::sockaddr_in = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                original = Some(from_sockaddr(&sa));
            }
            cmsg = libc::CMSG_NXTHDR(&raw const msg, cmsg);
        }
    }
    let original = original.ok_or_else(|| io::Error::other("no original destination"))?;
    Ok((usize::try_from(len).expect("non-negative"), from_sockaddr(&from), original))
}

/// Gives `packet` back to this host as `phone` sent it to `local`: from a
/// transparent socket bound to the phone's address, so it arrives on `lo`
/// with that source, which the diverting rules ignore.
fn reinject(phone: SocketAddrV4, local: SocketAddrV4, packet: &[u8]) -> io::Result<()> {
    let fd = udp_socket()?;
    set_int(&fd, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
    set_int(&fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    bind(&fd, phone)?;
    send_to(fd.as_raw_fd(), packet, local)
}

/// Sends `payload` to `to` in a UDP datagram from `from`, headers and all.
pub(crate) fn send_raw(raw: &OwnedFd, from: SocketAddrV4, to: SocketAddrV4, payload: &[u8]) -> io::Result<()> {
    let datagram = udp_datagram(from, to, payload)?;
    send_to(raw.as_raw_fd(), &datagram, to)
}

/// An IPv4 header and a UDP header, checksummed, in front of `payload`.
fn udp_datagram(from: SocketAddrV4, to: SocketAddrV4, payload: &[u8]) -> io::Result<Vec<u8>> {
    let udp_len = u16::try_from(8 + payload.len()).map_err(|_| io::Error::other("datagram too long"))?;
    let total = udp_len.checked_add(20).ok_or_else(|| io::Error::other("datagram too long"))?;
    let mut out = Vec::with_capacity(usize::from(total));
    out.extend_from_slice(&[0x45, 0]);
    out.extend_from_slice(&total.to_be_bytes());
    // Identification, and "don't fragment": WireGuard sizes its packets for
    // the path, as the kernel's own sends would.
    out.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    out.extend_from_slice(&from.ip().octets());
    out.extend_from_slice(&to.ip().octets());
    let header_sum = checksum(&[&out[..20]]);
    out[10..12].copy_from_slice(&header_sum.to_be_bytes());
    let mut udp = Vec::with_capacity(8);
    udp.extend_from_slice(&from.port().to_be_bytes());
    udp.extend_from_slice(&to.port().to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&from.ip().octets());
    pseudo.extend_from_slice(&to.ip().octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    // An all-zero sum is sent as all ones: zero means "no checksum".
    let sum = match checksum(&[&pseudo, &udp, payload]) {
        0 => 0xffff,
        s => s,
    };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    out.extend_from_slice(&udp);
    out.extend_from_slice(payload);
    Ok(out)
}

/// The internet checksum of `parts` laid end to end.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for byte in parts.iter().flat_map(|p| p.iter().copied()) {
        match odd.take() {
            None => odd = Some(byte),
            Some(hi) => sum += u32::from(u16::from_be_bytes([hi, byte])),
        }
    }
    if let Some(hi) = odd {
        sum += u32::from(u16::from_be_bytes([hi, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded to 16 bits")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checksums_verify() {
        let from: SocketAddrV4 = "192.0.2.1:51820".parse().unwrap();
        let to: SocketAddrV4 = "198.51.100.7:40000".parse().unwrap();
        for payload in [&b"odd"[..], &[4u8; 32][..], &[][..]] {
            let d = udp_datagram(from, to, payload).unwrap();
            assert_eq!(checksum(&[&d[..20]]), 0, "IPv4 header");
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&d[12..20]);
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&d[24..26]);
            assert_eq!(checksum(&[&pseudo, &d[20..]]), 0, "UDP over the pseudo-header");
            assert_eq!(&d[20..22], &51820u16.to_be_bytes());
            assert_eq!(&d[28..], payload);
        }
    }

    struct NoDivert;

    impl Divert for NoDivert {
        fn add(&self, _index: u32) {}
        fn retain(&self, _live: &[u32]) {}
    }

    #[test]
    fn a_relay_that_cannot_open_its_sockets_is_not_offered_until_it_can() {
        let relay = PhoneRelay::default();
        if Sockets::probe().is_err() {
            assert!(!relay.capable(), "without the raw socket, never");
            return;
        }
        assert!(relay.capable(), "probed before any poll names the ports");
        let divert: Arc<dyn Divert> = Arc::new(NoDivert);
        // Another program on the mesh port.
        let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(mesh) = holder.local_addr().unwrap() else { panic!() };
        let divert_port = UdpSocket::bind("0.0.0.0:0").unwrap().local_addr().unwrap().port();
        let config = Config { listen_port: 51820, divert_port, mesh, pool: None, nodes: vec![], devices: vec![] };
        assert!(relay.configure(Some(config.clone()), &divert).is_err());
        assert!(!relay.capable(), "stops being offered at once");
        relay.configure(None, &divert).unwrap();
        assert!(!relay.capable(), "tried again, the port still held");
        drop(holder);
        // Tried a few times, as polls would: a test elsewhere in this process
        // that starts a program holds a copy of every socket here for the
        // moment between its fork and its exec.
        let tries = || (0..40).map(|_| std::thread::sleep(Duration::from_millis(50)));
        assert!(
            tries().any(|()| relay.configure(None, &divert).is_ok() && relay.capable()),
            "and offered again once it is free"
        );
        assert!(tries().any(|()| relay.configure(Some(config.clone()), &divert).is_ok()));
        assert!(relay.is_running() && relay.capable());
        relay.configure(None, &divert).unwrap();
        assert!(!relay.is_running() && relay.capable());
    }

    /// A pool whose ports another program holds leaves the relay running
    /// from its main socket, offered as before; the pool opens on a later
    /// poll once they are free.
    #[test]
    fn a_relay_whose_pool_is_taken_works_from_its_main_socket_until_the_pool_opens() {
        let relay = PhoneRelay::default();
        if Sockets::probe().is_err() {
            return;
        }
        let divert: Arc<dyn Divert> = Arc::new(NoDivert);
        let free = || UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (mesh_port, divert_port) = (free(), free());
        // Two ports in a row, the second held by another program.
        let (first, holder) = loop {
            let first = free();
            let Some(next) = first.checked_add(1) else { continue };
            if let Ok(holder) = UdpSocket::bind(("127.0.0.1", next)) {
                break (first, holder);
            }
        };
        let pool = first..=first + 1;
        let config = Config {
            listen_port: 51820,
            divert_port,
            mesh: SocketAddrV4::new(Ipv4Addr::LOCALHOST, mesh_port),
            pool: Some(pool.clone()),
            nodes: vec![],
            devices: vec![],
        };
        let tries = || (0..40).map(|_| std::thread::sleep(Duration::from_millis(50)));
        assert!(tries().any(|()| relay.configure(Some(config.clone()), &divert).is_ok()), "the relay starts without its pool");
        assert!(relay.is_running() && relay.capable());
        assert_eq!(relay.pool(), None, "and the firewall is not told of one");
        drop(holder);
        assert!(tries().any(|()| relay.configure(Some(config.clone()), &divert).is_ok() && relay.pool().is_some()), "opened on a later poll");
        assert_eq!(relay.pool(), Some(pool));
        relay.pool_allowed();
        relay.configure(None, &divert).unwrap();
        assert_eq!(relay.pool(), None);
    }

    /// The whole path against a real kernel (PLAN.md #346): a phone on the
    /// "internet" side reaches a node behind the carrier and the carrier's
    /// own WireGuard at once, from one socket, to one port — the rules
    /// diverting only what is the node's, the sorter forwarding it over the
    /// mesh (a veth standing in for it) from a port of the pool and
    /// answering from the WireGuard port, the carrier's own handshake given
    /// back to its socket with the phone's address. Then the phone changes
    /// address mid-session and is answered there at once, with no new
    /// handshake; a spoofer at a third address replaying its packets and
    /// making up others gets none of the node's; and the phone, back at its
    /// first address, is answered there again. WireGuard runs in userspace
    /// on every side (boringtun), so this needs no WireGuard in the kernel;
    /// the node's stand-in sends where kernel WireGuard would, to the source
    /// of the last packet it authenticated.
    #[test]
    fn kernel_a_phone_reaches_a_relayed_node_and_the_carrier_on_one_port() {
        use crate::phone_relay::packet::tests::End;
        use crate::phone_relay::packet::Message;
        use defguard_boringtun::noise::{Tunn, TunnResult};
        use std::sync::mpsc;
        use wireserve_types::{FirewallBackend, Forwarding, PhoneRelayRules};

        if !crate::firewall::netns::reexec("phone_relay::io::tests::kernel_a_phone_reaches_a_relayed_node_and_the_carrier_on_one_port") {
            return;
        }
        let mut spaces = Vec::new();
        for _ in 0..2 {
            spaces.push(std::process::Command::new("unshare").args(["-n", "sleep", "60"]).spawn().unwrap());
        }
        std::thread::sleep(Duration::from_millis(300));
        let (phone_ns, node_ns) = (spaces[0].id(), spaces[1].id());
        let setup = format!(
            "ip link set lo up
             ip link add eth0 type veth peer name p0 && ip link set p0 netns {phone_ns}
             ip addr add 203.0.113.1/24 dev eth0 && ip link set eth0 up
             nsenter -t {phone_ns} -n sh -euc 'ip link set lo up; ip addr add 203.0.113.2/24 dev p0; ip addr add 203.0.113.3/24 dev p0; ip addr add 203.0.113.4/24 dev p0; ip link set p0 up'
             ip link add wg0 type veth peer name n0 && ip link set n0 netns {node_ns}
             ip addr add 100.90.0.2/24 dev wg0 && ip link set wg0 up
             nsenter -t {node_ns} -n sh -euc 'ip link set lo up; ip addr add 100.90.0.5/24 dev n0; ip link set n0 up'"
        );
        let out = std::process::Command::new("sh").args(["-euc", &setup]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let (phone, minipc, carrier) = (End::new(1), End::new(2), End::new(4));
        let mut fw = crate::firewall::nftables::NftablesBackend::new("wg0").unwrap();
        let rules = PhoneRelayRules { listen_port: 51820, divert_port: 42000, mesh_port: 42001, pool: Some(42003..=42066), indexes: Vec::new() };
        let forwarding = Forwarding {
            relay_self: Some("100.90.0.2".parse().unwrap()),
            relay_ends: vec![51820],
            phone_relay: Some(rules),
            ..Forwarding::default()
        };
        fw.apply(&[], &forwarding).unwrap();
        let relay = PhoneRelay::default();
        let diverted = fw.phone_divert();
        let divert: Arc<dyn Divert> = diverted.clone();
        relay
            .configure(
                Some(Config {
                    listen_port: 51820,
                    divert_port: 42000,
                    mesh: "100.90.0.2:42001".parse().unwrap(),
                    pool: Some(42003..=42066),
                    nodes: vec![("100.90.0.5:51820".parse().unwrap(), minipc.public)],
                    devices: vec![phone.public],
                }),
                &divert,
            )
            .unwrap();
        assert_eq!(relay.pool(), Some(42003..=42066));
        relay.pool_allowed();

        let inner = {
            let mut p = vec![0u8; 28];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&28u16.to_be_bytes());
            p[9] = 17;
            p[12..16].copy_from_slice(&[10, 1, 0, 9]);
            p[16..20].copy_from_slice(&[10, 1, 0, 5]);
            p
        };
        // A WireGuard end answering on `addr` in the namespace of `pid` (or
        // this one): what it receives, and from where, goes to the channel.
        // It echoes data, and sends some of its own when poked, always to
        // the source of the last packet it authenticated, as kernel
        // WireGuard does; what it cannot authenticate moves nothing.
        let serve = |pid: Option<u32>, addr: &str, mut tunn: Tunn| {
            let (tx, rx) = mpsc::channel::<(Vec<u8>, std::net::SocketAddr)>();
            let (poke, poked) = mpsc::channel::<()>();
            let (addr, own) = (addr.to_string(), inner.clone());
            std::thread::spawn(move || {
                if let Some(pid) = pid {
                    enter(pid);
                }
                let socket = UdpSocket::bind(&addr).unwrap();
                socket.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
                let (mut buf, mut out) = (vec![0u8; 2048], vec![0u8; 2048]);
                let mut endpoint: Option<std::net::SocketAddr> = None;
                let mut last = Instant::now();
                while last.elapsed() < Duration::from_secs(10) {
                    if poked.try_recv().is_ok() {
                        if let (Some(to), TunnResult::WriteToNetwork(p)) = (endpoint, tunn.encapsulate(&own, &mut out)) {
                            socket.send_to(p, to).unwrap();
                        }
                    }
                    let Ok((n, from)) = socket.recv_from(&mut buf) else { continue };
                    last = Instant::now();
                    let mut datagram = buf[..n].to_vec();
                    loop {
                        let result = tunn.decapsulate(Some(from.ip()), &datagram, &mut out);
                        if matches!(result, TunnResult::Err(_)) {
                            break;
                        }
                        if !datagram.is_empty() {
                            endpoint = Some(from);
                        }
                        let to = endpoint.expect("set by an authenticated packet");
                        match result {
                            TunnResult::WriteToNetwork(p) => {
                                socket.send_to(p, to).unwrap();
                                datagram.clear();
                            }
                            TunnResult::WriteToTunnelV4(p, _) => {
                                let got = p.to_vec();
                                let _ = tx.send((got.clone(), from));
                                // Echoed, so the phone sees data come back.
                                if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&got, &mut out) {
                                    socket.send_to(p, to).unwrap();
                                }
                                break;
                            }
                            _ => break,
                        }
                    }
                }
            });
            (rx, poke)
        };
        let (node_rx, poke_node) = serve(Some(node_ns), "100.90.0.5:51820", minipc.tunnel_to(&phone, 20));
        let (own_rx, _) = serve(None, "0.0.0.0:51820", carrier.tunnel_to(&phone, 30));
        std::thread::sleep(Duration::from_millis(200));

        // The phone, a socket at each of its two addresses, and a spoofer's
        // beside them: all dial the carrier's port.
        const AT_FIRST: usize = 0;
        const AT_SECOND: usize = 1;
        const SPOOFER: usize = 2;
        let (tx, phone_rx) = mpsc::channel::<(usize, Vec<u8>)>();
        let (to_send, send_rx) = mpsc::channel::<(usize, Vec<u8>)>();
        std::thread::spawn(move || {
            enter(phone_ns);
            let sockets: Vec<UdpSocket> = ["203.0.113.2:40000", "203.0.113.3:40001", "203.0.113.4:40002"]
                .into_iter()
                .map(|addr| {
                    let socket = UdpSocket::bind(addr).unwrap();
                    socket.set_nonblocking(true).unwrap();
                    socket
                })
                .collect();
            let mut buf = vec![0u8; 2048];
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                loop {
                    match send_rx.try_recv() {
                        Ok((at, p)) => {
                            sockets[at].send_to(&p, "203.0.113.1:51820").unwrap();
                        }
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => return,
                    }
                }
                for (at, socket) in sockets.iter().enumerate() {
                    while let Ok((n, from)) = socket.recv_from(&mut buf) {
                        assert_eq!(from.to_string(), "203.0.113.1:51820", "every answer comes from the port the phone dialled");
                        let _ = tx.send((at, buf[..n].to_vec()));
                    }
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        let mut to_node = phone.tunnel_to(&minipc, 1);
        let mut to_carrier = phone.tunnel_to(&carrier, 2);
        let is_data = |p: &[u8]| matches!(Message::parse(p), Some(Message::Data { .. }));
        // Drives `tunn` from the phone's first address until a data packet
        // comes back through it.
        let talk = |tunn: &mut Tunn, what: &str| {
            let mut out = vec![0u8; 2048];
            if let TunnResult::WriteToNetwork(p) = tunn.format_handshake_initiation(&mut out, false) {
                to_send.send((AT_FIRST, p.to_vec())).unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut sent_data = false;
            while Instant::now() < deadline {
                let Ok((_, mut datagram)) = phone_rx.recv_timeout(Duration::from_millis(200)) else { continue };
                loop {
                    match tunn.decapsulate(None, &datagram, &mut out) {
                        TunnResult::WriteToNetwork(p) => {
                            to_send.send((AT_FIRST, p.to_vec())).unwrap();
                            datagram.clear();
                        }
                        TunnResult::WriteToTunnelV4(..) => return,
                        _ => break,
                    }
                }
                if !sent_data {
                    if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&inner, &mut out) {
                        if is_data(p) {
                            to_send.send((AT_FIRST, p.to_vec())).unwrap();
                            sent_data = true;
                        }
                    }
                }
            }
            let rules = std::process::Command::new("nft").args(["list", "ruleset"]).output().unwrap();
            panic!("no data back from {what}; the rules:\n{}", String::from_utf8_lossy(&rules.stdout));
        };
        talk(&mut to_node, "the relayed node");
        talk(&mut to_carrier, "the carrier's own WireGuard");

        let (got, from) = node_rx.recv_timeout(Duration::from_secs(2)).expect("the node got the phone's data");
        assert_eq!(got, inner);
        assert_eq!(from.to_string(), "100.90.0.2:42003", "the node sees the phone as a port of the sorter's pool");
        let (got, from) = own_rx.recv_timeout(Duration::from_secs(2)).expect("the carrier got the phone's data");
        assert_eq!(got, inner);
        assert_eq!(from.to_string(), "203.0.113.2:40000", "the carrier's own WireGuard sees the phone itself");
        assert!(!diverted.indexes().is_empty(), "the node's session was diverted by its index");
        std::thread::sleep(Duration::from_millis(200));
        while phone_rx.try_recv().is_ok() {}
        while node_rx.try_recv().is_ok() {}

        // Waits for a data packet for `tunn` at `at`, and nothing anywhere
        // else.
        let answered_at = |tunn: &mut Tunn, at: usize, what: &str| {
            let mut out = vec![0u8; 2048];
            let deadline = Instant::now() + Duration::from_secs(2);
            while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                let Ok((got_at, datagram)) = phone_rx.recv_timeout(left) else { break };
                assert_eq!(got_at, at, "{what}: an answer at socket {got_at}");
                match tunn.decapsulate(None, &datagram, &mut out) {
                    TunnResult::WriteToTunnelV4(..) => return,
                    TunnResult::WriteToNetwork(_) => panic!("{what}: a new handshake"),
                    _ => {}
                }
            }
            panic!("{what}: no answer within two seconds");
        };
        // One packet of the session from `at`, no handshake, and its echo
        // back there; the packet sent.
        let exchange = |tunn: &mut Tunn, at: usize, what: &str| -> Vec<u8> {
            let mut out = vec![0u8; 2048];
            let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&inner, &mut out) else { panic!("{what}: nothing to send") };
            assert!(is_data(p), "{what}: a new handshake, not data");
            let sent = p.to_vec();
            to_send.send((at, sent.clone())).unwrap();
            answered_at(tunn, at, what);
            sent
        };

        // The phone changes address mid-session.
        let last = exchange(&mut to_node, AT_SECOND, "after the phone moved");
        let (_, from) = node_rx.recv_timeout(Duration::from_secs(2)).expect("the node got the moved phone's data");
        assert_eq!(from.to_string(), "100.90.0.2:42004", "the new address has a port of its own");
        // A spoofer at a third address: a copy of the phone's last packet,
        // and one made up with the session's index. The node takes neither,
        // and what it sends next still goes to the phone.
        let mut made_up = vec![0u8; 32];
        made_up[..8].copy_from_slice(&last[..8]);
        to_send.send((SPOOFER, last)).unwrap();
        to_send.send((SPOOFER, made_up)).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        assert!(node_rx.try_recv().is_err(), "the node took nothing of the spoofer's");
        poke_node.send(()).unwrap();
        answered_at(&mut to_node, AT_SECOND, "the node's own packet after the spoofer's");
        exchange(&mut to_node, AT_SECOND, "after the spoofer");
        // Back at the first address, whose port is still its own.
        exchange(&mut to_node, AT_FIRST, "back at the first address");
        poke_node.send(()).unwrap();
        answered_at(&mut to_node, AT_FIRST, "the node's own packet, back at the first address");
        std::thread::sleep(Duration::from_millis(300));
        assert!(phone_rx.try_recv().is_err(), "nothing for the spoofer, nor anything else");

        relay.configure(None, &divert).unwrap();
        for mut s in spaces {
            let _ = s.kill();
            let _ = s.wait();
        }
    }

    /// PLAN.md #339 with the carrier's own WireGuard in the kernel, not a
    /// stand-in: a handshake given back on `lo` is answered on the
    /// interface the phone is reached by, and the session then carries data
    /// both ways. Kernel WireGuard keeps the interface a packet arrived on
    /// with the endpoint it learns from it, and re-routes a reply whose
    /// route leaves elsewhere; this is the test that it does. Needs the
    /// wireguard module (CI loads it); skips without it.
    #[test]
    fn kernel_wireguard_answers_a_handshake_given_back_to_it() {
        use crate::phone_relay::packet::tests::End;
        use defguard_boringtun::noise::TunnResult;
        use wireserve_types::{FirewallBackend, Forwarding, PhoneRelayRules};

        if !crate::firewall::netns::reexec("phone_relay::io::tests::kernel_wireguard_answers_a_handshake_given_back_to_it") {
            return;
        }
        let (phone, carrier) = (End::new(1), End::new(4));
        let key = |b: [u8; 32]| defguard_wireguard_rs::key::Key::new(b).to_string();
        let mut space = std::process::Command::new("unshare").args(["-n", "sleep", "60"]).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let phone_ns = space.id();
        let setup = format!(
            "ip link set lo up
             ip link add eth0 type veth peer name p0 && ip link set p0 netns {phone_ns}
             ip addr add 203.0.113.1/24 dev eth0 && ip link set eth0 up
             nsenter -t {phone_ns} -n sh -euc 'ip link set lo up; ip addr add 203.0.113.2/24 dev p0; ip link set p0 up'
             ip link add wgc type wireguard"
        );
        let out = std::process::Command::new("sh").args(["-euc", &setup]).output().unwrap();
        if !out.status.success() {
            let _ = space.kill();
            let _ = space.wait();
            if String::from_utf8_lossy(&out.stderr).contains("type wireguard") || String::from_utf8_lossy(&out.stderr).contains("Unknown device type") {
                crate::firewall::netns::skip("no wireguard kernel module");
                return;
            }
            panic!("{}", String::from_utf8_lossy(&out.stderr));
        }
        let wg = format!(
            "printf '%s' '{}' > /tmp/wgc.key
             wg set wgc listen-port 51820 private-key /tmp/wgc.key peer '{}' allowed-ips 10.1.0.9/32
             ip addr add 10.1.0.1/24 dev wgc && ip link set wgc up",
            key(carrier.secret),
            key(phone.public),
        );
        let out = std::process::Command::new("sh").args(["-euc", &wg]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let mut fw = crate::firewall::nftables::NftablesBackend::new("wg0").unwrap();
        fw.apply(&[], &Forwarding {
            relay_self: Some("100.90.0.2".parse().unwrap()),
            phone_relay: Some(PhoneRelayRules { listen_port: 51820, divert_port: 42000, mesh_port: 42001, pool: None, indexes: Vec::new() }),
            ..Forwarding::default()
        })
        .unwrap();
        // The sorter needs its mesh address to exist; no node is relayed.
        let out = std::process::Command::new("sh").args(["-euc", "ip link add wg0 type veth peer name n0 && ip addr add 100.90.0.2/24 dev wg0 && ip link set wg0 up"]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let relay = PhoneRelay::default();
        let divert: Arc<dyn Divert> = fw.phone_divert();
        relay
            .configure(
                Some(Config { listen_port: 51820, divert_port: 42000, mesh: "100.90.0.2:42001".parse().unwrap(), pool: None, nodes: vec![], devices: vec![phone.public] }),
                &divert,
            )
            .unwrap();

        // The phone pings the carrier's tunnel address and waits for the reply.
        let answered = std::thread::spawn(move || {
            enter(phone_ns);
            let socket = UdpSocket::bind("203.0.113.2:40000").unwrap();
            socket.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
            let mut tunn = phone.tunnel_to(&carrier, 2);
            let (mut buf, mut out) = (vec![0u8; 2048], vec![0u8; 2048]);
            let ping = {
                let mut p = vec![0u8; 28];
                p[0] = 0x45;
                p[2..4].copy_from_slice(&28u16.to_be_bytes());
                p[8] = 64;
                p[9] = 1;
                p[12..16].copy_from_slice(&[10, 1, 0, 9]);
                p[16..20].copy_from_slice(&[10, 1, 0, 1]);
                let ip = checksum(&[&p[..20]]);
                p[10..12].copy_from_slice(&ip.to_be_bytes());
                p[20] = 8;
                p[24..26].copy_from_slice(&0x77u16.to_be_bytes());
                let icmp = checksum(&[&p[20..]]);
                p[22..24].copy_from_slice(&icmp.to_be_bytes());
                p
            };
            if let TunnResult::WriteToNetwork(p) = tunn.format_handshake_initiation(&mut out, false) {
                socket.send_to(p, "203.0.113.1:51820").unwrap();
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if let TunnResult::WriteToNetwork(p) = tunn.encapsulate(&ping, &mut out) {
                    socket.send_to(p, "203.0.113.1:51820").unwrap();
                }
                let Ok((n, from)) = socket.recv_from(&mut buf) else { continue };
                assert_eq!(from.to_string(), "203.0.113.1:51820");
                let mut datagram = buf[..n].to_vec();
                loop {
                    match tunn.decapsulate(None, &datagram, &mut out) {
                        TunnResult::WriteToNetwork(p) => {
                            socket.send_to(p, "203.0.113.1:51820").unwrap();
                            datagram.clear();
                        }
                        TunnResult::WriteToTunnelV4(p, _) if p.get(20) == Some(&0) => return true,
                        _ => break,
                    }
                }
            }
            false
        })
        .join()
        .unwrap();
        relay.configure(None, &divert).unwrap();
        let _ = space.kill();
        let _ = space.wait();
        let show = std::process::Command::new("wg").args(["show", "wgc"]).output().unwrap();
        assert!(answered, "no echo reply through the carrier's kernel WireGuard:\n{}", String::from_utf8_lossy(&show.stdout));
    }

    /// Moves this thread into the network namespace of `pid`.
    fn enter(pid: u32) {
        let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
        // SAFETY: setns(2) on a namespace file this thread opened; it
        // changes only this thread's namespace.
        assert_eq!(unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) }, 0, "{}", io::Error::last_os_error());
    }
}
