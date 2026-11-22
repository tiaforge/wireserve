//! The reflexive probe answered on this node's own WireGuard port (PLAN.md
//! M50, #348, #349).
//!
//! On networks that let UDP out to the WireGuard port and little else, a
//! probe to the coordinator's own port never arrives. The node on the
//! coordinator's host answers it on its WireGuard port instead, which kernel
//! WireGuard holds: the firewall's `reflexive-pre` chain takes a probe off the
//! port by tproxy — per packet, rewriting nothing, so no WireGuard packet
//! ever follows it — and hands it to the transparent socket here. The answer
//! leaves the raw socket with the address and port the prober dialled as its
//! source, as the phone relay's answers do (`phone_relay::io`).
//!
//! The answer is the coordinator's own (`wireserve_types::reflexive`): 19
//! bytes for 64, so still under 1x, sent once. The second answer from
//! another port (PLAN.md M40) stays the coordinator's alone. Anything
//! malformed or over its source's budget gets no answer at all.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use wireserve_types::rate_limit::SlidingWindowLimiter;
use wireserve_types::reflexive::{build_response, parse_request, RESPONSE_LEN};

use crate::phone_relay::io::{bind, recv_diverted, send_raw, set_int, udp_socket};

/// How often the thread looks up from its socket, to stop when told.
const TICK: Duration = Duration::from_millis(500);
/// The per-source budget: the coordinator's own default
/// (`WIRESERVE_REFLEXIVE_RATE_LIMIT_MAX` in its window). A node probes once
/// per start, three tries at most.
const PER_SOURCE_MAX: u32 = 20;
const PER_SOURCE_WINDOW_SECS: u64 = 10;

/// What the responder is told by each poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// This node's WireGuard listen port: only what was sent to it is
    /// answered.
    pub listen_port: u16,
    /// The transparent socket's port, on every address.
    pub divert_port: u16,
}

/// The answer to `packet` from `from`, if it gets one: a well-formed
/// request from a source still within its budget. A source the limiter can
/// no longer track gets none: answering untracked sources is the unlimited
/// reflection the limiter is there to prevent (`SlidingWindowLimiter::record`).
#[must_use]
pub fn answer(limiter: &SlidingWindowLimiter, packet: &[u8], from: SocketAddrV4) -> Option<[u8; RESPONSE_LEN]> {
    let nonce = parse_request(packet)?;
    let ip = std::net::IpAddr::V4(*from.ip());
    if limiter.is_blocked(ip) || !limiter.record(ip) {
        return None;
    }
    Some(build_response(nonce, from))
}

struct Running {
    config: Config,
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

/// The responder of one agent: stopped until a poll says this node answers
/// probes, and stopped again when it no longer does.
#[derive(Default)]
pub struct Responder {
    running: Mutex<Option<Running>>,
    /// The last firewall apply put the rule in place while this ran
    /// (PLAN.md #351): what the next poll reports.
    confirmed: AtomicBool,
}

impl Responder {
    /// Starts, moves or stops the responder. A failure to open its sockets
    /// leaves it stopped, to be tried again on the next poll.
    pub fn configure(&self, config: Option<Config>) -> io::Result<()> {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        let Some(config) = config else {
            if running.take().is_some() {
                tracing::info!("no longer answering reflexive probes on the WireGuard port");
            }
            self.confirmed.store(false, Ordering::Relaxed);
            return Ok(());
        };
        if running.as_ref().is_some_and(|r| r.config == config) {
            return Ok(());
        }
        running.take();
        self.confirmed.store(false, Ordering::Relaxed);
        let sockets = Sockets::open(config.divert_port)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("reflexive".into())
                .spawn(move || run(&sockets, config.listen_port, &stop))?
        };
        tracing::info!(listen_port = config.listen_port, divert_port = config.divert_port, "answering reflexive probes on the WireGuard port");
        *running = Some(Running { config, stop, thread: Some(thread) });
        Ok(())
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.lock().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Records whether the firewall now hands this responder its probes.
    pub fn set_confirmed(&self, confirmed: bool) {
        self.confirmed.store(confirmed && self.is_running(), Ordering::Relaxed);
    }

    /// Whether this node answers probes on its WireGuard port right now, as
    /// of the last firewall apply.
    #[must_use]
    pub fn confirmed(&self) -> bool {
        self.confirmed.load(Ordering::Relaxed)
    }
}

struct Sockets {
    divert: OwnedFd,
    raw: OwnedFd,
}

impl Sockets {
    fn open(divert_port: u16) -> io::Result<Self> {
        let divert = udp_socket()?;
        set_int(&divert, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
        set_int(&divert, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1)?;
        bind(&divert, SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, divert_port))?;
        // SAFETY: plain socket(2); the result is checked before use.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a socket this function just opened and owns.
        let raw = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self { divert, raw })
    }
}

fn run(io: &Sockets, listen_port: u16, stop: &AtomicBool) {
    let limiter = SlidingWindowLimiter::new(PER_SOURCE_MAX, PER_SOURCE_WINDOW_SECS);
    let mut buf = vec![0u8; 2048];
    while !stop.load(Ordering::Relaxed) {
        let mut fds = [libc::pollfd { fd: io.divert.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        // SAFETY: `fds` is a valid array of one pollfd for the call's length.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 1, i32::try_from(TICK.as_millis()).unwrap_or(500)) };
        if ready <= 0 || fds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        match recv_diverted(&io.divert, &mut buf) {
            // Only what was sent to the WireGuard port: the socket is bound on
            // every address, and something sent to it directly is no probe
            // the firewall handed over.
            Ok((len, from, local)) if local.port() == listen_port => {
                if let Some(response) = answer(&limiter, &buf[..len], from) {
                    if let Err(e) = send_raw(&io.raw, local, from, &response) {
                        tracing::debug!(error = %e, %from, "reflexive responder: could not send");
                    }
                }
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(error = %e, "reflexive responder: divert socket"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::reflexive::{build_request, parse_response};

    #[test]
    fn a_request_is_answered_with_the_address_it_came_from() {
        let limiter = SlidingWindowLimiter::new(PER_SOURCE_MAX, PER_SOURCE_WINDOW_SECS);
        let from: SocketAddrV4 = "198.51.100.7:40000".parse().unwrap();
        let resp = answer(&limiter, &build_request([7; 8]), from).expect("answered");
        assert_eq!(parse_response(&resp), Some(([7; 8], from)));
    }

    #[test]
    fn anything_else_gets_no_answer() {
        let limiter = SlidingWindowLimiter::new(PER_SOURCE_MAX, PER_SOURCE_WINDOW_SECS);
        let from: SocketAddrV4 = "198.51.100.7:40000".parse().unwrap();
        assert!(answer(&limiter, &[0u8; 64], from).is_none(), "no magic");
        assert!(answer(&limiter, &build_request([1; 8])[..63], from).is_none(), "short");
        // A WireGuard handshake initiation is never a probe.
        let mut initiation = [0u8; 148];
        initiation[0] = 1;
        assert!(answer(&limiter, &initiation, from).is_none());
    }

    #[test]
    fn a_source_over_its_budget_gets_no_answer_and_another_still_does() {
        let limiter = SlidingWindowLimiter::new(2, 60);
        let a: SocketAddrV4 = "198.51.100.7:40000".parse().unwrap();
        let b: SocketAddrV4 = "198.51.100.8:40000".parse().unwrap();
        assert!(answer(&limiter, &build_request([1; 8]), a).is_some());
        assert!(answer(&limiter, &build_request([2; 8]), a).is_some());
        assert!(answer(&limiter, &build_request([3; 8]), a).is_none());
        assert!(answer(&limiter, &build_request([4; 8]), b).is_some());
    }

    #[test]
    fn an_untracked_source_gets_no_answer() {
        let limiter = SlidingWindowLimiter::with_max_sources(5, 60, 0);
        let from: SocketAddrV4 = "198.51.100.7:40000".parse().unwrap();
        assert!(answer(&limiter, &build_request([1; 8]), from).is_none());
    }

    fn enter(pid: u32) {
        use std::os::fd::AsRawFd;
        let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
        // SAFETY: setns(2) on a namespace file this thread opened; it
        // changes only this thread's namespace.
        assert_eq!(unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) }, 0, "{}", io::Error::last_os_error());
    }

    /// A prober in another namespace sends a probe to this host's WireGuard
    /// port and gets its own address back from that port, while what else
    /// it sends from the same socket to the same port — WireGuard's packets
    /// — still reaches whatever holds the port (PLAN.md #347). A plain UDP
    /// socket stands in for kernel WireGuard: the rule and the responder
    /// never look at who holds it.
    #[test]
    fn kernel_a_probe_on_the_wireguard_port_is_answered_and_wireguard_keeps_the_rest() {
        use std::net::UdpSocket;
        use wireserve_types::{FirewallBackend, Forwarding, ReflexiveRules};

        if !crate::firewall::netns::reexec(
            "reflexive_responder::tests::kernel_a_probe_on_the_wireguard_port_is_answered_and_wireguard_keeps_the_rest",
        ) {
            return;
        }
        let mut space = std::process::Command::new("unshare").args(["-n", "sleep", "60"]).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let prober_ns = space.id();
        let setup = format!(
            "ip link set lo up
             ip link add eth0 type veth peer name p0 && ip link set p0 netns {prober_ns}
             ip addr add 203.0.113.1/24 dev eth0 && ip link set eth0 up
             nsenter -t {prober_ns} -n sh -euc 'ip link set lo up; ip addr add 203.0.113.2/24 dev p0; ip link set p0 up'"
        );
        let out = std::process::Command::new("sh").args(["-euc", &setup]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let wireguard = UdpSocket::bind("0.0.0.0:51820").unwrap();
        wireguard.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut fw = crate::firewall::nftables::NftablesBackend::new("wg0").unwrap();
        fw.apply(&[], &Forwarding { reflexive: Some(ReflexiveRules { listen_port: 51820, divert_port: 42002 }), ..Forwarding::default() })
            .unwrap();
        let responder = Responder::default();
        responder.configure(Some(Config { listen_port: 51820, divert_port: 42002 })).unwrap();
        responder.set_confirmed(true);
        assert!(responder.confirmed());

        let prober = std::thread::spawn(move || {
            enter(prober_ns);
            let socket = UdpSocket::bind("203.0.113.2:40000").unwrap();
            socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            let target = "203.0.113.1:51820";
            let mut buf = [0u8; 64];
            let mut answer = None;
            for _ in 0..5 {
                socket.send_to(&build_request([9; 8]), target).unwrap();
                if let Ok((n, src)) = socket.recv_from(&mut buf) {
                    answer = Some((src, parse_response(&buf[..n])));
                    break;
                }
            }
            // A WireGuard handshake initiation from the same socket, the
            // same flow as the probe.
            let mut initiation = [0u8; 148];
            initiation[0] = 1;
            socket.send_to(&initiation, target).unwrap();
            answer
        });
        let answer = prober.join().unwrap();
        let from: SocketAddrV4 = "203.0.113.2:40000".parse().unwrap();
        let (src, parsed) = answer.expect("the probe was answered");
        assert_eq!(src, "203.0.113.1:51820".parse().unwrap(), "from the port the prober dialled");
        assert_eq!(parsed, Some(([9; 8], from)), "with the address it came from");

        let mut buf = [0u8; 256];
        let (n, src) = wireguard.recv_from(&mut buf).expect("WireGuard still gets the flow's other packets");
        assert_eq!((n, src), (148, std::net::SocketAddr::V4(from)), "and never the probe");

        responder.configure(None).unwrap();
        assert!(!responder.confirmed() && !responder.is_running());
        let _ = space.kill();
        let _ = space.wait();
    }
}

