//! Noticing that another tool changed the ruleset — `ufw reload`,
//! `firewall-cmd --reload`, `nft -f /etc/nftables.conf`, a crowdsec
//! bouncer or geoip-shell rebuilding its table — so our rules come back
//! within about a second instead of at the next poll.
//!
//! The kernel multicasts every nftables change on `NFNLGRP_NFTABLES`, and
//! this listens to that group directly. Only table, chain and rule changes
//! outside our own tables matter; set and element churn (crowdsec updates
//! its blocklist sets constantly) is ignored, and ignoring it costs one
//! comparison on the message type. Events arriving in a burst are debounced
//! into one reconcile. The poll tick remains the safety net for everything
//! this can't see: legacy iptables (not nftables at all), a socket that
//! died, events the kernel dropped.
//!
//! This used to be an `nft -j monitor` child whose lines were parsed as
//! JSON. What that cost was not the parsing (PLAN.md #131) but the child:
//! `nft monitor` builds the whole ruleset cache — every element of every
//! set — at startup and holds it, which on a host running crowdsec and
//! geoip-shell was 118 MB against a measured 11 MB for the same work here,
//! and it is the one cost that grew with someone else's blocklists. A
//! socket and a 64 KB buffer do not grow.
//!
//! What is read out of a message is deliberately the least that decides the
//! question: the type, one byte of family, and the table's name. Everything
//! else — a rule's expressions, an element's key — is walked past. The
//! constants come from `linux/netfilter/nfnetlink.h` and
//! `linux/netfilter/nf_tables.h`; they are UAPI, so they are fixed, and
//! `kernel_the_listener_sees_what_the_planner_needs` pins them against a
//! real kernel rather than against this comment.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};

use netlink_sys::{constants::NETLINK_NETFILTER, Socket, SocketAddr};

use super::model::{is_own_table, Family};

/// `NFNLGRP_NFTABLES` — the group every nftables change is multicast on.
const NFNLGRP_NFTABLES: u32 = 7;
/// `NFNL_SUBSYS_NFTABLES`: the high byte of every message type we want.
const NFNL_SUBSYS_NFTABLES: u16 = 10;
/// `enum nf_tables_msg_types`, the six that change what the planner reads.
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_DELCHAIN: u16 = 5;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_DELRULE: u16 = 8;
/// `NFTA_TABLE_NAME`, `NFTA_CHAIN_TABLE` and `NFTA_RULE_TABLE` are all
/// attribute 1: a table's message names itself, a chain's and a rule's
/// name the table they are in, and either way it is what we filter on.
const NFTA_TABLE: u16 = 1;
/// `NLA_TYPE_MASK` — an attribute's type carries `NLA_F_NESTED` and
/// `NLA_F_NET_BYTEORDER` in its top bits.
const NLA_TYPE_MASK: u16 = 0x3fff;
/// `struct nlmsghdr`, then `struct nfgenmsg`.
const NLMSG_HDRLEN: usize = 16;
const NFGENMSG_LEN: usize = 4;

/// Big enough for any single notification, and the buffer is the only
/// memory this holds.
const BUF: usize = 64 * 1024;
/// What the socket is asked to hold while we are between reads. A
/// blocklist reload is tens of thousands of messages we drop on sight, but
/// they still have to fit until we get to them (see `ENOBUFS` below).
const RX_BUF: usize = 8 * 1024 * 1024;
/// How often a blocked read gives way so a stopped monitor can notice.
const POLL: Duration = Duration::from_millis(250);

/// Should this netlink message trigger a reconcile for `ifname`?
///
/// Changes outside our own tables, and deletions inside `ifname`'s own
/// deny table: a `flush ruleset` or `flush chain` shows up as exactly
/// those, and the reconcile is what restores the table (see the module
/// doc of `host_interop`). Our own per-poll replace deletes too, which
/// costs one reconcile that finds everything in place. Other agents'
/// tables stay ignored: reacting to each other's polls would have them
/// reconciling in response to one another.
#[must_use]
pub fn is_relevant(message: &[u8], ifname: &str) -> bool {
    let Some(event) = Event::parse(message) else {
        return false; // sets, elements, generations, other subsystems, …
    };
    let our_deny_table_lost_something =
        event.deleted && event.table == crate::firewall::nftables::table_name(ifname);
    !is_own_table(event.table) || our_deny_table_lost_something
}

/// True if any message in one datagram is relevant. The kernel may pack
/// several into one read.
#[must_use]
pub fn any_relevant(datagram: &[u8], ifname: &str) -> bool {
    let mut rest = datagram;
    while rest.len() >= NLMSG_HDRLEN {
        let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if len < NLMSG_HDRLEN || len > rest.len() {
            return false; // truncated: the caller has already treated it as a change
        }
        if is_relevant(&rest[..len], ifname) {
            return true;
        }
        let advance = (len + 3) & !3;
        if advance >= rest.len() {
            return false;
        }
        rest = &rest[advance..];
    }
    false
}

/// The three things a message has to say for this filter to have an
/// opinion about it.
struct Event<'a> {
    deleted: bool,
    table: &'a str,
}

impl<'a> Event<'a> {
    /// `None` for a message this filter has no use for — another
    /// subsystem's, another object kind's, a family that carries no IP
    /// traffic through an INPUT hook, or one too short to be either.
    fn parse(message: &'a [u8]) -> Option<Self> {
        let body = message.get(NLMSG_HDRLEN..)?;
        let kind = u16::from_ne_bytes([*message.get(4)?, *message.get(5)?]);
        if kind >> 8 != NFNL_SUBSYS_NFTABLES {
            return None;
        }
        let deleted = match kind & 0xff {
            NFT_MSG_NEWTABLE | NFT_MSG_NEWCHAIN | NFT_MSG_NEWRULE => false,
            NFT_MSG_DELTABLE | NFT_MSG_DELCHAIN | NFT_MSG_DELRULE => true,
            _ => return None,
        };
        // `struct nfgenmsg`: the family is its first byte.
        family(*body.first()?)?;
        let name = attribute(body.get(NFGENMSG_LEN..)?, NFTA_TABLE)?;
        // The kernel's strings are NUL-terminated, terminator included in
        // the attribute's length.
        let name = name.split(|b| *b == 0).next()?;
        Some(Self {
            deleted,
            table: std::str::from_utf8(name).ok()?,
        })
    }
}

/// `NFPROTO_*` for the families that carry IP traffic through an INPUT
/// hook — the same three [`Family`] names, which is what `ruleset` reads
/// out of a listing. `arp`, `bridge` and `netdev` are never touched.
fn family(nfproto: u8) -> Option<Family> {
    match nfproto {
        1 => Some(Family::Inet),
        2 => Some(Family::Ip),
        10 => Some(Family::Ip6),
        _ => None,
    }
}

/// The payload of the first attribute of type `want`, walking the
/// netlink TLVs. Every length is checked against what is left, so a
/// truncated or malformed message ends the walk instead of reading past
/// it.
fn attribute(mut attrs: &[u8], want: u16) -> Option<&[u8]> {
    while attrs.len() >= 4 {
        let len = u16::from_ne_bytes([attrs[0], attrs[1]]) as usize;
        let kind = u16::from_ne_bytes([attrs[2], attrs[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > attrs.len() {
            return None;
        }
        if kind == want {
            return Some(&attrs[4..len]);
        }
        let advance = (len + 3) & !3;
        if advance >= attrs.len() {
            return None;
        }
        attrs = &attrs[advance..];
    }
    None
}

/// A listener on the kernel's nftables event group. Its thread forwards
/// relevant events as `on_event()` messages and sends `on_exit()` if the
/// socket stops working; dropping this stops the thread.
pub struct Monitor {
    stop: Arc<AtomicBool>,
}

impl Monitor {
    /// Binds the socket before returning, so a change made after this call
    /// is queued for us even if the thread has not reached its first read.
    pub fn spawn<M: Send + 'static>(
        ifname: &str,
        tx: Sender<M>,
        on_event: fn() -> M,
        on_exit: fn() -> M,
    ) -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.bind(&SocketAddr::new(0, 0))?;
        socket.add_membership(NFNLGRP_NFTABLES)?;
        // Both best-effort: a smaller receive buffer only means more
        // dropped events, which `ENOBUFS` below turns into a reconcile.
        if let Err(e) = socket.set_rx_buf_sz(RX_BUF) {
            tracing::debug!(error = %e, "could not enlarge the nftables event socket's buffer");
        }
        set_read_timeout(&socket, POLL)?;

        let stop = Arc::new(AtomicBool::new(false));
        let ifname = ifname.to_string();
        let theirs = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("nft-monitor".into())
            .spawn(move || {
                if read_events(&socket, &ifname, &tx, on_event, &theirs).is_err() {
                    let _ = tx.send(on_exit());
                }
            })?;
        Ok(Self { stop })
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        // The thread owns the socket and closes it on its way out, within
        // one `POLL`. Nothing waits for that: it only ever sends on a
        // channel, and a send to a gone receiver ends it too.
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Reads until the socket fails or `stop` is set. `Ok(())` means stopped;
/// `Err` means the socket is no longer usable and the caller should say so.
fn read_events<M>(
    socket: &Socket,
    ifname: &str,
    tx: &Sender<M>,
    on_event: fn() -> M,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut buf = vec![0u8; BUF];
    let mut told_enobufs = false;
    while !stop.load(Ordering::Relaxed) {
        let changed = match recv(socket, &mut buf) {
            // Bigger than our buffer: rather than guess at what was cut
            // off, treat it as a change and let the reconcile look.
            Ok(n) if n > buf.len() => true,
            Ok(n) => any_relevant(&buf[..n], ifname),
            Err(e) if would_block(&e) => continue,
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                // The kernel dropped events because we were behind — a
                // blocklist reload is tens of thousands of messages. What
                // was lost is unknown, so reconcile rather than assume.
                if !std::mem::replace(&mut told_enobufs, true) {
                    tracing::warn!("the kernel dropped nftables events; reconciling in case one was ours");
                }
                true
            }
            Err(e) => return Err(e),
        };
        if changed && tx.send(on_event()).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

/// `MSG_TRUNC` so a message larger than `buf` reports its real size
/// instead of arriving silently cut short.
fn recv(socket: &Socket, buf: &mut [u8]) -> io::Result<usize> {
    let read = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            libc::MSG_TRUNC,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(read as usize)
}

fn would_block(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EAGAIN | libc::EINTR))
        || e.kind() == io::ErrorKind::WouldBlock
}

/// So a blocked read gives way often enough for [`Monitor::drop`] to be
/// noticed, without a second file descriptor to wake it.
fn set_read_timeout(socket: &Socket, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: libc::suseconds_t::from(timeout.subsec_micros()),
    };
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if set < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Collapses a burst of events into one action `delay` after the last.
#[derive(Debug)]
pub struct Debouncer {
    delay: Duration,
    deadline: Option<Instant>,
}

impl Debouncer {
    #[must_use]
    pub fn new(delay: Duration) -> Self {
        Self { delay, deadline: None }
    }

    pub fn event(&mut self, now: Instant) {
        self.deadline = Some(now + self.delay);
    }

    /// How long until something is due, if anything is pending.
    #[must_use]
    pub fn wait(&self, now: Instant) -> Option<Duration> {
        self.deadline.map(|d| d.saturating_duration_since(now))
    }

    /// True (once) when the pending action is due.
    pub fn take_due(&mut self, now: Instant) -> bool {
        match self.deadline {
            Some(d) if d <= now => {
                self.deadline = None;
                true
            }
            _ => false,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// One message as the kernel sends it: `struct nlmsghdr`, then
    /// `struct nfgenmsg`, then attributes. `attrs` are `(type, payload)`
    /// pairs, each padded to four bytes like the kernel pads them.
    fn message(kind: u16, family: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; NLMSG_HDRLEN];
        m[4..6].copy_from_slice(&((NFNL_SUBSYS_NFTABLES << 8) | kind).to_ne_bytes());
        m.extend_from_slice(&[family, 0, 0, 0]); // family, version, res_id
        for (kind, payload) in attrs {
            let len = 4 + payload.len();
            m.extend_from_slice(&(len as u16).to_ne_bytes());
            m.extend_from_slice(&kind.to_ne_bytes());
            m.extend_from_slice(payload);
            m.resize(m.len().div_ceil(4) * 4, 0);
        }
        let len = m.len() as u32;
        m[..4].copy_from_slice(&len.to_ne_bytes());
        m
    }

    /// The common case: a change to `table`, named the way a table's own
    /// message and a chain's or rule's message both name it.
    fn event(kind: u16, family: u8, table: &str) -> Vec<u8> {
        let mut name = table.as_bytes().to_vec();
        name.push(0);
        message(kind, family, &[(NFTA_TABLE, &name)])
    }

    const INET: u8 = 1;
    const IPV4: u8 = 2;
    const IPV6: u8 = 10;
    const ARP: u8 = 3;
    const BRIDGE: u8 = 7;

    #[test]
    fn foreign_table_chain_and_rule_changes_are_relevant() {
        for (kind, family) in [
            (NFT_MSG_NEWTABLE, IPV4),
            (NFT_MSG_DELTABLE, INET),
            (NFT_MSG_NEWCHAIN, INET),
            (NFT_MSG_DELCHAIN, IPV6),
            (NFT_MSG_NEWRULE, INET),
            (NFT_MSG_DELRULE, IPV4),
        ] {
            assert!(is_relevant(&event(kind, family, "filter"), "wg0"), "{kind} {family}");
        }
        // A table whose name merely starts like ours is not ours.
        assert!(is_relevant(&event(NFT_MSG_NEWTABLE, INET, "wireservex"), "wg0"));
    }

    #[test]
    fn set_churn_our_own_tables_and_other_families_are_ignored() {
        // Set and element messages: the churn this filter exists to not
        // care about. 9/11 are NEWSET/DELSET, 12/14 NEWSETELEM/DELSETELEM,
        // 15 NEWGEN — one per transaction, and it names no table.
        for kind in [9u16, 11, 12, 14, 15] {
            assert!(!is_relevant(&event(kind, INET, "crowdsec"), "wg0"), "message type {kind}");
        }
        // Families that carry no IP traffic through an INPUT hook.
        for family in [ARP, BRIDGE, 5 /* netdev */, 0 /* unspec */] {
            assert!(!is_relevant(&event(NFT_MSG_NEWRULE, family, "filter"), "wg0"), "family {family}");
        }
        // Our own tables, and another agent's: reacting to each other's
        // polls would have two agents reconciling in response to one
        // another for ever.
        for table in ["wireserve.wg0", "wireserve-interop.wg0", "wireserve.wireserve1", "wireserve-interop.wireserve1"] {
            assert!(!is_relevant(&event(NFT_MSG_NEWRULE, INET, table), "wg0"), "{table}");
        }
        // Another subsystem's message on the same socket.
        let mut conntrack = event(NFT_MSG_NEWRULE, INET, "filter");
        let conntrack_subsys = 1u16 << 8; // NFNL_SUBSYS_CTNETLINK, message type 0
        conntrack[4..6].copy_from_slice(&conntrack_subsys.to_ne_bytes());
        assert!(!is_relevant(&conntrack, "wg0"));
    }

    #[test]
    fn a_deletion_in_our_own_deny_table_is_relevant_to_us_alone() {
        // What `flush ruleset` and `flush chain` look like from here: our
        // table losing its rule, its chain, itself.
        for kind in [NFT_MSG_DELRULE, NFT_MSG_DELCHAIN, NFT_MSG_DELTABLE] {
            let lost = event(kind, INET, "wireserve.wg0");
            assert!(is_relevant(&lost, "wg0"), "{kind}");
            assert!(!is_relevant(&lost, "wireserve1"), "another agent's table is not ours to restore");
        }
        assert!(
            !is_relevant(&event(NFT_MSG_NEWRULE, INET, "wireserve.wg0"), "wg0"),
            "our own table being written is no news"
        );
    }

    #[test]
    fn the_table_name_is_found_after_other_attributes() {
        let mut name = b"filter".to_vec();
        name.push(0);
        let m = message(
            NFT_MSG_NEWRULE,
            INET,
            &[
                (7, &[1, 2, 3]),                 // something we don't read, oddly sized
                (NFTA_TABLE | 0x8000, &name),    // and NLA_F_NESTED set on the one we do
            ],
        );
        assert!(is_relevant(&m, "wg0"), "the walk must skip what it does not want");
    }

    #[test]
    fn garbage_is_ignored() {
        let good = event(NFT_MSG_NEWRULE, INET, "filter");
        assert!(is_relevant(&good, "wg0"));
        // Every truncation of a message that was fine.
        for cut in 0..good.len() {
            let _ = is_relevant(&good[..cut], "wg0"); // must not panic
        }
        assert!(!is_relevant(&[], "wg0"));
        assert!(!is_relevant(&good[..NLMSG_HDRLEN], "wg0"), "a header with no body says nothing");
        // An attribute claiming to be longer than what is left.
        let mut lying = good.clone();
        let attr = NLMSG_HDRLEN + NFGENMSG_LEN;
        lying[attr..attr + 2].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert!(!is_relevant(&lying, "wg0"));
        // A zero-length attribute, which would otherwise walk in place.
        let mut empty = good.clone();
        empty[attr..attr + 2].copy_from_slice(&0u16.to_ne_bytes());
        assert!(!is_relevant(&empty, "wg0"));
        // A name that is not UTF-8.
        assert!(!is_relevant(&message(NFT_MSG_NEWRULE, INET, &[(NFTA_TABLE, &[0xff, 0xfe, 0])]), "wg0"));
    }

    #[test]
    fn several_messages_in_one_datagram() {
        let mut packed = event(NFT_MSG_NEWSETELEM_FOR_TEST, INET, "crowdsec");
        packed.extend_from_slice(&event(NFT_MSG_NEWRULE, INET, "filter"));
        assert!(any_relevant(&packed, "wg0"), "the second message is the interesting one");

        let mut dull = event(NFT_MSG_NEWSETELEM_FOR_TEST, INET, "crowdsec");
        dull.extend_from_slice(&event(NFT_MSG_NEWRULE, INET, "wireserve.wg0"));
        assert!(!any_relevant(&dull, "wg0"));
    }

    /// `NFT_MSG_NEWSETELEM`, which this module never names because it only
    /// ever needs to not match.
    const NFT_MSG_NEWSETELEM_FOR_TEST: u16 = 12;

    /// A blocklist reload is tens of thousands of these, and deciding to
    /// drop one must not allocate: that is the whole point of reading the
    /// message rather than a rendering of it.
    #[test]
    fn dropping_an_element_event_allocates_nothing() {
        let churn: Vec<Vec<u8>> = (0..1000).map(|_| event(NFT_MSG_NEWSETELEM_FOR_TEST, INET, "crowdsec")).collect();
        let mut any = true;
        let used = crate::test_alloc::allocated(|| any = churn.iter().any(|m| is_relevant(m, "wg0")));
        assert!(!any);
        assert_eq!(used, 0, "reading a message must not allocate");
    }

    #[test]
    fn debouncer_collapses_a_burst_into_one_action_after_the_last_event() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut d = Debouncer::new(ms(500));
        assert_eq!(d.wait(t0), None);
        assert!(!d.take_due(t0));

        for i in 0..10 {
            d.event(t0 + ms(i * 100)); // last event at +900ms
        }
        assert!(!d.take_due(t0 + ms(1300)), "not due until 500ms after the LAST event");
        assert_eq!(d.wait(t0 + ms(1300)), Some(ms(100)));
        assert!(d.take_due(t0 + ms(1400)));
        assert!(!d.take_due(t0 + ms(5000)), "fires once");
        assert_eq!(d.wait(t0 + ms(5000)), None);
    }

    /// The listener against a real kernel: the same changes the
    /// `nft -j monitor` version of this test made, seen through our own
    /// socket. This is what pins the constants — a wrong group, subsystem,
    /// message type, family byte or attribute id shows up here as a count
    /// that is not three.
    #[test]
    fn kernel_the_listener_sees_what_the_planner_needs() {
        if !crate::firewall::netns::reexec("firewall::host_interop::monitor::tests::kernel_the_listener_sees_what_the_planner_needs") {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let monitor = Monitor::spawn("wg0", tx, || "changed", || "exited").expect("the event socket opens");

        let out = std::process::Command::new("sh")
            .args([
                "-euc",
                "nft add table inet wireserve.wg0\n\
                 nft add table ip crowdsec\n\
                 nft add set ip crowdsec s '{ type ipv4_addr; }'\n\
                 nft add element ip crowdsec s '{ 1.2.3.4 }'\n\
                 nft add table inet filter\n\
                 nft add chain inet filter input '{ type filter hook input priority 0; }'\n\
                 nft add table bridge br\n",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        // Drain until the kernel goes quiet: the crowdsec table, the filter
        // table and its chain — and nothing for our own table, the set, the
        // element or the bridge family.
        let mut seen = Vec::new();
        while let Ok(what) = rx.recv_timeout(Duration::from_millis(500)) {
            seen.push(what);
        }
        assert_eq!(seen, ["changed", "changed", "changed"], "one per foreign table/chain change");

        drop(monitor);
        // The thread stops on its own; nothing may arrive after it has.
        std::thread::sleep(POLL * 2);
        let out = std::process::Command::new("sh")
            .args(["-euc", "nft add table inet late"])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "a dropped monitor is silent");
    }
}
