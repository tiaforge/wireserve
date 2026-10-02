//! Linux v1 `FirewallBackend` — nftables via the `nft` binary's JSON API
//! (spec §5; see `firewall/nft.rs` for why this is no longer netlink via
//! `rustables`).

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use std::net::Ipv4Addr;

use nftables::expr::{
    BinaryOperation, CTDir, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix, Range, SetItem, CT,
};
use nftables::schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Rule, Table};
use nftables::stmt::{Accept, Drop, Limit, Mangle, Match, NATFamily, Operator, Reject, RejectType, Statement, NAT};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use wireserve_types::{FirewallBackend, Forwarding, PortMap, Proto, PublicRelay, RelayForward, ServiceRule, Sources};

use super::nft::{Nft, NftError};

/// Our table is `inet wireserve.<ifname>`: one per interface, so several
/// agents on one host each replace and remove only their own.
pub const TABLE_PREFIX: &str = "wireserve.";
pub(crate) const CHAIN_NAME: &str = "wireserve-in";
pub(crate) const FORWARD_CHAIN: &str = "wireserve-fwd";
const PRE_CHAIN: &str = "svc-pre";
const OUT_CHAIN: &str = "svc-out";
const MARK_PRE_CHAIN: &str = "svc-mark-pre";
const MARK_OUT_CHAIN: &str = "svc-mark-out";
const REV_POST_CHAIN: &str = "svc-rev-post";
const REV_IN_CHAIN: &str = "svc-rev-in";
const MASQ_CHAIN: &str = "svc-masq";
const EXIT_MARK_CHAIN: &str = "exit-mark";
const EXIT_MASQ_CHAIN: &str = "exit-masq";
const RELAY_PRE_CHAIN: &str = "relay-pre";
const RELAY_POST_CHAIN: &str = "relay-post";

/// Before conntrack (-200): the rewrite must happen before a connection
/// is ever tracked, so that the tracked connection is the rewritten one.
const PRIO_RAW: i32 = -300;
/// After conntrack, so the flow exists to carry the mark.
const PRIO_MANGLE: i32 = -150;
/// After source NAT (100), where a container runtime restores its reply.
const PRIO_AFTER_NAT: i32 = 300;
/// Source NAT itself.
const PRIO_SRCNAT: i32 = 100;
/// Destination NAT.
const PRIO_DSTNAT: i32 = -100;

/// The packet and conntrack mark bit that says "this flow came in through
/// a service address". One bit, always set and tested under a mask, so
/// it coexists with other users of the mark — deliberately outside
/// Tailscale's `0xff0000`, Kubernetes' `0x4000`/`0x8000` and Cilium's
/// `0xf00`. Several agents on one host share it safely: every rule that
/// acts on it also matches its own interface or its own node address.
pub const SERVICE_MARK: u32 = 0x0100_0000;

/// The conntrack mark bit that says "this flow is an exit client's, headed
/// for the internet" (PLAN.md M27). Its own bit rather than
/// [`SERVICE_MARK`]: a service may map onto a public address (M26), and the
/// reply rewrite for it matches that address and port under the service
/// bit, so an exit flow to the same address and port sharing the bit would
/// have its replies rewritten to look like they came from the service.
pub const EXIT_MARK: u32 = 0x0200_0000;

/// The conntrack mark bit that says "this flow is a phone's session,
/// relayed from this node's public address to another node" (PLAN.md M40).
/// Its own bit, like [`EXIT_MARK`]: the host firewalls are opened for
/// exactly these flows, and the guard on the public interface lets them in.
pub const RELAY_MARK: u32 = 0x0400_0000;

#[derive(Debug, thiserror::Error)]
pub enum NftablesError {
    #[error("nftables error: {0}")]
    Nft(#[from] NftError),
    /// The kernel refused to let us rewrite packet headers, which service
    /// addresses depend on: it does that in any network namespace owned
    /// by a user namespace other than the host's own ("netfilter: disable
    /// payload mangling in userns") — an unprivileged LXC container, say,
    /// or rootless podman.
    #[error(
        "the kernel refused the service-address rewrite rules (EPERM): packet rewriting only \
         works in the host's own user namespace, not in an unprivileged container — {0}"
    )]
    RewriteRefused(NftError),
}

#[must_use]
pub fn table_name(ifname: &str) -> String {
    format!("{TABLE_PREFIX}{ifname}")
}

/// The last ruleset [`NftablesBackend`] applied in full, shared with the
/// host-firewall interop so it can put our table back when something else
/// removes it (security review: `flush ruleset` from an nftables.service
/// reload deleted it, the interop re-opened the host firewall for the
/// interface within a second, and nothing restored the deny until the
/// next successful poll — never, while the coordinator was unreachable).
///
/// The lock is held across every apply, restore and teardown, never just
/// the read: a restore that read the previous ruleset while a poll was
/// applying the next could otherwise put the older one back over it.
pub type SharedRuleset = Arc<Mutex<Option<Nftables<'static>>>>;

/// Re-applies the ruleset in `shared`, if there is one. `Ok(false)` when
/// nothing has been applied yet or the backend was torn down.
pub fn restore(nft: &Nft, shared: &SharedRuleset) -> Result<bool, NftError> {
    let last = shared.lock().unwrap_or_else(|e| e.into_inner());
    match last.as_ref() {
        Some(batch) => nft.apply(batch).map(|()| true),
        None => Ok(false),
    }
}

pub struct NftablesBackend {
    /// The WireGuard interface every rule is scoped to — this backend must
    /// never install a rule that isn't `iifname`-restricted to it, or it
    /// would be firewalling the whole host rather than just the mesh.
    ifname: String,
    /// The carry interface (PLAN.md M39), which gets a table of its own
    /// with the same default-deny and the same service rules.
    carry: Option<String>,
    nft: Nft,
    last: SharedRuleset,
}

impl NftablesBackend {
    /// Fails if `nft` can't be found: the firewall is not optional, so a
    /// daemon without one must refuse to start rather than run open.
    pub fn new(ifname: impl Into<String>) -> Result<Self, NftablesError> {
        Ok(Self {
            ifname: ifname.into(),
            carry: None,
            nft: Nft::locate()?,
            last: SharedRuleset::default(),
        })
    }

    /// Also firewalls the carry interface `carry` (PLAN.md M39). Set before
    /// the first apply, so the interface is default-denied before it exists.
    #[must_use]
    pub fn with_carry(mut self, carry: Option<String>) -> Self {
        self.carry = carry;
        self
    }

    /// The handle the host-firewall interop restores our table from.
    #[must_use]
    pub fn last_applied(&self) -> SharedRuleset {
        Arc::clone(&self.last)
    }
}

fn table(name: &str) -> Table<'static> {
    Table {
        family: NfFamily::INet,
        name: Cow::Owned(name.to_string()),
        handle: None,
    }
}

/// "Delete the table `name` if it exists", as two commands inside one
/// transaction: adding a table that already exists is a no-op, so the
/// delete that follows always has something to remove. This is the
/// standard nft idiom for an unconditional atomic replace — no separate
/// existence check, and no window in which the old and new rulesets are
/// both partially applied.
fn delete_table_cmds(name: &str) -> [NfObject<'static>; 2] {
    [
        NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table(name)))),
        NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(table(name)))),
    ]
}

fn iifname_is(ifname: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Iifname,
        })),
        right: Expression::String(Cow::Owned(ifname.to_string())),
        op: Operator::EQ,
    })
}

/// `ct state { established, related }`. RELATED alongside ESTABLISHED:
/// ICMP errors tied to a tracked flow — packet-too-big for path MTU
/// discovery in particular, which WireGuard's reduced MTU makes routine — are
/// RELATED and would otherwise be dropped.
fn established_or_related() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::CT(CT {
            key: "state".into(),
            family: None,
            dir: None,
        })),
        right: Expression::List(vec![
            Expression::String("established".into()),
            Expression::String("related".into()),
        ]),
        op: Operator::IN,
    })
}

fn l4(proto: Proto) -> &'static str {
    match proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

fn payload(protocol: &'static str, field: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField {
        protocol: protocol.into(),
        field: field.into(),
    })))
}

fn meta(key: MetaKey) -> Expression<'static> {
    Expression::Named(NamedExpression::Meta(Meta { key }))
}

fn ct(key: &'static str, dir: Option<CTDir>) -> Expression<'static> {
    Expression::Named(NamedExpression::CT(CT {
        key: key.into(),
        family: None,
        dir,
    }))
}


fn addr(ip: Ipv4Addr) -> Expression<'static> {
    Expression::String(Cow::Owned(ip.to_string()))
}

/// `<left> in { values... }` — an anonymous nft *set* literal
/// (`NamedExpression::Set`), not `Expression::List`: nft's JSON grammar
/// only accepts a bare array for a bitmask/flags-typed field (`ct state`,
/// used by `established_or_related` above); for an address-typed field it
/// refuses a bare array with "Basetype of type IPv4 address is not
/// bitmask" — caught by `kernel_accepts_a_transit_pairs_ruleset` against
/// a real kernel, not assumed from documentation.
fn in_list(left: Expression<'static>, values: Vec<Expression<'static>>) -> Statement<'static> {
    Statement::Match(Match {
        left,
        right: Expression::Named(NamedExpression::Set(values.into_iter().map(SetItem::Element).collect())),
        op: Operator::IN,
    })
}

fn is(left: Expression<'static>, right: Expression<'static>) -> Statement<'static> {
    Statement::Match(Match {
        left,
        right,
        op: Operator::EQ,
    })
}

fn set(key: Expression<'static>, value: Expression<'static>) -> Statement<'static> {
    Statement::Mangle(Mangle { key, value })
}

/// `<key> & MARK == MARK`: the flow (or packet) is one of ours.
fn has_mark(key: Expression<'static>) -> Statement<'static> {
    is(
        Expression::BinaryOperation(Box::new(BinaryOperation::AND(key, Expression::Number(SERVICE_MARK)))),
        Expression::Number(SERVICE_MARK),
    )
}

/// `<key> set <key> | MARK`: ours, without disturbing anyone else's bits.
fn add_mark(key: Expression<'static>) -> Statement<'static> {
    set(
        key.clone(),
        Expression::BinaryOperation(Box::new(BinaryOperation::OR(vec![key, Expression::Number(SERVICE_MARK)]))),
    )
}

/// `<key> & MARK != MARK`: not one of ours.
fn lacks_mark(key: Expression<'static>) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::BinaryOperation(Box::new(BinaryOperation::AND(key, Expression::Number(SERVICE_MARK)))),
        right: Expression::Number(SERVICE_MARK),
        op: Operator::NEQ,
    })
}

/// `<key> & BIT == BIT`, for a bit other than the service mark.
fn has_bit(key: Expression<'static>, bit: u32) -> Statement<'static> {
    is(
        Expression::BinaryOperation(Box::new(BinaryOperation::AND(key, Expression::Number(bit)))),
        Expression::Number(bit),
    )
}

/// `<key> set <key> | BIT`, for a bit other than the service mark.
fn add_bit(key: Expression<'static>, bit: u32) -> Statement<'static> {
    set(
        key.clone(),
        Expression::BinaryOperation(Box::new(BinaryOperation::OR(vec![key, Expression::Number(bit)]))),
    )
}

/// `<key> & BITS == 0`: none of these bits. What the guard drops on.
fn lacks_bits(key: Expression<'static>, bits: u32) -> Statement<'static> {
    is(
        Expression::BinaryOperation(Box::new(BinaryOperation::AND(key, Expression::Number(bits)))),
        Expression::Number(0),
    )
}

/// `meta l4proto tcp reject with tcp reset`: a TCP connection to a port
/// nothing answers on is refused at once rather than left to time out. A
/// browser that tries HTTPS first on a service published only on 80 falls
/// back to HTTP as soon as it is refused, and only after a long wait when
/// the SYN is dropped. Only TCP: a mesh peer learns "closed" rather than
/// "filtered" and nothing more, one reset per packet it sent, sent back to
/// the address WireGuard already authenticated it by.
fn refuse_tcp() -> [Statement<'static>; 2] {
    [
        is(meta(MetaKey::L4proto), Expression::String("tcp".into())),
        Statement::Reject(Some(Reject::new(Some(RejectType::TCPReset), None))),
    ]
}

fn iifname_is_not(ifname: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: meta(MetaKey::Iifname),
        right: Expression::String(Cow::Owned(ifname.to_string())),
        op: Operator::NEQ,
    })
}

fn oifname_is(ifname: &str) -> Statement<'static> {
    is(meta(MetaKey::Oifname), Expression::String(Cow::Owned(ifname.to_string())))
}

fn oifname_is_not(ifname: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: meta(MetaKey::Oifname),
        right: Expression::String(Cow::Owned(ifname.to_string())),
        op: Operator::NEQ,
    })
}

fn prefix(ip: Ipv4Addr, len: u32) -> Expression<'static> {
    Expression::Named(NamedExpression::Prefix(Prefix { addr: Box::new(addr(ip)), len }))
}

/// The exit's own chains (PLAN.md M27), or nothing. A new flow from one of
/// the exit clients to anywhere outside `NOT_THE_INTERNET_V4` and the mesh is
/// marked with [`EXIT_MARK`] once conntrack exists, and masqueraded on its
/// way out of any interface but the mesh's.
///
/// Marked in prerouting rather than in our forward chain because the mark
/// is what the host's *other* firewalls are opened for (host interop's exit
/// openings), and their FORWARD chains run at the same priority as ours, in
/// no promised order. A flow a service address already rewrote carries the
/// service bit and is left to that path.
fn exit_chains(t: &str, ifname: &str, forwarding: &Forwarding) -> Vec<NfObject<'static>> {
    let Some((mesh, mesh_len)) = forwarding.mesh_v4 else {
        return Vec::new();
    };
    if forwarding.exit.is_empty() {
        return Vec::new();
    }
    let not_internet: Vec<SetItem<'static>> = wireserve_types::NOT_THE_INTERNET_V4
        .iter()
        .copied()
        .chain(std::iter::once((mesh, mesh_len)))
        .map(|(ip, len)| SetItem::Element(prefix(ip, u32::from(len))))
        .collect();
    vec![
        chain(t, EXIT_MARK_CHAIN, NfChainType::Filter, NfHook::Prerouting, PRIO_MANGLE),
        rule(t, EXIT_MARK_CHAIN, vec![
            iifname_is(ifname),
            in_list(payload("ip", "saddr"), forwarding.exit.iter().map(|a| addr(*a)).collect()),
            Statement::Match(Match {
                left: ct("state", None),
                right: Expression::List(vec![Expression::String("new".into())]),
                op: Operator::IN,
            }),
            lacks_mark(meta(MetaKey::Mark)),
            Statement::Match(Match {
                left: payload("ip", "daddr"),
                right: Expression::Named(NamedExpression::Set(not_internet)),
                op: Operator::NEQ,
            }),
            add_bit(ct("mark", None), EXIT_MARK),
        ]),
        chain(t, EXIT_MASQ_CHAIN, NfChainType::NAT, NfHook::Postrouting, PRIO_SRCNAT),
        rule(t, EXIT_MASQ_CHAIN, vec![
            has_bit(ct("mark", None), EXIT_MARK),
            oifname_is_not(ifname),
            Statement::Masquerade(None::<NAT>),
        ]),
    ]
}

fn dport_is(proto: Proto, port: u16) -> Statement<'static> {
    is(payload(l4(proto), "dport"), Expression::Number(u32::from(port)))
}

/// Marks a packet bound for a service's public port on its address and
/// rewrites it to the target port on `dest` — the node's own address, or
/// the mapping's target address — all before conntrack has seen it.
/// Shared by the packets arriving from the mesh and the node's own (see
/// `apply_batch`).
fn forward_rewrite(vip: Ipv4Addr, dest: Ipv4Addr, map: &PortMap) -> Vec<Statement<'static>> {
    vec![
        is(payload("ip", "daddr"), addr(vip)),
        dport_is(map.proto, map.public),
        set(payload("ip", "daddr"), addr(dest)),
        set(payload(l4(map.proto), "dport"), Expression::Number(u32::from(map.target))),
        add_mark(meta(MetaKey::Mark)),
    ]
}

/// The mapping a service this node's own terminator answers (PLAN.md M33)
/// amounts to: its public port on its address to `port`, where the
/// terminator listens on every address (PLAN.md M35) — the address itself
/// kept, since the terminator tells its services apart by it. With this the
/// rest of the machinery treats it as any other mapping: marked, which the
/// filter's accept and the host firewalls' openings (`host_interop`) key
/// on, and rewritten back on the way out.
fn terminated_map(map: &PortMap, port: u16) -> PortMap {
    PortMap { target: port, addr: None, ..*map }
}

/// The way back: a reply leaving the target port of a marked flow gets
/// the service's address and public port again, so the client sees the
/// answer come from where it sent the request.
fn reverse_rewrite(vip: Ipv4Addr, dest: Ipv4Addr, map: &PortMap) -> Vec<Statement<'static>> {
    vec![
        is(ct("direction", None), Expression::String("reply".into())),
        has_mark(ct("mark", None)),
        is(payload("ip", "saddr"), addr(dest)),
        is(payload(l4(map.proto), "sport"), Expression::Number(u32::from(map.target))),
        set(payload("ip", "saddr"), addr(vip)),
        set(payload(l4(map.proto), "sport"), Expression::Number(u32::from(map.public))),
    ]
}

/// End-to-end relaying (PLAN.md M39): this node forwards a pair's WireGuard
/// session, which it cannot read, between their carry interfaces. For each
/// direction, a packet from one side to this node's own mesh address at the
/// other side's relay port goes on to the other side's carry port, and
/// leaves from this node at the first side's relay port — the address the
/// other side dials this node at when it starts the session itself. So a
/// packet either side sends first finds the same tracked flow, whoever
/// started it, and each side always sees the other at one address and port.
///
/// Returns the nat chains' rules and the forward chain's accepts.
fn relay_rules(t: &str, ifname: &str, me: Ipv4Addr, pairs: &[RelayForward]) -> (Vec<NfObject<'static>>, Vec<NfObject<'static>>) {
    let mut nat = Vec::new();
    let mut fwd = Vec::new();
    let udp_dport = |port: u16| dport_is(Proto::Udp, port);
    let mut seen = std::collections::BTreeSet::new();
    for pair in pairs {
        for (from, to) in [(pair.a, pair.c), (pair.c, pair.a)] {
            if from.ip4 == to.ip4 || from.ip4 == me || to.ip4 == me || !seen.insert((from.ip4, to.ip4)) {
                continue;
            }
            nat.push(rule(t, RELAY_PRE_CHAIN, vec![
                iifname_is(ifname),
                is(payload("ip", "saddr"), addr(from.ip4)),
                is(payload("ip", "daddr"), addr(me)),
                udp_dport(to.relay_port),
                Statement::DNAT(Some(NAT {
                    addr: Some(addr(to.ip4)),
                    family: Some(NATFamily::IP),
                    port: Some(Expression::Number(u32::from(to.carry_port))),
                    flags: None,
                })),
            ]));
            nat.push(rule(t, RELAY_POST_CHAIN, vec![
                oifname_is(ifname),
                is(payload("ip", "saddr"), addr(from.ip4)),
                is(payload("ip", "daddr"), addr(to.ip4)),
                udp_dport(to.carry_port),
                Statement::SNAT(Some(NAT {
                    addr: Some(addr(me)),
                    family: Some(NATFamily::IP),
                    port: Some(Expression::Number(u32::from(from.relay_port))),
                    flags: None,
                })),
            ]));
            fwd.push(rule(t, FORWARD_CHAIN, vec![
                iifname_is(ifname),
                oifname_is(ifname),
                is(payload("ip", "saddr"), addr(from.ip4)),
                is(payload("ip", "daddr"), addr(to.ip4)),
                udp_dport(to.carry_port),
                Statement::Accept(None::<Accept>),
            ]));
        }
    }
    (nat, fwd)
}

fn port_range(lo: u16, hi: u16) -> Expression<'static> {
    Expression::Range(Box::new(Range { range: [Expression::Number(u32::from(lo)), Expression::Number(u32::from(hi))] }))
}

/// Phones relayed through this node's public address (PLAN.md M40): what
/// arrives on `public` at a node's relay port goes on to that node's own
/// WireGuard port, marked with [`RELAY_MARK`] and leaving from this node's
/// mesh address on a port of `phones` — a range, not one port, because a
/// phone that roams starts a new flow while its old one is still tracked.
/// Only new flows are rate-limited (a nat chain sees nothing else): past
/// the limit a packet isn't translated and meets the input drop for the
/// relay ports, so a flood from spoofed sources costs this node nothing it
/// forwards. WireGuard at the other end drops whatever no phone signed.
///
/// Returns the nat rules and the forward chain's rules for `public`.
fn public_relay_rules(
    t: &str,
    ifname: &str,
    public: &str,
    me: Ipv4Addr,
    relays: &[PublicRelay],
    phones: (u16, u16),
) -> (Vec<NfObject<'static>>, Vec<NfObject<'static>>) {
    let mut nat = Vec::new();
    let mut fwd = Vec::new();
    if relays.is_empty() || public == ifname {
        return (nat, fwd);
    }
    for r in relays {
        nat.push(rule(t, RELAY_PRE_CHAIN, vec![
            iifname_is(public),
            dport_is(Proto::Udp, r.port),
            Statement::Limit(Limit {
                rate: 200,
                rate_unit: None,
                per: Some("second".into()),
                burst: Some(400),
                burst_unit: None,
                inv: None,
            }),
            add_bit(ct("mark", None), RELAY_MARK),
            Statement::DNAT(Some(NAT {
                addr: Some(addr(r.to)),
                family: Some(NATFamily::IP),
                port: Some(Expression::Number(u32::from(r.to_port))),
                flags: None,
            })),
        ]));
        fwd.push(rule(t, FORWARD_CHAIN, vec![
            iifname_is(public),
            oifname_is(ifname),
            has_bit(ct("mark", None), RELAY_MARK),
            is(payload("ip", "daddr"), addr(r.to)),
            dport_is(Proto::Udp, r.to_port),
            Statement::Accept(None::<Accept>),
        ]));
    }
    // A flow whose relay has since gone: its phone still sends keepalives,
    // which would otherwise keep it forwarded for as long as it does.
    fwd.push(rule(t, FORWARD_CHAIN, vec![
        iifname_is(public),
        has_bit(ct("mark", None), RELAY_MARK),
        Statement::Drop(None::<Drop>),
    ]));
    nat.push(rule(t, RELAY_POST_CHAIN, vec![
        oifname_is(ifname),
        is(meta(MetaKey::L4proto), Expression::String("udp".into())),
        has_bit(ct("mark", None), RELAY_MARK),
        Statement::SNAT(Some(NAT {
            addr: Some(addr(me)),
            family: Some(NATFamily::IP),
            port: Some(port_range(phones.0, phones.1)),
            flags: None,
        })),
    ]));
    (nat, fwd)
}

/// A mapping onto another address (PLAN.md M26) leaves the node for that
/// address with the node's own address as its source: whatever answers
/// there — a router, a printer — has no route back into the mesh, and would
/// send its reply for a mesh client to its own default gateway instead.
/// Only the first packet of a flow passes a NAT chain, and that packet
/// still carries the mark the rewrite set. Never onto the mesh interface.
fn masquerade(ifname: &str, dest: Ipv4Addr, map: &PortMap) -> Vec<Statement<'static>> {
    vec![
        has_mark(meta(MetaKey::Mark)),
        is(payload("ip", "daddr"), addr(dest)),
        dport_is(map.proto, map.target),
        Statement::Match(Match {
            left: meta(MetaKey::Oifname),
            right: Expression::String(Cow::Owned(ifname.to_string())),
            op: Operator::NEQ,
        }),
        Statement::Masquerade(None::<NAT>),
    ]
}

fn chain(table: &str, name: &'static str, kind: NfChainType, hook: NfHook, prio: i32) -> NfObject<'static> {
    NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
        family: NfFamily::INet,
        table: Cow::Owned(table.to_string()),
        name: name.into(),
        _type: Some(kind),
        hook: Some(hook),
        prio: Some(prio),
        policy: Some(NfChainPolicy::Accept),
        ..Chain::default()
    })))
}

fn rule(table: &str, chain: &'static str, expr: Vec<Statement<'static>>) -> NfObject<'static> {
    NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
        family: NfFamily::INet,
        table: Cow::Owned(table.to_string()),
        chain: chain.into(),
        expr: expr.into(),
        handle: None,
        index: None,
        comment: None,
    })))
}

/// The whole transaction `apply` sends. Pure, so its exact shape is pinned
/// by tests without a kernel.
///
/// **Real bug found and fixed by an actual end-to-end deployment test**
/// (two agent containers + a coordinator, see PLAN.md decisions log):
/// this chain is a *base* chain hooked into netfilter's global INPUT path
/// — a base chain's own default policy applies to packets on *every*
/// interface, not just the ones its individual rules happen to
/// `iifname`-match. The original version set a `drop` policy, which
/// silently firewalled off **all** inbound traffic on every interface
/// (including the node's own outbound HTTP poll requests' return traffic
/// on its regular network interface) the moment the agent started — every
/// poll request hung in `SYN_SENT` forever, caught only by watching real
/// TCP state during a live test. Fixed by keeping the chain's own policy
/// at `accept` (safe for every non-WireGuard interface) and instead
/// scoping the actual deny behavior to an explicit final `iifname`
/// catch-all rule, so *only* traffic arriving on the WireGuard interface
/// is default-denied, per spec §5's actual intent. Every chain below
/// keeps that accept policy for the same reason.
///
/// Service addresses (`ServiceRule::Mapped`, PLAN.md M20) are rewritten,
/// not NATed. A connection gets one destination NAT per direction, and a
/// container runtime's published port is exactly such a NAT (netavark,
/// or Docker without its userland proxy): a DNAT of ours would be the
/// connection's only one and the runtime's would never run. So a request
/// has its address and port rewritten at raw priority, before conntrack
/// exists — conntrack, the runtime's NAT and the service all see an
/// ordinary `client → node:target` connection, the client's real address
/// included — and is marked; the mark is carried onto the flow, which is
/// what the filter accepts and what picks out the replies to rewrite
/// back once every NAT hook is done with them.
///
/// Rewriting headers needs the host's own user namespace: since the
/// "disable payload mangling in userns" hardening the kernel refuses it
/// with EPERM anywhere else (see `NftablesError::RewriteRefused`).
///
/// A mapping onto another address (PLAN.md M26) goes through the same
/// rewrite, with that address in place of the node's: the kernel then
/// routes the rewritten request out of the host, `svc-masq` gives it the
/// node's own source address, conntrack undoes that on the reply, and the
/// reply rewrite matches the target address as its source. Forwarding on
/// the interface the reply arrives on may have been turned on by the agent
/// for this alone (`Forwarding::guarded`); the forward chain then drops
/// everything arriving there that is not part of one of our flows.
#[cfg(test)]
pub(crate) fn apply_batch(ifname: &str, rules: &[ServiceRule], forwarding: &Forwarding) -> Nftables<'static> {
    apply_batch_with(ifname, None, rules, forwarding)
}

/// [`apply_batch`], plus the carry interface's own table when there is one
/// (PLAN.md M39) — in the same transaction, so the two never disagree.
pub(crate) fn apply_batch_with(
    ifname: &str,
    carry: Option<&str>,
    rules: &[ServiceRule],
    forwarding: &Forwarding,
) -> Nftables<'static> {
    let name = table_name(ifname);
    let t = name.as_str();
    let mut objects: Vec<NfObject<'static>> = delete_table_cmds(t).into();
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table(t)))));

    // (service address, where it goes — the node or the mapping's own
    // target address, the mapping, who may reach it)
    let mapped: Vec<(Ipv4Addr, Ipv4Addr, PortMap, &Sources)> = rules
        .iter()
        .filter_map(|r| match r {
            ServiceRule::Mapped { vip, node, map, sources } => Some((*vip, map.addr.unwrap_or(*node), *map, sources)),
            ServiceRule::Terminated { .. } => None,
        })
        .collect();
    // Answered on the service address by this node's own terminator
    // (PLAN.md M33).
    let terminated: Vec<(Ipv4Addr, PortMap, &Sources)> = rules
        .iter()
        .filter_map(|r| match r {
            ServiceRule::Terminated { vip, map, port, sources } => Some((*vip, terminated_map(map, *port), sources)),
            ServiceRule::Mapped { .. } => None,
        })
        .collect();
    let has_service_addresses = !mapped.is_empty() || !terminated.is_empty();
    let accept = || Statement::Accept(None::<Accept>);

    // ---- input: what reaches this host's own sockets from the mesh ----
    objects.push(chain(t, CHAIN_NAME, NfChainType::Filter, NfHook::Input, 0));
    // A terminated service's address is a local address of this host (the
    // agent routes it to `lo`), so without this anything on the LAN could
    // reach the terminator on it — and, where reverse-path filtering is
    // loose, claim a mesh source address it has not got. Only the mesh and
    // the host itself may.
    // The carry interface is the mesh too (PLAN.md M39).
    let not_mesh = || {
        let mut out = vec![iifname_is_not(ifname), iifname_is_not("lo")];
        out.extend(carry.map(iifname_is_not));
        out
    };
    // Relay ports (PLAN.md M40) from anywhere but the mesh: a relayed
    // packet was translated in prerouting and is forwarded, never
    // delivered here, so what reaches the input hook on one is untranslated
    // — its relay rule isn't in place yet, or it is over the limit. Dropped
    // before conntrack confirms it, so no flow is left behind that its
    // sender's keepalives would keep alive untranslated once the rule comes.
    // A port under a check is left to the agent's listener.
    //
    // Only new flows (PLAN.md #274): the relay ports lie inside Linux's
    // ephemeral range, so this host's own UDP — a DNS lookup, NTP — goes out
    // from one of them now and then, and its reply arrives here as part of
    // an established flow. An untranslated relay packet is never anything
    // but new: dropped, it leaves no flow to be established by.
    if let Some(((lo, hi), _)) = forwarding.relay_ranges {
        let mut expr = not_mesh();
        expr.push(is(payload("udp", "dport"), port_range(lo, hi)));
        if !forwarding.relay_checks.is_empty() {
            expr.push(Statement::Match(Match {
                left: payload("udp", "dport"),
                right: Expression::Named(NamedExpression::Set(
                    forwarding.relay_checks.iter().map(|p| SetItem::Element(Expression::Number(u32::from(*p)))).collect(),
                )),
                op: Operator::NEQ,
            }));
        }
        expr.push(Statement::Match(Match {
            left: ct("state", None),
            right: Expression::List(vec![Expression::String("new".into())]),
            op: Operator::IN,
        }));
        expr.push(Statement::Drop(None::<Drop>));
        objects.push(rule(t, CHAIN_NAME, expr));
    }
    for (vip, ..) in &terminated {
        let mut expr = not_mesh();
        expr.extend([is(payload("ip", "daddr"), addr(*vip)), Statement::Drop(None::<Drop>)]);
        objects.push(rule(t, CHAIN_NAME, expr));
    }
    // The terminator's own port, on every address of the host (PLAN.md
    // M35): the same, whatever the address. It answers nothing there but
    // its service addresses anyway; this keeps the LAN from even trying.
    let ports: std::collections::BTreeSet<u16> = terminated.iter().map(|(_, m, _)| m.target).collect();
    for port in ports {
        let mut expr = not_mesh();
        expr.extend([dport_is(Proto::Tcp, port), Statement::Drop(None::<Drop>)]);
        objects.push(rule(t, CHAIN_NAME, expr));
    }
    // Allow return traffic for connections this node itself initiated over
    // the WireGuard interface (e.g. this node acting as a client of another
    // peer's declared service) — without this, a WG-interface-scoped
    // default-deny would break outbound connectivity through the tunnel
    // just as badly as the bug above broke it on every other interface.
    objects.push(rule(t, CHAIN_NAME, vec![iifname_is(ifname), established_or_related(), accept()]));
    if has_service_addresses {
        objects.push(rule(t, CHAIN_NAME, vec![iifname_is(ifname), has_mark(ct("mark", None)), accept()]));
    }
    // Relayed sessions (PLAN.md M39) arrive through the mesh at the carry
    // interface's port, from whichever carrier relays them. WireGuard itself
    // drops anything on it that no peer of the carry interface signed.
    if !forwarding.relay_ends.is_empty() {
        objects.push(rule(t, CHAIN_NAME, vec![
            iifname_is(ifname),
            in_list(payload("udp", "dport"), forwarding.relay_ends.iter().map(|p| Expression::Number(u32::from(*p))).collect()),
            accept(),
        ]));
    }
    // Default-deny, but ONLY for the WireGuard interface — everything else
    // stays governed by the chain's own accept policy above. TCP is refused
    // rather than dropped (see `refuse_tcp`).
    let mut refuse = vec![iifname_is(ifname)];
    refuse.extend(refuse_tcp());
    objects.push(rule(t, CHAIN_NAME, refuse));
    objects.push(rule(t, CHAIN_NAME, vec![iifname_is(ifname), Statement::Drop(None::<Drop>)]));

    // ---- forward: what the mesh reaches *through* this host ----
    // A published container port is a DNAT to the container, so a request
    // for it is forwarded, never delivered locally, and the input chain
    // above never sees it. Without this chain every container port on the
    // node was reachable from the whole mesh, declared or not.
    objects.push(chain(t, FORWARD_CHAIN, NfChainType::Filter, NfHook::Forward, 0));
    // The interfaces whose forwarding this agent turned on (PLAN.md M26):
    // replies from a service's target address are the only thing it was
    // turned on for. Scoped to IPv4, the only switch the agent flips; a
    // flow of ours carries the mark in both directions, and so do ICMP
    // errors about it, which conntrack ties to the same flow. Never the
    // mesh interface itself, which would stop transit.
    //
    // An exit's replies (PLAN.md M27) arrive the same way, under their own
    // bit, so the guard lets through flows carrying either.
    for lan in forwarding.guarded.iter().filter(|g| g.as_str() != ifname) {
        objects.push(rule(t, FORWARD_CHAIN, vec![
            iifname_is(lan),
            is(meta(MetaKey::Nfproto), Expression::String("ipv4".into())),
            lacks_bits(ct("mark", None), SERVICE_MARK | EXIT_MARK | RELAY_MARK),
            Statement::Drop(None::<Drop>),
        ]));
    }
    objects.push(rule(t, FORWARD_CHAIN, vec![iifname_is(ifname), established_or_related(), accept()]));
    if !mapped.is_empty() {
        objects.push(rule(t, FORWARD_CHAIN, vec![iifname_is(ifname), has_mark(ct("mark", None)), accept()]));
    }
    // Opt-in transit (PLAN.md M23): this node is B, forwarding an
    // ordinary connection between two other peers, decrypted and
    // re-encrypted at the kernel WireGuard layer — never rewritten,
    // unlike a service address above. Only a *new* connection needs its
    // own rule here in each direction; its own reply traffic is already
    // covered by the `established_or_related()` accept above, the same
    // way a service's reply traffic is. One rule per direction per
    // family that actually has addresses on both ends (up to four for a
    // fully dual-stack pair), narrowly scoped to exactly this pair's own
    // addresses — never a blanket forward-everything rule.
    let (mut relay_nat, relay_fwd) = match forwarding.relay_self {
        Some(me) => relay_rules(t, ifname, me, &forwarding.relay),
        None => (Vec::new(), Vec::new()),
    };
    objects.extend(relay_fwd);
    if let (Some(me), Some(public), Some((_, phones))) =
        (forwarding.relay_self, forwarding.relay_public_iface.as_deref(), forwarding.relay_ranges)
    {
        let (nat, fwd) = public_relay_rules(t, ifname, public, me, &forwarding.relay_public, phones);
        relay_nat.extend(nat);
        objects.extend(fwd);
    }
    if !relay_nat.is_empty() {
        relay_nat.splice(0..0, [
            chain(t, RELAY_PRE_CHAIN, NfChainType::NAT, NfHook::Prerouting, PRIO_DSTNAT),
            chain(t, RELAY_POST_CHAIN, NfChainType::NAT, NfHook::Postrouting, PRIO_SRCNAT),
        ]);
    }
    // An exit client's new flow to the internet (PLAN.md M27), marked in
    // `exit-mark`. Anything else from it — its gateway's LAN, IPv6 on a host
    // that forwards it — meets the drop below.
    let exit = exit_chains(t, ifname, forwarding);
    if !exit.is_empty() {
        objects.push(rule(t, FORWARD_CHAIN, vec![
            iifname_is(ifname),
            oifname_is_not(ifname),
            has_bit(ct("mark", None), EXIT_MARK),
            accept(),
        ]));
    }
    objects.push(rule(t, FORWARD_CHAIN, vec![iifname_is(ifname), Statement::Drop(None::<Drop>)]));
    objects.extend(exit);
    objects.extend(relay_nat);
    if let Some(carry) = carry {
        objects.extend(carry_table(carry, &mapped, &terminated));
    }

    // The chains below are the service-address rewrite machinery
    // (PLAN.md M20) — transit needs none of it (a transited connection is
    // forwarded exactly as received, never rewritten), so this early
    // return is unaffected by `transit` and stays keyed on `mapped`
    // alone, same as before this feature existed — plus the terminated
    // services (PLAN.md M33), rewritten to the terminator's port (M35).
    if !has_service_addresses {
        return Nftables { objects: objects.into() };
    }

    // ---- service addresses ----
    // Who may (PLAN.md M36): a source the grants leave out is never
    // rewritten or marked, and meets the refusal below like a port the
    // address does not publish. Matched per packet, before conntrack, so
    // taking a source away cuts its open connections too.
    objects.push(chain(t, PRE_CHAIN, NfChainType::Filter, NfHook::Prerouting, PRIO_RAW));
    let mesh_rewrites = mapped
        .iter()
        .map(|(vip, dest, map, sources)| (*vip, *dest, map, *sources))
        .chain(terminated.iter().map(|(vip, map, sources)| (*vip, *vip, map, *sources)));
    for (vip, dest, map, sources) in mesh_rewrites {
        let mut expr = vec![iifname_is(ifname)];
        match sources {
            None => {}
            // Nobody: no rule at all — nft has no empty set literal — and
            // the address still refuses them below.
            Some(list) if list.is_empty() => continue,
            Some(list) => expr.push(in_list(payload("ip", "saddr"), list.iter().map(|a| addr(*a)).collect())),
        }
        expr.extend(forward_rewrite(vip, dest, map));
        objects.push(rule(t, PRE_CHAIN, expr));
    }
    // A port a service address does not publish. A mapped service's address
    // is not local to this host, so such a request never reaches the input
    // chain's refusal: it would be forwarded into the forward chain's drop,
    // or dropped by the kernel outright where forwarding is off. Refused
    // here instead, once the rules above have rewritten or marked every
    // request for a published port.
    let vips: std::collections::BTreeSet<Ipv4Addr> =
        mapped.iter().map(|(vip, ..)| *vip).chain(terminated.iter().map(|(vip, ..)| *vip)).collect();
    let mut refuse = vec![
        iifname_is(ifname),
        in_list(payload("ip", "daddr"), vips.into_iter().map(addr).collect()),
        lacks_mark(meta(MetaKey::Mark)),
    ];
    refuse.extend(refuse_tcp());
    objects.push(rule(t, PRE_CHAIN, refuse));
    // The node's own clients. A `route` chain, so the kernel routes the
    // packet again after its destination changed: it was headed for the
    // mesh interface (see `routes`, which routes this node's own service
    // addresses there) and is now local. Never filtered by the grants: a
    // program on this host reaches the backend directly anyway.
    objects.push(chain(t, OUT_CHAIN, NfChainType::Route, NfHook::Output, PRIO_RAW));
    for (vip, dest, map, _) in &mapped {
        objects.push(rule(t, OUT_CHAIN, forward_rewrite(*vip, *dest, map)));
    }
    // Without these a Caddy on this host's [::]:443 would answer them.
    for (vip, map, _) in &terminated {
        objects.push(rule(t, OUT_CHAIN, forward_rewrite(*vip, *vip, map)));
    }
    // Conntrack exists from here on: carry the packet's mark onto its flow,
    // where the filter and the reply rewrite can see it for every packet
    // in both directions.
    for (name, kind, hook) in [
        (MARK_PRE_CHAIN, NfChainType::Filter, NfHook::Prerouting),
        (MARK_OUT_CHAIN, NfChainType::Route, NfHook::Output),
    ] {
        objects.push(chain(t, name, kind, hook, PRIO_MANGLE));
        objects.push(rule(t, name, vec![has_mark(meta(MetaKey::Mark)), add_mark(ct("mark", None))]));
    }
    // Replies, after every NAT hook has restored what the container
    // runtime changed: postrouting for replies leaving the host (to the
    // mesh, or locally generated), input for replies to the node's own
    // clients that came back from a container.
    for (name, hook) in [(REV_POST_CHAIN, NfHook::Postrouting), (REV_IN_CHAIN, NfHook::Input)] {
        objects.push(chain(t, name, NfChainType::Filter, hook, PRIO_AFTER_NAT));
        for (vip, dest, map, _) in &mapped {
            objects.push(rule(t, name, reverse_rewrite(*vip, *dest, map)));
        }
        for (vip, map, _) in &terminated {
            objects.push(rule(t, name, reverse_rewrite(*vip, *vip, map)));
        }
    }
    let remote: Vec<_> = rules
        .iter()
        .filter_map(|r| match r {
            ServiceRule::Mapped { map, .. } => map.addr.map(|dest| (dest, *map)),
            ServiceRule::Terminated { .. } => None,
        })
        .collect();
    if !remote.is_empty() {
        objects.push(chain(t, MASQ_CHAIN, NfChainType::NAT, NfHook::Postrouting, PRIO_SRCNAT));
        for (dest, map) in &remote {
            objects.push(rule(t, MASQ_CHAIN, masquerade(ifname, *dest, map)));
        }
    }

    Nftables { objects: objects.into() }
}

/// The carry interface's own table (PLAN.md M39): what reaches this host
/// through a relayed session gets exactly what the same peer would get
/// over the mesh interface — its grants on the service addresses, replies
/// to this node's own connections, and a refusal for everything else. It
/// forwards nothing but a service's own flows (PLAN.md #278), as the mesh
/// interface's table does: a mapping onto a container's published port or
/// a LAN address is forwarded to it. The rewrites' marking, reply and
/// masquerade chains in the mesh interface's table aren't tied to an
/// interface, so they serve these flows too.
fn carry_table(
    carry: &str,
    mapped: &[(Ipv4Addr, Ipv4Addr, PortMap, &Sources)],
    terminated: &[(Ipv4Addr, PortMap, &Sources)],
) -> Vec<NfObject<'static>> {
    let name = table_name(carry);
    let t = name.as_str();
    let mut objects: Vec<NfObject<'static>> = delete_table_cmds(t).into();
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table(t)))));
    let accept = || Statement::Accept(None::<Accept>);
    let has_service_addresses = !mapped.is_empty() || !terminated.is_empty();

    objects.push(chain(t, CHAIN_NAME, NfChainType::Filter, NfHook::Input, 0));
    objects.push(rule(t, CHAIN_NAME, vec![iifname_is(carry), established_or_related(), accept()]));
    if has_service_addresses {
        objects.push(rule(t, CHAIN_NAME, vec![iifname_is(carry), has_mark(ct("mark", None)), accept()]));
    }
    let mut refuse = vec![iifname_is(carry)];
    refuse.extend(refuse_tcp());
    objects.push(rule(t, CHAIN_NAME, refuse));
    objects.push(rule(t, CHAIN_NAME, vec![iifname_is(carry), Statement::Drop(None::<Drop>)]));

    objects.push(chain(t, FORWARD_CHAIN, NfChainType::Filter, NfHook::Forward, 0));
    if !mapped.is_empty() {
        objects.push(rule(t, FORWARD_CHAIN, vec![iifname_is(carry), has_mark(ct("mark", None)), accept()]));
    }
    objects.push(rule(t, FORWARD_CHAIN, vec![iifname_is(carry), Statement::Drop(None::<Drop>)]));

    if !has_service_addresses {
        return objects;
    }
    objects.push(chain(t, PRE_CHAIN, NfChainType::Filter, NfHook::Prerouting, PRIO_RAW));
    let rewrites = mapped
        .iter()
        .map(|(vip, dest, map, sources)| (*vip, *dest, map, *sources))
        .chain(terminated.iter().map(|(vip, map, sources)| (*vip, *vip, map, *sources)));
    for (vip, dest, map, sources) in rewrites {
        let mut expr = vec![iifname_is(carry)];
        match sources {
            None => {}
            Some(list) if list.is_empty() => continue,
            Some(list) => expr.push(in_list(payload("ip", "saddr"), list.iter().map(|a| addr(*a)).collect())),
        }
        expr.extend(forward_rewrite(vip, dest, map));
        objects.push(rule(t, PRE_CHAIN, expr));
    }
    let vips: std::collections::BTreeSet<Ipv4Addr> =
        mapped.iter().map(|(vip, ..)| *vip).chain(terminated.iter().map(|(vip, ..)| *vip)).collect();
    let mut refuse = vec![
        iifname_is(carry),
        in_list(payload("ip", "daddr"), vips.into_iter().map(addr).collect()),
        lacks_mark(meta(MetaKey::Mark)),
    ];
    refuse.extend(refuse_tcp());
    objects.push(rule(t, PRE_CHAIN, refuse));
    objects
}

/// The transaction `teardown` sends: remove the table if present, nothing
/// else. Unlike the netlink version this replaces, removing a table that
/// was never created is not a special case — the add-then-delete pair
/// handles it, so there is no empty batch that could hang (see PLAN.md
/// decisions log for that bug).
pub(crate) fn teardown_batch(table: &str) -> Nftables<'static> {
    Nftables {
        objects: Vec::from(delete_table_cmds(table)).into(),
    }
}


impl FirewallBackend for NftablesBackend {
    type Error = NftablesError;

    /// Full-replace in one atomic transaction: the previous table (if any)
    /// is deleted and the table/chain/rules recreated from scratch. Service
    /// rules and transit forwarding pairs (PLAN.md M23) apply together, in
    /// the same transaction, so a mid-cycle failure can never leave them
    /// disagreeing about which cycle they reflect.
    fn apply(&mut self, rules: &[ServiceRule], forwarding: &Forwarding) -> Result<(), Self::Error> {
        let batch = apply_batch_with(&self.ifname, self.carry.as_deref(), rules, forwarding);
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        match self.nft.apply(&batch) {
            Ok(()) => {
                *last = Some(batch);
                Ok(())
            }
            Err(e @ NftError::Failed { .. })
                if e.to_string().contains("Operation not permitted")
                    && rules.iter().any(|r| matches!(r, ServiceRule::Mapped { .. })) =>
            {
                Err(NftablesError::RewriteRefused(e))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Removes this interface's table entirely, if present — and forgets
    /// it, so nothing restores a table that was meant to go.
    fn teardown(&mut self) -> Result<(), Self::Error> {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        *last = None;
        self.nft.apply(&teardown_batch(&table_name(&self.ifname)))?;
        if let Some(carry) = &self.carry {
            self.nft.apply(&teardown_batch(&table_name(carry)))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const NODE: Ipv4Addr = Ipv4Addr::new(100, 90, 0, 2);
    const VIP: Ipv4Addr = Ipv4Addr::new(100, 90, 0, 50);
    const TLS_PORT: u16 = wireserve_types::TLS_LISTEN_PORT;

    /// This node relaying `pairs` (PLAN.md M39) — with none, nothing but
    /// the default-deny.
    fn fwd(pairs: &[RelayForward]) -> Forwarding {
        Forwarding { relay: pairs.to_vec(), relay_self: Some(NODE), ..Forwarding::default() }
    }

    fn as_json(batch: &Nftables<'_>) -> Value {
        serde_json::to_value(batch).unwrap()
    }

    fn iif(ifname: &str) -> Value {
        json!({"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": ifname}})
    }

    fn table_json() -> Value {
        json!({"family": "inet", "name": "wireserve.wg0"})
    }

    fn rule_in(chain: &str, expr: Value) -> Value {
        json!({"add": {"rule": {
            "family": "inet", "table": "wireserve.wg0", "chain": chain, "expr": expr
        }}})
    }

    fn rule_json(expr: Value) -> Value {
        rule_in("wireserve-in", expr)
    }

    fn chain_json(name: &str, kind: &str, hook: &str, prio: i32) -> Value {
        json!({"add": {"chain": {
            "family": "inet", "table": "wireserve.wg0", "name": name,
            "type": kind, "hook": hook, "prio": prio, "policy": "accept"
        }}})
    }

    fn established() -> Value {
        json!({"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}})
    }

    fn in_addrs(protocol: &str, field: &str, addrs: &[&str]) -> Value {
        json!({"match": {"op": "in", "left": {"payload": {"protocol": protocol, "field": field}}, "right": {"set": addrs}}})
    }

    /// The mesh's default-deny at the end of the input chain: TCP refused,
    /// the rest dropped.
    fn input_deny() -> [Value; 2] {
        [
            rule_json(json!([iif("wg0"), refuse_tcp_json()[0], refuse_tcp_json()[1]])),
            rule_json(json!([iif("wg0"), {"drop": null}])),
        ]
    }

    fn refuse_tcp_json() -> [Value; 2] {
        [
            json!({"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}}),
            json!({"reject": {"type": "tcp reset"}}),
        ]
    }

    fn prelude() -> Vec<Value> {
        vec![
            json!({"add": {"table": table_json()}}),
            json!({"delete": {"table": table_json()}}),
            json!({"add": {"table": table_json()}}),
            chain_json("wireserve-in", "filter", "input", 0),
            rule_json(json!([iif("wg0"), established(), {"accept": null}])),
        ]
    }

    fn forward(extra: Vec<Value>) -> Vec<Value> {
        let mut out = vec![
            chain_json("wireserve-fwd", "filter", "forward", 0),
            rule_in("wireserve-fwd", json!([iif("wg0"), established(), {"accept": null}])),
        ];
        out.extend(extra);
        out.push(rule_in("wireserve-fwd", json!([iif("wg0"), {"drop": null}])));
        out
    }

    fn mapped(map: &str) -> ServiceRule {
        ServiceRule::Mapped {
            vip: VIP,
            node: NODE,
            map: map.parse().unwrap(),
            sources: None,
        }
    }

    #[test]
    fn apply_with_no_services_is_default_deny_on_the_interface_only() {
        let mut expected = prelude();
        expected.extend(input_deny());
        expected.extend(forward(vec![]));
        assert_eq!(as_json(&apply_batch("wg0", &[], &fwd(&[]))), json!({ "nftables": expected }));
    }



    fn pair(n: u8) -> RelayForward {
        RelayForward {
            a: wireserve_types::RelayEnd { ip4: format!("100.90.{n}.1").parse().unwrap(), relay_port: 41001, carry_port: 50001 },
            c: wireserve_types::RelayEnd { ip4: format!("100.90.{n}.3").parse().unwrap(), relay_port: 41003, carry_port: 50003 },
        }
    }

    #[test]
    fn no_relay_pairs_is_byte_for_byte_the_plain_default_deny() {
        assert_eq!(apply_batch("wg0", &[], &fwd(&[])), apply_batch("wg0", &[], &fwd(&[])));
        let mut expected = prelude();
        expected.extend(input_deny());
        expected.extend(forward(vec![]));
        assert_eq!(as_json(&apply_batch("wg0", &[], &fwd(&[]))), json!({ "nftables": expected }));
    }

    fn has_mark(key: Value) -> Value {
        json!({"match": {"op": "==", "left": {"&": [key, SERVICE_MARK]}, "right": SERVICE_MARK}})
    }

    fn mangle(key: Value, value: Value) -> Value {
        json!({"mangle": {"key": key, "value": value}})
    }

    fn field(protocol: &str, name: &str) -> Value {
        json!({"payload": {"protocol": protocol, "field": name}})
    }

    #[test]
    fn a_mapped_service_gets_the_rewrite_in_both_directions() {
        let batch = as_json(&apply_batch("wg0", &[mapped("80:5080")], &fwd(&[])));
        let objects = batch["nftables"].as_array().unwrap();
        let rules_of = |chain: &str| -> Vec<Value> {
            objects
                .iter()
                .filter_map(|o| o.pointer("/add/rule"))
                .filter(|r| r["chain"] == chain)
                .map(|r| r["expr"].clone())
                .collect()
        };
        let chains: Vec<(String, String, String, i64)> = objects
            .iter()
            .filter_map(|o| o.pointer("/add/chain"))
            .map(|c| {
                (
                    c["name"].as_str().unwrap().into(),
                    c["type"].as_str().unwrap().into(),
                    c["hook"].as_str().unwrap().into(),
                    c["prio"].as_i64().unwrap(),
                )
            })
            .collect();
        let chain = |n: &str, t: &str, h: &str, p: i64| (n.to_string(), t.to_string(), h.to_string(), p);
        assert_eq!(
            chains,
            [
                chain("wireserve-in", "filter", "input", 0),
                chain("wireserve-fwd", "filter", "forward", 0),
                chain("svc-pre", "filter", "prerouting", -300),
                chain("svc-out", "route", "output", -300),
                chain("svc-mark-pre", "filter", "prerouting", -150),
                chain("svc-mark-out", "route", "output", -150),
                chain("svc-rev-post", "filter", "postrouting", 300),
                chain("svc-rev-in", "filter", "input", 300),
            ]
        );

        let meta_mark = json!({"meta": {"key": "mark"}});
        let ct_mark = json!({"ct": {"key": "mark"}});
        let rewrite = vec![
            json!({"match": {"op": "==", "left": field("ip", "daddr"), "right": "100.90.0.50"}}),
            json!({"match": {"op": "==", "left": field("tcp", "dport"), "right": 80}}),
            mangle(field("ip", "daddr"), json!("100.90.0.2")),
            mangle(field("tcp", "dport"), json!(5080)),
            mangle(meta_mark.clone(), json!({"|": [meta_mark, SERVICE_MARK]})),
        ];
        let mut from_mesh = vec![iif("wg0")];
        from_mesh.extend(rewrite.clone());
        let [l4proto, reject] = refuse_tcp_json();
        let refuse = json!([
            iif("wg0"),
            in_addrs("ip", "daddr", &["100.90.0.50"]),
            {"match": {"op": "!=", "left": {"&": [meta_mark, SERVICE_MARK]}, "right": SERVICE_MARK}},
            l4proto,
            reject,
        ]);
        assert_eq!(rules_of("svc-pre"), [Value::Array(from_mesh), refuse]);
        assert_eq!(rules_of("svc-out"), [Value::Array(rewrite)]);

        let carry = json!([has_mark(json!({"meta": {"key": "mark"}})), mangle(ct_mark.clone(), json!({"|": [ct_mark, SERVICE_MARK]}))]);
        assert_eq!(rules_of("svc-mark-pre"), std::slice::from_ref(&carry));
        assert_eq!(rules_of("svc-mark-out"), [carry]);

        let back = json!([
            {"match": {"op": "==", "left": {"ct": {"key": "direction"}}, "right": "reply"}},
            has_mark(json!({"ct": {"key": "mark"}})),
            {"match": {"op": "==", "left": field("ip", "saddr"), "right": "100.90.0.2"}},
            {"match": {"op": "==", "left": field("tcp", "sport"), "right": 5080}},
            mangle(field("ip", "saddr"), json!("100.90.0.50")),
            mangle(field("tcp", "sport"), json!(80)),
        ]);
        assert_eq!(rules_of("svc-rev-post"), std::slice::from_ref(&back));
        assert_eq!(rules_of("svc-rev-in"), [back]);

        // Only a marked flow gets through, never the target port itself.
        let accept_marked = json!([iif("wg0"), has_mark(json!({"ct": {"key": "mark"}})), {"accept": null}]);
        let input = rules_of("wireserve-in");
        assert_eq!(input[1], accept_marked);
        assert!(!input.iter().any(|r| r.to_string().contains("5080")), "{input:?}");
        let fwd = rules_of("wireserve-fwd");
        assert_eq!(fwd[1], accept_marked);
        assert!(!fwd.iter().any(|r| r.to_string().contains("5080")), "{fwd:?}");
    }

    fn rules_in(batch: &Value, chain: &str) -> Vec<Value> {
        batch["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o.pointer("/add/rule"))
            .filter(|r| r["chain"] == chain)
            .map(|r| r["expr"].clone())
            .collect()
    }

    #[test]
    fn a_mapping_onto_another_address_rewrites_to_it_and_masquerades() {
        let batch = as_json(&apply_batch("wg0", &[mapped("443:192.168.178.1:80"), mapped("8080:5080")], &fwd(&[])));
        let meta_mark = json!({"meta": {"key": "mark"}});
        assert_eq!(
            rules_in(&batch, "svc-pre")[0],
            json!([
                iif("wg0"),
                {"match": {"op": "==", "left": field("ip", "daddr"), "right": "100.90.0.50"}},
                {"match": {"op": "==", "left": field("tcp", "dport"), "right": 443}},
                mangle(field("ip", "daddr"), json!("192.168.178.1")),
                mangle(field("tcp", "dport"), json!(80)),
                mangle(meta_mark.clone(), json!({"|": [meta_mark, SERVICE_MARK]})),
            ])
        );
        // The node-local mapping beside it still goes to the node.
        assert!(rules_in(&batch, "svc-pre")[1].to_string().contains(r#""value":"100.90.0.2""#));
        assert!(rules_in(&batch, "svc-rev-post")[0]
            .to_string()
            .contains(r#"{"match":{"left":{"payload":{"field":"saddr","protocol":"ip"}},"op":"==","right":"192.168.178.1"}}"#));

        // Only the remote one is masqueraded, only its first packet (still
        // marked), and never out of the mesh interface.
        assert_eq!(
            rules_in(&batch, "svc-masq"),
            [json!([
                has_mark(json!({"meta": {"key": "mark"}})),
                {"match": {"op": "==", "left": field("ip", "daddr"), "right": "192.168.178.1"}},
                {"match": {"op": "==", "left": field("tcp", "dport"), "right": 80}},
                {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}},
                {"masquerade": null},
            ])]
        );
        let chain = batch["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o.pointer("/add/chain"))
            .find(|c| c["name"] == "svc-masq")
            .unwrap();
        assert_eq!((&chain["type"], &chain["hook"], &chain["prio"]), (&json!("nat"), &json!("postrouting"), &json!(100)));
    }

    #[test]
    fn only_a_mapping_onto_another_address_gets_a_masquerade_chain() {
        let batch = as_json(&apply_batch("wg0", &[mapped("80:5080")], &fwd(&[]))).to_string();
        assert!(!batch.contains("svc-masq") && !batch.contains("masquerade"), "{batch}");
    }

    #[test]
    fn a_guarded_interface_forwards_only_our_own_flows() {
        let forwarding = Forwarding { guarded: vec!["eth0".into(), "wg0".into()], ..Forwarding::default() };
        let batch = as_json(&apply_batch("wg0", &[mapped("443:192.168.178.1:80")], &forwarding));
        let fwd_rules = rules_in(&batch, "wireserve-fwd");
        assert_eq!(
            fwd_rules[0],
            json!([
                iif("eth0"),
                {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv4"}},
                // Neither ours, an exit's (PLAN.md M27) nor a relayed phone's
                // (M40): all of them arrive on an interface the agent owns.
                {"match": {"op": "==", "left": {"&": [{"ct": {"key": "mark"}}, SERVICE_MARK | EXIT_MARK | RELAY_MARK]}, "right": 0}},
                {"drop": null},
            ])
        );
        // Never the mesh interface: that would drop every transit flow.
        assert_eq!(fwd_rules[1], json!([iif("wg0"), established(), {"accept": null}]));
        assert!(!fwd_rules.iter().any(|r| r[0] == iif("wg0") && r.to_string().contains(r#""op":"!=""#)));
    }

    // ---- PLAN.md M33: terminated on this node ----

    fn terminated(map: &str) -> ServiceRule {
        ServiceRule::Terminated { vip: VIP, map: map.parse().unwrap(), port: TLS_PORT, sources: None }
    }

    #[test]
    fn a_terminated_service_is_rewritten_to_the_terminator_and_closed_to_the_lan() {
        let batch = as_json(&apply_batch("wg0", &[terminated("443:32400")], &fwd(&[])));
        let text = batch.to_string();
        // 443 on the service address to the terminator's port on the same
        // address (PLAN.md M35), from the mesh and from the node itself; the
        // target never mentioned: the terminator reaches it locally. Then
        // any other port refused (see the mapped service's test).
        let pre = rules_in(&batch, "svc-pre");
        assert_eq!(pre.len(), 2, "{pre:?}");
        assert!(pre[1].to_string().contains("tcp reset"), "{pre:?}");
        let expected = forward_rewrite(VIP, VIP, &"443:11443".parse().unwrap());
        assert_eq!(pre[0], json!([iif("wg0")].into_iter().chain(expected.iter().map(|e| serde_json::to_value(e).unwrap())).collect::<Vec<_>>()));
        let out = rules_in(&batch, "svc-out");
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0], serde_json::to_value(&expected).unwrap());
        assert!(!text.contains("32400"), "{text}");
        // And back: from the terminator's port to 443, on the way out to the
        // mesh and to the node's own clients.
        let back = serde_json::to_value(reverse_rewrite(VIP, VIP, &"443:11443".parse().unwrap())).unwrap();
        for chain in ["svc-rev-post", "svc-rev-in"] {
            let rev = rules_in(&batch, chain);
            assert_eq!(rev.len(), 1, "{rev:?}");
            assert_eq!(rev[0], back);
        }
        // Accepted from the mesh by the mark; dropped from anywhere but the
        // mesh and the host itself, on the service address and on the
        // terminator's port at any address.
        let input = rules_in(&batch, "wireserve-in");
        assert!(input.iter().any(|r| r.to_string().contains("ct") && r.to_string().contains("accept")), "{input:?}");
        let lan_drop = input[0].to_string();
        assert!(
            lan_drop.contains("!=") && lan_drop.contains("\"lo\"") && lan_drop.contains(&VIP.to_string()) && lan_drop.contains("drop"),
            "{lan_drop}"
        );
        let port_drop = input[1].to_string();
        assert!(
            port_drop.contains("!=") && port_drop.contains("\"lo\"") && port_drop.contains("11443") && port_drop.contains("drop"),
            "{port_drop}"
        );
        // Nothing forwarded for it.
        assert!(!rules_in(&batch, "wireserve-fwd").iter().any(|r| r.to_string().contains("mark")));
    }

    #[test]
    fn without_a_mapped_service_there_are_no_rewrite_chains() {
        let batch = as_json(&apply_batch("wg0", &[], &fwd(&[]))).to_string();
        assert!(!batch.contains("svc-") && !batch.contains("mangle"), "{batch}");
    }

    #[test]
    fn no_forward_accept_leaves_the_destination_open() {
        // Security review finding #3, pinned structurally: a forward
        // accept keyed on a port alone lets a peer use this host as a
        // relay to anything it routes to. Every accept must be an existing
        // flow, one of our own marked flows, or name its destination.
        let batch = as_json(&apply_batch("wg0", &[terminated("443:22"), mapped("80:5080")], &fwd(&[pair(0)])));
        let forward: Vec<&Value> = batch["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o.pointer("/add/rule"))
            .filter(|r| r["chain"] == "wireserve-fwd")
            .collect();
        assert!(forward.len() > 3, "{forward:?}");
        for r in forward {
            let text = r["expr"].to_string();
            if !text.contains("accept") {
                continue;
            }
            let scoped = text.contains(r#""key":"state""#)
                || text.contains(r#"{"ct":{"key":"mark"}}"#)
                || text.contains(r#""field":"daddr""#)
                || text.contains(r#""key":"ip daddr""#)
                || text.contains(r#""key":"ip6 daddr""#);
            assert!(scoped, "forward accept with no destination: {r}");
        }
    }

    fn only(rule: ServiceRule, sources: &[&str]) -> ServiceRule {
        let list: Sources = Some(sources.iter().map(|a| a.parse().unwrap()).collect::<Vec<Ipv4Addr>>().into());
        match rule {
            ServiceRule::Mapped { vip, node, map, .. } => ServiceRule::Mapped { vip, node, map, sources: list },
            ServiceRule::Terminated { vip, map, port, .. } => ServiceRule::Terminated { vip, map, port, sources: list },
        }
    }

    #[test]
    fn a_restricted_service_is_rewritten_for_its_sources_alone() {
        // PLAN.md M36: the source match comes first, so a source left out is
        // never rewritten nor marked, and meets the refusal like any port
        // the address does not publish.
        let rules = [only(mapped("5432"), &["100.90.0.7", "100.90.0.1"]), only(terminated("443:8096"), &["100.90.0.7"])];
        let batch = as_json(&apply_batch("wg0", &rules, &fwd(&[])));
        let pre = rules_in(&batch, "svc-pre");
        assert_eq!(pre.len(), 3, "{pre:?}");
        for r in &pre[..2] {
            let text = r.to_string();
            assert!(text.contains("saddr") && text.contains("100.90.0.7"), "{text}");
            let saddr = text.find("saddr").unwrap();
            assert!(saddr < text.find("mangle").unwrap(), "matched before anything is rewritten: {text}");
        }
        assert!(pre[2].to_string().contains("tcp reset"));
        // The node's own clients reach it unfiltered.
        assert!(rules_in(&batch, "svc-out").iter().all(|r| !r.to_string().contains("saddr")));
    }

    #[test]
    fn a_service_nobody_may_reach_still_refuses_them() {
        let batch = as_json(&apply_batch("wg0", &[only(mapped("5432"), &[])], &fwd(&[])));
        let pre = rules_in(&batch, "svc-pre");
        assert_eq!(pre.len(), 1, "no rewrite, no empty set: {pre:?}");
        let refusal = pre[0].to_string();
        assert!(refusal.contains(&VIP.to_string()) && refusal.contains("tcp reset"), "{refusal}");
        assert_eq!(rules_in(&batch, "svc-out").len(), 1, "the node itself still reaches it");
    }

    #[test]
    fn every_rule_is_scoped_to_the_interface_or_to_a_flow_it_marked() {
        // The accept/drop rules and the inbound rewrite act on the mesh
        // interface only. The rest can't be: the node's own clients never
        // arrive on it, and replies leave on whatever interface. They're
        // scoped instead to what only this agent produces — its own
        // service address as destination, or its own mark.
        let rules = [terminated("8443:22"), mapped("80:5080"), mapped("53:5353/udp"), mapped("443:192.168.178.1:80")];
        for ifname in ["wg0", "wireserve0", "wg-mesh.1"] {
            let batch = as_json(&apply_batch(ifname, &rules, &exit_fwd(&[CLIENT])));
            let rules: Vec<&Value> = batch["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|o| o.pointer("/add/rule"))
                .collect();
            for r in rules {
                let first = &r["expr"][0];
                let text = r["expr"].to_string();
                let ok = match r["chain"].as_str().unwrap() {
                    "wireserve-fwd" | "svc-pre" | "exit-mark" => *first == iif(ifname),
                    // The terminated address's drop is for every interface
                    // but this one: it names the address; so is the drop of
                    // the terminator's own port.
                    "wireserve-in" => {
                        *first == iif(ifname) || text.contains("100.90.0.50") || text.contains(&format!(r#""right":{TLS_PORT}"#))
                    }
                    "exit-masq" => text.contains(&format!(r#""&":[{{"ct":{{"key":"mark"}}}},{EXIT_MARK}]"#)),
                    "svc-masq" => text.contains(&format!(r#""&":[{{"meta":{{"key":"mark"}}}},{SERVICE_MARK}]"#)),
                    "svc-out" => text.starts_with(r#"[{"match":{"left":{"payload":{"field":"daddr","protocol":"ip"}},"op":"==","right":"100.90.0.50"}}"#),
                    "svc-mark-pre" | "svc-mark-out" | "svc-rev-post" | "svc-rev-in" => {
                        text.contains(&format!(r#""&":[{{"meta":{{"key":"mark"}}}},{SERVICE_MARK}]"#))
                            || text.contains(&format!(r#""&":[{{"ct":{{"key":"mark"}}}},{SERVICE_MARK}]"#))
                    }
                    other => panic!("unexpected chain {other}"),
                };
                assert!(ok, "rule not scoped for {ifname}: {r}");
            }
        }
    }

    #[test]
    fn the_mark_is_only_ever_or_ed_in_and_tested_under_its_mask() {
        // Other software uses the packet and conntrack marks too; this
        // agent must never overwrite or compare their bits.
        let forwarding = Forwarding { guarded: vec!["eth0".into()], ..exit_fwd(&[CLIENT]) };
        let batch = as_json(&apply_batch("wg0", &[mapped("80:5080"), mapped("443:192.168.178.1:80")], &forwarding));
        for r in batch["nftables"].as_array().unwrap().iter().filter_map(|o| o.pointer("/add/rule")) {
            for stmt in r["expr"].as_array().unwrap() {
                let text = stmt.to_string();
                if !text.contains(r#""key":"mark""#) {
                    continue;
                }
                let masked_test = stmt.pointer("/match/left/&").is_some();
                let or_set = stmt.pointer("/mangle/value/|").is_some();
                assert!(masked_test || or_set, "mark used without its mask: {stmt}");
            }
        }
    }

    // ---- exit (PLAN.md M27) ----

    const CLIENT: Ipv4Addr = Ipv4Addr::new(100, 90, 0, 9);

    fn exit_fwd(clients: &[Ipv4Addr]) -> Forwarding {
        Forwarding {
            exit: clients.to_vec(),
            mesh_v4: Some((Ipv4Addr::new(100, 90, 0, 0), 24)),
            ..Forwarding::default()
        }
    }

    fn chain_names(batch: &Value) -> Vec<String> {
        batch["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o.pointer("/add/chain/name").and_then(Value::as_str).map(String::from))
            .collect()
    }

    #[test]
    fn an_exit_marks_new_internet_flows_from_its_clients_and_masquerades_them() {
        // No service at all: the exit must not ride on the service chains'
        // early return.
        let batch = as_json(&apply_batch("wg0", &[], &exit_fwd(&[CLIENT])));
        let ct_mark = json!({"ct": {"key": "mark"}});
        let mut not_internet: Vec<Value> = wireserve_types::NOT_THE_INTERNET_V4
            .iter()
            .map(|(ip, len)| json!({"prefix": {"addr": ip.to_string(), "len": len}}))
            .collect();
        not_internet.push(json!({"prefix": {"addr": "100.90.0.0", "len": 24}}));
        assert_eq!(
            rules_in(&batch, "exit-mark"),
            vec![json!([
                iif("wg0"),
                in_addrs("ip", "saddr", &["100.90.0.9"]),
                {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["new"]}},
                {"match": {"op": "!=", "left": {"&": [{"meta": {"key": "mark"}}, SERVICE_MARK]}, "right": SERVICE_MARK}},
                {"match": {"op": "!=", "left": field("ip", "daddr"), "right": {"set": not_internet}}},
                mangle(ct_mark.clone(), json!({"|": [ct_mark, EXIT_MARK]})),
            ])]
        );
        assert_eq!(
            rules_in(&batch, "exit-masq"),
            vec![json!([
                {"match": {"op": "==", "left": {"&": [{"ct": {"key": "mark"}}, EXIT_MARK]}, "right": EXIT_MARK}},
                {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}},
                {"masquerade": null},
            ])]
        );
        // Accepted just ahead of the interface's final drop, never after it.
        let fwd_rules = rules_in(&batch, "wireserve-fwd");
        let n = fwd_rules.len();
        assert_eq!(fwd_rules[n - 1], json!([iif("wg0"), {"drop": null}]));
        assert_eq!(
            fwd_rules[n - 2],
            json!([
                iif("wg0"),
                {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}},
                {"match": {"op": "==", "left": {"&": [{"ct": {"key": "mark"}}, EXIT_MARK]}, "right": EXIT_MARK}},
                {"accept": null},
            ])
        );
        let chains = chain_names(&batch);
        let pos = |n: &str| chains.iter().position(|c| c == n).unwrap();
        assert!(pos("exit-mark") > pos("wireserve-fwd"));
        let chain = |name: &str| {
            batch["nftables"].as_array().unwrap().iter().find_map(|o| o.pointer("/add/chain").filter(|c| c["name"] == name)).unwrap().clone()
        };
        let mark = chain("exit-mark");
        assert_eq!((&mark["type"], &mark["hook"], &mark["prio"]), (&json!("filter"), &json!("prerouting"), &json!(-150)));
        let masq = chain("exit-masq");
        assert_eq!((&masq["type"], &masq["hook"], &masq["prio"]), (&json!("nat"), &json!("postrouting"), &json!(100)));
    }

    #[test]
    fn no_exit_clients_or_no_mesh_range_means_no_exit_rules_at_all() {
        for forwarding in [
            exit_fwd(&[]),
            Forwarding { mesh_v4: None, ..exit_fwd(&[CLIENT]) },
        ] {
            let batch = as_json(&apply_batch("wg0", &[mapped("80:5080")], &forwarding));
            let text = batch.to_string();
            assert!(!text.contains("exit-") && !text.contains(&EXIT_MARK.to_string()), "{text}");
            assert_eq!(batch, as_json(&apply_batch("wg0", &[mapped("80:5080")], &Forwarding::default())));
        }
    }

    #[test]
    fn teardown_only_removes_our_table() {
        assert_eq!(
            as_json(&teardown_batch("wireserve.wg0")),
            json!({"nftables": [
                {"add": {"table": table_json()}},
                {"delete": {"table": table_json()}}
            ]})
        );
    }

    // ---- real kernel (unprivileged netns, skipped where unavailable) ----

    fn nft_script(batches: &[Nftables<'_>]) -> String {
        batches
            .iter()
            .map(|b| format!("nft -j -f - <<'JSON'\n{}\nJSON\n", serde_json::to_string(b).unwrap()))
            .collect()
    }

    fn normalised_lines(listing: &str) -> Vec<String> {
        // nft renders a ct-state bitmask as `established,related` (1.1.x)
        // or `{ established, related }` (some older releases) — the same
        // kernel rule either way, so normalise before comparing.
        listing
            .replace("{ established, related }", "established,related")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    }



    /// The relays' rules (PLAN.md M39, M40) are accepted by a real kernel —
    /// NAT included, which an unprivileged namespace allows.
    #[test]
    fn kernel_accepts_a_carriers_relay_rules() {
        let forwarding = Forwarding {
            relay_public: vec![wireserve_types::PublicRelay { port: 41004, to: "100.90.0.4".parse().unwrap(), to_port: 51820 }],
            relay_public_iface: Some("eth0".into()),
            relay_ranges: Some(((41000, 41999), (42000, 42999))),
            relay_checks: vec![41005],
            guarded: vec!["eth0".into()],
            ..fwd(&[pair(0)])
        };
        let script = nft_script(&[apply_batch("wg0", &[], &forwarding)]) + "nft list table inet wireserve.wg0";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        let lines = normalised_lines(&listing);
        let r = format!("0x{RELAY_MARK:08x}");
        for want in [
            "iifname \"wg0\" ip saddr 100.90.0.1 ip daddr 100.90.0.2 udp dport 41003 dnat ip to 100.90.0.3:50003".to_string(),
            "oifname \"wg0\" ip saddr 100.90.0.1 ip daddr 100.90.0.3 udp dport 50003 snat ip to 100.90.0.2:41001".to_string(),
            "iifname \"wg0\" oifname \"wg0\" ip saddr 100.90.0.1 ip daddr 100.90.0.3 udp dport 50003 accept".to_string(),
            format!("iifname \"eth0\" udp dport 41004 limit rate 200/second burst 400 packets ct mark set ct mark | {r} dnat ip to 100.90.0.4:51820"),
            format!("oifname \"wg0\" meta l4proto udp ct mark & {r} == {r} snat ip to 100.90.0.2:42000-42999"),
            format!("iifname \"eth0\" oifname \"wg0\" ct mark & {r} == {r} ip daddr 100.90.0.4 udp dport 51820 accept"),
            format!("iifname \"eth0\" ct mark & {r} == {r} drop"),
            "iifname != \"wg0\" iifname != \"lo\" udp dport 41000-41999 udp dport != 41005 ct state new drop".to_string(),
        ] {
            assert!(lines.contains(&want), "missing `{want}` in:\n{listing}");
        }
        let guard = format!("iifname \"eth0\" meta nfproto ipv4 ct mark & 0x{:08x} == 0x00000000 drop", SERVICE_MARK | EXIT_MARK | RELAY_MARK);
        assert!(lines.contains(&guard), "missing `{guard}` in:\n{listing}");
    }

    #[test]
    fn kernel_accepts_the_service_address_chains() {
        let rules = [mapped("80:5080"), mapped("53:5353/udp"), mapped("443:192.168.178.1:80")];
        let forwarding = Forwarding { guarded: vec!["eth0".into()], ..Forwarding::default() };
        let batch = serde_json::to_string(&apply_batch("wg0", &rules, &forwarding)).unwrap();
        let script = format!("nft -j -f - <<'JSON' || true\n{batch}\nJSON\nnft list ruleset");
        let Some((listing, stderr)) = crate::firewall::netns::run_capturing(&script) else {
            return;
        };
        if stderr.contains("Operation not permitted") {
            let errors: Vec<&str> = stderr.lines().filter(|l| l.contains("Error:")).collect();
            assert!(!errors.is_empty());
            for e in &errors {
                assert!(e.contains("Could not process rule: Operation not permitted"), "unexpected nft error: {e}\n{stderr}");
            }
            // mangling statements: 5 per forward rewrite (svc-pre, svc-out)
            // and 2 per reverse (svc-rev-post, svc-rev-in), per mapping;
            // nft reports each refused statement once.
            eprintln!("NOTE: payload rewriting refused in this user namespace; checked that nft accepted the JSON");
            return;
        }
        assert!(stderr.trim().is_empty(), "{stderr}");
        let lines = normalised_lines(&listing);
        let has = |l: &str| assert!(lines.iter().any(|x| x == l), "missing `{l}` in:\n{listing}");
        let m = format!("0x{SERVICE_MARK:08x}");
        has("type filter hook prerouting priority raw; policy accept;");
        has("type route hook output priority raw; policy accept;");
        has(&format!("iifname \"wg0\" ip daddr 100.90.0.50 tcp dport 80 ip daddr set 100.90.0.2 tcp dport set 5080 meta mark set meta mark | {m}"));
        has(&format!("ip daddr 100.90.0.50 udp dport 53 ip daddr set 100.90.0.2 udp dport set 5353 meta mark set meta mark | {m}"));
        has(&format!("meta mark & {m} == {m} ct mark set ct mark | {m}"));
        has(&format!("iifname \"wg0\" ct mark & {m} == {m} accept"));
        has(&format!("ct direction reply ct mark & {m} == {m} ip saddr 100.90.0.2 tcp sport 5080 ip saddr set 100.90.0.50 tcp sport set 80"));
        has(&format!("ct direction reply ct mark & {m} == {m} ip saddr 100.90.0.2 udp sport 5353 ip saddr set 100.90.0.50 udp sport set 53"));
        has(&format!("iifname \"wg0\" ip daddr 100.90.0.50 tcp dport 443 ip daddr set 192.168.178.1 tcp dport set 80 meta mark set meta mark | {m}"));
        has(&format!("ct direction reply ct mark & {m} == {m} ip saddr 192.168.178.1 tcp sport 80 ip saddr set 100.90.0.50 tcp sport set 443"));
        has("type nat hook postrouting priority srcnat; policy accept;");
        has(&format!("meta mark & {m} == {m} ip daddr 192.168.178.1 tcp dport 80 oifname != \"wg0\" masquerade"));
        has(&format!("iifname \"eth0\" meta nfproto ipv4 ct mark & {m} != {m} drop"));
    }

    /// A terminated service's rules (PLAN.md M33, M35). As with the mapped
    /// ones (`kernel_accepts_the_service_address_chains`), an unprivileged
    /// namespace refuses the rewrites, and every other rule must still be
    /// accepted; as root the whole listing is checked.
    #[test]
    fn kernel_accepts_a_terminated_service() {
        let batch = serde_json::to_string(&apply_batch("wg0", &[terminated("443:32400")], &fwd(&[]))).unwrap();
        let script = format!("nft -j -f - <<'JSON' || true\n{batch}\nJSON\nnft list ruleset");
        let Some((listing, stderr)) = crate::firewall::netns::run_capturing(&script) else {
            return;
        };
        if stderr.contains("Operation not permitted") {
            for e in stderr.lines().filter(|l| l.contains("Error:")) {
                assert!(e.contains("Could not process rule: Operation not permitted"), "unexpected nft error: {e}\n{stderr}");
            }
            eprintln!("NOTE: payload rewriting refused in this user namespace; checked that nft accepted the JSON");
            return;
        }
        assert!(stderr.trim().is_empty(), "{stderr}");
        let lines = normalised_lines(&listing);
        let has = |l: &str| assert!(lines.iter().any(|x| x == l), "missing `{l}` in:\n{listing}");
        let m = format!("0x{SERVICE_MARK:08x}");
        has(&format!("iifname \"wg0\" ip daddr 100.90.0.50 tcp dport 443 ip daddr set 100.90.0.50 tcp dport set 11443 meta mark set meta mark | {m}"));
        has(&format!("ip daddr 100.90.0.50 tcp dport 443 ip daddr set 100.90.0.50 tcp dport set 11443 meta mark set meta mark | {m}"));
        has(&format!("ct direction reply ct mark & {m} == {m} ip saddr 100.90.0.50 tcp sport 11443 ip saddr set 100.90.0.50 tcp sport set 443"));
        has("iifname != \"wg0\" iifname != \"lo\" ip daddr 100.90.0.50 drop");
        has("iifname != \"wg0\" iifname != \"lo\" tcp dport 11443 drop");
        has(&format!("iifname \"wg0\" ip daddr 100.90.0.50 meta mark & {m} != {m} meta l4proto tcp reject with tcp reset"));
        has(&format!("meta mark & {m} == {m} ct mark set ct mark | {m}"));
        has(&format!("iifname \"wg0\" ct mark & {m} == {m} accept"));
    }

    #[test]
    fn kernel_accepts_a_restricted_service() {
        let rules = [only(mapped("5432"), &["100.90.0.7", "100.90.0.8"]), only(mapped("6379"), &[])];
        let batch = serde_json::to_string(&apply_batch("wg0", &rules, &fwd(&[]))).unwrap();
        let script = format!("nft -j -f - <<'JSON' || true\n{batch}\nJSON\nnft list ruleset");
        let Some((listing, stderr)) = crate::firewall::netns::run_capturing(&script) else {
            return;
        };
        if stderr.contains("Operation not permitted") {
            for e in stderr.lines().filter(|l| l.contains("Error:")) {
                assert!(e.contains("Could not process rule: Operation not permitted"), "unexpected nft error: {e}\n{stderr}");
            }
            eprintln!("NOTE: payload rewriting refused in this user namespace; checked that nft accepted the JSON");
            return;
        }
        assert!(stderr.trim().is_empty(), "{stderr}");
        let lines = normalised_lines(&listing);
        let m = format!("0x{SERVICE_MARK:08x}");
        let want = format!(
            "iifname \"wg0\" ip saddr {{ 100.90.0.7, 100.90.0.8 }} ip daddr 100.90.0.50 tcp dport 5432 ip daddr set {NODE} tcp dport set 5432 meta mark set meta mark | {m}"
        );
        assert!(lines.iter().any(|x| x == &want), "missing `{want}` in:\n{listing}");
        // Nobody may reach 6379 from the mesh: only the node's own rewrite.
        let rewrites: Vec<_> = lines.iter().filter(|x| x.contains("tcp dport 6379 ip daddr set")).collect();
        assert!(rewrites.len() == 1 && !rewrites[0].starts_with("iifname"), "{listing}");
    }

    #[test]
    fn kernel_accepts_the_masquerade_and_the_guard() {
        let rules = [mapped("443:192.168.178.1:80")];
        let forwarding = Forwarding { guarded: vec!["eth0".into()], ..Forwarding::default() };
        let mut batch = apply_batch("wg0", &rules, &forwarding);
        // Drop the rewriting chains' rules, which need the host's user
        // namespace; what is left must all be accepted.
        batch.objects = batch
            .objects
            .iter()
            .filter(|o| {
                let text = serde_json::to_string(o).unwrap();
                !(text.contains("\"rule\"") && text.contains("mangle"))
            })
            .cloned()
            .collect::<Vec<_>>()
            .into();
        let script = nft_script(&[batch]) + "nft list table inet wireserve.wg0";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        let lines = normalised_lines(&listing);
        let m = format!("0x{SERVICE_MARK:08x}");
        for want in [
            "type nat hook postrouting priority srcnat; policy accept;".to_string(),
            format!("meta mark & {m} == {m} ip daddr 192.168.178.1 tcp dport 80 oifname != \"wg0\" masquerade"),
            format!("iifname \"eth0\" meta nfproto ipv4 ct mark & 0x{:08x} == 0x00000000 drop", SERVICE_MARK | EXIT_MARK | RELAY_MARK),
        ] {
            assert!(lines.contains(&want), "missing `{want}` in:\n{listing}");
        }
    }

    /// The exit against real packets (PLAN.md M27). This namespace is the
    /// gateway; a veth named `wg0` stands in for the mesh interface, since
    /// every rule keys on the name and none on WireGuard itself. Around it:
    /// the client, an "internet" host with no route back into the mesh, and
    /// a LAN host that does have one.
    ///
    /// - the client reaches the internet host, which it can only do
    ///   masqueraded, since that host cannot route to a mesh address;
    /// - it does not reach the LAN host, although forwarding and routing
    ///   would carry it there: private destinations are not the internet;
    /// - the internet host cannot open a connection into the mesh through
    ///   the guarded interface, even with a route to it.
    #[test]
    fn kernel_an_exit_forwards_its_clients_to_the_internet_and_nowhere_else() {
        if !crate::firewall::netns::reexec(
            "firewall::nftables::tests::kernel_an_exit_forwards_its_clients_to_the_internet_and_nowhere_else",
        ) {
            return;
        }
        let mut hosts = Vec::new();
        for _ in 0..3 {
            hosts.push(std::process::Command::new("unshare").args(["-n", "sleep", "60"]).spawn().unwrap());
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (client, internet, lan) = (hosts[0].id(), hosts[1].id(), hosts[2].id());
        let setup = format!(
            "ip link set lo up
             ip link add wg0 type veth peer name c0 && ip link set c0 netns {client}
             ip link add eth0 type veth peer name i0 && ip link set i0 netns {internet}
             ip link add lan0 type veth peer name l0 && ip link set l0 netns {lan}
             ip addr add 100.90.0.1/24 dev wg0 && ip link set wg0 up
             ip addr add 203.0.113.1/24 dev eth0 && ip link set eth0 up
             ip addr add 192.168.1.1/24 dev lan0 && ip link set lan0 up
             nsenter -t {client} -n sh -euc 'ip link set lo up; ip addr add 100.90.0.9/24 dev c0; ip link set c0 up; ip route add default via 100.90.0.1'
             nsenter -t {internet} -n sh -euc 'ip link set lo up; ip addr add 203.0.113.2/24 dev i0; ip link set i0 up'
             nsenter -t {lan} -n sh -euc 'ip link set lo up; ip addr add 192.168.1.2/24 dev l0; ip link set l0 up; ip route add 100.90.0.0/24 via 192.168.1.1'
             echo 0 > /proc/sys/net/ipv4/conf/all/forwarding
             for i in wg0 eth0 lan0; do echo 1 > /proc/sys/net/ipv4/conf/$i/forwarding; done"
        );
        let out = std::process::Command::new("sh").args(["-euc", &setup]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let forwarding = Forwarding { guarded: vec!["eth0".into()], ..exit_fwd(&[CLIENT]) };
        let script = nft_script(&[apply_batch("wg0", &[], &forwarding)]);
        let out = std::process::Command::new("sh").args(["-euc", &script]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let ping = |from: u32, to: &str| {
            std::process::Command::new("nsenter")
                .args(["-t", &from.to_string(), "-n", "ping", "-c3", "-i0.2", "-W1", to])
                .output()
                .unwrap()
                .status
                .success()
        };
        let to_internet = ping(client, "203.0.113.2");
        let to_lan = ping(client, "192.168.1.2");
        let _ = std::process::Command::new("nsenter")
            .args(["-t", &internet.to_string(), "-n", "ip", "route", "add", "100.90.0.0/24", "via", "203.0.113.1"])
            .status();
        let into_mesh = ping(internet, "100.90.0.9");
        for mut h in hosts {
            let _ = h.kill();
            let _ = h.wait();
        }
        assert!(to_internet, "the client must reach the internet host, masqueraded");
        assert!(!to_lan, "an exit must not forward to a private address");
        assert!(!into_mesh, "the guarded interface must not let anything new into the mesh");
    }

    /// The relay ports' drop (PLAN.md #274) spares this host's own UDP: a
    /// reply to a lookup sent from a relay port arrives, and a packet nobody
    /// asked for on one is still dropped.
    #[test]
    fn kernel_a_reply_to_this_hosts_own_udp_on_a_relay_port_arrives() {
        if !crate::firewall::netns::reexec(
            "firewall::nftables::tests::kernel_a_reply_to_this_hosts_own_udp_on_a_relay_port_arrives",
        ) {
            return;
        }
        let mut outside = std::process::Command::new("unshare").args(["-n", "sleep", "60"]).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let pid = outside.id();
        let setup = format!(
            "ip link set lo up
             ip link add eth0 type veth peer name o0 && ip link set o0 netns {pid}
             ip addr add 203.0.113.1/24 dev eth0 && ip link set eth0 up
             nsenter -t {pid} -n sh -euc 'ip link set lo up; ip addr add 203.0.113.2/24 dev o0; ip link set o0 up'"
        );
        let out = std::process::Command::new("sh").args(["-euc", &setup]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let forwarding = Forwarding { relay_ranges: Some(((41000, 41999), (42000, 42999))), ..Forwarding::default() };
        let script = nft_script(&[apply_batch("wg0", &[], &forwarding)]);
        let out = std::process::Command::new("sh").args(["-euc", &script]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        // Outside: a resolver that answers whatever arrives, and later sends
        // a datagram to a relay port unasked.
        let mut echo = std::process::Command::new("nsenter")
            .args(["-t", &pid.to_string(), "-n", "python3", "-c"])
            .arg(
                "import socket\n\
                 s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
                 s.bind(('203.0.113.2', 53))\n\
                 while True:\n    d, a = s.recvfrom(64)\n    s.sendto(d, a)\n",
            )
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        // This host: a lookup from relay port 41010.
        let socket = std::net::UdpSocket::bind("203.0.113.1:41010").unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        socket.send_to(b"lookup", "203.0.113.2:53").unwrap();
        let mut buf = [0u8; 64];
        let answered = socket.recv_from(&mut buf).is_ok_and(|(n, _)| &buf[..n] == b"lookup");
        // Unasked, to another relay port something listens on.
        let listener = std::net::UdpSocket::bind("203.0.113.1:41011").unwrap();
        listener.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
        let _ = std::process::Command::new("nsenter")
            .args(["-t", &pid.to_string(), "-n", "python3", "-c"])
            .arg("import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'unasked', ('203.0.113.1', 41011))")
            .status();
        let unasked_arrived = listener.recv_from(&mut buf).is_ok();
        let _ = echo.kill();
        let _ = echo.wait();
        let _ = outside.kill();
        let _ = outside.wait();
        assert!(answered, "the reply to this host's own lookup must arrive");
        assert!(!unasked_arrived, "a new flow to a relay port is still dropped");
    }

    /// A service mapped onto another address (PLAN.md M26) is reached from
    /// the carry interface the same way as from the mesh interface: a
    /// relayed peer (M39) has the same grants as a direct one (#278).
    ///
    /// Needs real root: an unprivileged namespace refuses the address
    /// rewrites' payload writes, and then this skips. Run the test binary
    /// itself under sudo to take it.
    #[test]
    fn kernel_a_mapped_service_is_reached_through_the_carry_interface_too() {
        if !crate::firewall::netns::reexec(
            "firewall::nftables::tests::kernel_a_mapped_service_is_reached_through_the_carry_interface_too",
        ) {
            return;
        }
        let mut hosts = Vec::new();
        for _ in 0..3 {
            hosts.push(std::process::Command::new("unshare").args(["-n", "sleep", "60"]).spawn().unwrap());
        }
        let stop = |hosts: Vec<std::process::Child>| {
            for mut h in hosts {
                let _ = h.kill();
                let _ = h.wait();
            }
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (direct, relayed, lan) = (hosts[0].id(), hosts[1].id(), hosts[2].id());
        let setup = format!(
            "ip link set lo up
             ip link add wg0 type veth peer name d0 && ip link set d0 netns {direct}
             ip link add wg0-t type veth peer name r0 && ip link set r0 netns {relayed}
             ip link add lan0 type veth peer name l0 && ip link set l0 netns {lan}
             ip addr add 100.90.0.2/32 dev wg0 && ip link set wg0 up && ip route add 100.90.0.7/32 dev wg0
             ip link set wg0-t up && ip route add 100.90.0.8/32 dev wg0-t src 100.90.0.2
             ip addr add 192.168.1.1/24 dev lan0 && ip link set lan0 up
             nsenter -t {direct} -n sh -euc 'ip link set lo up; ip addr add 100.90.0.7/32 dev d0; ip link set d0 up; ip route add 100.90.0.0/24 via 100.90.0.2 dev d0 onlink'
             nsenter -t {relayed} -n sh -euc 'ip link set lo up; ip addr add 100.90.0.8/32 dev r0; ip link set r0 up; ip route add 100.90.0.0/24 via 100.90.0.2 dev r0 onlink'
             nsenter -t {lan} -n sh -euc 'ip link set lo up; ip addr add 192.168.1.2/24 dev l0; ip link set l0 up'
             echo 0 > /proc/sys/net/ipv4/conf/all/forwarding
             echo 0 > /proc/sys/net/ipv4/conf/wg0-t/forwarding
             for i in wg0 lan0; do echo 1 > /proc/sys/net/ipv4/conf/$i/forwarding; done"
        );
        let out = std::process::Command::new("sh").args(["-euc", &setup]).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        // The veths stand in for WireGuard interfaces, which have no ARP:
        // the clients route through the host's address (Linux answers ARP
        // for it on any interface), never on-link to the service address,
        // which nothing would answer for.
        // 100.90.0.50:80 is 192.168.1.2:8080 on the LAN.
        let rule = ServiceRule::Mapped { vip: VIP, node: NODE, map: "80:192.168.1.2:8080".parse().unwrap(), sources: None };
        let forwarding = Forwarding { guarded: vec!["lan0".into()], ..Forwarding::default() };
        let script = nft_script(&[apply_batch_with("wg0", Some("wg0-t"), &[rule], &forwarding)]);
        let out = std::process::Command::new("sh").args(["-euc", &script]).output().unwrap();
        if String::from_utf8_lossy(&out.stderr).contains("Operation not permitted") {
            eprintln!("SKIPPED: the address rewrites need real root (run the test binary under sudo)");
            stop(hosts);
            return;
        }
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

        let mut server = std::process::Command::new("nsenter")
            .args(["-t", &lan.to_string(), "-n", "python3", "-c"])
            .arg(
                "import socket\n\
                 s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
                 s.bind(('192.168.1.2', 8080)); s.listen()\n\
                 while True:\n    c, _ = s.accept(); c.sendall(b'hello'); c.close()\n",
            )
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let fetch = |from: u32| {
            let out = std::process::Command::new("nsenter")
                .args(["-t", &from.to_string(), "-n", "python3", "-c"])
                .arg(format!("import socket; s = socket.create_connection(('{VIP}', 80), timeout=2); print(s.recv(16).decode())"))
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let through_mesh = fetch(direct);
        // IPv4 forwards only what arrives on an interface that forwards: the
        // agent turns the carry interface's switch on too (PLAN.md #279).
        let carry_not_forwarding = fetch(relayed);
        crate::firewall::ip_forward::set_enabled("wg0-t", true);
        let through_carry = fetch(relayed);
        let _ = server.kill();
        let _ = server.wait();
        stop(hosts);
        assert_eq!(through_mesh, "hello", "a direct peer reaches the LAN target");
        assert_eq!(carry_not_forwarding, "", "without the carry interface forwarding, nothing gets through it");
        assert_eq!(through_carry, "hello", "a relayed peer reaches it the same way");
    }

    // ---- end-to-end relay (PLAN.md M39) ----

    fn relay_pair() -> RelayForward {
        RelayForward {
            a: wireserve_types::RelayEnd { ip4: "100.90.0.1".parse().unwrap(), relay_port: 41001, carry_port: 50001 },
            c: wireserve_types::RelayEnd { ip4: "100.90.0.3".parse().unwrap(), relay_port: 41003, carry_port: 50003 },
        }
    }

    #[test]
    fn a_relayed_pair_is_sent_on_to_the_other_sides_carry_port_from_the_senders_relay_port() {
        let batch = as_json(&apply_batch("wg0", &[], &fwd(&[relay_pair()])));
        let udp = |port: u16| json!({"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": port}});
        let ip = |field: &str, a: &str| json!({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": field}}, "right": a}});
        let oif = json!({"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg0"}});
        assert_eq!(rules_in(&batch, "relay-pre"), [
            json!([iif("wg0"), ip("saddr", "100.90.0.1"), ip("daddr", "100.90.0.2"), udp(41003),
                {"dnat": {"addr": "100.90.0.3", "family": "ip", "port": 50003}}]),
            json!([iif("wg0"), ip("saddr", "100.90.0.3"), ip("daddr", "100.90.0.2"), udp(41001),
                {"dnat": {"addr": "100.90.0.1", "family": "ip", "port": 50001}}]),
        ]);
        assert_eq!(rules_in(&batch, "relay-post"), [
            json!([oif, ip("saddr", "100.90.0.1"), ip("daddr", "100.90.0.3"), udp(50003),
                {"snat": {"addr": "100.90.0.2", "family": "ip", "port": 41001}}]),
            json!([oif, ip("saddr", "100.90.0.3"), ip("daddr", "100.90.0.1"), udp(50001),
                {"snat": {"addr": "100.90.0.2", "family": "ip", "port": 41003}}]),
        ]);
        // Only that UDP is forwarded, and nothing else between the two.
        let fwd = rules_in(&batch, "wireserve-fwd");
        assert!(fwd.contains(&json!([iif("wg0"), oif, ip("saddr", "100.90.0.1"), ip("daddr", "100.90.0.3"), udp(50003), {"accept": null}])), "{fwd:?}");
        assert!(!serde_json::to_string(&fwd).unwrap().contains("\"set\""), "no address-set forward as transit has: {fwd:?}");
    }

    #[test]
    fn no_relay_rules_without_this_nodes_own_address_or_any_pair() {
        let without_self = Forwarding { relay_self: None, ..fwd(&[relay_pair()]) };
        for f in [without_self, fwd(&[])] {
            let batch = serde_json::to_string(&apply_batch("wg0", &[], &f)).unwrap();
            assert!(!batch.contains("relay-") && !batch.contains("nat\""), "{batch}");
        }
    }

    #[test]
    fn a_relayed_session_may_reach_the_carry_port_and_nothing_else_opens() {
        let forwarding = Forwarding { relay_ends: vec![50003], ..Forwarding::default() };
        let batch = as_json(&apply_batch("wg0", &[], &forwarding));
        let rules = rules_in(&batch, "wireserve-in");
        let open = json!([iif("wg0"), {"match": {"op": "in", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": {"set": [50003]}}}, {"accept": null}]);
        let at = rules.iter().position(|r| *r == open).expect("carry port accepted");
        assert_eq!(rules.last().unwrap(), &json!([iif("wg0"), {"drop": null}]));
        assert!(at < rules.len() - 2, "before the refusal and the drop");
    }

    #[test]
    fn the_carry_interface_gets_its_own_default_deny_and_the_same_grants() {
        let rules = [only(mapped("5432"), &["100.90.0.7"])];
        let batch = as_json(&apply_batch_with("wg0", Some("wg0-t"), &rules, &fwd(&[])));
        let in_table = |table: &str, chain: &str| -> Vec<Value> {
            batch["nftables"].as_array().unwrap().iter()
                .filter_map(|o| o.pointer("/add/rule"))
                .filter(|r| r["table"] == table && r["chain"] == chain)
                .map(|r| r["expr"].clone())
                .collect()
        };
        let input = in_table("wireserve.wg0-t", "wireserve-in");
        assert_eq!(input.first().unwrap(), &json!([iif("wg0-t"), established(), {"accept": null}]));
        assert_eq!(input.last().unwrap(), &json!([iif("wg0-t"), {"drop": null}]));
        // A mapped service's own flows go on to its target (PLAN.md #278),
        // and nothing else.
        assert_eq!(
            in_table("wireserve.wg0-t", "wireserve-fwd"),
            [
                json!([iif("wg0-t"), has_mark(json!({"ct": {"key": "mark"}})), {"accept": null}]),
                json!([iif("wg0-t"), {"drop": null}]),
            ]
        );
        let none = as_json(&apply_batch_with("wg0", Some("wg0-t"), &[terminated("443:32400")], &fwd(&[])));
        let forwards: Vec<&Value> = none["nftables"].as_array().unwrap().iter()
            .filter_map(|o| o.pointer("/add/rule"))
            .filter(|r| r["table"] == "wireserve.wg0-t" && r["chain"] == "wireserve-fwd")
            .collect();
        assert_eq!(forwards.len(), 1, "without a mapped service it forwards nothing: {forwards:?}");
        let pre = serde_json::to_string(&in_table("wireserve.wg0-t", "svc-pre")).unwrap();
        assert!(pre.contains("100.90.0.7") && pre.contains("wg0-t"), "the same grant: {pre}");
        // The mesh interface's own table is unchanged by it.
        assert_eq!(in_table("wireserve.wg0", "wireserve-in").last().unwrap(), &json!([iif("wg0"), {"drop": null}]));
    }

    #[test]
    fn a_terminated_address_is_not_dropped_for_the_carry_interface() {
        let batch = serde_json::to_string(&apply_batch_with("wg0", Some("wg0-t"), &[terminated("443:32400")], &fwd(&[]))).unwrap();
        assert_eq!(batch.matches(r#""right":"wg0-t","op":"!=""#).count(), 2, "both non-mesh drops exempt it: {batch}");
    }

    /// The relay against real WireGuard (PLAN.md M39). This namespace is the
    /// carrier B, with nothing but the rules `apply_batch` writes for it; A
    /// and C each run a mesh interface to B and a carry interface whose only
    /// peer is the other, dialled at B. They reach each other in both
    /// directions — whoever starts — while B forwards UDP and never an
    /// ICMP packet: it can't see inside.
    #[test]
    fn kernel_a_carrier_relays_a_session_it_cannot_read() {
        if !crate::firewall::netns::reexec("firewall::nftables::tests::kernel_a_carrier_relays_a_session_it_cannot_read") {
            return;
        }
        if std::process::Command::new("wg").arg("--version").output().is_err() {
            eprintln!("SKIPPED: no wg binary");
            return;
        }
        let mut hosts = Vec::new();
        for _ in 0..2 {
            hosts.push(std::process::Command::new("unshare").args(["-n", "sleep", "60"]).spawn().unwrap());
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        let (a, c) = (hosts[0].id(), hosts[1].id());
        let sh = |script: &str| {
            let out = std::process::Command::new("sh").args(["-euc", script]).output().unwrap();
            assert!(out.status.success(), "{script}\n{}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8(out.stdout).unwrap()
        };
        let keys = sh("for n in a b c; do k=$(wg genkey); echo $k $(echo $k | wg pubkey); done");
        let keys: Vec<Vec<&str>> = keys.lines().map(|l| l.split(' ').collect()).collect();
        let (ka, kb, kc) = (keys[0][0], keys[1][0], keys[2][0]);
        let (pa, pb, pc) = (keys[0][1], keys[1][1], keys[2][1]);
        // Underlay: A — B — C, and no way from A to C but through B.
        sh(&format!(
            "ip link set lo up
             ip link add ab type veth peer name ba && ip link set ba netns {a}
             ip link add cb type veth peer name bc && ip link set bc netns {c}
             ip addr add 10.1.0.2/24 dev ab && ip link set ab up
             ip addr add 10.2.0.2/24 dev cb && ip link set cb up
             nsenter -t {a} -n sh -euc 'ip link set lo up; ip addr add 10.1.0.1/24 dev ba; ip link set ba up'
             nsenter -t {c} -n sh -euc 'ip link set lo up; ip addr add 10.2.0.3/24 dev bc; ip link set bc up'
             ip link add wg0 type wireguard && ip addr add 100.90.0.2/32 dev wg0
             echo {kb} > /tmp/.kb && wg set wg0 private-key /tmp/.kb listen-port 51820 \
               peer {pa} allowed-ips 100.90.0.1/32 endpoint 10.1.0.1:51820 \
               peer {pc} allowed-ips 100.90.0.3/32 endpoint 10.2.0.3:51820 && rm /tmp/.kb
             ip link set wg0 up && ip route add 100.90.0.1/32 dev wg0 && ip route add 100.90.0.3/32 dev wg0
             echo 1 > /proc/sys/net/ipv4/conf/wg0/forwarding"
        ));
        // The carrier's table is in place before anyone dials it, as in a
        // real mesh, where it holds from the agent's start: a packet that
        // meets its drop is never tracked, so the first packet after the
        // relay rules arrive is the one that sets the flow's translation.
        sh(&nft_script(&[apply_batch("wg0", &[], &fwd(&[relay_pair()]))]));
        // A and C alike: mesh interface to B, carry interface to the other.
        for (pid, me, k, other, other_pub, other_relay, carry, other_carry) in [
            (a, "100.90.0.1", ka, "100.90.0.3", pc, 41003, 50001, 50003),
            (c, "100.90.0.3", kc, "100.90.0.1", pa, 41001, 50003, 50001),
        ] {
            let underlay_b = if pid == a { "10.1.0.2" } else { "10.2.0.2" };
            sh(&format!(
                "nsenter -t {pid} -n sh -euc '
                 ip link add wg0 type wireguard; ip addr add {me}/32 dev wg0
                 echo {k} > /tmp/.k{pid}; wg set wg0 private-key /tmp/.k{pid} listen-port 51820 \
                   peer {pb} allowed-ips 100.90.0.2/32 endpoint {underlay_b}:51820 persistent-keepalive 25
                 ip link set wg0 up; ip route add 100.90.0.2/32 dev wg0
                 ip link add wg0-t type wireguard; ip link set wg0-t mtu 1340
                 wg set wg0-t private-key /tmp/.k{pid} listen-port {carry} \
                   peer {other_pub} allowed-ips {other}/32 endpoint 100.90.0.2:{other_relay} persistent-keepalive 25
                 rm /tmp/.k{pid}
                 ip link set wg0-t up; ip route add {other}/32 dev wg0-t src {me}'"
            ));
            let _ = other_carry;
            // Its own tables: default-deny on both interfaces, the carry port
            // open to the mesh, and pings let in as a declared service would be.
            let batch = apply_batch_with("wg0", Some("wg0-t"), &[], &Forwarding { relay_ends: vec![carry], ..Forwarding::default() });
            sh(&format!(
                "nsenter -t {pid} -n sh -euc '{}'",
                nft_script(&[batch]).replace('\'', "'\\''")
                    + "nft insert rule inet wireserve.wg0-t wireserve-in iifname wg0-t icmp type echo-request accept"
            ));
        }
        sh("nft add table inet probe
            nft add chain inet probe f '{ type filter hook forward priority -10; }'
            nft add rule inet probe f meta l4proto icmp counter
            nft add rule inet probe f meta l4proto udp counter");
        let ping = |from: u32, to: &str| {
            std::process::Command::new("nsenter")
                .args(["-t", &from.to_string(), "-n", "ping", "-c3", "-i0.3", "-W3", to])
                .output()
                .unwrap()
                .status
                .success()
        };
        let a_to_c = ping(a, "100.90.0.3");
        let c_to_a = ping(c, "100.90.0.1");
        let counters = sh("nft list chain inet probe f");
        for mut h in hosts {
            let _ = h.kill();
            let _ = h.wait();
        }
        assert!(a_to_c, "A reaches C through the relay");
        assert!(c_to_a, "and C reaches A");
        let count = |proto: &str| -> u64 {
            let line = counters.lines().find(|l| l.contains(&format!("l4proto {proto}"))).unwrap();
            line.split("packets ").nth(1).unwrap().split(' ').next().unwrap().parse().unwrap()
        };
        assert_eq!(count("icmp"), 0, "the carrier never sees the pings: {counters}");
        assert!(count("udp") > 0, "only the session's UDP: {counters}");
    }

    #[test]
    fn kernel_apply_twice_replaces_rather_than_accumulates() {
        // Relay rules only filter and NAT, which an unprivileged namespace allows.
        let script = nft_script(&[apply_batch("wg0", &[], &fwd(&[pair(1)])), apply_batch("wg0", &[], &fwd(&[pair(2)]))])
            + "nft list table inet wireserve.wg0";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert!(!listing.contains("100.90.1."), "{listing}");
        assert!(listing.contains("ip saddr 100.90.2.1 ip daddr 100.90.2.3 udp dport 50003 accept"), "{listing}");
        assert_eq!(listing.matches("chain wireserve-in").count(), 1, "{listing}");
    }

    #[test]
    fn kernel_teardown_works_with_and_without_an_existing_table() {
        // Teardown on a fresh namespace (no table yet) must succeed — the
        // case that hung the old netlink implementation — and teardown
        // after apply must leave nothing behind.
        let script = nft_script(&[
            teardown_batch("wireserve.wg0"),
            apply_batch("wg0", &[], &fwd(&[])),
            teardown_batch("wireserve.wg0"),
        ])
            + "nft list ruleset";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert_eq!(listing.trim(), "");
    }

    #[test]
    fn every_interface_gets_its_own_table() {
        for ifname in ["wg0", "wireserve1"] {
            let batch = as_json(&apply_batch(ifname, &[mapped("80:5080")], &fwd(&[])));
            for object in batch["nftables"].as_array().unwrap() {
                let body = object.get("add").or_else(|| object.get("delete")).unwrap();
                let table = match body.get("table") {
                    Some(t) => &t["name"],
                    None => &body.as_object().unwrap().values().next().unwrap()["table"],
                };
                assert_eq!(*table, json!(format!("wireserve.{ifname}")), "{object}");
            }
        }
    }

    #[test]
    fn kernel_two_interfaces_keep_separate_tables() {
        let script = nft_script(&[
            apply_batch("wireserve0", &[], &fwd(&[pair(1)])),
            apply_batch("wireserve1", &[], &fwd(&[pair(2)])),
            apply_batch("wireserve0", &[], &fwd(&[pair(3)])),
            teardown_batch("wireserve.wireserve0"),
        ]) + "nft list ruleset";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert!(!listing.contains("wireserve.wireserve0"), "{listing}");
        assert!(listing.contains("table inet wireserve.wireserve1"), "{listing}");
        assert!(listing.contains("iifname \"wireserve1\" oifname \"wireserve1\" ip saddr 100.90.2.1 ip daddr 100.90.2.3 udp dport 50003 accept"), "{listing}");
    }
}
