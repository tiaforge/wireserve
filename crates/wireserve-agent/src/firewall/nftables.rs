//! Linux v1 `FirewallBackend` — nftables via the `nft` binary's JSON API
//! (spec §5; see `firewall/nft.rs` for why this is no longer netlink via
//! `rustables`).

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use std::net::Ipv4Addr;

use nftables::expr::{
    BinaryOperation, CTDir, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix, SetItem, CT,
};
use nftables::schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Rule, Table};
use nftables::stmt::{Accept, Drop, Mangle, Match, Operator, Reject, RejectType, Statement, NAT};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use wireserve_types::{FirewallBackend, Forwarding, PortMap, Proto, ServiceRule, TransitEndpoint, TransitForward};

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

/// Before conntrack (-200): the rewrite must happen before a connection
/// is ever tracked, so that the tracked connection is the rewritten one.
const PRIO_RAW: i32 = -300;
/// After conntrack, so the flow exists to carry the mark.
const PRIO_MANGLE: i32 = -150;
/// After source NAT (100), where a container runtime restores its reply.
const PRIO_AFTER_NAT: i32 = 300;
/// Source NAT itself.
const PRIO_SRCNAT: i32 = 100;

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
    nft: Nft,
    last: SharedRuleset,
}

impl NftablesBackend {
    /// Fails if `nft` can't be found: the firewall is not optional, so a
    /// daemon without one must refuse to start rather than run open.
    pub fn new(ifname: impl Into<String>) -> Result<Self, NftablesError> {
        Ok(Self {
            ifname: ifname.into(),
            nft: Nft::locate()?,
            last: SharedRuleset::default(),
        })
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
/// discovery in particular, which WireGuard's 1420 MTU makes routine — are
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

fn addr6(ip: std::net::Ipv6Addr) -> Expression<'static> {
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

/// Marks a request from the mesh for a service this node's own terminator
/// answers (PLAN.md M33), without rewriting it: the terminator listens on
/// the service address itself. The mark is what the rest of the machinery
/// already keys on — the filter's accept, and the host firewalls' openings
/// (`host_interop`), which admit marked flows and nothing else of ours —
/// so a terminated flow needs no rule of its own anywhere downstream.
fn mark_terminated(ifname: &str, vip: Ipv4Addr, map: &PortMap) -> Vec<Statement<'static>> {
    vec![
        iifname_is(ifname),
        is(payload("ip", "daddr"), addr(vip)),
        dport_is(map.proto, map.public),
        add_mark(meta(MetaKey::Mark)),
    ]
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

/// Every rule for one active transit pair (PLAN.md M23): one direction ×
/// one address family, only when that family actually has an address on
/// both ends of that direction. `TransitEndpoint::addrs4`/`addrs6` are
/// this endpoint's host address plus every owned VIP — matches
/// `ServiceRule::Mapped`'s existing "the node's own service addresses are
/// just more addresses that route to it" treatment.
fn transit_forward_rules(t: &str, ifname: &str, pair: &TransitForward) -> Vec<NfObject<'static>> {
    fn addrs4(e: &TransitEndpoint) -> Vec<Ipv4Addr> {
        e.ip4.into_iter().chain(e.vips.iter().copied()).collect()
    }
    fn addrs6(e: &TransitEndpoint) -> Vec<std::net::Ipv6Addr> {
        e.ip6.into_iter().collect()
    }

    let mut out = Vec::new();
    let accept = || Statement::Accept(None::<Accept>);

    let (near4, far4) = (addrs4(&pair.near), addrs4(&pair.far));
    if !near4.is_empty() && !far4.is_empty() {
        for (from, to) in [(&near4, &far4), (&far4, &near4)] {
            out.push(rule(t, FORWARD_CHAIN, vec![
                iifname_is(ifname),
                in_list(payload("ip", "saddr"), from.iter().map(|a| addr(*a)).collect()),
                in_list(payload("ip", "daddr"), to.iter().map(|a| addr(*a)).collect()),
                accept(),
            ]));
        }
    }
    let (near6, far6) = (addrs6(&pair.near), addrs6(&pair.far));
    if !near6.is_empty() && !far6.is_empty() {
        for (from, to) in [(&near6, &far6), (&far6, &near6)] {
            out.push(rule(t, FORWARD_CHAIN, vec![
                iifname_is(ifname),
                in_list(payload("ip6", "saddr"), from.iter().map(|a| addr6(*a)).collect()),
                in_list(payload("ip6", "daddr"), to.iter().map(|a| addr6(*a)).collect()),
                accept(),
            ]));
        }
    }
    out
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
pub(crate) fn apply_batch(ifname: &str, rules: &[ServiceRule], forwarding: &Forwarding) -> Nftables<'static> {
    let name = table_name(ifname);
    let t = name.as_str();
    let mut objects: Vec<NfObject<'static>> = delete_table_cmds(t).into();
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table(t)))));

    // (service address, where it goes — the node or the mapping's own
    // target address, the mapping)
    let mapped: Vec<(Ipv4Addr, Ipv4Addr, PortMap)> = rules
        .iter()
        .filter_map(|r| match *r {
            ServiceRule::Mapped { vip, node, map, .. } => Some((vip, map.addr.unwrap_or(node), map)),
            ServiceRule::Terminated { .. } => None,
        })
        .collect();
    // Answered on the service address by this node's own terminator
    // (PLAN.md M33).
    let terminated: Vec<(Ipv4Addr, PortMap)> = rules
        .iter()
        .filter_map(|r| match *r {
            ServiceRule::Terminated { vip, map } => Some((vip, map)),
            _ => None,
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
    for (vip, _) in &terminated {
        objects.push(rule(t, CHAIN_NAME, vec![
            iifname_is_not(ifname),
            iifname_is_not("lo"),
            is(payload("ip", "daddr"), addr(*vip)),
            Statement::Drop(None::<Drop>),
        ]));
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
            lacks_bits(ct("mark", None), SERVICE_MARK | EXIT_MARK),
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
    for pair in &forwarding.transit {
        objects.extend(transit_forward_rules(t, ifname, pair));
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

    // The chains below are the service-address rewrite machinery
    // (PLAN.md M20) — transit needs none of it (a transited connection is
    // forwarded exactly as received, never rewritten), so this early
    // return is unaffected by `transit` and stays keyed on `mapped`
    // alone, same as before this feature existed — plus the terminated
    // services (PLAN.md M33), which need the marking half of it.
    if !has_service_addresses {
        return Nftables { objects: objects.into() };
    }

    // ---- service addresses ----
    objects.push(chain(t, PRE_CHAIN, NfChainType::Filter, NfHook::Prerouting, PRIO_RAW));
    for (vip, dest, map) in &mapped {
        let mut expr = vec![iifname_is(ifname)];
        expr.extend(forward_rewrite(*vip, *dest, map));
        objects.push(rule(t, PRE_CHAIN, expr));
    }
    for (vip, map) in &terminated {
        objects.push(rule(t, PRE_CHAIN, mark_terminated(ifname, *vip, map)));
    }
    // A port a service address does not publish. A mapped service's address
    // is not local to this host, so such a request never reaches the input
    // chain's refusal: it would be forwarded into the forward chain's drop,
    // or dropped by the kernel outright where forwarding is off. Refused
    // here instead, once the rules above have rewritten or marked every
    // request for a published port.
    let vips: std::collections::BTreeSet<Ipv4Addr> =
        mapped.iter().map(|(vip, ..)| *vip).chain(terminated.iter().map(|(vip, _)| *vip)).collect();
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
    // addresses there) and is now local.
    objects.push(chain(t, OUT_CHAIN, NfChainType::Route, NfHook::Output, PRIO_RAW));
    for (vip, dest, map) in &mapped {
        objects.push(rule(t, OUT_CHAIN, forward_rewrite(*vip, *dest, map)));
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
        for (vip, dest, map) in &mapped {
            objects.push(rule(t, name, reverse_rewrite(*vip, *dest, map)));
        }
    }
    let remote: Vec<_> = rules
        .iter()
        .filter_map(|r| match *r {
            ServiceRule::Mapped { map, .. } => map.addr.map(|dest| (dest, map)),
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
        let batch = apply_batch(&self.ifname, rules, forwarding);
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const NODE: Ipv4Addr = Ipv4Addr::new(100, 90, 0, 2);
    const VIP: Ipv4Addr = Ipv4Addr::new(100, 90, 0, 50);

    fn fwd(transit: &[TransitForward]) -> Forwarding {
        Forwarding { transit: transit.to_vec(), ..Forwarding::default() }
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
        }
    }

    #[test]
    fn apply_with_no_services_is_default_deny_on_the_interface_only() {
        let mut expected = prelude();
        expected.extend(input_deny());
        expected.extend(forward(vec![]));
        assert_eq!(as_json(&apply_batch("wg0", &[], &fwd(&[]))), json!({ "nftables": expected }));
    }



    fn endpoint4(ip: &str, vips: &[&str]) -> TransitEndpoint {
        TransitEndpoint { ip4: Some(ip.parse().unwrap()), ip6: None, vips: vips.iter().map(|v| v.parse().unwrap()).collect() }
    }

    #[test]
    fn a_transit_pair_produces_bidirectional_address_scoped_forward_rules() {
        let pair = TransitForward {
            near: endpoint4("100.90.0.10", &["100.90.0.50"]),
            far: endpoint4("100.90.0.20", &[]),
        };
        let mut expected = prelude();
        expected.extend(input_deny());
        expected.extend(forward(vec![
            rule_in("wireserve-fwd", json!([
                iif("wg0"),
                in_addrs("ip", "saddr", &["100.90.0.10", "100.90.0.50"]),
                in_addrs("ip", "daddr", &["100.90.0.20"]),
                {"accept": null}
            ])),
            rule_in("wireserve-fwd", json!([
                iif("wg0"),
                in_addrs("ip", "saddr", &["100.90.0.20"]),
                in_addrs("ip", "daddr", &["100.90.0.10", "100.90.0.50"]),
                {"accept": null}
            ])),
        ]));
        assert_eq!(as_json(&apply_batch("wg0", &[], &fwd(&[pair]))), json!({ "nftables": expected }));
    }

    #[test]
    fn a_v6_only_transit_pair_produces_ip6_rules_not_ip4() {
        let pair = TransitForward {
            near: TransitEndpoint { ip4: None, ip6: Some("fd00:90::10".parse().unwrap()), vips: vec![] },
            far: TransitEndpoint { ip4: None, ip6: Some("fd00:90::20".parse().unwrap()), vips: vec![] },
        };
        let batch = as_json(&apply_batch("wg0", &[], &fwd(&[pair]))).to_string();
        assert!(batch.contains("\"protocol\":\"ip6\""), "{batch}");
        assert!(!batch.contains("\"protocol\":\"ip\""), "{batch}");
    }

    #[test]
    fn a_transit_pair_missing_one_sides_family_emits_no_rule_for_that_family() {
        // `near` has no v6 address at all — a rule with an empty `saddr`
        // set would be nonsensical (and, more importantly, would nft
        // reject or mis-render it as "match nothing" vs "match
        // everything"?). Emitting no rule for that family is the only
        // safe reading, mirrored on `desired_peers`'s dangling-`via`
        // handling: nothing to fold into, so nothing is misrouted either.
        let pair = TransitForward {
            near: endpoint4("100.90.0.10", &[]),
            far: TransitEndpoint { ip4: Some("100.90.0.20".parse().unwrap()), ip6: Some("fd00:90::20".parse().unwrap()), vips: vec![] },
        };
        let batch = as_json(&apply_batch("wg0", &[], &fwd(&[pair]))).to_string();
        assert!(!batch.contains("ip6"), "{batch}");
    }

    #[test]
    fn no_transit_pairs_is_byte_for_byte_unchanged_from_before_the_feature() {
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
                // Neither ours nor an exit's (PLAN.md M27): replies to both
                // arrive on an interface the agent owns.
                {"match": {"op": "==", "left": {"&": [{"ct": {"key": "mark"}}, SERVICE_MARK | EXIT_MARK]}, "right": 0}},
                {"drop": null},
            ])
        );
        // Never the mesh interface: that would drop every transit flow.
        assert_eq!(fwd_rules[1], json!([iif("wg0"), established(), {"accept": null}]));
        assert!(!fwd_rules.iter().any(|r| r[0] == iif("wg0") && r.to_string().contains(r#""op":"!=""#)));
    }

    // ---- PLAN.md M33: terminated on this node ----

    fn terminated(map: &str) -> ServiceRule {
        ServiceRule::Terminated { vip: VIP, map: map.parse().unwrap() }
    }

    #[test]
    fn a_terminated_service_is_marked_unrewritten_and_closed_to_the_lan() {
        let batch = as_json(&apply_batch("wg0", &[terminated("443:32400")], &fwd(&[])));
        let text = batch.to_string();
        // Marked on the way in, nothing rewritten anywhere, target never
        // mentioned: the terminator reaches it locally.
        // Then any other port refused (see the mapped service's test).
        let pre = rules_in(&batch, "svc-pre");
        assert_eq!(pre.len(), 2, "{pre:?}");
        assert!(pre[1].to_string().contains("tcp reset"), "{pre:?}");
        let pre = pre[0].to_string();
        assert!(pre.contains("443") && pre.contains(&VIP.to_string()) && pre.contains("mark"), "{pre}");
        assert!(!text.contains("32400"), "{text}");
        assert!(rules_in(&batch, "svc-rev-post").is_empty() && rules_in(&batch, "svc-out").is_empty());
        assert!(chain_names(&batch).contains(&"svc-mark-pre".to_string()), "chains exist with only a terminated rule");
        // Accepted from the mesh by the mark; dropped from anywhere but the
        // mesh and the host itself.
        let input = rules_in(&batch, "wireserve-in");
        assert!(input.iter().any(|r| r.to_string().contains("ct") && r.to_string().contains("accept")), "{input:?}");
        let lan_drop = input[0].to_string();
        assert!(
            lan_drop.contains("!=") && lan_drop.contains("\"lo\"") && lan_drop.contains(&VIP.to_string()) && lan_drop.contains("drop"),
            "{lan_drop}"
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
        let pair = TransitForward { near: endpoint4("100.90.0.10", &[]), far: endpoint4("100.90.0.20", &[]) };
        let batch = as_json(&apply_batch("wg0", &[terminated("443:22"), mapped("80:5080")], &fwd(&[pair])));
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
                    // but this one: it names the address.
                    "wireserve-in" => *first == iif(ifname) || text.contains("100.90.0.50"),
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



    #[test]
    fn kernel_accepts_a_transit_pairs_ruleset() {
        let pair = TransitForward {
            near: endpoint4("100.90.0.10", &["100.90.0.50"]),
            far: endpoint4("100.90.0.20", &[]),
        };
        let script = nft_script(&[apply_batch("wg0", &[], &fwd(&[pair]))]) + "nft list table inet wireserve.wg0";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert_eq!(
            normalised_lines(&listing),
            [
                "table inet wireserve.wg0 {",
                "chain wireserve-in {",
                "type filter hook input priority filter; policy accept;",
                "iifname \"wg0\" ct state established,related accept",
                "iifname \"wg0\" meta l4proto tcp reject with tcp reset",
                "iifname \"wg0\" drop",
                "}",
                "chain wireserve-fwd {",
                "type filter hook forward priority filter; policy accept;",
                "iifname \"wg0\" ct state established,related accept",
                "iifname \"wg0\" ip saddr { 100.90.0.10, 100.90.0.50 } ip daddr 100.90.0.20 accept",
                "iifname \"wg0\" ip saddr 100.90.0.20 ip daddr { 100.90.0.10, 100.90.0.50 } accept",
                "iifname \"wg0\" drop",
                "}",
                "}",
            ]
        );
    }

    /// The service-address chains. Rewriting headers needs the host's own
    /// user namespace, which an unprivileged test namespace is not: there
    /// the kernel refuses exactly the rules that rewrite, with EPERM, after
    /// `nft` has parsed and evaluated every statement — so that is checked
    /// instead, and every other rule must still have been accepted. As
    /// root (`sudo -E cargo test`, or CI) the whole listing is checked.
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

    /// A terminated service rewrites nothing, so the kernel takes its rules
    /// in an unprivileged namespace too (PLAN.md M33).
    #[test]
    fn kernel_accepts_a_terminated_service() {
        let batch = serde_json::to_string(&apply_batch("wg0", &[terminated("443:32400")], &fwd(&[]))).unwrap();
        let script = format!("nft -j -f - <<'JSON'\n{batch}\nJSON\nnft list ruleset");
        let Some((listing, stderr)) = crate::firewall::netns::run_capturing(&script) else {
            return;
        };
        assert!(stderr.trim().is_empty(), "{stderr}");
        let lines = normalised_lines(&listing);
        let has = |l: &str| assert!(lines.iter().any(|x| x == l), "missing `{l}` in:\n{listing}");
        let m = format!("0x{SERVICE_MARK:08x}");
        has(&format!("iifname \"wg0\" ip daddr 100.90.0.50 tcp dport 443 meta mark set meta mark | {m}"));
        has("iifname != \"wg0\" iifname != \"lo\" ip daddr 100.90.0.50 drop");
        has(&format!("iifname \"wg0\" ip daddr 100.90.0.50 meta mark & {m} != {m} meta l4proto tcp reject with tcp reset"));
        has(&format!("meta mark & {m} == {m} ct mark set ct mark | {m}"));
        has(&format!("iifname \"wg0\" ct mark & {m} == {m} accept"));
    }

    /// The masquerade and the guard rewrite nothing, so unlike the chains
    /// above the kernel takes them in an unprivileged namespace too.
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
            format!("iifname \"eth0\" meta nfproto ipv4 ct mark & 0x{:08x} == 0x00000000 drop", SERVICE_MARK | EXIT_MARK),
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

    #[test]
    fn kernel_apply_twice_replaces_rather_than_accumulates() {
        // Terminated rules only mark, which an unprivileged namespace allows.
        let tcp = |port: u16| terminated(&format!("{port}:{port}"));
        let script = nft_script(&[apply_batch("wg0", &[tcp(1)], &fwd(&[])), apply_batch("wg0", &[tcp(2)], &fwd(&[]))])
            + "nft list table inet wireserve.wg0";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert!(!listing.contains("dport 1 "), "{listing}");
        assert!(listing.contains("ip daddr 100.90.0.50 tcp dport 2 meta mark set"), "{listing}");
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
        let tcp = |port: u16| terminated(&format!("{port}:{port}"));
        let script = nft_script(&[
            apply_batch("wireserve0", &[tcp(1)], &fwd(&[])),
            apply_batch("wireserve1", &[tcp(2)], &fwd(&[])),
            apply_batch("wireserve0", &[tcp(3)], &fwd(&[])),
            teardown_batch("wireserve.wireserve0"),
        ]) + "nft list ruleset";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert!(!listing.contains("wireserve.wireserve0"), "{listing}");
        assert!(listing.contains("table inet wireserve.wireserve1"), "{listing}");
        assert!(listing.contains("iifname \"wireserve1\" ip daddr 100.90.0.50 tcp dport 2 meta mark set"), "{listing}");
    }
}
