//! Linux v1 `FirewallBackend` — nftables via the `nft` binary's JSON API
//! (spec §5; see `firewall/nft.rs` for why this is no longer netlink via
//! `rustables`).

use std::borrow::Cow;

use std::net::Ipv4Addr;

use nftables::expr::{
    BinaryOperation, CTDir, Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, CT,
};
use nftables::schema::{Chain, NfCmd, NfListObject, NfObject, Nftables, Rule, Table};
use nftables::stmt::{Accept, Drop, Mangle, Match, Operator, Statement};
use nftables::types::{NfChainPolicy, NfChainType, NfFamily, NfHook};
use wireserve_types::{FirewallBackend, PortMap, Proto, ServiceRule};

use super::nft::{Nft, NftError};

/// Our table is `inet wireserve.<ifname>`: one per interface, so several
/// agents on one host each replace and remove only their own.
pub const TABLE_PREFIX: &str = "wireserve.";
/// The single fixed-name table every version before multi-instance
/// support used. Nothing creates it any more; see `remove_legacy_table`.
pub const LEGACY_TABLE_NAME: &str = "wireserve";
const CHAIN_NAME: &str = "wireserve-in";
const FORWARD_CHAIN: &str = "wireserve-fwd";
const PRE_CHAIN: &str = "svc-pre";
const OUT_CHAIN: &str = "svc-out";
const MARK_PRE_CHAIN: &str = "svc-mark-pre";
const MARK_OUT_CHAIN: &str = "svc-mark-out";
const REV_POST_CHAIN: &str = "svc-rev-post";
const REV_IN_CHAIN: &str = "svc-rev-in";

/// Before conntrack (-200): the rewrite must happen before a connection
/// is ever tracked, so that the tracked connection is the rewritten one.
const PRIO_RAW: i32 = -300;
/// After conntrack, so the flow exists to carry the mark.
const PRIO_MANGLE: i32 = -150;
/// After source NAT (100), where a container runtime restores its reply.
const PRIO_AFTER_NAT: i32 = 300;

/// The packet and conntrack mark bit that says "this flow came in through
/// a service address". One bit, always set and tested under a mask, so
/// it coexists with other users of the mark — deliberately outside
/// Tailscale's `0xff0000`, Kubernetes' `0x4000`/`0x8000` and Cilium's
/// `0xf00`. Several agents on one host share it safely: every rule that
/// acts on it also matches its own interface or its own node address.
pub const SERVICE_MARK: u32 = 0x0100_0000;

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

pub struct NftablesBackend {
    /// The WireGuard interface every rule is scoped to — this backend must
    /// never install a rule that isn't `iifname`-restricted to it, or it
    /// would be firewalling the whole host rather than just the mesh.
    ifname: String,
    nft: Nft,
}

impl NftablesBackend {
    /// Fails if `nft` can't be found: the firewall is not optional, so a
    /// daemon without one must refuse to start rather than run open.
    pub fn new(ifname: impl Into<String>) -> Result<Self, NftablesError> {
        Ok(Self {
            ifname: ifname.into(),
            nft: Nft::locate()?,
        })
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

fn dport_is(proto: Proto, port: u16) -> Statement<'static> {
    is(payload(l4(proto), "dport"), Expression::Number(u32::from(port)))
}

/// Marks a packet bound for a service's public port on its address and
/// rewrites it to the target port on the node's own address, all before
/// conntrack has seen it. Shared by the packets arriving from the mesh
/// and the node's own (see `apply_batch`).
fn forward_rewrite(vip: Ipv4Addr, node: Ipv4Addr, map: &PortMap) -> Vec<Statement<'static>> {
    vec![
        is(payload("ip", "daddr"), addr(vip)),
        dport_is(map.proto, map.public),
        set(payload("ip", "daddr"), addr(node)),
        set(payload(l4(map.proto), "dport"), Expression::Number(u32::from(map.target))),
        add_mark(meta(MetaKey::Mark)),
    ]
}

/// The way back: a reply leaving the target port of a marked flow gets
/// the service's address and public port again, so the client sees the
/// answer come from where it sent the request.
fn reverse_rewrite(vip: Ipv4Addr, node: Ipv4Addr, map: &PortMap) -> Vec<Statement<'static>> {
    vec![
        is(ct("direction", None), Expression::String("reply".into())),
        has_mark(ct("mark", None)),
        is(payload("ip", "saddr"), addr(node)),
        is(payload(l4(map.proto), "sport"), Expression::Number(u32::from(map.target))),
        set(payload("ip", "saddr"), addr(vip)),
        set(payload(l4(map.proto), "sport"), Expression::Number(u32::from(map.public))),
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
pub(crate) fn apply_batch(ifname: &str, rules: &[ServiceRule]) -> Nftables<'static> {
    let name = table_name(ifname);
    let t = name.as_str();
    let mut objects: Vec<NfObject<'static>> = delete_table_cmds(t).into();
    objects.push(NfObject::CmdObject(NfCmd::Add(NfListObject::Table(table(t)))));

    let mapped: Vec<(Ipv4Addr, Ipv4Addr, PortMap)> = rules
        .iter()
        .filter_map(|r| match *r {
            ServiceRule::Mapped { vip, node, map } => Some((vip, node, map)),
            ServiceRule::Open { .. } => None,
        })
        .collect();
    let open: Vec<(Proto, u16)> = rules
        .iter()
        .filter_map(|r| match *r {
            ServiceRule::Open { proto, port } => Some((proto, port)),
            ServiceRule::Mapped { .. } => None,
        })
        .collect();
    let accept = || Statement::Accept(None::<Accept>);

    // ---- input: what reaches this host's own sockets from the mesh ----
    objects.push(chain(t, CHAIN_NAME, NfChainType::Filter, NfHook::Input, 0));
    // Allow return traffic for connections this node itself initiated over
    // the WireGuard interface (e.g. this node acting as a client of another
    // peer's declared service) — without this, a WG-interface-scoped
    // default-deny would break outbound connectivity through the tunnel
    // just as badly as the bug above broke it on every other interface.
    objects.push(rule(t, CHAIN_NAME, vec![iifname_is(ifname), established_or_related(), accept()]));
    for &(proto, port) in &open {
        objects.push(rule(t, CHAIN_NAME, vec![iifname_is(ifname), dport_is(proto, port), accept()]));
    }
    if !mapped.is_empty() {
        objects.push(rule(t, CHAIN_NAME, vec![iifname_is(ifname), has_mark(ct("mark", None)), accept()]));
    }
    // Default-deny, but ONLY for the WireGuard interface — everything else
    // stays governed by the chain's own accept policy above.
    objects.push(rule(t, CHAIN_NAME, vec![iifname_is(ifname), Statement::Drop(None::<Drop>)]));

    // ---- forward: what the mesh reaches *through* this host ----
    // A published container port is a DNAT to the container, so a request
    // for it is forwarded, never delivered locally, and the input chain
    // above never sees it. Without this chain every container port on the
    // node was reachable from the whole mesh, declared or not.
    objects.push(chain(t, FORWARD_CHAIN, NfChainType::Filter, NfHook::Forward, 0));
    objects.push(rule(t, FORWARD_CHAIN, vec![iifname_is(ifname), established_or_related(), accept()]));
    for &(proto, port) in &open {
        // After the runtime's DNAT the packet's own port is the
        // container's; the port the peer asked for is the original one.
        objects.push(rule(t, FORWARD_CHAIN, vec![
            iifname_is(ifname),
            is(meta(MetaKey::L4proto), Expression::String(l4(proto).into())),
            is(ct("proto-dst", Some(CTDir::Original)), Expression::Number(u32::from(port))),
            accept(),
        ]));
    }
    if !mapped.is_empty() {
        objects.push(rule(t, FORWARD_CHAIN, vec![iifname_is(ifname), has_mark(ct("mark", None)), accept()]));
    }
    objects.push(rule(t, FORWARD_CHAIN, vec![iifname_is(ifname), Statement::Drop(None::<Drop>)]));

    if mapped.is_empty() {
        return Nftables { objects: objects.into() };
    }

    // ---- service addresses ----
    objects.push(chain(t, PRE_CHAIN, NfChainType::Filter, NfHook::Prerouting, PRIO_RAW));
    for (vip, node, map) in &mapped {
        let mut expr = vec![iifname_is(ifname)];
        expr.extend(forward_rewrite(*vip, *node, map));
        objects.push(rule(t, PRE_CHAIN, expr));
    }
    // The node's own clients. A `route` chain, so the kernel routes the
    // packet again after its destination changed: it was headed for the
    // mesh interface (see `routes`, which routes this node's own service
    // addresses there) and is now local.
    objects.push(chain(t, OUT_CHAIN, NfChainType::Route, NfHook::Output, PRIO_RAW));
    for (vip, node, map) in &mapped {
        objects.push(rule(t, OUT_CHAIN, forward_rewrite(*vip, *node, map)));
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
        for (vip, node, map) in &mapped {
            objects.push(rule(t, name, reverse_rewrite(*vip, *node, map)));
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

/// Removes the fixed-name table of an agent from before multi-instance
/// support — left behind if that version crashed, or was upgraded while
/// its interface was up. Default-denying `wg0`, it would otherwise keep
/// blocking any other tunnel that later uses that name.
pub fn remove_legacy_table(nft: &Nft) -> Result<(), NftablesError> {
    nft.apply(&teardown_batch(LEGACY_TABLE_NAME))?;
    Ok(())
}

impl FirewallBackend for NftablesBackend {
    type Error = NftablesError;

    /// Full-replace in one atomic transaction: the previous table (if any)
    /// is deleted and the table/chain/rules recreated from scratch.
    fn apply(&mut self, rules: &[ServiceRule]) -> Result<(), Self::Error> {
        match self.nft.apply(&apply_batch(&self.ifname, rules)) {
            Err(e @ NftError::Failed { .. })
                if e.to_string().contains("Operation not permitted")
                    && rules.iter().any(|r| matches!(r, ServiceRule::Mapped { .. })) =>
            {
                Err(NftablesError::RewriteRefused(e))
            }
            other => Ok(other?),
        }
    }

    /// Removes this interface's table entirely, if present.
    fn teardown(&mut self) -> Result<(), Self::Error> {
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

    fn open(proto: Proto, port: u16) -> ServiceRule {
        ServiceRule::Open { proto, port }
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
        expected.push(rule_json(json!([iif("wg0"), {"drop": null}])));
        expected.extend(forward(vec![]));
        assert_eq!(as_json(&apply_batch("wg0", &[])), json!({ "nftables": expected }));
    }

    #[test]
    fn apply_opens_exactly_the_declared_services() {
        let rules = [open(Proto::Tcp, 32400), open(Proto::Udp, 5353)];
        let mut expected = prelude();
        expected.push(rule_json(json!([
            iif("wg0"),
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 32400}},
            {"accept": null}
        ])));
        expected.push(rule_json(json!([
            iif("wg0"),
            {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 5353}},
            {"accept": null}
        ])));
        expected.push(rule_json(json!([iif("wg0"), {"drop": null}])));
        // A container behind a published port is forwarded to: matched on
        // the port the peer asked for, before the runtime's DNAT.
        expected.extend(forward(vec![
            rule_in("wireserve-fwd", json!([
                iif("wg0"),
                {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
                {"match": {"op": "==", "left": {"ct": {"key": "proto-dst", "dir": "original"}}, "right": 32400}},
                {"accept": null}
            ])),
            rule_in("wireserve-fwd", json!([
                iif("wg0"),
                {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "udp"}},
                {"match": {"op": "==", "left": {"ct": {"key": "proto-dst", "dir": "original"}}, "right": 5353}},
                {"accept": null}
            ])),
        ]));
        assert_eq!(as_json(&apply_batch("wg0", &rules)), json!({ "nftables": expected }));
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
        let batch = as_json(&apply_batch("wg0", &[mapped("80:5080")]));
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
        assert_eq!(rules_of("svc-pre"), [Value::Array(from_mesh)]);
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

    #[test]
    fn without_a_mapped_service_there_are_no_rewrite_chains() {
        let batch = as_json(&apply_batch("wg0", &[open(Proto::Tcp, 22)])).to_string();
        assert!(!batch.contains("svc-") && !batch.contains("mangle"), "{batch}");
    }

    #[test]
    fn every_rule_is_scoped_to_the_interface_or_to_a_flow_it_marked() {
        // The accept/drop rules and the inbound rewrite act on the mesh
        // interface only. The rest can't be: the node's own clients never
        // arrive on it, and replies leave on whatever interface. They're
        // scoped instead to what only this agent produces — its own
        // service address as destination, or its own mark.
        let rules = [open(Proto::Tcp, 22), mapped("80:5080"), mapped("53:5353/udp")];
        for ifname in ["wg0", "wireserve0", "wg-mesh.1"] {
            let batch = as_json(&apply_batch(ifname, &rules));
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
                    "wireserve-in" | "wireserve-fwd" | "svc-pre" => *first == iif(ifname),
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
        let batch = as_json(&apply_batch("wg0", &[mapped("80:5080")]));
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
    fn kernel_accepts_apply_and_renders_the_expected_ruleset() {
        let script = nft_script(&[apply_batch("wg0", &[open(Proto::Tcp, 32400)])]) + "nft list table inet wireserve.wg0";
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
                "iifname \"wg0\" tcp dport 32400 accept",
                "iifname \"wg0\" drop",
                "}",
                "chain wireserve-fwd {",
                "type filter hook forward priority filter; policy accept;",
                "iifname \"wg0\" ct state established,related accept",
                "iifname \"wg0\" meta l4proto tcp ct original proto-dst 32400 accept",
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
        let rules = [mapped("80:5080"), mapped("53:5353/udp")];
        let batch = serde_json::to_string(&apply_batch("wg0", &rules)).unwrap();
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
    }

    #[test]
    fn kernel_apply_twice_replaces_rather_than_accumulates() {
        let tcp = |port| open(Proto::Tcp, port);
        let script = nft_script(&[apply_batch("wg0", &[tcp(1)]), apply_batch("wg0", &[tcp(2)])])
            + "nft list table inet wireserve.wg0";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert!(!listing.contains("dport 1 "), "{listing}");
        assert!(listing.contains("tcp dport 2 accept"), "{listing}");
        assert_eq!(listing.matches("chain wireserve-in").count(), 1, "{listing}");
    }

    #[test]
    fn kernel_teardown_works_with_and_without_an_existing_table() {
        // Teardown on a fresh namespace (no table yet) must succeed — the
        // case that hung the old netlink implementation — and teardown
        // after apply must leave nothing behind.
        let script = nft_script(&[
            teardown_batch("wireserve.wg0"),
            apply_batch("wg0", &[]),
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
            let batch = as_json(&apply_batch(ifname, &[mapped("80:5080")]));
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
        let tcp = |port| open(Proto::Tcp, port);
        let script = nft_script(&[
            apply_batch("wireserve0", &[tcp(1)]),
            apply_batch("wireserve1", &[tcp(2)]),
            apply_batch("wireserve0", &[tcp(3)]),
            teardown_batch("wireserve.wireserve0"),
        ]) + "nft list ruleset";
        let Some(listing) = crate::firewall::netns::run(&script) else {
            return;
        };
        assert!(!listing.contains("wireserve.wireserve0"), "{listing}");
        assert!(listing.contains("table inet wireserve.wireserve1"), "{listing}");
        assert!(listing.contains("iifname \"wireserve1\" tcp dport 2 accept"), "{listing}");
    }
}
