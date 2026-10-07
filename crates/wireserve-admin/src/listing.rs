//! What the list commands print for a person: padded tables from
//! `wireserve_types::term`, one header row each. `--json` prints the
//! coordinator's response instead, for scripts.

use chrono::{DateTime, Utc};
use wireserve_types::term::{ago, clean, fields, table};
use wireserve_types::{
    AdminPeersResponse, AdminServiceInfo, DnsRecordState, GrantsResponse, GroupsResponse, OwnersStatus, PeerInfo,
    RelayPortsResponse, ServiceApprovalState,
};

/// `-` for nothing, else the cleaned items joined by commas.
fn list(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_string()
    } else {
        items.iter().map(|s| clean(s)).collect::<Vec<_>>().join(",")
    }
}

fn opt(v: Option<&str>) -> String {
    v.map_or_else(|| "-".to_string(), clean)
}

/// `service list`. The DNS column only when the coordinator publishes
/// records, the NOTE column only when some service has one.
#[must_use]
pub fn services(services: &[AdminServiceInfo]) -> String {
    let dns = services.iter().any(|s| s.dns.is_some());
    let mut header = vec!["SERVICE", "NODE", "STATE", "ADDRESS", "PORTS", "GROUPS"];
    if dns {
        header.push("DNS");
    }
    let mut rows: Vec<Vec<String>> = services
        .iter()
        .map(|s| {
            let state = match s.state {
                ServiceApprovalState::Pending => "pending",
                ServiceApprovalState::Approved => "approved",
                ServiceApprovalState::Denied => "denied",
            };
            // In `wireserve <service>` syntax, target addresses included:
            // an approver should see that a node exposes its LAN.
            let ports = s.ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ");
            let mut row = vec![clean(&s.name), clean(&s.node), state.into(), opt(s.vip4.as_deref()), ports, list(&s.groups)];
            let mut note = s.denied_reason.as_deref().map(clean).unwrap_or_default();
            // Waiting again (PLAN.md #315): what the approval was given to.
            if !s.approved_ports.is_empty() {
                let was = s.approved_ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ");
                note = format!("approved before as {was}");
            }
            if dns {
                row.push(
                    match &s.dns {
                        None => "-",
                        Some(DnsRecordState::Published) => "published",
                        Some(DnsRecordState::Pending) => "pending",
                        Some(DnsRecordState::Error(e)) => {
                            note = format!("DNS: {}", clean(e));
                            "error"
                        }
                    }
                    .into(),
                );
            }
            row.push(note);
            row
        })
        .collect();
    if rows.iter().all(|r| r.last().is_some_and(String::is_empty)) {
        for r in &mut rows {
            r.pop();
        }
    } else {
        header.push("NOTE");
    }
    table(&header, &rows)
}

/// `group list`.
#[must_use]
pub fn groups(resp: &GroupsResponse) -> String {
    let rows: Vec<Vec<String>> = resp
        .groups
        .iter()
        .map(|g| {
            let granted: Vec<String> = g.granted_to.iter().map(ToString::to_string).collect();
            vec![clean(&g.name), list(&granted), list(&g.services)]
        })
        .collect();
    table(&["GROUP", "GRANTED TO", "SERVICES"], &rows)
}

/// `grant list`.
#[must_use]
pub fn grants(resp: &GrantsResponse) -> String {
    let rows: Vec<Vec<String>> =
        resp.grants.iter().map(|g| vec![clean(&g.source.to_string()), clean(&g.group)]).collect();
    table(&["SOURCE", "GROUP"], &rows)
}

/// `tag list`.
#[must_use]
pub fn tags(by_tag: &std::collections::BTreeMap<String, Vec<String>>) -> String {
    let rows: Vec<Vec<String>> = by_tag.iter().map(|(tag, nodes)| vec![clean(tag), list(nodes)]).collect();
    table(&["TAG", "NODES"], &rows)
}

/// `transit ports`.
#[must_use]
pub fn relay_ports(resp: &RelayPortsResponse) -> String {
    let rows: Vec<Vec<String>> = resp
        .ports
        .iter()
        .map(|p| {
            let state = match p.open {
                Some(true) => "open",
                Some(false) => "CLOSED",
                None => "unchecked",
            };
            let devices = if p.devices.is_empty() {
                "none, safe to close".to_string()
            } else {
                p.devices.iter().map(|d| clean(d)).collect::<Vec<_>>().join(", ")
            };
            vec![
                clean(&p.carrier),
                format!("udp/{}", p.port),
                opt(p.address.as_deref()),
                opt(p.node.as_deref()),
                state.into(),
                p.checked_at.map_or_else(|| "never".to_string(), |t| t.format("%Y-%m-%d").to_string()),
                devices,
            ]
        })
        .collect();
    table(&["CARRIER", "PORT", "ADDRESS", "NODE", "STATE", "CHECKED", "USED BY"], &rows)
}

/// Its relaying (PLAN.md M23): `on` when approved and switched on by the
/// node itself, `approved` when only the first, `unapproved` when only
/// the second.
fn transit(resp: &AdminPeersResponse, name: &str) -> &'static str {
    let approved = resp.transit_approved.iter().any(|n| n == name);
    let offering = resp.transit_offering.iter().any(|n| n == name);
    match (approved, offering) {
        (true, true) => "on",
        (true, false) => "approved",
        (false, true) => "unapproved",
        (false, false) => "-",
    }
}

/// `offering` for a node that runs `exit on`, `yes` for a device whose
/// last export has the full-tunnel profile (PLAN.md M27).
fn exit(resp: &AdminPeersResponse, name: &str) -> &'static str {
    if resp.exit_devices.iter().any(|n| n == name) {
        "yes"
    } else if resp.exit_offering.iter().any(|n| n == name) {
        "offering"
    } else {
        "-"
    }
}

fn stale(resp: &AdminPeersResponse, name: &str) -> bool {
    resp.stale_devices.iter().any(|n| n == name)
}

fn node_tags(resp: &AdminPeersResponse, name: &str) -> String {
    resp.tags.get(name).map_or_else(|| "-".to_string(), |t| list(t))
}

/// The address peers dial first: an operator's explicit one, else the one
/// found over IPv4, else over IPv6.
fn endpoint(p: &PeerInfo) -> String {
    opt(p.endpoint_addr.as_deref().or(p.endpoint_addr_v4.as_deref()).or(p.endpoint_addr_v6.as_deref()))
}

fn seen(p: &PeerInfo, now: DateTime<Utc>) -> String {
    p.last_handshake.map_or_else(|| "never".to_string(), |t| ago(t, now))
}

/// `node list`: what an admin looks for at a glance. `node show` has every
/// field.
#[must_use]
pub fn nodes(resp: &AdminPeersResponse, now: DateTime<Utc>) -> String {
    let rows: Vec<Vec<String>> = resp
        .peers
        .iter()
        .map(|p| {
            vec![
                clean(&p.name),
                clean(&p.ip4),
                endpoint(p),
                seen(p, now),
                transit(resp, &p.name).into(),
                exit(resp, &p.name).into(),
                node_tags(resp, &p.name),
                if stale(resp, &p.name) { "stale, run `device refresh`".into() } else { String::new() },
            ]
        })
        .collect();
    let mut header = vec!["NODE", "ADDRESS", "ENDPOINT", "SEEN", "TRANSIT", "EXIT", "TAGS"];
    let mut rows = rows;
    if rows.iter().all(|r| r.last().is_some_and(String::is_empty)) {
        for r in &mut rows {
            r.pop();
        }
    } else {
        header.push("NOTE");
    }
    table(&header, &rows)
}

/// `owner status` (PLAN.md M47, M48): the login server, the grants that
/// use people's groups, the owners and who is signed in, each with what to
/// do when it's missing.
#[must_use]
pub fn owners(status: &OwnersStatus, now: DateTime<Utc>) -> String {
    let Some(p) = &status.provider else {
        return "There is no login server: devices don't belong to anyone, nobody signs in, and access\n\
                goes by the device. To let access follow people, on the coordinator's machine run:\n\
                \x20 sudo wireserve-coordinator setup login\n"
            .to_string();
    };
    let mut out = String::new();
    let server = match &p.problem {
        None => format!("{}  (answering)", clean(&p.issuer)),
        Some(why) => format!("{}  NOT ANSWERING: {}", clean(&p.issuer), clean(why)),
    };
    let granted = if status.granted_groups.is_empty() {
        "none yet; owners' groups count only through one, e.g. `wireserve-admin grant add oidc:family media`".to_string()
    } else {
        status.granted_groups.iter().map(|g| format!("oidc:{}", clean(g))).collect::<Vec<_>>().join(", ")
    };
    out.push_str(&fields(&[
        ("login server", server),
        ("redirect URL", format!("{}  (registered there)", clean(&p.redirect_url))),
        ("groups", format!("from the `{}` claim, refreshed every {}", clean(&p.groups_claim), every(p.refresh_secs))),
        ("grants", granted),
        (
            "sign-in",
            if status.sign_in {
                format!("on: web services ask whoever their grants don't let in ({} signed in)", status.sessions.len())
            } else {
                "off until the coordinator publishes DNS records (`setup domain`)".to_string()
            },
        ),
    ]));
    out.push('\n');
    if status.owners.is_empty() {
        out.push_str("No device belongs to anyone yet. Hand one to its person with:\n");
        out.push_str("  wireserve-admin owner link <device> --qr\n");
    } else {
        out.push_str(&owner_table(status, now));
    }
    if !status.sessions.is_empty() {
        out.push('\n');
        out.push_str(&session_table(status, now));
    }
    out
}

fn note(stale: bool, failing_since: Option<DateTime<Utc>>, now: DateTime<Utc>) -> String {
    match (stale, failing_since) {
        (true, _) => "refresh failing for over an hour; its groups count for nothing".to_string(),
        (false, Some(since)) => format!("refresh failing since {}; groups count for an hour", ago(since, now)),
        (false, None) => String::new(),
    }
}

/// Drops the last column when no row has anything in it.
fn table_with_note(mut header: Vec<&str>, mut rows: Vec<Vec<String>>) -> String {
    if rows.iter().all(|r| r.last().is_some_and(String::is_empty)) {
        for r in &mut rows {
            r.pop();
        }
        header.pop();
    }
    table(&header, &rows)
}

fn session_table(status: &OwnersStatus, now: DateTime<Utc>) -> String {
    let rows: Vec<Vec<String>> = status
        .sessions
        .iter()
        .map(|s| {
            let who = s.person.email.as_deref().or(s.person.name.as_deref()).unwrap_or(&s.person.sub);
            vec![
                clean(who),
                list(&s.person.groups),
                ago(s.signed_in_at, now),
                ago(s.last_used_at, now),
                note(s.person.stale, s.failing_since, now),
            ]
        })
        .collect();
    table_with_note(vec!["SIGNED IN", "GROUPS", "SINCE", "USED", "NOTE"], rows)
}

fn owner_table(status: &OwnersStatus, now: DateTime<Utc>) -> String {
    let rows: Vec<Vec<String>> = status
        .owners
        .iter()
        .map(|o| {
            let who = o.owner.email.as_deref().or(o.owner.name.as_deref()).unwrap_or(&o.owner.sub);
            vec![clean(&o.node), clean(who), list(&o.owner.groups), ago(o.refreshed_at, now), note(o.owner.stale, o.failing_since, now)]
        })
        .collect();
    table_with_note(vec!["DEVICE", "OWNER", "GROUPS", "REFRESHED", "NOTE"], rows)
}

/// `15 min`, `1 h`, `90 s`.
fn every(secs: u64) -> String {
    match secs {
        s if s % 3600 == 0 => format!("{} h", s / 3600),
        s if s % 60 == 0 => format!("{} min", s / 60),
        s => format!("{s} s"),
    }
}

/// `node show`: one node, every field.
#[must_use]
pub fn node(resp: &AdminPeersResponse, p: &PeerInfo, now: DateTime<Utc>) -> String {
    let dialable = match resp.dialable.get(&p.name) {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    };
    let holds = resp.held_addresses.get(&p.name).map_or_else(|| "-".to_string(), |a| list(a));
    fields(&[
        ("node", clean(&p.name)),
        ("public key", clean(&p.pubkey)),
        ("address", clean(&p.ip4)),
        ("IPv6 address", clean(&p.ip6)),
        ("seen", seen(p, now)),
        ("endpoint", opt(p.endpoint_addr.as_deref())),
        ("found over IPv4", opt(p.endpoint_addr_v4.as_deref())),
        ("found over IPv6", opt(p.endpoint_addr_v6.as_deref())),
        ("LAN address", opt(p.lan_addr.as_deref())),
        ("reflexive", opt(p.reflexive_addr.as_deref())),
        ("dialable", dialable.into()),
        ("transit", transit(resp, &p.name).into()),
        ("exit", exit(resp, &p.name).into()),
        ("tags", node_tags(resp, &p.name)),
        ("config", if stale(resp, &p.name) { "stale, run `device refresh`".into() } else { "-".into() }),
        ("holds", holds),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{GrantInfo, GrantSource, GroupInfo, RelayPortStatus};

    fn now() -> DateTime<Utc> {
        "2026-10-03T12:00:00Z".parse().unwrap()
    }

    fn svc(name: &str, node: &str, state: ServiceApprovalState, ports: &[&str]) -> AdminServiceInfo {
        AdminServiceInfo {
            name: name.into(),
            node: node.into(),
            ip4: "10.1.0.2".into(),
            vip4: Some("10.1.0.9".into()),
            ports: ports.iter().map(|p| p.parse().unwrap()).collect(),
            state,
            declared_at: None,
            approved_at: None,
            denied_at: None,
            denied_reason: None,
            approved_ports: vec![],
            groups: vec!["default".into()],
            dns: None,
        }
    }

    fn peer(name: &str, ip4: &str) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: format!("pk-{name}"),
            ip4: ip4.into(),
            ip6: "fd00::1".into(),
            endpoint_addr: None,
            endpoint_addr_v4: None,
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: None,
            relay: Default::default(),
        }
    }

    #[test]
    fn services_line_up_and_leave_out_the_columns_nobody_uses() {
        let mut long = svc("a-long-service-name", "strato", ServiceApprovalState::Approved, &["80:3000"]);
        long.groups = vec!["infra".into(), "media".into()];
        let out = services(&[long, svc("dns", "lego2", ServiceApprovalState::Pending, &["53/udp", "53/tcp", "8080:8000"])]);
        assert_eq!(
            out,
            "\
SERVICE              NODE    STATE     ADDRESS   PORTS                        GROUPS
a-long-service-name  strato  approved  10.1.0.9  80:3000/tcp                  infra,media
dns                  lego2   pending   10.1.0.9  53/udp 53/tcp 8080:8000/tcp  default
"
        );
    }

    #[test]
    fn a_service_waiting_again_shows_what_was_approved() {
        let mut again = svc("router", "lego2", ServiceApprovalState::Pending, &["443:192.168.178.1:80"]);
        again.approved_ports = vec!["80:8080".parse().unwrap()];
        let out = services(&[again]);
        assert_eq!(
            out,
            "\
SERVICE  NODE   STATE    ADDRESS   PORTS                     GROUPS   NOTE
router   lego2  pending  10.1.0.9  443:192.168.178.1:80/tcp  default  approved before as 80:8080/tcp
"
        );
    }

    #[test]
    fn a_denial_and_a_dns_error_go_last_as_a_note() {
        let mut denied = svc("git", "lego2", ServiceApprovalState::Denied, &["22"]);
        denied.denied_reason = Some("not on\nthis node".into());
        denied.dns = Some(DnsRecordState::Pending);
        let mut broken = svc("web", "strato", ServiceApprovalState::Approved, &["443"]);
        broken.dns = Some(DnsRecordState::Error("record exists, not overwriting".into()));
        let mut plain = svc("x", "strato", ServiceApprovalState::Approved, &["80"]);
        plain.vip4 = None;
        let out = services(&[denied, broken, plain]);
        assert_eq!(
            out,
            "\
SERVICE  NODE    STATE     ADDRESS   PORTS    GROUPS   DNS      NOTE
git      lego2   denied    10.1.0.9  22/tcp   default  pending  not on\\nthis node
web      strato  approved  10.1.0.9  443/tcp  default  error    DNS: record exists, not overwriting
x        strato  approved  -         80/tcp   default  -
"
        );
    }

    #[test]
    fn nodes_show_the_glance_and_show_has_the_rest() {
        let mut lego2 = peer("lego2", "10.1.0.1");
        lego2.last_handshake = Some(now() - chrono::Duration::seconds(130));
        let mut strato = peer("strato", "10.1.0.2");
        strato.endpoint_addr_v4 = Some("85.215.231.166:51820".into());
        strato.endpoint_addr_v6 = Some("[2a01:4f8::2]:51820".into());
        let phone = peer("phone", "10.1.0.3");
        let resp = AdminPeersResponse {
            peers: vec![lego2, strato.clone(), phone],
            transit_approved: vec!["strato".into(), "lego2".into()],
            transit_offering: vec!["strato".into()],
            exit_offering: vec!["strato".into()],
            exit_devices: vec!["phone".into()],
            stale_devices: vec!["phone".into()],
            tags: [("strato".to_string(), vec!["ops".to_string(), "servers".to_string()])].into(),
            dialable: [("strato".to_string(), true)].into(),
            ..Default::default()
        };
        assert_eq!(
            nodes(&resp, now()),
            "\
NODE    ADDRESS   ENDPOINT              SEEN    TRANSIT   EXIT      TAGS         NOTE
lego2   10.1.0.1  -                     2m ago  approved  -         -
strato  10.1.0.2  85.215.231.166:51820  never   on        offering  ops,servers
phone   10.1.0.3  -                     never   -         yes       -            stale, run `device refresh`
"
        );
        let shown = node(&resp, &strato, now());
        assert!(shown.starts_with("node:             strato\n"), "{shown}");
        assert!(shown.contains("found over IPv6:  [2a01:4f8::2]:51820\n"), "{shown}");
        assert!(shown.contains("dialable:         yes\n"), "{shown}");
        assert!(shown.contains("tags:             ops,servers\n"), "{shown}");
    }

    #[test]
    fn groups_grants_tags_and_ports_are_tables_too() {
        let g = GroupsResponse {
            groups: vec![
                GroupInfo { name: "default".into(), services: vec!["web".into()], granted_to: vec![GrantSource::Everyone] },
                GroupInfo { name: "infra".into(), services: vec![], granted_to: vec![] },
            ],
        };
        assert_eq!(groups(&g), "GROUP    GRANTED TO  SERVICES\ndefault  everyone    web\ninfra    -           -\n");
        let gr = GrantsResponse { grants: vec![GrantInfo { source: "tag:ops".parse().unwrap(), group: "infra".into() }] };
        assert_eq!(grants(&gr), "SOURCE   GROUP\ntag:ops  infra\n");
        let t = [("ops".to_string(), vec!["a".to_string(), "b".to_string()])].into();
        assert_eq!(tags(&t), "TAG  NODES\nops  a,b\n");
        let p = RelayPortsResponse {
            ports: vec![RelayPortStatus {
                carrier: "strato".into(),
                address: Some("85.215.231.166".into()),
                port: 51901,
                node: Some("lego2".into()),
                devices: vec![],
                checked_at: None,
                open: Some(false),
            }],
        };
        assert_eq!(
            relay_ports(&p),
            "CARRIER  PORT       ADDRESS         NODE   STATE   CHECKED  USED BY\n\
             strato   udp/51901  85.215.231.166  lego2  CLOSED  never    none, safe to close\n"
        );
    }

    #[test]
    fn owner_status_says_what_is_missing() {
        use wireserve_types::{OwnedNode, OwnerInfo, OwnersProvider};
        let now = Utc::now();
        let off = OwnersStatus { provider: None, owners: vec![], sign_in: false, sessions: vec![], granted_groups: vec![] };
        assert!(owners(&off, now).contains("sudo wireserve-coordinator setup login"));

        let provider = OwnersProvider {
            issuer: "https://id.example.com".into(),
            redirect_url: "https://mesh.example.com/oidc/callback".into(),
            groups_claim: "groups".into(),
            scopes: vec!["openid".into()],
            refresh_secs: 900,
            problem: None,
        };
        let empty = OwnersStatus { provider: Some(provider.clone()), owners: vec![], sign_in: false, sessions: vec![], granted_groups: vec![] };
        let out = owners(&empty, now);
        assert!(out.contains("(answering)") && out.contains("every 15 min"), "{out}");
        assert!(out.contains("off until the coordinator publishes DNS records"), "{out}");
        assert!(out.contains("grant add oidc:family media") && out.contains("owner link <device>"), "{out}");

        let alice = OwnedNode {
            node: "laptop".into(),
            owner: OwnerInfo { sub: "a1".into(), email: Some("alice@example.com".into()), name: None, groups: vec!["family".into()], stale: false },
            refreshed_at: now - chrono::Duration::minutes(3),
            failing_since: None,
        };
        let bob = OwnedNode {
            node: "tv".into(),
            owner: OwnerInfo { sub: "b2".into(), email: None, name: Some("Bob".into()), groups: vec![], stale: false },
            refreshed_at: now - chrono::Duration::minutes(20),
            failing_since: Some(now - chrono::Duration::minutes(5)),
        };
        let down = OwnersProvider { problem: Some("discovery: connection refused".into()), ..provider };
        let session = wireserve_types::SignInSession {
            person: OwnerInfo { sub: "c3".into(), email: Some("carl@example.com".into()), name: None, groups: vec!["family".into()], stale: false },
            signed_in_at: now - chrono::Duration::hours(2),
            refreshed_at: now - chrono::Duration::minutes(1),
            last_used_at: now - chrono::Duration::minutes(1),
            failing_since: None,
        };
        let full = OwnersStatus {
            provider: Some(down),
            owners: vec![alice.clone(), bob],
            sign_in: true,
            sessions: vec![session],
            granted_groups: vec!["family".into()],
        };
        let out = owners(&full, now);
        assert!(out.contains("NOT ANSWERING: discovery: connection refused") && out.contains("oidc:family"), "{out}");
        assert!(out.contains("laptop  alice@example.com  family  3m ago"), "{out}");
        assert!(out.contains("refresh failing since 5m ago"), "{out}");
        assert!(out.contains("on: web services ask") && out.contains("(1 signed in)"), "{out}");
        assert!(out.contains("carl@example.com  family  2h ago  1m ago"), "{out}");
        let fine = OwnersStatus { owners: vec![alice], ..full };
        assert!(!owners(&fine, now).contains("NOTE"), "no note, no column");
    }
}
