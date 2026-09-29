//! `wireserve list` for a person: the daemon's cached view as
//! aligned tables. `list --json` prints the view itself, for scripts.
//!
//! Nearly every string here came from the coordinator, which renders it
//! into the operator's terminal; like `wireserve-admin`'s listings, every
//! control character is escaped rather than printed, so no field can move
//! the cursor, recolour the screen or forge a line of output.

use chrono::{DateTime, Utc};
use wireserve_types::{ErrorBody, PeerInfo, PortMap};

use crate::ipc::protocol::{ListView, LocalServiceView};

/// Escapes every control character (`\n`, `\r`, ESC, …) in `s`.
fn clean(s: &str) -> String {
    s.chars()
        .flat_map(|c| -> Box<dyn Iterator<Item = char>> {
            if c.is_control() {
                Box::new(c.escape_default())
            } else {
                Box::new(std::iter::once(c))
            }
        })
        .collect()
}

/// Left-aligned columns two spaces apart, sized to their widest cell; the
/// last column is not padded.
fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let width = |i: usize| {
        rows.iter()
            .map(|r| r[i].chars().count())
            .chain([header[i].len()])
            .max()
            .unwrap_or(0)
    };
    let widths: Vec<usize> = (0..header.len()).map(width).collect();
    let line = |cells: Vec<&str>| {
        let mut out = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                out.push_str(cell);
            } else {
                out.push_str(cell);
                out.push_str(&" ".repeat(widths[i] - cell.chars().count() + 2));
            }
        }
        out.trim_end().to_string() + "\n"
    };
    let mut out = line(header.to_vec());
    for r in rows {
        out.push_str(&line(r.iter().map(String::as_str).collect()));
    }
    out
}

fn ports(maps: &[PortMap]) -> String {
    maps.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ")
}

fn service_state(s: &LocalServiceView) -> &'static str {
    match (s.pending, s.online) {
        (true, _) => "pending approval",
        (false, true) => "online",
        (false, false) => "offline",
    }
}

fn service_row(s: &LocalServiceView, domain: Option<&str>) -> Vec<String> {
    let node = if s.local { format!("{} (this node)", clean(&s.node)) } else { clean(&s.node) };
    // A service the coordinator had no address left for is reachable
    // nowhere; say so rather than show its node's.
    let address = match &s.vip4 {
        Some(vip) => clean(vip),
        None => "(no address)".to_string(),
    };
    let maps = s.ports.clone();
    let host = match domain {
        Some(d) => format!("{}.{}", clean(&s.name), clean(d)),
        None => format!("{}.wg", clean(&s.name)),
    };
    vec![host, address, ports(&maps), node, service_state(s).into()]
}

/// `4s ago`, `3m ago`, `5h ago`, `2d ago`.
fn ago(then: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = (now - then).num_seconds().max(0);
    match secs {
        0..=59 => format!("{secs}s ago"),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86_399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

/// This node's own name for whichever peer `view.peers` lists under
/// `pubkey`, or the pubkey itself (truncated) if no such peer is known —
/// a dangling `transit_via`/`TransitPair` entry (a stale/inconsistent
/// directory) should never crash rendering, only degrade to something
/// still readable.
fn peer_name(view: &ListView, pubkey: &str) -> String {
    view.peers
        .iter()
        .find(|p| p.pubkey == pubkey)
        .map_or_else(|| format!("{}…", &pubkey[..pubkey.len().min(8)]), |p| clean(&p.name))
}

/// "direct" or "via <name>" (PLAN.md M23) — this node's own routing
/// decision for `p`, from the coordinator's `transit_via` hint on its
/// most recent poll response. Never reflects the kernel's actual live
/// `AllowedIPs` state (`list` reads `tunnel` for endpoint/handshake, but
/// `wg show allowed-ips` isn't parsed here) — the coordinator's hint and
/// what `wg::desired_peers` actually configured agree by construction
/// once a poll cycle has completed, so this is accurate as of the same
/// "last poll" staleness every other cached field in this view already
/// has.
fn route(p: &PeerInfo, view: &ListView) -> String {
    match p.transit_via.as_deref() {
        Some(via) => format!("via {}", peer_name(view, via)),
        None => "direct".to_string(),
    }
}

/// A peer's endpoint and last handshake, from the kernel when the daemon
/// could read it — the endpoint WireGuard really uses can differ from the
/// coordinator's record (a candidate of the other address family, say,
/// or the peer roamed) — and the coordinator's record otherwise.
fn peer_row(p: &PeerInfo, view: &ListView, is_self: bool, now: DateTime<Utc>) -> Vec<String> {
    let recorded = || {
        p.endpoint_addr
            .as_deref()
            .or(p.endpoint_addr_v4.as_deref())
            .or(p.endpoint_addr_v6.as_deref())
            .map_or_else(|| "-".to_string(), clean)
    };
    let (endpoint, handshake) = if is_self {
        (recorded(), "this node".to_string())
    } else if view.tunnel.is_empty() {
        (recorded(), "unknown".to_string())
    } else {
        match view.tunnel.iter().find(|t| t.pubkey == p.pubkey) {
            Some(t) => (
                t.endpoint.as_deref().map_or_else(|| "-".to_string(), clean),
                t.last_handshake.map_or_else(|| "never".to_string(), |at| ago(at, now)),
            ),
            None => (recorded(), "not configured".to_string()),
        }
    };
    let route = if is_self { "-".to_string() } else { route(p, view) };
    vec![clean(&p.name), clean(&p.ip4), endpoint, handshake, route]
}

/// A rejection's reason is either an admin's text or a coordinator error
/// body; show the message, not the JSON around it.
fn reason(raw: &str) -> String {
    let text = serde_json::from_str::<ErrorBody>(raw).map_or_else(|_| raw.to_string(), |b| b.error);
    clean(&text)
}

#[must_use]
pub fn render(view: &ListView, now: DateTime<Utc>) -> String {
    let mut out = String::new();
    let this = view.node.as_deref().map(clean);
    out.push_str(&format!(
        "{}{} on {}\n",
        this.as_deref().map(|n| format!("{n}, ")).unwrap_or_default(),
        if view.instance.is_empty() { "instance default".to_string() } else { format!("instance {}", clean(&view.instance)) },
        if view.ifname.is_empty() { "?".to_string() } else { clean(&view.ifname) },
    ));

    out.push('\n');
    if view.services.is_empty() {
        out.push_str("No services yet. Publish one with `wireserve serve <name> <port>`.\n");
    } else {
        let mut services: Vec<&LocalServiceView> = view.services.iter().collect();
        services.sort_by(|a, b| a.name.cmp(&b.name));
        let domain = view.service_domain.as_deref();
        let rows: Vec<Vec<String>> =
            services.into_iter().map(|s| service_row(s, domain)).collect();
        out.push_str(&table(&["SERVICE", "ADDRESS", "PORTS", "NODE", "STATE"], &rows));
    }

    out.push('\n');
    let mut peers: Vec<_> = view.peers.iter().collect();
    peers.sort_by(|a, b| a.name.cmp(&b.name));
    if peers.is_empty() {
        out.push_str("No peers yet — has this node completed a poll?\n");
    } else {
        let rows: Vec<Vec<String>> = peers
            .into_iter()
            .map(|p| peer_row(p, view, this.as_deref() == Some(clean(&p.name).as_str()), now))
            .collect();
        out.push_str(&table(&["PEER", "ADDRESS", "ENDPOINT", "HANDSHAKE", "ROUTE"], &rows));
    }

    if !view.rejected_services.is_empty() {
        out.push_str("\nNot published:\n");
        for r in &view.rejected_services {
            out.push_str(&format!("  {}: {}\n", clean(&r.name), reason(&r.reason)));
        }
    }

    if !view.service_notices.is_empty() {
        out.push_str("\nFrom the coordinator:\n");
        for n in &view.service_notices {
            out.push_str(&format!("  {}: {}\n", clean(&n.name), reason(&n.reason)));
        }
    }

    // Transit (PLAN.md M23): silent in the common case (opted out, not
    // carrying anything) so this stays out of the way for every node that
    // never touches the feature.
    if view.transit_capable || !view.transit_carrying.is_empty() {
        out.push('\n');
        out.push_str(&format!("Transit: {}", if view.transit_capable { "on" } else { "off" }));
        if view.transit_awaiting_approval {
            out.push_str(", waiting for an admin to approve this node as a carrier\n");
        } else if view.transit_carrying.is_empty() {
            out.push_str(", carrying nothing right now\n");
        } else {
            let pairs: Vec<String> = view
                .transit_carrying
                .iter()
                .map(|pair| format!("{} <-> {}", peer_name(view, &pair.a), peer_name(view, &pair.c)))
                .collect();
            out.push_str(&format!(", carrying: {}\n", pairs.join(", ")));
        }
    }

    // Exit (PLAN.md M27): silent unless opted in, like transit above.
    if view.exit_capable {
        out.push_str("Exit: on");
        if !view.transit_capable {
            out.push_str(", but an exit is a gateway first — also run `wireserve transit on`\n");
        } else if view.exit_clients.is_empty() {
            out.push_str(", no device uses this node as its exit yet\n");
        } else {
            let names: Vec<String> = view.exit_clients.iter().map(|pk| peer_name(view, pk)).collect();
            out.push_str(&format!(", for: {}\n", names.join(", ")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::protocol::TunnelPeer;
    use crate::state::RejectedService;

    fn now() -> DateTime<Utc> {
        "2026-09-21T12:00:00Z".parse().unwrap()
    }

    fn svc(name: &str, node: &str, vip4: Option<&str>, ports: &[&str]) -> LocalServiceView {
        LocalServiceView {
            name: name.into(),
            node: node.into(),
            ip4: "10.1.0.2".into(),
            vip4: vip4.map(Into::into),
            ports: ports.iter().map(|p| p.parse().unwrap()).collect(),
            online: true,
            local: false,
            pending: false,
        }
    }

    fn peer(name: &str, ip4: &str, endpoint: Option<&str>, online: bool) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            pubkey: format!("pk-{name}"),
            ip4: ip4.into(),
            ip6: String::new(),
            endpoint_addr: None,
            endpoint_addr_v4: endpoint.map(Into::into),
            endpoint_addr_v6: None,
            lan_addr: None,
            reflexive_addr: None,
            last_handshake: online.then(chrono::Utc::now),
            transit_via: None,
        }
    }

    #[test]
    fn renders_services_peers_and_rejections_as_tables() {
        let mut mine = svc("mydns", "lego2", Some("10.1.0.4"), &["53/udp", "53/tcp", "8080:8000"]);
        mine.local = true;
        mine.pending = true;
        let mut unaddressed = svc("plex", "strato", None, &["32400"]);
        unaddressed.online = false;
        let view = ListView {
            instance: "default".into(),
            ifname: "wireserve0".into(),
            node: Some("lego2".into()),
            service_domain: None,
            transit_capable: false,
            transit_carrying: vec![],
            transit_awaiting_approval: false,
            exit_capable: false,
            exit_clients: vec![],
            // The coordinator recorded strato's IPv6 candidate; WireGuard
            // is really talking to its IPv4 one.
            peers: vec![
                peer("strato", "10.1.0.2", Some("[2a01:4f8::2]:51820"), true),
                peer("lego2", "10.1.0.1", None, true),
                peer("newbie", "10.1.0.5", Some("198.51.100.7:51820"), false),
            ],
            tunnel: vec![
                TunnelPeer {
                    pubkey: "pk-strato".into(),
                    endpoint: Some("85.215.231.166:51820".into()),
                    last_handshake: Some(now() - chrono::Duration::seconds(74)),
                },
                TunnelPeer { pubkey: "pk-newbie".into(), endpoint: Some("198.51.100.7:51820".into()), last_handshake: None },
            ],
            services: vec![svc("openobserve", "strato", Some("10.1.0.3"), &["80:5080"]), mine, unaddressed],
            rejected_services: vec![RejectedService {
                name: "git".into(),
                reason: r#"{"error":"service name 'git' is already declared by another node","conflicting_service":"git"}"#.into(),
            }],
            service_notices: vec![],
        };
        assert_eq!(
            render(&view, now()),
            "\
lego2, instance default on wireserve0

SERVICE         ADDRESS       PORTS                        NODE               STATE
mydns.wg        10.1.0.4      53/udp 53/tcp 8080:8000/tcp  lego2 (this node)  pending approval
openobserve.wg  10.1.0.3      80:5080/tcp                  strato             online
plex.wg         (no address)  32400/tcp                    strato             offline

PEER    ADDRESS   ENDPOINT              HANDSHAKE  ROUTE
lego2   10.1.0.1  -                     this node  -
newbie  10.1.0.5  198.51.100.7:51820    never      direct
strato  10.1.0.2  85.215.231.166:51820  1m ago     direct

Not published:
  git: service name 'git' is already declared by another node
"
        );
    }

    #[test]
    fn without_the_kernels_view_it_falls_back_to_the_coordinators_record() {
        let view = ListView {
            peers: vec![peer("strato", "10.1.0.2", Some("[2a01:4f8::2]:51820"), true)],
            ..Default::default()
        };
        let out = render(&view, now());
        assert!(out.contains("strato  10.1.0.2  [2a01:4f8::2]:51820  unknown"), "{out}");
    }

    #[test]
    fn a_peer_routed_via_transit_shows_the_via_peers_name_not_its_pubkey() {
        let mut c = peer("c", "10.1.0.3", None, true);
        c.transit_via = Some("pk-b".into());
        let view = ListView {
            peers: vec![peer("b", "10.1.0.2", None, true), c],
            ..Default::default()
        };
        let out = render(&view, now());
        assert!(out.contains("via b"), "{out}");
        assert!(!out.contains("pk-b"), "{out}");
    }

    #[test]
    fn a_dangling_transit_via_naming_an_unknown_peer_degrades_to_a_truncated_pubkey_not_a_panic() {
        let mut c = peer("c", "10.1.0.3", None, true);
        c.transit_via = Some("pk-does-not-exist".into());
        let view = ListView { peers: vec![c], ..Default::default() };
        let out = render(&view, now());
        assert!(out.contains("via pk-does-…"), "{out}");
    }

    #[test]
    fn transit_status_is_silent_when_off_and_carrying_nothing() {
        let out = render(&ListView::default(), now());
        assert!(!out.contains("Transit:"), "{out}");
    }

    #[test]
    fn transit_on_but_idle_says_so() {
        let view = ListView { transit_capable: true, ..Default::default() };
        let out = render(&view, now());
        assert!(out.contains("Transit: on, carrying nothing right now"), "{out}");
    }

    #[test]
    fn transit_on_but_unapproved_says_what_it_is_waiting_for() {
        let view = ListView { transit_capable: true, transit_awaiting_approval: true, ..Default::default() };
        let out = render(&view, now());
        assert!(out.contains("Transit: on, waiting for an admin to approve this node as a carrier"), "{out}");
    }

    #[test]
    fn exit_status_is_silent_when_off() {
        let out = render(&ListView { transit_capable: true, ..Default::default() }, now());
        assert!(!out.contains("Exit:"), "{out}");
    }

    #[test]
    fn exit_on_without_transit_says_what_is_missing() {
        let out = render(&ListView { exit_capable: true, ..Default::default() }, now());
        assert!(out.contains("Exit: on, but an exit is a gateway first"), "{out}");
    }

    #[test]
    fn exit_clients_are_shown_by_name() {
        let view = ListView {
            transit_capable: true,
            exit_capable: true,
            exit_clients: vec!["pk-a".into()],
            peers: vec![peer("a", "10.1.0.1", None, true)],
            ..Default::default()
        };
        let out = render(&view, now());
        assert!(out.contains("Exit: on, for: a"), "{out}");
        let idle = render(&ListView { transit_capable: true, exit_capable: true, ..Default::default() }, now());
        let notice = wireserve_types::ServiceNotice { name: "vault".into(), reason: "there is no group infra\x1b[2J".into() };
        let out = render(&ListView { service_notices: vec![notice], ..Default::default() }, now());
        assert!(out.contains("vault: there is no group infra") && !out.contains('\x1b'), "{out}");
        assert!(idle.contains("Exit: on, no device uses this node as its exit yet"), "{idle}");
    }

    #[test]
    fn a_carried_pair_is_shown_by_name() {
        let view = ListView {
            transit_capable: true,
            transit_carrying: vec![wireserve_types::TransitPair { a: "pk-a".into(), c: "pk-c".into() }],
            peers: vec![peer("a", "10.1.0.1", None, true), peer("c", "10.1.0.3", None, true)],
            ..Default::default()
        };
        let out = render(&view, now());
        assert!(out.contains("Transit: on, carrying: a <-> c"), "{out}");
    }

    #[test]
    fn handshake_ages_read_naturally() {
        let at = |secs| ago(now() - chrono::Duration::seconds(secs), now());
        assert_eq!([at(0), at(59), at(60), at(3599), at(3600), at(86_400 * 3)], ["0s ago", "59s ago", "1m ago", "59m ago", "1h ago", "3d ago"]);
    }

    #[test]
    fn an_empty_view_says_what_to_do() {
        let out = render(&ListView::default(), now());
        assert!(out.contains("No services yet"), "{out}");
        assert!(out.contains("No peers yet"), "{out}");
    }

    #[test]
    fn control_characters_from_the_coordinator_are_escaped() {
        let mut s = svc("web", "evil\n\u{1b}[2Jnode", Some("10.1.0.3"), &["80"]);
        s.name = "web\r".into();
        let view = ListView {
            services: vec![s],
            peers: vec![peer("p\u{1b}]0;x\u{7}", "10.1.0.2", Some("1.2.3.4:5\nFAKE LINE"), false)],
            rejected_services: vec![RejectedService { name: "x".into(), reason: "a\nb".into() }],
            ..Default::default()
        };
        let out = render(&view, now());
        assert!(!out.contains('\u{1b}') && !out.contains('\r') && !out.contains('\u{7}'), "{out:?}");
        assert!(!out.contains("\nFAKE LINE") && !out.contains("\nb"), "{out:?}");
        assert!(out.contains(r"evil\n\u{1b}[2Jnode"), "{out}");
    }
}
