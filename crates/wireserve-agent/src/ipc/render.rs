//! `wireserve status` for a person: the daemon's cached view as
//! aligned tables. `status --json` prints the view itself, for scripts.
//! `wireserve <service>` shows one service's part of the same view.
//!
//! Nearly every string here came from the coordinator; `term::clean`
//! escapes every control character in it, as `wireserve-admin` does.

use chrono::{DateTime, Utc};
use wireserve_types::term::{ago, clean, table};
use wireserve_types::{ErrorBody, PeerInfo, PortMap, Reach};

use crate::ipc::protocol::{ListView, LocalServiceView};

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

/// `-` when the coordinator did not say, as one older than M45 does not.
fn service_access(s: &LocalServiceView) -> &'static str {
    match s.reach {
        Some(Reach::Allowed) => "yes",
        Some(Reach::SignIn) => "sign-in",
        Some(Reach::Denied) => "no",
        None => "-",
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
    vec![host, address, ports(&maps), node, service_state(s).into(), service_access(s).into()]
}

/// This node's own name for whichever peer `view.peers` lists under
/// `pubkey`, or the pubkey itself (truncated) if no such peer is known —
/// a dangling `relay.via`/`TransitPair` entry (a stale/inconsistent
/// directory) should never crash rendering, only degrade to something
/// still readable.
fn peer_name(view: &ListView, pubkey: &str) -> String {
    view.peers
        .iter()
        .find(|p| p.pubkey == pubkey)
        .map_or_else(|| format!("{}…", &pubkey[..pubkey.len().min(8)]), |p| clean(&p.name))
}

/// "direct" or "relayed by <name>" (PLAN.md M39) — this node's own routing
/// decision for `p`, from the coordinator's `relay.via` hint on its
/// most recent poll response. Never reflects the kernel's actual live
/// `AllowedIPs` state (`status` reads `tunnel` for endpoint/handshake, but
/// `wg show allowed-ips` isn't parsed here) — the coordinator's hint and
/// what `wg::desired_peers` actually configured agree by construction
/// once a poll cycle has completed, so this is accurate as of the same
/// "last poll" staleness every other cached field in this view already
/// has.
fn route(p: &PeerInfo, view: &ListView) -> String {
    match p.relay.via.as_deref() {
        Some(via) => format!("relayed by {}", peer_name(view, via)),
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

/// `wireserve <name>`: the service's row, and anything the coordinator
/// said about it. `None` when the view knows no service, rejection or
/// notice by that name.
#[must_use]
pub fn render_service(view: &ListView, name: &str) -> Option<String> {
    let service = view.services.iter().find(|s| s.name == name);
    let rejected: Vec<_> = view.rejected_services.iter().filter(|r| r.name == name).collect();
    let notices: Vec<_> = view.service_notices.iter().filter(|n| n.name == name).collect();
    if service.is_none() && rejected.is_empty() && notices.is_empty() {
        return None;
    }
    let mut out = String::new();
    if let Some(s) = service {
        out.push_str(&table(
            &["SERVICE", "ADDRESS", "PORTS", "NODE", "STATE", "ACCESS"],
            &[service_row(s, view.service_domain.as_deref())],
        ));
    }
    for r in rejected {
        out.push_str(&format!("Not published: {}\n", reason(&r.reason)));
    }
    for n in notices {
        out.push_str(&format!("From the coordinator: {}\n", reason(&n.reason)));
    }
    Some(out)
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
        out.push_str("No services yet. Publish one with `wireserve <name> <port>`.\n");
    } else {
        let mut services: Vec<&LocalServiceView> = view.services.iter().collect();
        services.sort_by(|a, b| a.name.cmp(&b.name));
        let domain = view.service_domain.as_deref();
        let rows: Vec<Vec<String>> =
            services.into_iter().map(|s| service_row(s, domain)).collect();
        out.push_str(&table(&["SERVICE", "ADDRESS", "PORTS", "NODE", "STATE", "ACCESS"], &rows));
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

    if view.reach_unavailable {
        out.push_str("\nACCESS is not known: the coordinator did not answer when asked.\n");
    }

    if view.reflexive_unknown {
        out.push_str(
            "\nThis node's NAT-mapped IPv4 port is unknown: its startup check couldn't reach the \
             coordinator's UDP responder. Peers behind a NAT can't reach it until it reaches them, \
             and may be relayed. Restart the agent once the coordinator answers.\n",
        );
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
    if view.transit_capable || !view.relay_carrying.is_empty() || !view.relay_public.is_empty() {
        out.push('\n');
        out.push_str(&format!("Transit: {}", if view.transit_capable { "on" } else { "off" }));
        if view.transit_awaiting_approval {
            out.push_str(", waiting for an admin to approve this node as a carrier\n");
        } else if view.relay_carrying.is_empty() && view.relay_public.is_empty() {
            out.push_str(", carrying nothing right now\n");
        } else {
            out.push('\n');
            if !view.relay_carrying.is_empty() {
                let pairs: Vec<String> = view
                    .relay_carrying
                    .iter()
                    .map(|pair| format!("{} <-> {}", peer_name(view, &pair.a), peer_name(view, &pair.c)))
                    .collect();
                out.push_str(&format!("  relaying (end to end, unreadable here): {}\n", pairs.join(", ")));
            }
            if !view.relay_public.is_empty() {
                let names: Vec<String> = view.relay_public.iter().map(|n| clean(n)).collect();
                out.push_str(&format!(
                    "  relaying devices to (end to end, on public ports — see `wireserve-admin transit ports`): {}\n",
                    names.join(", ")
                ));
            }
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
            terminated: false,
            reach: Some(Reach::Allowed),
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
            relay: Default::default(),
        }
    }

    #[test]
    fn renders_services_peers_and_rejections_as_tables() {
        let mut mine = svc("mydns", "lego2", Some("10.1.0.4"), &["53/udp", "53/tcp", "8080:8000"]);
        mine.local = true;
        mine.pending = true;
        let mut unaddressed = svc("plex", "strato", None, &["32400"]);
        unaddressed.online = false;
        unaddressed.reach = Some(Reach::Denied);
        let mut photos = svc("photos", "strato", Some("10.1.0.6"), &["443"]);
        photos.reach = Some(Reach::SignIn);
        let mut old = svc("wiki", "strato", Some("10.1.0.7"), &["80"]);
        old.reach = None;
        let view = ListView {
            instance: "default".into(),
            ifname: "wireserve0".into(),
            node: Some("lego2".into()),
            service_domain: None,
            reflexive_unknown: false,
            reach_unavailable: false,
            transit_capable: false,
            relay_carrying: vec![],
            relay_public: vec![],
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
                    rx_bytes: 0,
                },
                TunnelPeer { pubkey: "pk-newbie".into(), endpoint: Some("198.51.100.7:51820".into()), last_handshake: None, rx_bytes: 0 },
            ],
            services: vec![svc("openobserve", "strato", Some("10.1.0.3"), &["80:5080"]), mine, unaddressed, photos, old],
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

SERVICE         ADDRESS       PORTS                        NODE               STATE             ACCESS
mydns.wg        10.1.0.4      53/udp 53/tcp 8080:8000/tcp  lego2 (this node)  pending approval  yes
openobserve.wg  10.1.0.3      80:5080/tcp                  strato             online            yes
photos.wg       10.1.0.6      443/tcp                      strato             online            sign-in
plex.wg         (no address)  32400/tcp                    strato             offline           no
wiki.wg         10.1.0.7      80/tcp                       strato             online            -

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
    fn a_relayed_peer_shows_the_carriers_name_not_its_pubkey() {
        let mut c = peer("c", "10.1.0.3", None, true);
        c.relay.via = Some("pk-b".into());
        let view = ListView {
            peers: vec![peer("b", "10.1.0.2", None, true), c],
            ..Default::default()
        };
        let out = render(&view, now());
        assert!(out.contains("relayed by b"), "{out}");
        assert!(!out.contains("pk-b"), "{out}");
    }

    #[test]
    fn a_dangling_carrier_naming_an_unknown_peer_degrades_to_a_truncated_pubkey_not_a_panic() {
        let mut c = peer("c", "10.1.0.3", None, true);
        c.relay.via = Some("pk-does-not-exist".into());
        let view = ListView { peers: vec![c], ..Default::default() };
        let out = render(&view, now());
        assert!(out.contains("relayed by pk-does-…"), "{out}");
    }

    #[test]
    fn an_unknown_nat_mapped_port_is_said_only_when_the_check_failed() {
        assert!(!render(&ListView::default(), now()).contains("NAT-mapped"));
        let out = render(&ListView { reflexive_unknown: true, ..Default::default() }, now());
        assert!(out.contains("NAT-mapped IPv4 port is unknown"), "{out}");
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
    fn a_carried_pair_and_the_relayed_devices_are_shown_by_name() {
        let view = ListView {
            transit_capable: true,
            relay_carrying: vec![wireserve_types::TransitPair { a: "pk-c".into(), c: "pk-x".into() }],
            relay_public: vec!["minipc".into()],
            peers: vec![peer("c", "10.1.0.3", None, true), peer("x", "10.1.0.4", None, true)],
            ..Default::default()
        };
        let out = render(&view, now());
        assert!(out.contains("relaying (end to end, unreadable here): c <-> x"), "{out}");
        assert!(out.contains("relaying devices to (end to end, on public ports"), "{out}");
        assert!(out.contains("minipc"), "{out}");
    }

    #[test]
    fn one_service_shows_its_row_and_what_was_said_about_it() {
        let view = ListView {
            services: vec![svc("web", "lego2", Some("10.1.0.4"), &["80:5080"]), svc("db", "strato", None, &["5432"])],
            rejected_services: vec![RejectedService { name: "git".into(), reason: "taken".into() }],
            ..Default::default()
        };
        let web = render_service(&view, "web").unwrap();
        assert!(web.contains("web.wg") && web.contains("80:5080/tcp") && !web.contains("db.wg"), "{web}");
        assert_eq!(render_service(&view, "git").unwrap(), "Not published: taken\n");
        assert_eq!(render_service(&view, "nope"), None);
    }

    #[test]
    fn a_relayed_peer_says_so_and_names_its_carrier() {
        let mut c = peer("c", "10.1.0.3", None, true);
        c.relay.via = Some("pk-b".into());
        let view = ListView { peers: vec![peer("b", "10.1.0.2", None, true), c.clone()], ..Default::default() };
        assert_eq!(route(&c, &view), "relayed by b");
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

    #[test]
    fn access_that_could_not_be_asked_for_is_said_so_not_shown_as_unknown_per_service() {
        let view = ListView { reach_unavailable: true, ..Default::default() };
        assert!(render(&view, now()).contains("ACCESS is not known"));
        assert!(!render(&ListView::default(), now()).contains("ACCESS is not known"));
    }
}
