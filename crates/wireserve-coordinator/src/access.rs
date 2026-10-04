//! Who can reach what (PLAN.md M36): the one place grants become access.
//!
//! A node's principals are `everyone`, one `tag:` per tag an admin gave it,
//! and one `oidc:` per group of the person who owns it (PLAN.md M38). A
//! service's groups are its explicit ones, or `default`. A node reaches a
//! service when one of its principals is granted one of those groups.
//!
//! Everything here is pure: `/poll` and the admin's explain view feed it
//! the same rows and get the same answer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use wireserve_types::{GrantSource, Reach, ServiceAccess};

use crate::db::grants::{effective_groups, Grant};
use crate::db::nodes::NodeRow;
use crate::db::services::ServiceRow;

/// The grants and memberships in force, read once per request.
pub struct Rules {
    pub grants: Vec<Grant>,
    pub members: BTreeMap<String, BTreeSet<String>>,
    pub tags: BTreeMap<i64, BTreeSet<String>>,
    /// The identity provider's groups of each node's owner (PLAN.md M38).
    pub owner_groups: BTreeMap<i64, BTreeSet<String>>,
}

impl Rules {
    /// Every principal `node` acts as.
    #[must_use]
    pub fn principals(&self, node_id: i64) -> BTreeSet<GrantSource> {
        let mut out = BTreeSet::from([GrantSource::Everyone]);
        for tag in self.tags.get(&node_id).into_iter().flatten() {
            out.insert(GrantSource::Tag(tag.clone()));
        }
        for group in self.owner_groups.get(&node_id).into_iter().flatten() {
            out.insert(GrantSource::Oidc(group.clone()));
        }
        out
    }

    /// The groups `service` is in.
    #[must_use]
    pub fn groups_of(&self, service: &str) -> BTreeSet<String> {
        effective_groups(&self.members, service)
    }

    /// The sources granted any of `service`'s groups.
    #[must_use]
    pub fn granted(&self, service: &str) -> BTreeSet<GrantSource> {
        let groups = self.groups_of(service);
        self.grants.iter().filter(|g| groups.contains(&g.group)).map(|g| g.source.clone()).collect()
    }

    /// Whether `node_id` reaches `service` by who it is, and through which
    /// sources.
    #[must_use]
    pub fn matching(&self, node_id: i64, service: &str) -> BTreeSet<GrantSource> {
        let granted = self.granted(service);
        self.principals(node_id).into_iter().filter(|p| granted.contains(p)).collect()
    }
}

/// The rules as the database has them now.
pub fn read_rules(conn: &rusqlite::Connection) -> Result<Rules, crate::db::DbError> {
    Ok(Rules {
        grants: crate::db::grants::list_grants(conn)?,
        members: crate::db::grants::members(conn)?,
        tags: crate::db::grants::tags(conn)?,
        owner_groups: crate::db::owners::groups_by_node(conn, chrono::Utc::now())?,
    })
}

/// What a service's own node needs to know about the sign-in, beyond the
/// grants.
pub struct SignInFacts {
    /// The coordinator has a sign-in (PLAN.md M48): an identity provider,
    /// and DNS records for the terminators to serve under.
    pub available: bool,
    /// The owning node's terminator can check devices and fall back to the
    /// sign-in (`CAP_SIGN_IN`), reported on its latest poll.
    pub owner_capable: bool,
    /// Served with TLS by its own node right now.
    pub terminated: bool,
}

/// The access one service's owner enforces.
///
/// `sources` always holds the owner's own address: the host's own programs
/// reach its terminator from it, and would otherwise be refused by their
/// own node.
#[must_use]
pub fn service_access(
    service: &ServiceRow,
    owner: &NodeRow,
    peers: &[NodeRow],
    rules: &Rules,
    sign_in: &SignInFacts,
) -> ServiceAccess {
    let open = ServiceAccess { name: service.name.clone(), open: true, sources: vec![], sign_in: false, sign_in_groups: vec![] };
    let granted = rules.granted(&service.name);
    if granted.contains(&GrantSource::Everyone) {
        return open;
    }
    let mut sources: BTreeSet<Ipv4Addr> = peers
        .iter()
        .filter(|n| rules.principals(n.id).iter().any(|p| granted.contains(p)))
        .filter_map(|n| n.ip4.as_deref()?.parse().ok())
        .collect();
    if let Some(own) = owner.ip4.as_deref().and_then(|ip| ip.parse().ok()) {
        sources.insert(own);
    }
    let sign_in_groups = sign_in_groups(&granted);
    let sign_in = sign_in.offered(&sign_in_groups);
    ServiceAccess { name: service.name.clone(), open: false, sources: sources.into_iter().collect(), sign_in, sign_in_groups }
}

/// The identity provider's groups among `granted`.
fn sign_in_groups(granted: &BTreeSet<GrantSource>) -> Vec<String> {
    granted
        .iter()
        .filter_map(|s| match s {
            GrantSource::Oidc(g) => Some(g.clone()),
            _ => None,
        })
        .collect()
}

impl SignInFacts {
    /// Whether the owner's terminator lets anyone try the sign-in.
    fn offered(&self, sign_in_groups: &[String]) -> bool {
        self.available && self.owner_capable && self.terminated && !sign_in_groups.is_empty()
    }
}

/// What `requester` gets at `service` (PLAN.md M45): [`service_access`]'s
/// answer for one node, without working it out for every peer.
#[must_use]
pub fn reach(
    service: &ServiceRow,
    owner: &NodeRow,
    requester: &NodeRow,
    rules: &Rules,
    sign_in: &SignInFacts,
) -> Reach {
    if requester.id == owner.id {
        return Reach::Allowed;
    }
    let granted = rules.granted(&service.name);
    if granted.contains(&GrantSource::Everyone) {
        return Reach::Allowed;
    }
    // `service_access` lets a node in by its address: one without any is
    // let in nowhere.
    let addressed = requester.ip4.as_deref().is_some_and(|ip| ip.parse::<Ipv4Addr>().is_ok());
    if addressed && rules.principals(requester.id).iter().any(|p| granted.contains(p)) {
        return Reach::Allowed;
    }
    if sign_in.offered(&sign_in_groups(&granted)) {
        return Reach::SignIn;
    }
    Reach::Denied
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{PortMap, Proto};

    fn node(id: i64, name: &str, ip4: &str) -> NodeRow {
        let mut n = NodeRow::for_test(id, name);
        n.ip4 = Some(ip4.into());
        n
    }

    fn service(name: &str) -> ServiceRow {
        ServiceRow {
            node_id: 1,
            name: name.into(),
            vip4: Some("10.9.1.1".into()),
            ports: vec![PortMap::identity(443, Proto::Tcp)],
            declared_at: None,
            approved_at: None,
            denied_at: None,
            denied_reason: None,
        }
    }

    fn grant(source: &str, group: &str) -> Grant {
        Grant { source: source.parse().unwrap(), group: group.into() }
    }

    fn rules(grants: &[Grant]) -> Rules {
        Rules {
            grants: grants.to_vec(),
            members: BTreeMap::from([("db".into(), BTreeSet::from(["infra".to_string()]))]),
            tags: BTreeMap::from([(2, BTreeSet::from(["ops".to_string()]))]),
            owner_groups: BTreeMap::from([(3, BTreeSet::from(["family".to_string()]))]),
        }
    }

    fn peers() -> Vec<NodeRow> {
        vec![node(1, "home", "10.9.0.1"), node(2, "ci", "10.9.0.2"), node(3, "laptop", "10.9.0.3"), node(4, "tv", "10.9.0.4")]
    }

    const NO_SIGN_IN: SignInFacts = SignInFacts { available: false, owner_capable: true, terminated: true };
    const SIGN_IN: SignInFacts = SignInFacts { available: true, owner_capable: true, terminated: true };

    fn access(svc: &str, grants: &[Grant], si: &SignInFacts) -> ServiceAccess {
        let peers = peers();
        service_access(&service(svc), &peers[0], &peers, &rules(grants), si)
    }

    fn ips(list: &[&str]) -> Vec<Ipv4Addr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn everyone_granted_means_open() {
        let fresh = [grant("everyone", "default")];
        assert!(access("web", &fresh, &NO_SIGN_IN).open, "a service without a group is in default");
        let db = access("db", &fresh, &NO_SIGN_IN);
        assert!(!db.open, "an explicit group leaves default");
        assert_eq!(db.sources, ips(&["10.9.0.1"]), "only its own node");
    }

    #[test]
    fn tags_and_owner_groups_pick_the_nodes() {
        let a = access("db", &[grant("tag:ops", "infra")], &NO_SIGN_IN);
        assert_eq!(a.sources, ips(&["10.9.0.1", "10.9.0.2"]));
        let a = access("db", &[grant("tag:ops", "infra"), grant("oidc:family", "infra")], &NO_SIGN_IN);
        assert_eq!(a.sources, ips(&["10.9.0.1", "10.9.0.2", "10.9.0.3"]));
        assert_eq!(a.sign_in_groups, ["family"]);
        assert!(!a.sign_in, "no sign-in configured");
        let a = access("db", &[grant("tag:ops", "other")], &NO_SIGN_IN);
        assert_eq!(a.sources, ips(&["10.9.0.1"]), "a grant to another group is not this one's");
    }

    #[test]
    fn the_sign_in_needs_one_configured_a_capable_terminator_and_a_group_to_prove() {
        let g = [grant("oidc:family", "infra")];
        assert!(access("db", &g, &SIGN_IN).sign_in);
        assert!(!access("db", &[grant("tag:ops", "infra")], &SIGN_IN).sign_in, "nothing to prove by signing in");
        let not_capable = SignInFacts { owner_capable: false, ..SIGN_IN };
        assert!(!access("db", &g, &not_capable).sign_in);
        let not_terminated = SignInFacts { terminated: false, ..SIGN_IN };
        assert!(!access("db", &g, &not_terminated).sign_in);
    }

    /// What the owner's firewall would let `requester` through, from the
    /// access it is sent: the meaning `reach` must keep.
    fn enforced(a: &ServiceAccess, requester: &NodeRow) -> Reach {
        let ip: Option<Ipv4Addr> = requester.ip4.as_deref().and_then(|ip| ip.parse().ok());
        if a.open || ip.is_some_and(|ip| a.sources.contains(&ip)) {
            Reach::Allowed
        } else if a.sign_in {
            Reach::SignIn
        } else {
            Reach::Denied
        }
    }

    #[test]
    fn reach_agrees_with_the_access_the_owner_enforces() {
        let grant_sets: Vec<Vec<Grant>> = vec![
            vec![],
            vec![grant("everyone", "default")],
            vec![grant("everyone", "infra")],
            vec![grant("tag:ops", "infra")],
            vec![grant("oidc:family", "infra")],
            vec![grant("tag:ops", "infra"), grant("oidc:family", "infra")],
            vec![grant("oidc:friends", "infra")],
            vec![grant("tag:ops", "other")],
        ];
        let mut peers = peers();
        peers.push(NodeRow::for_test(5, "no-address"));
        let facts = [
            NO_SIGN_IN,
            SIGN_IN,
            SignInFacts { owner_capable: false, ..SIGN_IN },
            SignInFacts { terminated: false, ..SIGN_IN },
        ];
        for grants in &grant_sets {
            let r = rules(grants);
            for svc in ["web", "db"] {
                for si in &facts {
                    let a = service_access(&service(svc), &peers[0], &peers, &r, si);
                    for requester in &peers {
                        assert_eq!(
                            reach(&service(svc), &peers[0], requester, &r, si),
                            enforced(&a, requester),
                            "{svc} for {} with {grants:?}",
                            requester.name,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_node_outside_the_grants_is_told_it_may_sign_in_or_not() {
        let peers = peers();
        let g = [grant("oidc:family", "infra")];
        let tv = &peers[3];
        assert_eq!(reach(&service("db"), &peers[0], tv, &rules(&g), &SIGN_IN), Reach::SignIn);
        assert_eq!(reach(&service("db"), &peers[0], tv, &rules(&g), &NO_SIGN_IN), Reach::Denied);
        assert_eq!(reach(&service("db"), &peers[0], &peers[2], &rules(&g), &SIGN_IN), Reach::Allowed, "its owner is in family");
    }

    #[test]
    fn no_service_is_open_for_being_named_like_a_sign_in() {
        // Before M48 the forward_auth provider's own service was always
        // open; the coordinator is the sign-in now, and an `auth` is
        // restricted like anything else.
        let peers = vec![node(9, "gate", "10.9.0.9")];
        let mut r = rules(&[grant("tag:ops", "infra")]);
        r.members.insert("auth".into(), BTreeSet::from(["infra".to_string()]));
        let mut svc = service("auth");
        svc.node_id = 9;
        assert!(!service_access(&svc, &peers[0], &peers, &r, &SIGN_IN).open);
    }
}
