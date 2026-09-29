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

use wireserve_types::{GrantSource, ServiceAccess};

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
pub struct SignInFacts<'a> {
    /// `(service, node)` of the configured provider, if any.
    pub provider: Option<(&'a str, &'a str)>,
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
    sign_in: &SignInFacts<'_>,
) -> ServiceAccess {
    let open = ServiceAccess { name: service.name.clone(), open: true, sources: vec![], sign_in: false, sign_in_groups: vec![] };
    // The provider stays reachable by everyone: every terminator asks it,
    // and a browser not allowed anywhere yet has to reach its login page.
    if sign_in.provider == Some((service.name.as_str(), owner.name.as_str())) {
        return open;
    }
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
    let sign_in_groups: Vec<String> = granted
        .iter()
        .filter_map(|s| match s {
            GrantSource::Oidc(g) => Some(g.clone()),
            _ => None,
        })
        .collect();
    let sign_in =
        sign_in.provider.is_some() && sign_in.owner_capable && sign_in.terminated && !sign_in_groups.is_empty();
    ServiceAccess { name: service.name.clone(), open: false, sources: sources.into_iter().collect(), sign_in, sign_in_groups }
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

    const NO_SIGN_IN: SignInFacts<'static> = SignInFacts { provider: None, owner_capable: true, terminated: true };
    const SIGN_IN: SignInFacts<'static> = SignInFacts { provider: Some(("auth", "gate")), owner_capable: true, terminated: true };

    fn access(svc: &str, grants: &[Grant], si: &SignInFacts<'_>) -> ServiceAccess {
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
        assert!(!a.sign_in, "no provider configured");
        let a = access("db", &[grant("tag:ops", "other")], &NO_SIGN_IN);
        assert_eq!(a.sources, ips(&["10.9.0.1"]), "a grant to another group is not this one's");
    }

    #[test]
    fn the_sign_in_needs_a_provider_a_capable_terminator_and_a_group_to_prove() {
        let g = [grant("oidc:family", "infra")];
        assert!(access("db", &g, &SIGN_IN).sign_in);
        assert!(!access("db", &[grant("tag:ops", "infra")], &SIGN_IN).sign_in, "nothing to prove by signing in");
        let not_capable = SignInFacts { owner_capable: false, ..SIGN_IN };
        assert!(!access("db", &g, &not_capable).sign_in);
        let not_terminated = SignInFacts { terminated: false, ..SIGN_IN };
        assert!(!access("db", &g, &not_terminated).sign_in);
    }

    #[test]
    fn the_provider_on_its_own_node_is_always_open() {
        let peers = vec![node(9, "gate", "10.9.0.9")];
        let mut r = rules(&[grant("tag:ops", "infra")]);
        r.members.insert("auth".into(), BTreeSet::from(["infra".to_string()]));
        let mut svc = service("auth");
        svc.node_id = 9;
        assert!(service_access(&svc, &peers[0], &peers, &r, &SIGN_IN).open);
        let elsewhere = node(1, "home", "10.9.0.1");
        assert!(!service_access(&svc, &elsewhere, &peers, &r, &SIGN_IN).open, "only on the named node");
    }
}
