//! Publishing mesh services as reverse-proxy vhosts (PLAN.md M25).
//!
//! A phone has no hosts file, so `<name>.wg` cannot reach it. The way it gets
//! a name is a reverse proxy on one node holding a wildcard certificate, with
//! one public wildcard DNS record pointing at that proxy's service address —
//! the path M24's decision #104 named after ruling out a mesh resolver on the
//! evidence that iOS and Android would route *every* query through it.
//!
//! What this module does is keep that proxy's configuration in step with the
//! directory, so a service declared today is reachable by name immediately and
//! nobody edits a Caddyfile. The operator still owns the site block, the
//! certificate and the DNS record; this owns exactly one generated file.
//!
//! **Publishing TCP 443 is the opt-in.** It needs no new per-service field, so
//! no schema change, and it is what stops an SSH or Postgres service acquiring
//! a public hostname and a certificate it never asked for.

pub mod caddy;

use std::net::Ipv4Addr;

use wireserve_types::naming::publishes_tls;
use wireserve_types::{ServiceInfo, ServiceNaming, TLS_PUBLIC_PORT};

/// One published name and where it forwards.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VHost {
    /// The fully-qualified name, e.g. `plex.int.example.com`.
    pub host: String,
    /// The service address to forward to.
    pub upstream: Ipv4Addr,
    /// The published port on that address — always [`TLS_PUBLIC_PORT`] today,
    /// carried explicitly so the renderer never hardcodes it.
    pub port: u16,
    /// Behind the sign-in the operator configures on this proxy (PLAN.md
    /// M29). The service's own node admits nobody but this proxy, so this
    /// is the only way in.
    pub auth: bool,
}

/// Writes a proxy's configuration from a set of vhosts.
///
/// A trait with one implementation, for the same reason `FirewallBackend` is
/// one: `run_once` needs a fake so the wiring is testable without the real
/// daemon. Agent-local rather than in `wireserve-types`, unlike
/// `FirewallBackend` — nothing outside this crate implements or calls it, and
/// `ServiceInfo` already lives in types, so there is no orphan to avoid.
pub trait ProxyBackend {
    /// Makes the proxy serve exactly `vhosts`. Idempotent: a call that would
    /// not change the rendered configuration must do nothing at all, or the
    /// proxy is reloaded on every poll for the life of the daemon.
    fn sync(&mut self, vhosts: &[VHost]) -> Result<(), ProxyError>;

    /// Removes everything this backend wrote, and reloads.
    fn teardown(&mut self) -> Result<(), ProxyError>;
}

/// A backend's failure, type-erased.
///
/// Boxed rather than an associated type, unlike `FirewallBackend`: the poll
/// context holds this as `Option<&mut dyn ProxyBackend>` — the proxy is opt-in
/// per node, so it is genuinely absent on most of them — and an associated
/// type is not object-safe.
pub type ProxyError = Box<dyn std::error::Error + Send + Sync>;

/// The vhosts a directory calls for, sorted so an unchanged directory renders
/// byte for byte the same.
///
/// Deliberately *not* filtered on `ServiceInfo::online`: a node that flaps
/// would otherwise rewrite the configuration and reload the proxy on every
/// transition. A name that resolves to a service which happens to be down is
/// a 502, which is a better failure than a name that comes and goes.
#[must_use]
pub fn vhosts(services: &[ServiceInfo], naming: &ServiceNaming) -> Vec<VHost> {
    let mut out: Vec<VHost> = services
        .iter()
        .filter(|s| publishes_tls(s))
        // The proxy never proxies itself: a vhost pointing at the proxy's own
        // address would loop straight back in.
        .filter(|s| naming.proxy_service.as_deref() != Some(s.name.as_str()))
        .filter_map(|s| {
            // Re-validated here for the reason `hosts::is_safe_entry` gives:
            // the coordinator allocates these and validates the names, so a
            // bad one means a coordinator bug or a compromised coordinator,
            // and this writer is the last thing between that and a line of
            // attacker-chosen text in a configuration file that runs as root.
            // The address is rendered from the *parsed* value, so no byte off
            // the wire reaches the file.
            let Some(upstream) = s.vip4.as_deref().and_then(|v| v.parse::<Ipv4Addr>().ok()) else {
                // No service address means a coordinator from before they
                // existed; such a service answers on its node's address at the
                // target port, not the published one, so a vhost built from
                // the published port would forward into a closed port.
                tracing::warn!(
                    service = %s.name.escape_debug(),
                    "service has no address of its own; not publishing it by name"
                );
                return None;
            };
            if !wireserve_types::is_valid_dns_label(&s.name) {
                tracing::warn!(
                    service = %s.name.escape_debug(),
                    "refusing to publish a malformed service name"
                );
                return None;
            }
            let host = format!("{}.{}", s.name, naming.domain);
            if host.len() > 253 {
                tracing::warn!(service = %s.name.escape_debug(), "published name is too long");
                return None;
            }
            Some(VHost { host, upstream, port: TLS_PUBLIC_PORT, auth: s.auth })
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
pub mod fake {
    //! A backend that records instead of writing, for the poll-loop tests.
    use super::{ProxyBackend, VHost};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default, Clone)]
    pub struct FakeProxyBackend {
        pub calls: Arc<Mutex<Vec<Vec<VHost>>>>,
        pub fail: bool,
    }

    impl ProxyBackend for FakeProxyBackend {
        fn sync(&mut self, vhosts: &[VHost]) -> Result<(), super::ProxyError> {
            self.calls.lock().unwrap().push(vhosts.to_vec());
            if self.fail {
                return Err("fake proxy failure".into());
            }
            Ok(())
        }
        fn teardown(&mut self) -> Result<(), super::ProxyError> {
            if self.fail {
                return Err("fake proxy failure".into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{PortMap, Proto};

    fn svc(name: &str, vip: Option<&str>, public: u16, proto: Proto) -> ServiceInfo {
        ServiceInfo {
            auth: false,
            name: name.into(),
            node: "n".into(),
            ip4: "10.0.0.1".into(),
            port: public,
            proto,
            online: true,
            vip4: vip.map(Into::into),
            ports: vec![PortMap { public, target: 8080, proto, addr: None }],
        }
    }

    fn naming(proxy: Option<&str>) -> ServiceNaming {
        ServiceNaming { domain: "int.example.com".into(), proxy_service: proxy.map(Into::into) }
    }

    #[test]
    fn only_services_published_on_tcp_443_are_named() {
        let services = [
            svc("plex", Some("10.0.0.50"), 443, Proto::Tcp),
            svc("prom", Some("10.0.0.51"), 80, Proto::Tcp),
            svc("dns", Some("10.0.0.52"), 443, Proto::Udp),
            svc("ssh", Some("10.0.0.53"), 22, Proto::Tcp),
        ];
        let got = vhosts(&services, &naming(None));
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].host, "plex.int.example.com");
        assert_eq!(got[0].upstream, "10.0.0.50".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn the_proxy_never_proxies_itself() {
        let services = [svc("web", Some("10.0.0.2"), 443, Proto::Tcp)];
        assert!(
            vhosts(&services, &naming(Some("web"))).is_empty(),
            "a vhost for the proxy's own address forwards straight back into it"
        );
    }

    #[test]
    fn a_service_without_its_own_address_is_skipped_not_mispublished() {
        // Pre-service-address coordinator: it answers on node:target, so a
        // vhost built from the published port would point at a closed port.
        let services = [svc("plex", None, 443, Proto::Tcp)];
        assert!(vhosts(&services, &naming(None)).is_empty());
    }

    #[test]
    fn a_malformed_name_or_address_is_dropped_rather_than_written() {
        let mut bad_name = svc("plex", Some("10.0.0.50"), 443, Proto::Tcp);
        bad_name.name = "evil\nhandle { }".into();
        let mut bad_addr = svc("immich", Some("not-an-address"), 443, Proto::Tcp);
        bad_addr.vip4 = Some("10.0.0.51\nreverse_proxy evil:80".into());
        assert!(vhosts(&[bad_name, bad_addr], &naming(None)).is_empty());
    }

    #[test]
    fn output_is_sorted_so_an_unchanged_directory_renders_identically() {
        let a = svc("zulip", Some("10.0.0.60"), 443, Proto::Tcp);
        let b = svc("adguard", Some("10.0.0.61"), 443, Proto::Tcp);
        let one = vhosts(&[a.clone(), b.clone()], &naming(None));
        let two = vhosts(&[b, a], &naming(None));
        assert_eq!(one, two);
        assert_eq!(one[0].host, "adguard.int.example.com");
    }

    #[test]
    fn a_service_that_is_offline_is_still_published() {
        let mut s = svc("plex", Some("10.0.0.50"), 443, Proto::Tcp);
        s.online = false;
        assert_eq!(vhosts(&[s], &naming(None)).len(), 1, "flapping must not churn the config");
    }
}
