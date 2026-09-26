//! Keeps the public DNS records in step with the directory (PLAN.md M32).
//!
//! The coordinator's first background loop. Every pass computes the names
//! the directory implies — the same [`ServiceNames`] rule each agent's hosts
//! file follows — diffs them against what `dns_records` says was written,
//! and writes the difference. A pass runs every minute and whenever
//! something pokes [`Dns::wake`]; it never runs inside a request, so a slow
//! or failing provider costs nothing but a warning and a retry.
//!
//! Two rules keep it from doing damage:
//! * **Only what it wrote is ever deleted.** A name leaves DNS only while a
//!   `dns_records` row says this coordinator put it there.
//! * **A changed address must hold before it is written.** A new name is
//!   published at once and a withdrawn one removed at once, but a name
//!   moving from one address to another is written only once the new
//!   address has held for [`DEBOUNCE`]. A proxy briefly missing from the
//!   directory would otherwise swing every 443 name to its own address and
//!   back, and cached answers would carry the swing for a full TTL.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use wireserve_types::{ServiceInfo, ServiceNames, ServiceNaming};

use super::provider::DnsWriter;
use crate::db::{dns_records, nodes, services};
use crate::AppState;

/// How long a changed address must hold before it is written.
pub const DEBOUNCE: Duration = Duration::from_secs(20);
/// The pass interval when nothing pokes the loop.
const INTERVAL: Duration = Duration::from_secs(60);
/// The least time between two passes, however often the loop is poked:
/// every poll pokes it, and a pass with nothing to do is still a database
/// read.
const MIN_SPACING: Duration = Duration::from_secs(5);
/// The longest a run of provider failures pushes the next attempt out.
const MAX_BACKOFF: Duration = Duration::from_secs(900);

/// Where one service's record stands, for `GET /admin/services`.
pub use wireserve_types::DnsRecordState as RecordState;

/// The loop's handle, shared through [`AppState`].
pub struct Dns {
    pub writer: Arc<dyn DnsWriter>,
    /// Poked when the directory may have changed.
    pub wake: Notify,
    /// Service name → where its record stands, as of the last pass.
    pub status: std::sync::Mutex<BTreeMap<String, RecordState>>,
}

impl Dns {
    #[must_use]
    pub fn new(writer: Arc<dyn DnsWriter>) -> Self {
        Self { writer, wake: Notify::new(), status: std::sync::Mutex::new(BTreeMap::new()) }
    }

    /// The state of `service`'s record, `None` when the service has no
    /// public name.
    #[must_use]
    pub fn state_of(&self, service: &str) -> Option<RecordState> {
        self.status.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(service).cloned()
    }
}

/// One wanted record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub service: String,
    pub addr: Ipv4Addr,
}

/// Every record the directory implies, by lowercase FQDN. Empty without a
/// domain: the `.wg` names have no public zone.
#[must_use]
pub fn desired(services: &[ServiceInfo], naming: Option<&ServiceNaming>) -> BTreeMap<String, Wanted> {
    if naming.is_none() {
        return BTreeMap::new();
    }
    let names = ServiceNames::new(naming, services);
    services
        .iter()
        // The same re-check the hosts file makes: a name that is not a plain
        // label never becomes a record, whatever the database holds.
        .filter(|s| wireserve_types::is_valid_dns_label(&s.name))
        .filter_map(|s| {
            let addr = names.address(s)?;
            Some((names.host_name(s).to_ascii_lowercase(), Wanted { service: s.name.clone(), addr }))
        })
        .collect()
}

/// What one pass does.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub write: Vec<(String, Ipv4Addr)>,
    pub delete: Vec<String>,
    /// The soonest a held address change becomes due, if any is held.
    pub next_due: Option<Duration>,
}

/// Diffs `desired` against `written`. `moving` remembers, across passes,
/// each name whose address changed and since when; it is updated here.
pub fn plan(
    desired: &BTreeMap<String, Wanted>,
    written: &BTreeMap<String, String>,
    moving: &mut BTreeMap<String, (Ipv4Addr, Instant)>,
    now: Instant,
) -> Plan {
    let mut out = Plan::default();
    let mut still_moving = BTreeMap::new();
    for (fqdn, want) in desired {
        match written.get(fqdn) {
            None => out.write.push((fqdn.clone(), want.addr)),
            Some(have) if *have == want.addr.to_string() => {}
            Some(_) => {
                // A different target than last pass restarts the wait.
                let since = match moving.get(fqdn) {
                    Some((addr, since)) if *addr == want.addr => *since,
                    _ => now,
                };
                let held = now.saturating_duration_since(since);
                if held >= DEBOUNCE {
                    out.write.push((fqdn.clone(), want.addr));
                } else {
                    let due = DEBOUNCE - held;
                    out.next_due = Some(out.next_due.map_or(due, |d| d.min(due)));
                    still_moving.insert(fqdn.clone(), (want.addr, since));
                }
            }
        }
    }
    out.delete = written.keys().filter(|fqdn| !desired.contains_key(*fqdn)).cloned().collect();
    *moving = still_moving;
    out
}

/// What a pass reports back to the loop.
#[derive(Debug, Default)]
pub struct PassOutcome {
    pub failed: bool,
    pub next_due: Option<Duration>,
}

/// One pass: read the directory, write the difference, record the outcome.
/// Public so the integration tests can drive passes one at a time.
pub async fn pass(state: &AppState, dns: &Dns, moving: &mut BTreeMap<String, (Ipv4Addr, Instant)>) -> PassOutcome {
    let read = async {
        let conn = state.db.conn.lock().await;
        let peers = nodes::list_all_peers(&conn)?;
        let approved = services::list_approved(&conn)?;
        let auth = services::auth_names(&conn)?;
        let tls_ready = crate::db::tls::ready(&conn)?;
        let directory =
            crate::directory::services_directory(&approved, &peers, &state.directory_context(&auth, &tls_ready));
        Ok::<_, crate::db::DbError>((desired(&directory, state.config.service_naming().as_ref()), dns_records::all(&conn)?))
    };
    // The lock is dropped here: nothing below holds it across a provider
    // call, which can take seconds.
    let (want, mut written) = match read.await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "DNS sync could not read the directory");
            return PassOutcome { failed: true, next_due: None };
        }
    };

    let todo = plan(&want, &written, moving, Instant::now());
    let mut errors: BTreeMap<String, String> = BTreeMap::new();

    for (fqdn, addr) in &todo.write {
        match dns.writer.set_a(fqdn, *addr).await {
            Ok(()) => {
                let value = addr.to_string();
                tracing::info!(event = "dns_record_set", fqdn = %fqdn, addr = %value);
                if let Err(e) = dns_records::record(&*state.db.conn.lock().await, fqdn, &value) {
                    tracing::warn!(fqdn = %fqdn, error = %e, "DNS record written but not recorded; it will be written again");
                }
                written.insert(fqdn.clone(), value);
            }
            Err(e) => {
                tracing::warn!(fqdn = %fqdn, error = %e, "could not write DNS record");
                errors.insert(fqdn.clone(), e);
            }
        }
    }
    for fqdn in &todo.delete {
        match dns.writer.delete_a(fqdn).await {
            Ok(()) => {
                tracing::info!(event = "dns_record_deleted", fqdn = %fqdn);
                if let Err(e) = dns_records::forget(&*state.db.conn.lock().await, fqdn) {
                    tracing::warn!(fqdn = %fqdn, error = %e, "DNS record deleted but still recorded; it will be deleted again");
                }
                written.remove(fqdn);
            }
            Err(e) => {
                tracing::warn!(fqdn = %fqdn, error = %e, "could not delete DNS record");
                errors.insert(fqdn.clone(), e);
            }
        }
    }

    if !reap_challenges(state, dns).await {
        errors.insert("_acme-challenge".into(), "a challenge record could not be removed".into());
    }

    let status: BTreeMap<String, RecordState> = want
        .iter()
        .map(|(fqdn, w)| {
            let st = if let Some(e) = errors.get(fqdn) {
                RecordState::Error(e.clone())
            } else if written.get(fqdn) == Some(&w.addr.to_string()) {
                RecordState::Published
            } else {
                RecordState::Pending
            };
            (w.service.clone(), st)
        })
        .collect();
    *dns.status.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = status;

    PassOutcome { failed: !errors.is_empty(), next_due: todo.next_due }
}

/// Removes the ACME challenge records whose time is up (PLAN.md M33): the
/// ones a node withdrew, and the ones a node left behind. `false` when a
/// removal failed; its row stays, and the next pass tries again.
async fn reap_challenges(state: &AppState, dns: &Dns) -> bool {
    let now = chrono::Utc::now();
    let due: Vec<crate::db::tls::Challenge> = match crate::db::tls::challenges(&*state.db.conn.lock().await) {
        Ok(all) => all.into_iter().filter(|c| c.expires_at <= now).collect(),
        Err(e) => {
            tracing::warn!(error = %e, "DNS sync could not read the ACME challenges");
            return false;
        }
    };
    let mut ok = true;
    for c in due {
        if c.written {
            if let Err(e) = dns.writer.remove_txt(&c.fqdn, &c.value).await {
                tracing::warn!(fqdn = %c.fqdn, error = %e, "could not remove an ACME challenge record");
                ok = false;
                continue;
            }
        }
        if let Err(e) = crate::db::tls::delete_challenge(&*state.db.conn.lock().await, &c.fqdn, &c.value) {
            tracing::warn!(fqdn = %c.fqdn, error = %e, "ACME challenge removed but still recorded");
        }
    }
    ok
}

/// Runs forever. Spawned once at startup when a provider is configured.
pub async fn run(state: AppState, dns: Arc<Dns>) {
    let mut moving = BTreeMap::new();
    let mut failures: u32 = 0;
    loop {
        let outcome = pass(&state, &dns, &mut moving).await;
        failures = if outcome.failed { failures.saturating_add(1) } else { 0 };
        let wait = if failures > 0 {
            // 60s, 120s, 240s … capped: a provider that is down, or a token
            // that was revoked, should not be hammered once a minute.
            (INTERVAL * 2u32.saturating_pow(failures - 1).min(64)).min(MAX_BACKOFF)
        } else {
            outcome.next_due.map_or(INTERVAL, |due| due.min(INTERVAL))
        };
        tokio::time::sleep(MIN_SPACING).await;
        // Failures back off even when poked; everything else wakes early.
        if failures > 0 {
            tokio::time::sleep(wait.saturating_sub(MIN_SPACING)).await;
        } else {
            tokio::select! {
                () = dns.wake.notified() => {}
                () = tokio::time::sleep(wait.saturating_sub(MIN_SPACING)) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{PortMap, Proto};

    fn svc(name: &str, vip: &str, public: u16) -> ServiceInfo {
        ServiceInfo {
            auth: false,
            terminated: false,
            name: name.into(),
            node: "n".into(),
            ip4: "10.77.0.2".into(),
            port: public,
            proto: Proto::Tcp,
            online: true,
            vip4: Some(vip.into()),
            ports: vec![PortMap { public, target: 8080, proto: Proto::Tcp, addr: None }],
        }
    }

    fn naming(proxy: Option<&str>) -> ServiceNaming {
        ServiceNaming { domain: "Int.Example.com".into(), proxy_service: proxy.map(Into::into), acme: None }
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn desired_follows_the_hosts_file_rule() {
        let services = [svc("plex", "10.77.0.10", 443), svc("prom", "10.77.0.11", 80), svc("web", "10.77.0.12", 443)];
        let d = desired(&services, Some(&naming(Some("web"))));
        assert_eq!(d["plex.int.example.com"].addr, ip("10.77.0.12"), "443 goes to the proxy");
        assert_eq!(d["prom.int.example.com"].addr, ip("10.77.0.11"), "everything else to its own address");
        assert_eq!(d["web.int.example.com"].addr, ip("10.77.0.12"));
        assert!(desired(&services, None).is_empty(), "no domain, no public names");
    }

    #[test]
    fn a_bad_name_or_address_never_becomes_a_record() {
        let mut bad_name = svc("prom", "10.77.0.11", 80);
        bad_name.name = "evil.name".into();
        let mut bad_addr = svc("graf", "not-an-ip", 80);
        bad_addr.ip4 = "also-not".into();
        assert!(desired(&[bad_name, bad_addr], Some(&naming(None))).is_empty());
    }

    fn want(pairs: &[(&str, &str)]) -> BTreeMap<String, Wanted> {
        pairs.iter().map(|(f, a)| ((*f).into(), Wanted { service: "s".into(), addr: ip(a) })).collect()
    }

    fn have(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(f, a)| ((*f).into(), (*a).into())).collect()
    }

    #[test]
    fn new_names_are_written_and_only_our_withdrawn_names_deleted() {
        let mut moving = BTreeMap::new();
        let p = plan(
            &want(&[("a.d", "10.0.0.1"), ("b.d", "10.0.0.2")]),
            &have(&[("b.d", "10.0.0.2"), ("gone.d", "10.0.0.9")]),
            &mut moving,
            Instant::now(),
        );
        assert_eq!(p.write, vec![("a.d".into(), ip("10.0.0.1"))]);
        assert_eq!(p.delete, vec!["gone.d".to_string()]);
    }

    #[test]
    fn nothing_written_means_nothing_deleted() {
        // A fresh or restored database: the zone may hold anything, and none
        // of it is ours to remove.
        let p = plan(&want(&[]), &have(&[]), &mut BTreeMap::new(), Instant::now());
        assert_eq!(p, Plan::default());
    }

    #[test]
    fn a_changed_address_waits_out_the_debounce() {
        let mut moving = BTreeMap::new();
        let t0 = Instant::now();
        let w = want(&[("a.d", "10.0.0.2")]);
        let h = have(&[("a.d", "10.0.0.1")]);

        let first = plan(&w, &h, &mut moving, t0);
        assert!(first.write.is_empty());
        assert_eq!(first.next_due, Some(DEBOUNCE));

        let early = plan(&w, &h, &mut moving, t0 + DEBOUNCE / 2);
        assert!(early.write.is_empty());
        assert_eq!(early.next_due, Some(DEBOUNCE / 2));

        let due = plan(&w, &h, &mut moving, t0 + DEBOUNCE);
        assert_eq!(due.write, vec![("a.d".into(), ip("10.0.0.2"))]);
        assert!(moving.is_empty());
    }

    #[test]
    fn a_swing_back_cancels_the_pending_change() {
        let mut moving = BTreeMap::new();
        let t0 = Instant::now();
        let h = have(&[("a.d", "10.0.0.1")]);
        plan(&want(&[("a.d", "10.0.0.2")]), &h, &mut moving, t0);
        // Back where it was: nothing to write, and nothing left pending.
        let back = plan(&want(&[("a.d", "10.0.0.1")]), &h, &mut moving, t0 + DEBOUNCE);
        assert_eq!(back, Plan::default());
        assert!(moving.is_empty());
        // Moving again starts a fresh wait rather than inheriting the old one.
        let again = plan(&want(&[("a.d", "10.0.0.3")]), &h, &mut moving, t0 + DEBOUNCE * 2);
        assert!(again.write.is_empty());
    }
}
