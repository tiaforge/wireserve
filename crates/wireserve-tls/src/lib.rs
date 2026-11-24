//! The per-node TLS terminator (PLAN.md M33): `wireserve tls-daemon`.
//!
//! Serves each of this node's services published on TCP 443 with TLS, on
//! the service's own address, with a certificate it obtains itself — the
//! way `tailscale serve` does, but for names under the operator's own
//! domain, reachable from stock WireGuard apps.
//!
//! It runs as its own unprivileged user under its own unit, beside the
//! agent: it parses TLS and HTTP from the whole mesh, and none of that
//! belongs in the process that holds the node's WireGuard key and edits its
//! firewall. What it needs from the agent — which services, which
//! addresses, who is calling — it asks for over a socket that answers
//! nothing else, and the agent decides what reaches it.
//!
//! Every few seconds it checks in: it tells the agent what it serves right
//! now and gets back what it should serve. A service is served once its
//! certificate is held and its address is bound; the agent reports that to
//! the coordinator, which only then points the name at the service's own
//! address.
//!
//! On Windows (PLAN.md M52) it runs as its own service, under a virtual
//! account of its own, and listens on each service address's 443 and 80
//! itself: nothing there rewrites them onto one port.

pub mod acme;
pub mod link;
mod platform;
pub mod serve;
pub mod sign_in;
pub mod store;
mod upgrade;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use tokio::task::JoinHandle;
use wireserve_types::tls::{TlsConfig, TlsService};

use crate::link::Link;
use crate::serve::{Callers, Certs, SharedSignIn};
use crate::store::{Store, Stored};

pub struct Options {
    /// The agent's TLS socket.
    pub socket: PathBuf,
    /// Where certificates and the ACME account are kept.
    pub state_dir: PathBuf,
    /// A CA certificate to trust for the ACME server itself, for a test CA
    /// such as Pebble. Never needed for a public CA.
    pub ca_file: Option<PathBuf>,
    pub check_in_every: Duration,
    /// The port to listen on when systemd passed no socket (PLAN.md M35).
    /// Unused on Windows, where each service address's 443 is listened on.
    pub port: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("state directory: {0}")]
    State(std::io::Error),
    #[error("cannot listen on port {0}: {1}")]
    Listen(u16, std::io::Error),
}

/// The first retry after a failed issuance; doubled each time, up to
/// [`MAX_BACKOFF`]. Let's Encrypt allows five failed validations per name
/// per hour, so hammering it would lock the name out for longer.
const FIRST_BACKOFF: Duration = Duration::from_secs(120);
const MAX_BACKOFF: Duration = Duration::from_secs(6 * 3600);

/// How often expired certificates nobody needs are swept from disk.
const PRUNE_EVERY: Duration = Duration::from_secs(24 * 3600);

/// One served service.
struct Served {
    service: TlsService,
    /// In the listener's routes.
    routed: bool,
    /// Why its address could not be listened on, last time it was tried;
    /// logged when it changes.
    unclaimed: Option<String>,
}

/// An issuance running in the background: the name, the CA's directory,
/// and its chain and key.
type InFlight = (String, String, JoinHandle<Result<(String, String), acme::AcmeError>>);

/// Per-name issuance bookkeeping.
#[derive(Default)]
struct Issuance {
    cert: Option<Stored>,
    /// The directory of the CA `cert` came from.
    ca: Option<String>,
    renew_at: Option<SystemTime>,
    /// `renew_at` being asked of the CA, in a task of its own: the check-in
    /// loop waits on nothing across the network, since a CA that does not
    /// answer would stop the check-ins and the agent would take 443 from
    /// every service on the node.
    lookup: Option<JoinHandle<SystemTime>>,
    /// `cert` as issued (its CA's directory, chain and key) while it could
    /// not be stored.
    unsaved: Option<(String, String, String)>,
    failures: u32,
    not_before: Option<Instant>,
}

impl Issuance {
    /// Holds `stored`, from the CA at `ca`, in place of what was held.
    fn hold(&mut self, stored: Stored, ca: String) {
        self.cert = Some(stored);
        self.ca = Some(ca);
        self.renew_at = None;
        self.unsaved = None;
        if let Some(lookup) = self.lookup.take() {
            lookup.abort();
        }
    }
}

/// Runs until the process is stopped.
pub async fn run(opts: Options) -> Result<(), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let store = Store::open(&opts.state_dir).map_err(Error::State)?;
    let accounts = Arc::new(acme::Accounts::new(store.root(), opts.ca_file.clone()));
    let link = Link::new(&opts.socket);
    let certs = Arc::new(Certs::default());
    let tls = serve::server_config(certs.clone());
    let shared = serve::Shared::default();
    let (incoming, mut listening, port) = platform::open_tls(opts.port).map_err(|e| Error::Listen(opts.port, e))?;
    // Plain HTTP on services' port 80 (PLAN.md #328). Without its socket the
    // agent leaves port 80 to the services themselves, as before.
    let http_wanted = wireserve_types::http_listen_port(port);
    let http_listener = match platform::open_http(http_wanted) {
        Ok(Some(l)) => Some(l),
        Ok(None) => {
            tracing::warn!("systemd passed no plain-HTTP socket; port 80 is not guarded — `wireserve install` again to add it");
            None
        }
        Err(e) => {
            tracing::warn!(port = http_wanted, error = %e, "cannot listen for plain HTTP; port 80 is not guarded");
            None
        }
    };
    let http_port = http_listener.as_ref().map_or(0, |(_, _, port)| *port);
    let (http_incoming, mut http_listening) = match http_listener {
        Some((incoming, listening, _)) => (Some(incoming), listening),
        None => (None, serve::Listening::Every),
    };
    let mut http_served: BTreeMap<String, wireserve_types::tls::HttpService> = BTreeMap::new();

    let mut served: BTreeMap<String, Served> = BTreeMap::new();
    let mut issuance: BTreeMap<String, Issuance> = BTreeMap::new();
    // One issuance at a time: a node with many services staggers them
    // rather than asking the CA for all at once.
    let mut in_flight: Option<InFlight> = None;
    let mut last_prune: Option<Instant> = None;

    tracing::info!(socket = %link.socket().display(), port, http_port, "TLS terminator starting");
    let accepting = serve::spawn(incoming, tls, shared.clone());
    let accepting_http = http_incoming.map(|l| serve::spawn_http(l, shared.clone()));
    let mut tick = tokio::time::interval(opts.check_in_every);
    loop {
        tick.tick().await;

        // What is served right now: a certificate held, and routed to by a
        // listener that is up.
        let up = !accepting.is_finished();
        let serving: Vec<String> = served
            .values()
            .filter(|s| up && s.routed)
            .filter(|s| issuance.get(&s.service.fqdn).and_then(|i| i.cert.as_ref()).is_some_and(|c| c.valid_at(SystemTime::now())))
            .map(|s| s.service.name.clone())
            .collect();
        let http_up = accepting_http.as_ref().is_some_and(|h| !h.is_finished());
        let http: Vec<String> = if http_up { http_served.keys().cloned().collect() } else { Vec::new() };
        let config = match link.check_in(serving, port, http, if http_up { http_port } else { 0 }).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "could not check in with the agent; keeping what is served");
                continue;
            }
        };
        update_callers(&shared.callers, &config);
        update_sign_in(&shared.sign_in, config.sign_in.as_ref(), &link);
        *shared.identity.write().unwrap_or_else(std::sync::PoisonError::into_inner) = config.identity_headers.clone();
        *shared.strip.write().unwrap_or_else(std::sync::PoisonError::into_inner) = config.strip_headers.clone();
        *shared.forwarders.write().unwrap_or_else(std::sync::PoisonError::into_inner) = config.forwarding_nodes.clone();

        forget_gone(&mut served, &mut issuance, &certs, &shared, &mut listening, &config);
        if http_up {
            route_http(&shared, &mut http_served, &mut http_listening, &config.http);
        }

        let Some(settings) = config.acme.clone() else {
            continue;
        };

        if last_prune.is_none_or(|t| t.elapsed() >= PRUNE_EVERY) {
            last_prune = Some(Instant::now());
            prune(&store, &settings, &config);
        }

        // A finished issuance.
        if in_flight.as_ref().is_some_and(|(_, _, h)| h.is_finished()) {
            let (fqdn, directory, handle) = in_flight.take().expect("checked above");
            let entry = issuance.entry(fqdn.clone()).or_default();
            match handle.await {
                Ok(Ok((chain, key))) => issued(&store, &certs, entry, &fqdn, directory, chain, key),
                Ok(Err(e)) => {
                    let wait = back_off(entry);
                    tracing::warn!(fqdn = %fqdn, error = %e, retry_in = ?wait, "certificate issuance failed");
                }
                Err(e) => tracing::error!(fqdn = %fqdn, error = %e, "issuance task failed"),
            }
        }
        for (fqdn, entry) in &mut issuance {
            save_again(&store, entry, fqdn);
        }

        for service in &config.services {
            let entry = issuance.entry(service.fqdn.clone()).or_default();
            // The coordinator moved to another CA (staging to production,
            // most likely): that CA's certificate, stored or new, replaces
            // the one served — which stays served until then.
            let other_ca = |e: &Issuance| e.cert.is_some() && e.ca.as_deref() != Some(settings.directory.as_str());
            if entry.cert.is_none() || other_ca(entry) {
                match store.load(&settings.directory, &service.fqdn) {
                    Ok(Some(stored)) if stored.valid_at(SystemTime::now()) => {
                        certs.set(&service.fqdn, stored.key.clone());
                        entry.hold(stored, settings.directory.clone());
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(fqdn = %service.fqdn, error = %e, "stored certificate unreadable; getting a new one"),
                }
            }

            // Routed to as soon as there is a certificate to answer with.
            let s = served
                .entry(service.name.clone())
                .or_insert_with(|| Served { service: service.clone(), routed: false, unclaimed: None });
            // Another address or backend is another route; who may reach
            // it is only its policy, replaced in place below so no request
            // ever finds the service missing in between.
            if (s.service.vip, s.service.upstream) != (service.vip, service.upstream) && s.routed {
                shared.unroute(s.service.vip);
                if s.service.vip != service.vip {
                    listening.release(s.service.vip);
                }
                s.routed = false;
            }
            s.service = service.clone();
            if entry.cert.is_some() {
                let policy = Arc::new(serve::Policy {
                    fqdn: service.fqdn.clone(),
                    aliases: Vec::new(),
                    access: service.access.clone(),
                    cross_site: service.cross_site,
                });
                shared.policies.write().unwrap_or_else(std::sync::PoisonError::into_inner).insert(service.vip, policy);
                if !s.routed {
                    match listening.claim(service.vip) {
                        Ok(()) => {
                            tracing::info!(service = %service.name, addr = %service.vip, upstream = %service.upstream, "serving");
                            let route = Arc::new(serve::Route::new(service.upstream));
                            shared.routes.write().unwrap_or_else(std::sync::PoisonError::into_inner).insert(service.vip, route);
                            s.routed = true;
                            s.unclaimed = None;
                        }
                        // Tried again at the next check-in: the agent adds
                        // the address on its next poll.
                        Err(e) => {
                            let why = e.to_string();
                            if s.unclaimed.as_ref() != Some(&why) {
                                tracing::warn!(service = %service.name, addr = %service.vip, port, error = %why, "cannot listen on the service's address yet; not serving it");
                                s.unclaimed = Some(why);
                            }
                        }
                    }
                }
            }

            // Issue, or renew, one at a time and not while backing off.
            if in_flight.is_some() || entry.not_before.is_some_and(|t| Instant::now() < t) {
                continue;
            }
            let replacing = other_ca(entry);
            let due = match &entry.cert {
                None => true,
                Some(_) if replacing => true,
                Some(cert) => {
                    if entry.renew_at.is_none() {
                        match entry.lookup.take() {
                            Some(lookup) if lookup.is_finished() => {
                                entry.renew_at = Some(lookup.await.unwrap_or_else(|_| cert.default_renewal()));
                            }
                            Some(lookup) => entry.lookup = Some(lookup),
                            None => {
                                let (accounts, settings, cert) = (accounts.clone(), settings.clone(), cert.clone());
                                entry.lookup = Some(tokio::spawn(async move {
                                    match accounts.get(&settings).await {
                                        Ok(account) => acme::renewal_time(&account, &cert).await,
                                        Err(_) => cert.default_renewal(),
                                    }
                                }));
                            }
                        }
                    }
                    entry.renew_at.is_some_and(|t| SystemTime::now() >= t)
                }
            };
            if due {
                tracing::info!(
                    fqdn = %service.fqdn,
                    renewal = entry.cert.is_some() && !replacing,
                    ca = %settings.directory,
                    "requesting a certificate"
                );
                // Renewal information only names a certificate of the same CA.
                let replaces = if replacing { None } else { entry.cert.clone() };
                let (fqdn, link, settings, accounts) = (service.fqdn.clone(), link.clone(), settings.clone(), accounts.clone());
                let name = fqdn.clone();
                in_flight = Some((
                    name,
                    settings.directory.clone(),
                    tokio::spawn(async move {
                        let account = accounts.get(&settings).await?;
                        acme::issue(&account, &fqdn, &link, &settings, replaces.as_ref()).await
                    }),
                ));
            }
        }
    }
}

/// Waits longer after each failure, up to [`MAX_BACKOFF`]; returns how long.
fn back_off(entry: &mut Issuance) -> Duration {
    entry.failures += 1;
    let wait = (FIRST_BACKOFF * 2u32.saturating_pow(entry.failures - 1)).min(MAX_BACKOFF);
    entry.not_before = Some(Instant::now() + wait);
    wait
}

/// Serves a certificate just issued, and stores it. One that cannot be
/// stored is served all the same from memory — it is valid, and only a
/// restart would lose it — and its storing is tried again with the usual
/// backoff: ordering again instead would obtain a new certificate every
/// few seconds on a full disk, until the CA's limit on duplicates locked
/// the name out for a week.
fn issued(store: &Store, certs: &Certs, entry: &mut Issuance, fqdn: &str, directory: String, chain: String, key: String) {
    let stored = match store::parse(chain.as_bytes(), key.as_bytes()) {
        Ok(stored) => stored,
        Err(e) => {
            let wait = back_off(entry);
            tracing::warn!(fqdn, error = %e, retry_in = ?wait, "the CA's certificate cannot be used");
            return;
        }
    };
    certs.set(fqdn, stored.key.clone());
    entry.hold(stored, directory.clone());
    entry.failures = 0;
    entry.not_before = None;
    match store.save(&directory, fqdn, &chain, &key) {
        Ok(_) => tracing::info!(fqdn, ca = %directory, "certificate issued"),
        Err(e) => {
            let wait = back_off(entry);
            tracing::error!(fqdn, error = %e, retry_in = ?wait, "certificate issued and served, but it could not be stored");
            entry.unsaved = Some((directory, chain, key));
        }
    }
}

/// Tries again to store the certificate `issued` could not, once its
/// backoff is over.
fn save_again(store: &Store, entry: &mut Issuance, fqdn: &str) {
    if entry.not_before.is_some_and(|t| Instant::now() < t) {
        return;
    }
    let Some((directory, chain, key)) = entry.unsaved.take() else { return };
    match store.save(&directory, fqdn, &chain, &key) {
        Ok(_) => {
            tracing::info!(fqdn, ca = %directory, "stored the certificate served since it was issued");
            entry.failures = 0;
            entry.not_before = None;
        }
        Err(e) => {
            let wait = back_off(entry);
            tracing::error!(fqdn, error = %e, retry_in = ?wait, "the certificate served still cannot be stored");
            entry.unsaved = Some((directory, chain, key));
        }
    }
}

/// Stops serving what the agent no longer asks for, and forgets its
/// certificate state: the stored certificate stays on disk, and serving the
/// name again loads it from there instead of finding a held certificate the
/// resolver no longer has.
fn forget_gone(
    served: &mut BTreeMap<String, Served>,
    issuance: &mut BTreeMap<String, Issuance>,
    certs: &Certs,
    shared: &serve::Shared,
    listening: &mut serve::Listening,
    config: &TlsConfig,
) {
    let wanted: BTreeSet<&str> = config.services.iter().map(|s| s.name.as_str()).collect();
    served.retain(|name, s| {
        let keep = wanted.contains(name.as_str());
        if !keep {
            tracing::info!(service = %name, "no longer serving");
            if s.routed {
                shared.unroute(s.service.vip);
            }
            listening.release(s.service.vip);
            certs.remove(&s.service.fqdn);
            issuance.remove(&s.service.fqdn);
        }
        keep
    });
}

/// Answers exactly the services in `wanted` in plain HTTP (PLAN.md #328):
/// each one's policy replaced in place, its route only when its address or
/// backend changed, and the ones no longer wanted let go.
fn route_http(
    shared: &serve::Shared,
    served: &mut BTreeMap<String, wireserve_types::tls::HttpService>,
    listening: &mut serve::Listening,
    wanted: &[wireserve_types::tls::HttpService],
) {
    let names: BTreeSet<&str> = wanted.iter().map(|s| s.name.as_str()).collect();
    served.retain(|name, s| {
        let keep = names.contains(name.as_str());
        if !keep {
            tracing::info!(service = %name, "no longer answering its port 80");
            shared.unroute_http(s.vip);
            listening.release(s.vip);
        }
        keep
    });
    for service in wanted {
        let Some((fqdn, aliases)) = service.names.split_first() else { continue };
        if let Some(old) = served.get(&service.name) {
            if (old.vip, old.upstream) != (service.vip, service.upstream) {
                shared.unroute_http(old.vip);
                if old.vip != service.vip {
                    listening.release(old.vip);
                }
                served.remove(&service.name);
            }
        }
        // No sign-in without TLS: whoever the grants do not let in, it is
        // not offered to here.
        let mut access = service.access.clone();
        access.sign_in = false;
        let policy = Arc::new(serve::Policy { fqdn: fqdn.clone(), aliases: aliases.to_vec(), access, cross_site: service.cross_site });
        shared.http_policies.write().unwrap_or_else(std::sync::PoisonError::into_inner).insert(service.vip, policy);
        if !served.contains_key(&service.name) {
            // Tried again at the next check-in, quietly: the TLS side says
            // why an address cannot be listened on, and this is the same one.
            if let Err(e) = listening.claim(service.vip) {
                tracing::debug!(service = %service.name, addr = %service.vip, error = %e, "cannot listen on the service's port 80 yet");
                continue;
            }
            tracing::info!(service = %service.name, addr = %service.vip, upstream = %service.upstream, "answering its port 80");
            let route = Arc::new(serve::Route::new(service.upstream));
            shared.http_routes.write().unwrap_or_else(std::sync::PoisonError::into_inner).insert(service.vip, route);
            served.insert(service.name.clone(), service.clone());
        }
    }
}

/// Deletes stored certificates that have expired and are not the current
/// CA's certificate for a name still served: nothing can use those, for
/// serving or for renewal. A valid one stays, however long its name has
/// been unserved.
fn prune(store: &Store, settings: &wireserve_types::AcmeSettings, config: &TlsConfig) {
    let current = store::ca_id(&settings.directory);
    let wanted: BTreeSet<&str> = config.services.iter().map(|s| s.fqdn.as_str()).collect();
    match store.prune_expired(SystemTime::now(), |ca, fqdn| ca == current && wanted.contains(fqdn)) {
        Ok(removed) => {
            for (ca, fqdn) in removed {
                tracing::info!(fqdn = %fqdn, ca = %ca, "removed an expired certificate nothing needs");
            }
        }
        Err(e) => tracing::warn!(error = %e, "could not prune expired certificates"),
    }
}

/// Replaces the sign-in when the coordinator's settings changed — only then,
/// so the sessions renewed lately are still known after every check-in
/// that changed nothing.
fn update_sign_in(shared: &SharedSignIn, settings: Option<&wireserve_types::SignIn>, link: &Link) {
    let mut current = shared.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    if current.as_ref().map(|s| &s.settings) == settings {
        return;
    }
    *current = settings.and_then(|s| {
        let made = sign_in::SignIn::new(s.clone(), link.clone()).map(Arc::new);
        match &made {
            Some(_) => tracing::info!(login_url = %s.login_url, "sign-in"),
            None => tracing::warn!("the coordinator's sign-in key cannot be read; nobody gets in by signing in"),
        }
        made
    });
}

fn update_callers(callers: &Callers, config: &TlsConfig) {
    let map = config
        .callers
        .iter()
        .map(|c| (c.addr, serve::CallerInfo { node: c.node.clone() }))
        .collect();
    *callers.write().unwrap_or_else(std::sync::PoisonError::into_inner) = map;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn service(name: &str) -> TlsService {
        TlsService {
            name: name.into(),
            fqdn: format!("{name}.int.test"),
            vip: Ipv4Addr::new(100, 64, 0, 9),
            upstream: SocketAddr::from(([127, 0, 0, 1], 8080)),
            access: Default::default(),
            cross_site: false,
        }
    }

    #[test]
    fn an_unserved_name_forgets_its_certificate_so_serving_it_again_loads_from_disk() {
        let (chain, key) = store::tests::self_signed("plex.int.test", 36_500);
        let stored = store::parse(chain.as_bytes(), key.as_bytes()).unwrap();
        let certs = Certs::default();
        certs.set("plex.int.test", stored.key.clone());
        let shared = serve::Shared::default();
        let mut served = BTreeMap::from([("plex".to_string(), Served { service: service("plex"), routed: false, unclaimed: None })]);
        let mut issuance = BTreeMap::from([("plex.int.test".to_string(), Issuance { cert: Some(stored), ..Issuance::default() })]);

        forget_gone(&mut served, &mut issuance, &certs, &shared, &mut serve::Listening::Every, &TlsConfig::default());

        assert!(served.is_empty());
        assert!(issuance.is_empty(), "a held certificate the resolver lacks would never be loaded again");
    }

    #[test]
    fn a_name_still_wanted_keeps_its_state() {
        let (chain, key) = store::tests::self_signed("plex.int.test", 36_500);
        let stored = store::parse(chain.as_bytes(), key.as_bytes()).unwrap();
        let mut served = BTreeMap::from([("plex".to_string(), Served { service: service("plex"), routed: false, unclaimed: None })]);
        let mut issuance = BTreeMap::from([("plex.int.test".to_string(), Issuance { cert: Some(stored), ..Issuance::default() })]);
        let config = TlsConfig { services: vec![service("plex")], ..TlsConfig::default() };
        forget_gone(&mut served, &mut issuance, &Certs::default(), &serve::Shared::default(), &mut serve::Listening::Every, &config);
        assert_eq!((served.len(), issuance.len()), (1, 1));
    }

    #[test]
    fn a_certificate_that_cannot_be_stored_is_served_and_stored_later_without_ordering_again() {
        const CA: &str = "https://ca.test/dir";
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        // A file where the name's directory goes: no save can succeed.
        let ca_dir = dir.path().join("certs").join(store::ca_id(CA));
        std::fs::create_dir_all(&ca_dir).unwrap();
        std::fs::write(ca_dir.join("plex.int.test"), "").unwrap();
        let (chain, key) = store::tests::self_signed("plex.int.test", 36_500);
        let mut entry = Issuance::default();

        issued(&store, &Certs::default(), &mut entry, "plex.int.test", CA.into(), chain.clone(), key.clone());
        assert!(entry.cert.is_some(), "served from memory");
        assert!(entry.unsaved.is_some());
        assert!(entry.not_before.is_some_and(|t| t > Instant::now() + FIRST_BACKOFF / 2), "nothing is tried again at once");

        // Still backing off: not tried.
        save_again(&store, &mut entry, "plex.int.test");
        assert_eq!(entry.failures, 1);

        std::fs::remove_file(ca_dir.join("plex.int.test")).unwrap();
        entry.not_before = Some(Instant::now());
        save_again(&store, &mut entry, "plex.int.test");
        assert!(entry.unsaved.is_none());
        assert_eq!((entry.failures, entry.not_before), (0, None));
        let loaded = store.load(CA, "plex.int.test").unwrap().expect("stored at last");
        assert_eq!(Some(loaded.leaf), entry.cert.map(|c| c.leaf));
    }

    /// An agent on `socket` that answers every check-in with `config` and
    /// sends what the terminator said it serves to the returned channel.
    /// Unix only, as `serve`'s tests are: the stand-in agent is a Unix socket.
    #[cfg(unix)]
    fn fake_agent(socket: &std::path::Path, config: TlsConfig) -> tokio::sync::mpsc::UnboundedReceiver<Vec<String>> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use wireserve_types::tls::{TlsRequest, TlsResponse};
        let agent = tokio::net::UnixListener::bind(socket).unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (stream, _) = agent.accept().await.unwrap();
                let (read, mut write) = stream.into_split();
                let mut line = String::new();
                BufReader::new(read).read_line(&mut line).await.unwrap();
                let answer = match serde_json::from_str::<TlsRequest>(line.trim_end()).unwrap() {
                    TlsRequest::CheckIn { serving, .. } => {
                        let _ = tx.send(serving);
                        TlsResponse::Config(Box::new(config.clone()))
                    }
                    _ => TlsResponse::Error { message: "not in this test".into() },
                };
                let mut answer = serde_json::to_string(&answer).unwrap();
                answer.push('\n');
                let _ = write.write_all(answer.as_bytes()).await;
            }
        });
        rx
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn check_ins_go_on_while_the_ca_takes_connections_and_never_answers() {
        let dir = tempfile::tempdir().unwrap();
        // Bound and never accepted from: the kernel completes the TCP
        // handshake, and the TLS one then waits for ever.
        let ca = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let directory = format!("https://{}/dir", ca.local_addr().unwrap());
        // A held certificate, whose renewal time is asked of the CA, and a
        // name without one, which is issued.
        let state = dir.path().join("state");
        let (chain, key) = store::tests::self_signed("plex.int.test", 36_500);
        Store::open(&state).unwrap().save(&directory, "plex.int.test", &chain, &key).unwrap();
        let other = TlsService { vip: Ipv4Addr::new(100, 64, 0, 10), ..service("jelly") };
        let config = TlsConfig {
            acme: Some(wireserve_types::AcmeSettings { directory, email: None, propagation_secs: 0 }),
            services: vec![service("plex"), other],
            ..TlsConfig::default()
        };
        let socket = dir.path().join("tls.sock");
        let mut check_ins = fake_agent(&socket, config);

        let terminator = tokio::spawn(run(Options {
            socket,
            state_dir: state,
            ca_file: None,
            check_in_every: Duration::from_millis(20),
            port: 0,
        }));
        let mut serving = Vec::new();
        for n in 0..10 {
            serving = tokio::time::timeout(Duration::from_secs(5), check_ins.recv())
                .await
                .unwrap_or_else(|_| panic!("check-in {n} never came: the loop waits on the CA"))
                .unwrap();
        }
        assert_eq!(serving, vec!["plex".to_string()], "the held certificate is served meanwhile");
        terminator.abort();
        drop(ca);
    }
}
