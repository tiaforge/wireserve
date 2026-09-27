//! The per-node TLS terminator (PLAN.md M33): `wireserve tls-serve`.
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

pub mod acme;
pub mod link;
pub mod serve;
pub mod sign_in;
pub mod store;

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
    /// Another CA to trust for the sign-in check, besides the public roots —
    /// a test CA such as Pebble's issuing root. Never needed otherwise.
    pub trust_file: Option<PathBuf>,
    pub check_in_every: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("state directory: {0}")]
    State(std::io::Error),
}

/// The first retry after a failed issuance; doubled each time, up to
/// [`MAX_BACKOFF`]. Let's Encrypt allows five failed validations per name
/// per hour, so hammering it would lock the name out for longer.
const FIRST_BACKOFF: Duration = Duration::from_secs(120);
const MAX_BACKOFF: Duration = Duration::from_secs(6 * 3600);

/// One served service.
struct Served {
    service: TlsService,
    listener: Option<JoinHandle<()>>,
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
    failures: u32,
    not_before: Option<Instant>,
}

/// Runs until the process is stopped.
pub async fn run(opts: Options) -> Result<(), Error> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let store = Store::open(&opts.state_dir).map_err(Error::State)?;
    let accounts = acme::Accounts::new(store.root(), opts.ca_file.clone());
    let link = Link::new(&opts.socket);
    let certs = Arc::new(Certs::default());
    let tls = serve::server_config(certs.clone());
    let callers: Callers = Arc::default();
    let sign_in: SharedSignIn = Arc::default();
    let extra_roots: Vec<rustls_pki_types::CertificateDer<'static>> = match &opts.trust_file {
        None => Vec::new(),
        Some(path) => {
            use rustls_pki_types::pem::PemObject;
            let pem = std::fs::read(path).map_err(Error::State)?;
            rustls_pki_types::CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok).collect()
        }
    };

    let mut served: BTreeMap<String, Served> = BTreeMap::new();
    let mut issuance: BTreeMap<String, Issuance> = BTreeMap::new();
    // One issuance at a time: a node with many services staggers them
    // rather than asking the CA for all at once.
    let mut in_flight: Option<InFlight> = None;

    tracing::info!(socket = %link.socket().display(), "TLS terminator starting");
    let mut tick = tokio::time::interval(opts.check_in_every);
    loop {
        tick.tick().await;

        // What is served right now: a certificate held, and a listener up.
        let serving: Vec<String> = served
            .values()
            .filter(|s| s.listener.as_ref().is_some_and(|l| !l.is_finished()))
            .filter(|s| issuance.get(&s.service.fqdn).and_then(|i| i.cert.as_ref()).is_some_and(|c| c.valid_at(SystemTime::now())))
            .map(|s| s.service.name.clone())
            .collect();
        let config = match link.check_in(serving).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "could not check in with the agent; keeping what is served");
                continue;
            }
        };
        update_callers(&callers, &config);
        update_sign_in(&sign_in, config.sign_in.as_ref(), &extra_roots);

        // Services that are gone: stop serving them.
        let wanted: BTreeSet<&str> = config.services.iter().map(|s| s.name.as_str()).collect();
        served.retain(|name, s| {
            let keep = wanted.contains(name.as_str());
            if !keep {
                tracing::info!(service = %name, "no longer serving");
                if let Some(l) = s.listener.take() {
                    l.abort();
                }
                certs.remove(&s.service.fqdn);
            }
            keep
        });

        let Some(settings) = config.acme.clone() else {
            continue;
        };

        // A finished issuance.
        if in_flight.as_ref().is_some_and(|(_, _, h)| h.is_finished()) {
            let (fqdn, directory, handle) = in_flight.take().expect("checked above");
            let entry = issuance.entry(fqdn.clone()).or_default();
            match handle.await {
                Ok(Ok((chain, key))) => match store.save(&directory, &fqdn, &chain, &key) {
                    Ok(stored) => {
                        tracing::info!(fqdn = %fqdn, ca = %directory, "certificate issued");
                        certs.set(&fqdn, stored.key.clone());
                        entry.renew_at = None;
                        entry.cert = Some(stored);
                        entry.ca = Some(directory);
                        entry.failures = 0;
                        entry.not_before = None;
                    }
                    Err(e) => tracing::error!(fqdn = %fqdn, error = %e, "could not store the issued certificate"),
                },
                Ok(Err(e)) => {
                    entry.failures += 1;
                    let wait = (FIRST_BACKOFF * 2u32.saturating_pow(entry.failures - 1)).min(MAX_BACKOFF);
                    entry.not_before = Some(Instant::now() + wait);
                    tracing::warn!(fqdn = %fqdn, error = %e, retry_in = ?wait, "certificate issuance failed");
                }
                Err(e) => tracing::error!(fqdn = %fqdn, error = %e, "issuance task failed"),
            }
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
                        entry.cert = Some(stored);
                        entry.ca = Some(settings.directory.clone());
                        entry.renew_at = None;
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(fqdn = %service.fqdn, error = %e, "stored certificate unreadable; getting a new one"),
                }
            }

            // Listening as soon as there is a certificate to answer with.
            let s = served.entry(service.name.clone()).or_insert_with(|| Served { service: service.clone(), listener: None });
            if s.service != *service {
                if let Some(l) = s.listener.take() {
                    // Aborting only schedules the cancellation; until the
                    // task is dropped its socket still holds the address,
                    // and binding it again below would fail.
                    l.abort();
                    let _ = l.await;
                }
                s.service = service.clone();
            }
            let dead = s.listener.as_ref().is_none_or(JoinHandle::is_finished);
            if entry.cert.is_some() && dead {
                match serve::bind(service.vip) {
                    Ok(listener) => {
                        tracing::info!(service = %service.name, addr = %service.vip, upstream = %service.upstream, "serving");
                        let policy = serve::Policy { marked: service.sign_in, fqdn: service.fqdn.clone() };
                        s.listener = Some(serve::spawn(
                            listener,
                            tls.clone(),
                            service.upstream,
                            callers.clone(),
                            sign_in.clone(),
                            policy,
                        ));
                    }
                    // Another listener on 0.0.0.0:443, most likely: this
                    // service is simply not served here, and keeps the path
                    // it had.
                    Err(e) => tracing::warn!(service = %service.name, addr = %service.vip, error = %e, "cannot listen"),
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
                        entry.renew_at = Some(match accounts.get(&settings).await {
                            Ok(account) => acme::renewal_time(&account, cert).await,
                            Err(_) => cert.default_renewal(),
                        });
                    }
                    entry.renew_at.is_some_and(|t| SystemTime::now() >= t)
                }
            };
            if due {
                let account = match accounts.get(&settings).await {
                    Ok(a) => a,
                    Err(e) => {
                        entry.failures += 1;
                        entry.not_before = Some(Instant::now() + FIRST_BACKOFF);
                        tracing::warn!(error = %e, "no ACME account");
                        continue;
                    }
                };
                tracing::info!(
                    fqdn = %service.fqdn,
                    renewal = entry.cert.is_some() && !replacing,
                    ca = %settings.directory,
                    "requesting a certificate"
                );
                // Renewal information only names a certificate of the same CA.
                let replaces = if replacing { None } else { entry.cert.clone() };
                let (fqdn, link, settings) = (service.fqdn.clone(), link.clone(), settings.clone());
                let name = fqdn.clone();
                in_flight = Some((
                    name,
                    settings.directory.clone(),
                    tokio::spawn(async move { acme::issue(&account, &fqdn, &link, &settings, replaces.as_ref()).await }),
                ));
            }
        }
    }
}

/// Replaces the sign-in client when the provider moved — only then, so its
/// connection pool survives every check-in that changed nothing.
fn update_sign_in(shared: &SharedSignIn, target: Option<&wireserve_types::tls::SignInTarget>, extra_roots: &[rustls_pki_types::CertificateDer<'static>]) {
    let mut current = shared.write().unwrap_or_else(std::sync::PoisonError::into_inner);
    if current.as_ref().map(|s| &s.target) == target {
        return;
    }
    *current = target.map(|t| {
        tracing::info!(provider = %t.fqdn, addr = %t.vip, "sign-in provider");
        sign_in::SignIn::new(t.clone(), extra_roots)
    });
}

fn update_callers(callers: &Callers, config: &TlsConfig) {
    let map = config.callers.iter().map(|c| (c.addr, c.node.clone())).collect();
    *callers.write().unwrap_or_else(std::sync::PoisonError::into_inner) = map;
}
