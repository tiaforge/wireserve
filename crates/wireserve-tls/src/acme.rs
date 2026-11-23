//! Getting a certificate for one service name (PLAN.md M33), with DNS-01.
//!
//! The key is generated here, in the terminator, and never leaves it. The
//! challenge record is published by the coordinator on this node's behalf,
//! through the agent, and only for this node's own names: the coordinator
//! holds the DNS credential, this process holds the key, and neither holds
//! both.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use wireserve_types::AcmeSettings;

use crate::link::Link;
use crate::store::Stored;

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error("publishing the challenge: {0}")]
    Challenge(#[from] crate::link::LinkError),
    #[error("the CA left the order {0:?}")]
    Order(OrderStatus),
    #[error("the CA refused the challenge for {0}")]
    Invalid(String),
    #[error("account: {0}")]
    Account(String),
    #[error("the CA did not answer in time: {0}")]
    TimedOut(&'static str),
}

/// How long one request to the CA may take. instant-acme's own client has
/// no timeout at all, and a CA that takes the connection and never answers
/// would hold the one issuance at a time for good. Let's Encrypt answers
/// in well under a second; finalizing can take a few.
const CA_CALL: Duration = Duration::from_secs(30);

/// How long polling the order may go on: the CA validates the challenge,
/// then signs the certificate.
const POLL: Duration = Duration::from_secs(120);

/// How long a whole issuance may take before it counts as failed: the wait
/// for the record to propagate, plus ample time for every request, the
/// coordinator's call to the DNS provider and both polls.
#[must_use]
pub fn deadline(settings: &AcmeSettings) -> Duration {
    Duration::from_secs(u64::from(settings.propagation_secs)) + Duration::from_secs(10 * 60)
}

/// One call to the CA, given at most `limit`.
async fn call<T>(what: &'static str, limit: Duration, fut: impl std::future::Future<Output = T>) -> Result<T, AcmeError> {
    tokio::time::timeout(limit, fut).await.map_err(|_| AcmeError::TimedOut(what))
}

/// The ACME account, loaded or created once per CA.
pub struct Accounts {
    dir: PathBuf,
    ca_file: Option<PathBuf>,
    /// Held while the account is loaded or created: renewal times and the
    /// issuance ask for it from tasks of their own, and two creating it at
    /// once would make two accounts.
    lock: tokio::sync::Mutex<()>,
}

impl Accounts {
    #[must_use]
    pub fn new(dir: &Path, ca_file: Option<PathBuf>) -> Self {
        Self { dir: dir.to_path_buf(), ca_file, lock: tokio::sync::Mutex::new(()) }
    }

    /// One account file per directory URL, so moving between staging and
    /// production — or to a private CA — never reuses the wrong account.
    fn path(&self, directory: &str) -> PathBuf {
        self.dir.join(format!("account-{}.json", crate::store::ca_id(directory)))
    }

    fn builder(&self) -> Result<instant_acme::AccountBuilder, AcmeError> {
        Ok(match &self.ca_file {
            Some(ca) => Account::builder_with_root(ca)?,
            None => Account::builder()?,
        })
    }

    pub async fn get(&self, settings: &AcmeSettings) -> Result<Account, AcmeError> {
        let _held = self.lock.lock().await;
        let path = self.path(&settings.directory);
        if let Ok(text) = std::fs::read_to_string(&path) {
            let creds: AccountCredentials =
                serde_json::from_str(&text).map_err(|e| AcmeError::Account(format!("{}: {e}", path.display())))?;
            return Ok(call("the directory", CA_CALL, self.builder()?.from_credentials(creds)).await??);
        }
        let contact = settings.email.as_ref().map(|e| format!("mailto:{e}"));
        let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
        let new = NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false };
        let (account, creds) =
            call("creating the account", CA_CALL, self.builder()?.create(&new, settings.directory.clone(), None)).await??;
        let text = serde_json::to_string(&creds).map_err(|e| AcmeError::Account(e.to_string()))?;
        write_private(&path, &text).map_err(|e| AcmeError::Account(format!("{}: {e}", path.display())))?;
        tracing::info!(directory = %settings.directory, "created an ACME account");
        Ok(account)
    }
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

/// Obtains a certificate for `fqdn`: returns the chain and key as PEM.
pub async fn issue(
    account: &Account,
    fqdn: &str,
    link: &Link,
    settings: &AcmeSettings,
    replaces: Option<&Stored>,
) -> Result<(String, String), AcmeError> {
    let deadline = tokio::time::Instant::now() + deadline(settings);
    let identifiers = [Identifier::Dns(fqdn.to_string())];
    let mut new_order = NewOrder::new(&identifiers);
    // Tells the CA which certificate this one replaces (ARI), which it may
    // exempt from rate limits. Only when the CA offers ARI at all.
    let replaced_id = replaces.and_then(|s| CertificateIdentifier::try_from(&s.leaf).ok());
    if let Some(id) = &replaced_id {
        new_order = new_order.replaces(id.clone());
    }
    let mut order = match call("the new order", CA_CALL, account.new_order(&new_order)).await? {
        Ok(order) => order,
        // A CA without ARI refuses `replaces`; ask again without it.
        Err(instant_acme::Error::Unsupported(what)) if replaced_id.is_some() => {
            tracing::info!(fqdn, "the CA offers no {what}; ordering without naming the certificate replaced");
            call("the new order", CA_CALL, account.new_order(&NewOrder::new(&identifiers))).await??
        }
        // A CA with ARI refuses `replaces` too, for a certificate that
        // already has a replacement order (RFC 9773 `alreadyReplaced`): one
        // finalized whose certificate never reached the disk. Asking with
        // it again would be refused forever while the old one expires.
        Err(e) if replaced_id.is_some() && order_without_replaces(&e) => {
            tracing::warn!(fqdn, error = %e, "the CA refused the order naming the certificate replaced; ordering without it");
            call("the new order", CA_CALL, account.new_order(&NewOrder::new(&identifiers))).await??
        }
        Err(e) => return Err(e.into()),
    };

    let mut published: Vec<String> = Vec::new();
    let result = async {
        let mut authorizations = order.authorizations();
        while let Some(authz) = call("an authorization", CA_CALL, authorizations.next()).await? {
            let mut authz = authz?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => return Err(AcmeError::Invalid(fqdn.to_string())),
            }
            let mut challenge =
                authz.challenge(ChallengeType::Dns01).ok_or_else(|| AcmeError::Invalid(fqdn.to_string()))?;
            let value = challenge.key_authorization().dns_value();
            link.challenge(fqdn, &value, true).await?;
            published.push(value);
            // The coordinator wrote the record to the provider; give it time
            // to reach every one of the zone's nameservers before the CA looks.
            tokio::time::sleep(Duration::from_secs(u64::from(settings.propagation_secs))).await;
            call("the challenge", CA_CALL, challenge.set_ready()).await??;
        }
        // The policy's timeout is checked between polls only; a poll that
        // never returns is bounded here.
        let retries = RetryPolicy::new().timeout(POLL);
        match call("the order", POLL + CA_CALL, order.poll_ready(&retries)).await?? {
            OrderStatus::Ready => {}
            other => return Err(AcmeError::Order(other)),
        }
        let key_pem = call("finalizing", CA_CALL, order.finalize()).await??;
        let chain_pem = call("the certificate", POLL + CA_CALL, order.poll_certificate(&retries)).await??;
        Ok((chain_pem, key_pem))
    };
    // Past it the attempt is a failure like any other: the backoff applies,
    // and the next name on the node gets its turn.
    let result = tokio::time::timeout_at(deadline, result).await.unwrap_or(Err(AcmeError::TimedOut("the whole issuance")));

    // Withdrawn whatever happened, so no record outlives the order; the
    // coordinator would also expire it on its own.
    for value in published {
        if let Err(e) = link.challenge(fqdn, &value, false).await {
            tracing::warn!(fqdn, error = %e, "could not withdraw the challenge record; the coordinator will expire it");
        }
    }
    result
}

/// Whether an order the CA refused while it named the certificate replaced
/// is asked for again without naming it: for anything the CA answered,
/// whatever it said, but not when it was never reached or did not answer —
/// that says nothing about `replaces`, and the next attempt sends it again.
fn order_without_replaces(e: &instant_acme::Error) -> bool {
    !unreachable(e)
}

/// Whether `e` means the CA was not reached or did not finish answering:
/// the connection failed, or broke on the way. instant-acme's client
/// reports both as `Other`, with an I/O or hyper error somewhere beneath.
fn unreachable(e: &instant_acme::Error) -> bool {
    match e {
        instant_acme::Error::Hyper(_) | instant_acme::Error::Timeout(_) => true,
        instant_acme::Error::Other(inner) => {
            let mut source: Option<&(dyn std::error::Error + 'static)> = Some(inner.as_ref());
            while let Some(e) = source {
                if e.is::<std::io::Error>() || e.is::<hyper::Error>() {
                    return true;
                }
                source = e.source();
            }
            false
        }
        _ => false,
    }
}

/// When to renew `stored`: inside the CA's suggested window when it gives
/// one (ARI), two thirds through its life otherwise.
pub async fn renewal_time(account: &Account, stored: &Stored) -> SystemTime {
    let fallback = stored.default_renewal();
    let Ok(id) = CertificateIdentifier::try_from(&stored.leaf) else {
        return fallback;
    };
    match call("renewal information", CA_CALL, account.renewal_info(&id)).await {
        Ok(Ok((info, _))) => {
            let start: SystemTime = info.suggested_window.start.into();
            let end: SystemTime = info.suggested_window.end.into();
            // Somewhere in the window, so a fleet of terminators does not
            // renew in the same second.
            let span = end.duration_since(start).unwrap_or(Duration::ZERO);
            start + span.mul_f64(rand::random::<f64>())
        }
        Ok(Err(_)) | Err(_) => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(json: serde_json::Value) -> instant_acme::Error {
        instant_acme::Error::Api(serde_json::from_value(json).unwrap())
    }

    #[test]
    fn a_certificate_already_replaced_is_ordered_again_without_replaces() {
        // What a CA with ARI answers for a certificate whose replacement
        // order was finalized but never stored (RFC 9773 §5).
        let refused = problem(serde_json::json!({
            "type": "urn:ietf:params:acme:error:alreadyReplaced",
            "detail": "certificate already has a replacement order",
            "status": 409,
        }));
        assert!(order_without_replaces(&refused));
        assert!(order_without_replaces(&problem(serde_json::json!({ "type": "urn:ietf:params:acme:error:malformed", "status": 400 }))));
        assert!(order_without_replaces(&instant_acme::Error::Unsupported("ACME renewal information (ARI)")));
        // A CA that ignored `replaces` in its answer.
        assert!(order_without_replaces(&instant_acme::Error::Other("replaces field mismatch".into())));
    }

    #[test]
    fn a_broken_connection_is_not_a_reason_to_drop_replaces() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        assert!(!order_without_replaces(&instant_acme::Error::Other(Box::new(io))));
        assert!(!order_without_replaces(&instant_acme::Error::Timeout(None)));
    }

    #[tokio::test]
    async fn a_ca_that_cannot_be_reached_is_not_a_reason_to_drop_replaces() {
        // The error instant-acme's own client gives for a refused
        // connection, which it buries in `Other`.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let new = NewAccount { contact: &[], terms_of_service_agreed: true, only_return_existing: false };
        let Err(e) = Account::builder().unwrap().create(&new, format!("https://127.0.0.1:{port}/dir"), None).await else {
            panic!("nothing listens there");
        };
        assert!(matches!(e, instant_acme::Error::Other(_)), "{e:?}");
        assert!(!order_without_replaces(&e), "{e:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_ca_that_takes_the_connection_and_never_answers_times_out() {
        // Bound and never accepted from: the TLS handshake waits for ever.
        let ca = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let accounts = Accounts::new(dir.path(), None);
        let settings = AcmeSettings { directory: format!("https://{}/dir", ca.local_addr().unwrap()), email: None, propagation_secs: 0 };
        let started = tokio::time::Instant::now();
        let e = accounts.get(&settings).await.err().expect("nothing answers");
        assert!(matches!(e, AcmeError::TimedOut(_)), "{e:?}");
        assert_eq!(started.elapsed(), CA_CALL);
        drop(ca);
    }

    #[test]
    fn an_issuance_has_a_deadline_past_the_propagation_wait() {
        let settings = AcmeSettings { directory: String::new(), email: None, propagation_secs: 120 };
        let deadline = deadline(&settings);
        // The wait, both polls, the other requests, and the agent's minute
        // for publishing the record.
        assert!(deadline > Duration::from_secs(120) + POLL * 2 + CA_CALL * 4 + Duration::from_secs(60), "{deadline:?}");
    }
}
