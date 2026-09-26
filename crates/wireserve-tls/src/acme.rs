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
}

/// The ACME account, loaded or created once per CA.
pub struct Accounts {
    dir: PathBuf,
    ca_file: Option<PathBuf>,
}

impl Accounts {
    #[must_use]
    pub fn new(dir: &Path, ca_file: Option<PathBuf>) -> Self {
        Self { dir: dir.to_path_buf(), ca_file }
    }

    /// One account file per directory URL, so moving between staging and
    /// production — or to a private CA — never reuses the wrong account.
    fn path(&self, directory: &str) -> PathBuf {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        directory.hash(&mut h);
        self.dir.join(format!("account-{:016x}.json", h.finish()))
    }

    fn builder(&self) -> Result<instant_acme::AccountBuilder, AcmeError> {
        Ok(match &self.ca_file {
            Some(ca) => Account::builder_with_root(ca)?,
            None => Account::builder()?,
        })
    }

    pub async fn get(&self, settings: &AcmeSettings) -> Result<Account, AcmeError> {
        let path = self.path(&settings.directory);
        if let Ok(text) = std::fs::read_to_string(&path) {
            let creds: AccountCredentials =
                serde_json::from_str(&text).map_err(|e| AcmeError::Account(format!("{}: {e}", path.display())))?;
            return Ok(self.builder()?.from_credentials(creds).await?);
        }
        let contact = settings.email.as_ref().map(|e| format!("mailto:{e}"));
        let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, creds) = self
            .builder()?
            .create(
                &NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false },
                settings.directory.clone(),
                None,
            )
            .await?;
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
    let identifiers = [Identifier::Dns(fqdn.to_string())];
    let mut new_order = NewOrder::new(&identifiers);
    // Tells the CA which certificate this one replaces (ARI), which it may
    // exempt from rate limits. Only when the CA offers ARI at all.
    let replaced_id = replaces.and_then(|s| CertificateIdentifier::try_from(&s.leaf).ok());
    if let Some(id) = &replaced_id {
        new_order = new_order.replaces(id.clone());
    }
    let mut order = match account.new_order(&new_order).await {
        Ok(order) => order,
        // A CA without ARI refuses `replaces`; ask again without it.
        Err(instant_acme::Error::Unsupported(_)) if replaced_id.is_some() => {
            account.new_order(&NewOrder::new(&identifiers)).await?
        }
        Err(e) => return Err(e.into()),
    };

    let mut published: Vec<String> = Vec::new();
    let result = async {
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
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
            challenge.set_ready().await?;
        }
        let retries = RetryPolicy::new().timeout(Duration::from_secs(120));
        match order.poll_ready(&retries).await? {
            OrderStatus::Ready => {}
            other => return Err(AcmeError::Order(other)),
        }
        let key_pem = order.finalize().await?;
        let chain_pem = order.poll_certificate(&retries).await?;
        Ok((chain_pem, key_pem))
    }
    .await;

    // Withdrawn whatever happened, so no record outlives the order; the
    // coordinator would also expire it on its own.
    for value in published {
        if let Err(e) = link.challenge(fqdn, &value, false).await {
            tracing::warn!(fqdn, error = %e, "could not withdraw the challenge record; the coordinator will expire it");
        }
    }
    result
}

/// When to renew `stored`: inside the CA's suggested window when it gives
/// one (ARI), two thirds through its life otherwise.
pub async fn renewal_time(account: &Account, stored: &Stored) -> SystemTime {
    let fallback = stored.default_renewal();
    let Ok(id) = CertificateIdentifier::try_from(&stored.leaf) else {
        return fallback;
    };
    match account.renewal_info(&id).await {
        Ok((info, _)) => {
            let start: SystemTime = info.suggested_window.start.into();
            let end: SystemTime = info.suggested_window.end.into();
            // Somewhere in the window, so a fleet of terminators does not
            // renew in the same second.
            let span = end.duration_since(start).unwrap_or(Duration::ZERO);
            start + span.mul_f64(rand::random::<f64>())
        }
        Err(_) => fallback,
    }
}
