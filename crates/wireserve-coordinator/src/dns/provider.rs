//! Writing records through the configured provider (PLAN.md M32).
//!
//! [`DnsWriter`] is a trait only so the sync loop has a fake to test
//! against, the same reason the agent's `ProxyBackend` is one; there is one
//! real implementation, over `dns-update`.

use std::future::Future;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::time::Duration;

use dns_update::{DnsRecord, DnsRecordType, DnsUpdater};

use super::config::{tsig_algorithm, DnsConfig, DnsProvider};

pub type WriteResult = Result<(), String>;
pub type WriteFuture<'a> = Pin<Box<dyn Future<Output = WriteResult> + Send + 'a>>;
pub type ReadFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;

/// Every provider call gives up after this. The sync loop retries on its
/// next pass, so a hung API costs one pass, never the loop.
const TIMEOUT: Duration = Duration::from_secs(30);

pub trait DnsWriter: Send + Sync {
    /// What the zone holds at `fqdn` for the record types a service name
    /// would collide with (A, AAAA, CNAME), as `TYPE value` lines, asked of
    /// the provider itself, not a resolver with a cache. Empty for a name
    /// nothing is at. The sync loop asks before it first writes a name, so a
    /// record somebody else put there is never overwritten (and, when the
    /// service is withdrawn, deleted). A writer that cannot read says nothing
    /// is there.
    fn existing<'a>(&'a self, _fqdn: &'a str) -> ReadFuture<'a> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Makes `fqdn` resolve to exactly `addr`, replacing whatever A records
    /// the name held.
    fn set_a<'a>(&'a self, fqdn: &'a str, addr: Ipv4Addr) -> WriteFuture<'a>;
    /// Removes every A record at `fqdn`.
    fn delete_a<'a>(&'a self, fqdn: &'a str) -> WriteFuture<'a>;
    /// Adds one TXT value at `fqdn`, leaving any others in place.
    fn add_txt<'a>(&'a self, fqdn: &'a str, value: &'a str) -> WriteFuture<'a>;
    /// Removes one TXT value at `fqdn`, leaving any others in place.
    fn remove_txt<'a>(&'a self, fqdn: &'a str, value: &'a str) -> WriteFuture<'a>;
}

/// The real writer.
pub struct Provider {
    updater: DnsUpdater,
    zone: String,
    ttl: u32,
}

impl Provider {
    /// Builds the client for the configured provider. Fails only on
    /// settings the provider library itself rejects; nothing is contacted
    /// yet.
    pub fn connect(cfg: &DnsConfig) -> Result<Self, String> {
        let t = Some(TIMEOUT);
        let updater = match &cfg.provider {
            DnsProvider::Rfc2136 { server, key_name, secret, algorithm } => {
                DnsUpdater::new_rfc2136_tsig(server.as_str(), key_name, secret.clone(), tsig_algorithm(algorithm))
            }
            DnsProvider::Cloudflare { token } => DnsUpdater::new_cloudflare(token, t),
            DnsProvider::Desec { token } => DnsUpdater::new_desec(token, t),
            DnsProvider::Hetzner { token } => DnsUpdater::new_hetzner(token, t),
            DnsProvider::Porkbun { api_key, secret } => DnsUpdater::new_porkbun(api_key, secret, t),
        }
        .map_err(|e| format!("{} DNS provider: {e}", cfg.provider.name()))?;
        Ok(Self { updater, zone: cfg.zone.clone(), ttl: cfg.ttl })
    }
}

fn describe(e: dns_update::Error) -> String {
    e.to_string()
}

impl DnsWriter for Provider {
    fn existing<'a>(&'a self, fqdn: &'a str) -> ReadFuture<'a> {
        Box::pin(async move {
            let mut found = Vec::new();
            for kind in [DnsRecordType::A, DnsRecordType::AAAA, DnsRecordType::CNAME] {
                let records = self.updater.list_rrset(fqdn, kind, self.zone.as_str()).await.map_err(describe)?;
                for record in records {
                    match record {
                        DnsRecord::A(a) => found.push(format!("A {a}")),
                        DnsRecord::AAAA(a) => found.push(format!("AAAA {a}")),
                        DnsRecord::CNAME(t) => found.push(format!("CNAME {t}")),
                        _ => {}
                    }
                }
            }
            Ok(found)
        })
    }

    fn set_a<'a>(&'a self, fqdn: &'a str, addr: Ipv4Addr) -> WriteFuture<'a> {
        Box::pin(async move {
            self.updater
                .set_rrset(fqdn, DnsRecordType::A, self.ttl, vec![DnsRecord::A(addr)], self.zone.as_str())
                .await
                .map_err(describe)
        })
    }

    fn delete_a<'a>(&'a self, fqdn: &'a str) -> WriteFuture<'a> {
        Box::pin(async move {
            self.updater
                .set_rrset(fqdn, DnsRecordType::A, self.ttl, Vec::new(), self.zone.as_str())
                .await
                .map_err(describe)
        })
    }

    fn add_txt<'a>(&'a self, fqdn: &'a str, value: &'a str) -> WriteFuture<'a> {
        Box::pin(async move {
            self.updater
                .add_to_rrset(fqdn, DnsRecordType::TXT, self.ttl, vec![DnsRecord::TXT(value.to_string())], self.zone.as_str())
                .await
                .map_err(describe)
        })
    }

    fn remove_txt<'a>(&'a self, fqdn: &'a str, value: &'a str) -> WriteFuture<'a> {
        Box::pin(async move {
            self.updater
                .remove_from_rrset(fqdn, DnsRecordType::TXT, vec![DnsRecord::TXT(value.to_string())], self.zone.as_str())
                .await
                .map_err(describe)
        })
    }
}
