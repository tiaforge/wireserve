use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::rate_limit::{RateLimiter, TokenBuckets};
use crate::transit::TransitState;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Db>,
    pub config: Arc<Config>,
    pub rate_limiter: Arc<RateLimiter>,
    /// What one authenticated node may ask of `/poll`, per node.
    pub poll_limiter: Arc<TokenBuckets>,
    /// What one node may ask of `/reach`, per node: apart from the poll's
    /// allowance, so that a `status` is not refused because the polls used it
    /// up, and a loop of `status` does not use up the polls'.
    pub reach_limiter: Arc<TokenBuckets>,
    /// What one node may ask of `/tls/challenge` — each new value is a call
    /// to the operator's DNS provider — per node.
    pub challenge_limiter: Arc<TokenBuckets>,
    /// What one node may ask of the sign-in's renew and end calls, per node
    /// (PLAN.md M48).
    pub sign_in_limiter: Arc<TokenBuckets>,
    /// What one node may redeem, per node, apart from renewals: anyone on
    /// the mesh can make a terminator try a ticket, and that must not cost
    /// the people already signed in their renewals (PLAN.md #312).
    pub redeem_limiter: Arc<TokenBuckets>,
    /// How often one address may start a sign-in at `/sign-in`, which needs
    /// no credential (PLAN.md #312).
    pub sign_in_start_limiter: Arc<crate::rate_limit::SlidingWindowLimiter>,
    /// Ephemeral transit-selection state (PLAN.md M23) — see
    /// `transit::TransitState`'s module doc for why this lives in memory
    /// rather than the database.
    pub transit: Arc<TransitState>,
    /// The public DNS sync (PLAN.md M32), when a provider is configured.
    pub dns: Option<Arc<crate::dns::Dns>>,
    /// Device owners through the identity provider (PLAN.md M38), when one
    /// is configured.
    pub oidc: Option<Arc<crate::oidc::Oidc>>,
    /// Which `(node, device's node)` pairs have had a device owner's
    /// identity named to the node since this process started — so that the
    /// first time is logged, and only the first.
    pub released: Arc<std::sync::Mutex<std::collections::HashSet<(i64, i64)>>>,
    /// A UDP socket on a port of its own (PLAN.md M40), which nothing ever
    /// sent to: the reflexive responder answers from it a second time, and
    /// port checks are sent from it, so what arrives from it was let in
    /// unasked. `None` where it could not be bound.
    pub probe_udp: Option<Arc<std::net::UdpSocket>>,
    /// What `/poll` reads of the mesh, shared between polls.
    pub directory: Arc<crate::directory_state::DirectoryCache>,
    /// How many whole directories may be on their way to nodes at once.
    pub full_directory_limit: Arc<tokio::sync::Semaphore>,
    /// How many responses may be worked out at once, on threads of their own
    /// ([`response_builds`]).
    pub response_builds: Arc<tokio::sync::Semaphore>,
}

/// More than this many whole directories on their way at once (from the
/// moment one is asked for to the last of it sent) and the rest are told to
/// come back. They share their buffers, so what each costs is what the
/// connection holds, and what the node at the other end must hold to read it.
pub const FULL_DIRECTORIES_IN_FLIGHT: usize = 32;

/// How many `/poll` and `/reach` responses may be built at once: twice the
/// cores, at least four. The rest wait as tasks, which cost next to nothing,
/// rather than as threads of their own; a moment's stall in the directory
/// otherwise parked a thread per poll that arrived during it, hundreds of them
/// at 20,000 nodes, each with memory the allocator keeps.
#[must_use]
pub fn response_builds() -> usize {
    std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get).saturating_mul(2).max(4)
}

impl AppState {
    /// How the directory is shaped from this coordinator's settings.
    #[must_use]
    pub fn directory_context<'a>(
        &'a self,
        tls_ready: &'a std::collections::HashMap<String, i64>,
    ) -> crate::directory::DirectoryContext<'a> {
        crate::directory::DirectoryContext {
            tls_ready,
            dns: self.dns.is_some(),
            online_threshold_secs: self.config.online_threshold_secs,
        }
    }

    /// Whether this is the first time `to` is told who owns `device`'s node.
    #[must_use]
    pub fn first_release(&self, to: i64, device: i64) -> bool {
        self.released.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert((to, device))
    }

    /// Tells `/poll` the nodes, services or rules it shares between polls may
    /// have changed, so the next one reads them again. Call it after the write.
    pub fn directory_changed(&self) {
        self.directory.changed();
    }

    /// Tells the DNS sync the directory may have changed. Cheap and safe to
    /// call from any handler: pokes coalesce, and the loop spaces its passes.
    pub fn poke_dns(&self) {
        if let Some(dns) = &self.dns {
            dns.wake.notify_one();
        }
    }
}
