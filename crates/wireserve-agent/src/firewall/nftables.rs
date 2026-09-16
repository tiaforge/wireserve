//! Linux v1 `FirewallBackend` — nftables via netlink (`rustables`), no
//! shelling out to `nft` (spec §5). Feature-gated behind `nftables`
//! (default-on) because `rustables` needs `clang`/`libclang` at build time;
//! see Cargo.toml and PLAN.md decisions log.

use rustables::{
    Batch, Chain, ChainPolicy, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule, Table,
};
use wireserve_types::{FirewallBackend, Proto, ServiceRule};

const TABLE_NAME: &str = "wireserve";
const CHAIN_NAME: &str = "wireserve-in";

#[derive(Debug, thiserror::Error)]
pub enum NftablesError {
    #[error("nftables rule build error: {0}")]
    Build(#[from] rustables::error::BuilderError),
    #[error("nftables query error: {0}")]
    Query(#[from] rustables::error::QueryError),
}

pub struct NftablesBackend {
    /// The WireGuard interface every rule is scoped to — this backend must
    /// never install a rule that isn't `iiface`-restricted to it, or it
    /// would be firewalling the whole host rather than just the mesh.
    ifname: String,
}

impl NftablesBackend {
    #[must_use]
    pub fn new(ifname: impl Into<String>) -> Self {
        Self {
            ifname: ifname.into(),
        }
    }

    fn existing_table() -> Result<Option<Table>, NftablesError> {
        let tables = rustables::list_tables()?;
        Ok(tables
            .into_iter()
            .find(|t| t.get_name().is_some_and(|n| n == TABLE_NAME)))
    }

    /// Queues "delete the existing table, if any" onto `batch` — the same
    /// add-then-del pattern `rustables`' own examples use to remove a table
    /// that must already exist for a `Del` message to be valid.
    fn queue_delete_existing(batch: &mut Batch) -> Result<(), NftablesError> {
        if let Some(existing) = Self::existing_table()? {
            batch.add(&existing, MsgType::Add);
            batch.add(&existing, MsgType::Del);
        }
        Ok(())
    }

    fn to_protocol(proto: Proto) -> Protocol {
        match proto {
            Proto::Tcp => Protocol::TCP,
            Proto::Udp => Protocol::UDP,
        }
    }
}

impl FirewallBackend for NftablesBackend {
    type Error = NftablesError;

    /// Full-replace: one atomic batch that (if a previous `wireserve` table
    /// exists) deletes it and recreates the table/chain/rules from
    /// scratch — never a window where the old and new rulesets are both
    /// partially applied.
    fn apply(&mut self, rules: &[ServiceRule]) -> Result<(), Self::Error> {
        let mut batch = Batch::new();
        Self::queue_delete_existing(&mut batch)?;

        let table = Table::new(ProtocolFamily::Inet).with_name(TABLE_NAME);
        batch.add(&table, MsgType::Add);

        let chain = Chain::new(&table)
            .with_name(CHAIN_NAME)
            .with_hook(Hook::new(HookClass::In, 0))
            .with_policy(ChainPolicy::Drop)
            .add_to_batch(&mut batch);

        for rule in rules {
            Rule::new(&chain)?
                .iiface(&self.ifname)?
                .dport(rule.port, Self::to_protocol(rule.proto))
                .accept()
                .add_to_batch(&mut batch);
        }

        batch.send()?;
        Ok(())
    }

    /// Removes the `wireserve` table entirely, if present. No-op if it was
    /// never created (e.g. a fresh install where `apply` was never called).
    fn teardown(&mut self) -> Result<(), Self::Error> {
        let mut batch = Batch::new();
        Self::queue_delete_existing(&mut batch)?;
        batch.send()?;
        Ok(())
    }
}
