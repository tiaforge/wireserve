//! Tolerant reader for `nft -j list ruleset`.
//!
//! Deliberately *not* the `nftables` crate's typed schema: that
//! deserializer fails the whole document on a single expression it does
//! not model, and the tables we read here belong to other tools
//! (crowdsec, firewalld, geoip-shell, iptables-nft's `xt` compat rules)
//! that use whatever nft supports. We only need a handful of fields, so
//! everything else is ignored and every object we don't understand is
//! skipped rather than fatal.

use serde::Deserialize;
use serde_json::Value;

use super::model::{ChainInfo, ChainRef, Family, NftView, RuleInfo, TableInfo};

#[derive(Debug, thiserror::Error)]
#[error("unreadable nft JSON: {0}")]
pub struct RulesetError(#[from] serde_json::Error);

#[derive(Deserialize)]
struct Document {
    nftables: Vec<Value>,
}

#[derive(Deserialize)]
struct RawTable {
    family: String,
    name: String,
    #[serde(default)]
    flags: Flags,
}

/// nft renders `flags` as a string for one flag and an array for several.
#[derive(Deserialize, Default)]
#[serde(untagged)]
enum Flags {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Flags {
    fn into_vec(self) -> Vec<String> {
        match self {
            Flags::None => vec![],
            Flags::One(f) => vec![f],
            Flags::Many(f) => f,
        }
    }
}

#[derive(Deserialize)]
struct RawChain {
    family: String,
    table: String,
    name: String,
    #[serde(rename = "type")]
    chain_type: Option<String>,
    hook: Option<String>,
}

#[derive(Deserialize)]
struct RawRule {
    family: String,
    table: String,
    chain: String,
    handle: u64,
    comment: Option<String>,
    #[serde(default)]
    expr: Vec<Value>,
}

/// Parses `nft -j list ruleset` output. Only a malformed document (not an
/// object with an `nftables` array) is an error; objects of other kinds,
/// other families, or unexpected shapes are skipped.
pub fn parse(json: &[u8]) -> Result<NftView, RulesetError> {
    let doc: Document = serde_json::from_slice(json)?;
    let mut view = NftView::default();
    for object in doc.nftables {
        let Value::Object(mut map) = object else {
            continue;
        };
        if let Some(t) = map.remove("table") {
            if let Ok(t) = serde_json::from_value::<RawTable>(t) {
                if let Some(family) = Family::parse(&t.family) {
                    view.tables.push(TableInfo {
                        family,
                        name: t.name,
                        flags: t.flags.into_vec(),
                    });
                }
            }
        } else if let Some(c) = map.remove("chain") {
            if let Ok(c) = serde_json::from_value::<RawChain>(c) {
                if let Some(family) = Family::parse(&c.family) {
                    view.chains.push(ChainInfo {
                        chain: ChainRef {
                            family,
                            table: c.table,
                            chain: c.name,
                        },
                        hook: c.hook,
                        chain_type: c.chain_type,
                        rules: vec![],
                    });
                }
            }
        } else if let Some(r) = map.remove("rule") {
            let Ok(r) = serde_json::from_value::<RawRule>(r) else {
                continue;
            };
            let Some(family) = Family::parse(&r.family) else {
                continue;
            };
            // nft lists a chain before its rules, in rule order.
            let chain = view.chains.iter_mut().find(|c| {
                c.chain.family == family && c.chain.table == r.table && c.chain.chain == r.chain
            });
            if let Some(chain) = chain {
                chain.rules.push(RuleInfo {
                    handle: r.handle,
                    comment: r.comment,
                    expr: r.expr,
                });
            }
        }
    }
    Ok(view)
}
