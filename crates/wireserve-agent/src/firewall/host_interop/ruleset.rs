//! Tolerant reader for `nft -j list ruleset`.
//!
//! Deliberately *not* the `nftables` crate's typed schema: that
//! deserializer fails the whole document on a single expression it does
//! not model, and the tables we read here belong to other tools
//! (crowdsec, firewalld, geoip-shell, iptables-nft's `xt` compat rules)
//! that use whatever nft supports. We only need a handful of fields, so
//! everything else is ignored and every object we don't understand is
//! skipped rather than fatal.
//!
//! Skipped *as the document is read*, which is what the streaming
//! [`Deserialize`] impls below are for. The three object kinds we keep —
//! table, chain, rule — are a small part of what `list ruleset` prints on
//! exactly the hosts this module exists for: crowdsec's blocklists and
//! geoip-shell's country sets are hundreds of thousands of set elements,
//! and a set element costs far more as a parsed `Value` than as JSON
//! text. Reading the document into `Vec<Value>` first and picking the
//! three kinds out of it afterwards, as this did, meant every reconcile —
//! one per poll tick, plus one per debounced `nft monitor` event — built
//! and dropped a `Value` tree some thirty to fifty times the size of the
//! ruleset. Dropping it does not give the memory back: those are millions
//! of small allocations that glibc keeps in its arenas, so the agent's RSS
//! stayed at the high-water mark for the life of the process. A node with
//! 4.4 MB of ruleset JSON sat at 215 MB, against 10-30 MB everywhere
//! else, from the first reconcile (which `HostInterop::start` runs
//! synchronously) onwards — which is why it looked like a leak that
//! restarting could not clear.

use std::fmt;

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::model::{ChainInfo, ChainRef, Family, NftView, RuleInfo, TableInfo};

#[derive(Debug, thiserror::Error)]
#[error("unreadable nft JSON: {0}")]
pub struct RulesetError(#[from] serde_json::Error);

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
    let Document(view) = serde_json::from_slice(json)?;
    Ok(view)
}

/// The kinds of object this reader keeps. Everything else nft can print —
/// `set`, `element`, `map`, `flowtable`, `counter`, `metainfo`, whatever a
/// later nft adds — is skipped without being parsed into anything.
#[derive(Clone, Copy)]
enum Kind {
    Table,
    Chain,
    Rule,
}

impl Kind {
    fn parse(key: &str) -> Option<Self> {
        match key {
            "table" => Some(Self::Table),
            "chain" => Some(Self::Chain),
            "rule" => Some(Self::Rule),
            _ => None,
        }
    }
}

/// One element of the `nftables` array: either one of our three kinds with
/// its body, or something to ignore.
///
/// The body is kept as a `Value` and converted below rather than
/// deserialized straight into `RawTable`/`RawChain`/`RawRule`, because a
/// shape we don't recognise has to be skippable — and a failed
/// `Deserialize` ends the whole document, where a failed `from_value` ends
/// one object. Only these three kinds are ever materialised, so the cost
/// is bounded by the rules on the host, not by its sets.
enum Object {
    Known(Kind, Value),
    Other,
}

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ObjectVisitor)
    }
}

struct ObjectVisitor;

impl<'de> Visitor<'de> for ObjectVisitor {
    type Value = Object;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an nft object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Object, A::Error> {
        let mut found = Object::Other;
        while let Some(key) = map.next_key::<String>()? {
            match Kind::parse(&key) {
                Some(kind) if matches!(found, Object::Other) => found = Object::Known(kind, map.next_value()?),
                // nft wraps exactly one object per element, so a second
                // key is nothing we know how to read; skip it as we skip
                // every other kind.
                _ => drop(map.next_value::<IgnoredAny>()?),
            }
        }
        Ok(found)
    }

    // nft's array holds objects and nothing else, but this reader treats a
    // document it does not recognise as something to skip rather than as a
    // failure, and that has to hold for the elements too.
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Object, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Object::Other)
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Object, E> {
        Ok(Object::Other)
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Object, E> {
        Ok(Object::Other)
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Object, E> {
        Ok(Object::Other)
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Object, E> {
        Ok(Object::Other)
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Object, E> {
        Ok(Object::Other)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Object, E> {
        Ok(Object::Other)
    }

    fn visit_none<E: de::Error>(self) -> Result<Object, E> {
        Ok(Object::Other)
    }
}

/// `{"nftables": [ ... ]}`, read into the view as it goes.
struct Document(NftView);

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(DocumentVisitor)
    }
}

struct DocumentVisitor;

impl<'de> Visitor<'de> for DocumentVisitor {
    type Value = Document;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an object with an `nftables` array")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Document, A::Error> {
        let mut view = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == "nftables" && view.is_none() {
                view = Some(map.next_value_seed(Objects)?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        view.map(Document).ok_or_else(|| de::Error::missing_field("nftables"))
    }
}

/// The `nftables` array itself: every element folded into one [`NftView`],
/// so no element outlives the step that reads it.
struct Objects;

impl<'de> DeserializeSeed<'de> for Objects {
    type Value = NftView;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<NftView, D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Objects {
    type Value = NftView;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an array of nft objects")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NftView, A::Error> {
        let mut view = NftView::default();
        while let Some(object) = seq.next_element::<Object>()? {
            let Object::Known(kind, body) = object else {
                continue;
            };
            add(&mut view, kind, body);
        }
        Ok(view)
    }
}

/// Folds one table, chain or rule into `view`. A body that is not the
/// shape its kind implies, or a family we don't handle, is dropped here —
/// the tolerance the module doc promises.
fn add(view: &mut NftView, kind: Kind, body: Value) {
    match kind {
        Kind::Table => {
            if let Ok(t) = serde_json::from_value::<RawTable>(body) {
                if let Some(family) = Family::parse(&t.family) {
                    view.tables.push(TableInfo {
                        family,
                        name: t.name,
                        flags: t.flags.into_vec(),
                    });
                }
            }
        }
        Kind::Chain => {
            if let Ok(c) = serde_json::from_value::<RawChain>(body) {
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
        }
        Kind::Rule => {
            let Ok(r) = serde_json::from_value::<RawRule>(body) else {
                return;
            };
            let Some(family) = Family::parse(&r.family) else {
                return;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_alloc::allocated;
    use std::fmt::Write as _;

    /// A `nft -j list ruleset` document shaped like the hosts this reader
    /// exists for: one big geoip-shell/crowdsec-style set, a handful of
    /// rules. `elements` is what used to decide the agent's memory.
    fn ruleset_json(elements: usize) -> Vec<u8> {
        let mut s = String::from(r#"{"nftables":[{"metainfo":{"version":"1.1.6"}},"#);
        s.push_str(r#"{"table":{"family":"inet","name":"geoip-shell","handle":1}},"#);
        s.push_str(r#"{"set":{"family":"inet","name":"allow","table":"geoip-shell","type":"ipv4_addr","handle":2,"flags":["interval"],"elem":["#);
        for i in 0..elements {
            if i > 0 {
                s.push(',');
            }
            let (a, b, c) = ((i >> 16) as u8, (i >> 8) as u8, i as u8);
            write!(s, r#"{{"prefix":{{"addr":"{a}.{b}.{c}.0","len":24}}}}"#).unwrap();
        }
        s.push_str(r#"]}},{"chain":{"family":"inet","table":"geoip-shell","name":"input","handle":3,"type":"filter","hook":"input","prio":-141,"policy":"accept"}},"#);
        s.push_str(r#"{"rule":{"family":"inet","table":"geoip-shell","chain":"input","handle":4,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"accept":null}]}}]}"#);
        s.into_bytes()
    }

    /// The bug this reader's streaming shape exists to prevent: reading the
    /// document into `Vec<Value>` first allocated tens of times the
    /// ruleset's size for set elements that are then thrown away, and
    /// glibc kept every byte of it for the life of the agent (module doc).
    /// A quarter of the input is a generous bound — before this, the same
    /// document cost about forty times it.
    #[test]
    fn set_elements_cost_nothing_to_skip() {
        let json = ruleset_json(50_000);
        let mut view = None;
        let used = allocated(|| view = Some(parse(&json).expect("parses")));
        let view = view.unwrap();
        assert_eq!(view.chains[0].rules.len(), 1, "the rule after the set is still read");
        assert!(
            used < json.len() / 4,
            "parsing {} KB of ruleset allocated {} KB — set elements are being materialised again",
            json.len() / 1024,
            used / 1024
        );
    }

    /// What the reader keeps is unchanged by how much it skips.
    #[test]
    fn a_huge_set_changes_nothing_about_the_view() {
        assert_eq!(parse(&ruleset_json(0)).unwrap(), parse(&ruleset_json(20_000)).unwrap());
    }

    /// nft emits one object per element, but this reader has always
    /// treated anything it doesn't recognise as something to skip rather
    /// than as a failure — that has to hold for elements that aren't
    /// objects at all, and for objects carrying more than one key.
    #[test]
    fn elements_that_are_not_objects_are_skipped_not_fatal() {
        let json = br#"{"metainfo": {"x": 1}, "nftables": [
            "a string", 7, 1.5, true, null, ["nested", "array"],
            {"table": {"family": "inet", "name": "t", "handle": 1}, "extra": {"junk": [1, 2]}},
            {"element": {"elem": "1.2.3.4"}}
        ]}"#;
        let view = parse(json).expect("parses");
        assert_eq!(view.tables.len(), 1);
        assert_eq!(view.tables[0].name, "t");
    }

    #[test]
    fn a_document_without_an_nftables_array_is_an_error() {
        assert!(parse(br#"{"something-else": []}"#).is_err());
        assert!(parse(b"[]").is_err());
        assert!(parse(b"not json").is_err());
    }
}
