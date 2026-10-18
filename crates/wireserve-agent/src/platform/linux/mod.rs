//! What only Linux has (see [`crate::platform`]).

pub mod capabilities;
pub mod claim;
pub mod firewall;
pub mod forwarding;
pub mod host_addresses;
pub mod host_interop;
#[cfg(test)]
pub mod netns;
pub mod nft;
pub mod nftables;
pub mod routes;
pub mod wg;
