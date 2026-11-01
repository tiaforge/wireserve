//! Phones reach every node through one carrier, on the carrier's own
//! WireGuard port (PLAN.md M49).
//!
//! The kernel's WireGuard keeps the port. The firewall diverts to the agent
//! only what may be another node's — every handshake initiation, and the
//! packets of sessions a relayed node answered — and the agent sends each
//! one on to its node over the mesh, or back to the kernel as it came.
//! Nothing is decrypted: the carrier holds no key to any of these sessions.

#[cfg(target_os = "linux")]
pub mod io;
pub mod packet;
pub mod sorter;
