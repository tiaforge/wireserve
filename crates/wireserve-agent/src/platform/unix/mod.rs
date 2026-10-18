//! What every Unix shares (see [`crate::platform`]).

#[cfg(not(target_os = "linux"))]
pub mod claim;
pub mod fs;
pub mod install;
pub mod ipc;
pub mod lock;
pub mod net;
pub mod paths;
pub mod service;
