//! What differs between operating systems for the terminator, as the
//! agent's `platform` is for the agent: the link to the agent, the
//! listening sockets, and private files. Both offer the same functions;
//! this is the one module that chooses.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;
