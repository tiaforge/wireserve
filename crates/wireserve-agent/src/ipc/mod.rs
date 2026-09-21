pub mod client;
pub mod protocol;
pub mod render;
pub mod server;

pub use protocol::{IpcRequest, IpcResponse};
pub use server::AgentContext;
