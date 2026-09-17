pub mod client;
pub mod config;
pub mod export_config;

use client::{AdminClient, ClientError};
use wireserve_types::{
    is_valid_dns_label, AdminPeersResponse, CreateNodeResponse, NodeKind, RejoinResponse,
};

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(
        "invalid name '{0}': must be lowercase alphanumeric/hyphen, 1-63 chars, \
         not starting/ending with a hyphen"
    )]
    InvalidName(String),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    ExportConfig(#[from] export_config::ExportConfigError),
}

/// Spec §3: "fail fast, don't round trip to the server for an obvious
/// violation." Every subcommand that takes a `name` argument runs it
/// through this before making any network call.
fn validate_name(name: &str) -> Result<(), CliError> {
    if is_valid_dns_label(name) {
        Ok(())
    } else {
        Err(CliError::InvalidName(name.to_string()))
    }
}

pub fn cmd_create_node(
    client: &AdminClient,
    name: &str,
    kind: NodeKind,
    ttl_secs: Option<u64>,
) -> Result<CreateNodeResponse, CliError> {
    validate_name(name)?;
    Ok(client.create_node(name, kind, ttl_secs)?)
}

pub fn cmd_revoke(client: &AdminClient, name: &str) -> Result<(), CliError> {
    validate_name(name)?;
    Ok(client.revoke(name)?)
}

pub fn cmd_delete_node(client: &AdminClient, name: &str) -> Result<(), CliError> {
    validate_name(name)?;
    Ok(client.delete_node(name)?)
}

pub fn cmd_clear_endpoint(client: &AdminClient, name: &str) -> Result<(), CliError> {
    validate_name(name)?;
    Ok(client.clear_endpoint(name)?)
}

pub fn cmd_rejoin(
    client: &AdminClient,
    name: &str,
    ttl_secs: Option<u64>,
) -> Result<RejoinResponse, CliError> {
    validate_name(name)?;
    Ok(client.rejoin(name, ttl_secs)?)
}

pub fn cmd_list_peers(client: &AdminClient) -> Result<AdminPeersResponse, CliError> {
    Ok(client.list_peers()?)
}

pub fn cmd_export_config(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
) -> Result<String, CliError> {
    validate_name(name)?;
    Ok(export_config::run(admin_client, node_facing_url, name)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_name_rejects_invalid_and_accepts_valid() {
        assert!(validate_name("good-name").is_ok());
        assert!(validate_name("Bad_Name").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name(&"a".repeat(64)).is_err());
    }
}
