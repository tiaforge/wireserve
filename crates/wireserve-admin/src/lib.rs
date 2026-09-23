pub mod client;
pub mod config;
pub mod export_config;
pub mod qr;

use client::{AdminClient, ClientError};
use wireserve_types::{
    is_valid_dns_label, AdminPeersResponse, AdminServicesResponse, CreateNodeResponse, NodeKind,
    RejoinResponse, MAX_DENY_REASON_LEN,
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
    #[error("denial reason is {0} bytes; the limit is {MAX_DENY_REASON_LEN}")]
    DenyReasonTooLong(usize),
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

pub fn cmd_clear_endpoint(
    client: &AdminClient,
    name: &str,
    family: Option<&str>,
) -> Result<(), CliError> {
    validate_name(name)?;
    Ok(client.clear_endpoint(name, family)?)
}

pub fn cmd_rejoin(
    client: &AdminClient,
    name: &str,
    ttl_secs: Option<u64>,
) -> Result<RejoinResponse, CliError> {
    validate_name(name)?;
    // No kind expectation: a bare `rejoin` names the node explicitly and has
    // always worked on either kind. Only `export-config --refresh` asserts a
    // kind, because it is the caller that could aim at the wrong one.
    Ok(client.rejoin(name, ttl_secs, None)?)
}

pub fn cmd_list_peers(client: &AdminClient) -> Result<AdminPeersResponse, CliError> {
    Ok(client.list_peers()?)
}

pub fn cmd_list_services(client: &AdminClient) -> Result<AdminServicesResponse, CliError> {
    Ok(client.list_services()?)
}

/// Both names are validated before any network call — spec §3's fail-fast
/// rule, and a second reason here: these are the first two path segments
/// this crate interpolates from two separate user inputs, and a valid DNS
/// label cannot contain `/` or `..`.
pub fn cmd_approve_service(
    client: &AdminClient,
    node: &str,
    service: &str,
) -> Result<(), CliError> {
    validate_name(node)?;
    validate_name(service)?;
    Ok(client.approve_service(node, service)?)
}

pub fn cmd_deny_service(
    client: &AdminClient,
    node: &str,
    service: &str,
    reason: Option<&str>,
) -> Result<(), CliError> {
    validate_name(node)?;
    validate_name(service)?;
    if let Some(r) = reason {
        if r.len() > MAX_DENY_REASON_LEN {
            return Err(CliError::DenyReasonTooLong(r.len()));
        }
    }
    Ok(client.deny_service(node, service, reason)?)
}

pub fn cmd_approve_transit(client: &AdminClient, name: &str) -> Result<(), CliError> {
    validate_name(name)?;
    Ok(client.approve_transit(name)?)
}

pub fn cmd_deny_transit(client: &AdminClient, name: &str) -> Result<(), CliError> {
    validate_name(name)?;
    Ok(client.deny_transit(name)?)
}

pub fn cmd_export_config(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
    gateway: Option<&str>,
) -> Result<String, CliError> {
    validate_name(name)?;
    if let Some(gateway) = gateway {
        validate_name(gateway)?;
    }
    Ok(export_config::run(admin_client, node_facing_url, name, gateway)?)
}

/// Re-issue a `.conf` for a static peer that already exists (PLAN.md M24),
/// keeping its name and mesh address. See [`export_config::run_refresh`] for
/// what this mutates and when.
pub fn cmd_export_config_refresh(
    admin_client: &AdminClient,
    node_facing_url: &str,
    name: &str,
    gateway: Option<&str>,
) -> Result<String, CliError> {
    validate_name(name)?;
    if let Some(gateway) = gateway {
        validate_name(gateway)?;
    }
    Ok(export_config::run_refresh(admin_client, node_facing_url, name, gateway)?)
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
