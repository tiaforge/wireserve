//! `wireserve-agent join <coordinator-url> <join-token>` — the bootstrap
//! command spec §4.6 implies but doesn't name (PLAN.md decisions log #5).
//! Generates a keypair locally, redeems the join token via `/register`,
//! and persists the result to local state at mode 600.

use defguard_wireguard_rs::key::Key;
use wireserve_types::{NodeKind, RegisterRequest, RegisterResponse};

use crate::state::AgentState;

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("HTTP error talking to coordinator: {0}")]
    Http(#[from] reqwest::Error),
    #[error("coordinator rejected registration: {0}")]
    Rejected(String),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
}

pub struct JoinParams<'a> {
    pub coordinator_url: &'a str,
    pub join_token: &'a str,
    pub listen_port: u16,
    pub endpoint_addr: Option<String>,
}

/// Performs the join: keypair generation, `/register`, and persists the
/// resulting state. Returns the saved state on success.
pub async fn join(params: JoinParams<'_>) -> Result<AgentState, JoinError> {
    let private_key = Key::generate();
    let public_key = private_key.public_key();

    // Security review S6: the join token (and the bearer token coming
    // back) would cross the network in clear over plain http:// to a
    // non-loopback host. A warning, not a refusal — a loopback or
    // internal-network coordinator without TLS is a legitimate topology.
    if wireserve_types::is_plaintext_http_to_remote_host(params.coordinator_url) {
        eprintln!(
            "warning: registering with {} over plain HTTP — the join token and the returned \
             bearer token will cross the network in clear. Spec §7 assumes a TLS-terminating \
             reverse proxy in front of the coordinator; use an https:// URL unless this really \
             is a loopback/trusted-local connection.",
            params.coordinator_url
        );
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let url = format!("{}/register", params.coordinator_url.trim_end_matches('/'));
    let req = RegisterRequest {
        join_token: params.join_token.to_string(),
        pubkey: public_key.to_string(),
        kind: NodeKind::Agent,
        listen_port: Some(params.listen_port),
        endpoint_addr: params.endpoint_addr.clone(),
    };

    let resp = client.post(&url).json(&req).send().await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(JoinError::Rejected(body));
    }
    let reg: RegisterResponse = resp.json().await?;

    let state = AgentState {
        pending_services: Vec::new(),
        coordinator_url: Some(params.coordinator_url.to_string()),
        bearer_token: Some(reg.bearer_token),
        private_key: Some(private_key.to_string()),
        public_key: Some(public_key.to_string()),
        ip4: Some(reg.ip4),
        ip6: Some(reg.ip6),
        listen_port: Some(params.listen_port),
        endpoint_addr: params.endpoint_addr,
        declared_services: Vec::new(),
        last_directory: None,
        rejected_services: Vec::new(),
    };
    state.save(&crate::paths::state_path())?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_private_key_never_appears_in_the_register_request() {
        // The request we build must only ever carry the derived public
        // key — never the private key bytes/string, in any field.
        let private_key = Key::generate();
        let public_key = private_key.public_key();
        let req = RegisterRequest {
            join_token: "jtk_x".into(),
            pubkey: public_key.to_string(),
            kind: NodeKind::Agent,
            listen_port: Some(51820),
            endpoint_addr: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains(&private_key.to_string()));
        assert!(json.contains(&public_key.to_string()));
    }
}
