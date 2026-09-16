//! The five-step reconciliation loop (spec §4.3): send `/poll`, reconcile
//! WireGuard peers, reconcile this node's own firewall rules, rewrite the
//! hosts-file managed block, persist merged state. A failed cycle is
//! logged and skipped rather than crashing the daemon or tearing down an
//! already-correctly-configured interface (a transient coordinator/network
//! blip shouldn't make things *more* broken than they already were).

use std::path::Path;

use wireserve_types::{FirewallBackend, PollRequest, PollResponse, ServiceDecl, ServiceRule};

use crate::state::AgentState;
use crate::wg::WgInterface;

#[derive(Debug, thiserror::Error)]
pub enum PollError {
    #[error("HTTP error talking to coordinator: {0}")]
    Http(#[from] reqwest::Error),
    #[error("coordinator rejected poll: {0}")]
    Rejected(String),
    #[error("WireGuard reconciliation failed: {0}")]
    Wg(#[from] defguard_wireguard_rs::error::WireguardInterfaceError),
    #[error("firewall reconciliation failed: {0}")]
    Firewall(String),
    #[error("hosts-file sync failed: {0}")]
    Hosts(#[from] std::io::Error),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
    #[error("agent is not registered yet — run `wireserve-agent join` first")]
    NotRegistered,
}

/// Builds the request body from currently-declared services — this is the
/// node's own view of what it's serving, independent of anything the
/// coordinator has told it.
pub fn build_poll_request(declared: &[ServiceDecl], endpoint_addr: Option<String>) -> PollRequest {
    PollRequest {
        endpoint_addr,
        services: declared.to_vec(),
    }
}

/// Firewall rules are derived from what THIS node declared in the request
/// it just sent — never from the coordinator's response, and never from
/// the full mesh directory (spec §5: "a node only ever firewalls itself").
pub fn service_rules(declared: &[ServiceDecl]) -> Vec<ServiceRule> {
    declared
        .iter()
        .map(|d| ServiceRule {
            proto: d.proto,
            port: d.port,
        })
        .collect()
}

pub struct PollContext<'a, F: FirewallBackend> {
    pub client: &'a reqwest::Client,
    pub coordinator_url: &'a str,
    pub bearer_token: &'a str,
    pub hosts_path: &'a Path,
    pub wg: &'a mut WgInterface,
    pub firewall: &'a mut F,
}

/// Runs exactly one poll cycle against `state`, performing all five steps
/// in order. Returns the fresh directory on success.
pub async fn run_once<F: FirewallBackend>(
    ctx: &mut PollContext<'_, F>,
    state: &mut AgentState,
) -> Result<PollResponse, PollError>
where
    F::Error: std::fmt::Display,
{
    let bearer = state.bearer_token.as_deref().ok_or(PollError::NotRegistered)?;
    let self_pubkey = state.public_key.clone().unwrap_or_default();

    // 1. send
    let req = build_poll_request(&state.declared_services, state.endpoint_addr.clone());
    let url = format!("{}/poll", ctx.coordinator_url.trim_end_matches('/'));
    let resp = ctx
        .client
        .post(&url)
        .bearer_auth(bearer)
        .json(&req)
        .send()
        .await?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(PollError::Rejected(body));
    }
    let directory: PollResponse = resp.json().await?;

    // 2. reconcile WireGuard peers
    ctx.wg.reconcile(&directory.peers, &self_pubkey)?;

    // 3. reconcile this node's own firewall rules (from what we declared,
    //    not from the coordinator's response).
    let rules = service_rules(&state.declared_services);
    ctx.firewall
        .apply(&rules)
        .map_err(|e| PollError::Firewall(e.to_string()))?;

    // 4. rewrite the hosts-file managed block from the full directory.
    crate::hosts::sync(ctx.hosts_path, &directory.services)?;

    // 5. persist merged state.
    state.last_directory = Some(directory.clone());
    state.save(&crate::paths::state_path())?;

    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::Proto;

    #[test]
    fn build_poll_request_carries_declared_services_verbatim() {
        let declared = vec![ServiceDecl {
            name: "plex".into(),
            port: 32400,
            proto: Proto::Tcp,
        }];
        let req = build_poll_request(&declared, Some("host:51820".into()));
        assert_eq!(req.services.len(), 1);
        assert_eq!(req.endpoint_addr.as_deref(), Some("host:51820"));
    }

    #[test]
    fn service_rules_maps_declared_services_to_firewall_rules() {
        let declared = vec![
            ServiceDecl { name: "plex".into(), port: 32400, proto: Proto::Tcp },
            ServiceDecl { name: "dns".into(), port: 53, proto: Proto::Udp },
        ];
        let rules = service_rules(&declared);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], ServiceRule { proto: Proto::Tcp, port: 32400 });
        assert_eq!(rules[1], ServiceRule { proto: Proto::Udp, port: 53 });
    }

    #[test]
    fn service_rules_ignores_service_names_entirely() {
        // Firewall rules only ever need proto+port — names are a
        // hosts-file/DNS concern, not a firewall one. This test exists to
        // pin that boundary down explicitly.
        let declared = vec![ServiceDecl { name: "anything-goes-here".into(), port: 1, proto: Proto::Tcp }];
        let rules = service_rules(&declared);
        assert_eq!(rules, vec![ServiceRule { proto: Proto::Tcp, port: 1 }]);
    }
}
