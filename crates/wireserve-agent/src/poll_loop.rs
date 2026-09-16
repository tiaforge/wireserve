//! The five-step reconciliation loop (spec §4.3): send `/poll`, reconcile
//! WireGuard peers, reconcile this node's own firewall rules, rewrite the
//! hosts-file managed block, persist merged state. A failed cycle is
//! logged and skipped rather than crashing the daemon or tearing down an
//! already-correctly-configured interface (a transient coordinator/network
//! blip shouldn't make things *more* broken than they already were).

use std::path::Path;

use tokio::sync::Mutex;
use wireserve_types::{FirewallBackend, PollRequest, PollResponse, ServiceDecl, ServiceRule};

use crate::state::AgentState;
use crate::wg::WgInterface;

#[derive(Debug, thiserror::Error)]
pub enum PollError {
    #[error("HTTP error talking to coordinator: {0}")]
    Http(#[from] reqwest::Error),
    /// Carries the status code — not just the body text — so callers can
    /// tell a revoked-node 401 (F9: the daemon should notice and react,
    /// not silently retry forever with a dead bearer token) apart from
    /// any other rejection.
    #[error("coordinator rejected poll ({status}): {message}")]
    Rejected {
        status: reqwest::StatusCode,
        message: String,
    },
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

impl PollError {
    /// F9 (security review): a 401 specifically means this node's bearer
    /// token no longer works — almost always because an admin revoked it
    /// — as opposed to a transient network/server error that's worth
    /// blindly retrying.
    #[must_use]
    pub fn is_unauthorized(&self) -> bool {
        matches!(
            self,
            PollError::Rejected {
                status,
                ..
            } if *status == reqwest::StatusCode::UNAUTHORIZED
        )
    }
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

/// Parses a `/poll` error body for a `conflicting_service` name (spec
/// §4.3's 409, coordinator side) and, if present, removes it from
/// `declared_services` and records why in `rejected_services` (security
/// review F3). Kept pure/testable separately from the network call.
/// Returns whether it actually quarantined anything, so the caller knows
/// whether `state` needs saving.
pub fn quarantine_rejected_service(state: &mut AgentState, error_body: &str) -> bool {
    let Some(name) = serde_json::from_str::<wireserve_types::ErrorBody>(error_body)
        .ok()
        .and_then(|b| b.conflicting_service)
    else {
        return false;
    };
    state.declared_services.retain(|d| d.name != name);
    state.rejected_services.retain(|r| r.name != name);
    state.rejected_services.push(crate::state::RejectedService {
        name,
        reason: error_body.to_string(),
    });
    true
}

pub struct PollContext<'a, F: FirewallBackend> {
    pub client: &'a reqwest::Client,
    pub coordinator_url: &'a str,
    pub hosts_path: &'a Path,
    pub wg: &'a mut WgInterface,
    pub firewall: &'a mut F,
}

/// Runs exactly one poll cycle against the daemon's single shared `state`,
/// performing all five steps in order. Returns the fresh directory on
/// success.
///
/// F1 (security review, round 2): `state` is the same `Mutex` the IPC
/// server mutates, and the lock is held only for the moments this
/// function reads or writes it — never across the network round trip —
/// so a `serve`/`unserve`/`list` issued while a poll is in flight is
/// neither blocked nor lost. Only the fields this cycle actually
/// produces (`last_directory`, a quarantined declaration) are written
/// back; `declared_services` is never overwritten wholesale.
pub async fn run_once<F: FirewallBackend>(
    ctx: &mut PollContext<'_, F>,
    state: &Mutex<AgentState>,
) -> Result<PollResponse, PollError>
where
    F::Error: std::fmt::Display,
{
    // Snapshot exactly what this cycle sends, then release the lock.
    let (bearer, self_pubkey, declared, endpoint_addr) = {
        let s = state.lock().await;
        (
            s.bearer_token.clone().ok_or(PollError::NotRegistered)?,
            s.public_key.clone().unwrap_or_default(),
            s.declared_services.clone(),
            s.endpoint_addr.clone(),
        )
    };

    // 1. send
    let req = build_poll_request(&declared, endpoint_addr);
    let url = format!("{}/poll", ctx.coordinator_url.trim_end_matches('/'));
    let resp = ctx
        .client
        .post(&url)
        .bearer_auth(&bearer)
        .json(&req)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        // F3 (security review): a single colliding service name used to
        // wedge the whole agent forever — this cycle's poll failed before
        // ever reaching peer reconciliation, and since the same
        // declaration was resent every cycle, EVERY future cycle failed
        // the same way, so the agent stopped seeing new peers or
        // revocations too. Quarantine exactly the offending declaration
        // (drop it from what gets sent, record why) so the *next* cycle
        // succeeds normally instead of repeating this forever. This
        // cycle still reports failure — reconciliation resumes on the
        // next poll interval, not this one.
        {
            let mut s = state.lock().await;
            if quarantine_rejected_service(&mut s, &body_text) {
                s.save(&crate::paths::state_path())?;
            }
        }

        return Err(PollError::Rejected {
            status,
            message: body_text,
        });
    }
    let directory: PollResponse = resp.json().await?;

    // 2. reconcile WireGuard peers
    ctx.wg.reconcile(&directory.peers, &self_pubkey)?;

    // 3. reconcile this node's own firewall rules — from the snapshot
    //    this cycle actually sent (spec §5), not from the coordinator's
    //    response and not from whatever `serve` may have queued since.
    let rules = service_rules(&declared);
    ctx.firewall
        .apply(&rules)
        .map_err(|e| PollError::Firewall(e.to_string()))?;

    // 4. rewrite the hosts-file managed block from the full directory.
    crate::hosts::sync(ctx.hosts_path, &directory.services)?;

    // 5. persist merged state.
    {
        let mut s = state.lock().await;
        s.last_directory = Some(directory.clone());
        s.save(&crate::paths::state_path())?;
    }

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

    // ---- F3: quarantine_rejected_service ----

    fn state_with_declared(names: &[&str]) -> AgentState {
        AgentState {
            declared_services: names
                .iter()
                .map(|n| ServiceDecl {
                    name: (*n).to_string(),
                    port: 1,
                    proto: Proto::Tcp,
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn quarantine_removes_the_named_service_and_records_why() {
        let mut state = state_with_declared(&["plex", "homeassistant"]);
        let body = serde_json::to_string(&wireserve_types::ErrorBody::service_collision(
            "service name 'plex' is already in use",
            "plex",
        ))
        .unwrap();

        let quarantined = quarantine_rejected_service(&mut state, &body);

        assert!(quarantined);
        assert_eq!(state.declared_services.len(), 1);
        assert_eq!(state.declared_services[0].name, "homeassistant");
        assert_eq!(state.rejected_services.len(), 1);
        assert_eq!(state.rejected_services[0].name, "plex");
    }

    #[test]
    fn quarantine_is_a_no_op_for_a_body_without_conflicting_service() {
        let mut state = state_with_declared(&["plex"]);
        let quarantined = quarantine_rejected_service(&mut state, r#"{"error":"invalid join token"}"#);

        assert!(!quarantined);
        assert_eq!(state.declared_services.len(), 1);
        assert!(state.rejected_services.is_empty());
    }

    #[test]
    fn quarantine_is_a_no_op_for_unparseable_body() {
        let mut state = state_with_declared(&["plex"]);
        let quarantined = quarantine_rejected_service(&mut state, "not json at all");

        assert!(!quarantined);
        assert_eq!(state.declared_services.len(), 1);
    }

    #[test]
    fn requarantining_the_same_name_does_not_duplicate_the_record() {
        let mut state = state_with_declared(&["plex"]);
        let body = serde_json::to_string(&wireserve_types::ErrorBody::service_collision(
            "service name 'plex' is already in use",
            "plex",
        ))
        .unwrap();

        quarantine_rejected_service(&mut state, &body);
        quarantine_rejected_service(&mut state, &body);

        assert_eq!(state.rejected_services.len(), 1);
    }

    // ---- F9: PollError::is_unauthorized ----

    #[test]
    fn is_unauthorized_true_only_for_401() {
        let unauthorized = PollError::Rejected {
            status: reqwest::StatusCode::UNAUTHORIZED,
            message: "unauthorized".into(),
        };
        assert!(unauthorized.is_unauthorized());

        let conflict = PollError::Rejected {
            status: reqwest::StatusCode::CONFLICT,
            message: "conflict".into(),
        };
        assert!(!conflict.is_unauthorized());

        assert!(!PollError::NotRegistered.is_unauthorized());
    }
}
