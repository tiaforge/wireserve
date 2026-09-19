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
/// coordinator has told it. `dual` is this cycle's actively-probed
/// endpoint candidates (see `probe::probe_both`) — always sent verbatim
/// (including `None`s), same COALESCE-preserving contract the coordinator
/// already applies to them.
pub fn build_poll_request(
    declared: &[ServiceDecl],
    endpoint_addr: Option<String>,
    dual: &crate::probe::DualProbeResult,
) -> PollRequest {
    PollRequest {
        endpoint_addr,
        endpoint_addr_v4: dual.v4.clone(),
        endpoint_addr_v6: dual.v6.clone(),
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
    quarantine(state, name, error_body.to_string());
    true
}

/// Drops a declaration and records why, so it stops being resent every
/// cycle but does not silently vanish from `wireserve list` (security
/// review F3).
///
/// Shared by the name-collision path and the admin-denial path so the two
/// cannot drift — in particular so both get the de-duplication that stops
/// a repeatedly-quarantined name accumulating records.
fn quarantine(state: &mut AgentState, name: String, reason: String) {
    state.declared_services.retain(|d| d.name != name);
    state.rejected_services.retain(|r| r.name != name);
    state.pending_services.retain(|n| n != &name);
    state
        .rejected_services
        .push(crate::state::RejectedService { name, reason });
}

/// Folds the approval verdicts from a SUCCESSFUL poll into local state.
///
/// The asymmetry between the two verdicts is the important part:
///
/// * **pending** stays in `declared_services`. The node keeps declaring
///   it so an admin can still approve it, keeps its own firewall hole
///   open (spec §5 — a node only ever firewalls itself, and nothing
///   resolves `<name>.wg` for it yet anyway), and is simply absent from
///   every other node's directory. It is recorded so `wireserve list` can
///   say "waiting on approval" instead of looking identical to "not
///   polled yet".
///
/// * **denied** is quarantined exactly as a name collision is: dropped
///   from `declared_services` so it stops being resent forever, with the
///   admin's reason kept so the operator can see why. Because
///   `service_rules` derives from `declared_services`, that drop is also
///   what closes the local firewall hole.
///
/// Returns whether anything changed, so the caller knows whether to save.
pub fn apply_approval_verdicts(state: &mut AgentState, directory: &PollResponse) -> bool {
    let mut changed = false;

    for denied in &directory.denied_services {
        if state.declared_services.iter().any(|d| d.name == denied.name) {
            let reason = denied
                .reason
                .clone()
                .unwrap_or_else(|| "denied by an administrator".to_string());
            tracing::error!(
                service = %denied.name,
                reason = ?denied.reason,
                "declared service was denied by an admin — withdrawing it locally"
            );
            quarantine(state, denied.name.clone(), reason);
            changed = true;
        }
    }

    let pending: Vec<String> = directory
        .pending_services
        .iter()
        .map(|p| p.name.clone())
        .collect();
    for name in &pending {
        if !state.pending_services.contains(name) {
            tracing::warn!(
                service = %name,
                "declared service is waiting on admin approval — no other node can \
                 resolve <name>.wg for it yet"
            );
        }
    }
    if pending != state.pending_services {
        state.pending_services = pending;
        changed = true;
    }

    changed
}

pub struct PollContext<'a, F: FirewallBackend> {
    pub client: &'a reqwest::Client,
    pub coordinator_url: &'a str,
    pub hosts_path: &'a Path,
    /// This instance's label on its hosts-file block (see
    /// `hosts::sync`); `None` for the default instance.
    pub hosts_label: Option<&'a str>,
    pub state_path: &'a Path,
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
    let (bearer, self_pubkey, declared, endpoint_addr, listen_port) = {
        let s = state.lock().await;
        (
            s.bearer_token.clone().ok_or(PollError::NotRegistered)?,
            s.public_key.clone().unwrap_or_default(),
            s.declared_services.clone(),
            s.endpoint_addr.clone(),
            s.listen_port.unwrap_or(51820),
        )
    };

    // Actively probe both families against the coordinator this cycle —
    // see `probe` module doc. Reused for two jobs below: the self-report
    // in this poll's own request body, and (via `dual.v6.is_some()`) the
    // "do I have real working IPv6 right now" signal for peer
    // reconciliation's endpoint preference.
    let dual = crate::probe::probe_both(ctx.coordinator_url, listen_port, crate::probe::PROBE_TIMEOUT).await;
    let prefer_ipv6 = dual.v6.is_some();

    // 1. send
    let req = build_poll_request(&declared, endpoint_addr, &dual);
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
                s.save(ctx.state_path)?;
            }
        }

        return Err(PollError::Rejected {
            status,
            message: body_text,
        });
    }
    let directory: PollResponse = resp.json().await?;

    // Approval verdicts are folded in BEFORE the firewall rules are
    // computed, and that ordering is the whole point.
    //
    // `declared` is the snapshot taken before the request was sent. A
    // denial arriving in this response drops the name from
    // `declared_services`, and since `service_rules` derives from that
    // list, recomputing it here is what closes the local firewall hole on
    // *this* cycle rather than the next one. Applying the verdict to
    // persisted state alone and leaving `rules` built from the stale
    // snapshot would leave a denied service reachable for another poll
    // interval — twenty seconds by default, which reads as a bug rather
    // than as a design.
    //
    // This is the one place the coordinator's response influences a
    // node's own firewall, amending the rule stated on step 3 below. It
    // is safe in exactly one direction and must stay that way: a verdict
    // can only ever remove a rule, never add one, so a compromised or
    // buggy coordinator can close ports on a node but can never open one.
    let declared = {
        let mut s = state.lock().await;
        if apply_approval_verdicts(&mut s, &directory) {
            s.save(ctx.state_path)?;
        }
        s.declared_services.clone()
    };

    // Steps 2-4 are all synchronous and can block: netlink round trips,
    // DNS resolution of peer endpoints inside `reconcile`, and file I/O.
    // `block_in_place` moves this worker off the async scheduler for the
    // duration so the IPC server (`list`/`serve`/`leave`) stays
    // responsive on the other workers.
    let rules = service_rules(&declared);
    tokio::task::block_in_place(|| -> Result<(), PollError> {
        // 2. reconcile WireGuard peers
        ctx.wg.reconcile(&directory.peers, &self_pubkey, prefer_ipv6)?;

        // 3. reconcile this node's own firewall rules — from what this
        //    node declared (spec §5), not from the coordinator's
        //    directory and not from whatever `serve` may have queued
        //    since. The one exception is an admin denial, already folded
        //    in above, which can only ever close a hole; see there.
        ctx.firewall
            .apply(&rules)
            .map_err(|e| PollError::Firewall(e.to_string()))?;

        // 4. rewrite the hosts-file managed block from the full directory.
        crate::hosts::sync(ctx.hosts_path, ctx.hosts_label, &directory.services)?;
        Ok(())
    })?;

    // 5. persist merged state.
    {
        let mut s = state.lock().await;
        s.last_directory = Some(directory.clone());
        s.save(ctx.state_path)?;
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
        let dual = crate::probe::DualProbeResult {
            v4: Some("203.0.113.5:51820".into()),
            v6: None,
        };
        let req = build_poll_request(&declared, Some("host:51820".into()), &dual);
        assert_eq!(req.services.len(), 1);
        assert_eq!(req.endpoint_addr.as_deref(), Some("host:51820"));
        assert_eq!(req.endpoint_addr_v4.as_deref(), Some("203.0.113.5:51820"));
        assert!(req.endpoint_addr_v6.is_none());
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

    // ---- service approval verdicts ----

    fn directory_with(
        pending: &[&str],
        denied: &[(&str, Option<&str>)],
    ) -> PollResponse {
        PollResponse {
            peers: vec![],
            services: vec![],
            pending_services: pending
                .iter()
                .map(|n| wireserve_types::PendingService {
                    name: (*n).to_string(),
                    port: 1,
                    proto: Proto::Tcp,
                    declared_at: None,
                })
                .collect(),
            denied_services: denied
                .iter()
                .map(|(n, r)| wireserve_types::DeniedService {
                    name: (*n).to_string(),
                    reason: r.map(str::to_string),
                    denied_at: None,
                })
                .collect(),
        }
    }

    #[test]
    fn a_denied_service_is_quarantined_from_a_successful_poll() {
        let mut state = state_with_declared(&["plex", "git"]);
        let changed = apply_approval_verdicts(
            &mut state,
            &directory_with(&[], &[("plex", Some("reserved for the build box"))]),
        );

        assert!(changed);
        assert_eq!(state.declared_services.len(), 1);
        assert_eq!(state.declared_services[0].name, "git");
        assert_eq!(state.rejected_services.len(), 1);
        assert_eq!(state.rejected_services[0].name, "plex");
        assert!(state.rejected_services[0].reason.contains("reserved for the build box"));
    }

    #[test]
    fn a_denied_service_loses_its_firewall_hole_because_it_leaves_declared_services() {
        // The mechanism behind same-cycle closure: firewall rules derive
        // from `declared_services`, so quarantining the name is what shuts
        // the port. `run_once` recomputes `rules` after this call for
        // exactly that reason.
        let mut state = state_with_declared(&["plex", "git"]);
        state.declared_services[0].port = 32400;
        assert!(service_rules(&state.declared_services)
            .iter()
            .any(|r| r.port == 32400));

        apply_approval_verdicts(&mut state, &directory_with(&[], &[("plex", None)]));

        assert!(
            !service_rules(&state.declared_services)
                .iter()
                .any(|r| r.port == 32400),
            "a denied service's port must not survive in the rule set"
        );
    }

    #[test]
    fn a_pending_service_is_recorded_but_never_quarantined() {
        // Pending keeps being declared (so an admin can still approve it)
        // and keeps its own firewall hole — the node is only firewalling
        // itself, and nothing resolves <name>.wg for it yet anyway.
        let mut state = state_with_declared(&["plex"]);
        state.declared_services[0].port = 32400;

        let changed = apply_approval_verdicts(&mut state, &directory_with(&["plex"], &[]));

        assert!(changed);
        assert_eq!(state.declared_services.len(), 1, "still declared");
        assert!(state.rejected_services.is_empty(), "pending is not a rejection");
        assert_eq!(state.pending_services, vec!["plex".to_string()]);
        assert!(service_rules(&state.declared_services)
            .iter()
            .any(|r| r.port == 32400));
    }

    #[test]
    fn pending_services_are_replaced_not_merged() {
        // An approval is observed as a name *disappearing* from the
        // coordinator's pending list, so merging would mean a service
        // stayed flagged "waiting" forever after it was approved.
        let mut state = state_with_declared(&["plex", "git"]);
        apply_approval_verdicts(&mut state, &directory_with(&["plex", "git"], &[]));
        assert_eq!(state.pending_services.len(), 2);

        apply_approval_verdicts(&mut state, &directory_with(&["git"], &[]));
        assert_eq!(state.pending_services, vec!["git".to_string()]);
    }

    #[test]
    fn a_response_without_the_approval_fields_changes_nothing() {
        // What an older coordinator, or one with approval disabled,
        // returns. Must be a no-op, not an implicit "everything denied".
        let mut state = state_with_declared(&["plex"]);
        let changed = apply_approval_verdicts(&mut state, &directory_with(&[], &[]));

        assert!(!changed);
        assert_eq!(state.declared_services.len(), 1);
        assert!(state.rejected_services.is_empty());
        assert!(state.pending_services.is_empty());
    }

    #[test]
    fn denying_a_name_this_node_no_longer_declares_is_a_no_op() {
        let mut state = state_with_declared(&["git"]);
        let changed = apply_approval_verdicts(&mut state, &directory_with(&[], &[("plex", None)]));
        assert!(!changed);
        assert!(state.rejected_services.is_empty());
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
