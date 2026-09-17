//! Local persisted agent state: bearer token, this node's own WireGuard
//! private key, the last successful poll's directory, and any
//! `serve`/`unserve` declarations queued locally but not yet confirmed by a
//! poll (§4.6). Written at mode 600 from the moment of creation (§7) — a
//! leaked backup of this file is as sensitive as a leaked bearer token or
//! private key.

use std::path::Path;

use serde::{Deserialize, Serialize};
use wireserve_types::{PollResponse, ServiceDecl};

use crate::fsutil::atomic_write;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    pub coordinator_url: Option<String>,
    pub bearer_token: Option<String>,
    /// Base64 WireGuard private key — never sent anywhere, only ever used
    /// locally to configure the kernel interface.
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub ip4: Option<String>,
    pub ip6: Option<String>,
    pub listen_port: Option<u16>,
    /// Sent as `endpoint_addr` on every `/poll` (spec §4.3 models this as
    /// resendable each cycle, "may change (dynamic DNS etc.)") — persisted
    /// here rather than hardcoded, so it survives daemon restarts and can
    /// be refreshed independently of a full `join`.
    pub endpoint_addr: Option<String>,
    /// This node's own declared services — the source of truth sent as
    /// `services` in each `/poll` request.
    pub declared_services: Vec<ServiceDecl>,
    /// The full mesh + service directory from the last successful poll,
    /// used to answer `wireserve list` without a network round trip.
    pub last_directory: Option<PollResponse>,
    /// Service declarations the coordinator rejected (name collision with
    /// another node, spec §4.3) — removed from `declared_services` so
    /// they're not resent forever (security review F3), but kept here so
    /// `wireserve list` can show *why* a `serve` call didn't take effect
    /// instead of it just silently vanishing.
    #[serde(default)]
    pub rejected_services: Vec<RejectedService>,
    /// Names this node declared that the coordinator is holding for admin
    /// approval, as of the last successful poll.
    ///
    /// Coordinator-derived and replaced wholesale every cycle, never
    /// merged — an approval shows up here as a name *disappearing*, which
    /// is also how `wireserve list` learns to stop flagging it. Denials
    /// are not kept here; they go through `rejected_services`, which
    /// already exists for declarations that will not take effect.
    #[serde(default)]
    pub pending_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectedService {
    pub name: String,
    pub reason: String,
}

#[cfg(unix)]
fn set_dir_mode_700(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_dir_mode_700(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid state file contents: {0}")]
    Parse(#[from] serde_json::Error),
}

impl AgentState {
    pub fn load(path: &Path) -> Result<Self, StateError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read(path)?;
        Ok(serde_json::from_slice(&raw)?)
    }

    /// Persists state at mode 600, atomically (see `fsutil::atomic_write`).
    pub fn save(&self, path: &Path) -> Result<(), StateError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            // The file itself is 0600 (§7), but the directory holding it
            // was left at whatever the umask produced — typically 0755.
            // Under systemd or the shipped container images the directory
            // is root-owned so that is not exploitable, but this code
            // should not be the part that depends on it: a
            // world-writable-by-default parent is what makes temp-file
            // games against `atomic_write` worth attempting in the first
            // place.
            set_dir_mode_700(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        atomic_write(path, &json, 0o600)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn load_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-state.json");
        let state = AgentState::load(&path).unwrap();
        assert!(state.bearer_token.is_none());
        assert!(state.declared_services.is_empty());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-state.json");
        let mut state = AgentState {
            bearer_token: Some("brt_abc".into()),
            private_key: Some("privkeybase64".into()),
            ..Default::default()
        };
        state.declared_services.push(ServiceDecl {
            name: "plex".into(),
            port: 32400,
            proto: wireserve_types::Proto::Tcp,
        });
        state.save(&path).unwrap();

        let loaded = AgentState::load(&path).unwrap();
        assert_eq!(loaded.bearer_token.as_deref(), Some("brt_abc"));
        assert_eq!(loaded.declared_services.len(), 1);
    }

    #[test]
    fn save_creates_file_at_mode_600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-state.json");
        let state = AgentState {
            bearer_token: Some("brt_secret".into()),
            private_key: Some("supersecretprivatekey".into()),
            ..Default::default()
        };
        state.save(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state file containing secrets must be mode 600");
    }

    #[test]
    fn save_creates_parent_directory_root_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("agent-state.json");
        let state = AgentState::default();
        state.save(&path).unwrap();
        assert!(path.exists());

        let mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "the directory holding key material must not be world-readable");
    }

    #[test]
    fn load_rejects_corrupt_json_rather_than_silently_defaulting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-state.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(AgentState::load(&path).is_err());
    }
}
