//! Resolves the admin token and coordinator URL used by every subcommand.
//!
//! Precedence for the admin token: an explicit `--admin-token` CLI flag,
//! then the `WIRESERVE_ADMIN_TOKEN` env var (same variable name the
//! coordinator itself reads), then the contents of a local token file
//! (`WIRESERVE_ADMIN_TOKEN_FILE` env var, or
//! `~/.config/wireserve-admin/admin_token` by default). Spec §4.0 says
//! "local config/env" without specifying a format — this is deliberately a
//! plain trimmed-text file holding just the token, not a structured
//! TOML/YAML config, since there's exactly one secret to store.

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "no admin token found — pass --admin-token, set WIRESERVE_ADMIN_TOKEN, or write one to {0}"
    )]
    MissingAdminToken(String),
    #[error("no coordinator URL found — pass --coordinator-url or set WIRESERVE_COORDINATOR_URL")]
    MissingCoordinatorUrl,
    #[error(
        "no node-facing URL found for the /register call — pass --register-url or set \
         WIRESERVE_REGISTER_URL. This is the coordinator's OTHER listener: spec §4.0 requires \
         the admin and node-facing listeners to be bound separately (e.g. different ports), so \
         --coordinator-url alone isn't enough for export-config"
    )]
    MissingRegisterUrl,
}

fn default_token_file_path() -> String {
    std::env::var("WIRESERVE_ADMIN_TOKEN_FILE").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{home}/.config/wireserve-admin/admin_token")
    })
}

/// Resolves the admin token from (in order): an explicit CLI flag, the
/// `WIRESERVE_ADMIN_TOKEN` env var, or a local token file. Returns a clear
/// error — before any network call is ever made — if none are present.
pub fn resolve_admin_token(cli_flag: Option<&str>) -> Result<String, ConfigError> {
    if let Some(t) = cli_flag {
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    if let Ok(t) = std::env::var("WIRESERVE_ADMIN_TOKEN") {
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let path = default_token_file_path();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(ConfigError::MissingAdminToken(path))
}

/// Resolves the coordinator base URL from an explicit CLI flag or the
/// `WIRESERVE_COORDINATOR_URL` env var; trailing slashes are stripped so
/// every caller can safely append a path starting with `/`.
pub fn resolve_coordinator_url(cli_flag: Option<&str>) -> Result<String, ConfigError> {
    if let Some(u) = cli_flag {
        if !u.is_empty() {
            return Ok(u.trim_end_matches('/').to_string());
        }
    }
    if let Ok(u) = std::env::var("WIRESERVE_COORDINATOR_URL") {
        if !u.is_empty() {
            return Ok(u.trim_end_matches('/').to_string());
        }
    }
    Err(ConfigError::MissingCoordinatorUrl)
}

/// Resolves the node-facing base URL used only by `export-config`'s
/// `/register` call (spec §4.2) — deliberately separate from
/// `resolve_coordinator_url`, which resolves the *admin* listener's URL.
/// See `ConfigError::MissingRegisterUrl` for why these can't default to
/// the same value.
pub fn resolve_register_url(cli_flag: Option<&str>) -> Result<String, ConfigError> {
    if let Some(u) = cli_flag {
        if !u.is_empty() {
            return Ok(u.trim_end_matches('/').to_string());
        }
    }
    if let Ok(u) = std::env::var("WIRESERVE_REGISTER_URL") {
        if !u.is_empty() {
            return Ok(u.trim_end_matches('/').to_string());
        }
    }
    Err(ConfigError::MissingRegisterUrl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env vars are process-global state; serialize tests that touch them so
    // they can't interleave and read each other's values.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn cli_flag_takes_precedence_over_env() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WIRESERVE_ADMIN_TOKEN", "env-token");
        let resolved = resolve_admin_token(Some("flag-token")).unwrap();
        assert_eq!(resolved, "flag-token");
        std::env::remove_var("WIRESERVE_ADMIN_TOKEN");
    }

    #[test]
    fn env_used_when_no_flag() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WIRESERVE_ADMIN_TOKEN", "env-token-2");
        let resolved = resolve_admin_token(None).unwrap();
        assert_eq!(resolved, "env-token-2");
        std::env::remove_var("WIRESERVE_ADMIN_TOKEN");
    }

    #[test]
    fn missing_everywhere_is_a_clear_error_before_any_network_call() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_ADMIN_TOKEN");
        std::env::set_var("WIRESERVE_ADMIN_TOKEN_FILE", "/nonexistent/path/for/test");
        let err = resolve_admin_token(None).unwrap_err();
        assert!(matches!(err, ConfigError::MissingAdminToken(_)));
        std::env::remove_var("WIRESERVE_ADMIN_TOKEN_FILE");
    }

    #[test]
    fn falls_back_to_token_file() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_ADMIN_TOKEN");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("admin_token");
        std::fs::write(&path, "file-token\n").unwrap();
        std::env::set_var("WIRESERVE_ADMIN_TOKEN_FILE", &path);
        let resolved = resolve_admin_token(None).unwrap();
        assert_eq!(resolved, "file-token");
        std::env::remove_var("WIRESERVE_ADMIN_TOKEN_FILE");
    }

    #[test]
    fn coordinator_url_strips_trailing_slash() {
        assert_eq!(
            resolve_coordinator_url(Some("http://localhost:8081/")).unwrap(),
            "http://localhost:8081"
        );
    }

    #[test]
    fn missing_coordinator_url_is_an_error() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_COORDINATOR_URL");
        assert!(resolve_coordinator_url(None).is_err());
    }

    #[test]
    fn register_url_is_resolved_independently_of_coordinator_url() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_REGISTER_URL");
        std::env::set_var("WIRESERVE_COORDINATOR_URL", "http://127.0.0.1:8081");
        // Coordinator (admin) URL being set must not satisfy the
        // register-URL lookup — they are two different listeners.
        assert!(resolve_register_url(None).is_err());
        std::env::set_var("WIRESERVE_REGISTER_URL", "http://127.0.0.1:8080");
        assert_eq!(
            resolve_register_url(None).unwrap(),
            "http://127.0.0.1:8080"
        );
        std::env::remove_var("WIRESERVE_COORDINATOR_URL");
        std::env::remove_var("WIRESERVE_REGISTER_URL");
    }
}
