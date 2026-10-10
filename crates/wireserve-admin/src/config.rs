//! Resolves the admin token and coordinator URL used by every subcommand.
//!
//! Precedence for the admin token: an explicit `--admin-token` CLI flag,
//! then the `WIRESERVE_ADMIN_TOKEN` env var (same variable name the
//! coordinator itself reads), then the contents of a local token file
//! (`WIRESERVE_ADMIN_TOKEN_FILE` env var, or
//! `~/.config/wireserve-admin/admin_token` by default). Spec §4.0 says
//! "local config/env" without specifying a format — this is deliberately a
//! plain trimmed-text file holding just the token, not a structured
//! TOML/YAML config, since there's exactly one secret to store. The
//! coordinator URL and the node-facing register URL follow the same
//! flag → env → file shape, in their own files.
//!
//! Every one of these has an `_interactive` counterpart
//! (`resolve_admin_token_interactive`, etc.) that, if the plain resolver
//! comes up empty AND stdin is a real terminal, prompts for the value and
//! offers to save it to that same file for next time — never for scripts
//! or CI, where stdin isn't a terminal and these behave exactly like the
//! plain resolvers.

use std::io::IsTerminal;

/// The coordinator's own compiled-in default for `WIRESERVE_ADMIN_LISTEN_ADDR`
/// (`crates/wireserve-coordinator/src/config.rs`). The admin listener is
/// loopback-only by construction — the coordinator refuses to start
/// otherwise — so defaulting to it here removes a setting that is
/// effectively never anything else, while an operator with a nonstandard
/// admin listen address can still override it exactly as before.
const DEFAULT_COORDINATOR_URL: &str = "http://127.0.0.1:47821";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "no admin token found — pass --admin-token, set WIRESERVE_ADMIN_TOKEN, or write one to {0}"
    )]
    MissingAdminToken(String),
    #[error(
        "no node-facing URL found for the /register call — pass --register-url or set \
         WIRESERVE_REGISTER_URL. This is the coordinator's OTHER listener: the admin and node-facing listeners are bound \
         separately (e.g. different ports), so --coordinator-url alone isn't enough for device create"
    )]
    MissingRegisterUrl,
}

fn config_file_path(env_override: &str, filename: &str) -> String {
    std::env::var(env_override).unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{home}/.config/wireserve-admin/{filename}")
    })
}

fn default_token_file_path() -> String {
    config_file_path("WIRESERVE_ADMIN_TOKEN_FILE", "admin_token")
}

fn default_coordinator_url_file_path() -> String {
    config_file_path("WIRESERVE_COORDINATOR_URL_FILE", "coordinator_url")
}

fn default_register_url_file_path() -> String {
    config_file_path("WIRESERVE_REGISTER_URL_FILE", "register_url")
}

/// Whether stdin is an interactive terminal — the gate every prompt in this
/// module is behind. A script or CI invocation (stdin redirected from a
/// file, closed, or piped) never blocks waiting for input: it falls
/// through to the exact error or default the plain resolver already gives.
fn is_interactive() -> bool {
    std::io::stdin().is_terminal()
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

/// Same as [`resolve_admin_token`], except when it comes up empty and
/// stdin is a terminal: prompts (masked, like a password) instead of
/// erroring, and offers to save the entered value to the token file so
/// future invocations don't need to ask again.
pub fn resolve_admin_token_interactive(cli_flag: Option<&str>) -> Result<String, ConfigError> {
    match resolve_admin_token(cli_flag) {
        Ok(t) => Ok(t),
        Err(e) => {
            if !is_interactive() {
                return Err(e);
            }
            eprintln!("{e}");
            let token = rpassword::prompt_password("Admin token: ")
                .unwrap_or_default()
                .trim()
                .to_string();
            if token.is_empty() {
                return Err(e);
            }
            maybe_save(&default_token_file_path(), &token);
            Ok(token)
        }
    }
}

/// The flag → env → file precedence shared by [`resolve_coordinator_url`]
/// and its interactive counterpart, without the final hardcoded-default
/// fallback — so the interactive version can tell "nothing configured"
/// apart from "explicitly configured to the same value as the default."
fn explicit_coordinator_url(cli_flag: Option<&str>) -> Option<String> {
    if let Some(u) = cli_flag {
        if !u.is_empty() {
            return Some(u.trim_end_matches('/').to_string());
        }
    }
    if let Ok(u) = std::env::var("WIRESERVE_COORDINATOR_URL") {
        if !u.is_empty() {
            return Some(u.trim_end_matches('/').to_string());
        }
    }
    let path = default_coordinator_url_file_path();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Resolves the coordinator base URL from an explicit CLI flag, the
/// `WIRESERVE_COORDINATOR_URL` env var, or a saved coordinator-URL file,
/// falling back to the admin listener's own compiled-in default address;
/// trailing slashes are stripped so every caller can safely append a path
/// starting with `/`.
pub fn resolve_coordinator_url(cli_flag: Option<&str>) -> Result<String, ConfigError> {
    Ok(explicit_coordinator_url(cli_flag).unwrap_or_else(|| DEFAULT_COORDINATOR_URL.to_string()))
}

/// Same as [`resolve_coordinator_url`], except when nothing is explicitly
/// configured and stdin is a terminal: prompts with the compiled-in
/// default shown in brackets (blank input accepts it) instead of silently
/// using it, and offers to save the answer for next time. Never prompts
/// when running non-interactively — the silent default is unchanged there.
pub fn resolve_coordinator_url_interactive(cli_flag: Option<&str>) -> Result<String, ConfigError> {
    if let Some(u) = explicit_coordinator_url(cli_flag) {
        return Ok(u);
    }
    if !is_interactive() {
        return resolve_coordinator_url(cli_flag);
    }
    let answer = prompt_line(&format!("Coordinator admin URL [{DEFAULT_COORDINATOR_URL}]: "));
    let url = if answer.is_empty() {
        DEFAULT_COORDINATOR_URL.to_string()
    } else {
        answer.trim_end_matches('/').to_string()
    };
    maybe_save(&default_coordinator_url_file_path(), &url);
    Ok(url)
}

/// Resolves the node-facing base URL used only by `device create`'s
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
    let path = default_register_url_file_path();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(ConfigError::MissingRegisterUrl)
}

/// Same as [`resolve_register_url`], except when it comes up empty and
/// stdin is a terminal: prompts instead of erroring, and offers to save
/// the answer — this URL doesn't change between one `node create` and the
/// next, so it's worth remembering exactly like the admin token is.
pub fn resolve_register_url_interactive(cli_flag: Option<&str>) -> Result<String, ConfigError> {
    match resolve_register_url(cli_flag) {
        Ok(u) => Ok(u),
        Err(e) => {
            if !is_interactive() {
                return Err(e);
            }
            eprintln!("{e}");
            let answer = prompt_line("Coordinator's public (node-facing) URL: ");
            if answer.is_empty() {
                return Err(e);
            }
            let url = answer.trim_end_matches('/').to_string();
            maybe_save(&default_register_url_file_path(), &url);
            Ok(url)
        }
    }
}

/// Prints `label` to stderr (prompts are UI, not program output — kept off
/// stdout so nothing here ends up in a redirected/piped result) and reads
/// one trimmed line from stdin.
fn prompt_line(label: &str) -> String {
    eprint!("{label}");
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

/// Asks whether to persist `value` to `path` for next time (default yes —
/// blank or anything other than an explicit "n"/"no" saves), and writes it
/// mode 600 on unix if so. Never fails the caller: a save that doesn't
/// work is a warning, not a reason to lose the value just resolved.
fn maybe_save(path: &str, value: &str) {
    let answer = prompt_line(&format!("Save it to {path} for next time? [Y/n]: "));
    if matches!(answer.to_lowercase().as_str(), "n" | "no") {
        return;
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("warning: could not create {}: {e}", parent.display());
            return;
        }
    }
    match write_secret_file(path, value) {
        Ok(()) => eprintln!("saved to {path}"),
        Err(e) => eprintln!("warning: could not save to {path}: {e}"),
    }
}

#[cfg(unix)]
fn write_secret_file(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    writeln!(f, "{contents}")
}

#[cfg(not(unix))]
fn write_secret_file(path: &str, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, format!("{contents}\n"))
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
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WIRESERVE_COORDINATOR_URL_FILE", "/nonexistent/path/for/test");
        assert_eq!(
            resolve_coordinator_url(Some("http://localhost:8081/")).unwrap(),
            "http://localhost:8081"
        );
        std::env::remove_var("WIRESERVE_COORDINATOR_URL_FILE");
    }

    #[test]
    fn missing_coordinator_url_falls_back_to_the_admin_listener_default() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_COORDINATOR_URL");
        // Neutralizes the new file fallback, exactly like the admin-token
        // equivalent above — otherwise a real
        // ~/.config/wireserve-admin/coordinator_url on the machine running
        // this test would make it flaky.
        std::env::set_var("WIRESERVE_COORDINATOR_URL_FILE", "/nonexistent/path/for/test");
        assert_eq!(
            resolve_coordinator_url(None).unwrap(),
            DEFAULT_COORDINATOR_URL
        );
        std::env::remove_var("WIRESERVE_COORDINATOR_URL_FILE");
    }

    #[test]
    fn falls_back_to_coordinator_url_file() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_COORDINATOR_URL");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("coordinator_url");
        std::fs::write(&path, "https://wireserve.example.com\n").unwrap();
        std::env::set_var("WIRESERVE_COORDINATOR_URL_FILE", &path);
        let resolved = resolve_coordinator_url(None).unwrap();
        assert_eq!(resolved, "https://wireserve.example.com");
        std::env::remove_var("WIRESERVE_COORDINATOR_URL_FILE");
    }

    #[test]
    fn register_url_is_resolved_independently_of_coordinator_url() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_REGISTER_URL");
        std::env::set_var("WIRESERVE_REGISTER_URL_FILE", "/nonexistent/path/for/test");
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
        std::env::remove_var("WIRESERVE_REGISTER_URL_FILE");
    }

    #[test]
    fn falls_back_to_register_url_file() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_REGISTER_URL");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("register_url");
        std::fs::write(&path, "https://wireserve.example.com\n").unwrap();
        std::env::set_var("WIRESERVE_REGISTER_URL_FILE", &path);
        let resolved = resolve_register_url(None).unwrap();
        assert_eq!(resolved, "https://wireserve.example.com");
        std::env::remove_var("WIRESERVE_REGISTER_URL_FILE");
    }

    // ---- interactive variants: non-interactive (cargo test's own stdin
    // is never a terminal) behave identically to the plain resolvers ----

    #[test]
    fn interactive_admin_token_matches_plain_resolver_when_not_a_tty() {
        let _g = ENV_LOCK.lock().unwrap();
        assert!(!is_interactive(), "cargo test's stdin should never be a tty");
        std::env::set_var("WIRESERVE_ADMIN_TOKEN", "env-token-3");
        assert_eq!(
            resolve_admin_token_interactive(None).unwrap(),
            resolve_admin_token(None).unwrap()
        );
        std::env::remove_var("WIRESERVE_ADMIN_TOKEN");
    }

    #[test]
    fn interactive_coordinator_url_matches_plain_resolver_when_not_a_tty() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_COORDINATOR_URL");
        std::env::set_var("WIRESERVE_COORDINATOR_URL_FILE", "/nonexistent/path/for/test");
        assert_eq!(
            resolve_coordinator_url_interactive(None).unwrap(),
            DEFAULT_COORDINATOR_URL
        );
        std::env::remove_var("WIRESERVE_COORDINATOR_URL_FILE");
    }

    #[test]
    fn interactive_register_url_matches_plain_resolver_when_not_a_tty() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WIRESERVE_REGISTER_URL");
        std::env::set_var("WIRESERVE_REGISTER_URL_FILE", "/nonexistent/path/for/test");
        assert!(resolve_register_url_interactive(None).is_err());
        std::env::remove_var("WIRESERVE_REGISTER_URL_FILE");
    }
}
