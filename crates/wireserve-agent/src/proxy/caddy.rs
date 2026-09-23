//! The Caddy [`ProxyBackend`](super::ProxyBackend) (PLAN.md M25).
//!
//! Renders matchers into a file the operator's own site block imports:
//!
//! ```caddyfile
//! *.int.example.com {
//!     tls { dns cloudflare {env.CF_API_TOKEN} }
//!     import /etc/caddy/conf.d/wireserve.caddy
//! }
//! ```
//!
//! Matchers inside one wildcard site, never a site block per service, and that
//! is not a style preference. A `plex.int.example.com { … }` block is more
//! specific than the wildcard, so Caddy would try to get it its own
//! certificate over HTTP-01 — which cannot work for a name that resolves to a
//! mesh address — and one site block per service is also one ACME order per
//! service, against Let's Encrypt's fifty-certificates-per-domain-per-week
//! limit. One wildcard certificate covers every service that will ever exist.
//!
//! The generated file is owned outright rather than being a managed block
//! inside a shared one: teardown is an unlink, and there is no need for the
//! flock dance `hosts.rs` does, which exists only because every instance on a
//! host shares one `/etc/hosts`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::{ProxyBackend, VHost};
use crate::fsutil::atomic_write;

/// Where `caddy` is looked for, in order, when no explicit path is given.
const CANDIDATES: [&str; 4] =
    ["/usr/bin/caddy", "/usr/local/bin/caddy", "/bin/caddy", "/usr/sbin/caddy"];

/// `caddy reload` dials the admin API, so unlike `nft` it can hang on a
/// socket rather than failing. `Command::output()` has no timeout of its own.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Readable by the caddy user, which is generally not root.
const CONF_MODE: u32 = 0o644;

#[derive(Debug, thiserror::Error)]
pub enum CaddyError {
    #[error(
        "no caddy binary found (looked in {0}) — the agent was asked for the caddy proxy \
         backend, so this is a misconfiguration, not a missing optional feature"
    )]
    NotFound(String),
    #[error("writing {path}: {source}")]
    Write { path: PathBuf, source: std::io::Error },
    #[error("running {cmd}: {source}")]
    Spawn { cmd: String, source: std::io::Error },
    #[error("{cmd} timed out after {}s", COMMAND_TIMEOUT.as_secs())]
    Timeout { cmd: String },
    #[error("{cmd} failed: {stderr}")]
    Failed { cmd: String, stderr: String },
}

pub struct Caddy {
    binary: PathBuf,
    /// The file this backend owns completely.
    conf_path: PathBuf,
    /// The operator's main Caddyfile. Validation has to run against this, not
    /// against the fragment — the fragment alone resolves none of the global
    /// options, the site block it lives in, or any other import.
    main_config: PathBuf,
}

impl Caddy {
    /// Locates the binary up front and refuses if it is missing.
    ///
    /// The `Nft::locate` precedent rather than firewalld's optional one: the
    /// operator explicitly asked for this backend, so its absence is a startup
    /// error, not something to rediscover and log every twenty seconds.
    pub fn locate(conf_path: PathBuf, main_config: PathBuf) -> Result<Self, CaddyError> {
        let binary = CANDIDATES
            .iter()
            .map(Path::new)
            .find(|p| p.exists())
            .map(Path::to_path_buf)
            .ok_or_else(|| CaddyError::NotFound(CANDIDATES.join(", ")))?;
        Ok(Self { binary, conf_path, main_config })
    }

    #[cfg(test)]
    pub fn with_binary(binary: PathBuf, conf_path: PathBuf, main_config: PathBuf) -> Self {
        Self { binary, conf_path, main_config }
    }

    fn run(&self, args: &[&str]) -> Result<(), CaddyError> {
        let cmd = format!("{} {}", self.binary.display(), args.join(" "));
        let mut child = Command::new(&self.binary)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|source| CaddyError::Spawn { cmd: cmd.clone(), source })?;

        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(CaddyError::Timeout { cmd });
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(source) => return Err(CaddyError::Spawn { cmd, source }),
            }
        }
        let out = child
            .wait_with_output()
            .map_err(|source| CaddyError::Spawn { cmd: cmd.clone(), source })?;
        if out.status.success() {
            return Ok(());
        }
        Err(CaddyError::Failed {
            cmd,
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        })
    }

    /// Validate against the main config, then reload.
    ///
    /// `caddy` directly rather than `systemctl reload caddy`: it works in a
    /// container, it does not assume systemd, and it gives back the tool's own
    /// stderr instead of a unit's exit code.
    fn validate_and_reload(&self) -> Result<(), CaddyError> {
        let main = self.main_config.to_string_lossy().into_owned();
        self.run(&["validate", "--adapter", "caddyfile", "--config", &main])?;
        self.run(&["reload", "--config", &main])
    }

    /// Writes `contents`, then validates and reloads — restoring whatever was
    /// there before if either step fails.
    ///
    /// The rollback is the point. Caddy's reload is atomic and keeps the
    /// running configuration when a new one will not load, so a bad fragment
    /// cannot take the proxy down *now* — but left on disk it would take it
    /// down at the next restart, a reboot or a package upgrade later, with
    /// nothing connecting the failure to this agent.
    fn write_and_reload(&self, contents: &str, previous: Option<String>) -> Result<(), CaddyError> {
        self.put(contents)?;
        match self.validate_and_reload() {
            Ok(()) => Ok(()),
            Err(e) => {
                match &previous {
                    Some(prev) => {
                        let _ = self.put(prev);
                    }
                    None => {
                        let _ = std::fs::remove_file(&self.conf_path);
                    }
                }
                // Best-effort: the rollback restores a configuration that was
                // already live, so a failure here says nothing new.
                let _ = self.validate_and_reload();
                Err(e)
            }
        }
    }

    fn put(&self, contents: &str) -> Result<(), CaddyError> {
        if let Some(parent) = self.conf_path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| CaddyError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        atomic_write(&self.conf_path, contents.as_bytes(), CONF_MODE).map_err(|source| {
            CaddyError::Write { path: self.conf_path.clone(), source }
        })
    }
}

impl ProxyBackend for Caddy {
    fn sync(&mut self, vhosts: &[VHost]) -> Result<(), super::ProxyError> {
        let desired = render(vhosts);
        let existing = std::fs::read_to_string(&self.conf_path).ok();
        if existing.as_deref() == Some(desired.as_str()) {
            return Ok(());
        }
        self.write_and_reload(&desired, existing)?;
        tracing::info!(
            path = %self.conf_path.display(),
            vhosts = vhosts.len(),
            "published mesh services to the reverse proxy"
        );
        Ok(())
    }

    fn teardown(&mut self) -> Result<(), super::ProxyError> {
        if !self.conf_path.exists() {
            return Ok(());
        }
        std::fs::remove_file(&self.conf_path)
            .map_err(|source| CaddyError::Write { path: self.conf_path.clone(), source })?;
        self.validate_and_reload()?;
        Ok(())
    }
}

/// The generated fragment.
///
/// `http://` to the backend on purpose: 443 is the *published* port, which the
/// owning node's firewall rewrites to whatever the service really listens on,
/// and that is plain HTTP. There is no second TLS hop to verify.
#[must_use]
pub fn render(vhosts: &[VHost]) -> String {
    let mut out = String::from(
        "# Generated by wireserve. Rewritten whenever the mesh changes; edits are lost.\n",
    );
    for v in vhosts {
        // `v.host` is `<dns label>.<validated domain>` and `v.upstream` is a
        // parsed address, so neither can carry Caddyfile syntax.
        out.push_str(&format!("@{} host {}\n", matcher_name(&v.host), v.host));
        out.push_str(&format!("handle @{} {{\n", matcher_name(&v.host)));
        out.push_str(&format!("\treverse_proxy http://{}:{}\n", v.upstream, v.port));
        out.push_str("}\n");
    }
    out
}

/// A Caddy named matcher for this host: the service label alone, which is
/// already `[a-z0-9-]` and unique across the mesh.
fn matcher_name(host: &str) -> &str {
    host.split('.').next().unwrap_or(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn vh(name: &str, ip: &str) -> VHost {
        VHost {
            host: format!("{name}.int.example.com"),
            upstream: ip.parse::<Ipv4Addr>().unwrap(),
            port: 443,
        }
    }

    #[test]
    fn renders_a_matcher_and_handle_per_service() {
        let out = render(&[vh("plex", "10.0.0.50")]);
        assert!(out.contains("@plex host plex.int.example.com\n"), "{out}");
        assert!(out.contains("handle @plex {\n"), "{out}");
        assert!(out.contains("reverse_proxy http://10.0.0.50:443\n"), "{out}");
    }

    #[test]
    fn never_emits_a_site_block() {
        // A site block per service would be more specific than the operator's
        // wildcard, so Caddy would try HTTP-01 for each name and fail — and
        // it would be one ACME order per service besides.
        let out = render(&[vh("plex", "10.0.0.50"), vh("immich", "10.0.0.51")]);
        for line in out.lines() {
            assert!(
                !line.trim_start().starts_with("plex.") && !line.trim_start().starts_with("immich."),
                "looks like a site address, not a matcher: {line}"
            );
        }
        assert_eq!(out.matches("reverse_proxy").count(), 2);
    }

    #[test]
    fn the_same_vhosts_render_byte_for_byte_identically() {
        let v = [vh("plex", "10.0.0.50")];
        assert_eq!(render(&v), render(&v));
    }

    #[test]
    fn an_empty_directory_still_renders_a_valid_fragment() {
        let out = render(&[]);
        assert!(out.starts_with('#'));
        assert!(!out.contains("handle"));
    }

    #[test]
    fn the_staging_file_cannot_be_picked_up_by_an_import_glob() {
        // `atomic_write` stages at `.<name>.tmp`, so an `import conf.d/*.caddy`
        // never sees a half-written file. Pinned because the alternative is a
        // proxy that occasionally loads a truncated config.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wireserve.caddy");
        crate::fsutil::atomic_write(&path, b"x", 0o644).unwrap();
        let staged: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "wireserve.caddy")
            .collect();
        assert!(
            staged.iter().all(|n| !n.ends_with(".caddy")),
            "a leftover staging file must not match *.caddy: {staged:?}"
        );
    }
}
