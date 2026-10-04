//! `wireserve-coordinator setup …` (PLAN.md M47): what a first install
//! leaves out, each when its time comes.
//!
//! `install` asks only what a working mesh needs. A domain and a login
//! server each need something the person may not have yet — a domain and a
//! DNS token, a login server — and each only makes sense once they know why
//! they would want it. So each is a verb of its own, which
//! starts by saying what it is for in terms of the person's own mesh, and
//! can be run, run again, or turned off at any time.
//!
//! Like `install`, every question has a flag and a terminal is never
//! required; at a terminal, the current setting is each question's default.
//! Only the keys a verb is about are touched in `coordinator.env`, and the
//! coordinator is restarted to take them.

pub mod domain;
pub mod login;

use std::io::IsTerminal;
use std::path::Path;

use crate::install::envfile::{self, Change};
use crate::install::questions::{self, AskError};

#[derive(clap::Subcommand)]
pub enum SetupCommand {
    /// Real names for your services, like plex.home.example.com: they work
    /// on phones too, and get HTTPS
    Domain(domain::DomainArgs),
    /// Let access follow people instead of devices, through a login server
    /// you run (Pocket ID, Authentik, Keycloak, …)
    Login(login::LoginArgs),
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("setup must be run as root (sudo), on the coordinator's machine")]
    NotRoot,
    #[error("the coordinator is not installed here (no {0}); run `sudo wireserve-coordinator install` first")]
    NotInstalled(&'static str),
    #[error(transparent)]
    Ask(#[from] AskError),
    #[error("{0}")]
    Failed(String),
}

pub fn run(command: SetupCommand) -> Result<(), SetupError> {
    crate::install::require_root().map_err(|_| SetupError::NotRoot)?;
    let env_text = std::fs::read_to_string(crate::install::ENV_DEST)
        .map_err(|_| SetupError::NotInstalled(crate::install::ENV_DEST))?;
    let ctx = Ctx { interactive: std::io::stdin().is_terminal(), env_text };
    match command {
        SetupCommand::Domain(args) => domain::run(&ctx, &args),
        SetupCommand::Login(args) => login::run(&ctx, &args),
    }
}

/// What every verb starts from.
pub struct Ctx {
    /// Whether stdin is a terminal: only then is anything asked.
    pub interactive: bool,
    /// `coordinator.env` as it is now.
    pub env_text: String,
}

impl Ctx {
    /// A setting as the env file has it, empty counting as unset.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<String> {
        envfile::get(&self.env_text, key).filter(|v| !v.is_empty())
    }

    /// The running coordinator's admin side, to look at the mesh with.
    #[must_use]
    pub fn admin(&self) -> Option<Admin> {
        Admin::from_env(&self.env_text)
    }
}

/// Shows what is about to change and asks to go ahead, unless `--yes` or
/// no terminal.
pub fn confirm(ctx: &Ctx, yes: bool, summary: &[String]) -> Result<(), SetupError> {
    if !ctx.interactive || yes {
        return Ok(());
    }
    eprintln!();
    eprintln!("Ready to save:");
    for line in summary {
        eprintln!("  {line}");
    }
    eprintln!();
    if questions::ask_yes_no("Save, and restart the coordinator?", true) {
        Ok(())
    } else {
        Err(AskError::Declined.into())
    }
}

/// Writes `changes` into `coordinator.env` and restarts the coordinator
/// to take them. Returns whether anything changed.
pub fn save(ctx: &Ctx, changes: &[(&str, Change)]) -> Result<bool, SetupError> {
    let text = envfile::apply(&ctx.env_text, changes);
    if text == ctx.env_text {
        println!("nothing to change; {} is as it was", crate::install::ENV_DEST);
        return Ok(false);
    }
    crate::install::write_env_file(&text).map_err(|e| SetupError::Failed(e.to_string()))?;
    let unit = crate::install::UNIT_NAME;
    if crate::install::systemctl_ok(&["is-active", "--quiet", unit]) {
        // A few setups in a row would otherwise run into systemd's start
        // limit (five in ten seconds), and a restart asked for by hand
        // should not be refused for it.
        let _ = crate::install::systemctl_ok(&["reset-failed", unit]);
        crate::install::systemctl(&["restart", unit]).map_err(|e| SetupError::Failed(e.to_string()))?;
        println!("saved; restarted {unit}");
    } else {
        println!("saved; {unit} is not running — `sudo systemctl start {unit}` starts it with these settings");
    }
    Ok(true)
}

/// The coordinator's admin API on this machine, with the key it uses.
pub struct Admin {
    base: String,
    token: String,
    http: reqwest::blocking::Client,
}

impl Admin {
    fn from_env(env_text: &str) -> Option<Self> {
        let addr = envfile::get(env_text, "WIRESERVE_ADMIN_LISTEN_ADDR")
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| "127.0.0.1:47821".into());
        let state_dir = crate::install::state_dir(env_text);
        let token = crate::install::admin_token(env_text, Path::new(&state_dir))?;
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;
        Some(Self { base: format!("http://{addr}"), token, http })
    }

    /// `GET` an admin path. `None` when the coordinator does not answer —
    /// it may be stopped — which every caller treats as "can't say".
    pub fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Option<T> {
        let resp = self.http.get(format!("{}{path}", self.base)).bearer_auth(&self.token).send().ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json().ok()
    }

    pub fn services(&self) -> Option<Vec<wireserve_types::AdminServiceInfo>> {
        self.get::<wireserve_types::AdminServicesResponse>("/admin/services").map(|r| r.services)
    }

    pub fn grants(&self) -> Option<Vec<wireserve_types::GrantInfo>> {
        self.get::<wireserve_types::GrantsResponse>("/admin/grants").map(|r| r.grants)
    }

    pub fn nodes(&self) -> Option<Vec<String>> {
        self.get::<wireserve_types::AdminPeersResponse>("/admin/peers").map(|r| r.peers.into_iter().map(|p| p.name).collect())
    }
}

/// Whether every device gets the same access: no grant names a tag or a
/// group of people, only `everyone`. Then a person's groups — or a sign-in
/// — would change nothing yet.
#[must_use]
pub fn same_for_every_device(grants: &[wireserve_types::GrantInfo]) -> bool {
    grants.iter().all(|g| g.source == wireserve_types::GrantSource::Everyone)
}

/// The `oidc:` groups some grant names.
#[must_use]
pub fn people_groups(grants: &[wireserve_types::GrantInfo]) -> Vec<String> {
    let mut out: Vec<String> = grants
        .iter()
        .filter_map(|g| match &g.source {
            wireserve_types::GrantSource::Oidc(name) => Some(name.clone()),
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `Set` the value, or `Clear` the key when it is the built-in default —
/// so a file never pins a default that a later version might improve.
#[must_use]
pub fn set_unless_default(value: &str, default: &str) -> Change {
    if value == default {
        Change::Clear
    } else {
        Change::Set(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireserve_types::{GrantInfo, GrantSource};

    #[test]
    fn only_grants_to_everyone_treat_every_device_the_same() {
        let everyone = GrantInfo { source: GrantSource::Everyone, group: "default".into() };
        assert!(same_for_every_device(&[]));
        assert!(same_for_every_device(std::slice::from_ref(&everyone)));
        let family = GrantInfo { source: GrantSource::Oidc("family".into()), group: "media".into() };
        let ops = GrantInfo { source: GrantSource::Tag("ops".into()), group: "infra".into() };
        assert!(!same_for_every_device(&[everyone.clone(), family.clone()]));
        assert!(!same_for_every_device(std::slice::from_ref(&ops)));
        assert_eq!(people_groups(&[everyone, family.clone(), ops, family]), ["family"]);
    }
}
