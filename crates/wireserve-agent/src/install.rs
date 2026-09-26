//! `wireserve install` — installs the binary and the right systemd
//! unit for an instance in one step, then hands off to the same `join`
//! logic `wireserve join` uses on its own (see `main.rs`'s
//! `cmd_join`, which `cmd_install` calls directly — this module supplies
//! only the install-specific primitives, so the token prompt and every
//! other bit of `join`'s behaviour stays in exactly one place).
//!
//! The two unit files are `include_str!`'d at compile time rather than
//! read from `deploy/systemd/` on disk: what gets installed can never
//! drift from the binary that installed it, which a separate install
//! script reading those files at runtime couldn't guarantee.
//!
//! Run again on a node that has already joined, and given no join arguments,
//! it upgrades instead: the same binary and unit installs, no join, and a
//! restart of every running agent so none keeps executing the old binary.
//! That makes `scp wireserve host:/tmp/ && ssh host sudo /tmp/wireserve install`
//! the whole update.
//!
//! It also creates the `wireserve` group whose members may use the daemon
//! without sudo (see `ipc::server::serve`), but never adds anyone to it.
//!
//! The binary is `wireserve`; the systemd unit keeps the name
//! `wireserve-agent`, since it names the daemon and renaming it would
//! break `systemctl restart wireserve-agent` on every running deployment.
//!
//! Linux/systemd only — Quadlet/podman deployments keep using
//! `deploy/quadlet/*.container` by hand, as already documented.

use crate::paths::Instance;

const UNIT_DEFAULT: &str = include_str!("../../../deploy/systemd/wireserve-agent.service");
const UNIT_TEMPLATE: &str = include_str!("../../../deploy/systemd/wireserve-agent@.service");
const BIN_DEST: &str = "/usr/local/bin/wireserve";
/// Where earlier versions put the binary, before it was called `wireserve`.
const OLD_BIN_DEST: &str = "/usr/local/bin/wireserve-agent";
const UNIT_DEFAULT_DEST: &str = "/etc/systemd/system/wireserve-agent.service";
const UNIT_TEMPLATE_DEST: &str = "/etc/systemd/system/wireserve-agent@.service";
/// The TLS terminator's units (PLAN.md M33), installed beside the agent's.
const TLS_UNIT_DEFAULT: &str = include_str!("../../../deploy/systemd/wireserve-tls.service");
const TLS_UNIT_TEMPLATE: &str = include_str!("../../../deploy/systemd/wireserve-tls@.service");
const TLS_UNIT_DEFAULT_DEST: &str = "/etc/systemd/system/wireserve-tls.service";
const TLS_UNIT_TEMPLATE_DEST: &str = "/etc/systemd/system/wireserve-tls@.service";

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("wireserve install must be run as root (sudo)")]
    NotRoot,
    #[error("wireserve install only supports Linux with systemd")]
    UnsupportedPlatform,
    #[error("could not install the binary to {0}: {1}")]
    InstallBinary(&'static str, std::io::Error),
    #[error("could not create the `{0}` group: {1}")]
    Group(String, String),
    #[error("could not create the `{0}` user: {1}")]
    User(String, String),
    #[error("could not install the systemd unit to {0}: {1}")]
    InstallUnit(&'static str, std::io::Error),
    #[error("could not run `systemctl {0}`: {1}")]
    SystemctlSpawn(String, std::io::Error),
    #[error("`systemctl {0}` failed: {1}")]
    Systemctl(String, String),
}

/// The systemd unit content, install path, and unit name to enable, for
/// a given instance. Pure — no filesystem access — so it's testable on
/// its own.
fn unit_for(instance: &Instance) -> (&'static str, &'static str, String) {
    if instance.is_default() {
        (UNIT_DEFAULT, UNIT_DEFAULT_DEST, "wireserve-agent".to_string())
    } else {
        (UNIT_TEMPLATE, UNIT_TEMPLATE_DEST, format!("wireserve-agent@{}", instance.name()))
    }
}

#[cfg(target_os = "linux")]
pub fn require_root() -> Result<(), InstallError> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(InstallError::NotRoot)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn require_root() -> Result<(), InstallError> {
    Err(InstallError::UnsupportedPlatform)
}

/// Copies the currently running binary to `/usr/local/bin/wireserve-agent`,
/// unless it's already running from exactly there.
pub fn install_self() -> Result<(), InstallError> {
    let current = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| InstallError::InstallBinary(BIN_DEST, e))?;
    if current == std::path::Path::new(BIN_DEST) {
        return Ok(());
    }
    let bytes = std::fs::read(&current).map_err(|e| InstallError::InstallBinary(BIN_DEST, e))?;
    crate::fsutil::atomic_write(std::path::Path::new(BIN_DEST), &bytes, 0o755)
        .map_err(|e| InstallError::InstallBinary(BIN_DEST, e))
}

/// Whether something is still at the path earlier versions installed the
/// binary to, as `wireserve-agent`. `install` never touches it — it may be
/// someone's own arrangement, or still what a script points at — it only
/// says so, since nothing uses it any more.
pub fn old_binary_present() -> bool {
    std::fs::symlink_metadata(OLD_BIN_DEST).is_ok()
}

/// Creates the group the daemon shares its socket with, if sharing is on
/// and it does not exist yet. Returns its name when it exists afterwards.
/// Must run before the daemon starts: it looks the group up once, at bind.
pub fn ensure_socket_group() -> Result<Option<String>, InstallError> {
    let Some(name) = crate::ipc::server::socket_group_name() else {
        return Ok(None);
    };
    if crate::ipc::server::group_exists(&name) {
        return Ok(Some(name));
    }
    let output = std::process::Command::new("groupadd")
        .args(["--system", &name])
        .output()
        .map_err(|e| InstallError::Group(name.clone(), e.to_string()))?;
    if output.status.success() {
        Ok(Some(name))
    } else {
        Err(InstallError::Group(name, String::from_utf8_lossy(&output.stderr).trim().to_string()))
    }
}

/// Creates the TLS terminator's system user (and its group, of the same
/// name), if it does not exist yet (PLAN.md M33). The daemon hands the
/// terminator's socket to that group; the terminator runs as that user.
pub fn ensure_tls_user() -> Result<String, InstallError> {
    let name = crate::ipc::tls::tls_group_name().unwrap_or_else(|| crate::ipc::tls::DEFAULT_TLS_GROUP.to_string());
    if crate::ipc::server::group_exists(&name) && user_exists(&name) {
        return Ok(name);
    }
    let output = std::process::Command::new("useradd")
        .args(["--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", &name])
        .output()
        .map_err(|e| InstallError::User(name.clone(), e.to_string()))?;
    if output.status.success() {
        Ok(name)
    } else {
        Err(InstallError::User(name, String::from_utf8_lossy(&output.stderr).trim().to_string()))
    }
}

fn user_exists(name: &str) -> bool {
    std::process::Command::new("id").args(["-u", name]).output().is_ok_and(|o| o.status.success())
}

/// The terminator's unit content, install path and unit name for
/// `instance`. Pure, like [`unit_for`].
fn tls_unit_for(instance: &Instance) -> (&'static str, &'static str, String) {
    if instance.is_default() {
        (TLS_UNIT_DEFAULT, TLS_UNIT_DEFAULT_DEST, "wireserve-tls".to_string())
    } else {
        (TLS_UNIT_TEMPLATE, TLS_UNIT_TEMPLATE_DEST, format!("wireserve-tls@{}", instance.name()))
    }
}

/// Writes the terminator's unit for `instance`, and the other kind too if it
/// is already on disk; returns the unit name to enable.
pub fn install_tls_unit(instance: &Instance) -> Result<String, InstallError> {
    let (content, dest, unit_name) = tls_unit_for(instance);
    crate::fsutil::atomic_write(std::path::Path::new(dest), content.as_bytes(), 0o644)
        .map_err(|e| InstallError::InstallUnit(dest, e))?;
    let (other, other_dest) = if instance.is_default() {
        (TLS_UNIT_TEMPLATE, TLS_UNIT_TEMPLATE_DEST)
    } else {
        (TLS_UNIT_DEFAULT, TLS_UNIT_DEFAULT_DEST)
    };
    if std::path::Path::new(other_dest).exists() {
        crate::fsutil::atomic_write(std::path::Path::new(other_dest), other.as_bytes(), 0o644)
            .map_err(|e| InstallError::InstallUnit(other_dest, e))?;
    }
    Ok(unit_name)
}

/// Writes the systemd unit for `instance` and returns the unit name
/// (`wireserve-agent` or `wireserve-agent@<instance>`) for the caller to
/// `daemon-reload` and `enable --now`.
pub fn install_unit(instance: &Instance) -> Result<String, InstallError> {
    let (content, dest, unit_name) = unit_for(instance);
    crate::fsutil::atomic_write(std::path::Path::new(dest), content.as_bytes(), 0o644)
        .map_err(|e| InstallError::InstallUnit(dest, e))?;
    Ok(unit_name)
}

fn systemctl(args: &[&str]) -> Result<(), InstallError> {
    let cmdline = args.join(" ");
    let output = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| InstallError::SystemctlSpawn(cmdline.clone(), e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(InstallError::Systemctl(cmdline, String::from_utf8_lossy(&output.stderr).trim().to_string()))
    }
}

/// Install is an upgrade — no join — when this instance already holds an
/// identity and the caller passed nothing to join with. Any join argument
/// means they want a (re-)join, which is what it always did.
pub fn is_upgrade(registered: bool, join_args_given: bool) -> bool {
    registered && !join_args_given
}

/// Rewrites the *other* kind of agent unit too, if it is on disk. The
/// binary is shared by every instance, and a template unit left pointing at
/// an old path or missing a capability would break instances this run was
/// not asked about, the next time one restarts.
pub fn refresh_other_unit(instance: &Instance) -> Result<(), InstallError> {
    let (content, dest) = if instance.is_default() {
        (UNIT_TEMPLATE, UNIT_TEMPLATE_DEST)
    } else {
        (UNIT_DEFAULT, UNIT_DEFAULT_DEST)
    };
    if std::path::Path::new(dest).exists() {
        crate::fsutil::atomic_write(std::path::Path::new(dest), content.as_bytes(), 0o644)
            .map_err(|e| InstallError::InstallUnit(dest, e))?;
    }
    Ok(())
}

/// The agent units systemd is running right now, as full unit names
/// (`wireserve-agent.service`, `wireserve-agent@work.service`).
pub fn active_agent_units() -> Result<Vec<String>, InstallError> {
    let args = ["list-units", "--plain", "--no-legend", "--no-pager", "--state=active", "wireserve-agent*.service"];
    let output = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| InstallError::SystemctlSpawn(args.join(" "), e))?;
    if !output.status.success() {
        return Err(InstallError::Systemctl(
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    Ok(parse_active_units(&String::from_utf8_lossy(&output.stdout)))
}

/// First column of `systemctl list-units --plain --no-legend`, kept only
/// when it is an agent unit — the glob also matches nothing else today, but
/// a restart is not something to do on a pattern's say-so.
fn parse_active_units(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| {
            *name == "wireserve-agent.service"
                || (name.starts_with("wireserve-agent@") && name.ends_with(".service"))
        })
        .map(str::to_string)
        .collect()
}

pub fn systemctl_restart(unit: &str) -> Result<(), InstallError> {
    systemctl(&["restart", unit])
}

pub fn systemctl_daemon_reload() -> Result<(), InstallError> {
    systemctl(&["daemon-reload"])
}

pub fn systemctl_enable_now(unit: &str) -> Result<(), InstallError> {
    systemctl(&["enable", "--now", unit])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_for_default_instance() {
        let (content, dest, name) = unit_for(&Instance::default());
        assert_eq!(content, UNIT_DEFAULT);
        assert_eq!(dest, "/etc/systemd/system/wireserve-agent.service");
        assert_eq!(name, "wireserve-agent");
    }

    #[test]
    fn unit_for_named_instance() {
        let instance = Instance::new("work").unwrap();
        let (content, dest, name) = unit_for(&instance);
        assert_eq!(content, UNIT_TEMPLATE);
        assert_eq!(dest, "/etc/systemd/system/wireserve-agent@.service");
        assert_eq!(name, "wireserve-agent@work");
    }

    #[test]
    fn install_upgrades_only_a_registered_node_given_nothing_to_join_with() {
        assert!(is_upgrade(true, false));
        assert!(!is_upgrade(true, true), "a URL or token means a re-join");
        assert!(!is_upgrade(false, false), "nothing to upgrade on a fresh node");
        assert!(!is_upgrade(false, true));
    }

    #[test]
    fn active_units_are_read_from_the_listing_and_only_agent_units_kept() {
        let listing = "wireserve-agent.service loaded active running WireServe agent\n\
                       wireserve-agent@work.service loaded active running WireServe agent (work)\n\
                       wireserve-agent-extra.service loaded active running something else\n\
                       \n";
        assert_eq!(
            parse_active_units(listing),
            vec!["wireserve-agent.service".to_string(), "wireserve-agent@work.service".to_string()]
        );
        assert!(parse_active_units("").is_empty());
    }

    #[test]
    fn the_terminator_runs_beside_its_own_agent_as_its_own_user() {
        let (content, dest, name) = tls_unit_for(&Instance::default());
        assert_eq!((dest, name.as_str()), ("/etc/systemd/system/wireserve-tls.service", "wireserve-tls"));
        assert!(content.contains(&format!("ExecStart={BIN_DEST} tls-serve")));
        assert!(content.contains("PartOf=wireserve-agent.service") && content.contains("WantedBy=wireserve-agent.service"));
        assert!(content.contains("User=wireserve-tls") && content.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"));

        let (content, _, name) = tls_unit_for(&Instance::new("work").unwrap());
        assert_eq!(name, "wireserve-tls@work");
        assert!(content.contains(&format!("ExecStart={BIN_DEST} --instance %i tls-serve")));
        assert!(content.contains("PartOf=wireserve-agent@%i.service"));
        // The agent makes the directory the terminator's socket lives in.
        assert!(UNIT_DEFAULT.contains("RuntimeDirectory=wireserve wireserve-tls\n"));
        assert!(UNIT_TEMPLATE.contains("RuntimeDirectory=wireserve-%i wireserve-tls-%i\n"));
    }

    #[test]
    fn the_unit_starts_the_renamed_binary() {
        assert!(UNIT_DEFAULT.contains(&format!("ExecStart={BIN_DEST} daemon")));
        assert!(UNIT_TEMPLATE.contains(&format!("ExecStart={BIN_DEST} --instance %i daemon")));
    }
}
