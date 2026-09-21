//! `wireserve-agent install` — installs the binary and the right systemd
//! unit for an instance in one step, then hands off to the same `join`
//! logic `wireserve-agent join` uses on its own (see `main.rs`'s
//! `cmd_join`, which `cmd_install` calls directly — this module supplies
//! only the install-specific primitives, so the token prompt and every
//! other bit of `join`'s behaviour stays in exactly one place).
//!
//! The two unit files are `include_str!`'d at compile time rather than
//! read from `deploy/systemd/` on disk: what gets installed can never
//! drift from the binary that installed it, which a separate install
//! script reading those files at runtime couldn't guarantee.
//!
//! Linux/systemd only — Quadlet/podman deployments keep using
//! `deploy/quadlet/*.container` by hand, as already documented.

use crate::paths::Instance;

const UNIT_DEFAULT: &str = include_str!("../../../deploy/systemd/wireserve-agent.service");
const UNIT_TEMPLATE: &str = include_str!("../../../deploy/systemd/wireserve-agent@.service");
const BIN_DEST: &str = "/usr/local/bin/wireserve-agent";
const UNIT_DEFAULT_DEST: &str = "/etc/systemd/system/wireserve-agent.service";
const UNIT_TEMPLATE_DEST: &str = "/etc/systemd/system/wireserve-agent@.service";

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("wireserve-agent install must be run as root (sudo)")]
    NotRoot,
    #[error("wireserve-agent install only supports Linux with systemd")]
    UnsupportedPlatform,
    #[error("could not install the binary to {0}: {1}")]
    InstallBinary(&'static str, std::io::Error),
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
}
