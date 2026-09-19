//! firewalld: its nftables table is owned (`owner` flag — writes from
//! anyone else fail with EPERM), so instead of inserting rules we bind the
//! interface to its `trusted` zone, for this boot only (no `--permanent`),
//! through `firewall-cmd`. The planner decides when; this module only
//! observes and runs the commands.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::model::FirewalldState;

const CANDIDATES: &[&str] = &["/usr/bin/firewall-cmd", "/usr/sbin/firewall-cmd", "/bin/firewall-cmd", "/sbin/firewall-cmd"];

#[must_use]
pub fn locate() -> Option<PathBuf> {
    CANDIDATES.iter().map(Path::new).find(|p| p.is_file()).map(Path::to_path_buf)
}

#[must_use]
pub fn state_args() -> Vec<String> {
    vec!["--state".into()]
}

#[must_use]
pub fn zone_args(ifname: &str, permanent: bool) -> Vec<String> {
    let mut args = Vec::new();
    if permanent {
        args.push("--permanent".into());
    }
    args.push(format!("--get-zone-of-interface={ifname}"));
    args
}

/// Runtime only — deliberately never `--permanent`: the binding must not
/// outlive the agent (a reboot, or a crash followed by an uninstall, must
/// not leave the interface name trusted for whatever uses it next).
#[must_use]
pub fn trust_args(ifname: &str) -> Vec<String> {
    vec!["--zone=trusted".into(), format!("--change-interface={ifname}")]
}

#[must_use]
pub fn untrust_args(ifname: &str) -> Vec<String> {
    vec!["--zone=trusted".into(), format!("--remove-interface={ifname}")]
}

/// `--get-zone-of-interface` prints the zone and exits 0, or prints
/// `no zone` and exits non-zero (2) when the interface has none.
#[must_use]
pub fn parse_zone(success: bool, stdout: &str) -> Option<String> {
    let zone = stdout.trim();
    (success && !zone.is_empty() && zone != "no zone").then(|| zone.to_string())
}

fn run(bin: &Path, args: &[String]) -> Option<(bool, String)> {
    let out = Command::new(bin).args(args).output().ok()?;
    Some((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}

/// firewalld's view of `ifname`. Anything that prevents a clear answer —
/// no binary, not running, D-Bus unreachable (e.g. inside a container) —
/// is `Unavailable`, and the planner then does nothing on this side.
#[must_use]
pub fn observe(ifname: &str) -> FirewalldState {
    let Some(bin) = locate() else {
        return FirewalldState::Unavailable;
    };
    match run(&bin, &state_args()) {
        Some((true, _)) => {}
        _ => return FirewalldState::Unavailable,
    }
    let zone = |permanent| {
        run(&bin, &zone_args(ifname, permanent)).and_then(|(ok, out)| parse_zone(ok, &out))
    };
    FirewalldState::Running {
        runtime_zone: zone(false),
        permanent_zone: zone(true),
    }
}

pub fn execute(args: &[String]) -> Result<(), String> {
    let bin = locate().ok_or("firewall-cmd not found")?;
    let out = Command::new(&bin)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {}: {e}", bin.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "firewall-cmd {} exited with {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_is_exact_and_runtime_only() {
        assert_eq!(state_args(), ["--state"]);
        assert_eq!(zone_args("wg0", false), ["--get-zone-of-interface=wg0"]);
        assert_eq!(zone_args("wg0", true), ["--permanent", "--get-zone-of-interface=wg0"]);
        assert_eq!(trust_args("wg0"), ["--zone=trusted", "--change-interface=wg0"]);
        assert_eq!(untrust_args("wg0"), ["--zone=trusted", "--remove-interface=wg0"]);
        for args in [trust_args("wg0"), untrust_args("wg0")] {
            assert!(!args.iter().any(|a| a == "--permanent"), "{args:?}");
        }
    }

    #[test]
    fn zone_output_parsing() {
        // As printed by firewalld 2.5.0 on SteamOS.
        assert_eq!(parse_zone(true, "public\n"), Some("public".into()));
        assert_eq!(parse_zone(true, "trusted\n"), Some("trusted".into()));
        assert_eq!(parse_zone(false, "no zone\n"), None);
        assert_eq!(parse_zone(true, "no zone\n"), None);
        assert_eq!(parse_zone(false, ""), None);
        assert_eq!(parse_zone(true, ""), None);
    }
}
