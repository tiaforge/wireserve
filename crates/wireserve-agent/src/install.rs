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
const UNIT_DEFAULT_DEST: &str = "/etc/systemd/system/wireserve-agent.service";
const UNIT_TEMPLATE_DEST: &str = "/etc/systemd/system/wireserve-agent@.service";
/// The TLS terminator's units (PLAN.md M33), installed beside the agent's.
const TLS_UNIT_DEFAULT: &str = include_str!("../../../deploy/systemd/wireserve-tls.service");
const TLS_UNIT_TEMPLATE: &str = include_str!("../../../deploy/systemd/wireserve-tls@.service");
const TLS_UNIT_DEFAULT_DEST: &str = "/etc/systemd/system/wireserve-tls.service";
const TLS_UNIT_TEMPLATE_DEST: &str = "/etc/systemd/system/wireserve-tls@.service";
/// The socket systemd holds for it (PLAN.md M35).
const TLS_SOCKET_DEFAULT: &str = include_str!("../../../deploy/systemd/wireserve-tls.socket");
const TLS_SOCKET_TEMPLATE: &str = include_str!("../../../deploy/systemd/wireserve-tls@.socket");
const TLS_SOCKET_DEFAULT_DEST: &str = "/etc/systemd/system/wireserve-tls.socket";
const TLS_SOCKET_TEMPLATE_DEST: &str = "/etc/systemd/system/wireserve-tls@.socket";
const SYSTEMD_DIR: &str = "/etc/systemd/system";

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
    #[error("could not write the terminator's port to {0}: {1}")]
    TlsPort(String, std::io::Error),
    #[error("TLS port {0} is already the terminator's port of another instance ({1})")]
    TlsPortTaken(u16, String),
    #[error("TLS port {0} is in use on this host")]
    TlsPortInUse(u16),
    #[error("no free TLS port found above {0}; pass one with --tls-port")]
    NoFreeTlsPort(u16),
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

/// Copies the currently running binary to `/usr/local/bin/wireserve`,
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

/// The terminator's socket unit content and install path for `instance`,
/// and the name of its port drop-in's directory. Pure, like [`unit_for`].
fn tls_socket_for(instance: &Instance) -> (&'static str, &'static str, String) {
    if instance.is_default() {
        (TLS_SOCKET_DEFAULT, TLS_SOCKET_DEFAULT_DEST, "wireserve-tls.socket.d".to_string())
    } else {
        (TLS_SOCKET_TEMPLATE, TLS_SOCKET_TEMPLATE_DEST, format!("wireserve-tls@{}.socket.d", instance.name()))
    }
}

/// What [`install_tls_units`] did.
pub struct TlsUnits {
    /// The service to enable, as `wireserve-tls[@<instance>]`.
    pub service: String,
    /// Its socket, as `wireserve-tls[@<instance>].socket`.
    pub socket: String,
    /// The port its socket listens on.
    pub port: u16,
    /// The socket's unit or port changed: it must be started again to
    /// listen where it now says.
    pub changed: bool,
    /// Worth telling the operator: a port chosen or kept.
    pub note: Option<String>,
}

/// Writes the terminator's service and socket units for `instance`, and the
/// other kind too if it is already on disk; then its port (PLAN.md M35).
///
/// The port: `tls_port` when given, written to the socket's drop-in. Without
/// it a drop-in already there is kept as it is — never silently replaced.
/// Otherwise the default instance listens on [`wireserve_types::TLS_LISTEN_PORT`],
/// as its unit says, and a named instance gets the first port above it no
/// other instance has and nothing on this host listens on: every instance's
/// socket listens on every address, so no two may share one.
pub fn install_tls_units(instance: &Instance, tls_port: Option<u16>) -> Result<TlsUnits, InstallError> {
    let (content, dest, service) = tls_unit_for(instance);
    write_unit(content, dest)?;
    let (socket_content, socket_dest, dropin_dir) = tls_socket_for(instance);
    let mut changed = write_unit(socket_content, socket_dest)?;
    let (other, other_dest, other_socket, other_socket_dest) = if instance.is_default() {
        (TLS_UNIT_TEMPLATE, TLS_UNIT_TEMPLATE_DEST, TLS_SOCKET_TEMPLATE, TLS_SOCKET_TEMPLATE_DEST)
    } else {
        (TLS_UNIT_DEFAULT, TLS_UNIT_DEFAULT_DEST, TLS_SOCKET_DEFAULT, TLS_SOCKET_DEFAULT_DEST)
    };
    if std::path::Path::new(other_dest).exists() {
        write_unit(other, other_dest)?;
        write_unit(other_socket, other_socket_dest)?;
    }

    let dropin_dir = std::path::Path::new(SYSTEMD_DIR).join(&dropin_dir);
    let dropin = dropin_dir.join("port.conf");
    let current = std::fs::read_to_string(&dropin).ok().and_then(|t| parse_listen_port(&t));
    let others = other_instance_ports(instance);
    let taken = |port: u16| others.iter().find(|(_, p)| *p == port).map(|(name, _)| name.clone());
    let socket = format!("{service}.socket");
    let (port, note) = match (tls_port, current) {
        (Some(port), current) => {
            if let Some(owner) = taken(port) {
                return Err(InstallError::TlsPortTaken(port, owner));
            }
            let ours = current.unwrap_or(if instance.is_default() { wireserve_types::TLS_LISTEN_PORT } else { 0 }) == port;
            if !ours && !port_free(port) {
                return Err(InstallError::TlsPortInUse(port));
            }
            (port, (!ours).then(|| format!("the TLS terminator now listens on port {port}")))
        }
        (None, Some(port)) => (port, None),
        (None, None) if instance.is_default() => (wireserve_types::TLS_LISTEN_PORT, None),
        (None, None) => {
            let from = wireserve_types::TLS_LISTEN_PORT;
            let taken_ports: std::collections::BTreeSet<u16> = others.iter().map(|(_, p)| *p).collect();
            let port = pick_tls_port(from, &taken_ports, port_free).ok_or(InstallError::NoFreeTlsPort(from))?;
            (port, Some(format!("this instance's TLS terminator listens on port {port} (`--tls-port` to change it)")))
        }
    };
    let wanted = dropin_content(port);
    let default_unit = instance.is_default() && port == wireserve_types::TLS_LISTEN_PORT && current.is_none();
    if !default_unit && std::fs::read_to_string(&dropin).ok().as_deref() != Some(wanted.as_str()) {
        let err = |e| InstallError::TlsPort(dropin.display().to_string(), e);
        std::fs::create_dir_all(&dropin_dir).map_err(err)?;
        crate::fsutil::atomic_write(&dropin, wanted.as_bytes(), 0o644).map_err(err)?;
        changed = true;
    }
    Ok(TlsUnits { service, socket, port, changed, note })
}

/// Writes `content` to `dest` unless it already holds it; whether it wrote.
fn write_unit(content: &str, dest: &'static str) -> Result<bool, InstallError> {
    if std::fs::read_to_string(dest).is_ok_and(|c| c == content) {
        return Ok(false);
    }
    crate::fsutil::atomic_write(std::path::Path::new(dest), content.as_bytes(), 0o644)
        .map_err(|e| InstallError::InstallUnit(dest, e))?;
    Ok(true)
}

/// A socket drop-in listening on `port` instead of the unit's own port.
fn dropin_content(port: u16) -> String {
    format!(
        "# Written by `wireserve install` (PLAN.md M35): where this TLS terminator\n\
         # listens. The agent rewrites its service addresses' 443 to it.\n\
         [Socket]\n\
         ListenStream=\n\
         ListenStream=0.0.0.0:{port}\n"
    )
}

/// The port the last `ListenStream=` of a socket unit or drop-in names.
fn parse_listen_port(text: &str) -> Option<u16> {
    // An empty one clears those before it; so, last, it clears them all.
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("ListenStream="))
        .next_back()
        .filter(|v| !v.is_empty())
        .and_then(|v| v.rsplit(':').next())
        .and_then(|p| p.parse().ok())
}

/// The first port after `from` that is neither `taken` nor in use.
fn pick_tls_port(from: u16, taken: &std::collections::BTreeSet<u16>, free: impl Fn(u16) -> bool) -> Option<u16> {
    // Below the Kubernetes NodePort range, like `from` itself.
    (from.saturating_add(1)..30000).find(|p| !taken.contains(p) && free(*p))
}

/// Every other instance's terminator port on this host: the default
/// instance's always — its unit's own, unless a drop-in says otherwise —
/// and each named instance's that has a drop-in.
fn other_instance_ports(instance: &Instance) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    if !instance.is_default() {
        let port = std::fs::read_to_string(std::path::Path::new(SYSTEMD_DIR).join("wireserve-tls.socket.d/port.conf"))
            .ok()
            .and_then(|t| parse_listen_port(&t))
            .unwrap_or(wireserve_types::TLS_LISTEN_PORT);
        out.push(("the default instance".to_string(), port));
    }
    let own = format!("wireserve-tls@{}.socket.d", instance.name());
    let Ok(entries) = std::fs::read_dir(SYSTEMD_DIR) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(other) = name.strip_prefix("wireserve-tls@").and_then(|n| n.strip_suffix(".socket.d")) else {
            continue;
        };
        if !instance.is_default() && name == own {
            continue;
        }
        if let Some(port) = std::fs::read_to_string(entry.path().join("port.conf")).ok().and_then(|t| parse_listen_port(&t)) {
            out.push((format!("instance {other}"), port));
        }
    }
    out
}

/// Whether nothing on this host listens on `port` on any address.
fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).is_ok()
}

/// Makes the terminator listen where its socket unit now says: stopped
/// while its socket starts again, when the socket changed (a first install
/// of it, or another port), then enabled and started with its socket.
pub fn start_tls(units: &TlsUnits) -> Result<(), InstallError> {
    if units.changed {
        systemctl(&["stop", &units.service])?;
        systemctl(&["restart", &units.socket])?;
    }
    systemctl(&["enable", "--now", &units.socket])?;
    systemctl(&["enable", "--now", &units.service])
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
        assert!(content.contains("User=wireserve-tls") && content.contains("CapabilityBoundingSet=\n"));
        assert!(!content.contains("AmbientCapabilities"), "no privilege at all (PLAN.md M35)");
        assert!(content.contains("Requires=wireserve-tls.socket"));

        let (content, _, name) = tls_unit_for(&Instance::new("work").unwrap());
        assert_eq!(name, "wireserve-tls@work");
        assert!(content.contains(&format!("ExecStart={BIN_DEST} --instance %i tls-serve")));
        assert!(content.contains("PartOf=wireserve-agent@%i.service") && content.contains("Requires=wireserve-tls@%i.socket"));
        // The agent makes the directory the terminator's socket lives in.
        assert!(UNIT_DEFAULT.contains("RuntimeDirectory=wireserve wireserve-tls\n"));
        assert!(UNIT_TEMPLATE.contains("RuntimeDirectory=wireserve-%i wireserve-tls-%i\n"));
    }

    #[test]
    fn the_terminators_socket_listens_on_the_default_port_everywhere() {
        let (content, dest, dropins) = tls_socket_for(&Instance::default());
        assert_eq!((dest, dropins.as_str()), ("/etc/systemd/system/wireserve-tls.socket", "wireserve-tls.socket.d"));
        assert_eq!(parse_listen_port(content), Some(wireserve_types::TLS_LISTEN_PORT));
        assert!(content.contains("ListenStream=0.0.0.0:"));
        let (content, dest, dropins) = tls_socket_for(&Instance::new("work").unwrap());
        assert_eq!((dest, dropins.as_str()), ("/etc/systemd/system/wireserve-tls@.socket", "wireserve-tls@work.socket.d"));
        assert_eq!(parse_listen_port(content), Some(wireserve_types::TLS_LISTEN_PORT));
    }

    #[test]
    fn a_port_drop_in_replaces_the_units_port_and_reads_back() {
        let text = dropin_content(12443);
        assert!(text.contains("ListenStream=\nListenStream=0.0.0.0:12443\n"), "{text}");
        assert_eq!(parse_listen_port(&text), Some(12443));
        assert_eq!(parse_listen_port("[Socket]\nListenStream=\n"), None, "cleared and not set again");
        assert_eq!(parse_listen_port("ListenStream=11500\n"), Some(11500), "a bare port too");
        assert_eq!(parse_listen_port("ListenStream=0.0.0.0:12443\nListenStream=\n"), None, "cleared last");
    }

    #[test]
    fn a_named_instance_gets_the_first_port_nobody_has() {
        let taken = std::collections::BTreeSet::from([11443, 11444]);
        assert_eq!(pick_tls_port(11443, &taken, |_| true), Some(11445));
        assert_eq!(pick_tls_port(11443, &taken, |p| p != 11445), Some(11446), "something else listens there");
        assert_eq!(pick_tls_port(11443, &taken, |_| false), None);
    }

    #[test]
    fn the_unit_starts_the_renamed_binary() {
        assert!(UNIT_DEFAULT.contains(&format!("ExecStart={BIN_DEST} daemon")));
        assert!(UNIT_TEMPLATE.contains(&format!("ExecStart={BIN_DEST} --instance %i daemon")));
    }
}
