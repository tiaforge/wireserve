//! `wireserve-coordinator install` — sets up a coordinator on this machine
//! in one command (PLAN.md M31), the way `wireserve install` does a node.
//!
//! A fresh install asks a few plain-language questions (see `questions`),
//! writes `/etc/wireserve/coordinator.env` from the answers, creates the
//! `wireserve-coordinator` user and group, installs this binary and the
//! `wireserve-admin` next to it, generates the admin key and mesh ranges,
//! starts the service, and saves the admin key for whoever will run
//! `wireserve-admin`.
//!
//! Run again on a machine that already has the unit, it upgrades instead:
//! binaries and unit replaced, the service restarted, no questions and no
//! change to `coordinator.env`. `--reconfigure` asks again, with the
//! current settings as the defaults, and edits only the keys it asks about.
//!
//! The service runs as its own `wireserve-coordinator` user. It used to run
//! as `wireserve`, which on a host that also runs an agent is the group
//! allowed to drive the root agent daemon over its socket (M30). The old
//! user is left alone: removing it would also remove that group.
//!
//! The unit is `include_str!`'d, like the agent's, so what gets installed
//! can never drift from the binary that installed it.

pub mod admin_config;
pub mod envfile;
pub mod questions;

use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use questions::{Answers, Asker, Current, Given, WebServer};

const UNIT: &str = include_str!("../../../../deploy/systemd/wireserve-coordinator.service");
const ENV_EXAMPLE: &str = include_str!("../../../../deploy/env/coordinator.env.example");

pub const DEFAULT_SERVICE_USER: &str = "wireserve-coordinator";
pub const BIN_DEST: &str = "/usr/local/bin/wireserve-coordinator";
const ADMIN_BIN_DEST: &str = "/usr/local/bin/wireserve-admin";
pub(crate) const UNIT_NAME: &str = "wireserve-coordinator";
const UNIT_DEST: &str = "/etc/systemd/system/wireserve-coordinator.service";
const DROPIN_DIR: &str = "/etc/systemd/system/wireserve-coordinator.service.d";
const DROPIN_DEST: &str = "/etc/systemd/system/wireserve-coordinator.service.d/user.conf";
const ENV_DIR: &str = "/etc/wireserve";
pub(crate) const ENV_DEST: &str = "/etc/wireserve/coordinator.env";
const STATE_DIR: &str = "/var/lib/wireserve-coordinator";

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("wireserve-coordinator install must be run as root (sudo)")]
    NotRoot,
    #[error("wireserve-coordinator install needs Linux with systemd")]
    UnsupportedPlatform,
    #[error(transparent)]
    Ask(#[from] questions::AskError),
    #[error(
        "the coordinator is already installed here, so this run would only upgrade it and \
         ignore {0}; add --reconfigure to change its settings"
    )]
    SettingsWithoutReconfigure(&'static str),
    #[error("{0}")]
    Failed(String),
}

pub(crate) fn failed(what: impl std::fmt::Display, e: impl std::fmt::Display) -> InstallError {
    InstallError::Failed(format!("{what}: {e}"))
}

#[derive(clap::Args, Debug, Default)]
pub struct InstallArgs {
    /// Ask the setup questions again on an installed coordinator, with its
    /// current settings as the defaults.
    #[arg(long)]
    pub reconfigure: bool,
    /// The web address your machines reach the coordinator at, e.g.
    /// https://mesh.example.com.
    #[arg(long, value_name = "URL")]
    pub public_url: Option<String>,
    /// The internal port the web server passes requests to (default 47820).
    /// The admin port is the next one up.
    #[arg(long)]
    pub port: Option<u16>,
    /// The HTTPS web server (reverse proxy) runs on this machine.
    #[arg(long, conflicts_with_all = ["web_server_at", "listen_on"])]
    pub web_server_here: bool,
    /// The web server runs on another machine, at this address
    // Only it may tell the coordinator where a request really came from.
    #[arg(long, value_name = "IP", requires = "listen_on")]
    pub web_server_at: Option<IpAddr>,
    /// With --web-server-at: this machine's LAN address, which the
    /// coordinator listens on.
    #[arg(long, value_name = "IP", requires = "web_server_at")]
    pub listen_on: Option<IpAddr>,
    /// New services wait for `wireserve-admin service approve` (the default).
    #[arg(long, conflicts_with = "no_approval")]
    pub approval: bool,
    /// New services are shared with every machine at once.
    #[arg(long)]
    pub no_approval: bool,
    /// Save the admin key for this local user (default: whoever ran sudo).
    #[arg(long, value_name = "USER", conflicts_with = "no_admin_user")]
    pub admin_user: Option<String>,
    /// Don't save the admin key for anyone.
    #[arg(long)]
    pub no_admin_user: bool,
    /// The user and group the service runs as (default wireserve-coordinator).
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,
    /// Don't ask for confirmation before installing.
    #[arg(long, short)]
    pub yes: bool,
}

impl InstallArgs {
    fn given(&self) -> Given {
        Given {
            public_url: self.public_url.clone(),
            web_server: if self.web_server_here {
                Some(WebServer::Here)
            } else {
                self.web_server_at
                    .zip(self.listen_on)
                    .map(|(proxy_ip, listen_ip)| WebServer::Elsewhere { listen_ip, proxy_ip })
            },
            port: self.port,
            approval: if self.approval {
                Some(true)
            } else if self.no_approval {
                Some(false)
            } else {
                None
            },
            admin_user: if self.no_admin_user { Some(None) } else { self.admin_user.clone().map(Some) },
        }
    }

    /// The first setting flag given, if any — an upgrade reads none of them.
    fn first_setting_flag(&self) -> Option<&'static str> {
        [
            (self.public_url.is_some(), "--public-url"),
            (self.port.is_some(), "--port"),
            (self.web_server_here, "--web-server-here"),
            (self.web_server_at.is_some(), "--web-server-at"),
            (self.approval, "--approval"),
            (self.no_approval, "--no-approval"),
            (self.admin_user.is_some(), "--admin-user"),
            (self.no_admin_user, "--no-admin-user"),
        ]
        .into_iter()
        .find_map(|(given, flag)| given.then_some(flag))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Fresh,
    Reconfigure,
    Upgrade,
}

/// An installed unit means upgrade, unless asked to reconfigure. A
/// hand-installed coordinator (the README's manual steps) counts as
/// installed too, so it is upgraded rather than asked about from scratch.
#[must_use]
pub fn mode(unit_installed: bool, reconfigure: bool) -> Mode {
    match (unit_installed, reconfigure) {
        (false, _) => Mode::Fresh,
        (true, true) => Mode::Reconfigure,
        (true, false) => Mode::Upgrade,
    }
}

pub fn run(args: InstallArgs) -> Result<(), InstallError> {
    require_root()?;
    if !Path::new("/run/systemd/system").is_dir() {
        return Err(InstallError::UnsupportedPlatform);
    }
    let interactive = std::io::stdin().is_terminal();
    let old_unit = std::fs::read_to_string(UNIT_DEST).ok();
    let mode = mode(old_unit.is_some(), args.reconfigure);
    if mode == Mode::Upgrade {
        if let Some(flag) = args.first_setting_flag() {
            return Err(InstallError::SettingsWithoutReconfigure(flag));
        }
    }
    let service_user = args
        .user
        .clone()
        .or_else(dropin_user)
        .unwrap_or_else(|| DEFAULT_SERVICE_USER.to_string());
    let env_before = std::fs::read_to_string(ENV_DEST).ok();

    let answers = if mode == Mode::Upgrade {
        None
    } else {
        let asker = Asker {
            interactive,
            given: args.given(),
            current: env_before.as_deref().map(Current::from_env_file).unwrap_or_default(),
            sudo_user: std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty() && u != "root"),
            port_free: &port_free,
            is_local: &is_local_address,
            user_exists: &|name| lookup_user(name).is_some(),
        };
        let answers = asker.ask_all()?;
        if interactive && !args.yes {
            questions::confirm(&answers, &service_user)?;
        }
        Some(answers)
    };

    eprintln!();
    let (uid, gid) = ensure_service_user(&service_user)?;
    install_binary(&current_exe()?, BIN_DEST)?;
    let admin_installed = install_admin_binary()?;

    // Only the keys asked about are touched; a fresh file starts from the
    // documented example, so every other setting is there to be found.
    let env_after = match &answers {
        Some(a) => {
            let base = env_before.clone().unwrap_or_else(|| ENV_EXAMPLE.to_string());
            let text = envfile::apply(&base, &a.env_changes());
            write_env_file(&text)?;
            text
        }
        None => env_before.clone().unwrap_or_default(),
    };

    let state_dir = state_dir(&env_after);
    if mode != Mode::Upgrade {
        pregenerate_secrets(&env_after, &state_dir, uid, gid)?;
    }

    write_file(Path::new(UNIT_DEST), UNIT.as_bytes(), 0o644)?;
    if service_user != DEFAULT_SERVICE_USER || Path::new(DROPIN_DEST).exists() {
        std::fs::create_dir_all(DROPIN_DIR).map_err(|e| failed(DROPIN_DIR, e))?;
        write_file(Path::new(DROPIN_DEST), dropin(&service_user).as_bytes(), 0o644)?;
    }
    systemctl(&["daemon-reload"])?;

    if mode == Mode::Upgrade {
        if systemctl_ok(&["is-active", "--quiet", UNIT_NAME]) {
            systemctl(&["restart", UNIT_NAME])?;
            println!("upgraded; restarted {UNIT_NAME}");
        } else {
            println!("upgraded; {UNIT_NAME} was not running — `sudo systemctl enable --now {UNIT_NAME}` starts it");
        }
    } else {
        systemctl(&["enable", UNIT_NAME])?;
        // Restart, not start: on --reconfigure it is already running with
        // the old settings.
        systemctl(&["restart", UNIT_NAME])?;
        println!("{UNIT_NAME} is running, as the `{service_user}` user");
    }
    if !admin_installed {
        println!(
            "(no wireserve-admin next to this binary, so it was not installed; put it next to \
             wireserve-coordinator and run this again, or copy it to {ADMIN_BIN_DEST} yourself)"
        );
    }

    if let Some(answers) = &answers {
        if let Some(user) = &answers.admin_user {
            save_admin_config(user, answers, &env_after, &state_dir)?;
        }
        print_next_steps(answers, &service_user, &state_dir);
    }
    Ok(())
}

// ---- system pieces ----

#[cfg(target_os = "linux")]
pub(crate) fn require_root() -> Result<(), InstallError> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(InstallError::NotRoot)
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn require_root() -> Result<(), InstallError> {
    Err(InstallError::UnsupportedPlatform)
}

fn current_exe() -> Result<PathBuf, InstallError> {
    std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| failed("could not find this program's own path", e))
}

/// Copies `from` to `dest`, unless it already is `dest`.
fn install_binary(from: &Path, dest: &str) -> Result<(), InstallError> {
    if from == Path::new(dest) {
        return Ok(());
    }
    let bytes = std::fs::read(from).map_err(|e| failed(format!("could not read {}", from.display()), e))?;
    write_file(Path::new(dest), &bytes, 0o755)
}

/// Installs the `wireserve-admin` lying next to this binary. Returns
/// whether there was one.
fn install_admin_binary() -> Result<bool, InstallError> {
    let exe = current_exe()?;
    let Some(sibling) = exe.parent().map(|d| d.join("wireserve-admin")) else {
        return Ok(false);
    };
    let Ok(sibling) = sibling.canonicalize() else {
        return Ok(false);
    };
    install_binary(&sibling, ADMIN_BIN_DEST)?;
    Ok(true)
}

/// Writes `contents` to `path` at exactly `mode`: a temp file created
/// fresh beside it (never following a link), then renamed over it.
fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), InstallError> {
    write_file_io(path, contents, mode).map_err(|e| failed(format!("could not write {}", path.display()), e))
}

pub(crate) fn write_file_io(path: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| std::io::Error::other("path has no file name"))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(".tmp");
    let tmp = dir.join(tmp_name);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
    let written = f.write_all(contents).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

pub(crate) fn write_env_file(text: &str) -> Result<(), InstallError> {
    std::fs::create_dir_all(ENV_DIR).map_err(|e| failed(ENV_DIR, e))?;
    // Root-owned and private: systemd reads it as PID 1, before dropping to
    // the service user, and it may hold the admin key.
    write_file(Path::new(ENV_DEST), text.as_bytes(), 0o600)
}

/// Where the coordinator keeps its database and generated secrets, as the
/// service will see it.
pub(crate) fn state_dir(env_text: &str) -> PathBuf {
    envfile::get(env_text, "WIRESERVE_DB_PATH")
        .filter(|p| !p.is_empty())
        .and_then(|p| Path::new(&p).parent().map(Path::to_path_buf))
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from(STATE_DIR))
}

/// Generates the admin key and mesh ranges now, as root, exactly as the
/// first start would — so the key can be handed to the admin user straight
/// away. Skipped for a database the operator placed themselves: its
/// directory is theirs to arrange.
fn pregenerate_secrets(env_text: &str, state_dir: &Path, uid: u32, gid: u32) -> Result<(), InstallError> {
    if envfile::get(env_text, "WIRESERVE_DB_PATH").is_some_and(|p| !p.is_empty()) {
        return Ok(());
    }
    let dir_existed = state_dir.exists();
    if !dir_existed {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)
            .map_err(|e| failed(state_dir.display(), e))?;
    }
    let secrets = state_dir.join("coordinator-secrets.env");
    let secrets_existed = secrets.exists();
    crate::bootstrap::resolve_with(state_dir, |key| envfile::get(env_text, key))
        .map_err(|e| failed("could not generate the admin key and mesh ranges", e))?;
    // Only what this run created changes hands. An existing directory is
    // left to systemd, which chowns all of it to the service user whenever
    // the top-level owner is wrong — chowning just the top here would stop
    // it doing so for the database inside.
    let chown = |p: &Path| {
        std::os::unix::fs::lchown(p, Some(uid), Some(gid)).map_err(|e| failed(format!("could not chown {}", p.display()), e))
    };
    if !dir_existed {
        chown(state_dir)?;
    }
    if !secrets_existed {
        chown(&secrets)?;
    }
    Ok(())
}

/// The admin key as the running coordinator uses it: set in the env file,
/// or else generated into the state directory.
pub(crate) fn admin_token(env_text: &str, state_dir: &Path) -> Option<String> {
    envfile::get(env_text, "WIRESERVE_ADMIN_TOKEN").filter(|t| !t.is_empty()).or_else(|| {
        let text = std::fs::read_to_string(state_dir.join("coordinator-secrets.env")).ok()?;
        envfile::get(&text, "WIRESERVE_ADMIN_TOKEN").filter(|t| !t.is_empty())
    })
}

fn save_admin_config(user: &str, answers: &Answers, env_text: &str, state_dir: &Path) -> Result<(), InstallError> {
    // When the first start generates the key (a database it has to move in
    // first, say), it appears a moment after the restart.
    let mut token = admin_token(env_text, state_dir);
    for _ in 0..60 {
        if token.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        token = admin_token(env_text, state_dir);
    }
    let Some(token) = token else {
        println!(
            "could not find the admin key to save for {user}; once the coordinator has started, \
             `sudo grep WIRESERVE_ADMIN_TOKEN {}/coordinator-secrets.env` shows it",
            state_dir.display()
        );
        return Ok(());
    };
    let (uid, gid, home) = lookup_user(user).ok_or_else(|| failed(user, "no such user"))?;
    // Written by the user's own process, not root's: their home directory
    // is theirs to arrange, links and all, and root following a link
    // planted there would write wherever it pointed.
    use std::os::unix::process::CommandExt;
    let status = std::process::Command::new(BIN_DEST)
        .arg("save-admin-config")
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env(admin_config::TOKEN_ENV, token)
        .env(admin_config::REGISTER_URL_ENV, &answers.public_url)
        .env(admin_config::COORDINATOR_URL_ENV, format!("http://{}", answers.admin_addr()))
        .current_dir(&home)
        .uid(uid)
        .gid(gid)
        .status()
        .map_err(|e| failed(format!("could not save the admin settings for {user}"), e))?;
    if !status.success() {
        return Err(failed(format!("could not save the admin settings for {user}"), status));
    }
    Ok(())
}

/// Creates the service's group and user if they are missing. Never changes
/// an existing one. Returns their ids.
fn ensure_service_user(name: &str) -> Result<(u32, u32), InstallError> {
    if lookup_group(name).is_none() {
        run_tool("groupadd", &["--system", name])?;
    }
    if lookup_user(name).is_none() {
        let shell = ["/usr/sbin/nologin", "/usr/bin/nologin", "/sbin/nologin"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .unwrap_or("/bin/false");
        run_tool(
            "useradd",
            &["--system", "--gid", name, "--no-create-home", "--home-dir", STATE_DIR, "--shell", shell, name],
        )?;
        println!("created the `{name}` user and group");
    }
    let (uid, _, _) = lookup_user(name).ok_or_else(|| failed(name, "user still missing after useradd"))?;
    let gid = lookup_group(name).ok_or_else(|| failed(name, "group still missing after groupadd"))?;
    Ok((uid, gid))
}

fn dropin(user: &str) -> String {
    format!(
        "# Written by `wireserve-coordinator install --user {user}`.\n[Service]\nUser={user}\nGroup={user}\n"
    )
}

/// The user an earlier `--user` install chose, from its drop-in.
fn dropin_user() -> Option<String> {
    let text = std::fs::read_to_string(DROPIN_DEST).ok()?;
    text.lines().filter_map(|l| l.trim().strip_prefix("User=")).next_back().map(|u| u.trim().to_string())
}

fn run_tool(program: &str, args: &[&str]) -> Result<(), InstallError> {
    let cmdline = format!("{program} {}", args.join(" "));
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| failed(format!("could not run `{cmdline}`"), e))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(failed(format!("`{cmdline}` failed"), String::from_utf8_lossy(&output.stderr).trim()))
    }
}

pub(crate) fn systemctl(args: &[&str]) -> Result<(), InstallError> {
    run_tool("systemctl", args)
}

pub(crate) fn systemctl_ok(args: &[&str]) -> bool {
    std::process::Command::new("systemctl").args(args).status().is_ok_and(|s| s.success())
}

/// Whether the node port (TCP on `ip`, UDP on every address) and the admin
/// port above it (TCP on loopback) are free.
fn port_free(ip: IpAddr, port: u16) -> Result<(), String> {
    let wildcard = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    std::net::TcpListener::bind(SocketAddr::new(ip, port))
        .map_err(|e| format!("TCP port {port} is not free ({e})"))?;
    std::net::UdpSocket::bind(SocketAddr::new(wildcard, port))
        .map_err(|e| format!("UDP port {port} is not free ({e})"))?;
    let admin = port + 1;
    std::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), admin))
        .map_err(|e| format!("port {admin}, which the admin side uses, is not free ({e})"))?;
    Ok(())
}

/// Whether `ip` belongs to this machine: only then can a socket bind it.
fn is_local_address(ip: IpAddr) -> bool {
    std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// uid, primary gid and home directory of a local user.
pub(crate) fn lookup_user(name: &str) -> Option<(u32, u32, PathBuf)> {
    use std::os::unix::ffi::OsStrExt;
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 4096];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            let doubled = buf.len() * 2;
            buf.resize(doubled, 0);
            continue;
        }
        if rc != 0 || out.is_null() {
            return None;
        }
        let home = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
        let home = PathBuf::from(std::ffi::OsStr::from_bytes(home.to_bytes()));
        return Some((pwd.pw_uid, pwd.pw_gid, home));
    }
}

fn lookup_group(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 4096];
    loop {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut out: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe { libc::getgrnam_r(cname.as_ptr(), &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            let doubled = buf.len() * 2;
            buf.resize(doubled, 0);
            continue;
        }
        return if rc == 0 && !out.is_null() { Some(grp.gr_gid) } else { None };
    }
}

// ---- what is left for a person to do ----

/// What `setup` can add later (PLAN.md M47), printed after an install so a
/// newcomer knows it exists without reading anything first.
pub const SETUP_HINTS: &str = "\
Worth doing early, if you own a domain:
  sudo wireserve-coordinator setup domain     names that work on phones too, and HTTPS
                                              (renames services from .wg, so best before
                                              you add many)

Later, if more than one person uses this mesh:
  sudo wireserve-coordinator setup login      let access follow people, not devices,
                                              through a login server you run
";

/// The Caddy site block for these answers.
#[must_use]
pub fn caddy_block(answers: &Answers) -> String {
    format!(
        "{} {{\n\treverse_proxy {}\n}}\n",
        questions::url_authority(&answers.public_url),
        answers.listen_addr()
    )
}

fn print_next_steps(answers: &Answers, service_user: &str, state_dir: &Path) {
    let rule = "========================================================================";
    let port = answers.port;
    println!();
    println!("{rule}");
    println!("What's left to do by hand:");
    println!();
    let where_ = match answers.web_server {
        WebServer::Here => "on this machine".to_string(),
        WebServer::Elsewhere { proxy_ip, .. } => format!("on {proxy_ip}"),
    };
    println!("1. Point your web server {where_} at the coordinator. For Caddy, add this");
    println!("   to /etc/caddy/Caddyfile and run `sudo systemctl reload caddy`:");
    println!();
    for line in caddy_block(answers).lines() {
        println!("     {line}");
    }
    println!();
    println!("   Caddy gets the certificate by itself once the DNS name points at it.");
    println!("   nginx: see deploy/proxy/nginx.conf.example in the source.");
    println!();
    println!("2. Firewall and router:");
    println!("     open    TCP 443        (the web server; what your machines connect to)");
    println!("     open    UDP {port:<10} (optional: helps machines behind home routers)");
    println!("     CLOSED  TCP {port:<10} (unencrypted; only the web server may reach it)");
    println!("     CLOSED  TCP {:<10} (admin; this machine only, and it never listens elsewhere)", port + 1);
    if let WebServer::Elsewhere { proxy_ip, listen_ip } = answers.web_server {
        println!("   The coordinator listens on {listen_ip}, so allow TCP {port} there from {proxy_ip} only.");
    }
    println!();
    println!("3. Add your first device:");
    match &answers.admin_user {
        Some(user) => println!("     wireserve-admin node create laptop        (as {user})"),
        None => {
            println!("     wireserve-admin node create laptop");
            println!("   It needs the admin key from {}/coordinator-secrets.env", state_dir.display());
            println!("   (`sudo grep WIRESERVE_ADMIN_TOKEN` it).");
        }
    }
    println!();
    print!("{}", SETUP_HINTS);
    println!();
    println!("Settings: /etc/wireserve/coordinator.env. `sudo wireserve-coordinator install --reconfigure`");
    println!("asks these questions again.");
    println!("The service runs as `{service_user}`; logs: journalctl -u {UNIT_NAME}");
    println!("{rule}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_installed_unit_means_upgrade_unless_reconfiguring() {
        assert_eq!(mode(false, false), Mode::Fresh);
        assert_eq!(mode(false, true), Mode::Fresh, "nothing to reconfigure yet");
        assert_eq!(mode(true, false), Mode::Upgrade);
        assert_eq!(mode(true, true), Mode::Reconfigure);
    }

    #[test]
    fn the_unit_runs_as_its_own_user_not_the_agents_group() {
        assert!(UNIT.contains("\nUser=wireserve-coordinator\n"));
        assert!(UNIT.contains("\nGroup=wireserve-coordinator\n"));
        assert!(!UNIT.contains("ExecStartPre"), "a fresh install has nothing to move");
        assert!(UNIT.contains(&format!("ExecStart={BIN_DEST}\n")));
    }

    #[test]
    fn a_fresh_env_file_keeps_the_documentation_and_adds_the_answers() {
        let a = Answers {
            public_url: "https://mesh.example.com".into(),
            web_server: WebServer::Here,
            port: 47820,
            approval: true,
            admin_user: None,
        };
        let text = envfile::apply(ENV_EXAMPLE, &a.env_changes());
        assert!(text.starts_with(ENV_EXAMPLE.trim_end()));
        assert_eq!(envfile::get(&text, "WIRESERVE_LISTEN_ADDR").as_deref(), Some("127.0.0.1:47820"));
        assert_eq!(envfile::get(&text, "WIRESERVE_PUBLIC_URL").as_deref(), Some("https://mesh.example.com"));
        // The example documents every key only in comments, so nothing in
        // it is active until the installer sets it.
        assert_eq!(envfile::get(ENV_EXAMPLE, "WIRESERVE_LISTEN_ADDR"), None);
        assert_eq!(envfile::get(ENV_EXAMPLE, "WIRESERVE_SERVICE_DOMAIN"), None);
    }

    #[test]
    fn state_dir_follows_an_explicit_database_path() {
        assert_eq!(state_dir(""), PathBuf::from(STATE_DIR));
        assert_eq!(state_dir("WIRESERVE_DB_PATH=/srv/ws/c.db\n"), PathBuf::from("/srv/ws"));
        assert_eq!(state_dir("WIRESERVE_DB_PATH=c.db\n"), PathBuf::from(STATE_DIR));
    }

    #[test]
    fn the_admin_token_comes_from_the_env_file_before_the_generated_one() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("coordinator-secrets.env"), "# x\nWIRESERVE_ADMIN_TOKEN=generated\n").unwrap();
        assert_eq!(admin_token("", dir.path()).as_deref(), Some("generated"));
        assert_eq!(admin_token("WIRESERVE_ADMIN_TOKEN=mine\n", dir.path()).as_deref(), Some("mine"));
        assert_eq!(admin_token("", &dir.path().join("missing")), None);
    }

    #[test]
    fn pregenerated_secrets_follow_the_env_file_not_the_installers_environment() {
        let dir = tempfile::tempdir().unwrap();
        let env = "WIRESERVE_NET_V4_CIDR=10.77.0.0/24\n";
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        pregenerate_secrets(env, dir.path(), uid, gid).unwrap();
        let secrets = std::fs::read_to_string(dir.path().join("coordinator-secrets.env")).unwrap();
        assert!(envfile::get(&secrets, "WIRESERVE_ADMIN_TOKEN").is_some());
        assert!(envfile::get(&secrets, "WIRESERVE_NET_V6_PREFIX").is_some());
        assert_eq!(
            envfile::get(&secrets, "WIRESERVE_NET_V4_CIDR"),
            None,
            "a range the env file sets is the service's, not one to generate"
        );
    }

    #[test]
    fn caddy_is_pointed_at_the_listener() {
        let mut a = Answers {
            public_url: "https://mesh.example.com".into(),
            web_server: WebServer::Here,
            port: 48000,
            approval: true,
            admin_user: None,
        };
        assert_eq!(caddy_block(&a), "mesh.example.com {\n\treverse_proxy 127.0.0.1:48000\n}\n");
        a.web_server = WebServer::Elsewhere {
            listen_ip: "192.168.1.10".parse().unwrap(),
            proxy_ip: "192.168.1.20".parse().unwrap(),
        };
        assert_eq!(caddy_block(&a), "mesh.example.com {\n\treverse_proxy 192.168.1.10:48000\n}\n");
    }

    #[test]
    fn the_dropin_names_the_chosen_user() {
        assert!(dropin("coord").contains("\nUser=coord\nGroup=coord\n"));
    }

    #[test]
    fn upgrade_rejects_setting_flags() {
        assert_eq!(InstallArgs::default().first_setting_flag(), None);
        let args = InstallArgs { no_approval: true, ..InstallArgs::default() };
        assert_eq!(args.first_setting_flag(), Some("--no-approval"));
        let args = InstallArgs { yes: true, user: Some("u".into()), ..InstallArgs::default() };
        assert_eq!(args.first_setting_flag(), None, "--yes and --user are not settings");
    }
}
