//! `install` on Windows (PLAN.md M49, M50): the files, the services, the
//! group and the `Path`.

use std::time::Duration;

use crate::paths::Instance;

/// `install` on Windows: the files into `%ProgramFiles%\wireserve`, the
/// instance's service (see [`super::service`]), a join unless this is an
/// upgrade, and the service started. Every running agent service is
/// stopped while the binary it runs is replaced, and started again after.
pub async fn run<J, F>(
    instance: &Instance,
    request: crate::platform::install::Request,
    join: J,
) -> Result<(), Box<dyn std::error::Error>>
where
    J: FnOnce() -> F,
    F: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    use super::service as winservice;
    let tls_port = request.tls_port;
    if tls_port.is_some() {
        return Err("--tls-port: on Windows the TLS terminator listens on each service's own 443 and 80".into());
    }
    if let Some(url) = &request.coordinator_url {
        crate::register::check_coordinator_transport(url, request.allow_plaintext_http)?;
    }
    if !super::security::is_elevated()? {
        return Err("`install` needs an elevated terminal: open it with \"Run as administrator\"".into());
    }
    // As on Linux (`install::is_upgrade`): an identity, and nothing given
    // to join with, is an upgrade.
    let registered = crate::state::AgentState::load(&instance.state_path())?.bearer_token.is_some();
    let upgrade = registered && !request.join_args_given;

    // Terminators first: each checks in with its agent.
    let instances = crate::paths::all_instances();
    let mut running_tls = Vec::new();
    for other in &instances {
        if winservice::stop_and_wait(&winservice::tls_service_name(other))? {
            running_tls.push(other.clone());
        }
    }
    let running = winservice::running_instances(instances)?;
    for other in &running {
        winservice::stop_and_wait(&winservice::service_name(other))?;
    }
    // Whatever fails from here on, what was running runs again, on whichever
    // files are in place: a failed upgrade must not leave the node offline.
    let installed = install_and_start(instance, join, upgrade, &running, &running_tls).await;
    if let Err(e) = &installed {
        let mut restarted = Vec::new();
        for other in &running {
            if winservice::start(&winservice::service_name(other), &other.log_path()).is_ok() {
                restarted.push(winservice::service_name(other));
            }
        }
        for other in &running_tls {
            if winservice::start(&winservice::tls_service_name(other), &other.tls_log_path()).is_ok() {
                restarted.push(winservice::tls_service_name(other));
            }
        }
        if !restarted.is_empty() {
            return Err(format!("{e} (started again what was running: {})", restarted.join(", ")).into());
        }
    }
    let (exe, name, tls_name, group, on_path) = installed?;
    let dir = exe.parent().ok_or("the installed wireserve.exe has no folder")?;
    let instance_flag = if instance.is_default() { String::new() } else { format!(" --instance {}", instance.name()) };
    println!();
    if upgrade {
        println!("upgraded; {name} is running again");
    } else {
        println!("{name} is running");
    }
    let command = if on_path { "wireserve".to_string() } else { format!("& \"{}\"", exe.display()) };
    println!("From an elevated terminal, `{command}{instance_flag} status` shows its peers.");
    if on_path {
        println!("({} is on the system Path now; a terminal opened before this one does not see it yet.)", dir.display());
    }
    println!("Its log: {}; its TLS terminator's, {tls_name}: {}", instance.log_path().display(), instance.tls_log_path().display());
    if let Some(group) = group {
        // Who this terminal runs as: the one to add, unless the elevation
        // prompt took another administrator's password. Every service was
        // (re)started above, after the group existed: no restart to suggest.
        let who = std::env::var("USERNAME").ok().filter(|u| !u.is_empty());
        println!();
        println!("To use it without an elevated terminal, join the `{group}` group and sign out and in again:");
        println!("  net localgroup {group} {} /add", who.as_deref().unwrap_or("<user>"));
    }
    Ok(())
}

/// The part of a Windows `install` after every service is stopped: the
/// files, the group, the `Path`, both services, the join, and starting
/// what should run. The installed executable, the two services' names,
/// the group and whether the `Path` has the folder.
#[allow(clippy::type_complexity)]
async fn install_and_start<J, F>(
    instance: &Instance,
    join: J,
    upgrade: bool,
    running: &[Instance],
    running_tls: &[Instance],
) -> Result<(std::path::PathBuf, String, String, Option<String>, bool), Box<dyn std::error::Error>>
where
    J: FnOnce() -> F,
    F: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    use super::service as winservice;
    let exe = install_files()?;
    // Before the service starts: it looks the group up once, when it
    // creates its pipe.
    let group = match crate::ipc::server::socket_group_name() {
        Some(group) => {
            super::security::ensure_local_group(&group, "May use the wireserve agent without elevation")?;
            Some(group)
        }
        None => None,
    };
    let dir = exe.parent().ok_or("the installed wireserve.exe has no folder")?.to_path_buf();
    let on_path = match super::system_path::add_to_system_path(&dir) {
        Ok(_) => true,
        // Only a convenience: the full path still works.
        Err(e) => {
            eprintln!("warning: could not add {} to the system Path: {e}", dir.display());
            false
        }
    };
    let name = winservice::service_name(instance);
    winservice::install(&name, instance, &exe)?;
    // The TLS terminator (PLAN.md M50), under an account of its own whose
    // state directory only it and administrators may read. Before the
    // agent starts: the agent looks its account up once, at start.
    let tls_name = winservice::tls_service_name(instance);
    winservice::install_tls(&tls_name, instance, &exe)?;
    let tls_account = super::security::service_sid(&tls_name)?
        .ok_or_else(|| format!("the {tls_name} service was created, but Windows knows no account NT SERVICE\\{tls_name}"))?;
    super::security::ensure_private_dir_for(&instance.tls_state_dir(), &tls_account)?;
    if !upgrade {
        join().await?;
    }
    winservice::start(&name, &instance.log_path())?;
    winservice::start(&tls_name, &instance.tls_log_path())?;
    for other in running.iter().filter(|i| *i != instance) {
        winservice::start(&winservice::service_name(other), &other.log_path())?;
    }
    for other in running_tls.iter().filter(|i| *i != instance) {
        winservice::start(&winservice::tls_service_name(other), &other.tls_log_path())?;
    }
    Ok((exe, name, tls_name, group, on_path))
}

/// Copies this executable and the `wireguard.dll` beside it into
/// `%ProgramFiles%\wireserve`, where only administrators can change them —
/// the service runs them as LocalSystem. Returns the installed executable.
fn install_files() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let program_files = std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
    let dir = std::path::PathBuf::from(program_files).join("wireserve");
    let current = std::env::current_exe()?.canonicalize()?;
    let dll = current.with_file_name("wireguard.dll");
    if !dll.is_file() {
        return Err(format!(
            "wireguard.dll must be next to {} (both come in the release zip)",
            current.display()
        )
        .into());
    }
    std::fs::create_dir_all(&dir)?;
    for (from, file) in [(&current, "wireserve.exe"), (&dll, "wireguard.dll")] {
        let to = dir.join(file);
        if to.canonicalize().is_ok_and(|t| t == *from) {
            continue;
        }
        // The same file already (the DLL, most upgrades): nothing to replace,
        // and nothing to wait for a process to let go of.
        if std::fs::read(&to).is_ok_and(|have| std::fs::read(from).is_ok_and(|want| want == have)) {
            continue;
        }
        // Copied beside, then renamed over: never a half-written file where
        // the service looks for it.
        let tmp = dir.join(format!(".{file}.tmp"));
        std::fs::copy(from, &tmp).map_err(|e| format!("could not copy {} to {}: {e}", from.display(), dir.display()))?;
        // A stopped service's process may still be exiting, and holding the
        // file, for a moment after the service reports stopped.
        let mut tries = 0;
        while let Err(e) = std::fs::rename(&tmp, &to) {
            tries += 1;
            if tries == 20 {
                let _ = std::fs::remove_file(&tmp);
                return Err(format!("could not replace {}: {e}", to.display()).into());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    Ok(dir.join("wireserve.exe"))
}
