//! Saves `wireserve-admin`'s settings in the admin user's home, so they can
//! run it with no flags: the admin key, the public address `create-node`
//! prints for new machines, and the admin listener's address.
//!
//! This runs as that user, not as root: `install` starts
//! `wireserve-coordinator save-admin-config` with the user's uid and gid
//! and the values in its environment (the same variable names
//! `wireserve-admin` itself reads). Their home is theirs to arrange, links
//! and all, and a root process following a link planted there would write
//! wherever it pointed.

use std::io::IsTerminal;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const TOKEN_ENV: &str = "WIRESERVE_ADMIN_TOKEN";
pub const REGISTER_URL_ENV: &str = "WIRESERVE_REGISTER_URL";
pub const COORDINATOR_URL_ENV: &str = "WIRESERVE_COORDINATOR_URL";

/// What to do with one settings file, given what is there now.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    Write,
    AlreadySo,
    /// Something else is saved there.
    Differs(String),
}

#[must_use]
pub fn plan(existing: Option<&str>, wanted: &str) -> Plan {
    match existing.map(str::trim) {
        None | Some("") => Plan::Write,
        Some(e) if e == wanted => Plan::AlreadySo,
        Some(e) => Plan::Differs(e.to_string()),
    }
}

/// `wireserve-coordinator save-admin-config`.
pub fn save_from_env() -> Result<(), String> {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let home = var("HOME").ok_or("HOME is not set")?;
    let token = var(TOKEN_ENV).ok_or(format!("{TOKEN_ENV} is not set"))?;
    let register_url = var(REGISTER_URL_ENV).ok_or(format!("{REGISTER_URL_ENV} is not set"))?;
    let coordinator_url = var(COORDINATOR_URL_ENV).ok_or(format!("{COORDINATOR_URL_ENV} is not set"))?;

    let dir = PathBuf::from(home).join(".config").join("wireserve-admin");
    std::fs::create_dir_all(&dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    save_url(&dir.join("register_url"), &register_url)?;
    save_url(&dir.join("coordinator_url"), &coordinator_url)?;

    let path = dir.join("admin_token");
    match plan(std::fs::read_to_string(&path).ok().as_deref(), &token) {
        Plan::Write => write(&path, &token)?,
        Plan::AlreadySo => {}
        Plan::Differs(_) => {
            if std::io::stdin().is_terminal() && ask_replace(&path) {
                write(&path, &token)?;
            } else {
                println!(
                    "left the admin key already saved in {} as it was; to use this coordinator's \
                     instead:\n  sudo grep WIRESERVE_ADMIN_TOKEN /var/lib/wireserve-coordinator/coordinator-secrets.env \
                     | cut -d= -f2 > {}",
                    path.display(),
                    path.display()
                );
                return Ok(());
            }
        }
    }
    println!("saved the admin key and addresses in {} — wireserve-admin needs no flags", dir.display());
    Ok(())
}

fn save_url(path: &Path, url: &str) -> Result<(), String> {
    match plan(std::fs::read_to_string(path).ok().as_deref(), url) {
        Plan::Write => write(path, url),
        Plan::AlreadySo => Ok(()),
        Plan::Differs(old) => {
            write(path, url)?;
            println!("{}: now {url} (was {old})", path.display());
            Ok(())
        }
    }
}

fn ask_replace(path: &Path) -> bool {
    eprintln!();
    eprintln!("  A different admin key is already saved in {}", path.display());
    eprintln!("  (for another coordinator, or an earlier install of this one).");
    loop {
        eprint!("Replace the key saved there? [Y/n] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
            return false;
        }
        match line.trim().to_lowercase().as_str() {
            "" | "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => eprintln!("  please answer y or n"),
        }
    }
}

fn write(path: &Path, value: &str) -> Result<(), String> {
    super::write_file_io(path, format!("{value}\n").as_bytes(), 0o600)
        .map_err(|e| format!("could not write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans() {
        assert_eq!(plan(None, "a"), Plan::Write);
        assert_eq!(plan(Some("\n"), "a"), Plan::Write);
        assert_eq!(plan(Some("a\n"), "a"), Plan::AlreadySo);
        assert_eq!(plan(Some("b\n"), "a"), Plan::Differs("b".into()));
    }
}
