//! The system `Path`: `install` adds `%ProgramFiles%\wireserve` to it, so
//! `wireserve status` works from any terminal opened after, as
//! `/usr/local/bin/wireserve` does on Linux. `leave` leaves it, as it
//! leaves the files it points to.
//!
//! The value is edited in the registry, where Windows keeps it, and kept
//! as it is stored: unexpanded, as `REG_EXPAND_SZ`, so the `%SystemRoot%`
//! and the like in it stay variables.

use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
    KEY_SET_VALUE, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE};

use crate::platform::windows::net::{check, wide};

const ENVIRONMENT_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: a key we opened; closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

/// Appends `dir` to the system `Path` unless it is in it already, and
/// tells running programs the environment changed: Explorer, and so every
/// terminal started from it after, picks the new value up; a terminal
/// already open keeps its own. Returns whether it was added.
pub fn add_to_system_path(dir: &Path) -> io::Result<bool> {
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: a NUL-terminated subkey; `key` is written by the call.
    check(unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide(ENVIRONMENT_KEY).as_ptr(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &mut key)
    })?;
    let key = Key(key);
    let name = wide("Path");
    let (current, kind) = match query(&key, &name)? {
        Some((value, kind @ (REG_EXPAND_SZ | REG_SZ))) => (value, kind),
        Some((_, kind)) => {
            return Err(io::Error::other(format!("the system Path is not a string (registry type {kind}); left as it is")));
        }
        None => (String::new(), REG_EXPAND_SZ),
    };
    let Some(new) = with_entry(&current, &dir.to_string_lossy()) else {
        return Ok(false);
    };
    let data = wide(&new);
    // SAFETY: `data` is NUL-terminated and its byte length is given.
    check(unsafe {
        RegSetValueExW(key.0, name.as_ptr(), 0, kind, data.as_ptr().cast(), (data.len() * 2) as u32)
    })?;
    let what = wide("Environment");
    // SAFETY: a NUL-terminated string that outlives the call; a program
    // that does not answer within the timeout is skipped.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            what.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            5000,
            std::ptr::null_mut(),
        )
    };
    Ok(true)
}

/// The string value `name` of `key` as stored, with its type; `None` when
/// there is no such value.
fn query(key: &Key, name: &[u16]) -> io::Result<Option<(String, REG_VALUE_TYPE)>> {
    let mut kind: REG_VALUE_TYPE = 0;
    let mut len = 0u32;
    // SAFETY: a size query.
    let code =
        unsafe { RegQueryValueExW(key.0, name.as_ptr(), std::ptr::null(), &mut kind, std::ptr::null_mut(), &mut len) };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    check(code)?;
    let mut buf = vec![0u16; (len as usize).div_ceil(2)];
    // SAFETY: `buf` is at least `len` bytes, written by the call.
    check(unsafe {
        RegQueryValueExW(key.0, name.as_ptr(), std::ptr::null(), &mut kind, buf.as_mut_ptr().cast(), &mut len)
    })?;
    buf.truncate((len as usize) / 2);
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(Some((String::from_utf16_lossy(&buf), kind)))
}

/// `path` with `dir` appended, or `None` when an entry already names it:
/// compared as Windows compares paths, ignoring case, quotes and a
/// trailing backslash. Appended, not prepended, so it never shadows what
/// was there first.
fn with_entry(path: &str, dir: &str) -> Option<String> {
    let norm = |e: &str| e.trim().trim_matches('"').trim_end_matches('\\').to_lowercase();
    let want = norm(dir);
    if path.split(';').any(|e| norm(e) == want) {
        return None;
    }
    let path = path.trim_end_matches(';');
    Some(if path.is_empty() { dir.to_string() } else { format!("{path};{dir}") })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = r"C:\Program Files\wireserve";

    #[test]
    fn a_new_entry_goes_last() {
        assert_eq!(
            with_entry(r"%SystemRoot%\system32;%SystemRoot%", DIR).unwrap(),
            r"%SystemRoot%\system32;%SystemRoot%;C:\Program Files\wireserve"
        );
        assert_eq!(with_entry(r"C:\a;", DIR).unwrap(), r"C:\a;C:\Program Files\wireserve");
        assert_eq!(with_entry("", DIR).unwrap(), DIR);
    }

    #[test]
    fn an_entry_already_there_is_not_added_again() {
        assert_eq!(with_entry(r"C:\a;C:\Program Files\wireserve", DIR), None);
        assert_eq!(with_entry(r"C:\a;c:\program files\WIRESERVE\;C:\b", DIR), None);
        assert_eq!(with_entry(r#"C:\a;"C:\Program Files\wireserve""#, DIR), None);
        assert!(with_entry(r"C:\Program Files\wireserve2", DIR).is_some());
    }
}
