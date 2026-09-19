//! Thin wrapper around the `nft` binary's JSON API — the one place in the
//! agent that talks to nftables.
//!
//! Replaces the original netlink-via-`rustables` design (spec §5 has been
//! updated; PLAN.md decisions log explains why): `rustables` could only
//! append rules (never insert at a chain's head, which the host-firewall
//! interop needs), could only partially decode other tools' rulesets
//! (iptables-nft's `xt` compat expressions in particular), and pulled in a
//! clang/bindgen build dependency and a GPLv3 license. `nft` itself decodes
//! and encodes everything the kernel understands, and every change we send
//! goes through as one atomic transaction (`nft -j -f -`), exactly as it
//! did with a netlink batch.
//!
//! Commands are *built* with the `nftables` crate's typed schema, so a
//! misspelled key is a compile error rather than a runtime rejection.
//! Anything *read back* from the kernel goes through our own tolerant
//! structs instead — see `host_interop` — because that crate's
//! deserializer rejects a whole ruleset over one expression it doesn't
//! model, and other tools' tables are exactly where unfamiliar expressions
//! live.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nftables::schema::Nftables;

/// Where `nft` is looked for, in order. Deliberately a fixed list rather
/// than a `PATH` lookup: the agent runs as root, and whatever binary it
/// finds here is handed the host's whole firewall.
pub const NFT_CANDIDATES: &[&str] = &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"];

#[derive(Debug, thiserror::Error)]
pub enum NftError {
    #[error(
        "the `nft` binary was not found (looked in {}) — install the `nftables` package; \
         the agent refuses to run without its firewall",
        NFT_CANDIDATES.join(", ")
    )]
    NotFound,
    #[error("failed to run {path}: {source}")]
    Spawn {
        path: String,
        source: std::io::Error,
    },
    #[error("{path} exited with {status}: {stderr}")]
    Failed {
        path: String,
        status: std::process::ExitStatus,
        stderr: String,
    },
    #[error("failed to encode nft JSON: {0}")]
    Encode(#[from] serde_json::Error),
}

/// A located `nft` binary.
#[derive(Debug, Clone)]
pub struct Nft {
    path: PathBuf,
}

impl Nft {
    /// Finds `nft` among [`NFT_CANDIDATES`].
    pub fn locate() -> Result<Self, NftError> {
        Self::locate_in(NFT_CANDIDATES)
    }

    fn locate_in(candidates: &[&str]) -> Result<Self, NftError> {
        candidates
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .map(|p| Self { path: p.to_path_buf() })
            .ok_or(NftError::NotFound)
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Applies `batch` as one atomic transaction: either every command in
    /// it takes effect or none does.
    pub fn apply(&self, batch: &Nftables<'_>) -> Result<(), NftError> {
        let json = serde_json::to_vec(batch)?;
        self.run(&["-j", "-f", "-"], Some(&json)).map(|_| ())
    }

    /// Runs `nft` with `args`, optionally feeding `stdin`, and returns its
    /// stdout. A non-zero exit is an error carrying `nft`'s own message.
    pub fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, NftError> {
        let path = self.path.display().to_string();
        let mut child = Command::new(&self.path)
            .args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| NftError::Spawn {
                path: path.clone(),
                source,
            })?;
        if let Some(input) = stdin {
            // Dropped at the end of this block, closing the pipe so `nft`
            // sees EOF and starts processing.
            let mut pipe = child.stdin.take().expect("stdin was piped");
            pipe.write_all(input).map_err(|source| NftError::Spawn {
                path: path.clone(),
                source,
            })?;
        }
        let out = child.wait_with_output().map_err(|source| NftError::Spawn {
            path: path.clone(),
            source,
        })?;
        if !out.status.success() {
            return Err(NftError::Failed {
                path,
                status: out.status,
                stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            });
        }
        Ok(out.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_picks_the_first_existing_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("nft");
        std::fs::write(&present, "").unwrap();
        let missing = dir.path().join("missing-nft");
        let nft = Nft::locate_in(&[missing.to_str().unwrap(), present.to_str().unwrap()]).unwrap();
        assert_eq!(nft.path(), present);
    }

    #[test]
    fn locate_fails_closed_when_nothing_is_found() {
        let err = Nft::locate_in(&["/nonexistent/wireserve-test/nft"]).unwrap_err();
        assert!(matches!(err, NftError::NotFound));
    }

    #[test]
    fn locate_never_consults_path() {
        // Only absolute, fixed locations — a PATH-relative name would let
        // whatever is first on root's PATH receive the host's firewall.
        assert!(NFT_CANDIDATES.iter().all(|c| c.starts_with('/')));
    }

    #[test]
    fn run_reports_nonzero_exit_with_stderr() {
        let nft = Nft {
            path: PathBuf::from("/bin/sh"),
        };
        let err = nft.run(&["-c", "echo boom >&2; exit 3"], None).unwrap_err();
        match err {
            NftError::Failed { stderr, .. } => assert_eq!(stderr, "boom"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn run_feeds_stdin_and_returns_stdout() {
        let nft = Nft {
            path: PathBuf::from("/bin/sh"),
        };
        let out = nft.run(&["-c", "cat"], Some(b"hello")).unwrap();
        assert_eq!(out, b"hello");
    }
}
