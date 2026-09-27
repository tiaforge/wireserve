//! Certificates on disk (PLAN.md M33): one directory per CA and name under
//! the terminator's own state directory, readable by it alone. Per CA, so a
//! certificate from Let's Encrypt's staging CA is never served once the
//! coordinator points at production.
//!
//! Kept across restarts so a restart never costs an issuance: Let's
//! Encrypt allows five duplicate certificates a week, and every agent
//! upgrade restarts the terminator.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// One certificate, ready to serve.
#[derive(Clone)]
pub struct Stored {
    pub key: Arc<CertifiedKey>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// The leaf, for renewal information.
    pub leaf: CertificateDer<'static>,
}

impl Stored {
    /// When to renew without the CA's advice: two thirds of the way
    /// through its life, the conventional point (a 90-day certificate is
    /// renewed with 30 days left).
    #[must_use]
    pub fn default_renewal(&self) -> SystemTime {
        let life = self.not_after.duration_since(self.not_before).unwrap_or(Duration::ZERO);
        self.not_before + life * 2 / 3
    }

    #[must_use]
    pub fn valid_at(&self, now: SystemTime) -> bool {
        self.not_before <= now && now < self.not_after
    }
}

/// A short name for an ACME directory URL, stable across builds (FNV-1a):
/// it names files on disk, which must outlive any one toolchain.
#[must_use]
pub fn ca_id(directory: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in directory.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("certs"))?;
        set_mode(&root, 0o700)?;
        Ok(Self { root })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir(&self, directory: &str, fqdn: &str) -> PathBuf {
        self.root.join("certs").join(ca_id(directory)).join(fqdn)
    }

    /// The certificate for `fqdn` from the CA at `directory`, if one is
    /// stored and readable.
    pub fn load(&self, directory: &str, fqdn: &str) -> io::Result<Option<Stored>> {
        let dir = self.dir(directory, fqdn);
        let (Ok(chain), Ok(key)) = (std::fs::read(dir.join("cert.pem")), std::fs::read(dir.join("key.pem"))) else {
            return Ok(None);
        };
        parse(&chain, &key).map(Some)
    }

    /// Stores a freshly issued certificate, replacing the old one only once
    /// both files are fully written.
    pub fn save(&self, directory: &str, fqdn: &str, chain_pem: &str, key_pem: &str) -> io::Result<Stored> {
        let stored = parse(chain_pem.as_bytes(), key_pem.as_bytes())?;
        let dir = self.dir(directory, fqdn);
        std::fs::create_dir_all(&dir)?;
        set_mode(&dir, 0o700)?;
        if let Some(ca) = dir.parent() {
            set_mode(ca, 0o700)?;
        }
        write_atomic(&dir.join("key.pem"), key_pem.as_bytes())?;
        write_atomic(&dir.join("cert.pem"), chain_pem.as_bytes())?;
        Ok(stored)
    }
}

/// Parses a PEM chain and key into something rustls serves, with the
/// leaf's validity period.
pub fn parse(chain_pem: &[u8], key_pem: &[u8]) -> io::Result<Stored> {
    let bad = |what: &str, e: &dyn std::fmt::Display| io::Error::new(io::ErrorKind::InvalidData, format!("{what}: {e}"));
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| bad("certificate chain", &e))?;
    let leaf = chain.first().cloned().ok_or_else(|| bad("certificate chain", &"empty"))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| bad("private key", &e))?;
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).map_err(|e| bad("private key", &e))?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|e| bad("certificate", &e))?;
    let to_time = |t: x509_parser::time::ASN1Time| {
        SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(t.timestamp()).unwrap_or(0))
    };
    Ok(Stored {
        not_before: to_time(cert.validity().not_before),
        not_after: to_time(cert.validity().not_after),
        key: Arc::new(CertifiedKey::new(chain, signing)),
        leaf,
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A self-signed certificate for `name`, valid from now for `days`.
    pub(crate) fn self_signed(name: &str, days: i64) -> (String, String) {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        let now = rcgen::date_time_ymd(2026, 1, 1);
        params.not_before = now;
        params.not_after = now + time::Duration::days(days);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn a_saved_certificate_loads_back_and_renews_two_thirds_in() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert!(store.load(CA, "plex.int.test").unwrap().is_none());
        let (chain, key) = self_signed("plex.int.test", 90);
        store.save(CA, "plex.int.test", &chain, &key).unwrap();
        let loaded = store.load(CA, "plex.int.test").unwrap().unwrap();
        let life = loaded.not_after.duration_since(loaded.not_before).unwrap();
        assert_eq!(life, Duration::from_secs(90 * 86_400));
        assert_eq!(loaded.default_renewal(), loaded.not_before + Duration::from_secs(60 * 86_400));
        use std::os::unix::fs::PermissionsExt;
        let key_path = dir.path().join("certs").join(ca_id(CA)).join("plex.int.test/key.pem");
        let mode = std::fs::metadata(key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    const CA: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

    #[test]
    fn another_ca_has_its_own_certificates() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let (chain, key) = self_signed("plex.int.test", 90);
        store.save(CA, "plex.int.test", &chain, &key).unwrap();
        assert!(store.load(wireserve_types::LETS_ENCRYPT_DIRECTORY, "plex.int.test").unwrap().is_none());
    }

    #[test]
    fn the_ca_id_is_fixed_forever() {
        // Names directories on disk: a change would re-issue everything.
        assert_eq!(ca_id(""), "cbf29ce484222325");
        assert_eq!(ca_id("a"), "af63dc4c8601ec8c");
        assert_ne!(ca_id(CA), ca_id(wireserve_types::LETS_ENCRYPT_DIRECTORY));
    }

    #[test]
    fn garbage_is_refused() {
        assert!(parse(b"not pem", b"not pem").is_err());
    }
}
