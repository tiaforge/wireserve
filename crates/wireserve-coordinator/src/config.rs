use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub admin_listen_addr: SocketAddr,
    pub admin_token: String,
    pub db_path: String,
    pub net_v4_cidr: String,
    pub net_v6_prefix: String,
    pub online_threshold_secs: i64,
    pub rate_limit_max: u32,
    pub rate_limit_window_secs: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("invalid value for {0}: {1}")]
    Invalid(&'static str, String),
    #[error(
        "WIRESERVE_ADMIN_LISTEN_ADDR ({0}) is not loopback or a private-range address — the \
         admin surface must never be reachable from an untrusted network (spec §4.0)"
    )]
    AdminListenerNotPrivate(SocketAddr),
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let listen_addr = env_or("WIRESERVE_LISTEN_ADDR", "0.0.0.0:8080")?;
        let admin_listen_addr = env_or("WIRESERVE_ADMIN_LISTEN_ADDR", "127.0.0.1:8081")?;
        validate_admin_listener(admin_listen_addr)?;

        let admin_token = std::env::var("WIRESERVE_ADMIN_TOKEN")
            .map_err(|_| ConfigError::Missing("WIRESERVE_ADMIN_TOKEN"))?;
        if admin_token.is_empty() {
            return Err(ConfigError::Invalid(
                "WIRESERVE_ADMIN_TOKEN",
                "must not be empty".into(),
            ));
        }

        let db_path =
            std::env::var("WIRESERVE_DB_PATH").unwrap_or_else(|_| "wireserve.db".to_string());
        let net_v4_cidr = std::env::var("WIRESERVE_NET_V4_CIDR")
            .unwrap_or_else(|_| "100.90.0.0/24".to_string());
        let net_v6_prefix = std::env::var("WIRESERVE_NET_V6_PREFIX")
            .unwrap_or_else(|_| "fd00:90::/64".to_string());

        let online_threshold_secs = env_parse_or("WIRESERVE_ONLINE_THRESHOLD_SECS", 180)?;
        let rate_limit_max = env_parse_or("WIRESERVE_RATE_LIMIT_MAX", 10)?;
        let rate_limit_window_secs = env_parse_or("WIRESERVE_RATE_LIMIT_WINDOW_SECS", 60)?;

        Ok(Self {
            listen_addr,
            admin_listen_addr,
            admin_token,
            db_path,
            net_v4_cidr,
            net_v6_prefix,
            online_threshold_secs,
            rate_limit_max,
            rate_limit_window_secs,
        })
    }
}

fn env_or(key: &'static str, default: &str) -> Result<SocketAddr, ConfigError> {
    let raw = std::env::var(key).unwrap_or_else(|_| default.to_string());
    raw.parse()
        .map_err(|_| ConfigError::Invalid(key, raw))
}

fn env_parse_or<T: std::str::FromStr>(key: &'static str, default: T) -> Result<T, ConfigError> {
    match std::env::var(key) {
        Ok(raw) => raw
            .parse()
            .map_err(|_| ConfigError::Invalid(key, raw)),
        Err(_) => Ok(default),
    }
}

/// The admin listener must never be reachable from an untrusted network,
/// independent of the token check (spec §4.0) — enforced here as a hard
/// startup failure, not merely documented operator guidance.
pub fn validate_admin_listener(addr: SocketAddr) -> Result<(), ConfigError> {
    if is_loopback_or_private(addr.ip()) {
        Ok(())
    } else {
        Err(ConfigError::AdminListenerNotPrivate(addr))
    }
}

pub fn is_loopback_or_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                // Unique Local Address range fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wildcard_bind() {
        let addr: SocketAddr = "0.0.0.0:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }

    #[test]
    fn rejects_public_address() {
        let addr: SocketAddr = "1.2.3.4:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }

    #[test]
    fn accepts_loopback() {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
    }

    #[test]
    fn accepts_private_range() {
        let addr: SocketAddr = "10.0.0.5:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
        let addr: SocketAddr = "192.168.1.5:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
    }

    #[test]
    fn accepts_ipv6_loopback_and_ula() {
        let addr: SocketAddr = "[::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
        let addr: SocketAddr = "[fd00::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_ok());
    }

    #[test]
    fn rejects_public_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:8081".parse().unwrap();
        assert!(validate_admin_listener(addr).is_err());
    }
}
