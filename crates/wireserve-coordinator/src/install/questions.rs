//! The handful of questions `wireserve-coordinator install` asks, and how
//! each answer is settled: a command-line flag first, then (only at a
//! terminal) a question whose default is the current setting, then that
//! current setting or the built-in default without asking.
//!
//! The wording is written for someone setting this up for the first time:
//! every question says what the setting is for before asking for it, and
//! nothing assumes the reader knows the env variable behind it.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::envfile::{self, Change};

pub const DEFAULT_PORT: u16 = 47820;

/// Where the HTTPS web server in front of the coordinator runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebServer {
    /// On this machine: the coordinator listens on loopback only.
    Here,
    /// On another machine: the coordinator listens on `listen_ip`, one of
    /// this machine's private addresses, and believes forwarded client
    /// addresses from `proxy_ip` alone.
    Elsewhere { listen_ip: IpAddr, proxy_ip: IpAddr },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    pub public_url: String,
    pub web_server: WebServer,
    pub port: u16,
    pub approval: bool,
    /// The local user to save `wireserve-admin`'s settings for, if any.
    pub admin_user: Option<String>,
}

/// What `--flags` said, one field per question. `None` means the flag was
/// not given, so the question is asked (or its default taken).
#[derive(Debug, Clone, Default)]
pub struct Given {
    pub public_url: Option<String>,
    pub web_server: Option<WebServer>,
    pub port: Option<u16>,
    pub approval: Option<bool>,
    /// `Some(None)` is `--no-admin-user`.
    pub admin_user: Option<Option<String>>,
}

/// The settings as the env file has them now, so a second run offers them
/// as its defaults instead of starting over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Current {
    pub public_url: Option<String>,
    pub web_server: Option<WebServer>,
    pub port: Option<u16>,
    pub approval: Option<bool>,
}

impl Current {
    #[must_use]
    pub fn from_env_file(text: &str) -> Self {
        let listen: Option<SocketAddr> = envfile::get(text, "WIRESERVE_LISTEN_ADDR").and_then(|a| a.parse().ok());
        let proxy: Option<IpAddr> = envfile::get(text, "WIRESERVE_TRUSTED_PROXY").and_then(|a| a.parse().ok());
        let web_server = listen.map(|addr| match proxy {
            Some(proxy_ip) if !addr.ip().is_loopback() => WebServer::Elsewhere { listen_ip: addr.ip(), proxy_ip },
            _ => WebServer::Here,
        });
        Self {
            public_url: envfile::get(text, "WIRESERVE_PUBLIC_URL").filter(|u| !u.is_empty()),
            web_server,
            port: listen.map(|a| a.port()),
            approval: envfile::get(text, "WIRESERVE_REQUIRE_SERVICE_APPROVAL").and_then(|v| v.parse().ok()),
        }
    }
}

impl Answers {
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        match self.web_server {
            WebServer::Here => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
            WebServer::Elsewhere { listen_ip, .. } => SocketAddr::new(listen_ip, self.port),
        }
    }

    /// The admin listener sits one above the node port, as the two
    /// built-in defaults (47820/47821) already do. Loopback always.
    #[must_use]
    pub fn admin_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port + 1)
    }

    /// The env-file edits these answers stand for. Names, the sign-in and
    /// device owners are `setup`'s (PLAN.md M47), and left alone here.
    #[must_use]
    pub fn env_changes(&self) -> Vec<(&'static str, Change)> {
        let (trust_all, trusted_proxy) = match self.web_server {
            // Only local processes can reach a loopback listener, so every
            // peer is the web server (or already root-equivalent).
            WebServer::Here => (true, Change::Clear),
            WebServer::Elsewhere { proxy_ip, .. } => (false, Change::Set(proxy_ip.to_string())),
        };
        vec![
            ("WIRESERVE_PUBLIC_URL", Change::Set(self.public_url.clone())),
            ("WIRESERVE_LISTEN_ADDR", Change::Set(self.listen_addr().to_string())),
            ("WIRESERVE_ADMIN_LISTEN_ADDR", Change::Set(self.admin_addr().to_string())),
            ("WIRESERVE_TRUST_PROXY_HEADERS", Change::Set(trust_all.to_string())),
            ("WIRESERVE_TRUSTED_PROXY", trusted_proxy),
            ("WIRESERVE_REQUIRE_SERVICE_APPROVAL", Change::Set(self.approval.to_string())),
        ]
    }

    /// The one-screen summary shown before anything is installed.
    #[must_use]
    pub fn summary(&self, service_user: &str) -> String {
        let mut s = String::new();
        s.push_str(&format!("  Web address:          {}\n", self.public_url));
        match &self.web_server {
            WebServer::Here => {
                s.push_str(&format!("  Web server:           on this machine, passing requests to {}\n", self.listen_addr()));
            }
            WebServer::Elsewhere { proxy_ip, .. } => {
                s.push_str(&format!("  Web server:           {proxy_ip}, passing requests to {}\n", self.listen_addr()));
            }
        }
        s.push_str(&format!(
            "  Port:                 {} (TCP must stay closed to the internet; UDP may be forwarded)\n",
            self.port
        ));
        s.push_str(&format!("  Admin port:           {} (this machine only)\n", self.admin_addr()));
        s.push_str(&format!(
            "  Service approval:     {}\n",
            if self.approval { "on — new services wait for you" } else { "off — new services are shared at once" }
        ));
        s.push_str(&format!(
            "  Admin key saved for:  {}\n",
            self.admin_user.as_deref().unwrap_or("nobody (read it from the state directory later)")
        ));
        s.push_str(&format!("  Runs as user:         {service_user}\n"));
        s.push_str("Everything else keeps its default and can be changed in /etc/wireserve/coordinator.env.\n");
        s
    }
}

// ---- validation, kept pure so it can be tested ----

/// Checks a public URL and returns it normalised (no trailing slash),
/// plus a warning to show when it is plain HTTP.
pub fn check_public_url(raw: &str) -> Result<(String, Option<String>), String> {
    let url = raw.trim().trim_end_matches('/').to_string();
    let (rest, plain) = if let Some(r) = url.strip_prefix("https://") {
        (r, false)
    } else if let Some(r) = url.strip_prefix("http://") {
        (r, true)
    } else {
        return Err("it has to start with https://, like https://mesh.example.com".into());
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains(char::is_whitespace) {
        return Err("there is no host name after https://".into());
    }
    if rest.contains('/') {
        return Err("give just the address, without a path after it".into());
    }
    if !plain {
        return Ok((url, None));
    }
    let host = authority_host(authority);
    let local = host == "localhost"
        || host.parse::<IpAddr>().is_ok_and(crate::config::is_loopback_or_private);
    if !local {
        return Err("plain http:// would send every key over the internet unencrypted; use https://".into());
    }
    Ok((
        url,
        Some(
            "plain http:// is only safe if every network between your machines and this one is \
             trusted; each `wireserve install` will need --allow-plaintext-http"
                .into(),
        ),
    ))
}

/// The host part of `host:port` / `[v6]:port` / `host`.
#[must_use]
pub fn authority_host(authority: &str) -> &str {
    if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next().unwrap_or(inner)
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    }
}

/// The host (and port, if one was given) of a public URL: what a Caddy
/// site block is named after.
#[must_use]
pub fn url_authority(url: &str) -> &str {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://")).unwrap_or(url);
    rest.split('/').next().unwrap_or(rest)
}

pub fn check_port(raw: &str) -> Result<u16, String> {
    let port: u16 = raw.trim().parse().map_err(|_| "that is not a port number".to_string())?;
    // Below 1024 needs a capability the unit does not grant; the admin
    // listener takes the next port up, so 65535 leaves it none.
    if !(1024..=65534).contains(&port) {
        return Err("pick a number between 1024 and 65534".into());
    }
    Ok(port)
}

/// An address the coordinator can listen on when the web server is
/// elsewhere: one of this machine's own, and private.
pub fn check_listen_ip(raw: &str, is_local: impl Fn(IpAddr) -> bool) -> Result<IpAddr, String> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| "that is not an IP address".to_string())?;
    if ip.is_loopback() {
        return Err("that only works when the web server is on this machine; answer yes to the question before".into());
    }
    if ip.is_unspecified() || !crate::config::is_loopback_or_private(ip) {
        return Err("it has to be a private (LAN) address, so the internet can't reach it".into());
    }
    if !is_local(ip) {
        return Err("that address does not belong to this machine".into());
    }
    Ok(ip)
}

pub fn check_proxy_ip(raw: &str) -> Result<IpAddr, String> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| "that is not an IP address".to_string())?;
    if ip.is_loopback() || ip.is_unspecified() {
        return Err("give the web server machine's own address on your network".into());
    }
    Ok(ip)
}

pub fn check_domain(raw: &str) -> Result<String, String> {
    let d = raw.trim().trim_end_matches('.').to_lowercase();
    if wireserve_types::is_valid_hostname(&d) && d.contains('.') {
        Ok(d)
    } else {
        Err("that is not a domain like home.example.com".into())
    }
}

pub fn check_dns_provider(raw: &str) -> Result<String, String> {
    let p = raw.trim().to_ascii_lowercase();
    if crate::dns::config::PROVIDERS.contains(&p.as_str()) {
        Ok(p)
    } else {
        Err(format!("pick one of {}", crate::dns::config::PROVIDERS.join(", ")))
    }
}

pub fn check_node_name(raw: &str) -> Result<String, String> {
    let p = raw.trim().to_lowercase();
    if wireserve_types::is_valid_dns_label(&p) {
        Ok(p)
    } else {
        Err("a node name is one word of letters, digits and dashes, like homeserver".into())
    }
}

pub fn check_service_name(raw: &str) -> Result<String, String> {
    let p = raw.trim().to_lowercase();
    if wireserve_types::is_valid_dns_label(&p) {
        Ok(p)
    } else {
        Err("a service name is one word of letters, digits and dashes, like web".into())
    }
}

// ---- asking ----

/// Settles every answer. `interactive` is whether stdin is a terminal;
/// `port_free` checks a port that is not already the coordinator's own;
/// `is_local` whether an address belongs to this machine; `user_exists`
/// whether a local user of that name exists.
pub struct Asker<'a> {
    pub interactive: bool,
    pub given: Given,
    pub current: Current,
    /// Who ran sudo — the default admin user.
    pub sudo_user: Option<String>,
    pub port_free: &'a dyn Fn(IpAddr, u16) -> Result<(), String>,
    pub is_local: &'a dyn Fn(IpAddr) -> bool,
    pub user_exists: &'a dyn Fn(&str) -> bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AskError {
    #[error("{0}")]
    Invalid(String),
    #[error("no answer for \"{question}\" — pass {flag} when not running at a terminal")]
    Missing { question: &'static str, flag: &'static str },
    #[error("stopped; nothing was changed")]
    Declined,
}

impl Asker<'_> {
    pub fn ask_all(&self) -> Result<Answers, AskError> {
        if self.interactive {
            eprintln!();
            eprintln!("A few questions first. Press Enter to take the answer in [brackets].");
        }
        let public_url = self.public_url()?;
        let web_server = self.web_server()?;
        let port = self.port(&web_server)?;
        let approval = self.approval()?;
        let admin_user = self.admin_user()?;
        Ok(Answers { public_url, web_server, port, approval, admin_user })
    }

    fn public_url(&self) -> Result<String, AskError> {
        let check = |raw: &str| {
            check_public_url(raw).map(|(url, warning)| {
                if let Some(w) = warning {
                    eprintln!("note: {w}");
                }
                url
            })
        };
        if let Some(raw) = &self.given.public_url {
            return check(raw).map_err(|e| AskError::Invalid(format!("--public-url: {e}")));
        }
        if !self.interactive {
            return self.current.public_url.clone().ok_or(AskError::Missing {
                question: "web address of this coordinator",
                flag: "--public-url",
            });
        }
        explain(&[
            "Your machines reach this coordinator through a web address with HTTPS,",
            "e.g. https://mesh.example.com. It is the address you'll put in your",
            "web server (Caddy, nginx, …) and the one every new machine is given",
            "when it joins.",
        ]);
        ask_until("Web address of this coordinator", self.current.public_url.as_deref(), check)
    }

    fn web_server(&self) -> Result<WebServer, AskError> {
        if let Some(w) = &self.given.web_server {
            if let WebServer::Elsewhere { listen_ip, proxy_ip } = w {
                check_listen_ip(&listen_ip.to_string(), self.is_local)
                    .map_err(|e| AskError::Invalid(format!("--listen-on: {e}")))?;
                check_proxy_ip(&proxy_ip.to_string())
                    .map_err(|e| AskError::Invalid(format!("--web-server-at: {e}")))?;
            }
            return Ok(w.clone());
        }
        let current = self.current.web_server.clone().unwrap_or(WebServer::Here);
        if !self.interactive {
            return Ok(current);
        }
        explain(&[
            "The coordinator only speaks plain, unencrypted HTTP, so it never faces",
            "the internet itself. A web server in front of it takes care of that:",
            "it is what your machines actually connect to (on the normal HTTPS",
            "port, 443), it holds the certificate for your web address, and it",
            "passes each request on to the coordinator over a private connection.",
            "This kind of web server is called a reverse proxy; Caddy and nginx are",
            "common choices, and Caddy gets its certificate by itself. If you don't",
            "have one yet, that's fine: at the end, this installer prints a",
            "ready-to-use Caddy configuration for you.",
        ]);
        let here = ask_yes_no(
            "Does that web server run (or will it run) on this same machine?",
            current == WebServer::Here,
        );
        if here {
            return Ok(WebServer::Here);
        }
        let (cur_listen, cur_proxy) = match current {
            WebServer::Elsewhere { listen_ip, proxy_ip } => (Some(listen_ip.to_string()), Some(proxy_ip.to_string())),
            WebServer::Here => (None, None),
        };
        eprintln!();
        let listen_ip = ask_until(
            "Which address of this machine can the web server reach? (usually its LAN address, like 192.168.1.10)",
            cur_listen.as_deref(),
            |raw| check_listen_ip(raw, self.is_local),
        )?;
        explain(&[
            "The web server tells the coordinator which address each machine",
            "really connected from. Only the web server may say that, otherwise",
            "anyone on your network could pretend to be someone else.",
        ]);
        let proxy_ip = ask_until(
            "What is the web server's address on your network? (like 192.168.1.20)",
            cur_proxy.as_deref(),
            check_proxy_ip,
        )?;
        Ok(WebServer::Elsewhere { listen_ip, proxy_ip })
    }

    fn port(&self, web_server: &WebServer) -> Result<u16, AskError> {
        let listen_ip = match web_server {
            WebServer::Here => IpAddr::V4(Ipv4Addr::LOCALHOST),
            WebServer::Elsewhere { listen_ip, .. } => *listen_ip,
        };
        // The coordinator's own current port is in use by the coordinator
        // itself; that is not a clash.
        let usable = |port: u16| -> Result<u16, String> {
            if Some(port) != self.current.port {
                (self.port_free)(listen_ip, port)?;
            }
            Ok(port)
        };
        if let Some(port) = self.given.port {
            return check_port(&port.to_string())
                .and_then(usable)
                .map_err(|e| AskError::Invalid(format!("--port {port}: {e}")));
        }
        let default = self.current.port.unwrap_or(DEFAULT_PORT);
        if !self.interactive {
            return usable(default).map_err(|e| AskError::Invalid(format!("port {default}: {e}; pass --port")));
        }
        explain(&[
            "The internal port the web server passes requests to. This one must",
            "NOT be reachable from the internet: don't open or forward it in your",
            "router or firewall, since everything on it is unencrypted. Only the",
            "web server should talk to it. (Your machines connect to the web",
            "server on 443, never to this port directly.)",
            "",
            "One exception: the same number is also used over UDP, a separate kind",
            "of traffic that doesn't go through the web server, to help machines",
            "behind home routers find each other. If you want that, forward ONLY",
            "UDP on this port to this machine. Still keep TCP closed.",
            "",
            "Any free port works; the default is fine unless something else",
            "already uses it.",
        ]);
        ask_until("Port", Some(&default.to_string()), |raw| check_port(raw).and_then(usable))
    }

    fn approval(&self) -> Result<bool, AskError> {
        if let Some(a) = self.given.approval {
            return Ok(a);
        }
        let default = self.current.approval.unwrap_or(true);
        if !self.interactive {
            return Ok(default);
        }
        explain(&[
            "When a machine offers a new service (say, \"plex\"), every other machine",
            "learns its name. With approval on, nothing is shared until you say",
            "`wireserve-admin service approve plex --node <machine>`, so one broken",
            "or stolen machine can't take over a name. Turn it off if every machine is yours and you",
            "trust all of them.",
        ]);
        Ok(ask_yes_no("Should new services wait for your approval?", default))
    }

    fn admin_user(&self) -> Result<Option<String>, AskError> {
        let check = |raw: &str| -> Result<Option<String>, String> {
            let u = raw.trim();
            if u == "-" {
                return Ok(None);
            }
            if (self.user_exists)(u) {
                Ok(Some(u.to_string()))
            } else {
                Err(format!("there is no user called {u:?} on this machine (enter - to skip)"))
            }
        };
        if let Some(given) = &self.given.admin_user {
            return match given {
                None => Ok(None),
                Some(u) => check(u).map_err(|e| AskError::Invalid(format!("--admin-user: {e}"))),
            };
        }
        let default = self.sudo_user.clone();
        if !self.interactive {
            return Ok(default.filter(|u| (self.user_exists)(u)));
        }
        explain(&[
            "`wireserve-admin` needs the coordinator's admin key. It can be saved",
            "for one user on this machine so they never have to type it.",
        ]);
        ask_until("Save it for which user? (- to skip)", Some(default.as_deref().unwrap_or("-")), check)
    }
}

/// Shows the final summary and asks whether to go ahead.
pub fn confirm(answers: &Answers, service_user: &str) -> Result<(), AskError> {
    eprintln!();
    eprintln!("Ready to install:");
    eprint!("{}", answers.summary(service_user));
    eprintln!();
    if ask_yes_no("Install with these settings?", true) {
        Ok(())
    } else {
        Err(AskError::Declined)
    }
}

pub(crate) fn explain<S: AsRef<str>>(lines: &[S]) {
    eprintln!();
    for line in lines {
        let line = line.as_ref();
        if line.is_empty() {
            eprintln!();
        } else {
            eprintln!("  {line}");
        }
    }
}

fn read_line() -> Option<String> {
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        // End of input: there is nobody left to answer.
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

/// Asks until `check` accepts the answer. Enter takes `default`.
pub(crate) fn ask_until<T>(
    label: &str,
    default: Option<&str>,
    check: impl Fn(&str) -> Result<T, String>,
) -> Result<T, AskError> {
    loop {
        match default {
            Some(d) => eprint!("{label} [{d}]: "),
            None => eprint!("{label}: "),
        }
        let _ = std::io::stderr().flush();
        let Some(answer) = read_line() else {
            return Err(AskError::Declined);
        };
        let answer = if answer.is_empty() {
            match default {
                Some(d) => d.to_string(),
                None => continue,
            }
        } else {
            answer
        };
        match check(&answer) {
            Ok(v) => return Ok(v),
            Err(e) => eprintln!("  {e}"),
        }
    }
}

/// Asks for a secret without echoing it. Enter keeps `current`, which is
/// never shown.
pub(crate) fn ask_secret(label: &str, current: Option<String>) -> Result<Option<String>, AskError> {
    loop {
        let prompt = if current.is_some() { format!("{label} [keep current]: ") } else { format!("{label}: ") };
        let answer = rpassword::prompt_password(prompt).map_err(|_| AskError::Declined)?;
        let answer = answer.trim();
        if !answer.is_empty() {
            return Ok(Some(answer.to_string()));
        }
        if current.is_some() {
            return Ok(current);
        }
    }
}

pub(crate) fn ask_yes_no(label: &str, default: bool) -> bool {
    loop {
        eprint!("{label} {} ", if default { "[Y/n]" } else { "[y/N]" });
        let _ = std::io::stderr().flush();
        let Some(answer) = read_line() else {
            return default;
        };
        match answer.to_lowercase().as_str() {
            "" => return default,
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => eprintln!("  please answer y or n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answers() -> Answers {
        Answers {
            public_url: "https://mesh.example.com".into(),
            web_server: WebServer::Here,
            port: 47820,
            approval: true,
            admin_user: Some("tia".into()),
        }
    }

    fn change<'a>(changes: &'a [(&str, Change)], key: &str) -> &'a Change {
        &changes.iter().find(|(k, _)| *k == key).unwrap().1
    }

    #[test]
    fn a_web_server_here_listens_on_loopback_and_trusts_its_headers() {
        let a = answers();
        let c = a.env_changes();
        assert_eq!(change(&c, "WIRESERVE_LISTEN_ADDR"), &Change::Set("127.0.0.1:47820".into()));
        assert_eq!(change(&c, "WIRESERVE_ADMIN_LISTEN_ADDR"), &Change::Set("127.0.0.1:47821".into()));
        assert_eq!(change(&c, "WIRESERVE_TRUST_PROXY_HEADERS"), &Change::Set("true".into()));
        assert_eq!(change(&c, "WIRESERVE_TRUSTED_PROXY"), &Change::Clear);
    }

    #[test]
    fn a_web_server_elsewhere_is_the_only_one_believed() {
        let mut a = answers();
        a.port = 48000;
        a.web_server = WebServer::Elsewhere {
            listen_ip: "192.168.1.10".parse().unwrap(),
            proxy_ip: "192.168.1.20".parse().unwrap(),
        };
        let c = a.env_changes();
        assert_eq!(change(&c, "WIRESERVE_LISTEN_ADDR"), &Change::Set("192.168.1.10:48000".into()));
        assert_eq!(change(&c, "WIRESERVE_ADMIN_LISTEN_ADDR"), &Change::Set("127.0.0.1:48001".into()));
        assert_eq!(change(&c, "WIRESERVE_TRUST_PROXY_HEADERS"), &Change::Set("false".into()));
        assert_eq!(change(&c, "WIRESERVE_TRUSTED_PROXY"), &Change::Set("192.168.1.20".into()));
    }

    #[test]
    fn install_leaves_names_owners_and_the_sign_in_to_setup() {
        let c = answers().env_changes();
        for key in ["WIRESERVE_SERVICE_DOMAIN", "WIRESERVE_DNS_PROVIDER", "WIRESERVE_AUTH_SERVICE", "WIRESERVE_OIDC_ISSUER"] {
            assert!(!c.iter().any(|(k, _)| *k == key), "{key} is setup's");
        }
    }

    #[test]
    fn the_env_file_the_answers_write_reads_back_as_the_same_answers() {
        let mut a = answers();
        a.approval = false;
        a.web_server = WebServer::Elsewhere {
            listen_ip: "10.0.0.5".parse().unwrap(),
            proxy_ip: "10.0.0.6".parse().unwrap(),
        };
        let text = envfile::apply("", &a.env_changes());
        let current = Current::from_env_file(&text);
        assert_eq!(
            current,
            Current {
                public_url: Some(a.public_url.clone()),
                web_server: Some(a.web_server.clone()),
                port: Some(a.port),
                approval: Some(false),
            }
        );
    }

    #[test]
    fn public_urls() {
        assert_eq!(check_public_url("https://mesh.example.com/").unwrap(), ("https://mesh.example.com".into(), None));
        assert!(check_public_url("https://mesh.example.com:8443").is_ok());
        assert!(check_public_url("mesh.example.com").is_err());
        assert!(check_public_url("https://").is_err());
        assert!(check_public_url("https://mesh.example.com/coord").is_err());
        assert!(check_public_url("http://mesh.example.com").is_err(), "plain HTTP over the internet");
        assert!(check_public_url("http://203.0.113.5:47820").is_err());
        let (url, warning) = check_public_url("http://192.168.1.10:47820").unwrap();
        assert_eq!(url, "http://192.168.1.10:47820");
        assert!(warning.is_some());
        assert_eq!(url_authority("https://mesh.example.com:8443"), "mesh.example.com:8443");
    }

    #[test]
    fn ports() {
        assert_eq!(check_port("47820"), Ok(47820));
        assert!(check_port("80").is_err(), "needs a capability the unit does not grant");
        assert!(check_port("65535").is_err(), "leaves no port for the admin listener");
        assert!(check_port("x").is_err());
    }

    #[test]
    fn addresses() {
        let local = |ip: IpAddr| ip == "192.168.1.10".parse::<IpAddr>().unwrap();
        assert!(check_listen_ip("192.168.1.10", local).is_ok());
        assert!(check_listen_ip("192.168.1.11", local).is_err(), "not this machine's");
        assert!(check_listen_ip("127.0.0.1", |_| true).is_err());
        assert!(check_listen_ip("0.0.0.0", |_| true).is_err());
        assert!(check_listen_ip("203.0.113.5", |_| true).is_err(), "public");
        assert!(check_proxy_ip("192.168.1.20").is_ok());
        assert!(check_proxy_ip("127.0.0.1").is_err());
    }

    #[test]
    fn domains_and_proxy_names() {
        assert_eq!(check_domain("Home.Example.com."), Ok("home.example.com".into()));
        assert!(check_domain("int.test").is_ok());
        assert!(check_domain("localhost").is_err());
        assert!(check_domain("bad domain.com").is_err());
        assert_eq!(check_service_name("Auth"), Ok("auth".into()));
        assert!(check_service_name("auth.example.com").is_err());
    }

    fn asker<'a>(given: Given, current: Current) -> Asker<'a> {
        Asker {
            interactive: false,
            given,
            current,
            sudo_user: Some("tia".into()),
            port_free: &|_, _| Ok(()),
            is_local: &|_| true,
            user_exists: &|u| u == "tia" || u == "tester",
        }
    }

    #[test]
    fn without_a_terminal_flags_and_defaults_decide() {
        let given = Given { public_url: Some("https://mesh.test".into()), ..Given::default() };
        let a = asker(given, Current::default()).ask_all().unwrap();
        assert_eq!(a, Answers {
            public_url: "https://mesh.test".into(),
            web_server: WebServer::Here,
            port: DEFAULT_PORT,
            approval: true,
            admin_user: Some("tia".into()),
        });
    }

    #[test]
    fn without_a_terminal_a_fresh_install_needs_the_public_url() {
        let err = asker(Given::default(), Current::default()).ask_all().unwrap_err();
        assert!(matches!(err, AskError::Missing { flag: "--public-url", .. }), "{err}");
    }

    #[test]
    fn without_a_terminal_the_current_settings_are_kept() {
        let current = Current {
            public_url: Some("https://old.test".into()),
            web_server: Some(WebServer::Here),
            port: Some(48000),
            approval: Some(false),
        };
        let a = asker(Given { approval: Some(true), ..Given::default() }, current).ask_all().unwrap();
        assert_eq!(a.public_url, "https://old.test");
        assert_eq!(a.port, 48000);
        assert!(a.approval, "the flag wins over the current setting");
    }

    #[test]
    fn a_taken_port_is_refused_unless_it_is_the_coordinators_own() {
        let taken: &dyn Fn(IpAddr, u16) -> Result<(), String> = &|_, _| Err("in use".into());
        let mut a = asker(
            Given { public_url: Some("https://mesh.test".into()), port: Some(48000), ..Given::default() },
            Current::default(),
        );
        a.port_free = taken;
        assert!(a.ask_all().is_err());
        a.current.port = Some(48000);
        assert_eq!(a.ask_all().unwrap().port, 48000);
    }

    #[test]
    fn admin_user_flags() {
        let base = || Given { public_url: Some("https://mesh.test".into()), ..Given::default() };
        let a = asker(Given { admin_user: Some(Some("tester".into())), ..base() }, Current::default());
        assert_eq!(a.ask_all().unwrap().admin_user.as_deref(), Some("tester"));
        let a = asker(Given { admin_user: Some(None), ..base() }, Current::default());
        assert_eq!(a.ask_all().unwrap().admin_user, None);
        let a = asker(Given { admin_user: Some(Some("nobody-here".into())), ..base() }, Current::default());
        assert!(a.ask_all().is_err());
    }
}
