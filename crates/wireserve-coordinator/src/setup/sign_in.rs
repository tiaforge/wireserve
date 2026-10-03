//! `setup sign-in` (PLAN.md M47, from M34's install question): the
//! forward_auth provider every terminator asks before letting a request
//! through to a service whose grants name a group of people.
//!
//! Any forward_auth provider works (`wireserve-tls`'s `sign_in.rs`), but
//! each has its own verify path, cookie and header names. Presets fill
//! them in for the ones checked against their source: authward, Authentik's
//! embedded outpost and Authelia; "other" asks for each.

use super::{confirm, people_groups, save, set_unless_default, Ctx, SetupError};
use crate::install::envfile::Change;
use crate::install::questions::{ask_until, ask_yes_no, check_node_name, check_service_name, explain, AskError};

#[derive(clap::Args, Debug, Default)]
pub struct SignInArgs {
    /// Your sign-in service: authward, authentik, authelia or other
    #[arg(long, value_name = "NAME", conflicts_with = "off")]
    pub provider: Option<String>,
    /// The wireserve service it runs as (default: auth)
    #[arg(long, value_name = "NAME", conflicts_with = "off")]
    pub service: Option<String>,
    /// The node that runs it
    // Every sign-in goes there, and a service of the same name on any other
    // node is ignored.
    #[arg(long, value_name = "NODE", conflicts_with = "off")]
    pub node: Option<String>,
    /// With --provider authentik: the Client ID of its proxy provider, which
    /// its session cookie is named after
    #[arg(long, value_name = "ID", conflicts_with = "off")]
    pub authentik_client_id: Option<String>,
    /// With --provider other: the path the terminators ask
    #[arg(long, value_name = "PATH", conflicts_with = "off")]
    pub verify_path: Option<String>,
    /// With --provider other: its session cookie's name
    #[arg(long, value_name = "NAME", conflicts_with = "off")]
    pub cookie: Option<String>,
    /// With --provider other: the header it names the user in
    #[arg(long, value_name = "HEADER", conflicts_with = "off")]
    pub user_header: Option<String>,
    /// With --provider other: the header it names their e-mail in
    #[arg(long, value_name = "HEADER", conflicts_with = "off")]
    pub email_header: Option<String>,
    /// With --provider other: the header it lists their groups in
    #[arg(long, value_name = "HEADER", conflicts_with = "off")]
    pub groups_header: Option<String>,
    /// With --provider other: what separates the groups, , or |
    #[arg(long, value_name = "CHAR", conflicts_with = "off")]
    pub groups_separator: Option<char>,
    /// No sign-in.
    #[arg(long)]
    pub off: bool,
    /// Don't ask before saving.
    #[arg(long, short)]
    pub yes: bool,
}

/// A provider's own names for things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Preset {
    pub name: &'static str,
    pub verify_path: &'static str,
    /// `None`: Authentik's is named after its client ID.
    pub cookie: Option<&'static str>,
    pub user: &'static str,
    pub email: &'static str,
    pub groups: &'static str,
    pub separator: char,
    /// Whether it binds a session to the device it was made on, which the
    /// terminators make possible by naming the device (access-control.md).
    pub binds_sessions: bool,
    /// The port it usually listens on, for the `wireserve <svc> 443:<port>`
    /// hint.
    pub port: u16,
}

pub const AUTHWARD: Preset = Preset {
    name: "authward",
    verify_path: "/verify",
    cookie: Some("authward_session"),
    user: "x-auth-user",
    email: "x-auth-email",
    groups: "x-auth-groups",
    separator: ',',
    binds_sessions: true,
    port: 8080,
};

/// The embedded outpost's Caddy endpoint, which rebuilds the URL from the
/// `X-Forwarded-*` headers the terminators send, and answers a browser not
/// signed in with a redirect. Groups are `|`-separated.
pub const AUTHENTIK: Preset = Preset {
    name: "authentik",
    verify_path: "/outpost.goauthentik.io/auth/caddy",
    cookie: None,
    user: "x-authentik-username",
    email: "x-authentik-email",
    groups: "x-authentik-groups",
    separator: '|',
    binds_sessions: true,
    port: 9000,
};

/// `/api/authz/forward-auth`: a 302 to the portal for a browser not signed
/// in, `Remote-*` headers joined with commas.
pub const AUTHELIA: Preset = Preset {
    name: "authelia",
    verify_path: "/api/authz/forward-auth",
    cookie: Some("authelia_session"),
    user: "remote-user",
    email: "remote-email",
    groups: "remote-groups",
    separator: ',',
    binds_sessions: false,
    port: 9091,
};

pub const PRESETS: [Preset; 3] = [AUTHWARD, AUTHENTIK, AUTHELIA];

/// Authentik's proxy session cookie: `authentik_proxy_` and the first four
/// bytes of the SHA-256 of the proxy provider's client ID, in hex (its
/// `src/outpost/proxy/cookie.rs`).
#[must_use]
pub fn authentik_cookie(client_id: &str) -> String {
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(client_id.trim().as_bytes());
    let mut name = "authentik_proxy_".to_string();
    for b in hash.iter().take(4) {
        name.push_str(&format!("{b:02x}"));
    }
    name
}

/// The settings `setup sign-in` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignIn {
    pub service: String,
    pub node: String,
    pub verify_path: String,
    pub cookie: String,
    pub user: String,
    pub email: String,
    pub groups: String,
    pub separator: char,
}

impl SignIn {
    fn lookup(&self, key: &str) -> Option<String> {
        Some(match key {
            "WIRESERVE_AUTH_SERVICE" => self.service.clone(),
            "WIRESERVE_AUTH_NODE" => self.node.clone(),
            "WIRESERVE_AUTH_VERIFY_PATH" => self.verify_path.clone(),
            "WIRESERVE_AUTH_SESSION_COOKIE" => self.cookie.clone(),
            "WIRESERVE_AUTH_USER_HEADER" => self.user.clone(),
            "WIRESERVE_AUTH_EMAIL_HEADER" => self.email.clone(),
            "WIRESERVE_AUTH_GROUPS_HEADER" => self.groups.clone(),
            "WIRESERVE_AUTH_GROUPS_SEPARATOR" => self.separator.to_string(),
            _ => return None,
        })
    }

    /// Checks the settings the way the coordinator will at startup.
    pub fn check(&self) -> Result<(), String> {
        let describe = |e: crate::config::ConfigError| match e {
            crate::config::ConfigError::Invalid(key, why) => format!("{key} {why}"),
            e => e.to_string(),
        };
        crate::config::sign_in_from_lookup(|k| self.lookup(k), true).map_err(describe)?;
        crate::config::identity_headers_from_lookup(|k| self.lookup(k)).map_err(describe)?;
        Ok(())
    }

    /// The preset these settings are, if any.
    #[must_use]
    pub fn preset(&self) -> Option<Preset> {
        PRESETS.into_iter().find(|p| {
            p.verify_path == self.verify_path
                && p.user == self.user
                && p.groups == self.groups
                && p.separator == self.separator
                && p.cookie.is_none_or(|c| c == self.cookie)
        })
    }
}

pub const KEYS: [&str; 8] = [
    "WIRESERVE_AUTH_SERVICE",
    "WIRESERVE_AUTH_NODE",
    "WIRESERVE_AUTH_VERIFY_PATH",
    "WIRESERVE_AUTH_SESSION_COOKIE",
    "WIRESERVE_AUTH_USER_HEADER",
    "WIRESERVE_AUTH_EMAIL_HEADER",
    "WIRESERVE_AUTH_GROUPS_HEADER",
    "WIRESERVE_AUTH_GROUPS_SEPARATOR",
];

/// The env-file edits. authward's names are the coordinator's defaults and
/// stay out of the file.
///
/// Turning the sign-in off keeps the identity header names: a device's
/// owner (M38) is named to backends in them too, and a backend set up to
/// read Authentik's would stop hearing who calls.
#[must_use]
pub fn env_changes(sign_in: Option<&SignIn>) -> Vec<(&'static str, Change)> {
    let Some(s) = sign_in else {
        return KEYS[..4].iter().map(|k| (*k, Change::Clear)).collect();
    };
    vec![
        ("WIRESERVE_AUTH_SERVICE", Change::Set(s.service.clone())),
        ("WIRESERVE_AUTH_NODE", Change::Set(s.node.clone())),
        ("WIRESERVE_AUTH_VERIFY_PATH", set_unless_default(&s.verify_path, AUTHWARD.verify_path)),
        ("WIRESERVE_AUTH_SESSION_COOKIE", set_unless_default(&s.cookie, AUTHWARD.cookie.unwrap_or_default())),
        ("WIRESERVE_AUTH_USER_HEADER", set_unless_default(&s.user, AUTHWARD.user)),
        ("WIRESERVE_AUTH_EMAIL_HEADER", set_unless_default(&s.email, AUTHWARD.email)),
        ("WIRESERVE_AUTH_GROUPS_HEADER", set_unless_default(&s.groups, AUTHWARD.groups)),
        ("WIRESERVE_AUTH_GROUPS_SEPARATOR", set_unless_default(&s.separator.to_string(), ",")),
    ]
}

fn current(ctx: &Ctx) -> Option<SignIn> {
    let d = AUTHWARD;
    Some(SignIn {
        service: ctx.get("WIRESERVE_AUTH_SERVICE")?,
        node: ctx.get("WIRESERVE_AUTH_NODE").unwrap_or_default(),
        verify_path: ctx.get("WIRESERVE_AUTH_VERIFY_PATH").unwrap_or_else(|| d.verify_path.into()),
        cookie: ctx.get("WIRESERVE_AUTH_SESSION_COOKIE").unwrap_or_else(|| d.cookie.unwrap_or_default().into()),
        user: ctx.get("WIRESERVE_AUTH_USER_HEADER").map_or_else(|| d.user.into(), |v| v.to_ascii_lowercase()),
        email: ctx.get("WIRESERVE_AUTH_EMAIL_HEADER").map_or_else(|| d.email.into(), |v| v.to_ascii_lowercase()),
        groups: ctx.get("WIRESERVE_AUTH_GROUPS_HEADER").map_or_else(|| d.groups.into(), |v| v.to_ascii_lowercase()),
        separator: ctx.get("WIRESERVE_AUTH_GROUPS_SEPARATOR").and_then(|v| v.trim().chars().next()).unwrap_or(','),
    })
}

fn check_provider(raw: &str) -> Result<Option<Preset>, String> {
    let p = raw.trim().to_ascii_lowercase();
    if p == "other" {
        return Ok(None);
    }
    PRESETS.into_iter().find(|x| x.name == p).map(Some).ok_or_else(|| "pick authward, authentik, authelia or other".into())
}

fn check_text(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() || s.contains(char::is_whitespace) {
        return Err("it can't be empty or hold spaces".into());
    }
    Ok(s.to_string())
}

fn check_separator(raw: &str) -> Result<char, String> {
    match raw.trim() {
        "," => Ok(','),
        "|" => Ok('|'),
        _ => Err("type , or |".into()),
    }
}

pub fn run(ctx: &Ctx, args: &SignInArgs) -> Result<(), SetupError> {
    let current = current(ctx);
    let has_dns = ctx.get("WIRESERVE_SERVICE_DOMAIN").is_some() && ctx.get("WIRESERVE_DNS_PROVIDER").is_some();
    let flags = args.provider.is_some() || args.service.is_some() || args.node.is_some();
    let wanted = if args.off {
        false
    } else if flags || !ctx.interactive {
        flags || current.is_some()
    } else if !has_dns {
        // Nothing to ask yet: say what it is for, and what comes first.
        explain(&WHY);
        explain(&[
            "It needs your own domain first, with DNS records wireserve manages: the",
            "sign-in runs in each node's HTTPS. When you want it:",
            "",
            "  sudo wireserve-coordinator setup domain",
            "  sudo wireserve-coordinator setup sign-in",
        ]);
        return Ok(());
    } else {
        explain(&WHY);
        ask_yes_no("Ask people to sign in on shared computers?", current.is_some())
    };
    if !wanted {
        if current.is_none() {
            println!("Nothing changed: no sign-in, as before.");
            return Ok(());
        }
        confirm(ctx, args.yes, &["Sign-in:  off — every service goes by the device again".into()])?;
        save(ctx, &env_changes(None))?;
        return Ok(());
    }
    if !has_dns {
        return Err(SetupError::Failed(
            "the sign-in needs your own domain, with DNS records wireserve manages: it runs in each \
             node's HTTPS, which needs them. Run `sudo wireserve-coordinator setup domain` first."
                .into(),
        ));
    }
    let domain = ctx.get("WIRESERVE_SERVICE_DOMAIN").unwrap_or_default();
    let nodes = ctx.admin().and_then(|a| a.nodes());
    let (sign_in, preset) = ask(ctx, args, current.as_ref(), &domain, nodes.as_deref())?;
    sign_in.check().map_err(SetupError::Failed)?;

    let summary = vec![
        format!("Sign-in:        https://{}.{domain}, run by {}", sign_in.service, preset.map_or("your provider", |p| p.name)),
        format!("On node:        {} (the same name anywhere else is ignored)", sign_in.node),
        format!("Verify path:    {}", sign_in.verify_path),
        format!("Session cookie: {}", sign_in.cookie),
        format!("Headers:        {}, {}, {} (groups split on {})", sign_in.user, sign_in.email, sign_in.groups, sign_in.separator),
    ];
    confirm(ctx, args.yes, &summary)?;
    if !save(ctx, &env_changes(Some(&sign_in)))? {
        return Ok(());
    }
    println!();
    println!("Next:");
    let port = preset.map_or_else(|| "<its port>".to_string(), |p| p.port.to_string());
    println!("  on {}:   wireserve {} 443:{port}", sign_in.node, sign_in.service);
    let grants = ctx.admin().and_then(|a| a.grants());
    if grants.as_deref().map(people_groups).unwrap_or_default().is_empty() {
        println!("  then:      wireserve-admin grant add oidc:family media");
        println!("             a service in \"media\" then asks anyone not granted otherwise to sign in,");
        println!("             and lets in people in \"family\".");
    } else {
        println!("  Services whose grants name a group of people now ask anyone not granted");
        println!("  otherwise to sign in.");
    }
    if !preset.is_some_and(|p| p.binds_sessions) {
        println!();
        println!("Note: {} does not tie a session to the device it was made on. Its cookie reaches", preset.map_or("your provider", |p| p.name));
        println!("every service under {domain}, so whoever runs one of them could reuse a visitor's");
        println!("session. Approve services only for nodes you trust (see docs/access-control.md).");
    }
    Ok(())
}

const WHY: [&str; 14] = [
    "Some computers are shared: the family laptop, the TV. To wireserve that's",
    "one device, so everyone using it gets the same access.",
    "",
    "For web services, wireserve can tell the people apart: a service asks",
    "whoever opens it to sign in first, and lets them in if their group may.",
    "This works for web pages only (HTTPS on port 443) — SSH, file shares or a",
    "game server still go by the device — and apps that aren't a browser, like",
    "the Jellyfin or Home Assistant apps, can't sign in this way.",
    "",
    "It needs a sign-in service you run as one of your wireserve services:",
    "authward, or the one built into Authentik or Authelia.",
    "",
    "If no computer here is shared, you don't need this; skipping it changes",
    "nothing, and you can come back any time.",
];

fn ask(
    ctx: &Ctx,
    args: &SignInArgs,
    current: Option<&SignIn>,
    domain: &str,
    nodes: Option<&[String]>,
) -> Result<(SignIn, Option<Preset>), SetupError> {
    let interactive = ctx.interactive;
    let current_preset = current.and_then(SignIn::preset);
    let preset = match &args.provider {
        Some(raw) => check_provider(raw).map_err(|e| AskError::Invalid(format!("--provider: {e}")))?,
        None if !interactive => match current {
            Some(c) => c.preset(),
            None => Some(AUTHWARD),
        },
        None => {
            eprintln!();
            let default = match (current, current_preset) {
                (Some(_), None) => "other",
                (_, Some(p)) => p.name,
                (None, None) => "authward",
            };
            ask_until("Which sign-in service do you run? (authward, authentik, authelia, other)", Some(default), check_provider)?
        }
    };

    let service = match &args.service {
        Some(raw) => check_service_name(raw).map_err(|e| AskError::Invalid(format!("--service: {e}")))?,
        None => {
            let default = current.map_or("auth", |c| c.service.as_str());
            if interactive {
                explain(&[
                    "It runs as a wireserve service on port 443, like any other, and its",
                    &format!("pages are then at https://<name>.{domain}."),
                ]);
                ask_until("Its service name", Some(default), check_service_name)?
            } else {
                default.to_string()
            }
        }
    };
    let current_node = current.map(|c| c.node.as_str()).filter(|n| !n.is_empty());
    let node = match &args.node {
        Some(raw) => check_node_name(raw).map_err(|e| AskError::Invalid(format!("--node: {e}")))?,
        None if !interactive => current_node
            .map(str::to_string)
            .ok_or(AskError::Missing { question: "the node running the sign-in", flag: "--node" })?,
        None => {
            explain(&[
                "Every sign-in goes to that service, so it is trusted only on the machine",
                "you name here: the same name shared by any other machine is ignored.",
            ]);
            ask_until("Machine running it (its node name)", current_node, check_node_name)?
        }
    };
    if let Some(nodes) = nodes {
        if !nodes.contains(&node) {
            eprintln!("note: there is no node called {node} yet; the sign-in starts working once it joins and serves {service}");
        }
    }

    let keep = |pick: fn(&SignIn) -> &String, fallback: &str| current.map_or_else(|| fallback.to_string(), |c| pick(c).clone());
    let sign_in = match preset {
        Some(p) => {
            let cookie = match p.cookie {
                Some(c) => c.to_string(),
                None => authentik_client_cookie(interactive, args, current)?,
            };
            SignIn {
                service,
                node,
                verify_path: p.verify_path.into(),
                cookie,
                user: p.user.into(),
                email: p.email.into(),
                groups: p.groups.into(),
                separator: p.separator,
            }
        }
        None => {
            let field = |given: &Option<String>, label: &str, flag: &'static str, kept: String| -> Result<String, AskError> {
                match given {
                    Some(v) => check_text(v).map_err(|e| AskError::Invalid(format!("{flag}: {e}"))),
                    None if !interactive => Ok(kept),
                    None => ask_until(label, Some(&kept), check_text),
                }
            };
            if interactive {
                explain(&[
                    "Your provider's documentation for Caddy's forward_auth names these.",
                    "Enter keeps the value in [brackets].",
                ]);
            }
            let verify_path = field(&args.verify_path, "Path the check goes to", "--verify-path", keep(|c| &c.verify_path, AUTHWARD.verify_path))?;
            let cookie = field(&args.cookie, "Its session cookie's name", "--cookie", keep(|c| &c.cookie, AUTHWARD.cookie.unwrap_or_default()))?;
            let user = field(&args.user_header, "Header naming the user", "--user-header", keep(|c| &c.user, AUTHWARD.user))?;
            let email = field(&args.email_header, "Header naming their e-mail", "--email-header", keep(|c| &c.email, AUTHWARD.email))?;
            let groups = field(&args.groups_header, "Header listing their groups", "--groups-header", keep(|c| &c.groups, AUTHWARD.groups))?;
            let kept_sep = current.map_or(',', |c| c.separator);
            let separator = match args.groups_separator {
                Some(c) => check_separator(&c.to_string()).map_err(|e| AskError::Invalid(format!("--groups-separator: {e}")))?,
                None if !interactive => kept_sep,
                None => ask_until("What separates the groups in it? (, or |)", Some(&kept_sep.to_string()), check_separator)?,
            };
            SignIn {
                service,
                node,
                verify_path,
                cookie,
                user: user.to_ascii_lowercase(),
                email: email.to_ascii_lowercase(),
                groups: groups.to_ascii_lowercase(),
                separator,
            }
        }
    };
    Ok((sign_in, preset))
}

/// Authentik's cookie, from its proxy provider's client ID.
fn authentik_client_cookie(interactive: bool, args: &SignInArgs, current: Option<&SignIn>) -> Result<String, AskError> {
    if let Some(id) = &args.authentik_client_id {
        return check_text(id).map(|id| authentik_cookie(&id)).map_err(|e| AskError::Invalid(format!("--authentik-client-id: {e}")));
    }
    let kept = current.filter(|c| c.cookie.starts_with("authentik_proxy_")).map(|c| c.cookie.clone());
    if !interactive {
        return kept.ok_or(AskError::Missing { question: "the Authentik proxy provider's client ID", flag: "--authentik-client-id" });
    }
    explain(&[
        "In Authentik, the sign-in is a Proxy Provider in \"Forward auth (domain",
        "level)\" mode, served by the embedded outpost. Its session cookie is",
        "named after the provider's Client ID, which its page shows. (Enter keeps",
        "the cookie set now, if there is one.)",
    ]);
    let answer = ask_until("The proxy provider's Client ID", Some(kept.as_deref().unwrap_or("-")), |raw| {
        let raw = raw.trim();
        if raw == "-" {
            return kept.clone().ok_or_else(|| "the cookie can't be worked out without it".to_string());
        }
        if kept.as_deref() == Some(raw) {
            return Ok(raw.to_string());
        }
        check_text(raw).map(|id| authentik_cookie(&id))
    })?;
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change<'a>(changes: &'a [(&str, Change)], key: &str) -> &'a Change {
        &changes.iter().find(|(k, _)| *k == key).unwrap().1
    }

    fn sign_in(p: Preset, cookie: &str) -> SignIn {
        SignIn {
            service: "auth".into(),
            node: "gate".into(),
            verify_path: p.verify_path.into(),
            cookie: cookie.into(),
            user: p.user.into(),
            email: p.email.into(),
            groups: p.groups.into(),
            separator: p.separator,
        }
    }

    #[test]
    fn authentiks_cookie_is_named_after_its_client_id() {
        // `printf client-123 | sha256sum` begins b44ea687.
        let name = authentik_cookie("client-123");
        assert_eq!(name, "authentik_proxy_b44ea687");
        assert_eq!(name, authentik_cookie(" client-123 "));
        assert_ne!(name, authentik_cookie("client-456"));
    }

    #[test]
    fn every_preset_passes_the_coordinators_own_checks() {
        for p in PRESETS {
            let s = sign_in(p, p.cookie.unwrap_or("authentik_proxy_0011aabb"));
            s.check().unwrap_or_else(|e| panic!("{}: {e}", p.name));
            assert_eq!(s.preset(), Some(p), "{} is recognised again", p.name);
        }
        let mut odd = sign_in(AUTHWARD, "authward_session");
        odd.verify_path = "/auth".into();
        assert_eq!(odd.preset(), None);
        odd.user = "cookie".into();
        assert!(odd.check().is_err(), "a header everything relies on");
    }

    #[test]
    fn authward_writes_only_the_service_and_node() {
        let c = env_changes(Some(&sign_in(AUTHWARD, "authward_session")));
        assert_eq!(change(&c, "WIRESERVE_AUTH_SERVICE"), &Change::Set("auth".into()));
        assert_eq!(change(&c, "WIRESERVE_AUTH_NODE"), &Change::Set("gate".into()));
        for key in &KEYS[2..] {
            assert_eq!(change(&c, key), &Change::Clear, "{key}");
        }
        let c = env_changes(Some(&sign_in(AUTHENTIK, "authentik_proxy_0011aabb")));
        assert_eq!(change(&c, "WIRESERVE_AUTH_GROUPS_SEPARATOR"), &Change::Set("|".into()));
        assert_eq!(change(&c, "WIRESERVE_AUTH_SESSION_COOKIE"), &Change::Set("authentik_proxy_0011aabb".into()));
    }

    #[test]
    fn off_keeps_the_identity_header_names() {
        let c = env_changes(None);
        assert_eq!(c.len(), 4);
        assert!(c.iter().all(|(k, v)| *v == Change::Clear && !k.ends_with("_HEADER") && !k.ends_with("_SEPARATOR")));
    }
}
