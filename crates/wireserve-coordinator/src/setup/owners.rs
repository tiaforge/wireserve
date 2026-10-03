//! `setup owners` (PLAN.md M47): devices that belong to someone, through
//! the operator's login server (M38).
//!
//! The coordinator becomes an OpenID Connect client of that server. What
//! has to match on both sides — the redirect URL, the issuer, the client —
//! is shown or checked here, against the server's discovery document,
//! before anything is saved: a typo would otherwise only show when someone
//! opened a claim link.

use super::{confirm, people_groups, same_for_every_device, save, set_unless_default, Ctx, SetupError};
use crate::install::envfile::Change;
use crate::install::questions::{ask_secret, ask_until, ask_yes_no, explain, AskError};

/// What the coordinator asks for unless told otherwise (`config.rs`).
pub const DEFAULT_SCOPES: [&str; 5] = ["openid", "email", "profile", "groups", "offline_access"];
const DEFAULT_GROUPS_CLAIM: &str = "groups";
const SECRET_ENV: &str = "WIRESERVE_OIDC_CLIENT_SECRET";
const KEYS: [&str; 5] = [
    "WIRESERVE_OIDC_ISSUER",
    "WIRESERVE_OIDC_CLIENT_ID",
    "WIRESERVE_OIDC_CLIENT_SECRET",
    "WIRESERVE_OIDC_GROUPS_CLAIM",
    "WIRESERVE_OIDC_SCOPES",
];

#[derive(clap::Args, Debug, Default)]
pub struct OwnersArgs {
    /// The login server's issuer URL, e.g. https://id.example.com
    // The client secret comes from WIRESERVE_OIDC_CLIENT_SECRET, never the
    // command line, where any user could read it.
    #[arg(long, value_name = "URL", conflicts_with = "off")]
    pub issuer: Option<String>,
    /// The client ID wireserve was registered under at the login server.
    #[arg(long, value_name = "ID", conflicts_with = "off")]
    pub client_id: Option<String>,
    /// The claim that lists a person's groups (default: groups).
    #[arg(long, value_name = "CLAIM", conflicts_with = "off")]
    pub groups_claim: Option<String>,
    /// Devices belong to nobody any more.
    #[arg(long)]
    pub off: bool,
    /// Don't check the login server's discovery document first.
    #[arg(long)]
    pub skip_check: bool,
    /// Don't ask before saving.
    #[arg(long, short)]
    pub yes: bool,
}

/// The settings `setup owners` writes.
#[derive(Clone, PartialEq, Eq)]
pub struct Owners {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub groups_claim: String,
    /// Narrowed to what the server lists, when it lists any.
    pub scopes: Vec<String>,
}

// The secret never reaches a log or a panic message.
impl std::fmt::Debug for Owners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Owners").field("issuer", &self.issuer).field("client_id", &self.client_id).finish_non_exhaustive()
    }
}

#[must_use]
pub fn env_changes(owners: Option<&Owners>) -> Vec<(&'static str, Change)> {
    let Some(o) = owners else {
        return KEYS.iter().map(|k| (*k, Change::Clear)).collect();
    };
    let default_scopes = DEFAULT_SCOPES.join(" ");
    vec![
        ("WIRESERVE_OIDC_ISSUER", Change::Set(o.issuer.clone())),
        ("WIRESERVE_OIDC_CLIENT_ID", Change::Set(o.client_id.clone())),
        ("WIRESERVE_OIDC_CLIENT_SECRET", Change::Set(o.client_secret.clone())),
        ("WIRESERVE_OIDC_GROUPS_CLAIM", set_unless_default(&o.groups_claim, DEFAULT_GROUPS_CLAIM)),
        ("WIRESERVE_OIDC_SCOPES", set_unless_default(&o.scopes.join(" "), &default_scopes)),
    ]
}

/// What the login server's discovery document says, as far as it matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// The issuer exactly as the server spells it, which the coordinator
    /// then uses: providers differ on a trailing slash.
    pub issuer: String,
    /// The scopes to ask for: the defaults the server lists, when it lists
    /// any. Keycloak refuses a scope it does not know, and Authentik puts
    /// groups in `profile` rather than a `groups` scope.
    pub scopes: Vec<String>,
    /// Things worth knowing, that don't stop anything.
    pub notes: Vec<String>,
}

/// Judges a discovery document fetched for `configured`.
pub fn judge(configured: &str, doc: &serde_json::Value, groups_claim: &str) -> Result<Discovered, String> {
    let issuer = doc.get("issuer").and_then(|v| v.as_str()).ok_or("its discovery document names no issuer")?;
    if issuer.trim_end_matches('/') != configured.trim_end_matches('/') {
        return Err(format!("it calls itself {issuer}; use exactly that"));
    }
    if doc.get("token_endpoint").and_then(|v| v.as_str()).is_none() {
        return Err("its discovery document has no token endpoint".into());
    }
    let list = |key: &str| -> Option<Vec<String>> {
        doc.get(key)?.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
    };
    let mut notes = Vec::new();
    let scopes = match list("scopes_supported") {
        Some(supported) => {
            let kept: Vec<String> = DEFAULT_SCOPES
                .iter()
                .filter(|s| **s == "openid" || supported.iter().any(|x| x == *s))
                .map(|s| (*s).to_string())
                .collect();
            if !kept.iter().any(|s| s == "offline_access") {
                notes.push(
                    "it does not list the offline_access scope. Without a refresh token the coordinator \
                     cannot keep anyone's groups current, and claiming a device fails; most servers need \
                     it allowed for the client (see the recipe for yours)."
                        .into(),
                );
            }
            kept
        }
        None => DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect(),
    };
    if let Some(claims) = list("claims_supported") {
        if !claims.iter().any(|c| c == groups_claim) {
            notes.push(format!(
                "it does not list a `{groups_claim}` claim. Some servers (Keycloak) only add it through a \
                 mapper you set up; without it people have no groups here."
            ));
        }
    }
    Ok(Discovered { issuer: issuer.to_string(), scopes, notes })
}

/// Fetches and judges the discovery document of `issuer`.
pub fn discover(issuer: &str, groups_claim: &str) -> Result<Discovered, String> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = http.get(&url).send().map_err(|e| format!("could not reach {url}: {}", innermost(&e)))?;
    if !resp.status().is_success() {
        return Err(format!("{url} answered {}; is that the issuer URL?", resp.status()));
    }
    let doc: serde_json::Value = resp.json().map_err(|e| format!("{url} is not a discovery document: {e}"))?;
    judge(issuer, &doc, groups_claim)
}

/// The deepest cause of an error: reqwest's own message only says that a
/// request failed, its source says why (refused, unknown host, …).
fn innermost(e: &dyn std::error::Error) -> String {
    let mut cause = e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

pub fn check_issuer_syntax(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if !(s.starts_with("https://") || s.starts_with("http://")) || s.contains(char::is_whitespace) {
        return Err("that is not an address like https://id.example.com".into());
    }
    Ok(s.to_string())
}

fn check_plain(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    if s.is_empty() || s.contains(char::is_whitespace) {
        return Err("it can't be empty or hold spaces".into());
    }
    Ok(s.to_string())
}

/// The settings as the env file has them now.
fn current(ctx: &Ctx) -> Option<Owners> {
    Some(Owners {
        issuer: ctx.get("WIRESERVE_OIDC_ISSUER")?,
        client_id: ctx.get("WIRESERVE_OIDC_CLIENT_ID").unwrap_or_default(),
        client_secret: ctx.get("WIRESERVE_OIDC_CLIENT_SECRET").unwrap_or_default(),
        groups_claim: ctx.get("WIRESERVE_OIDC_GROUPS_CLAIM").unwrap_or_else(|| DEFAULT_GROUPS_CLAIM.into()),
        scopes: ctx
            .get("WIRESERVE_OIDC_SCOPES")
            .map(|s| s.split([' ', ',']).filter(|x| !x.is_empty()).map(str::to_string).collect())
            .unwrap_or_else(|| DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect()),
    })
}

pub fn run(ctx: &Ctx, args: &OwnersArgs) -> Result<(), SetupError> {
    let public = ctx.get("WIRESERVE_PUBLIC_URL").ok_or_else(|| {
        SetupError::Failed("the coordinator has no WIRESERVE_PUBLIC_URL; `sudo wireserve-coordinator install --reconfigure` sets it".into())
    })?;
    let redirect = format!("{public}/claim/callback");
    let current = current(ctx);
    let grants = ctx.admin().and_then(|a| a.grants());

    let wanted = if args.off {
        false
    } else if args.issuer.is_some() || args.client_id.is_some() || args.groups_claim.is_some() || !ctx.interactive {
        args.issuer.is_some() || current.is_some()
    } else {
        explain(&why(grants.as_deref()));
        ask_yes_no("Let devices belong to people?", current.is_some())
    };
    if !wanted {
        if current.is_none() {
            println!("Nothing changed: devices don't belong to anyone, as before.");
            return Ok(());
        }
        confirm(ctx, args.yes, &["Device owners:  off — devices lose what their owners' groups gave them".into()])?;
        save(ctx, &env_changes(None))?;
        return Ok(());
    }

    let owners = ask(ctx, args, current.as_ref(), &redirect)?;
    let summary = vec![
        format!("Login server:   {}", owners.issuer),
        format!("Client ID:      {}", owners.client_id),
        format!("Redirect URL:   {redirect}   (registered there)"),
        format!("Groups claim:   {}", owners.groups_claim),
        format!("Scopes:         {}", owners.scopes.join(" ")),
    ];
    confirm(ctx, args.yes, &summary)?;
    if !save(ctx, &env_changes(Some(&owners)))? {
        return Ok(());
    }
    println!();
    println!("Devices can now belong to people. Next, from wherever you use wireserve-admin:");
    let groups = grants.as_deref().map(people_groups).unwrap_or_default();
    if groups.is_empty() {
        println!("  wireserve-admin grant add oidc:family media    let the \"family\" group reach the services in \"media\"");
    } else {
        println!("  (grants already name: {})", groups.iter().map(|g| format!("oidc:{g}")).collect::<Vec<_>>().join(", "));
    }
    println!("  wireserve-admin owner link laptop --qr         the person opens it and signs in");
    println!("  wireserve-admin owner status                   checks the login server and lists owners");
    Ok(())
}

/// Why anyone would want this, in terms of their own mesh.
fn why(grants: Option<&[wireserve_types::GrantInfo]>) -> Vec<String> {
    let mut lines: Vec<String> = [
        "Right now each device gets access on its own: what its tags allow, or",
        "what every device gets.",
        "",
        "If other people use this mesh too, access can follow the PERSON instead.",
        "Anna's laptop and her phone both get what Anna is allowed, and when she",
        "leaves the \"family\" group at your login server, both lose it — nobody",
        "has to retag anything. You hand each device to its person with a link",
        "they open once and sign in with.",
        "",
        "This needs a login server you already run, like Pocket ID, Authentik or",
        "Keycloak. If it's just you, or you don't run one, you don't need this;",
        "skipping it changes nothing, and you can come back any time.",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    if grants.is_some_and(same_for_every_device) {
        lines.push(String::new());
        lines.push("At the moment every device gets the same access (no grant names a tag or".into());
        lines.push("a group of people), so this changes nothing until you also grant a group,".into());
        lines.push("e.g. `wireserve-admin grant add oidc:family media`.".into());
    }
    lines
}

fn ask(ctx: &Ctx, args: &OwnersArgs, current: Option<&Owners>, redirect: &str) -> Result<Owners, SetupError> {
    let groups_claim = match &args.groups_claim {
        Some(c) => check_plain(c).map_err(|e| AskError::Invalid(format!("--groups-claim: {e}")))?,
        None => current.map_or_else(|| DEFAULT_GROUPS_CLAIM.to_string(), |c| c.groups_claim.clone()),
    };
    let probe = |issuer: &str, claim: &str| -> Result<Discovered, String> {
        if args.skip_check {
            Ok(Discovered {
                issuer: issuer.to_string(),
                scopes: current.map_or_else(|| DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect(), |c| c.scopes.clone()),
                notes: Vec::new(),
            })
        } else {
            eprintln!("  checking {issuer} …");
            discover(issuer, claim)
        }
    };

    if !ctx.interactive {
        let issuer = match &args.issuer {
            Some(raw) => check_issuer_syntax(raw).map_err(|e| AskError::Invalid(format!("--issuer: {e}")))?,
            None => current.map(|c| c.issuer.clone()).ok_or(AskError::Missing { question: "the issuer", flag: "--issuer" })?,
        };
        let client_id = match &args.client_id {
            Some(raw) => check_plain(raw).map_err(|e| AskError::Invalid(format!("--client-id: {e}")))?,
            None => current.map(|c| c.client_id.clone()).filter(|c| !c.is_empty())
                .ok_or(AskError::Missing { question: "the client ID", flag: "--client-id" })?,
        };
        let client_secret = std::env::var(SECRET_ENV).ok().filter(|s| !s.trim().is_empty()).map(|s| s.trim().to_string())
            .or_else(|| current.map(|c| c.client_secret.clone()).filter(|s| !s.is_empty()))
            .ok_or(AskError::Missing { question: "the client secret", flag: SECRET_ENV })?;
        let found = probe(&issuer, &groups_claim).map_err(|e| SetupError::Failed(format!("the login server at {issuer}: {e}")))?;
        for n in &found.notes {
            eprintln!("note: {n}");
        }
        return Ok(Owners { issuer: found.issuer, client_id, client_secret, groups_claim, scopes: found.scopes });
    }

    explain(&[
        "First, at your login server, create an application for wireserve — it may",
        "be called an OpenID Connect client, an OAuth2 provider or an app — with a",
        "client secret (\"confidential\"). It asks where to send people back after",
        "they sign in. Give it exactly:",
        "",
        &format!("    {redirect}"),
        "",
        "Step by step for Pocket ID, Authentik and Keycloak: docs/identity-providers.md",
        "in wireserve's source.",
    ]);
    explain(&[
        "The login server's issuer URL is the address it signs in under:",
        "  Pocket ID:  its own address, like https://id.example.com",
        "  Authentik:  https://auth.example.com/application/o/<the app's slug>/",
        "  Keycloak:   https://kc.example.com/realms/<your realm>",
    ]);
    let found = ask_until("Issuer URL", current.map(|c| c.issuer.as_str()), |raw| {
        let issuer = check_issuer_syntax(raw)?;
        probe(&issuer, &groups_claim)
    })?;
    eprintln!("  OK: found {}.", found.issuer);
    for n in &found.notes {
        eprintln!("  note: {n}");
    }
    let client_id = ask_until("Client ID", current.map(|c| c.client_id.as_str()).filter(|c| !c.is_empty()), check_plain)?;
    let client_secret = loop {
        if let Some(s) = ask_secret("Client secret", current.map(|c| c.client_secret.clone()).filter(|s| !s.is_empty()))? {
            break s;
        }
    };
    explain(&[
        "The claim your login server lists a person's groups in. It is nearly",
        "always \"groups\"; Enter keeps it.",
    ]);
    let groups_claim = ask_until("Groups claim", Some(&groups_claim), check_plain)?;
    Ok(Owners { issuer: found.issuer, client_id, client_secret, groups_claim, scopes: found.scopes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn change<'a>(changes: &'a [(&str, Change)], key: &str) -> &'a Change {
        &changes.iter().find(|(k, _)| *k == key).unwrap().1
    }

    #[test]
    fn the_issuer_is_taken_as_the_server_spells_it() {
        let doc = json!({"issuer": "https://auth.example.com/application/o/wireserve/", "token_endpoint": "https://t"});
        let d = judge("https://auth.example.com/application/o/wireserve", &doc, "groups").unwrap();
        assert_eq!(d.issuer, "https://auth.example.com/application/o/wireserve/");
        assert_eq!(d.scopes, DEFAULT_SCOPES, "nothing listed, nothing narrowed");
        assert!(d.notes.is_empty());
        let err = judge("https://other.example.com", &doc, "groups").unwrap_err();
        assert!(err.contains("use exactly that"), "{err}");
        assert!(judge("https://auth.example.com/application/o/wireserve", &json!({"issuer": "https://auth.example.com/application/o/wireserve/"}), "groups").is_err(), "no token endpoint");
    }

    #[test]
    fn scopes_are_narrowed_to_what_the_server_lists() {
        // Authentik: groups come in `profile`, there is no `groups` scope.
        let doc = json!({"issuer": "https://a", "token_endpoint": "https://t",
            "scopes_supported": ["openid", "email", "profile", "offline_access"],
            "claims_supported": ["sub", "email", "groups"]});
        let d = judge("https://a", &doc, "groups").unwrap();
        assert_eq!(d.scopes, ["openid", "email", "profile", "offline_access"]);
        assert!(d.notes.is_empty(), "{:?}", d.notes);

        let doc = json!({"issuer": "https://k", "token_endpoint": "https://t",
            "scopes_supported": ["openid", "email"], "claims_supported": ["sub"]});
        let d = judge("https://k", &doc, "groups").unwrap();
        assert_eq!(d.scopes, ["openid", "email"]);
        assert_eq!(d.notes.len(), 2, "no offline_access, no groups claim: {:?}", d.notes);
    }

    #[test]
    fn defaults_stay_out_of_the_file_and_off_clears_everything() {
        let o = Owners {
            issuer: "https://id.example.com".into(),
            client_id: "wireserve".into(),
            client_secret: "s3cret".into(),
            groups_claim: "groups".into(),
            scopes: DEFAULT_SCOPES.iter().map(|s| (*s).to_string()).collect(),
        };
        let c = env_changes(Some(&o));
        assert_eq!(change(&c, "WIRESERVE_OIDC_ISSUER"), &Change::Set("https://id.example.com".into()));
        assert_eq!(change(&c, "WIRESERVE_OIDC_SCOPES"), &Change::Clear);
        assert_eq!(change(&c, "WIRESERVE_OIDC_GROUPS_CLAIM"), &Change::Clear);
        let narrowed = Owners { scopes: vec!["openid".into(), "profile".into()], groups_claim: "roles".into(), ..o.clone() };
        let c = env_changes(Some(&narrowed));
        assert_eq!(change(&c, "WIRESERVE_OIDC_SCOPES"), &Change::Set("openid profile".into()));
        assert_eq!(change(&c, "WIRESERVE_OIDC_GROUPS_CLAIM"), &Change::Set("roles".into()));
        assert!(env_changes(None).iter().all(|(_, c)| *c == Change::Clear));
        assert!(!format!("{o:?}").contains("s3cret"));
    }

    #[test]
    fn the_why_says_when_it_would_change_nothing_yet() {
        let open = [wireserve_types::GrantInfo { source: wireserve_types::GrantSource::Everyone, group: "default".into() }];
        assert!(why(Some(&open)).iter().any(|l| l.contains("changes nothing until")));
        assert!(!why(None).iter().any(|l| l.contains("changes nothing until")), "can't say without the coordinator");
    }

    #[test]
    fn the_default_scopes_are_the_coordinators() {
        let cfg = crate::config::oidc_from_lookup(
            |k| match k {
                "WIRESERVE_OIDC_ISSUER" => Some("https://id".into()),
                "WIRESERVE_OIDC_CLIENT_ID" | "WIRESERVE_OIDC_CLIENT_SECRET" => Some("x".into()),
                _ => None,
            },
            Some("https://m"),
            &"ab".repeat(32),
        )
        .unwrap()
        .unwrap();
        assert_eq!(cfg.scopes, DEFAULT_SCOPES);
    }
}
