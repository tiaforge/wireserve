//! `setup domain` (PLAN.md M47, from M31/M32's install questions): service
//! names under a domain the operator owns, and the DNS provider the
//! coordinator writes their records through.
//!
//! A domain *replaces* `.wg` (names-and-https.md), so turning one on
//! renames every service. Anything configured with its old name breaks,
//! so the services are listed with their new names before anything changes.

use super::{confirm, save, Ctx, SetupError};
use crate::install::envfile::Change;
use crate::install::questions::{
    ask_secret, ask_until, ask_yes_no, check_dns_provider as check_provider_name, check_domain, explain, AskError,
};

#[derive(clap::Args, Debug, Default)]
pub struct DomainArgs {
    /// Name services <name>.<DOMAIN> instead of <name>.wg.
    #[arg(long, value_name = "DOMAIN", conflicts_with = "off")]
    pub domain: Option<String>,
    /// Go back to <name>.wg (also turns off the sign-in, which needs the
    /// DNS records).
    #[arg(long)]
    pub off: bool,
    /// Publish services' DNS records through this provider: rfc2136, cloudflare, desec, hetzner, porkbun
    // Its credentials are read from the WIRESERVE_DNS_* environment
    // variables, or asked for at a terminal.
    #[arg(long, value_name = "PROVIDER", conflicts_with_all = ["no_dns", "off"])]
    pub dns_provider: Option<String>,
    /// Leave DNS records to you: the names then work on wireserve machines only.
    #[arg(long, conflicts_with = "off")]
    pub no_dns: bool,
    /// Don't write and remove a test record through the DNS provider first.
    #[arg(long)]
    pub skip_dns_check: bool,
    /// Don't ask before saving.
    #[arg(long, short)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Naming {
    pub domain: String,
    /// The provider the coordinator publishes the names through (PLAN.md
    /// M32), or `None` to leave DNS to the operator.
    pub dns: Option<DnsAnswer>,
}

/// A DNS provider and the settings it needs, as `WIRESERVE_DNS_*` keys.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub provider: String,
    pub fields: Vec<(&'static str, String)>,
    /// The zone the records go into, when it is a parent of the service
    /// domain (`home.example.com` in the zone `example.com`); `None` when
    /// the domain is a zone of its own. Hetzner, Porkbun and RFC 2136 need
    /// it exactly.
    pub zone: Option<String>,
}

// Credentials never reach a log or a panic message.
impl std::fmt::Debug for DnsAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsAnswer").field("provider", &self.provider).field("zone", &self.zone).finish_non_exhaustive()
    }
}

impl DnsAnswer {
    /// Checks the answer the way the coordinator will at startup, so a
    /// setting it would refuse is caught before anything is saved.
    pub fn check(&self, domain: &str) -> Result<crate::dns::DnsConfig, String> {
        let lookup = |key: &str| {
            if key == "WIRESERVE_DNS_PROVIDER" {
                return Some(self.provider.clone());
            }
            if key == "WIRESERVE_DNS_ZONE" {
                return self.zone.clone();
            }
            self.fields.iter().find(|(k, _)| *k == key).map(|(_, v)| v.clone())
        };
        match crate::dns::config::from_lookup(lookup, Some(domain)) {
            Ok(Some(cfg)) => Ok(cfg),
            Ok(None) => Err("no DNS provider given".into()),
            Err(crate::config::ConfigError::Invalid(key, why)) => Err(format!("{key} {why}")),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// The naming as the env file has it now.
#[must_use]
pub fn current(get: impl Fn(&str) -> Option<String>) -> Option<Naming> {
    let dns = get("WIRESERVE_DNS_PROVIDER")
        .map(|p| p.trim().to_ascii_lowercase())
        .filter(|p| crate::dns::config::PROVIDERS.contains(&p.as_str()))
        .map(|provider| DnsAnswer {
            fields: crate::dns::config::fields(&provider)
                .iter()
                .filter_map(|f| Some((f.key, get(f.key)?)))
                .collect(),
            zone: get("WIRESERVE_DNS_ZONE"),
            provider,
        });
    get("WIRESERVE_SERVICE_DOMAIN").map(|domain| Naming { domain, dns })
}

/// The env-file edits for `naming`. Without DNS records there are no
/// terminators, so a sign-in set up before (`sign_in_set`) is turned off
/// too — the coordinator would refuse to start with it.
#[must_use]
pub fn env_changes(naming: Option<&Naming>, sign_in_set: bool) -> Vec<(&'static str, Change)> {
    let mut changes = vec![(
        "WIRESERVE_SERVICE_DOMAIN",
        naming.map_or(Change::Clear, |n| Change::Set(n.domain.clone())),
    )];
    // Turning DNS off, or switching provider, clears every credential the
    // new setting does not use: a token nothing reads any more is still a
    // live token sitting in a file.
    let dns = naming.and_then(|n| n.dns.as_ref());
    changes.push(("WIRESERVE_DNS_PROVIDER", dns.map_or(Change::Clear, |d| Change::Set(d.provider.clone()))));
    for key in crate::dns::config::CREDENTIAL_KEYS {
        let value = dns.and_then(|d| d.fields.iter().find(|(k, _)| *k == key));
        changes.push((key, value.map_or(Change::Clear, |(_, v)| Change::Set(v.clone()))));
    }
    let zone = dns.and_then(|d| d.zone.clone());
    changes.push(("WIRESERVE_DNS_ZONE", zone.map_or(Change::Clear, Change::Set)));
    if dns.is_none() && sign_in_set {
        changes.push(("WIRESERVE_AUTH_SERVICE", Change::Clear));
        changes.push(("WIRESERVE_AUTH_NODE", Change::Clear));
    }
    changes
}

/// What the flags said. `Some(None)` is `--off` / `--no-dns`.
#[derive(Debug, Clone, Default)]
pub struct Given {
    pub domain: Option<Option<String>>,
    pub dns_provider: Option<Option<String>>,
}

impl From<&DomainArgs> for Given {
    fn from(a: &DomainArgs) -> Self {
        Self {
            domain: if a.off { Some(None) } else { a.domain.clone().map(Some) },
            dns_provider: if a.no_dns { Some(None) } else { a.dns_provider.clone().map(Some) },
        }
    }
}

/// Settles the naming: a flag first, then (at a terminal) a question whose
/// default is the current setting, then the current setting.
pub struct Asker<'a> {
    pub interactive: bool,
    /// Reads a `WIRESERVE_DNS_*` credential from the environment: how a
    /// run that is not at a terminal is given one without putting a secret
    /// on the command line.
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub given: Given,
    pub current: Option<Naming>,
    /// The services there are now, which a new domain renames.
    pub services: Vec<String>,
}

impl Asker<'_> {
    pub fn ask(&self) -> Result<Option<Naming>, AskError> {
        let Some(domain) = self.domain()? else {
            return Ok(None);
        };
        let dns = self.dns(&domain)?;
        Ok(Some(Naming { domain, dns }))
    }

    fn domain(&self) -> Result<Option<String>, AskError> {
        let current = self.current.as_ref().map(|n| n.domain.clone());
        match &self.given.domain {
            Some(None) => return Ok(None),
            Some(Some(raw)) => {
                return check_domain(raw).map(Some).map_err(|e| AskError::Invalid(format!("--domain: {e}")));
            }
            None if !self.interactive => return Ok(current),
            None => {}
        }
        explain(&[
            "Right now your services get names like plex.wg, which only work on",
            "computers running wireserve. If you own a domain, they can have real",
            "names instead, like plex.home.example.com: those work on phones too,",
            "and every service on port 443 gets HTTPS with a valid certificate.",
        ]);
        if !ask_yes_no("Use your own domain for service names?", current.is_some()) {
            return Ok(None);
        }
        explain(&[
            "Best is a part of your domain you use for nothing else, like",
            "home.example.com for the domain example.com.",
        ]);
        loop {
            let domain = ask_until("Domain for your services (e.g. home.example.com)", current.as_deref(), check_domain)?;
            if current.as_deref() == Some(domain.as_str()) || self.services.is_empty() {
                return Ok(Some(domain));
            }
            explain(&renames(&self.services, current.as_deref(), &domain));
            if ask_yes_no("Rename them?", true) {
                return Ok(Some(domain));
            }
        }
    }

    /// The DNS provider for `domain` (PLAN.md M32): `--dns-provider` /
    /// `--no-dns` first, then the question, then the current setting. A
    /// credential comes from its `WIRESERVE_DNS_*` environment variable,
    /// then the question (hidden, for a secret), then the current setting.
    fn dns(&self, domain: &str) -> Result<Option<DnsAnswer>, AskError> {
        let current = self.current.as_ref().and_then(|n| n.dns.clone());
        let provider = match &self.given.dns_provider {
            Some(None) => return Ok(None),
            Some(Some(p)) => {
                Some(check_provider_name(p).map_err(|e| AskError::Invalid(format!("--dns-provider: {e}")))?)
            }
            None if !self.interactive => match &current {
                Some(c) => Some(c.provider.clone()),
                None => return Ok(None),
            },
            None => None,
        };
        let provider = match provider {
            Some(p) => p,
            None => {
                explain(&[
                    "For these names to work everywhere, wireserve creates a DNS record",
                    &format!("for each service (like plex.{domain}) at the company that runs your"),
                    "domain's DNS — usually where you bought the domain, unless you moved",
                    "its DNS elsewhere, e.g. to Cloudflare. It needs an API token from",
                    "that company. It only creates and removes records named after your",
                    &format!("services under {domain}; everything else in your domain is left alone."),
                    "Without it, the names only work on computers running wireserve, and",
                    "there is no HTTPS.",
                ]);
                if !ask_yes_no("Let wireserve manage these DNS records?", current.is_some()) {
                    return Ok(None);
                }
                eprintln!();
                ask_until(
                    "Who runs your domain's DNS? (cloudflare, desec, hetzner, porkbun, or rfc2136 for your own DNS server)",
                    current.as_ref().map(|c| c.provider.as_str()),
                    check_provider_name,
                )?
            }
        };
        let asking = self.interactive
            && crate::dns::config::fields(&provider).iter().any(|f| (self.env)(f.key).is_none_or(|v| v.trim().is_empty()));
        if asking {
            explain(crate::dns::config::help(&provider));
        }
        loop {
            let mut fields = Vec::new();
            for f in crate::dns::config::fields(&provider) {
                let kept = current
                    .as_ref()
                    .filter(|c| c.provider == provider)
                    .and_then(|c| c.fields.iter().find(|(k, _)| *k == f.key))
                    .map(|(_, v)| v.clone());
                let value = if let Some(v) = (self.env)(f.key).filter(|v| !v.trim().is_empty()) {
                    Some(v.trim().to_string())
                } else if !self.interactive {
                    kept.or_else(|| f.default.map(str::to_string))
                } else if f.secret {
                    ask_secret(f.label, kept)?
                } else {
                    Some(ask_until(f.label, kept.as_deref().or(f.default), |raw| Ok::<_, String>(raw.trim().to_string()))?)
                };
                match value {
                    Some(v) => fields.push((f.key, v)),
                    None => {
                        return Err(AskError::Missing { question: "a DNS provider credential", flag: f.key });
                    }
                }
            }
            let zone = self.dns_zone(current.as_ref().and_then(|c| c.zone.clone()))?
                .filter(|z| !z.eq_ignore_ascii_case(domain));
            let answer = DnsAnswer { provider: provider.clone(), fields, zone };
            match answer.check(domain) {
                Ok(_) => return Ok(Some(answer)),
                Err(e) if self.interactive => eprintln!("  {e}; let's try that again"),
                Err(e) => return Err(AskError::Invalid(e)),
            }
        }
    }

    /// The zone the records go into, when already known:
    /// `WIRESERVE_DNS_ZONE`, then the current setting. Never asked —
    /// `check_dns_provider` finds it by trying the domain and its parents;
    /// few people know what their provider calls a zone.
    fn dns_zone(&self, current: Option<String>) -> Result<Option<String>, AskError> {
        match (self.env)("WIRESERVE_DNS_ZONE").filter(|z| !z.trim().is_empty()) {
            Some(z) => check_domain(&z).map(Some).map_err(|e| AskError::Invalid(format!("WIRESERVE_DNS_ZONE: {e}"))),
            None => Ok(current),
        }
    }
}

/// The lines saying what a new domain does to the services there are.
#[must_use]
pub fn renames(services: &[String], from: Option<&str>, to: &str) -> Vec<String> {
    let from = from.unwrap_or("wg");
    let mut lines = vec!["Your services get new names; the old ones stop working:".to_string()];
    lines.push(String::new());
    let shown = 8;
    for s in services.iter().take(shown) {
        lines.push(format!("  {s}.{from}  ->  {s}.{to}"));
    }
    if services.len() > shown {
        lines.push(format!("  … and {} more", services.len() - shown));
    }
    lines.push(String::new());
    lines.push("Anything set up with an old name needs the new one: bookmarks, and apps".into());
    lines.push("that are told their own address (Gitea's ROOT_URL, a sign-in redirect URL, …).".into());
    lines
}

pub fn run(ctx: &Ctx, args: &DomainArgs) -> Result<(), SetupError> {
    let current = current(|k| ctx.get(k));
    let services = if ctx.interactive {
        let mut names: Vec<String> =
            ctx.admin().and_then(|a| a.services()).unwrap_or_default().into_iter().map(|s| s.name).collect();
        names.sort();
        names.dedup();
        names
    } else {
        Vec::new()
    };
    let asker = Asker {
        interactive: ctx.interactive,
        env: &|key| std::env::var(key).ok(),
        given: Given::from(args),
        current: current.clone(),
        services,
    };
    let mut naming = asker.ask()?;
    if !args.skip_dns_check {
        if let Some(n) = &mut naming {
            if let Some(dns) = &mut n.dns {
                if current.as_ref() != Some(&Naming { domain: n.domain.clone(), dns: Some(dns.clone()) }) {
                    check_dns_provider(dns, &n.domain)?;
                }
            }
        }
    }
    let sign_in_set = ctx.get("WIRESERVE_AUTH_SERVICE").is_some();
    let mut summary = vec![match &naming {
        Some(n) => format!("Service names:  <name>.{}", n.domain),
        None => "Service names:  <name>.wg".to_string(),
    }];
    match naming.as_ref().map(|n| &n.dns) {
        Some(Some(d)) => summary.push(format!("DNS records:    written through {}; HTTPS on each node", d.provider)),
        Some(None) => summary.push("DNS records:    none (names work on wireserve machines only)".into()),
        None => {}
    }
    let dns_off = naming.as_ref().is_none_or(|n| n.dns.is_none());
    if dns_off && sign_in_set {
        summary.push("Sign-in:        turned off (it needs the DNS records)".into());
    }
    confirm(ctx, args.yes, &summary)?;
    if !save(ctx, &env_changes(naming.as_ref(), sign_in_set))? {
        return Ok(());
    }
    println!();
    match &naming {
        Some(Naming { domain, dns: Some(_) }) => {
            println!("Every approved service is now <name>.{domain}, and one published on 443 gets HTTPS");
            println!("from its own node, e.g.:  wireserve plex 443:32400   ->  https://plex.{domain}");
            println!("Nodes pick up the new names within a minute.");
        }
        Some(Naming { domain, dns: None }) => {
            println!("Services are now <name>.{domain}, on machines running wireserve. Run this again and");
            println!("let wireserve manage DNS records for names that work on phones too, and HTTPS.");
        }
        None => println!("Services are named <name>.wg again."),
    }
    if dns_off && sign_in_set {
        println!("The sign-in is off; `sudo wireserve-coordinator setup sign-in` sets it up again.");
    }
    Ok(())
}

/// Writes and removes one throwaway TXT record through the provider, so a
/// wrong token is found now, and not later as names that never appear.
///
/// It also finds the zone the records go into, which is not asked: few
/// people know what their provider calls a zone. It tries the zone already
/// set, then the domain itself, then each domain it sits under
/// (`home.example.com`, `example.com`), and keeps the first one the
/// provider takes. Cloudflare and deSEC find the zone themselves, so the
/// domain itself works there at once.
fn check_dns_provider(dns: &mut DnsAnswer, domain: &str) -> Result<(), SetupError> {
    let failed = |what: &str, e: &dyn std::fmt::Display| SetupError::Failed(format!("{what}: {e}"));
    let name = format!("_wireserve-check.{domain}");
    eprintln!("Checking that wireserve can create DNS records for {domain} …");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| failed("starting the DNS check", &e))?;
    let mut refused = Vec::new();
    for zone in zone_candidates(dns.zone.as_deref(), domain) {
        let attempt = DnsAnswer { zone: Some(zone.clone()), ..dns.clone() };
        let cfg = attempt.check(domain).map_err(SetupError::Failed)?;
        let provider = crate::dns::provider::Provider::connect(&cfg).map_err(SetupError::Failed)?;
        let value = crate::tokengen::generate("wireserve-check-");
        let written = runtime.block_on(async {
            use crate::dns::provider::DnsWriter as _;
            provider.add_txt(&name, &value).await?;
            if let Err(e) = provider.remove_txt(&name, &value).await {
                eprintln!("note: the test record {name} could not be removed ({e}); delete it by hand");
            }
            Ok::<_, String>(())
        });
        match written {
            Ok(()) => {
                eprintln!("  OK: the records go into {zone}.");
                dns.zone = (!zone.eq_ignore_ascii_case(domain)).then_some(zone);
                return Ok(());
            }
            Err(e) => refused.push(format!("  as part of {zone}: {e}")),
        }
    }
    Err(SetupError::Failed(format!(
        "{} did not accept a test record for {domain}:\n{}\nNothing was changed. Check that the token is right and may \
         change DNS records for {domain}, then run this again (--skip-dns-check skips this test).",
        dns.provider,
        refused.join("\n")
    )))
}

/// The zones to try for `domain`, most likely first: one already set, the
/// domain, then each parent down to two labels (never a bare `com`).
fn zone_candidates(set: Option<&str>, domain: &str) -> Vec<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let mut out: Vec<String> = set.map(|z| z.trim_end_matches('.').to_ascii_lowercase()).into_iter().collect();
    let mut rest = domain.as_str();
    loop {
        if !out.iter().any(|z| z == rest) {
            out.push(rest.to_string());
        }
        match rest.split_once('.') {
            Some((_, parent)) if parent.contains('.') => rest = parent,
            _ => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::envfile;

    fn change<'a>(changes: &'a [(&str, Change)], key: &str) -> &'a Change {
        &changes.iter().find(|(k, _)| *k == key).unwrap().1
    }

    fn asker<'a>(given: Given, current: Option<Naming>, env: &'a dyn Fn(&str) -> Option<String>) -> Asker<'a> {
        Asker { interactive: false, env, given, current, services: Vec::new() }
    }

    fn from_file(text: &str) -> Option<Naming> {
        current(|k| envfile::get(text, k).filter(|v| !v.is_empty()))
    }

    fn dns_given() -> Given {
        Given { domain: Some(Some("int.test".into())), dns_provider: Some(Some("Cloudflare".into())) }
    }

    #[test]
    fn the_zone_is_looked_for_from_the_domain_down_to_two_labels() {
        assert_eq!(zone_candidates(None, "Home.Example.com."), ["home.example.com", "example.com"]);
        assert_eq!(zone_candidates(None, "a.b.example.co.uk"), ["a.b.example.co.uk", "b.example.co.uk", "example.co.uk", "co.uk"]);
        assert_eq!(zone_candidates(Some("example.com"), "home.example.com"), ["example.com", "home.example.com"]);
        assert_eq!(zone_candidates(None, "example.com"), ["example.com"]);
    }

    #[test]
    fn domain_flags_and_the_current_setting() {
        let none = |_: &str| None;
        let given = Given { domain: Some(Some("Int.Test".into())), ..Given::default() };
        assert_eq!(asker(given, None, &none).ask().unwrap(), Some(Naming { domain: "int.test".into(), dns: None }));
        let current = Some(Naming { domain: "int.test".into(), dns: None });
        assert_eq!(asker(Given::default(), current.clone(), &none).ask().unwrap(), current, "kept without a terminal");
        assert_eq!(asker(Given { domain: Some(None), ..Given::default() }, current, &none).ask().unwrap(), None);
        let c = env_changes(None, false);
        assert_eq!(change(&c, "WIRESERVE_SERVICE_DOMAIN"), &Change::Clear);
        assert!(!c.iter().any(|(k, _)| *k == "WIRESERVE_AUTH_SERVICE"), "nothing to turn off");
    }

    #[test]
    fn a_provider_flag_takes_its_credential_from_the_environment() {
        let env = |k: &str| (k == "WIRESERVE_DNS_API_TOKEN").then(|| "cf-token".to_string());
        let n = asker(dns_given(), None, &env).ask().unwrap().unwrap();
        assert_eq!(n.dns.as_ref().unwrap().provider, "cloudflare");
        let c = env_changes(Some(&n), false);
        assert_eq!(change(&c, "WIRESERVE_DNS_PROVIDER"), &Change::Set("cloudflare".into()));
        assert_eq!(change(&c, "WIRESERVE_DNS_API_TOKEN"), &Change::Set("cf-token".into()));
        assert_eq!(change(&c, "WIRESERVE_DNS_TSIG_SECRET"), &Change::Clear, "other providers' keys are cleared");
        assert_eq!(from_file(&envfile::apply("", &c)), Some(n), "reads back as the same answer");
    }

    #[test]
    fn a_provider_flag_without_its_credential_is_refused() {
        let err = asker(dns_given(), None, &|_| None).ask().unwrap_err();
        assert!(matches!(err, AskError::Missing { flag: "WIRESERVE_DNS_API_TOKEN", .. }), "{err}");
    }

    #[test]
    fn a_bad_credential_is_refused_before_anything_is_saved() {
        let given = Given { dns_provider: Some(Some("rfc2136".into())), ..dns_given() };
        let env = |k: &str| match k {
            "WIRESERVE_DNS_SERVER" => Some("10.0.0.53:53".to_string()),
            "WIRESERVE_DNS_TSIG_KEY_NAME" => Some("k".to_string()),
            "WIRESERVE_DNS_TSIG_SECRET" => Some("not base64!".to_string()),
            _ => None,
        };
        let err = asker(given, None, &env).ask().unwrap_err();
        assert!(err.to_string().contains("WIRESERVE_DNS_TSIG_SECRET"), "{err}");
    }

    #[test]
    fn a_rerun_keeps_the_provider_and_no_dns_clears_every_credential() {
        let file = "WIRESERVE_SERVICE_DOMAIN=int.test\nWIRESERVE_DNS_PROVIDER=hetzner\nWIRESERVE_DNS_API_TOKEN=hz-token\n";
        let none = |_: &str| None;
        let kept = asker(Given::default(), from_file(file), &none).ask().unwrap().unwrap();
        let dns = kept.dns.unwrap();
        assert_eq!((dns.provider.as_str(), dns.fields.clone()), ("hetzner", vec![("WIRESERVE_DNS_API_TOKEN", "hz-token".into())]));

        let off = asker(Given { dns_provider: Some(None), ..Given::default() }, from_file(file), &none).ask().unwrap();
        assert_eq!(off.as_ref().unwrap().dns, None);
        let c = env_changes(off.as_ref(), false);
        assert_eq!(change(&c, "WIRESERVE_DNS_PROVIDER"), &Change::Clear);
        assert_eq!(change(&c, "WIRESERVE_DNS_API_TOKEN"), &Change::Clear);
    }

    #[test]
    fn without_dns_records_the_sign_in_is_turned_off_too() {
        let n = Naming { domain: "int.test".into(), dns: None };
        for c in [env_changes(Some(&n), true), env_changes(None, true)] {
            assert_eq!(change(&c, "WIRESERVE_AUTH_SERVICE"), &Change::Clear);
            assert_eq!(change(&c, "WIRESERVE_AUTH_NODE"), &Change::Clear);
        }
        let with_dns = Naming {
            dns: Some(DnsAnswer { provider: "cloudflare".into(), fields: vec![("WIRESERVE_DNS_API_TOKEN", "t".into())], zone: None }),
            ..n
        };
        assert!(!env_changes(Some(&with_dns), true).iter().any(|(k, _)| *k == "WIRESERVE_AUTH_SERVICE"));
    }

    #[test]
    fn a_parent_zone_is_checked_kept_and_cleared() {
        let given = Given { domain: Some(Some("home.example.com".into())), dns_provider: Some(Some("hetzner".into())) };
        let env = |k: &str| match k {
            "WIRESERVE_DNS_API_TOKEN" => Some("hz-token".to_string()),
            "WIRESERVE_DNS_ZONE" => Some("Example.com".to_string()),
            _ => None,
        };
        let n = asker(given.clone(), None, &env).ask().unwrap();
        assert_eq!(n.as_ref().unwrap().dns.as_ref().unwrap().check("home.example.com").unwrap().zone, "example.com");
        let text = envfile::apply("", &env_changes(n.as_ref(), false));
        assert!(text.contains("WIRESERVE_DNS_ZONE=example.com"), "{text}");

        // A rerun keeps it, and checks with it.
        let kept = asker(Given::default(), from_file(&text), &|_| None).ask().unwrap().unwrap();
        assert_eq!(kept.dns.unwrap().check("home.example.com").unwrap().zone, "example.com");

        // A zone that does not contain the domain is refused up front.
        let wrong = |k: &str| match k {
            "WIRESERVE_DNS_API_TOKEN" => Some("hz-token".to_string()),
            "WIRESERVE_DNS_ZONE" => Some("other.com".to_string()),
            _ => None,
        };
        let err = asker(given, None, &wrong).ask().unwrap_err();
        assert!(err.to_string().contains("WIRESERVE_DNS_ZONE"), "{err}");

        // The domain as its own zone is no setting; turning DNS off clears it.
        let own = |k: &str| match k {
            "WIRESERVE_DNS_API_TOKEN" => Some("t".to_string()),
            "WIRESERVE_DNS_ZONE" => Some("int.test".to_string()),
            _ => None,
        };
        let n = asker(dns_given(), None, &own).ask().unwrap();
        assert_eq!(change(&env_changes(n.as_ref(), false), "WIRESERVE_DNS_ZONE"), &Change::Clear);
        let off = asker(Given { dns_provider: Some(None), ..Given::default() }, from_file(&text), &|_| None).ask().unwrap();
        assert_eq!(change(&env_changes(off.as_ref(), false), "WIRESERVE_DNS_ZONE"), &Change::Clear);
    }

    #[test]
    fn the_dns_answer_never_prints_its_credentials() {
        let d = DnsAnswer {
            provider: "cloudflare".into(),
            fields: vec![("WIRESERVE_DNS_API_TOKEN", "cf-live".into())],
            zone: None,
        };
        assert!(!format!("{d:?}").contains("cf-live"));
    }

    #[test]
    fn a_new_domain_lists_the_renames() {
        let services: Vec<String> = (0..10).map(|i| format!("s{i}")).collect();
        let lines = renames(&services, None, "home.example.com");
        assert!(lines.iter().any(|l| l.contains("s0.wg  ->  s0.home.example.com")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("2 more")), "{lines:?}");
        let lines = renames(&services[..1], Some("old.example.com"), "new.example.com");
        assert!(lines.iter().any(|l| l.contains("s0.old.example.com  ->  s0.new.example.com")), "{lines:?}");
    }
}
