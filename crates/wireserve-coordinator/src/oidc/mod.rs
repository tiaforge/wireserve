//! Device owners through the operator's identity provider (PLAN.md M38).
//!
//! The coordinator is an OpenID Connect client of the same provider the
//! sign-in uses, so a group means the same on both paths. A person claims a
//! node with a link only an admin can make (`claim`): the code flow with
//! PKCE, a confirmation page naming the node, and the node is theirs — its
//! grants then count their groups. Their refresh token, sealed with a key
//! kept outside the database, lets the coordinator fetch the groups again
//! (`refresh`), and a provider refusing it ends the ownership.

pub mod claim;
pub mod pages;
pub mod refresh;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use openidconnect::core::{CoreClient, CoreErrorResponseType, CoreGenderClaim, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AccessToken, AdditionalClaims, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope, SubjectIdentifier, TokenResponse,
    UserInfoClaims,
};
use serde::{Deserialize, Serialize};

use crate::config::OidcConfig;

/// The most groups kept for one person.
const MAX_GROUPS: usize = 256;

/// How long the provider may take for any one request.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

type Client = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Http(#[from] axum::http::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("the identity provider could not be reached or understood: {0}")]
    Provider(String),
    #[error("the identity provider's answer did not check out: {0}")]
    Invalid(String),
    #[error("the identity provider gave no refresh token; ask for the offline_access scope (WIRESERVE_OIDC_SCOPES)")]
    NoRefreshToken,
}

/// Who signed in, as the provider says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub sub: String,
    /// Only one the provider marks verified (PLAN.md #275).
    pub email: Option<String>,
    pub name: Option<String>,
    pub groups: Vec<String>,
    pub refresh_token: String,
}

/// What a refresh brought.
#[derive(Debug)]
pub struct Refreshed {
    pub groups: Vec<String>,
    pub refresh_token: String,
    /// The verified email of the refreshed ID token (PLAN.md #275): `None`
    /// when the provider sent no ID token, which says nothing either way.
    pub email: Option<Option<String>>,
}

/// The ID token's email, if the provider marks it verified (PLAN.md #275).
/// An unverified one is whatever the person typed into their profile, and
/// it goes to backends as the owner's email header: one that keys on email
/// would take them for whoever's address they typed. authward refuses it
/// the same way.
fn verified_email<AC: openidconnect::AdditionalClaims, GC: openidconnect::GenderClaim>(
    claims: &openidconnect::IdTokenClaims<AC, GC>,
) -> Option<String> {
    match (claims.email(), claims.email_verified()) {
        (Some(email), Some(true)) => Some(email.to_string()),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// The provider refused the token (`invalid_grant`): revoked, expired,
    /// or the person is gone. The ownership ends.
    #[error("the identity provider refused the refresh token")]
    Refused,
    /// Anything else — the provider down, a network error. The owner goes
    /// stale.
    #[error("{0}")]
    Failed(String),
}

/// The sign-in half-done: what the callback must match.
pub struct Pending {
    pub csrf: CsrfToken,
    pub nonce: Nonce,
    pub pkce: PkceCodeVerifier,
}

/// Every claim the provider sent, so the configured groups claim can be read
/// from the userinfo answer whatever it is called.
#[derive(Debug, Deserialize, Serialize)]
struct AnyClaims {
    #[serde(flatten)]
    rest: serde_json::Map<String, serde_json::Value>,
}

impl AdditionalClaims for AnyClaims {}

pub struct Oidc {
    pub config: OidcConfig,
    http: reqwest::Client,
    pub(crate) flows: Mutex<HashMap<String, claim::Flow>>,
}

async fn send(http: reqwest::Client, req: openidconnect::HttpRequest) -> Result<openidconnect::HttpResponse, HttpError> {
    let (parts, body) = req.into_parts();
    let resp = http.request(parts.method, parts.uri.to_string()).headers(parts.headers).body(body).send().await?;
    let mut out = axum::http::Response::builder().status(resp.status());
    for (name, value) in resp.headers() {
        out = out.header(name, value);
    }
    Ok(out.body(resp.bytes().await?.to_vec())?)
}

impl Oidc {
    #[must_use]
    pub fn new(config: OidcConfig) -> Self {
        let http = reqwest::Client::builder()
            // Following redirects from the provider's endpoints would let a
            // redirect point this process at anything (SSRF).
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .expect("a client with a timeout and no redirects builds");
        Self { config, http, flows: Mutex::default() }
    }

    fn caller(&self) -> impl Fn(openidconnect::HttpRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<openidconnect::HttpResponse, HttpError>> + Send>> {
        let http = self.http.clone();
        move |req| Box::pin(send(http.clone(), req))
    }

    /// The client, from the provider's discovery document — fetched every
    /// time, so a provider rotating its keys is picked up.
    async fn client(&self) -> Result<Client, OidcError> {
        let issuer = IssuerUrl::new(self.config.issuer.clone()).map_err(|e| OidcError::Provider(e.to_string()))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &self.caller())
            .await
            .map_err(|e| OidcError::Provider(format!("discovery: {e}")))?;
        let redirect = RedirectUrl::new(self.config.redirect_url.clone()).map_err(|e| OidcError::Provider(e.to_string()))?;
        Ok(CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(redirect))
    }

    /// Where to send the browser to sign in, and what its return must match.
    pub async fn begin(&self) -> Result<(String, Pending), OidcError> {
        let client = self.client().await?;
        let (challenge, pkce) = PkceCodeChallenge::new_random_sha256();
        let mut req = client
            .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
            .set_pkce_challenge(challenge);
        for scope in self.config.scopes.iter().filter(|s| *s != "openid") {
            req = req.add_scope(Scope::new(scope.clone()));
        }
        let (url, csrf, nonce) = req.url();
        Ok((url.to_string(), Pending { csrf, nonce, pkce }))
    }

    /// Exchanges the code the browser came back with, checks the ID token,
    /// and reads who it is.
    pub async fn finish(&self, code: String, pending: Pending) -> Result<Identity, OidcError> {
        let client = self.client().await?;
        let caller = self.caller();
        let tokens = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| OidcError::Provider(e.to_string()))?
            .set_pkce_verifier(pending.pkce)
            .request_async(&caller)
            .await
            .map_err(|e| OidcError::Provider(format!("token: {}", describe(&e))))?;
        let id_token = tokens.id_token().ok_or_else(|| OidcError::Invalid("no ID token".into()))?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &pending.nonce)
            .map_err(|e| OidcError::Invalid(format!("ID token: {e}")))?;
        let sub = claims.subject().to_string();
        let email = verified_email(claims);
        let name = claims
            .name()
            .and_then(|n| n.get(None))
            .map(|n| n.to_string())
            .or_else(|| claims.preferred_username().map(|u| u.to_string()));
        let refresh_token = tokens.refresh_token().ok_or(OidcError::NoRefreshToken)?.secret().clone();
        let groups = self.groups(&client, &id_token.to_string(), tokens.access_token(), &sub).await?;
        Ok(Identity { sub, email, name, groups, refresh_token })
    }

    /// Fetches a person's groups again with their refresh token. `sub` is
    /// who the token belongs to; a provider answering for anyone else is
    /// not believed.
    pub async fn refresh(&self, refresh_token: &str, sub: &str) -> Result<Refreshed, RefreshError> {
        let client = self.client().await.map_err(|e| RefreshError::Failed(e.to_string()))?;
        let caller = self.caller();
        let token = RefreshToken::new(refresh_token.to_string());
        let request = client
            .exchange_refresh_token(&token)
            .map_err(|e| RefreshError::Failed(e.to_string()))?;
        let tokens = match request.request_async(&caller).await {
            Ok(t) => t,
            Err(RequestTokenError::ServerResponse(r)) if *r.error() == CoreErrorResponseType::InvalidGrant => {
                return Err(RefreshError::Refused);
            }
            Err(e) => return Err(RefreshError::Failed(describe(&e))),
        };
        let rotated = tokens.refresh_token().map_or_else(|| refresh_token.to_string(), |t| t.secret().clone());
        let (jwt, email) = match tokens.id_token() {
            Some(id_token) => {
                // A refreshed ID token carries no nonce of ours to check.
                let claims = id_token
                    .claims(&client.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
                    .map_err(|e| RefreshError::Failed(format!("ID token: {e}")))?;
                if claims.subject().as_str() != sub {
                    return Err(RefreshError::Failed("the refreshed ID token names someone else".into()));
                }
                (id_token.to_string(), Some(verified_email(claims)))
            }
            None => (String::new(), None),
        };
        let groups =
            self.groups(&client, &jwt, tokens.access_token(), sub).await.map_err(|e| RefreshError::Failed(e.to_string()))?;
        Ok(Refreshed { groups, refresh_token: rotated, email })
    }

    /// The groups claim, from the ID token already checked (`jwt`) when it
    /// carries it, else from the userinfo endpoint — which must answer for
    /// the same `sub`.
    async fn groups(&self, client: &Client, jwt: &str, access: &AccessToken, sub: &str) -> Result<Vec<String>, OidcError> {
        if let Some(groups) = jwt_claim(jwt, &self.config.groups_claim) {
            return Ok(groups_of(&groups));
        }
        let Ok(request) = client.user_info(access.clone(), Some(SubjectIdentifier::new(sub.to_string()))) else {
            // No userinfo endpoint, and nothing in the ID token: no groups.
            return Ok(Vec::new());
        };
        let info: UserInfoClaims<AnyClaims, CoreGenderClaim> =
            request.request_async(&self.caller()).await.map_err(|e| OidcError::Provider(format!("userinfo: {e}")))?;
        Ok(info.additional_claims().rest.get(&self.config.groups_claim).map(groups_of).unwrap_or_default())
    }

    /// Seals a refresh token for `node_id`: XChaCha20-Poly1305 under the
    /// token key, with the node as associated data, so a sealed token moved
    /// to another node's row does not open.
    #[must_use]
    pub fn seal(&self, node_id: i64, token: &str) -> String {
        use base64::Engine as _;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let cipher = chacha20poly1305::XChaCha20Poly1305::new((&self.config.token_key).into());
        let nonce: [u8; 24] = rand::random();
        let sealed = cipher
            .encrypt((&nonce).into(), Payload { msg: token.as_bytes(), aad: &node_id.to_be_bytes() })
            .expect("sealing a short token does not fail");
        let mut out = nonce.to_vec();
        out.extend(sealed);
        base64::engine::general_purpose::STANDARD.encode(out)
    }

    /// Opens what [`Self::seal`] sealed for `node_id`.
    #[must_use]
    pub fn open(&self, node_id: i64, sealed: &str) -> Option<String> {
        use base64::Engine as _;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        let raw = base64::engine::general_purpose::STANDARD.decode(sealed).ok()?;
        if raw.len() < 24 {
            return None;
        }
        let (nonce, ct) = raw.split_at(24);
        let cipher = chacha20poly1305::XChaCha20Poly1305::new((&self.config.token_key).into());
        let plain = cipher.decrypt(nonce.into(), Payload { msg: ct, aad: &node_id.to_be_bytes() }).ok()?;
        String::from_utf8(plain).ok()
    }
}

/// An error's chain, for the log.
fn describe(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

/// A claim of a JWT whose signature has already been checked — read here
/// only because openidconnect keeps claims it does not know to itself.
fn jwt_claim(jwt: &str, claim: &str) -> Option<serde_json::Value> {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let mut all: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&raw).ok()?;
    all.remove(claim)
}

/// A groups claim — a list, or one name — kept to names a grant could have
/// named.
fn groups_of(value: &serde_json::Value) -> Vec<String> {
    let names: Vec<&str> = match value {
        serde_json::Value::Array(items) => items.iter().filter_map(serde_json::Value::as_str).collect(),
        serde_json::Value::String(s) => vec![s.as_str()],
        _ => Vec::new(),
    };
    let mut out: Vec<String> =
        names.into_iter().filter(|g| wireserve_types::is_valid_oidc_group(g)).map(str::to_string).collect();
    out.sort();
    out.dedup();
    out.truncate(MAX_GROUPS);
    out
}

#[cfg(test)]
pub(crate) fn test_config() -> OidcConfig {
    OidcConfig {
        issuer: "https://id.example.com".into(),
        client_id: "wireserve".into(),
        client_secret: "s3cret".into(),
        scopes: vec!["openid".into(), "groups".into(), "offline_access".into()],
        groups_claim: "groups".into(),
        refresh_interval: Duration::from_secs(900),
        token_key: [7; 32],
        redirect_url: "https://mesh.example.com/claim/callback".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_token_opens_for_its_own_node_only() {
        let oidc = Oidc::new(test_config());
        let sealed = oidc.seal(3, "refresh-me");
        assert!(!sealed.contains("refresh-me"));
        assert_eq!(oidc.open(3, &sealed).as_deref(), Some("refresh-me"));
        assert_eq!(oidc.open(4, &sealed), None, "moved to another node's row");
        assert_ne!(oidc.seal(3, "refresh-me"), sealed, "a fresh nonce each time");
        let mut other = test_config();
        other.token_key = [8; 32];
        assert_eq!(Oidc::new(other).open(3, &sealed), None, "another key");
        assert_eq!(oidc.open(3, "not base64!"), None);
    }

    #[test]
    fn groups_come_as_a_list_or_one_name_and_only_usable_names_stay() {
        use base64::Engine as _;
        let payload = serde_json::json!({"sub": "a", "groups": ["family", "admins", "a,b", "family"], "role": "x"});
        let jwt = format!(
            "h.{}.s",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let groups = groups_of(&jwt_claim(&jwt, "groups").unwrap());
        assert_eq!(groups, ["admins", "family"]);
        assert_eq!(groups_of(&jwt_claim(&jwt, "role").unwrap()), ["x"]);
        assert!(jwt_claim(&jwt, "missing").is_none());
        assert!(jwt_claim("not a jwt", "groups").is_none());
    }
}
