//! HTTP client for the coordinator's `/admin/*` and `/register` endpoints.
//!
//! Deliberately separate from `wireserve-agent`'s own HTTP client, which
//! talks to `/poll` with a per-node bearer token. Spec is explicit that the
//! admin trust surface and the per-node surface must never blur together in
//! code (the same reasoning that gave the coordinator its two separate auth
//! extractors) — so this crate does not import or share an "authenticated
//! coordinator client" helper with `wireserve-agent`, even though the two
//! look superficially similar. A little duplicated HTTP boilerplate between
//! the two crates is the intended shape here, not an oversight.

use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use wireserve_types::{
    AdminPeersResponse, CreateNodeRequest, CreateNodeResponse, ErrorBody, NodeKind,
    RegisterRequest, RegisterResponse, RejoinResponse,
};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error talking to coordinator: {0}")]
    Http(#[from] reqwest::Error),
    #[error("coordinator returned {status}: {message}")]
    Api {
        status: StatusCode,
        message: String,
    },
}

pub struct AdminClient {
    http: Client,
    base_url: String,
    admin_token: String,
}

impl AdminClient {
    #[must_use]
    pub fn new(base_url: impl Into<String>, admin_token: impl Into<String>) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.into(),
            admin_token: admin_token.into(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), path)
    }

    fn check_status(resp: Response) -> Result<Response, ClientError> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status();
            let message = resp
                .json::<ErrorBody>()
                .map(|b| b.error)
                .unwrap_or_else(|_| status.to_string());
            Err(ClientError::Api { status, message })
        }
    }

    /// `POST /admin/nodes` (spec §4.1).
    pub fn create_node(
        &self,
        name: &str,
        kind: NodeKind,
    ) -> Result<CreateNodeResponse, ClientError> {
        let resp = self
            .http
            .post(self.url("/admin/nodes"))
            .bearer_auth(&self.admin_token)
            .json(&CreateNodeRequest {
                name: name.to_string(),
                kind,
            })
            .send()?;
        Ok(Self::check_status(resp)?.json()?)
    }

    /// `POST /admin/nodes/{name}/revoke` (spec §4.4).
    pub fn revoke(&self, name: &str) -> Result<(), ClientError> {
        let resp = self
            .http
            .post(self.url(&format!("/admin/nodes/{name}/revoke")))
            .bearer_auth(&self.admin_token)
            .send()?;
        Self::check_status(resp)?;
        Ok(())
    }

    /// `POST /admin/nodes/{name}/rejoin` (spec §4.5).
    pub fn rejoin(&self, name: &str) -> Result<RejoinResponse, ClientError> {
        let resp = self
            .http
            .post(self.url(&format!("/admin/nodes/{name}/rejoin")))
            .bearer_auth(&self.admin_token)
            .send()?;
        Ok(Self::check_status(resp)?.json()?)
    }

    /// `GET /admin/peers` (spec §4.5.1).
    pub fn list_peers(&self) -> Result<AdminPeersResponse, ClientError> {
        let resp = self
            .http
            .get(self.url("/admin/peers"))
            .bearer_auth(&self.admin_token)
            .send()?;
        Ok(Self::check_status(resp)?.json()?)
    }

    /// `POST /register` (spec §4.2). Deliberately unauthenticated — no
    /// admin-token header — since the join token in the body is itself the
    /// credential for this endpoint.
    pub fn register(&self, req: &RegisterRequest) -> Result<RegisterResponse, ClientError> {
        let resp = self.http.post(self.url("/register")).json(req).send()?;
        Ok(Self::check_status(resp)?.json()?)
    }
}
