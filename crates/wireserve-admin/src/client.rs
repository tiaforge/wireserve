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
    AdminPeersResponse, AdminServicesResponse, CreateNodeRequest, CreateNodeResponse,
    DenyServiceRequest, ErrorBody, NodeKind, RegisterRequest, RegisterResponse, RejoinRequest, SetGatewayRequest,
    RejoinResponse, SetViaGatewayRequest, SetViaGatewayResponse,
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

/// Builds the blocking client with a bounded timeout, so a hung coordinator
/// fails the command instead of leaving the operator's terminal stuck.
/// Panics only where `Client::new()` would have (reqwest cannot construct
/// a client without a system trust store — see the coordinator Dockerfile
/// note on `ca-certificates`).
fn http_client() -> Client {
    Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client (is a system CA trust store installed?)")
}

impl AdminClient {
    #[must_use]
    pub fn new(base_url: impl Into<String>, admin_token: impl Into<String>) -> Self {
        Self {
            http: http_client(),
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
        ttl_secs: Option<u64>,
    ) -> Result<CreateNodeResponse, ClientError> {
        let resp = self
            .http
            .post(self.url("/admin/nodes"))
            .bearer_auth(&self.admin_token)
            .json(&CreateNodeRequest {
                name: name.to_string(),
                kind,
                ttl_secs,
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

    /// `DELETE /admin/nodes/{name}` (security review F8). The coordinator
    /// refuses with 409 while the node is still active.
    pub fn delete_node(&self, name: &str) -> Result<(), ClientError> {
        let resp = self
            .http
            .delete(self.url(&format!("/admin/nodes/{name}")))
            .bearer_auth(&self.admin_token)
            .send()?;
        Self::check_status(resp)?;
        Ok(())
    }

    /// `DELETE /admin/nodes/{name}/endpoint` (unqualified) or
    /// `.../endpoint/{family}` (`family` = `Some("v4")`/`Some("v6")`).
    /// Unqualified clears the explicit override plus both actively-probed
    /// candidates; a family clears only that one probed candidate,
    /// leaving the explicit override and the other family untouched. The
    /// node re-reports whatever it clears if it still has that value
    /// configured/reachable on its next poll.
    pub fn clear_endpoint(&self, name: &str, family: Option<&str>) -> Result<(), ClientError> {
        let path = match family {
            Some(family) => format!("/admin/nodes/{name}/endpoint/{family}"),
            None => format!("/admin/nodes/{name}/endpoint"),
        };
        let resp = self
            .http
            .delete(self.url(&path))
            .bearer_auth(&self.admin_token)
            .send()?;
        Self::check_status(resp)?;
        Ok(())
    }

    /// `POST /admin/nodes/{name}/rejoin` (spec §4.5).
    ///
    /// `expect_kind` is checked by the coordinator *before* it mutates
    /// anything (PLAN.md M24) — pass it whenever the caller knows what it is
    /// aiming at, so a rejoin can never null a live agent node's pubkey on
    /// the way to discovering it was the wrong kind.
    pub fn rejoin(
        &self,
        name: &str,
        ttl_secs: Option<u64>,
        expect_kind: Option<NodeKind>,
    ) -> Result<RejoinResponse, ClientError> {
        let resp = self
            .http
            .post(self.url(&format!("/admin/nodes/{name}/rejoin")))
            .bearer_auth(&self.admin_token)
            .json(&RejoinRequest { ttl_secs, kind: expect_kind })
            .send()?;
        Ok(Self::check_status(resp)?.json()?)
    }

    /// `PUT /admin/nodes/{name}/gateway` (PLAN.md M24) — records how a static
    /// peer's `.conf` is shaped, so `/poll` can derive routing that matches
    /// the file actually on the device.
    pub fn set_gateway(
        &self,
        name: &str,
        gateway: Option<&str>,
        conf_peers: &[String],
        exit: bool,
    ) -> Result<(), ClientError> {
        let resp = self
            .http
            .put(self.url(&format!("/admin/nodes/{name}/gateway")))
            .bearer_auth(&self.admin_token)
            .json(&SetGatewayRequest {
                gateway: gateway.map(ToString::to_string),
                conf_peers: conf_peers.to_vec(),
                exit,
            })
            .send()?;
        Self::check_status(resp)?;
        Ok(())
    }

    /// `PUT /admin/nodes/{name}/via-gateway` (PLAN.md #134) — whether devices
    /// exported with a gateway reach this node through it.
    pub fn set_via_gateway(&self, name: &str, enabled: bool) -> Result<SetViaGatewayResponse, ClientError> {
        let resp = self
            .http
            .put(self.url(&format!("/admin/nodes/{name}/via-gateway")))
            .bearer_auth(&self.admin_token)
            .json(&SetViaGatewayRequest { enabled })
            .send()?;
        Ok(Self::check_status(resp)?.json()?)
    }

    /// `GET /admin/services` — every declared service and its approval
    /// state.
    pub fn list_services(&self) -> Result<AdminServicesResponse, ClientError> {
        let resp = self
            .http
            .get(self.url("/admin/services"))
            .bearer_auth(&self.admin_token)
            .send()?;
        Ok(Self::check_status(resp)?.json()?)
    }

    /// `POST /admin/nodes/{node}/services/{service}/approve`.
    ///
    /// Both names are in the path because approval binds to the pair —
    /// there is no "approve whoever holds this name" call.
    pub fn approve_service(&self, node: &str, service: &str) -> Result<(), ClientError> {
        let resp = self
            .http
            .post(self.url(&format!("/admin/nodes/{node}/services/{service}/approve")))
            .bearer_auth(&self.admin_token)
            .send()?;
        Self::check_status(resp)?;
        Ok(())
    }

    /// `POST /admin/nodes/{name}/transit/approve`.
    pub fn approve_transit(&self, name: &str) -> Result<(), ClientError> {
        let resp = self
            .http
            .post(self.url(&format!("/admin/nodes/{name}/transit/approve")))
            .bearer_auth(&self.admin_token)
            .send()?;
        Self::check_status(resp)?;
        Ok(())
    }

    /// `POST /admin/nodes/{name}/transit/deny`.
    pub fn deny_transit(&self, name: &str) -> Result<(), ClientError> {
        let resp = self
            .http
            .post(self.url(&format!("/admin/nodes/{name}/transit/deny")))
            .bearer_auth(&self.admin_token)
            .send()?;
        Self::check_status(resp)?;
        Ok(())
    }

    /// `POST /admin/nodes/{node}/services/{service}/deny`.
    pub fn deny_service(
        &self,
        node: &str,
        service: &str,
        reason: Option<&str>,
    ) -> Result<(), ClientError> {
        let resp = self
            .http
            .post(self.url(&format!("/admin/nodes/{node}/services/{service}/deny")))
            .bearer_auth(&self.admin_token)
            .json(&DenyServiceRequest {
                reason: reason.map(str::to_string),
            })
            .send()?;
        Self::check_status(resp)?;
        Ok(())
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

}

/// `POST /register` (spec §4.2), sent to the coordinator's **node-facing**
/// listener — a different address/port from every other call in this
/// module, which talk to the admin listener (spec §4.0 mandates the two
/// be bound separately, e.g. different ports, so they can't be reached
/// the same way). Deliberately not an `AdminClient` method for that
/// reason: bundling it in would make "one base URL" look like it's
/// enough for every call this crate makes, which it isn't. Also
/// deliberately unauthenticated — no admin-token header — since the join
/// token in the body is itself the credential for this endpoint.
pub fn register(
    node_facing_base_url: &str,
    req: &RegisterRequest,
) -> Result<RegisterResponse, ClientError> {
    let url = format!("{}/register", node_facing_base_url.trim_end_matches('/'));
    let resp = http_client().post(url).json(req).send()?;
    Ok(AdminClient::check_status(resp)?.json()?)
}
