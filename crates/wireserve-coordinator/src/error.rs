use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use wireserve_types::ErrorBody;

use crate::db::DbError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    /// A 404 that says what is missing.
    #[error("{0}")]
    NoSuch(String),
    #[error("too many requests")]
    TooManyRequests,
    #[error(transparent)]
    Internal(#[from] DbError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        // The service-collision case carries an extra machine-readable
        // field (spec §4.3 / security review F3) so the agent can
        // quarantine exactly the offending declaration instead of the
        // whole poll cycle wedging on it forever — everything else is a
        // plain `{error}` body.
        if let AppError::Internal(DbError::ServiceNameCollision(name)) = &self {
            let body = ErrorBody::service_collision(
                format!("service name '{name}' is already in use"),
                name.clone(),
            );
            return (StatusCode::CONFLICT, Json(body)).into_response();
        }

        let (status, message) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::NoSuch(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::TooManyRequests => {
                (StatusCode::TOO_MANY_REQUESTS, "too many requests".to_string())
            }
            AppError::Internal(DbError::JoinTokenInvalid) => {
                (StatusCode::BAD_REQUEST, "invalid join token".to_string())
            }
            AppError::Internal(DbError::NameTaken) => {
                (StatusCode::CONFLICT, "name already in use".to_string())
            }
            AppError::Internal(DbError::PubkeyTaken) => (
                StatusCode::CONFLICT,
                "pubkey already registered to another node".to_string(),
            ),
            AppError::Internal(DbError::ServiceNameCollision(_)) => unreachable!("handled above"),
            AppError::Internal(DbError::Ipam(crate::ipam::IpamError::Exhausted)) => {
                tracing::error!("the mesh address range is full");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the mesh's address range is full; an admin must free some (revoke and delete nodes nobody uses, \
                     or deny services) or set a larger WIRESERVE_NET_V4_CIDR before more can join"
                        .to_string(),
                )
            }
            AppError::Internal(DbError::NodeNotFound) => {
                (StatusCode::NOT_FOUND, "not found".to_string())
            }
            AppError::Internal(other) => {
                tracing::error!(error = %other, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(ErrorBody::new(message))).into_response()
    }
}
