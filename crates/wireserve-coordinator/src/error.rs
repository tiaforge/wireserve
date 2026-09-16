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
    #[error("not found")]
    NotFound,
    #[error("too many requests")]
    TooManyRequests,
    #[error(transparent)]
    Internal(#[from] DbError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
            AppError::TooManyRequests => {
                (StatusCode::TOO_MANY_REQUESTS, "too many requests".to_string())
            }
            AppError::Internal(DbError::JoinTokenInvalid) => {
                (StatusCode::BAD_REQUEST, "invalid join token".to_string())
            }
            AppError::Internal(DbError::NameTaken) => {
                (StatusCode::CONFLICT, "name already in use".to_string())
            }
            AppError::Internal(DbError::ServiceNameCollision(name)) => (
                StatusCode::CONFLICT,
                format!("service name '{name}' is already in use"),
            ),
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
        (status, Json(ErrorBody { error: message })).into_response()
    }
}
