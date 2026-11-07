//! Canonical HTTP error type for agent-platform backends.
//!
//! Every backend (drive, pigeon, bowerbird, social-graph, granite, gotta)
//! had its own `ApiError`/`AppError` with a hand-rolled `IntoResponse`. Some
//! redacted 5xx bodies (pigeon, social-graph), some leaked the raw message
//! (drive, bowerbird), and gotta leaked entire anyhow chains. This crate is
//! the single source of truth, and it makes redaction **true by
//! construction**: the [`IntoResponse`] impl ALWAYS replaces the body of any
//! 5xx (server-error) response with a generic `"internal error"` string and
//! logs the real detail server-side. There is no code path through which an
//! internal `5xx` message reaches the client, because the redaction key off
//! the status code itself — not off which variant produced it.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// The body a client sees for a redacted server error. Constant so a 5xx
/// can never carry a variable, internal-detail-leaking message.
const REDACTED_INTERNAL_BODY: &str = "internal error";

/// Canonical API error. The union of the variants used across the platform
/// backends. Each carries an optional caller-facing message; for 5xx variants
/// that message is treated as internal detail (logged, never returned).
#[derive(Debug)]
pub enum ApiError {
    /// 400 — the request was malformed. `message` is caller-facing.
    BadRequest(String),
    /// 401 — no/invalid credentials. Body is a fixed `"unauthorized"`.
    Unauthorized,
    /// 403 — authenticated but not permitted. Body is a fixed `"forbidden"`.
    Forbidden,
    /// 404 — resource not found. `message` is caller-facing.
    NotFound(String),
    /// 409 — conflict with current state. `message` is caller-facing.
    Conflict(String),
    /// 413 — payload too large. `message` is caller-facing.
    PayloadTooLarge(String),
    /// 429 — rate limited. `message` is caller-facing.
    RateLimited(String),
    /// 501 — not implemented. `message` is caller-facing.
    NotImplemented(String),
    /// 503 — service unavailable. `message` is caller-facing.
    ServiceUnavailable(String),
    /// 500 — internal error. `message` is internal detail: logged
    /// server-side, NEVER returned to the client (redacted by construction).
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl ApiError {
    /// Status code this error maps to.
    fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The caller-facing message for non-5xx variants. Returns the internal
    /// detail string for 5xx variants too, but [`IntoResponse`] never uses it
    /// for 5xx — it logs it instead. Kept private so the only public way to
    /// turn an error into a response is the redacting `into_response`.
    fn detail(&self) -> &str {
        match self {
            Self::BadRequest(m)
            | Self::NotFound(m)
            | Self::Conflict(m)
            | Self::PayloadTooLarge(m)
            | Self::RateLimited(m)
            | Self::NotImplemented(m)
            | Self::ServiceUnavailable(m)
            | Self::Internal(m) => m,
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        // Redaction is keyed off the status code, not the variant: ANY 5xx
        // gets a generic body and its detail logged server-side. This makes
        // it impossible to add a new 5xx variant that leaks — the redaction
        // happens here, uniformly, by construction.
        if status.is_server_error() {
            tracing::error!(
                %status,
                detail = %self.detail(),
                "request failed with server error",
            );
            return (
                status,
                Json(ErrorBody {
                    error: REDACTED_INTERNAL_BODY,
                }),
            )
                .into_response();
        }
        (
            status,
            Json(ErrorBody {
                error: self.detail(),
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_string(resp: Response) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn internal_error_body_is_redacted() {
        let secret = "dynamodb ConditionalCheckFailed on table prod-items at arn:aws:...";
        let (status, body) = body_string(ApiError::Internal(secret.into()).into_response()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("dynamodb"), "leaked internal detail: {body}");
        assert!(body.contains("internal error"));
    }

    #[tokio::test]
    async fn service_unavailable_is_also_redacted() {
        let (status, body) =
            body_string(ApiError::ServiceUnavailable("upstream xyz down".into()).into_response())
                .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!body.contains("upstream"), "leaked 5xx detail: {body}");
        assert!(body.contains("internal error"));
    }

    #[tokio::test]
    async fn client_errors_pass_message_through() {
        let (status, body) =
            body_string(ApiError::BadRequest("missing field `name`".into()).into_response()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("missing field `name`"));
    }

    #[tokio::test]
    async fn unauthorized_and_forbidden_have_fixed_bodies() {
        let (s1, b1) = body_string(ApiError::Unauthorized.into_response()).await;
        assert_eq!(s1, StatusCode::UNAUTHORIZED);
        assert!(b1.contains("unauthorized"));
        let (s2, b2) = body_string(ApiError::Forbidden.into_response()).await;
        assert_eq!(s2, StatusCode::FORBIDDEN);
        assert!(b2.contains("forbidden"));
    }

    #[tokio::test]
    async fn rate_limited_maps_to_429() {
        let (status, _) =
            body_string(ApiError::RateLimited("slow down".into()).into_response()).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }
}
