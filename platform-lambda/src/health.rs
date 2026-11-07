//! Shared `/health` and `/_service-info` response shapes.
//!
//! Every agent-platform backend (drive, pigeon, granite, bowerbird) defines a
//! byte-identical `GET /health` returning `{"service": "<name>", "status":
//! "ok"}`, plus a `/_service-info` carrying the same `{service, protocol,
//! implementation_status, bind_addr, store}` core. These helpers are the single
//! source of truth for those shapes.
//!
//! They are *value builders*, not axum handlers: a backend's handler stays a
//! one-liner that wraps the returned struct in `axum::Json`, e.g.
//!
//! ```no_run
//! # use platform_lambda::health::{Health, ServiceInfo};
//! async fn health() -> axum::Json<Health> {
//!     axum::Json(Health::ok("pigeon"))
//! }
//! ```
//!
//! Keeping them as plain `Serialize` structs (rather than handlers bound to a
//! particular `AppState`) lets each service keep its own state type and its own
//! extra `_service-info` fields (drive, for instance, appends `default_limits`)
//! while still sharing the common core.

use axum::{routing::get, Json, Router};
use serde::Serialize;

/// An axum [`Router`] serving `GET /health` → `{"service": "<name>", "status":
/// "ok"}` and nothing else.
///
/// This is the canonical health endpoint the ~8 byte-identical services
/// (drive, granite, loom, pigeon, model-gateway, spend, compute, bowerbird)
/// each hand-rolled as a one-line handler returning their own `HealthResponse`.
/// Merge it into a service's app (`app.merge(health_router("drive"))`) to drop
/// the duplicated handler + response type.
///
/// It serves ONLY `/health`. `/healthz` (and any other path) is intentionally
/// NOT served — a service that wires this in and nothing else for that path
/// returns 404 for `/healthz`. The per-service `/_service-info` (which carries
/// extra, service-specific fields) stays owned by each service.
///
/// `service` is `'static` because the value is a compile-time constant in every
/// caller — the same constant the hand-rolled handlers embedded.
pub fn health_router(service: &'static str) -> Router {
    Router::new().route(
        "/health",
        get(move || async move { Json(Health::ok(service)) }),
    )
}

/// The `GET /health` response: `{"service": "<name>", "status": "ok"}`.
///
/// `status` is always `"ok"` — the route's only job is to answer "is the
/// process up and routing?", which is true by virtue of the handler running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Health {
    pub service: &'static str,
    pub status: &'static str,
}

impl Health {
    /// Build the standard healthy response for `service`.
    pub fn ok(service: &'static str) -> Self {
        Self {
            service,
            status: "ok",
        }
    }
}

/// The common `/_service-info` core shared by every backend.
///
/// Services that need extra fields (e.g. drive's `default_limits`) should keep
/// their own struct rather than contort this one; this captures the shape that
/// is genuinely identical across services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceInfo {
    pub service: &'static str,
    pub protocol: &'static str,
    pub implementation_status: &'static str,
    pub bind_addr: String,
    pub store: &'static str,
}

impl ServiceInfo {
    /// Build the standard service-info payload.
    ///
    /// `bind_addr` is taken as an owned `String` because it is derived from the
    /// runtime-resolved socket address (`state.bind_addr.to_string()`), not a
    /// compile-time constant like the other fields.
    pub fn new(
        service: &'static str,
        protocol: &'static str,
        implementation_status: &'static str,
        bind_addr: String,
        store: &'static str,
    ) -> Self {
        Self {
            service,
            protocol,
            implementation_status,
            bind_addr,
            store,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_ok_has_status_ok_and_named_service() {
        let h = Health::ok("pigeon");
        assert_eq!(h.service, "pigeon");
        assert_eq!(h.status, "ok");
    }

    #[test]
    fn health_serializes_to_the_canonical_shape() {
        let json = serde_json::to_value(Health::ok("granite")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"service": "granite", "status": "ok"})
        );
    }

    #[tokio::test]
    async fn health_router_serves_health_with_canonical_body() {
        use axum::body::to_bytes;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt; // for `oneshot`

        let app = health_router("drive");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"service": "drive", "status": "ok"})
        );
    }

    /// The router serves ONLY `/health`. `/healthz` is intentionally NOT served,
    /// so a service that wires this in returns 404 for `/healthz`.
    #[tokio::test]
    async fn health_router_returns_404_for_healthz() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = health_router("drive");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn service_info_serializes_to_the_canonical_core_shape() {
        let info = ServiceInfo::new(
            "bowerbird",
            "Bowerbird static-site hosting",
            "site CRUD slice active; publish engine pending",
            "127.0.0.1:8085".to_owned(),
            "memory",
        );
        let json = serde_json::to_value(info).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "service": "bowerbird",
                "protocol": "Bowerbird static-site hosting",
                "implementation_status": "site CRUD slice active; publish engine pending",
                "bind_addr": "127.0.0.1:8085",
                "store": "memory"
            })
        );
    }
}
