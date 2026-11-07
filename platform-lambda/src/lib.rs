//! Shared axum-on-Lambda runtime glue for agent-platform backends.
//!
//! drive, pigeon, and bowerbird each carried byte-identical copies of
//! `run_lambda`, `shutdown_signal`, and `init_tracing`, plus the same
//! local-vs-Lambda `main` shape. This crate is the single source of truth.
//!
//! A backend's `main` becomes:
//!
//! ```no_run
//! # use axum::Router;
//! # async fn build_app() -> Router { Router::new() }
//! #[tokio::main]
//! async fn main() {
//!     let app = build_app().await;
//!     platform_lambda::serve(
//!         app,
//!         platform_lambda::ServeConfig {
//!             bind_env: "DRIVE_SERVICE_BIND_ADDR",
//!             default_bind: "127.0.0.1:8082",
//!             default_filter: "drive_service=info",
//!         },
//!     )
//!     .await;
//! }
//! ```

use std::net::SocketAddr;
use std::sync::OnceLock;

use axum::Router;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tracing_subscriber::EnvFilter;

pub mod health;
pub mod store;

/// Re-export the canonical health endpoint at the crate root so consumers can
/// `platform_lambda::health_router("drive")` without naming the `health` module.
pub use health::health_router;

/// Environment variable the Lambda runtime sets. Its presence is how a
/// process distinguishes "running inside Lambda" from "running locally".
const AWS_LAMBDA_RUNTIME_API_ENV: &str = "AWS_LAMBDA_RUNTIME_API";

/// Configuration for [`serve`]. Each field is the per-service value that used
/// to be a hard-coded literal in every backend's `main`.
#[derive(Debug, Clone, Copy)]
pub struct ServeConfig {
    /// Env var holding the local bind address (e.g. `DRIVE_SERVICE_BIND_ADDR`).
    pub bind_env: &'static str,
    /// Default `host:port` used when `bind_env` is unset.
    pub default_bind: &'static str,
    /// Default tracing filter (e.g. `"drive_service=info"`) used when
    /// `RUST_LOG`/`RUST_LOG`-style env filters are absent.
    pub default_filter: &'static str,
}

/// The `default_filter` the global subscriber was installed with, set by the
/// first [`init_tracing`] call.
static INSTALLED_FILTER: OnceLock<String> = OnceLock::new();

/// Initialize the global tracing subscriber from the environment, falling
/// back to `default_filter` when no `EnvFilter` is set.
///
/// Idempotent: the first call installs the subscriber; a later call with the
/// same `default_filter` does nothing. That is what lets a backend call it as
/// the first line of `main`, so events emitted while it builds its app (before
/// [`serve`], which calls it again) reach the log instead of being dropped for
/// want of a subscriber (drive#59).
///
/// # Panics
///
/// If a later call passes a different `default_filter` (it would silently not
/// apply), or if a subscriber not installed by this function is already the
/// global default.
pub fn init_tracing(default_filter: &str) {
    let installed = INSTALLED_FILTER.get_or_init(|| {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
        tracing_subscriber::fmt().with_env_filter(filter).init();
        default_filter.to_owned()
    });
    assert_eq!(
        installed, default_filter,
        "init_tracing already installed the subscriber with a different default filter"
    );
}

/// Run `app` under the AWS Lambda runtime, wrapping it in the
/// `axum_aws_lambda::LambdaLayer` adapter so an ordinary axum `Router` speaks
/// the Lambda HTTP event protocol.
pub async fn run_lambda(app: Router) -> Result<(), lambda_http::Error> {
    let app = ServiceBuilder::new()
        .layer(axum_aws_lambda::LambdaLayer::default())
        .service(app);
    lambda_http::run(app).await
}

/// Future that completes on Ctrl-C (SIGINT) or SIGTERM. Pass to
/// `axum::serve(...).with_graceful_shutdown(...)` for clean local shutdown.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

/// One-call entrypoint owning the local-vs-Lambda detect.
///
/// Initializes tracing (a no-op if the caller already did, with the same
/// filter: see [`init_tracing`]), then:
/// - if `AWS_LAMBDA_RUNTIME_API` is set, runs `app` under the Lambda runtime;
/// - otherwise binds the configured address and serves locally with graceful
///   shutdown on Ctrl-C / SIGTERM.
///
/// This consolidates the `main` body that drive/pigeon/bowerbird each
/// duplicated. Panics with a descriptive message on any unrecoverable startup
/// failure (bad bind address, bind failure, Lambda runtime error) — the same
/// fail-loud behavior the hand-written `main`s had.
pub async fn serve(app: Router, config: ServeConfig) {
    init_tracing(config.default_filter);

    let bind_addr: SocketAddr = std::env::var(config.bind_env)
        .unwrap_or_else(|_| config.default_bind.to_owned())
        .parse()
        .unwrap_or_else(|_| panic!("{} must be host:port", config.bind_env));

    if std::env::var_os(AWS_LAMBDA_RUNTIME_API_ENV).is_some() {
        run_lambda(app).await.expect("run Lambda service");
        return;
    }

    let listener = TcpListener::bind(bind_addr)
        .await
        .expect("bind service listener");
    tracing::info!(%bind_addr, "starting service");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("run service");
}
