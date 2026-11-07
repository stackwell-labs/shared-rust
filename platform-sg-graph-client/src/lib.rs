//! Social-Graph **graph-access** client, shared by third-party apps.
//!
//! An app authenticates a user by their opaque **graph-access token** (minted in
//! the browser via SG's graph-OAuth consent flow). This client resolves that
//! token against SG's three graph-access endpoints — the protocol both gotta and
//! porch had copy-pasted (and let drift) into their own `clients/social_graph.rs`:
//!
//! - [`SocialGraphClient::resolve_me`] — `GET /api/graph-access/me` → the caller's
//!   per-app pseudonym ([`AppUserView`]).
//! - [`SocialGraphClient::register_membership`] — `POST /api/graph-access/membership`
//!   → upsert the caller's graph-app membership (idempotent) so connections can
//!   discover them.
//! - [`SocialGraphClient::connections_members`] — `GET
//!   /api/graph-access/connections/members` → the caller's connections who have
//!   joined this app, as pseudonyms.
//!
//! The client returns the RAW resolved data; each app keeps its own return
//! shaping (a plain pseudonym, or an environment-scoped identity built from
//! [`AppUserView::environment`]) and error mapping. No global `users.id` is ever
//! seen — SG mints a per-(app, user) pseudonym bound to the token server-side.
//!
//! Every call reports SG rejecting the token the same way, as
//! [`SgError::Rejected`], so an app maps that one variant to its own
//! Unauthorized and everything else to Internal (shared-rust#16).

use serde::Deserialize;

/// SG's `AppUserView` (camelCase wire shape). `id` is the caller's per-app
/// pseudonym. `environment` is the plane SG resolved the identity in (prod vs a
/// `/test/{tenant}` login) — ABSENT today (SG is not yet env-partitioned), which
/// an env-aware app reads as Production. Fields are public so apps shape their own
/// return (pseudonym-only, or an env-scoped identity).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUserView {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
}

#[derive(Deserialize)]
struct Member {
    #[serde(rename = "appUserId")]
    app_user_id: String,
}

/// A graph-access call failed. Its own error type so any consumer maps it (an
/// anyhow app via `?`, an app with its own `ApiError` via `.map_err`).
///
/// A consumer maps [`SgError::Rejected`] to its Unauthorized (the caller's
/// token is bad: prompt a re-sign-in) and the other two to Internal (SG or the
/// network failed).
#[derive(Debug)]
pub enum SgError {
    /// SG rejected the graph-access token (it answered 401 or 403, the status
    /// carried here): expired, forged or revoked. The caller's auth failure,
    /// not the app's.
    Rejected(u16),
    /// SG answered any other non-2xx status.
    Status(u16),
    /// The request did not complete (it failed to send, or the response body
    /// failed to read or decode). Never carries a status SG answered.
    Transport(reqwest::Error),
}

impl SgError {
    /// Classify a response by status: `Ok` on 2xx, else [`SgError::Rejected`]
    /// for 401/403 and [`SgError::Status`] for the rest. The one place a status
    /// becomes an error, so every call reports a rejected token the same way.
    fn check(resp: reqwest::Response) -> Result<reqwest::Response, SgError> {
        let status = resp.status();
        match status.as_u16() {
            _ if status.is_success() => Ok(resp),
            code @ (401 | 403) => Err(SgError::Rejected(code)),
            code => Err(SgError::Status(code)),
        }
    }
}

impl std::fmt::Display for SgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SgError::Rejected(code) => write!(f, "social-graph rejected the token -> {code}"),
            SgError::Status(code) => write!(f, "social-graph -> {code}"),
            SgError::Transport(e) => write!(f, "social-graph transport: {e}"),
        }
    }
}

impl std::error::Error for SgError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SgError::Transport(e) => Some(e),
            SgError::Rejected(_) | SgError::Status(_) => None,
        }
    }
}

/// A graph-access client bound to a Social-Graph base URL.
pub struct SocialGraphClient {
    http: reqwest::Client,
    base_url: String,
}

impl SocialGraphClient {
    pub fn new(http: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    /// Resolve the graph-access token to the caller's [`AppUserView`]. A token
    /// SG rejects is [`SgError::Rejected`].
    pub async fn resolve_me(&self, token: &str) -> Result<AppUserView, SgError> {
        let resp = self
            .http
            .get(format!("{}/api/graph-access/me", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(SgError::Transport)?;
        SgError::check(resp)?
            .json()
            .await
            .map_err(SgError::Transport)
    }

    /// Upsert the caller's graph-app membership (idempotent) so their connections
    /// can discover them. Without it a joined user is invisible in every
    /// connection's audience.
    pub async fn register_membership(
        &self,
        token: &str,
        app_user_id: &str,
        app_display_name: Option<&str>,
    ) -> Result<(), SgError> {
        self.http
            .post(format!("{}/api/graph-access/membership", self.base_url))
            .bearer_auth(token)
            .json(&serde_json::json!({
                "appUserId": app_user_id,
                "appDisplayName": app_display_name,
            }))
            .send()
            .await
            .map_err(SgError::Transport)
            .and_then(SgError::check)?;
        Ok(())
    }

    /// The caller's connections who have JOINED this app, as per-app pseudonyms —
    /// the valid audience / fan-out targets.
    pub async fn connections_members(&self, token: &str) -> Result<Vec<String>, SgError> {
        let members: Vec<Member> = self
            .http
            .get(format!(
                "{}/api/graph-access/connections/members",
                self.base_url
            ))
            .bearer_auth(token)
            .send()
            .await
            .map_err(SgError::Transport)
            .and_then(SgError::check)?
            .json()
            .await
            .map_err(SgError::Transport)?;
        Ok(members.into_iter().map(|m| m.app_user_id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn resolve_me_returns_the_view_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/graph-access/me"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "psd_alice",
                "displayName": "Alice",
            })))
            .mount(&server)
            .await;
        let c = SocialGraphClient::new(reqwest::Client::new(), server.uri());
        let v = c.resolve_me("tok").await.unwrap();
        assert_eq!(v.id, "psd_alice");
        assert_eq!(v.display_name.as_deref(), Some("Alice"));
        assert!(v.environment.is_none());
    }

    /// A client against an SG whose every graph-access endpoint answers `status`.
    async fn sg_answering(status: u16) -> (MockServer, SocialGraphClient) {
        let server = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let c = SocialGraphClient::new(reqwest::Client::new(), server.uri());
        (server, c)
    }

    /// The error each of the three calls returns against an SG answering `status`.
    async fn errors_on(status: u16) -> [(&'static str, SgError); 3] {
        let (_s, c) = sg_answering(status).await;
        [
            ("resolve_me", c.resolve_me("t").await.unwrap_err()),
            (
                "register_membership",
                c.register_membership("t", "psd", None).await.unwrap_err(),
            ),
            (
                "connections_members",
                c.connections_members("t").await.unwrap_err(),
            ),
        ]
    }

    #[tokio::test]
    async fn a_rejected_token_is_rejected_on_every_call() {
        for status in [401, 403] {
            for (call, e) in errors_on(status).await {
                assert!(
                    matches!(e, SgError::Rejected(code) if code == status),
                    "{call} on {status}: {e:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn any_other_failing_status_is_status_on_every_call() {
        for status in [400, 404, 500, 503] {
            for (call, e) in errors_on(status).await {
                assert!(
                    matches!(e, SgError::Status(code) if code == status),
                    "{call} on {status}: {e:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn an_unreachable_sg_is_transport() {
        // Bind then drop a listener so the port refuses connections.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let c = SocialGraphClient::new(reqwest::Client::new(), format!("http://{addr}"));
        assert!(matches!(
            c.resolve_me("t").await,
            Err(SgError::Transport(_))
        ));
        assert!(matches!(
            c.connections_members("t").await,
            Err(SgError::Transport(_))
        ));
        assert!(matches!(
            c.register_membership("t", "psd", None).await,
            Err(SgError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn connections_members_maps_app_user_ids() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/graph-access/connections/members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "appUserId": "psd_bob", "displayName": "B" },
                { "appUserId": "psd_carol", "displayName": "C" },
            ])))
            .mount(&server)
            .await;
        let c = SocialGraphClient::new(reqwest::Client::new(), server.uri());
        assert_eq!(
            c.connections_members("tok").await.unwrap(),
            vec!["psd_bob".to_string(), "psd_carol".to_string()]
        );
    }

    #[tokio::test]
    async fn register_membership_posts_the_pseudonym_and_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/graph-access/membership"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let c = SocialGraphClient::new(reqwest::Client::new(), server.uri());
        c.register_membership("tok", "psd_bob", Some("Bob"))
            .await
            .unwrap();
    }
}
