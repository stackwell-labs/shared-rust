//! Clients for chirp's trusted-service routes, authenticated by the calling
//! service's own machine token (shared-rust#5).
//!
//! - [`RootResolver`]: `POST /control/root-for-sub`, pairwise sub to root.
//! - [`OperatorIntrospector`]: `POST /operator/introspect`, live operator
//!   status.
//!
//! Drive, Granite and Social Graph each carried their own copy of these, with
//! three different answers to "what if the resolver isn't configured" and a
//! hand-rolled `client_credentials` cache in two of them. Here both clients take
//! a [`MachineTokenMinter`] and present its token as the bearer; chirp
//! authorizes the call by a flag on that client's record (`operator_introspect`
//! today, and a dedicated `root_resolve` flag once chirp ships it). There is no
//! static-bearer path.
//!
//! **Configuration is not optional.** Neither client has an "absent" state:
//! [`RootResolver::new`] and [`OperatorIntrospector::new`] take the chirp base
//! URL and a minter, and refuse a blank or non-http(s) URL with a
//! [`ConfigError`]. A service that reads its settings and builds these at
//! startup therefore fails at boot when they are missing, rather than passing
//! ids through, failing closed per request or answering 503 only in some
//! modes.
//!
//! **Failure is [`Unavailable`].** Every transport, mint, auth or parse failure
//! is one error the caller must not read as a negative answer: an outage of the
//! resolver is never "this sub has no root", and an outage of introspection is
//! never "not an operator" either (the caller denies, but says why).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use chirp_auth_client::mint::{MachineTokenMinter, MintError};
use platform_http_error::ApiError;
use serde::Deserialize;

use crate::ids::{PairwiseSub, RootId};

/// The root-for-sub route, relative to the chirp base URL.
pub const ROOT_FOR_SUB_PATH: &str = "/control/root-for-sub";
/// The operator-introspection route, relative to the chirp base URL.
pub const OPERATOR_INTROSPECT_PATH: &str = "/operator/introspect";

/// [`RootResolver::root_of`]'s cache is cleared when it reaches this many
/// entries, bounding a long-lived instance's memory.
pub const ROOT_CACHE_MAX: usize = 10_000;

/// The chirp control route could not give an answer. The reason names the
/// failure (a status code, a mint rejection, a malformed body) and never holds
/// a token or a response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    route: &'static str,
    reason: String,
}

impl Unavailable {
    fn new(route: &'static str, reason: impl Into<String>) -> Self {
        Self {
            route,
            reason: reason.into(),
        }
    }

    /// Which chirp route failed ([`ROOT_FOR_SUB_PATH`] or
    /// [`OPERATOR_INTROSPECT_PATH`]).
    pub fn route(&self) -> &'static str {
        self.route
    }

    /// What went wrong, for a log line.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chirp {} unavailable: {}", self.route, self.reason)
    }
}

impl std::error::Error for Unavailable {}

/// A 503 whose caller-facing text names the route but not the reason; log the
/// [`Unavailable`] itself before converting if the reason matters.
impl From<Unavailable> for ApiError {
    fn from(e: Unavailable) -> Self {
        ApiError::ServiceUnavailable(format!("chirp {} unavailable", e.route))
    }
}

/// A chirp control client was built from settings it cannot work with. Meant
/// to stop boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// What both clients share: where chirp is, whose machine token to present, and
/// the HTTP client to send with (a service passes its UA-bearing one: chirp's
/// CloudFront WAF refuses UA-less requests).
#[derive(Clone)]
struct MachineCaller {
    base_url: String,
    minter: Arc<MachineTokenMinter>,
    http: reqwest::Client,
}

impl MachineCaller {
    fn new(
        base_url: &str,
        minter: Arc<MachineTokenMinter>,
        http: reqwest::Client,
    ) -> Result<Self, ConfigError> {
        let base_url = base_url.trim().trim_end_matches('/');
        if base_url.is_empty() {
            return Err(ConfigError(
                "chirp base URL is empty: a chirp control client must be configured".to_owned(),
            ));
        }
        let parsed = reqwest::Url::parse(base_url)
            .map_err(|e| ConfigError(format!("chirp base URL does not parse: {e}")))?;
        if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
            return Err(ConfigError(
                "chirp base URL must be an http(s) URL with a host".to_owned(),
            ));
        }
        Ok(Self {
            base_url: base_url.to_owned(),
            minter,
            http,
        })
    }

    /// POST `{"sub": …}` to `route` with a fresh-or-cached machine token.
    async fn post_sub(
        &self,
        route: &'static str,
        sub: &PairwiseSub,
    ) -> Result<reqwest::Response, Unavailable> {
        let token = self.minter.token().await.map_err(|e| {
            Unavailable::new(
                route,
                match e {
                    MintError::Rejected(_) => {
                        "chirp rejected this service's client credentials".to_owned()
                    }
                    MintError::Suppressed { retry_after } => format!(
                        "machine-token minting suppressed for {}s after a rejection",
                        retry_after.as_secs()
                    ),
                    MintError::Transient(_) => "machine-token mint failed".to_owned(),
                },
            )
        })?;
        self.http
            .post(format!("{}{route}", self.base_url))
            .bearer_auth(token)
            .json(&serde_json::json!({ "sub": sub.as_str() }))
            .send()
            .await
            .map_err(|e| {
                let kind = if e.is_timeout() {
                    "timed out"
                } else if e.is_connect() {
                    "could not connect"
                } else {
                    "request failed"
                };
                Unavailable::new(route, kind)
            })
    }
}

/// chirp's answer for a sub it knows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Resolved {
    /// The account the sub belongs to.
    #[serde(rename = "root_id")]
    pub root: RootId,
    /// Whether chirp still issues this sub. `false` marks a sub minted before
    /// the D2 key cut: it still resolves, but no sign-in will present it again,
    /// so a service must not file new work to it. Required: a chirp answer
    /// without it is [`Unavailable`], never read as current.
    pub current: bool,
}

/// Resolves a pairwise sub to its root account through chirp's
/// `POST /control/root-for-sub`.
///
/// Cheap to clone; clones share the root cache.
#[derive(Clone)]
pub struct RootResolver {
    caller: MachineCaller,
    /// sub -> root. A sub's root never changes (chirp never re-points a sub),
    /// so a positive answer can be kept for the instance's life. Negative
    /// answers are not kept: a sub with no root yet may be indexed later.
    cache: Arc<Mutex<HashMap<PairwiseSub, RootId>>>,
}

impl RootResolver {
    /// Build a resolver for the chirp at `base_url` (e.g.
    /// `https://signin.chirpauth.com`, never a `/test/{tenant}` issuer: the
    /// control plane is not tenant-scoped), authenticating with `minter`'s
    /// machine token. The minter's client must carry chirp's root-resolve flag.
    pub fn new(
        base_url: &str,
        minter: Arc<MachineTokenMinter>,
        http: reqwest::Client,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            caller: MachineCaller::new(base_url, minter, http)?,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Ask chirp for `sub`'s root and standing, uncached.
    ///
    /// - `Ok(Some(_))`: chirp knows the sub.
    /// - `Ok(None)`: chirp answered `404 no_root_for_sub`. Any other 404 (a
    ///   chirp with the route switched off) is [`Unavailable`].
    /// - `Err(Unavailable)`: anything else.
    ///
    /// Uncached because `current` can change: a current sub becomes retired at
    /// the D2 key cut. Use [`Self::root_of`] when only the root matters.
    pub async fn resolve(&self, sub: &PairwiseSub) -> Result<Option<Resolved>, Unavailable> {
        let resp = self.caller.post_sub(ROOT_FOR_SUB_PATH, sub).await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return match resp.json::<ErrorBody>().await {
                Ok(body) if body.error == "no_root_for_sub" => Ok(None),
                _ => Err(Unavailable::new(
                    ROOT_FOR_SUB_PATH,
                    "404 without no_root_for_sub: the route is not enabled",
                )),
            };
        }
        if !status.is_success() {
            return Err(Unavailable::new(
                ROOT_FOR_SUB_PATH,
                format!("chirp answered {status}"),
            ));
        }
        let resolved: Resolved = resp.json().await.map_err(|_| {
            Unavailable::new(
                ROOT_FOR_SUB_PATH,
                "chirp's answer is not {root_id: usr_…, current: bool}",
            )
        })?;
        self.remember(sub, &resolved.root);
        Ok(Some(resolved))
    }

    /// `sub`'s root, from the instance cache when this sub has resolved before.
    /// Same `None`/[`Unavailable`] meaning as [`Self::resolve`]. For the
    /// per-request owner-keying path, where only the root matters and a chirp
    /// round trip per request would be the added latency.
    pub async fn root_of(&self, sub: &PairwiseSub) -> Result<Option<RootId>, Unavailable> {
        if let Some(root) = self.cached(sub) {
            return Ok(Some(root));
        }
        Ok(self.resolve(sub).await?.map(|r| r.root))
    }

    fn cached(&self, sub: &PairwiseSub) -> Option<RootId> {
        // A poisoned lock only means another request panicked mid-insert; the
        // map is still a valid cache, so read through it.
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        cache.get(sub).cloned()
    }

    fn remember(&self, sub: &PairwiseSub, root: &RootId) {
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= ROOT_CACHE_MAX {
            cache.clear();
        }
        cache.insert(sub.clone(), root.clone());
    }
}

/// Asks chirp whether a sub is an operator right now, through
/// `POST /operator/introspect`. Uncached: operator status is checked live so a
/// demotion takes effect at once.
#[derive(Clone)]
pub struct OperatorIntrospector {
    caller: MachineCaller,
}

impl OperatorIntrospector {
    /// Build an introspector for the chirp at `base_url`, authenticating with
    /// `minter`'s machine token. The minter's client must carry chirp's
    /// `operator_introspect` flag.
    pub fn new(
        base_url: &str,
        minter: Arc<MachineTokenMinter>,
        http: reqwest::Client,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            caller: MachineCaller::new(base_url, minter, http)?,
        })
    }

    /// Whether `sub` is an operator now. `Err` means chirp could not say; a
    /// caller gating an operator action denies on it.
    pub async fn is_operator(&self, sub: &PairwiseSub) -> Result<bool, Unavailable> {
        let resp = self.caller.post_sub(OPERATOR_INTROSPECT_PATH, sub).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(Unavailable::new(
                OPERATOR_INTROSPECT_PATH,
                format!("chirp answered {status}"),
            ));
        }
        let body: IntrospectBody = resp.json().await.map_err(|_| {
            Unavailable::new(
                OPERATOR_INTROSPECT_PATH,
                "chirp's answer has no boolean is_operator",
            )
        })?;
        Ok(body.is_operator)
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

#[derive(Deserialize)]
struct IntrospectBody {
    is_operator: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chirp_auth_client::mint::MintConfig;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "machine.id.token";

    /// A chirp stand-in whose `/token` mints [`TOKEN`] for `cs_live_svc`.
    async fn chirp() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "id_token": TOKEN, "expires_in": 3600 })),
            )
            .mount(&server)
            .await;
        server
    }

    fn minter(server: &MockServer) -> Arc<MachineTokenMinter> {
        Arc::new(MachineTokenMinter::new(MintConfig::new(
            server.uri(),
            "cs_live_svc",
            "secret",
        )))
    }

    fn sub(s: &str) -> PairwiseSub {
        PairwiseSub::parse(s).unwrap()
    }

    /// Mount a root-for-sub answer, requiring the machine token as bearer and
    /// the sub in the body.
    async fn answer_root(server: &MockServer, for_sub: &str, status: u16, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path(ROOT_FOR_SUB_PATH))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_json(serde_json::json!({ "sub": for_sub })))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn resolver(server: &MockServer) -> RootResolver {
        RootResolver::new(&server.uri(), minter(server), reqwest::Client::new()).unwrap()
    }

    #[tokio::test]
    async fn resolves_root_and_standing_with_the_machine_token() {
        let server = chirp().await;
        answer_root(
            &server,
            "sub_alice",
            200,
            serde_json::json!({ "root_id": "usr_alice", "current": false }),
        )
        .await;
        let got = resolver(&server)
            .await
            .resolve(&sub("sub_alice"))
            .await
            .unwrap();
        assert_eq!(
            got,
            Some(Resolved {
                root: RootId::parse("usr_alice").unwrap(),
                current: false
            })
        );
    }

    #[tokio::test]
    async fn no_root_for_sub_is_none() {
        let server = chirp().await;
        answer_root(
            &server,
            "sub_ghost",
            404,
            serde_json::json!({ "error": "no_root_for_sub" }),
        )
        .await;
        assert_eq!(
            resolver(&server).await.resolve(&sub("sub_ghost")).await,
            Ok(None)
        );
    }

    #[tokio::test]
    async fn a_disabled_route_is_unavailable_not_none() {
        let server = chirp().await;
        answer_root(
            &server,
            "sub_alice",
            404,
            serde_json::json!({ "error": "not_found" }),
        )
        .await;
        let err = resolver(&server)
            .await
            .resolve(&sub("sub_alice"))
            .await
            .unwrap_err();
        assert_eq!(err.route(), ROOT_FOR_SUB_PATH);
    }

    #[tokio::test]
    async fn refusals_and_bad_answers_are_unavailable() {
        let cases = [
            (401, serde_json::json!({ "error": "unauthorized" })),
            (403, serde_json::json!({ "error": "forbidden" })),
            (400, serde_json::json!({ "error": "bad_request" })),
            (500, serde_json::json!({})),
            // `current` missing: never read as current.
            (200, serde_json::json!({ "root_id": "usr_alice" })),
            // A root in the wrong namespace.
            (
                200,
                serde_json::json!({ "root_id": "sub_alice", "current": true }),
            ),
            (200, serde_json::json!({ "root_id": "", "current": true })),
        ];
        for (status, body) in cases {
            let server = chirp().await;
            answer_root(&server, "sub_alice", status, body.clone()).await;
            let got = resolver(&server).await.resolve(&sub("sub_alice")).await;
            assert!(got.is_err(), "{status} {body} gave {got:?}");
        }
    }

    #[tokio::test]
    async fn a_rejected_client_is_unavailable_without_calling_the_route() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({ "error": "invalid_client" })),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(ROOT_FOR_SUB_PATH))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let err = resolver(&server)
            .await
            .resolve(&sub("sub_alice"))
            .await
            .unwrap_err();
        assert!(err.reason().contains("rejected"), "{err}");
        assert!(!err.to_string().contains("secret"), "{err}");
    }

    #[tokio::test]
    async fn root_of_caches_positive_answers_only() {
        let server = chirp().await;
        Mock::given(method("POST"))
            .and(path(ROOT_FOR_SUB_PATH))
            .and(body_json(serde_json::json!({ "sub": "sub_alice" })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "root_id": "usr_alice", "current": true })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(ROOT_FOR_SUB_PATH))
            .and(body_json(serde_json::json!({ "sub": "sub_ghost" })))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({ "error": "no_root_for_sub" })),
            )
            .expect(2)
            .mount(&server)
            .await;
        let r = resolver(&server).await;
        let clone = r.clone();
        let alice = Some(RootId::parse("usr_alice").unwrap());
        assert_eq!(r.root_of(&sub("sub_alice")).await.unwrap(), alice);
        assert_eq!(clone.root_of(&sub("sub_alice")).await.unwrap(), alice);
        assert_eq!(r.root_of(&sub("sub_ghost")).await.unwrap(), None);
        assert_eq!(r.root_of(&sub("sub_ghost")).await.unwrap(), None);
        // `expect` counts are checked when `server` drops.
    }

    #[tokio::test]
    async fn introspects_operator_status() {
        let server = chirp().await;
        for (who, is_op) in [("sub_op", true), ("sub_user", false)] {
            Mock::given(method("POST"))
                .and(path(OPERATOR_INTROSPECT_PATH))
                .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
                .and(body_json(serde_json::json!({ "sub": who })))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({ "sub": who, "is_operator": is_op, "checked_at_epoch": 1 }),
                ))
                .mount(&server)
                .await;
        }
        let i = OperatorIntrospector::new(&server.uri(), minter(&server), reqwest::Client::new())
            .unwrap();
        assert!(i.is_operator(&sub("sub_op")).await.unwrap());
        assert!(!i.is_operator(&sub("sub_user")).await.unwrap());
    }

    #[tokio::test]
    async fn introspection_refusal_is_unavailable_not_false() {
        let server = chirp().await;
        Mock::given(method("POST"))
            .and(path(OPERATOR_INTROSPECT_PATH))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_json(serde_json::json!({ "error": "forbidden" })),
            )
            .mount(&server)
            .await;
        let i = OperatorIntrospector::new(&server.uri(), minter(&server), reqwest::Client::new())
            .unwrap();
        let err = i.is_operator(&sub("sub_op")).await.unwrap_err();
        assert_eq!(err.route(), OPERATOR_INTROSPECT_PATH);
        let api: ApiError = err.into();
        assert!(matches!(api, ApiError::ServiceUnavailable(_)));
    }

    #[test]
    fn blank_or_odd_base_urls_refuse_to_build() {
        let m = Arc::new(MachineTokenMinter::new(MintConfig::new(
            "https://x",
            "c",
            "s",
        )));
        for bad in [
            "",
            "   ",
            "/",
            "signin.chirpauth.com",
            "ftp://signin.chirpauth.com",
            "https://",
        ] {
            assert!(
                RootResolver::new(bad, m.clone(), reqwest::Client::new()).is_err(),
                "{bad:?} built"
            );
            assert!(
                OperatorIntrospector::new(bad, m.clone(), reqwest::Client::new()).is_err(),
                "{bad:?} built"
            );
        }
        let ok =
            RootResolver::new("https://signin.chirpauth.com/", m, reqwest::Client::new()).unwrap();
        assert_eq!(ok.caller.base_url, "https://signin.chirpauth.com");
    }
}
