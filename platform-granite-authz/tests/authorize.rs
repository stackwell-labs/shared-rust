//! `GraniteAuthz::authorize` as a service calls it, against a fake ChirpAuth
//! token endpoint and a fake Granite.

use std::sync::Arc;

use base64::Engine as _;
use http::HeaderMap;
use platform_chirp_auth::mint::{MachineTokenMinter, MintConfig};
use platform_chirp_auth::{Authenticated, Caller, Plane};
use platform_granite_authz::{Denied, GraniteAuthz, Refusal};
use platform_http_error::ApiError;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The issuer of this service's machine token on each plane. The token's `iss`
/// is what tells the service which plane Granite looks the grant up on.
const PROD_ISSUER: &str = "https://signin.chirpauth.com";
const ACME_ISSUER: &str = "https://signin.chirpauth.com/test/acme";
const GRANT: &str = "6f1c1b7e-3a51-4c43-9a8e-2f0b6f9a0c11";

fn machine() -> Authenticated {
    Authenticated {
        caller: Caller::Machine {
            sub: "agent_cg".to_owned(),
            owner_sub: "sub_owner".to_owned(),
            client_id: "cs_live_cg".to_owned(),
        },
        plane: Plane::Prod,
    }
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(*k, v.parse().unwrap());
    }
    h
}

fn presenting_grant() -> HeaderMap {
    headers(&[("x-approval-grant", GRANT), ("x-user-id", "sub_alice")])
}

fn acme() -> Plane {
    Plane::Test {
        tenant: "acme".to_owned(),
    }
}

fn on_plane(plane: Plane) -> Authenticated {
    Authenticated { plane, ..machine() }
}

/// A JWT-shaped machine token with these claims. Only its `iss` is read
/// (unverified) by the service; Granite is the one that verifies it.
fn token_with(claims: serde_json::Value) -> String {
    let b64 = |v: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    format!(
        "{}.{}.sig",
        b64(&serde_json::json!({ "alg": "RS256", "typ": "JWT" })),
        b64(&claims)
    )
}

fn service_token(issuer: &str) -> String {
    token_with(serde_json::json!({ "iss": issuer, "sub": "svc", "aud": "cs_live_svc" }))
}

fn grant_json(environment: serde_json::Value) -> serde_json::Value {
    let mut grant = grant_without_environment();
    grant["environment"] = environment;
    grant
}

/// A grant as Granite returns it once granite#96 drops `environment`.
fn grant_without_environment() -> serde_json::Value {
    serde_json::json!({
        "id": GRANT,
        "owner_uid": "gsub_alice",
        "request_id": "0b9c1f7e-3a51-4c43-9a8e-2f0b6f9a0c22",
        "subject_app_id": "compute-gateway",
        "subject_chirp_sub": "agent_cg",
        "service_id": "storage",
        "resource": "model-gateway:call",
        "scopes": ["model.gateway.call"],
        "expires_at": null,
        "status": "active",
    })
}

/// ChirpAuth minting this service a production machine token.
async fn chirp() -> MockServer {
    chirp_minting(&service_token(PROD_ISSUER)).await
}

async fn chirp_minting(token: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "id_token": token, "expires_in": 3600 })),
        )
        .mount(&server)
        .await;
    server
}

fn authz(chirp: &MockServer, granite: &str) -> GraniteAuthz {
    let minter = Arc::new(MachineTokenMinter::new(MintConfig::new(
        chirp.uri(),
        "cs_live_svc",
        "secret",
    )));
    GraniteAuthz::new("model-gateway", granite, minter).unwrap()
}

/// Granite answering `status` with `body` to the exact verify this crate must
/// send: the service's own (production) token, the named person, the caller as
/// subject.
async fn granite(status: u16, body: serde_json::Value) -> MockServer {
    granite_for(&service_token(PROD_ISSUER), status, body).await
}

async fn granite_for(token: &str, status: u16, body: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/grants/verify"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .and(header("x-user-id", "sub_alice"))
        .and(body_json(serde_json::json!({
            "grant_id": GRANT,
            "resource": "model-gateway:call",
            "scopes": ["model.gateway.call"],
            "subject_chirp_sub": "agent_cg",
        })))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&server)
        .await;
    server
}

async fn authorize(
    authz: &GraniteAuthz,
    who: &Authenticated,
    headers: &HeaderMap,
) -> Result<platform_granite_authz::Authorized, Refusal> {
    authz
        .authorize(who, headers, "model-gateway:call", "model.gateway.call")
        .await
}

#[tokio::test]
async fn approved_grant_is_returned_with_whom_the_caller_acts_for() {
    let chirp = chirp().await;
    let granite = granite(
        200,
        serde_json::json!({ "approved": true, "grant": grant_json("Prod".into()) }),
    )
    .await;
    let got = authorize(
        &authz(&chirp, &granite.uri()),
        &machine(),
        &presenting_grant(),
    )
    .await
    .unwrap();
    assert_eq!(got.grant.id.to_string(), GRANT);
    assert_eq!(got.grant.owner_uid, "gsub_alice");
    assert_eq!(got.on_behalf_of, "sub_alice");
}

#[tokio::test]
async fn sends_a_user_agent_so_granites_waf_admits_it() {
    let chirp = chirp().await;
    let granite = granite(
        200,
        serde_json::json!({ "approved": true, "grant": grant_json("Prod".into()) }),
    )
    .await;
    authorize(
        &authz(&chirp, &granite.uri()),
        &machine(),
        &presenting_grant(),
    )
    .await
    .unwrap();
    let requests: Vec<Request> = granite.received_requests().await.unwrap();
    let ua = requests[0]
        .headers
        .get("user-agent")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        ua.starts_with("platform-granite-authz/") && ua.ends_with("(model-gateway)"),
        "{ua}"
    );
}

#[tokio::test]
async fn not_approved_is_denied_with_granites_reason() {
    let chirp = chirp().await;
    let granite = granite(
        200,
        serde_json::json!({ "approved": false, "reason": "grant revoked" }),
    )
    .await;
    let got = authorize(
        &authz(&chirp, &granite.uri()),
        &machine(),
        &presenting_grant(),
    )
    .await;
    assert_eq!(
        got.unwrap_err(),
        Refusal::Denied(Denied::NotApproved {
            reason: Some("grant revoked".to_owned())
        })
    );
}

#[tokio::test]
async fn unknown_grant_is_denied() {
    let chirp = chirp().await;
    let granite = granite(404, serde_json::json!({ "error": "not found" })).await;
    let got = authorize(
        &authz(&chirp, &granite.uri()),
        &machine(),
        &presenting_grant(),
    )
    .await;
    assert_eq!(
        got.unwrap_err(),
        Refusal::Denied(Denied::NotApproved { reason: None })
    );
}

/// The plane check rests on this service's own token, not on Granite's
/// `grant.environment` echo (shared-rust#34): a caller on another plane than
/// the token is refused before Granite is asked, whatever Granite would say.
#[tokio::test]
async fn a_caller_on_another_plane_than_the_services_token_is_wrong_plane() {
    let cases = [
        // A Test caller of a production service: the grant Granite would find
        // is a Prod grant, which a Test caller must not use.
        (PROD_ISSUER, acme(), grant_json("Prod".into())),
        (PROD_ISSUER, acme(), grant_without_environment()),
        // A Prod caller of a Test-plane service.
        (ACME_ISSUER, Plane::Prod, grant_without_environment()),
        // Another tenant's caller.
        (
            ACME_ISSUER,
            Plane::Test {
                tenant: "globex".to_owned(),
            },
            grant_json(serde_json::json!({ "Test": { "tenant": "acme" } })),
        ),
    ];
    for (issuer, plane, grant) in cases {
        let token = service_token(issuer);
        let chirp = chirp_minting(&token).await;
        let granite = granite_for(
            &token,
            200,
            serde_json::json!({ "approved": true, "grant": grant }),
        )
        .await;
        let got = authorize(
            &authz(&chirp, &granite.uri()),
            &on_plane(plane.clone()),
            &presenting_grant(),
        )
        .await;
        assert_eq!(
            got.unwrap_err(),
            Refusal::Denied(Denied::WrongPlane),
            "{issuer} {plane:?}"
        );
        assert!(
            granite.received_requests().await.unwrap().is_empty(),
            "{issuer} {plane:?}: Granite must not be asked"
        );
    }
}

/// A Test-plane service approves its own plane's grant even though Granite no
/// longer says which plane the grant is on (granite#96), which granite-client
/// reads as Prod: the echo is not consulted.
#[tokio::test]
async fn a_test_plane_service_approves_a_grant_granite_returns_without_environment() {
    let token = service_token(ACME_ISSUER);
    let chirp = chirp_minting(&token).await;
    let granite = granite_for(
        &token,
        200,
        serde_json::json!({ "approved": true, "grant": grant_without_environment() }),
    )
    .await;
    let got = authorize(
        &authz(&chirp, &granite.uri()),
        &on_plane(acme()),
        &presenting_grant(),
    )
    .await
    .unwrap();
    assert_eq!(got.grant.id.to_string(), GRANT);
    assert_eq!(got.on_behalf_of, "sub_alice");
}

/// A machine token that names no issuer is this service's mint gone wrong:
/// no verdict on the caller's grant, and Granite is not asked.
#[tokio::test]
async fn a_service_token_naming_no_issuer_is_unavailable() {
    for token in [
        "opaque-token".to_owned(),
        "a.!!!.c".to_owned(),
        token_with(serde_json::json!({ "sub": "svc" })),
        token_with(serde_json::json!({ "iss": 7 })),
    ] {
        let chirp = chirp_minting(&token).await;
        let granite = MockServer::start().await;
        let got = authorize(
            &authz(&chirp, &granite.uri()),
            &machine(),
            &presenting_grant(),
        )
        .await;
        let Err(Refusal::Unavailable(u)) = got else {
            panic!("{token}: {got:?}")
        };
        assert_eq!(u.reason(), "this service's machine token names no issuer");
        assert!(granite.received_requests().await.unwrap().is_empty());
    }
}

/// Every answer that is no verdict on the grant is a 503, never a 401 or 403:
/// Granite down, refusing this service's token (401), refusing it as an
/// enforcer (403), or answering garbage.
#[tokio::test]
async fn granite_without_a_verdict_is_unavailable() {
    let chirp = chirp().await;
    for (status, body) in [
        (500, serde_json::json!({ "error": "internal" })),
        (503, serde_json::json!({ "error": "unavailable" })),
        (401, serde_json::json!({ "error": "unauthorized" })),
        (403, serde_json::json!({ "error": "forbidden" })),
        (429, serde_json::json!({ "error": "slow down" })),
        (200, serde_json::json!({ "unexpected": true })),
        (200, serde_json::json!({ "approved": true })),
    ] {
        let granite = granite(status, body.clone()).await;
        let got = authorize(
            &authz(&chirp, &granite.uri()),
            &machine(),
            &presenting_grant(),
        )
        .await;
        let err = got.unwrap_err();
        assert!(
            matches!(err, Refusal::Unavailable(_)),
            "{status} {body}: {err:?}"
        );
        assert!(matches!(
            ApiError::from(err),
            ApiError::ServiceUnavailable(_)
        ));
    }
}

#[tokio::test]
async fn unreachable_granite_is_unavailable() {
    let chirp = chirp().await;
    // A port nothing listens on: bind, read the port, drop the listener.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let got = authorize(
        &authz(&chirp, &format!("http://127.0.0.1:{port}")),
        &machine(),
        &presenting_grant(),
    )
    .await;
    let Err(Refusal::Unavailable(u)) = got else {
        panic!("{got:?}")
    };
    assert_eq!(u.reason(), "could not connect to granite");
}

#[tokio::test]
async fn a_token_mint_failure_is_unavailable_and_granite_is_not_called() {
    let chirp = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({ "error": "invalid_client" })),
        )
        .mount(&chirp)
        .await;
    let granite = granite(
        200,
        serde_json::json!({ "approved": true, "grant": grant_json("Prod".into()) }),
    )
    .await;
    let got = authorize(
        &authz(&chirp, &granite.uri()),
        &machine(),
        &presenting_grant(),
    )
    .await;
    let Err(Refusal::Unavailable(u)) = got else {
        panic!("{got:?}")
    };
    assert_eq!(
        u.reason(),
        "chirp rejected this service's client credentials"
    );
    assert!(granite.received_requests().await.unwrap().is_empty());
}

/// Refusals the request itself settles: Granite is never asked.
#[tokio::test]
async fn refusals_before_granite_is_asked() {
    let chirp = chirp().await;
    let granite = MockServer::start().await;
    let authz = authz(&chirp, &granite.uri());
    let person = Authenticated {
        caller: Caller::Human {
            sub: "sub_alice".to_owned(),
            client_id: "cs_test_rp".to_owned(),
        },
        plane: Plane::Prod,
    };
    let cases: [(&Authenticated, HeaderMap, Denied); 6] = [
        (&person, presenting_grant(), Denied::NotAMachine),
        (
            &machine(),
            headers(&[("x-user-id", "sub_alice")]),
            Denied::NoGrant,
        ),
        (
            &machine(),
            headers(&[("x-approval-grant", "  "), ("x-user-id", "sub_alice")]),
            Denied::NoGrant,
        ),
        (
            &machine(),
            headers(&[("x-approval-grant", "grant-7"), ("x-user-id", "sub_alice")]),
            Denied::MalformedGrant,
        ),
        (
            &machine(),
            headers(&[("x-approval-grant", GRANT)]),
            Denied::NoActingUser,
        ),
        (
            &machine(),
            headers(&[("x-approval-grant", GRANT), ("x-user-id", &"a".repeat(129))]),
            Denied::NoActingUser,
        ),
    ];
    for (who, headers, want) in cases {
        let got = authorize(&authz, who, &headers).await.unwrap_err();
        assert_eq!(got, Refusal::Denied(want.clone()), "{want:?}");
        assert!(matches!(ApiError::from(got), ApiError::Forbidden));
    }
    assert!(granite.received_requests().await.unwrap().is_empty());
}
