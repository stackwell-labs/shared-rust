//! `GraniteAuthz::authorize` as a service calls it, against a fake ChirpAuth
//! token endpoint and a fake Granite.

use std::sync::Arc;

use http::HeaderMap;
use platform_chirp_auth::mint::{MachineTokenMinter, MintConfig};
use platform_chirp_auth::{Authenticated, Caller, Plane};
use platform_granite_authz::{Denied, GraniteAuthz, Refusal};
use platform_http_error::ApiError;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SERVICE_TOKEN: &str = "service.machine.token";
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

fn grant_json(environment: serde_json::Value) -> serde_json::Value {
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
        "environment": environment,
    })
}

async fn chirp() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "id_token": SERVICE_TOKEN, "expires_in": 3600 }),
            ),
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
/// send: the service's own token, the named person, the caller as subject.
async fn granite(status: u16, body: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/grants/verify"))
        .and(header(
            "authorization",
            format!("Bearer {SERVICE_TOKEN}").as_str(),
        ))
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

#[tokio::test]
async fn a_grant_from_another_plane_is_denied() {
    let chirp = chirp().await;
    let granite = granite(
        200,
        serde_json::json!({
            "approved": true,
            "grant": grant_json(serde_json::json!({ "Test": { "tenant": "acme" } })),
        }),
    )
    .await;
    let got = authorize(
        &authz(&chirp, &granite.uri()),
        &machine(),
        &presenting_grant(),
    )
    .await;
    assert_eq!(got.unwrap_err(), Refusal::Denied(Denied::WrongPlane));
}

#[tokio::test]
async fn a_prod_grant_does_not_authorize_a_test_plane_request() {
    let chirp = chirp().await;
    let granite = granite(
        200,
        serde_json::json!({ "approved": true, "grant": grant_json("Prod".into()) }),
    )
    .await;
    let who = Authenticated {
        plane: Plane::Test {
            tenant: "acme".to_owned(),
        },
        ..machine()
    };
    let got = authorize(&authz(&chirp, &granite.uri()), &who, &presenting_grant()).await;
    assert_eq!(got.unwrap_err(), Refusal::Denied(Denied::WrongPlane));
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
