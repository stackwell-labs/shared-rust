//! `Authenticator` against real RS256 tokens and the shared `testkit::Fixture`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::routing::get;
use axum::Router;
use http::{HeaderMap, Request, StatusCode};
use platform_chirp_auth::testkit::{
    mint_human_id_token, mint_machine_id_token, mint_test_id_token, Fixture,
};
use platform_chirp_auth::{
    env, AllowlistUnavailable, AuthFailure, Authenticator, Caller, Environment, MachineAllowlist,
    Machines, Policy, TestIdentities, TestPrincipal,
};
use tower::ServiceExt as _;

const RP: &str = "cs_test_rp";
const AGENT_CLIENT: &str = "cs_test_agent";

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn policy(issuer: &str, machines: Machines, test_identities: TestIdentities) -> Policy {
    Policy {
        issuer: issuer.to_owned(),
        humans: Some(set(&[RP])),
        machines,
        test_identities,
    }
}

fn humans_and_agent(issuer: &str) -> Authenticator {
    Authenticator::new(policy(issuer, Machines::Allow(set(&[AGENT_CLIENT])), TestIdentities::Reject))
        .expect("valid policy")
}

fn bearer(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    headers
}

#[tokio::test]
async fn a_person_and_an_allowed_agent_are_callers() {
    let fixture = Fixture::global();
    let auth = humans_and_agent(fixture.issuer());

    let person = auth
        .authenticate(&bearer(&mint_human_id_token(fixture.issuer(), RP, "sub_alice")))
        .await;
    assert_eq!(
        person,
        Ok(Caller::Human {
            sub: "sub_alice".into()
        })
    );
    assert_eq!(person.unwrap().environment(), Environment::Prod);

    let agent = auth
        .verify(&mint_machine_id_token(fixture.issuer(), AGENT_CLIENT, "agent_1", "sub_alice"))
        .await;
    assert_eq!(
        agent,
        Ok(Caller::Machine {
            sub: "agent_1".into(),
            owner_sub: "sub_alice".into(),
            client_id: AGENT_CLIENT.into()
        })
    );
    assert_eq!(agent.unwrap().environment(), Environment::Prod);
}

#[tokio::test]
async fn refusals_are_401_and_a_rejected_machine_is_its_own_verdict() {
    let fixture = Fixture::global();
    let auth = humans_and_agent(fixture.issuer());

    assert_eq!(auth.authenticate(&HeaderMap::new()).await, Err(AuthFailure::Unauthorized));
    assert_eq!(auth.verify("not.a.jwt").await, Err(AuthFailure::Unauthorized));
    // A person's token minted for another RP.
    let elsewhere = mint_human_id_token(fixture.issuer(), "cs_other_rp", "sub_alice");
    assert_eq!(auth.verify(&elsewhere).await, Err(AuthFailure::Unauthorized));
    // A verified agent from a client this service does not name: definitive.
    let stranger = mint_machine_id_token(fixture.issuer(), "cs_stranger", "agent_2", "sub_bob");
    assert_eq!(auth.verify(&stranger).await, Err(AuthFailure::RejectedMachine));
}

#[tokio::test]
async fn a_throttled_chirpauth_is_503_not_401() {
    let fixture = Fixture::global();
    let auth = humans_and_agent(fixture.throttled_issuer());
    let person = mint_human_id_token(fixture.throttled_issuer(), RP, "sub_alice");
    let agent = mint_machine_id_token(fixture.throttled_issuer(), AGENT_CLIENT, "agent_1", "sub_alice");
    assert_eq!(auth.verify(&person).await, Err(AuthFailure::Unavailable));
    assert_eq!(auth.verify(&agent).await, Err(AuthFailure::Unavailable));
}

#[tokio::test]
async fn an_unreachable_chirpauth_is_503() {
    // Bind then drop: nothing listens on the port any more.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let issuer = format!("http://127.0.0.1:{port}");
    let auth = humans_and_agent(&issuer);
    let person = mint_human_id_token(&issuer, RP, "sub_alice");
    assert_eq!(auth.verify(&person).await, Err(AuthFailure::Unavailable));
}

#[tokio::test]
async fn a_test_principal_is_refused_unless_the_policy_accepts_it() {
    let fixture = Fixture::global();
    let issuer = fixture.test_issuer("tenant1");
    let token = mint_test_id_token(&issuer, RP, "sub_tester");

    let refusing = Authenticator::new(policy(&issuer, Machines::None, TestIdentities::Reject)).unwrap();
    assert_eq!(refusing.verify(&token).await, Err(AuthFailure::Unauthorized));

    let accepting = Authenticator::new(policy(&issuer, Machines::None, TestIdentities::Accept)).unwrap();
    let caller = accepting.verify(&token).await;
    assert_eq!(
        caller,
        Ok(Caller::Test {
            tenant: "tenant1".into(),
            principal: TestPrincipal::Human {
                sub: "sub_tester".into()
            }
        })
    );
    assert_eq!(
        caller.unwrap().environment(),
        Environment::Test {
            tenant: "tenant1".into()
        }
    );

    // A production-keyset token never verifies at a test issuer, and the
    // reverse: the environment axis is the lib's.
    let prod_token = mint_human_id_token(&issuer, RP, "sub_alice");
    assert_eq!(accepting.verify(&prod_token).await, Err(AuthFailure::Unauthorized));
}

/// shared-rust#18: a machine token is a test principal when a test keyset
/// verified it. Under `Reject` it is refused like a test person; under
/// `Accept` it is a `Caller::Test`, never a `Caller::Machine`.
#[tokio::test]
async fn a_test_keyset_machine_is_a_test_principal() {
    let fixture = Fixture::global();
    let issuer = fixture.test_issuer("tenant1");
    let agent = mint_machine_id_token(&issuer, AGENT_CLIENT, "agent_t", "sub_tester");
    let machines = || Machines::Allow(set(&[AGENT_CLIENT]));

    let refusing = Authenticator::new(policy(&issuer, machines(), TestIdentities::Reject)).unwrap();
    assert_eq!(refusing.verify(&agent).await, Err(AuthFailure::Unauthorized));

    let accepting = Authenticator::new(policy(&issuer, machines(), TestIdentities::Accept)).unwrap();
    assert_eq!(
        accepting.verify(&agent).await,
        Ok(Caller::Test {
            tenant: "tenant1".into(),
            principal: TestPrincipal::Machine {
                sub: "agent_t".into(),
                owner_sub: "sub_tester".into(),
                client_id: AGENT_CLIENT.into(),
            }
        })
    );

    // The machine policy still applies to a test machine.
    let stranger = mint_machine_id_token(&issuer, "cs_stranger", "agent_s", "sub_tester");
    assert_eq!(accepting.verify(&stranger).await, Err(AuthFailure::RejectedMachine));
    let dynamic = |registry: Registry, test_identities| {
        Authenticator::new(policy(&issuer, Machines::Dynamic(Arc::new(registry)), test_identities))
            .unwrap()
    };
    let unlisted = dynamic(Registry(Ok(set(&["cs_someone_else"]))), TestIdentities::Accept);
    assert_eq!(unlisted.verify(&agent).await, Err(AuthFailure::RejectedMachine));
    let listed = dynamic(Registry(Ok(set(&[AGENT_CLIENT]))), TestIdentities::Accept);
    assert!(matches!(
        listed.verify(&agent).await,
        Ok(Caller::Test {
            principal: TestPrincipal::Machine { .. },
            ..
        })
    ));
    // Under Reject the allowlist is never asked: an outage there can't turn a
    // refused test token into a 503.
    let down = dynamic(Registry(Err(AllowlistUnavailable)), TestIdentities::Reject);
    assert_eq!(down.verify(&agent).await, Err(AuthFailure::Unauthorized));
}

#[tokio::test]
async fn machine_policies_any_and_none() {
    let fixture = Fixture::global();
    let agent = mint_machine_id_token(fixture.issuer(), "cs_whoever", "agent_3", "sub_carol");

    let any = Authenticator::new(policy(fixture.issuer(), Machines::Any, TestIdentities::Reject)).unwrap();
    assert!(matches!(any.verify(&agent).await, Ok(Caller::Machine { .. })));

    let none = Authenticator::new(policy(fixture.issuer(), Machines::None, TestIdentities::Reject)).unwrap();
    assert_eq!(none.verify(&agent).await, Err(AuthFailure::Unauthorized));

    // Machine-only: no person's token verifies.
    let machine_only = Authenticator::new(Policy {
        humans: None,
        ..policy(fixture.issuer(), Machines::Any, TestIdentities::Reject)
    })
    .unwrap();
    let person = mint_human_id_token(fixture.issuer(), RP, "sub_alice");
    assert_eq!(machine_only.verify(&person).await, Err(AuthFailure::Unauthorized));
    assert!(matches!(machine_only.verify(&agent).await, Ok(Caller::Machine { .. })));
}

struct Registry(Result<BTreeSet<String>, AllowlistUnavailable>);

#[async_trait::async_trait]
impl MachineAllowlist for Registry {
    async fn allows(&self, client_id: &str) -> Result<bool, AllowlistUnavailable> {
        self.0.as_ref().map(|set| set.contains(client_id)).map_err(|error| *error)
    }
}

#[tokio::test]
async fn a_dynamic_allowlist_is_consulted_and_its_outage_is_503() {
    let fixture = Fixture::global();
    let dynamic = |registry: Registry| {
        Authenticator::new(policy(
            fixture.issuer(),
            Machines::Dynamic(Arc::new(registry)),
            TestIdentities::Reject,
        ))
        .unwrap()
    };
    let agent = mint_machine_id_token(fixture.issuer(), AGENT_CLIENT, "agent_1", "sub_alice");

    let listed = dynamic(Registry(Ok(set(&[AGENT_CLIENT]))));
    assert!(matches!(listed.verify(&agent).await, Ok(Caller::Machine { .. })));

    let unlisted = dynamic(Registry(Ok(set(&["cs_someone_else"]))));
    assert_eq!(unlisted.verify(&agent).await, Err(AuthFailure::RejectedMachine));

    let down = dynamic(Registry(Err(AllowlistUnavailable)));
    assert_eq!(down.verify(&agent).await, Err(AuthFailure::Unavailable));
}

#[test]
fn policies_that_cannot_be_served_are_refused() {
    let issuer = "https://signin.example";
    let refused = |policy: Policy| Authenticator::new(policy).expect_err("must refuse");

    refused(Policy {
        issuer: "  ".into(),
        ..policy(issuer, Machines::None, TestIdentities::Reject)
    });
    refused(Policy {
        humans: Some(set(&[" "])),
        ..policy(issuer, Machines::None, TestIdentities::Reject)
    });
    refused(policy(issuer, Machines::Allow(BTreeSet::new()), TestIdentities::Reject));
    refused(Policy {
        humans: None,
        ..policy(issuer, Machines::None, TestIdentities::Reject)
    });
}

#[test]
fn env_readers_refuse_a_missing_or_blank_var() {
    // Unique prefix: no other test reads these.
    const PREFIX: &str = "PCA_TEST_ENV_READERS";
    // SAFETY: only this test touches PCA_TEST_ENV_READERS_* vars.
    unsafe {
        std::env::remove_var("PCA_TEST_ENV_READERS_CHIRP_ISSUER");
        std::env::set_var("PCA_TEST_ENV_READERS_HUMAN_AUDIENCES", " , ");
        std::env::set_var("PCA_TEST_ENV_READERS_MACHINE_CLIENTS", "cs_a, cs_b ,");
    }
    assert_eq!(
        env::issuer(PREFIX).unwrap_err().to_string(),
        "PCA_TEST_ENV_READERS_CHIRP_ISSUER is not set"
    );
    assert!(env::human_audiences(PREFIX).is_err());
    assert_eq!(env::machine_clients(PREFIX).unwrap(), set(&["cs_a", "cs_b"]));
    unsafe { std::env::set_var("PCA_TEST_ENV_READERS_CHIRP_ISSUER", "  ") };
    assert_eq!(
        env::issuer(PREFIX).unwrap_err().to_string(),
        "PCA_TEST_ENV_READERS_CHIRP_ISSUER is blank"
    );
}

#[derive(Clone)]
struct AppState {
    auth: Authenticator,
}

impl axum::extract::FromRef<AppState> for Authenticator {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

async fn whoami(caller: Caller, State(_): State<AppState>) -> String {
    caller.sub().to_owned()
}

async fn status_of(app: Router, token: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::get("/whoami");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app.oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn the_extractor_answers_200_401_and_503() {
    let fixture = Fixture::global();
    let app = |issuer: &str| {
        Router::new()
            .route("/whoami", get(whoami))
            .with_state(AppState {
                auth: humans_and_agent(issuer),
            })
    };

    let token = mint_human_id_token(fixture.issuer(), RP, "sub_alice");
    assert_eq!(
        status_of(app(fixture.issuer()), Some(&token)).await,
        (StatusCode::OK, "sub_alice".to_owned())
    );
    assert_eq!(status_of(app(fixture.issuer()), None).await.0, StatusCode::UNAUTHORIZED);

    let token = mint_human_id_token(fixture.throttled_issuer(), RP, "sub_alice");
    assert_eq!(
        status_of(app(fixture.throttled_issuer()), Some(&token)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}
