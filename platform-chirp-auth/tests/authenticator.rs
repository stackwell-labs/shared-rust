//! `Authenticator` against real RS256 tokens and the shared `testkit::Fixture`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::routing::get;
use axum::Router;
use http::{HeaderMap, Request, StatusCode};
use platform_chirp_auth::mint::{MachineTokenMinter, MintConfig};
use platform_chirp_auth::testkit::{
    mint_human_id_token, mint_machine_id_token, mint_test_id_token, root_for_sub, Fixture,
    TestSigningKey, TEST_KID,
};
use platform_chirp_auth::{
    env, environment_from_issuer, ActingFor, AllowlistUnavailable, AuthFailure, Authenticated,
    Authenticator, Caller, MachineAllowlist, Machines, PersonId, Plane, Policy, RootId,
    RootResolver, ID_TOKEN_TYP,
};
use tower::ServiceExt as _;

const RP: &str = "cs_test_rp";
const AGENT_CLIENT: &str = "cs_test_agent";

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// A policy for `issuer`, with the fixture's root resolver when the issuer is
/// production's (a test tenant's issuer takes none).
fn policy(issuer: &str, machines: Machines, test_tenants: Option<&[&str]>) -> Policy {
    Policy {
        issuer: issuer.to_owned(),
        humans: Some(set(&[RP])),
        machines,
        test_tenants: test_tenants.map(set),
        resolver: prod_resolver(issuer),
    }
}

fn prod_resolver(issuer: &str) -> Option<RootResolver> {
    (environment_from_issuer(issuer) == Plane::Prod).then(|| Fixture::global().root_resolver())
}

fn root(id: &str) -> PersonId {
    PersonId::Root(RootId::parse(id).unwrap())
}

fn test_person(tenant: &str, sub: &str) -> PersonId {
    PersonId::Test {
        tenant: tenant.to_owned(),
        sub: sub.to_owned(),
    }
}

fn humans_and_agent(issuer: &str) -> Authenticator {
    Authenticator::new(policy(issuer, Machines::Allow(set(&[AGENT_CLIENT])), None))
        .expect("valid policy")
}

fn test_plane(tenant: &str) -> Plane {
    Plane::Test {
        tenant: tenant.to_owned(),
    }
}

/// `caller` verified on `plane`, as the person the fixture's resolver gives
/// them (a machine: its owner).
fn on(plane: Plane, caller: Caller) -> Result<Authenticated, AuthFailure> {
    let sub = match &caller {
        Caller::Human { sub, .. } => sub,
        Caller::Machine { owner_sub, .. } => owner_sub,
    };
    let person = match &plane {
        Plane::Prod => root_for_sub(sub).map(|r| root(&r)),
        Plane::Test { tenant } => Some(test_person(tenant, sub)),
    };
    Ok(Authenticated {
        caller,
        plane,
        person,
    })
}

fn human(sub: &str) -> Caller {
    human_at(sub, RP)
}

fn human_at(sub: &str, client_id: &str) -> Caller {
    Caller::Human {
        sub: sub.to_owned(),
        client_id: client_id.to_owned(),
    }
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

    assert_eq!(auth.planes(), [Plane::Prod]);

    let person = auth
        .authenticate(&bearer(&mint_human_id_token(
            fixture.issuer(),
            RP,
            "sub_alice",
        )))
        .await;
    assert_eq!(person, on(Plane::Prod, human("sub_alice")));

    let agent = auth
        .verify(&mint_machine_id_token(
            fixture.issuer(),
            AGENT_CLIENT,
            "agent_1",
            "sub_alice",
        ))
        .await;
    assert_eq!(
        agent,
        on(
            Plane::Prod,
            Caller::Machine {
                sub: "agent_1".into(),
                owner_sub: "sub_alice".into(),
                client_id: AGENT_CLIENT.into()
            }
        )
    );
}

#[tokio::test]
async fn refusals_are_401_and_a_rejected_machine_is_its_own_verdict() {
    let fixture = Fixture::global();
    let auth = humans_and_agent(fixture.issuer());

    assert_eq!(
        auth.authenticate(&HeaderMap::new()).await,
        Err(AuthFailure::Unauthorized)
    );
    assert_eq!(
        auth.verify("not.a.jwt").await,
        Err(AuthFailure::Unauthorized)
    );
    // A person's token minted for another RP.
    let elsewhere = mint_human_id_token(fixture.issuer(), "cs_other_rp", "sub_alice");
    assert_eq!(
        auth.verify(&elsewhere).await,
        Err(AuthFailure::Unauthorized)
    );
    // A verified agent from a client this service does not name: definitive.
    let stranger = mint_machine_id_token(fixture.issuer(), "cs_stranger", "agent_2", "sub_bob");
    assert_eq!(
        auth.verify(&stranger).await,
        Err(AuthFailure::RejectedMachine)
    );
}

/// shared-rust#27: a service with several Chirp clients learns which one a
/// person's token was minted for. Chirp's pairwise `sub` is per (person,
/// client), so the same `sub` at two clients is two people, on either plane.
#[tokio::test]
async fn a_person_carries_the_client_their_token_was_for() {
    let fixture = Fixture::global();
    let tenant = fixture.test_issuer("tenant1");
    let auth = Authenticator::new(Policy {
        issuer: fixture.issuer().to_owned(),
        humans: Some(set(&[RP, "cs_test_rp2"])),
        machines: Machines::None,
        test_tenants: Some(set(&["tenant1"])),
        resolver: Some(fixture.root_resolver()),
    })
    .unwrap();

    for (client, sub) in [(RP, "sub_alice"), ("cs_test_rp2", "sub_alice")] {
        assert_eq!(
            auth.verify(&mint_human_id_token(fixture.issuer(), client, sub))
                .await,
            on(Plane::Prod, human_at(sub, client))
        );
        assert_eq!(
            auth.verify(&mint_test_id_token(&tenant, client, sub)).await,
            on(test_plane("tenant1"), human_at(sub, client))
        );
    }
}

/// A person's token naming two of the service's clients is refused: whose
/// pairwise `sub` it is can't be told (shared-rust#27). chirp-auth-client
/// applies the rule now (chirp-auth#186); this pins that it still reaches
/// the service as a 401.
#[tokio::test]
async fn a_person_naming_two_accepted_clients_is_401() {
    let fixture = Fixture::global();
    let auth = Authenticator::new(Policy {
        issuer: fixture.issuer().to_owned(),
        humans: Some(set(&[RP, "cs_test_rp2"])),
        machines: Machines::None,
        test_tenants: None,
        resolver: Some(fixture.root_resolver()),
    })
    .unwrap();
    let mint = |aud: serde_json::Value| {
        TestSigningKey::new(TEST_KID).sign(
            &serde_json::json!({"alg": "RS256", "typ": ID_TOKEN_TYP, "kid": TEST_KID}),
            &serde_json::json!({
                "iss": fixture.issuer(),
                "sub": "sub_alice",
                "aud": aud,
                "exp": 4_102_444_800_i64, // 2100-01-01
            }),
        )
    };

    assert_eq!(
        auth.verify(&mint(serde_json::json!([RP, "cs_test_rp2"])))
            .await,
        Err(AuthFailure::Unauthorized)
    );
    // One accepted client among others is that client.
    assert_eq!(
        auth.verify(&mint(serde_json::json!(["cs_other", RP])))
            .await,
        on(Plane::Prod, human_at("sub_alice", RP))
    );
}

#[tokio::test]
async fn a_throttled_chirpauth_is_503_not_401() {
    let fixture = Fixture::global();
    let auth = humans_and_agent(fixture.throttled_issuer());
    let person = mint_human_id_token(fixture.throttled_issuer(), RP, "sub_alice");
    let agent = mint_machine_id_token(
        fixture.throttled_issuer(),
        AGENT_CLIENT,
        "agent_1",
        "sub_alice",
    );
    assert_eq!(auth.verify(&person).await, Err(AuthFailure::Unavailable));
    assert_eq!(auth.verify(&agent).await, Err(AuthFailure::Unavailable));
}

#[tokio::test]
async fn an_unreachable_chirpauth_is_503() {
    // Bind then drop: nothing listens on the port any more.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let issuer = format!("http://127.0.0.1:{port}");
    let auth = humans_and_agent(&issuer);
    let person = mint_human_id_token(&issuer, RP, "sub_alice");
    assert_eq!(auth.verify(&person).await, Err(AuthFailure::Unavailable));
}

/// shared-rust#19: one deployment serves production and the test tenants it
/// declares, each on its own plane. Any other tenant's token is a 401.
#[tokio::test]
async fn a_test_tenant_is_served_only_once_declared() {
    let fixture = Fixture::global();
    let tester = mint_test_id_token(&fixture.test_issuer("tenant1"), RP, "sub_tester");
    let undeclared = mint_test_id_token(&fixture.test_issuer("tenant2"), RP, "sub_tester");
    let person = mint_human_id_token(fixture.issuer(), RP, "sub_alice");

    let prod_only = Authenticator::new(policy(fixture.issuer(), Machines::None, None)).unwrap();
    assert_eq!(
        prod_only.verify(&tester).await,
        Err(AuthFailure::Unauthorized)
    );

    let both =
        Authenticator::new(policy(fixture.issuer(), Machines::None, Some(&["tenant1"]))).unwrap();
    assert_eq!(both.planes(), [Plane::Prod, test_plane("tenant1")]);
    assert_eq!(
        both.verify(&tester).await,
        on(test_plane("tenant1"), human("sub_tester"))
    );
    assert_eq!(
        both.verify(&person).await,
        on(Plane::Prod, human("sub_alice"))
    );
    assert_eq!(
        both.verify(&undeclared).await,
        Err(AuthFailure::Unauthorized)
    );
}

/// The issue's done-when: ChirpAuth lets every tenant mint any `test:` sub, so
/// two tenants' `test:alice` are the same caller on different planes.
#[tokio::test]
async fn two_tenants_test_alice_resolve_to_different_planes() {
    let fixture = Fixture::global();
    let auth = Authenticator::new(policy(
        fixture.issuer(),
        Machines::None,
        Some(&["acme", "globex"]),
    ))
    .unwrap();
    let alice_at =
        |tenant: &str| mint_test_id_token(&fixture.test_issuer(tenant), RP, "test:alice");

    let acme = auth.verify(&alice_at("acme")).await.unwrap();
    let globex = auth.verify(&alice_at("globex")).await.unwrap();
    assert_eq!(acme.caller, globex.caller);
    assert_eq!(acme.plane, test_plane("acme"));
    assert_eq!(globex.plane, test_plane("globex"));
    // And two people: the tenant is part of a test PersonId.
    assert_eq!(acme.person, Some(test_person("acme", "test:alice")));
    assert_ne!(acme.person, globex.person);
}

/// A deployment whose issuer is one test tenant's serves only that plane: its
/// environment comes from the issuer at boot.
#[tokio::test]
async fn a_test_issuer_deployment_serves_only_its_tenant() {
    let fixture = Fixture::global();
    let issuer = fixture.test_issuer("tenant1");
    let auth = Authenticator::new(policy(&issuer, Machines::None, None)).unwrap();
    assert_eq!(auth.planes(), [test_plane("tenant1")]);

    let tester = mint_test_id_token(&issuer, RP, "sub_tester");
    assert_eq!(
        auth.verify(&tester).await,
        on(test_plane("tenant1"), human("sub_tester"))
    );
    // A production-keyset token never verifies at a test issuer, and the
    // reverse: the environment axis is the lib's.
    let prod_shaped = mint_human_id_token(&issuer, RP, "sub_alice");
    assert_eq!(
        auth.verify(&prod_shaped).await,
        Err(AuthFailure::Unauthorized)
    );
    let prod = mint_human_id_token(fixture.issuer(), RP, "sub_alice");
    assert_eq!(auth.verify(&prod).await, Err(AuthFailure::Unauthorized));
}

/// shared-rust#18: a machine token is on a test plane when a test keyset
/// verified it. Undeclared, it is refused like a test person; declared, it is
/// a `Caller::Machine` on that tenant's plane, under the same machine policy.
#[tokio::test]
async fn a_test_keyset_machine_is_on_its_tenants_plane() {
    let fixture = Fixture::global();
    let agent = mint_machine_id_token(
        &fixture.test_issuer("tenant1"),
        AGENT_CLIENT,
        "agent_t",
        "sub_tester",
    );
    let machines = || Machines::Allow(set(&[AGENT_CLIENT]));
    let tenant1: Option<&[&str]> = Some(&["tenant1"]);

    let refusing = Authenticator::new(policy(fixture.issuer(), machines(), None)).unwrap();
    assert_eq!(
        refusing.verify(&agent).await,
        Err(AuthFailure::Unauthorized)
    );

    let accepting = Authenticator::new(policy(fixture.issuer(), machines(), tenant1)).unwrap();
    assert_eq!(
        accepting.verify(&agent).await,
        on(
            test_plane("tenant1"),
            Caller::Machine {
                sub: "agent_t".into(),
                owner_sub: "sub_tester".into(),
                client_id: AGENT_CLIENT.into(),
            }
        )
    );

    // The machine policy still applies to a test machine.
    let stranger = mint_machine_id_token(
        &fixture.test_issuer("tenant1"),
        "cs_stranger",
        "agent_s",
        "sub_tester",
    );
    assert_eq!(
        accepting.verify(&stranger).await,
        Err(AuthFailure::RejectedMachine)
    );
    let dynamic = |registry: Registry, test_tenants| {
        Authenticator::new(policy(
            fixture.issuer(),
            Machines::Dynamic(Arc::new(registry)),
            test_tenants,
        ))
        .unwrap()
    };
    let unlisted = dynamic(Registry(Ok(set(&["cs_someone_else"]))), tenant1);
    assert_eq!(
        unlisted.verify(&agent).await,
        Err(AuthFailure::RejectedMachine)
    );
    let listed = dynamic(Registry(Ok(set(&[AGENT_CLIENT]))), tenant1);
    assert!(matches!(
        listed.verify(&agent).await,
        Ok(Authenticated {
            caller: Caller::Machine { .. },
            plane: Plane::Test { .. },
            ..
        })
    ));
    // Undeclared, the allowlist is never asked: an outage there can't turn a
    // refused test token into a 503.
    let down = dynamic(Registry(Err(AllowlistUnavailable)), None);
    assert_eq!(down.verify(&agent).await, Err(AuthFailure::Unauthorized));
}

#[tokio::test]
async fn machine_policies_any_and_none() {
    let fixture = Fixture::global();
    let agent = mint_machine_id_token(fixture.issuer(), "cs_whoever", "agent_3", "sub_carol");

    let any = Authenticator::new(policy(fixture.issuer(), Machines::Any, None)).unwrap();
    assert!(matches!(
        any.verify(&agent).await,
        Ok(Authenticated {
            caller: Caller::Machine { .. },
            ..
        })
    ));

    let none = Authenticator::new(policy(fixture.issuer(), Machines::None, None)).unwrap();
    assert_eq!(none.verify(&agent).await, Err(AuthFailure::Unauthorized));

    // Machine-only: no person's token verifies.
    let machine_only = Authenticator::new(Policy {
        humans: None,
        ..policy(fixture.issuer(), Machines::Any, None)
    })
    .unwrap();
    let person = mint_human_id_token(fixture.issuer(), RP, "sub_alice");
    assert_eq!(
        machine_only.verify(&person).await,
        Err(AuthFailure::Unauthorized)
    );
    assert!(matches!(
        machine_only.verify(&agent).await,
        Ok(Authenticated {
            caller: Caller::Machine { .. },
            ..
        })
    ));
}

struct Registry(Result<BTreeSet<String>, AllowlistUnavailable>);

#[async_trait::async_trait]
impl MachineAllowlist for Registry {
    async fn allows(&self, client_id: &str) -> Result<bool, AllowlistUnavailable> {
        self.0
            .as_ref()
            .map(|set| set.contains(client_id))
            .map_err(|error| *error)
    }
}

#[tokio::test]
async fn a_dynamic_allowlist_is_consulted_and_its_outage_is_503() {
    let fixture = Fixture::global();
    let dynamic = |registry: Registry| {
        Authenticator::new(policy(
            fixture.issuer(),
            Machines::Dynamic(Arc::new(registry)),
            None,
        ))
        .unwrap()
    };
    let agent = mint_machine_id_token(fixture.issuer(), AGENT_CLIENT, "agent_1", "sub_alice");

    let listed = dynamic(Registry(Ok(set(&[AGENT_CLIENT]))));
    assert!(matches!(
        listed.verify(&agent).await,
        Ok(Authenticated {
            caller: Caller::Machine { .. },
            ..
        })
    ));

    let unlisted = dynamic(Registry(Ok(set(&["cs_someone_else"]))));
    assert_eq!(
        unlisted.verify(&agent).await,
        Err(AuthFailure::RejectedMachine)
    );

    let down = dynamic(Registry(Err(AllowlistUnavailable)));
    assert_eq!(down.verify(&agent).await, Err(AuthFailure::Unavailable));
}

#[test]
fn policies_that_cannot_be_served_are_refused() {
    let issuer = "https://signin.example";
    let refused = |policy: Policy| Authenticator::new(policy).expect_err("must refuse");

    refused(Policy {
        issuer: "  ".into(),
        ..policy(issuer, Machines::None, None)
    });
    refused(Policy {
        humans: Some(set(&[" "])),
        ..policy(issuer, Machines::None, None)
    });
    refused(policy(issuer, Machines::Allow(BTreeSet::new()), None));
    refused(policy(issuer, Machines::None, Some(&[" "])));
    refused(policy(issuer, Machines::None, Some(&["a/b"])));
    // A test issuer has no test tenants of its own.
    refused(policy(
        "https://signin.example/test/t1",
        Machines::None,
        Some(&["t2"]),
    ));
    refused(Policy {
        humans: None,
        ..policy(issuer, Machines::None, None)
    });
    // shared-rust#41: production callers are always resolved, so a production
    // issuer without a resolver stops boot, not the first request.
    refused(Policy {
        resolver: None,
        ..policy(issuer, Machines::None, None)
    });
    refused(Policy {
        resolver: None,
        ..policy(issuer, Machines::None, Some(&["t1"]))
    });
    // A test tenant's issuer resolves nobody, so a resolver there is a mistake.
    refused(Policy {
        resolver: Some(Fixture::global().root_resolver()),
        ..policy("https://signin.example/test/t1", Machines::None, None)
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
    assert_eq!(
        env::machine_clients(PREFIX).unwrap(),
        set(&["cs_a", "cs_b"])
    );
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

async fn whoami(
    Authenticated {
        caller,
        plane,
        person,
    }: Authenticated,
    State(_): State<AppState>,
) -> String {
    let person = person.map_or("nobody".to_owned(), |p| p.to_string());
    format!("{} as {person} on {plane}", caller.sub())
}

async fn status_of(app: Router, token: Option<&str>) -> (StatusCode, String) {
    let mut request = Request::get("/whoami");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap();
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
        (StatusCode::OK, "sub_alice as usr_alice on prod".to_owned())
    );
    assert_eq!(
        status_of(app(fixture.issuer()), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    // A verified person chirp has no account for.
    let token = mint_human_id_token(fixture.issuer(), RP, "sub_noroot_gone");
    assert_eq!(
        status_of(app(fixture.issuer()), Some(&token)).await.0,
        StatusCode::UNAUTHORIZED
    );

    let token = mint_human_id_token(fixture.throttled_issuer(), RP, "sub_alice");
    assert_eq!(
        status_of(app(fixture.throttled_issuer()), Some(&token))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

// ---- PersonId (shared-rust#41) ----------------------------------------------

/// One person is one `PersonId::Root` whichever client's pairwise sub reached
/// the service; a test person is their sub on their tenant's plane, never
/// resolved.
#[tokio::test]
async fn a_person_is_their_root_whichever_client_their_sub_is_for() {
    let fixture = Fixture::global();
    let auth = Authenticator::new(Policy {
        humans: Some(set(&[RP, "cs_test_rp2"])),
        ..policy(fixture.issuer(), Machines::None, Some(&["tenant1"]))
    })
    .unwrap();

    let at_rp = auth
        .verify(&mint_human_id_token(fixture.issuer(), RP, "sub_alice"))
        .await
        .unwrap();
    let at_rp2 = auth
        .verify(&mint_human_id_token(
            fixture.issuer(),
            "cs_test_rp2",
            "sub_alice.rp2",
        ))
        .await
        .unwrap();
    assert_ne!(at_rp.caller, at_rp2.caller);
    assert_eq!(at_rp.person, Some(root("usr_alice")));
    assert_eq!(at_rp.person, at_rp2.person);

    let tester = auth
        .verify(&mint_test_id_token(
            &fixture.test_issuer("tenant1"),
            RP,
            "test:alice",
        ))
        .await
        .unwrap();
    assert_eq!(tester.person, Some(test_person("tenant1", "test:alice")));
    assert_eq!(tester.person.as_ref().unwrap().as_str(), "test:alice");
}

/// A machine's person is its owner's. A machine no person owns (chirp
/// resolves a system-owned client's owner to no account) is admitted as
/// acting for nobody; a person chirp has no account for is refused.
#[tokio::test]
async fn a_machine_is_its_owners_person_and_a_rootless_person_is_refused() {
    let fixture = Fixture::global();
    let auth = humans_and_agent(fixture.issuer());

    let owned = auth
        .verify(&mint_machine_id_token(
            fixture.issuer(),
            AGENT_CLIENT,
            "agent_1",
            "sub_bob.cli",
        ))
        .await
        .unwrap();
    assert_eq!(owned.person, Some(root("usr_bob")));

    let system = auth
        .verify(&mint_machine_id_token(
            fixture.issuer(),
            AGENT_CLIENT,
            "agent_sys",
            "sub_noroot_system",
        ))
        .await
        .unwrap();
    assert!(matches!(system.caller, Caller::Machine { .. }));
    assert_eq!(system.person, None);

    assert_eq!(
        auth.verify(&mint_human_id_token(
            fixture.issuer(),
            RP,
            "sub_noroot_gone"
        ))
        .await,
        Err(AuthFailure::NoPerson)
    );
    // A production token whose sub is not a pairwise sub names nobody chirp
    // could resolve.
    assert_eq!(
        auth.verify(&mint_human_id_token(fixture.issuer(), RP, "usr_alice"))
            .await,
        Err(AuthFailure::Unauthorized)
    );
}

/// The resolver's outage is a 503, for a person and for a machine (whose
/// owner might be a person): never "no root".
#[tokio::test]
async fn a_resolver_outage_is_503() {
    let fixture = Fixture::global();
    let auth = Authenticator::new(Policy {
        resolver: Some(fixture.throttled_root_resolver()),
        ..policy(
            fixture.issuer(),
            Machines::Allow(set(&[AGENT_CLIENT])),
            Some(&["tenant1"]),
        )
    })
    .unwrap();
    assert_eq!(
        auth.verify(&mint_human_id_token(fixture.issuer(), RP, "sub_alice"))
            .await,
        Err(AuthFailure::Unavailable)
    );
    assert_eq!(
        auth.verify(&mint_machine_id_token(
            fixture.issuer(),
            AGENT_CLIENT,
            "agent_1",
            "sub_noroot_system",
        ))
        .await,
        Err(AuthFailure::Unavailable)
    );
    // A test person is never resolved, so the outage does not reach them.
    let tester = mint_test_id_token(&fixture.test_issuer("tenant1"), RP, "test:alice");
    assert!(auth.verify(&tester).await.is_ok());
}

/// A chirp stand-in whose `/token` mints a token, for a resolver test that
/// needs to count or shape root-for-sub answers.
async fn chirp_control() -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(
            serde_json::json!({ "id_token": "machine.id.token", "expires_in": 3600 }),
        ))
        .mount(&server)
        .await;
    server
}

async fn answer_root(
    server: &wiremock::MockServer,
    sub: &str,
    status: u16,
    body: serde_json::Value,
    times: u64,
) {
    use wiremock::matchers::{body_json, method, path};
    wiremock::Mock::given(method("POST"))
        .and(path("/control/root-for-sub"))
        .and(body_json(serde_json::json!({ "sub": sub })))
        .respond_with(wiremock::ResponseTemplate::new(status).set_body_json(body))
        .expect(times)
        .mount(server)
        .await;
}

fn resolver_at(server: &wiremock::MockServer) -> RootResolver {
    let minter = MachineTokenMinter::new(MintConfig::new(server.uri(), "cs_svc", "secret"));
    RootResolver::new(&server.uri(), Arc::new(minter), reqwest::Client::new()).unwrap()
}

/// Only chirp's `no_root_for_sub` means "no root": any other 404 (a chirp
/// with the route off) is an outage, so a misconfiguration is loud.
#[tokio::test]
async fn only_no_root_for_sub_is_no_root() {
    let fixture = Fixture::global();
    let chirp = chirp_control().await;
    answer_root(
        &chirp,
        "sub_alice",
        404,
        serde_json::json!({ "error": "not_found" }),
        1,
    )
    .await;
    answer_root(
        &chirp,
        "sub_gone",
        404,
        serde_json::json!({ "error": "no_root_for_sub" }),
        1,
    )
    .await;
    let auth = Authenticator::new(Policy {
        resolver: Some(resolver_at(&chirp)),
        ..policy(fixture.issuer(), Machines::None, None)
    })
    .unwrap();
    assert_eq!(
        auth.verify(&mint_human_id_token(fixture.issuer(), RP, "sub_alice"))
            .await,
        Err(AuthFailure::Unavailable)
    );
    assert_eq!(
        auth.verify(&mint_human_id_token(fixture.issuer(), RP, "sub_gone"))
            .await,
        Err(AuthFailure::NoPerson)
    );
}

/// One cached resolver: a person's root is asked for once per instance, and
/// a system machine's "no root" is kept too, so neither costs a chirp call
/// per request. Clones of the Authenticator share the cache.
#[tokio::test]
async fn the_resolver_is_asked_once_per_sub() {
    let fixture = Fixture::global();
    let chirp = chirp_control().await;
    answer_root(
        &chirp,
        "sub_alice",
        200,
        serde_json::json!({ "root_id": "usr_alice", "current": true }),
        1,
    )
    .await;
    answer_root(
        &chirp,
        "sub_system",
        404,
        serde_json::json!({ "error": "no_root_for_sub" }),
        1,
    )
    .await;
    let auth = Authenticator::new(Policy {
        resolver: Some(resolver_at(&chirp)),
        ..policy(
            fixture.issuer(),
            Machines::Allow(set(&[AGENT_CLIENT])),
            None,
        )
    })
    .unwrap();
    let person = mint_human_id_token(fixture.issuer(), RP, "sub_alice");
    let system = mint_machine_id_token(fixture.issuer(), AGENT_CLIENT, "agent_s", "sub_system");
    for auth in [auth.clone(), auth] {
        assert_eq!(
            auth.verify(&person).await.unwrap().person,
            Some(root("usr_alice"))
        );
        assert_eq!(auth.verify(&system).await.unwrap().person, None);
    }
    // `expect(1)` on each answer is checked when `chirp` drops.
}

fn with_user_id(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-user-id", value.parse().unwrap());
    headers
}

/// `x-user-id` becomes an `ActingFor`, resolved on the request's plane the
/// same way the caller is.
#[tokio::test]
async fn x_user_id_is_acting_for_a_person() {
    let fixture = Fixture::global();
    let auth = Authenticator::new(policy(
        fixture.issuer(),
        Machines::Allow(set(&[AGENT_CLIENT])),
        Some(&["tenant1"]),
    ))
    .unwrap();
    let agent = auth
        .verify(&mint_machine_id_token(
            fixture.issuer(),
            AGENT_CLIENT,
            "agent_1",
            "sub_noroot_system",
        ))
        .await
        .unwrap();

    assert_eq!(auth.acting_for(&agent, &HeaderMap::new()).await, Ok(None));
    assert_eq!(
        auth.acting_for(&agent, &with_user_id("sub_carol.granite"))
            .await,
        Ok(Some(ActingFor(root("usr_carol"))))
    );
    // A root on the wire is not a pairwise sub: refused, never trusted as is.
    assert_eq!(
        auth.acting_for(&agent, &with_user_id("usr_carol")).await,
        Err(AuthFailure::Unauthorized)
    );
    assert_eq!(
        auth.acting_for(&agent, &with_user_id("sub_noroot_x")).await,
        Err(AuthFailure::NoPerson)
    );

    let test_agent = auth
        .verify(&mint_machine_id_token(
            &fixture.test_issuer("tenant1"),
            AGENT_CLIENT,
            "agent_t",
            "test:owner",
        ))
        .await
        .unwrap();
    assert_eq!(
        auth.acting_for(&test_agent, &with_user_id("test:carol"))
            .await,
        Ok(Some(ActingFor(test_person("tenant1", "test:carol"))))
    );
    assert_eq!(
        auth.acting_for(&test_agent, &with_user_id("test: carol"))
            .await,
        Err(AuthFailure::Unauthorized)
    );

    let down = Authenticator::new(Policy {
        resolver: Some(fixture.throttled_root_resolver()),
        ..policy(fixture.issuer(), Machines::Any, None)
    })
    .unwrap();
    assert_eq!(
        down.acting_for(&agent, &with_user_id("sub_carol")).await,
        Err(AuthFailure::Unavailable)
    );
}
