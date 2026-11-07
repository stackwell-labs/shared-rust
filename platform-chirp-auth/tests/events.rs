//! A deletion-webhook receiver's test, written the way a service writes it:
//! only `platform_chirp_auth` paths, no direct chirp-auth-client
//! (shared-rust#17).

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use platform_chirp_auth::testkit::{user_deleted_claims, JwksServer, TestSigningKey};
use platform_chirp_auth::{verify_chirp_event, ChirpAuthConfig, ChirpEvent, EventRejection};

const AUD: &str = "cs_test_receiver";
const KID: &str = "event_test_1";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

fn audiences(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[tokio::test]
async fn a_signed_user_deleted_event_verifies() {
    let key = TestSigningKey::new(KID);
    let server = JwksServer::start(vec![key.jwk()]).await;
    let config = ChirpAuthConfig::new(server.issuer(), AUD);
    let token = key.sign_event(&user_deleted_claims(
        server.issuer(),
        AUD,
        "sub_1",
        "evt_1",
        now(),
    ));

    let event = verify_chirp_event(&reqwest::Client::new(), &config, &token, &audiences(&[AUD]))
        .await
        .expect("verifies");

    let ChirpEvent::UserDeleted { sub, event_id, .. } = event;
    assert_eq!((sub.as_str(), event_id.as_str()), ("sub_1", "evt_1"));
}

#[tokio::test]
async fn an_event_signed_by_an_unpublished_key_is_unverified() {
    let server = JwksServer::start(vec![TestSigningKey::new(KID).jwk()]).await;
    let config = ChirpAuthConfig::new(server.issuer(), AUD);
    let forger = TestSigningKey::other(KID);
    let token = forger.sign_event(&user_deleted_claims(
        server.issuer(),
        AUD,
        "sub_1",
        "evt_1",
        now(),
    ));

    let rejection =
        verify_chirp_event(&reqwest::Client::new(), &config, &token, &audiences(&[AUD]))
            .await
            .expect_err("a key Chirp never published");

    assert!(
        matches!(rejection, EventRejection::Unverified(_)),
        "{rejection:?}"
    );
}
