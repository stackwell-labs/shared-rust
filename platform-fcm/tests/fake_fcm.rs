//! The real sender against the testkit's fake FCM: the token mint (with a
//! verified RS256 assertion), the cache, the send, and the reading of FCM's
//! answer.

use std::collections::HashMap;
use std::time::Duration;

use platform_fcm::testkit::FakeFcm;
use platform_fcm::{Delivery, FcmSender, HttpV1Sender, Message, Notification, Priority};

fn approval() -> Message {
    Message {
        priority: Priority::High(Notification {
            title: "Approval requested".into(),
            body: "Open Granite to review".into(),
            channel_id: Some("approvals".into()),
        }),
        data: HashMap::from([("request_id".to_owned(), "abc".to_owned())]),
        ttl: Duration::from_secs(600),
    }
}

#[tokio::test]
async fn a_send_mints_a_verified_token_and_reports_each_device() {
    let fcm = FakeFcm::start().await;
    fcm.unregister("dead-device");
    let sender = fcm.sender();

    let first = sender.send("live-device", &approval()).await;
    assert!(
        matches!(&first, Delivery::Accepted { message_id } if message_id.starts_with("projects/fake-project/messages/")),
        "{first:?}"
    );
    assert_eq!(
        sender.send("dead-device", &approval()).await,
        Delivery::Unregistered {
            reason: "FCM 404 NOT_FOUND UNREGISTERED: Requested entity was not found.".into()
        }
    );
    // One mint served both sends.
    assert_eq!(fcm.tokens_issued(), 1);

    let sent = fcm.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].token, "live-device");
    let m = &sent[0].body;
    assert_eq!(m["android"]["priority"], "HIGH");
    assert_eq!(m["android"]["ttl"], "600s");
    assert_eq!(m["android"]["notification"]["channel_id"], "approvals");
    assert_eq!(m["notification"]["title"], "Approval requested");
    assert_eq!(m["data"]["request_id"], "abc");
}

#[tokio::test]
async fn a_refused_send_is_a_failure_with_fcms_reason() {
    let fcm = FakeFcm::start().await;
    fcm.respond(
        "bad-payload",
        400,
        serde_json::json!({ "error": { "status": "INVALID_ARGUMENT",
            "message": "Invalid data payload key: from",
            "details": [{ "errorCode": "INVALID_ARGUMENT" }] } }),
    );
    assert_eq!(
        fcm.sender().send("bad-payload", &approval()).await,
        Delivery::Failed {
            reason: "FCM 400 INVALID_ARGUMENT INVALID_ARGUMENT: Invalid data payload key: from"
                .into()
        }
    );
}

/// A token within a minute of expiry is not reused.
#[tokio::test]
async fn a_token_near_expiry_is_minted_again() {
    let fcm = FakeFcm::start().await;
    fcm.set_token_lifetime_secs(30);
    let sender = fcm.sender();
    for _ in 0..2 {
        let d = sender.send("live-device", &approval()).await;
        assert!(matches!(d, Delivery::Accepted { .. }), "{d:?}");
    }
    assert_eq!(fcm.tokens_issued(), 2);
}

/// An assertion the token endpoint refuses (here: signed for a different
/// account) makes the push a failure, not a panic or an error into the caller.
#[tokio::test]
async fn a_mint_the_token_endpoint_refuses_is_a_failure() {
    let fcm = FakeFcm::start().await;
    let mut json: serde_json::Value = serde_json::from_str(&fcm.service_account_json()).unwrap();
    json["client_email"] = "someone-else@example.iam.gserviceaccount.com".into();
    let sender = HttpV1Sender::from_service_account_json(&json.to_string()).unwrap();
    match sender.send("live-device", &approval()).await {
        Delivery::Failed { reason } => {
            assert!(reason.starts_with("access-token mint failed"), "{reason}");
            assert!(reason.contains("invalid_grant"), "{reason}");
        }
        other => panic!("expected a mint failure, got {other:?}"),
    }
    assert_eq!(fcm.tokens_issued(), 0);
}

/// An unreachable FCM is a failure within the timeout, not a hang.
#[tokio::test]
async fn an_unreachable_token_endpoint_is_a_failure() {
    let fcm = FakeFcm::start().await;
    let mut json: serde_json::Value = serde_json::from_str(&fcm.service_account_json()).unwrap();
    json["token_uri"] = "http://127.0.0.1:1/token".into();
    let sender = HttpV1Sender::from_service_account_json(&json.to_string()).unwrap();
    assert!(matches!(
        sender.send("live-device", &approval()).await,
        Delivery::Failed { .. }
    ));
}
