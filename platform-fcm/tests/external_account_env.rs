//! `HttpV1Sender::from_external_account_json`, the public keyless
//! constructor, reading the AWS role credentials from the environment as it
//! does on Lambda. It sends nothing: its sender points at the real FCM. A test binary of its own: it sets process environment
//! variables, so nothing else may run beside it. One test, so its steps
//! never race each other either.

use platform_fcm::testkit::{self, FakeFcm};
use platform_fcm::HttpV1Sender;

const VARS: [(&str, &str); 4] = [
    ("AWS_ACCESS_KEY_ID", testkit::AWS_ACCESS_KEY_ID),
    ("AWS_SECRET_ACCESS_KEY", testkit::AWS_SECRET_ACCESS_KEY),
    ("AWS_SESSION_TOKEN", testkit::AWS_SESSION_TOKEN),
    ("AWS_REGION", testkit::AWS_REGION),
];

#[tokio::test]
async fn the_public_constructor_reads_the_lambda_environment() {
    let fcm = FakeFcm::start().await;
    let config = fcm.external_account_json();

    // Without the role credentials there is nothing to sign with: an error
    // at construction, naming the variable, not a failure at the first push.
    for (name, _) in VARS {
        std::env::remove_var(name);
    }
    let err = HttpV1Sender::from_external_account_json(&config, testkit::PROJECT_ID)
        .unwrap_err()
        .to_string();
    assert!(err.contains("AWS_ACCESS_KEY_ID"), "{err}");

    for (name, value) in VARS {
        std::env::set_var(name, value);
    }
    let err = HttpV1Sender::from_external_account_json(&config, " ").unwrap_err();
    assert!(err.to_string().contains("project id"), "{err}");

    // It builds; minting and sending through the fake is the testkit's
    // `external_account_sender`, which differs only in where the same
    // credentials come from. This one would send to the real FCM.
    let sender = HttpV1Sender::from_external_account_json(&config, testkit::PROJECT_ID)
        .expect("build from the environment");
    assert_eq!(sender.project_id(), testkit::PROJECT_ID);
    // The secret never shows in the sender's Debug.
    let debug = format!("{sender:?}");
    assert!(debug.contains(testkit::AWS_ACCESS_KEY_ID), "{debug}");
    assert!(!debug.contains(testkit::AWS_SECRET_ACCESS_KEY), "{debug}");
    assert!(!debug.contains(testkit::AWS_SESSION_TOKEN), "{debug}");
}
