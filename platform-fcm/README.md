# platform-fcm

The one FCM HTTP v1 sender (shared-rust#2). Shriek, Granite and ChirpAuth each
carried a copy, and only Shriek's set Android priority or reported what became
of a push. This is Shriek's version, extracted.

```rust
use platform_fcm::{Delivery, FcmSender, HttpV1Sender, Message, Notification, Priority};

// At boot. A credential that is set but bad is an Err: refuse to start.
let sender = HttpV1Sender::from_service_account_json(&json)?;

let message = Message {
    priority: Priority::High(Notification {
        title: "Approval requested".into(),
        body: "Open Granite to review".into(),
        channel_id: Some("approvals".into()), // a channel the app creates
    }),
    data: [("request_id".into(), id)].into(),
    ttl: Duration::from_secs(600),
};
match sender.send(&device.fcm_token, &message).await {
    Delivery::Accepted { message_id } => { /* record it */ }
    Delivery::Unregistered { .. } => { /* drop the device: it never comes back */ }
    Delivery::Failed { reason } => { /* count / audit it */ }
}
```

## The contract

- **Every message names its priority.** FCM's default is NORMAL, which a
  dozing phone holds until its next maintenance window (about 10 minutes).
  `Priority::High` wakes it, and it can only be built with a `Notification`,
  because Android demotes a HIGH message that shows nothing.
  `Priority::Normal(None)` is a data-only message.
- **The caller picks the TTL and channel.** There is no default TTL (FCM's is
  28 days). A `channel_id` lives on the `Notification`, so a data-only message
  cannot name one.
- **`send` returns a `Delivery` and never panics or errors.** `Unregistered`
  (FCM's 404 `UNREGISTERED`) means the token is dead. Everything else that
  did not go out is `Failed` with FCM's status and `errorCode` in the reason.
  Each request is bounded by `REQUEST_TIMEOUT` (10 s). `Delivery` is
  `#[must_use]`.
- **One credential policy.** `ServiceAccount::from_json` loads the RSA key, so
  a bad key fails at boot. No error message carries a value from the JSON.
  `NoopSender` is only for a service with no credential named, and every push
  it is handed is `Failed`.
- The OAuth token is cached and minted again within 60 s of expiry.

What stays in each service: which devices, the payload, its channel and TTL,
and what it does with each `Delivery`.

## Testing

The `testkit` feature adds `testkit::FakeFcm`. It is a local server for both
Google endpoints. The token endpoint verifies the RS256 assertion (signature,
`iss`, `aud`, `scope`, expiry). The send endpoint records each message and
answers per device: accepted, `unregister(token)` or `respond(token, status,
body)`. `FakeFcm::sender()` is a real `HttpV1Sender` pointed at it:

```toml
[dev-dependencies]
platform-fcm = { git = "https://github.com/stackwell-labs/shared-rust.git", tag = "…", package = "platform-fcm", features = ["testkit"] }
```

`PLATFORM_FCM_KEY_FILE=<service-account.json> cargo test -p platform-fcm`
also mints a real token from Google. It sends nothing.
