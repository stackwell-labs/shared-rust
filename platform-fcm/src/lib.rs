//! The one FCM HTTP v1 sender (shared-rust#2).
//!
//! Shriek, Granite and ChirpAuth each carried their own copy of this client and
//! the copies drifted: only Shriek's set Android priority and reported what
//! became of a push. This crate is Shriek's version, made the only one.
//!
//! - [`ServiceAccount::from_json`] parses the Google service-account JSON and
//!   loads its RSA key, so a credential that is set but bad fails at boot, not
//!   at the first push.
//! - [`HttpV1Sender`] mints the OAuth token (an RS256 JWT assertion), caches
//!   it, and sends. [`FcmSender::send`] returns a [`Delivery`] and never
//!   panics or returns an error into the caller's write path: push is
//!   best-effort, and the caller decides what a failure means.
//! - A [`Message`] must say its [`Priority`]. FCM's default when the `android`
//!   block is absent is NORMAL, which a phone in Doze holds until its next
//!   maintenance window (about 10 minutes; Shriek, 2026-10-25). A
//!   [`Priority::High`] push carries a [`Notification`] by construction:
//!   Android demotes a high-priority message that shows nothing.
//! - [`NoopSender`] is for a service with no credential named at all. Every
//!   push it is handed did not go out, so it reports [`Delivery::Failed`].
//!
//! What stays in each service: which devices, what payload, the channel and TTL
//! it chooses, and what it does with each [`Delivery`] (prune a device on
//! [`Delivery::Unregistered`], count, audit).

#[cfg(feature = "testkit")]
pub mod testkit;

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ring::signature::RsaKeyPair;

/// Where a service account's OAuth token comes from when its JSON names none.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// The OAuth scope an FCM send needs.
pub const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// How long one request (token mint or send) may take before it is a
/// [`Delivery::Failed`]. A caller awaits the send on its write path, so a hung
/// FCM must not hang the caller.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

const FCM_BASE: &str = "https://fcm.googleapis.com";

/// A token within this many seconds of expiry is minted again.
const TOKEN_REFRESH_MARGIN_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// The message
// ---------------------------------------------------------------------------

/// One push to one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Whether FCM may wake a dozing phone for it, and what it shows.
    pub priority: Priority,
    /// Machine-readable keys the app deep-links on. FCM refuses a few reserved
    /// keys (`from`, `message_type`, and keys starting `google.` or `gcm.`).
    pub data: HashMap<String, String>,
    /// How long FCM keeps trying to reach a phone that is off or offline before
    /// it drops the push. Sent in whole seconds; FCM's maximum is 28 days and a
    /// longer one is refused ([`Delivery::Failed`]). There is no default: FCM's
    /// own is 28 days, which is wrong for anything a user is waiting on.
    pub ttl: Duration,
}

/// The Android delivery priority. There is deliberately no default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Priority {
    /// Delivered at once, waking a phone in Doze. Android rations high-priority
    /// delivery and demotes a high-priority message that shows nothing, so a
    /// HIGH push always carries a notification: this is the only way to build
    /// one. Use it for what a person is waiting on (a page, an approval).
    High(Notification),
    /// FCM's NORMAL: a phone in Doze gets it at its next maintenance window.
    /// With no notification it is a data-only message the app handles itself.
    Normal(Option<Notification>),
}

impl Priority {
    fn notification(&self) -> Option<&Notification> {
        match self {
            Priority::High(n) => Some(n),
            Priority::Normal(n) => n.as_ref(),
        }
    }

    fn fcm_name(&self) -> &'static str {
        match self {
            Priority::High(_) => "HIGH",
            Priority::Normal(_) => "NORMAL",
        }
    }
}

/// The text the system tray shows, rendered by the FCM SDK even when the app's
/// own code is not running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub title: String,
    pub body: String,
    /// The Android notification channel to post on. When the app is in the
    /// background the FCM SDK renders the notification itself, and with no
    /// channel it uses its own "Miscellaneous" channel at default importance,
    /// which does not show heads-up. The app must create the channel it names.
    pub channel_id: Option<String>,
}

/// The HTTP v1 request body for `message` to the device `fcm_token`.
///
/// The `android` block is always present, so the priority sent is always the
/// one the caller chose. No `apns` block: no platform app runs on iOS.
pub fn message_body(fcm_token: &str, message: &Message) -> serde_json::Value {
    let mut android = serde_json::json!({
        "priority": message.priority.fcm_name(),
        "ttl": format!("{}s", message.ttl.as_secs()),
    });
    let mut body = serde_json::json!({
        "token": fcm_token,
        "data": message.data,
    });
    if let Some(n) = message.priority.notification() {
        body["notification"] = serde_json::json!({ "title": n.title, "body": n.body });
        if let Some(channel_id) = &n.channel_id {
            android["notification"] = serde_json::json!({ "channel_id": channel_id });
        }
    }
    body["android"] = android;
    serde_json::json!({ "message": body })
}

// ---------------------------------------------------------------------------
// The outcome
// ---------------------------------------------------------------------------

/// What became of one push to one device.
///
/// Ignoring one is a warning, so a caller cannot silently go back to
/// log-and-drop:
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// async fn fire_and_forget(sender: &dyn platform_fcm::FcmSender, m: &platform_fcm::Message) {
///     sender.send("token", m).await;
/// }
/// ```
#[must_use = "a push outcome is the point of the send: count it, audit it, or prune the device"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// FCM accepted the message; `message_id` is FCM's name for it. This is as
    /// far as a server can see: acceptance is not proof the phone displayed it.
    Accepted { message_id: String },
    /// It did not go out: the OAuth token mint failed, FCM refused it, the
    /// request errored or timed out, or push is not configured at all.
    Failed { reason: String },
    /// It did not go out because FCM says the token is dead (404 `UNREGISTERED`:
    /// the app was uninstalled, or reinstalled under a new token). Unlike
    /// [`Delivery::Failed`] this is about the device, not the path, and it will
    /// never succeed again: drop the device.
    Unregistered { reason: String },
}

/// Classify FCM's answer to one send. 2xx carries the message `name`; an error
/// carries `error.status` and, in its details, FCM's own `errorCode` (e.g.
/// `UNREGISTERED`), which is what tells a dead device apart from a broken
/// credential. `UNREGISTERED` is the one answer that condemns the token: FCM's
/// docs say to stop sending to it. An `INVALID_ARGUMENT` can also mean a bad
/// payload, so it stays a plain failure.
pub fn classify(status: u16, body: &serde_json::Value) -> Delivery {
    if (200..300).contains(&status) {
        let message_id = body
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(FCM returned no message name)")
            .to_owned();
        return Delivery::Accepted { message_id };
    }
    let error = body.get("error");
    let text = |key: &str| {
        error
            .and_then(|e| e.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
    };
    let code = error
        .and_then(|e| e.get("details"))
        .and_then(|d| d.as_array())
        .and_then(|d| d.iter().find_map(|x| x.get("errorCode")?.as_str()))
        .unwrap_or("");
    let mut message: String = text("message").chars().take(200).collect();
    let status = status.to_string();
    let mut reason = ["FCM", status.as_str(), text("status"), code]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if !message.is_empty() {
        message.insert_str(0, ": ");
        reason.push_str(&message);
    }
    if code == "UNREGISTERED" {
        Delivery::Unregistered { reason }
    } else {
        Delivery::Failed { reason }
    }
}

// ---------------------------------------------------------------------------
// Senders
// ---------------------------------------------------------------------------

/// Sends a [`Message`] to one FCM registration token and reports what
/// happened. An implementation must not panic; a failure is a
/// [`Delivery::Failed`]. A trait so a service's fan-out can be tested with a
/// recording mock.
// async_trait marks the boxed future #[must_use] too; Delivery's own
// attribute is the one with the message.
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait FcmSender: Send + Sync {
    async fn send(&self, fcm_token: &str, message: &Message) -> Delivery;
}

/// The sender for a service with no FCM credential named. Every push it is
/// handed is a push that did not go out, so it reports a failure: a user with
/// devices and no credential must show up as failed pushes, not as delivered.
///
/// Not a fallback for a credential that is set but bad: that is a
/// [`ServiceAccount::from_json`] error, and the service should refuse to boot.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopSender;

#[async_trait::async_trait]
impl FcmSender for NoopSender {
    async fn send(&self, _fcm_token: &str, _message: &Message) -> Delivery {
        Delivery::Failed {
            reason: "push is not configured (no FCM service account)".to_owned(),
        }
    }
}

/// A credential that cannot be used. The message names what is wrong and
/// never carries the key or any other value from the JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FCM service account: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// A Google service account whose RSA key has been loaded.
#[derive(Clone)]
pub struct ServiceAccount {
    client_email: String,
    token_uri: String,
    project_id: String,
    key: Arc<RsaKeyPair>,
}

impl fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("client_email", &self.client_email)
            .field("token_uri", &self.token_uri)
            .field("project_id", &self.project_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl ServiceAccount {
    /// Parse the JSON key file Google issues for a service account. Needs
    /// `client_email`, `private_key` (PKCS#8 PEM) and `project_id`;
    /// `token_uri` defaults to [`DEFAULT_TOKEN_URI`]. The key is loaded here,
    /// so a malformed one is an error now rather than at the first push.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        // Parsed to a Value first, and fields read by hand, so no serde
        // message can echo a field's value (the key) into the error.
        let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
            ConfigError(format!(
                "not JSON (line {}, column {})",
                e.line(),
                e.column()
            ))
        })?;
        let field = |name: &str| -> Result<String, ConfigError> {
            match value.get(name).and_then(|v| v.as_str()) {
                Some(s) if !s.trim().is_empty() => Ok(s.to_owned()),
                _ => Err(ConfigError(format!(
                    "`{name}` is missing, empty or not a string"
                ))),
            }
        };
        let client_email = field("client_email")?;
        let project_id = field("project_id")?;
        let private_key = field("private_key")?;
        let token_uri = match value.get("token_uri") {
            None => DEFAULT_TOKEN_URI.to_owned(),
            Some(_) => field("token_uri")?,
        };
        let der = pkcs8_der_from_pem(&private_key)?;
        let key = RsaKeyPair::from_pkcs8(&der)
            .map_err(|e| ConfigError(format!("`private_key` is not a PKCS#8 RSA key: {e}")))?;
        Ok(Self {
            client_email,
            token_uri,
            project_id,
            key: Arc::new(key),
        })
    }

    pub fn client_email(&self) -> &str {
        &self.client_email
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn token_uri(&self) -> &str {
        &self.token_uri
    }

    /// The signed JWT assertion exchanged for an access token, issued at `now`
    /// (Unix seconds) and valid for an hour.
    fn assertion(&self, now: u64) -> Result<String, String> {
        let header = br#"{"alg":"RS256","typ":"JWT"}"#;
        let claims = serde_json::json!({
            "iss": self.client_email,
            "scope": FCM_SCOPE,
            "aud": self.token_uri,
            "iat": now,
            "exp": now + 3600,
        })
        .to_string();
        let signing_input = format!("{}.{}", b64url(header), b64url(claims.as_bytes()));
        let rng = ring::rand::SystemRandom::new();
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &rng,
                signing_input.as_bytes(),
                &mut sig,
            )
            .map_err(|e| format!("sign assertion: {e}"))?;
        Ok(format!("{signing_input}.{}", b64url(&sig)))
    }
}

/// Strip the PEM armour and base64-decode the body.
fn pkcs8_der_from_pem(pem: &str) -> Result<Vec<u8>, ConfigError> {
    let b64: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| ConfigError("`private_key` is not base64 inside its PEM armour".to_owned()))
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: u64,
}

/// The real sender: FCM HTTP v1 with a cached OAuth token.
pub struct HttpV1Sender {
    account: ServiceAccount,
    /// [`FCM_BASE`]; the testkit points it at its fake.
    fcm_base: String,
    http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
}

impl fmt::Debug for HttpV1Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpV1Sender")
            .field("account", &self.account)
            .field("fcm_base", &self.fcm_base)
            .finish_non_exhaustive()
    }
}

impl HttpV1Sender {
    pub fn new(account: ServiceAccount) -> Result<Self, ConfigError> {
        Self::with_base(account, FCM_BASE.to_owned())
    }

    /// Parse `json` ([`ServiceAccount::from_json`]) and build the sender.
    pub fn from_service_account_json(json: &str) -> Result<Self, ConfigError> {
        Self::new(ServiceAccount::from_json(json)?)
    }

    fn with_base(account: ServiceAccount, fcm_base: String) -> Result<Self, ConfigError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| ConfigError(format!("build HTTP client: {e}")))?;
        Ok(Self {
            account,
            fcm_base,
            http,
            token: Mutex::new(None),
        })
    }

    pub fn account(&self) -> &ServiceAccount {
        &self.account
    }

    /// A cached access token, or a freshly minted one.
    async fn access_token(&self) -> Result<String, String> {
        let now = now_unix();
        let cached = self.token.lock().ok().and_then(|c| c.clone());
        if let Some(cached) = cached {
            if now + TOKEN_REFRESH_MARGIN_SECS < cached.expires_at {
                return Ok(cached.token);
            }
        }
        let assertion = self.account.assertion(now)?;
        let resp = self
            .http
            .post(&self.account.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("token request: {e}"))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("token endpoint {status}, body not JSON: {e}"))?;
        if !status.is_success() {
            return Err(format!("token endpoint {status}: {body}"));
        }
        let token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("token response has no access_token")?
            .to_owned();
        let ttl = body
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        if let Ok(mut cache) = self.token.lock() {
            *cache = Some(CachedToken {
                token: token.clone(),
                expires_at: now + ttl,
            });
        }
        Ok(token)
    }
}

#[async_trait::async_trait]
impl FcmSender for HttpV1Sender {
    async fn send(&self, fcm_token: &str, message: &Message) -> Delivery {
        let token = match self.access_token().await {
            Ok(token) => token,
            Err(e) => {
                return Delivery::Failed {
                    reason: format!("access-token mint failed: {e}"),
                }
            }
        };
        let url = format!(
            "{}/v1/projects/{}/messages:send",
            self.fcm_base, self.account.project_id
        );
        let resp = match self
            .http
            .post(&url)
            .bearer_auth(token)
            .json(&message_body(fcm_token, message))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return Delivery::Failed {
                    reason: format!("send error: {e}"),
                }
            }
        };
        let status = resp.status();
        // An unreadable body still leaves the status to report.
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        classify(status.as_u16(), &body)
    }
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Message {
        Message {
            priority: Priority::High(Notification {
                title: "chirp: no signal".into(),
                body: "down for 90s".into(),
                channel_id: Some("shriek_alerts".into()),
            }),
            data: HashMap::from([("service".to_owned(), "chirp".to_owned())]),
            ttl: Duration::from_secs(24 * 60 * 60),
        }
    }

    /// A HIGH push names its priority, TTL and channel, and keeps its
    /// notification, without which Android demotes it.
    #[test]
    fn a_high_push_carries_priority_ttl_channel_and_notification() {
        let body = message_body("device-tok", &page());
        let m = &body["message"];
        assert_eq!(m["token"], "device-tok");
        assert_eq!(m["notification"]["title"], "chirp: no signal");
        assert_eq!(m["notification"]["body"], "down for 90s");
        assert_eq!(m["data"]["service"], "chirp");
        assert_eq!(m["android"]["priority"], "HIGH");
        assert_eq!(m["android"]["ttl"], "86400s");
        assert_eq!(m["android"]["notification"]["channel_id"], "shriek_alerts");
    }

    /// NORMAL is sent explicitly, and a data-only message has no notification
    /// block and no channel.
    #[test]
    fn a_normal_data_only_push_says_normal_and_shows_nothing() {
        let msg = Message {
            priority: Priority::Normal(None),
            data: HashMap::new(),
            ttl: Duration::from_millis(1500),
        };
        let m = &message_body("t", &msg)["message"];
        assert_eq!(m["android"]["priority"], "NORMAL");
        assert_eq!(m["android"]["ttl"], "1s");
        assert!(m.get("notification").is_none());
        assert!(m["android"].get("notification").is_none());
    }

    #[test]
    fn no_channel_means_no_android_notification_block() {
        let mut msg = page();
        if let Priority::High(n) = &mut msg.priority {
            n.channel_id = None;
        }
        let m = &message_body("t", &msg)["message"];
        assert!(m["notification"].is_object());
        assert!(m["android"].get("notification").is_none());
    }

    #[test]
    fn fcm_answers_are_classified_with_the_reason_kept() {
        let ok = serde_json::json!({ "name": "projects/p/messages/0:123" });
        assert_eq!(
            classify(200, &ok),
            Delivery::Accepted {
                message_id: "projects/p/messages/0:123".into()
            }
        );
        let unregistered = serde_json::json!({ "error": {
            "code": 404, "status": "NOT_FOUND", "message": "Requested entity was not found.",
            "details": [{ "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                          "errorCode": "UNREGISTERED" }]
        }});
        assert_eq!(
            classify(404, &unregistered),
            Delivery::Unregistered {
                reason: "FCM 404 NOT_FOUND UNREGISTERED: Requested entity was not found.".into()
            }
        );
        // A 404 without UNREGISTERED does not condemn the token.
        assert_eq!(
            classify(
                404,
                &serde_json::json!({ "error": { "status": "NOT_FOUND" } })
            ),
            Delivery::Failed {
                reason: "FCM 404 NOT_FOUND".into()
            }
        );
        // A bad payload is not a dead device.
        let invalid = serde_json::json!({ "error": { "status": "INVALID_ARGUMENT",
            "details": [{ "errorCode": "INVALID_ARGUMENT" }] } });
        assert!(matches!(classify(400, &invalid), Delivery::Failed { .. }));
        let denied = serde_json::json!({ "error": { "status": "UNAUTHENTICATED" } });
        assert_eq!(
            classify(401, &denied),
            Delivery::Failed {
                reason: "FCM 401 UNAUTHENTICATED".into()
            }
        );
        assert_eq!(
            classify(503, &serde_json::Value::Null),
            Delivery::Failed {
                reason: "FCM 503".into()
            }
        );
    }

    #[tokio::test]
    async fn the_noop_sender_reports_a_failure() {
        assert!(matches!(
            NoopSender.send("tok", &page()).await,
            Delivery::Failed { .. }
        ));
    }

    /// Every way a credential can be bad is an error at construction, and no
    /// error repeats a value from the JSON.
    #[test]
    fn a_bad_service_account_fails_at_construction_without_echoing_it() {
        let secret =
            "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWtleS1ieXRlcw==\n-----END PRIVATE KEY-----\n";
        let cases = [
            "not json".to_owned(),
            r#"{"client_email":"a@b","project_id":"p"}"#.to_owned(),
            format!(r#"{{"client_email":"a@b","project_id":"p","private_key":{}}}"#, serde_json::json!(secret)),
            format!(r#"{{"client_email":"a@b","project_id":"","private_key":{}}}"#, serde_json::json!(secret)),
            format!(r#"{{"client_email":"a@b","project_id":"p","private_key":{},"token_uri":7}}"#, serde_json::json!(secret)),
            r#"{"client_email":"a@b","project_id":"p","private_key":"-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----"}"#.to_owned(),
        ];
        for json in cases {
            let err = ServiceAccount::from_json(&json)
                .expect_err(&json)
                .to_string();
            assert!(!err.contains("c2VjcmV0"), "{err}");
            assert!(err.starts_with("FCM service account: "), "{err}");
        }
    }

    /// Verifies a REAL service-account key against this code path (the RS256
    /// assertion and Google's OAuth exchange). Runs only when
    /// PLATFORM_FCM_KEY_FILE names a key file; needs the network. Sends
    /// nothing to any device.
    #[tokio::test]
    async fn a_real_key_mints_an_access_token() {
        let Ok(path) = std::env::var("PLATFORM_FCM_KEY_FILE") else {
            eprintln!("PLATFORM_FCM_KEY_FILE unset: skipping the real-key token mint");
            return;
        };
        let json = std::fs::read_to_string(path).expect("read key file");
        let sender = HttpV1Sender::from_service_account_json(&json).expect("parse real key");
        let token = sender.access_token().await.expect("mint an OAuth token");
        assert!(!token.is_empty());
    }
}
