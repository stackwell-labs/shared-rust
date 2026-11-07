//! A fake FCM for tests (`testkit` feature).
//!
//! One local HTTP server plays both of Google's endpoints the sender talks to:
//!
//! - the OAuth token endpoint, which checks the RS256 JWT assertion against the
//!   fake service account's public key (signature, `iss`, `aud`, `scope`,
//!   expiry) before it issues a token, so the real mint path is exercised;
//! - the FCM v1 send endpoint, which requires a token it issued, records every
//!   message, and answers per device: accepted by default, or whatever
//!   [`FakeFcm::respond`] / [`FakeFcm::unregister`] set.
//!
//! [`FakeFcm::sender`] returns a real [`HttpV1Sender`] pointed at it, so a
//! service's tests drive the same code production does.
//!
//! ```no_run
//! # async fn example() {
//! use platform_fcm::{testkit::FakeFcm, FcmSender};
//!
//! let fcm = FakeFcm::start().await;
//! fcm.unregister("dead-device");
//! let sender = fcm.sender();
//! // ... run the service's fan-out with `sender`, then:
//! let sent = fcm.sent();
//! assert_eq!(sent[0].body["android"]["priority"], "HIGH");
//! # }
//! ```

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::EncodePrivateKey;
use rsa::signature::Verifier;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use crate::{HttpV1Sender, ServiceAccount, FCM_SCOPE};

/// The fake service account's `client_email`.
pub const CLIENT_EMAIL: &str = "fcm@fake-project.iam.gserviceaccount.com";
/// The fake service account's `project_id`.
pub const PROJECT_ID: &str = "fake-project";

/// One RSA-2048 key per test process: keygen is the slow part.
fn key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("generate testkit RSA key")
    })
}

fn private_key_pem() -> String {
    let der = key().to_pkcs8_der().expect("encode testkit key as PKCS#8");
    let b64 = STANDARD.encode(der.as_bytes());
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// One message the fake received.
#[derive(Debug, Clone, PartialEq)]
pub struct Sent {
    /// The device token it was addressed to.
    pub token: String,
    /// The request's `message` object, as sent.
    pub body: serde_json::Value,
}

#[derive(Default)]
struct Inner {
    sent: Vec<Sent>,
    responses: HashMap<String, (u16, serde_json::Value)>,
    issued: Vec<String>,
    token_lifetime_secs: u64,
    token_uri: String,
}

type Shared = Arc<Mutex<Inner>>;

/// A running fake FCM. It serves until the test process exits.
#[derive(Clone)]
pub struct FakeFcm {
    base: String,
    inner: Shared,
}

impl FakeFcm {
    /// Bind `127.0.0.1:0` and serve. Must run inside a tokio runtime.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake FCM");
        let base = format!("http://{}", listener.local_addr().expect("fake FCM addr"));
        let inner: Shared = Arc::new(Mutex::new(Inner {
            token_lifetime_secs: 3600,
            token_uri: format!("{base}/token"),
            ..Inner::default()
        }));
        let app = Router::new()
            .route("/token", post(token))
            .route("/v1/projects/{project}/messages:send", post(send))
            .with_state(inner.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { base, inner }
    }

    /// A service-account JSON whose `token_uri` is this fake and whose key
    /// the fake verifies assertions against.
    pub fn service_account_json(&self) -> String {
        serde_json::json!({
            "type": "service_account",
            "project_id": PROJECT_ID,
            "client_email": CLIENT_EMAIL,
            "private_key": private_key_pem(),
            "token_uri": self.lock().token_uri,
        })
        .to_string()
    }

    /// A real [`HttpV1Sender`] whose token mint and sends go to this fake.
    pub fn sender(&self) -> HttpV1Sender {
        let account = ServiceAccount::from_json(&self.service_account_json())
            .expect("the testkit service account parses");
        HttpV1Sender::with_base(account, self.base.clone()).expect("build testkit sender")
    }

    /// Answer every later send to `token` with `status` and `body` (FCM's
    /// error shape is `{"error": {"status": .., "details": [{"errorCode": ..}]}}`).
    pub fn respond(&self, token: &str, status: u16, body: serde_json::Value) {
        self.lock()
            .responses
            .insert(token.to_owned(), (status, body));
    }

    /// Answer every later send to `token` the way FCM answers for an
    /// uninstalled app: 404 `UNREGISTERED`.
    pub fn unregister(&self, token: &str) {
        self.respond(
            token,
            404,
            serde_json::json!({ "error": {
                "code": 404,
                "status": "NOT_FOUND",
                "message": "Requested entity was not found.",
                "details": [{
                    "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                    "errorCode": "UNREGISTERED",
                }],
            }}),
        );
    }

    /// The `expires_in` the token endpoint grants from now on (default 3600).
    pub fn set_token_lifetime_secs(&self, secs: u64) {
        self.lock().token_lifetime_secs = secs;
    }

    /// Every message received so far, in order, including refused ones.
    pub fn sent(&self) -> Vec<Sent> {
        self.lock().sent.clone()
    }

    /// How many access tokens the token endpoint has issued.
    pub fn tokens_issued(&self) -> usize {
        self.lock().issued.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("fake FCM state")
    }
}

type Answer = (StatusCode, Json<serde_json::Value>);

fn answer(status: StatusCode, body: serde_json::Value) -> Answer {
    (status, Json(body))
}

async fn token(State(inner): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Answer {
    let token_uri = inner.lock().expect("fake FCM state").token_uri.clone();
    let invalid = |why: &str| {
        answer(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "invalid_grant", "error_description": why }),
        )
    };
    if form.get("grant_type").map(String::as_str)
        != Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
    {
        return invalid("grant_type is not jwt-bearer");
    }
    let Some(assertion) = form.get("assertion") else {
        return invalid("no assertion");
    };
    if let Err(why) = check_assertion(assertion, &token_uri) {
        return invalid(&why);
    }
    let mut inner = inner.lock().expect("fake FCM state");
    let issued = format!("fake-access-token-{}", inner.issued.len() + 1);
    inner.issued.push(issued.clone());
    answer(
        StatusCode::OK,
        serde_json::json!({
            "access_token": issued,
            "expires_in": inner.token_lifetime_secs,
            "token_type": "Bearer",
        }),
    )
}

/// Verify the assertion the way Google does: RS256 over `header.claims` with
/// the account's public key, and the claims a service-account grant needs.
fn check_assertion(assertion: &str, token_uri: &str) -> Result<(), String> {
    let mut parts = assertion.split('.');
    let (Some(header), Some(claims), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("assertion is not header.claims.signature".into());
    };
    let decode = |part: &str| URL_SAFE_NO_PAD.decode(part).map_err(|e| e.to_string());
    let header: serde_json::Value =
        serde_json::from_slice(&decode(header)?).map_err(|e| e.to_string())?;
    if header["alg"] != "RS256" {
        return Err(format!("alg is {}, not RS256", header["alg"]));
    }
    let signature = Signature::try_from(decode(sig)?.as_slice()).map_err(|e| e.to_string())?;
    let signing_input = &assertion[..assertion.rfind('.').expect("three parts")];
    VerifyingKey::<Sha256>::new(RsaPublicKey::from(key()))
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "signature does not verify".to_owned())?;
    let claims: serde_json::Value =
        serde_json::from_slice(&decode(claims)?).map_err(|e| e.to_string())?;
    let expect = |name: &str, want: &str| {
        if claims[name] == want {
            Ok(())
        } else {
            Err(format!("{name} is {}, want {want}", claims[name]))
        }
    };
    expect("iss", CLIENT_EMAIL)?;
    expect("aud", token_uri)?;
    expect("scope", FCM_SCOPE)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    match (claims["iat"].as_u64(), claims["exp"].as_u64()) {
        (Some(iat), Some(exp)) if iat <= now + 60 && now < exp && exp - iat <= 3600 => Ok(()),
        _ => Err(format!(
            "iat {} / exp {} is not a current grant of at most an hour",
            claims["iat"], claims["exp"]
        )),
    }
}

async fn send(
    State(inner): State<Shared>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Answer {
    let mut inner = inner.lock().expect("fake FCM state");
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !bearer.is_some_and(|t| inner.issued.iter().any(|i| i == t)) {
        return answer(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({ "error": { "code": 401, "status": "UNAUTHENTICATED" } }),
        );
    }
    if project != PROJECT_ID {
        return answer(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": { "code": 404, "status": "NOT_FOUND",
                "message": format!("no project {project}") } }),
        );
    }
    let message = body["message"].clone();
    let token = message["token"].as_str().unwrap_or_default().to_owned();
    let n = inner.sent.len();
    inner.sent.push(Sent {
        token: token.clone(),
        body: message,
    });
    match inner.responses.get(&token) {
        Some((status, body)) => answer(
            StatusCode::from_u16(*status).expect("a valid status"),
            body.clone(),
        ),
        None => answer(
            StatusCode::OK,
            serde_json::json!({ "name": format!("projects/{PROJECT_ID}/messages/{n}") }),
        ),
    }
}
