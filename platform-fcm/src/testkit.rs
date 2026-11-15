//! A fake FCM for tests (`testkit` feature).
//!
//! One local HTTP server plays every Google endpoint the sender talks to:
//!
//! - the OAuth token endpoint, which checks the RS256 JWT assertion against the
//!   fake service account's public key (signature, `iss`, `aud`, `scope`,
//!   expiry) before it issues a token, so the real mint path is exercised;
//! - for the keyless credential ([`FakeFcm::external_account_sender`],
//!   shared-rust#38), Google STS, which verifies the SigV4 signature on the
//!   AWS `GetCallerIdentity` subject against the fake AWS role's secret (and
//!   its date, host, session token and target pool) before it issues a
//!   federated token, and the IAM credentials `generateAccessToken`, which
//!   takes only a federated token it issued and grants the FCM scope;
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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{KeyPair as _, RsaKeyPair, UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};

use crate::external_account::{sigv4, AwsCredentials};
use crate::{
    pkcs8_der_from_pem, Credential, ExternalAccount, HttpV1Sender, ServiceAccount,
    AWS_SUBJECT_TOKEN_TYPE, FCM_SCOPE,
};

/// The fake service account's `client_email`.
pub const CLIENT_EMAIL: &str = "fcm@fake-project.iam.gserviceaccount.com";
/// The fake service account's `project_id`.
pub const PROJECT_ID: &str = "fake-project";

/// The workload identity pool provider the fake external account federates
/// through.
pub const AUDIENCE: &str =
    "//iam.googleapis.com/projects/0/locations/global/workloadIdentityPools/fake-pool/providers/fake-aws";
/// The fake AWS role credentials [`FakeFcm::external_account_sender`] signs
/// with, as Lambda would put them in `AWS_ACCESS_KEY_ID`,
/// `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` and `AWS_REGION`.
pub const AWS_ACCESS_KEY_ID: &str = "ASIAFAKEFAKEFAKEFAKE";
pub const AWS_SECRET_ACCESS_KEY: &str = "fake/aws+secret/access/key";
pub const AWS_SESSION_TOKEN: &str = "fake-aws-session-token";
pub const AWS_REGION: &str = "eu-west-1";

/// The `regional_cred_verification_url` of the fake external account. The
/// fake STS checks the subject against it and never calls AWS.
const VERIFICATION_URL: &str =
    "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15";

fn fake_aws() -> AwsCredentials {
    AwsCredentials {
        access_key_id: AWS_ACCESS_KEY_ID.to_owned(),
        secret_access_key: AWS_SECRET_ACCESS_KEY.to_owned(),
        session_token: Some(AWS_SESSION_TOKEN.to_owned()),
        region: AWS_REGION.to_owned(),
    }
}

/// The fake service account's RSA-2048 private key, PKCS#8 PEM. A fixed,
/// public test key (shared-rust#23), as chirp-auth-client's testkit keys are:
/// it signs only assertions this fake verifies, so it guards nothing. Inline
/// rather than `include_str!`d, so no source file reads another (amber-ci's
/// job inputs in `.amber/ci.toml` rely on that).
const PRIVATE_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDQbJWA3GepJMci\n\
zF2J4MD6wRpJqL5gWiyuRmV3lrwGdTvnIUA4ABN72/VxlwKojtvwMiAF5HTGZ59e\n\
hkmCOAZGueamJhnBVs/BbROylf2/P+GX+OnL+v30opF29rBl8m6rNpZ3ya0lLD/x\n\
xbblesymqKNINo8lwskjjudpfk6TPe+31Rs33zU3sRuwpOgrBNcx3gind2EJi1o2\n\
SmKDWyPkmOq5/kg43Zv6di1vy24eRl06OAGV/gaoLGb6Q2gc9z2W86WQoxgIbWOX\n\
KXEO5WGIMld8Dre6JMdT5pQSvm1iNO5cXKpGBr1KwAnibSKntD4JmUk5q31GAYVk\n\
1m5/M6JXAgMBAAECggEAZheqK9LKnBm9yZfdgbosDSglnksf5caF+F/XN/sH4wnt\n\
68tnz4aKBLO7yIY18Sb5KPEEqp47bSw47m5M95JF0MMi7ePf3cqOPasWaPX7s4Cx\n\
GmX878PkPb6cDm/L/EQCXa+BiO+q9nh0YhN9AW9ja4dTY/4FpHODXv2S8SPDjW94\n\
zLP4gPldpoWqjYOkEyvQ7dqOIDD1J5O48Hp+75jfhZvd2GLBE717ywSUS8QmM+OW\n\
3Fvi5U3xJu6v/r9y/MH4ol4pKKGLf251kZJMEoY+RsBzyxPXR0r7kF9xIAGqUuXE\n\
x052MabbjEGJ8DiYCPnvQEp6qnk8y6ywEB5WWv7EQQKBgQDw1Kizg8B0axRyHhP6\n\
Kh+IpNz52E5ZY5tknJ3LW/JG/ePPy4jZrZ3TsWYMbVE7EnIy/htqP7lCsqJB6Xgy\n\
sZTMe76JWc/U3DTQSJa10ZerGFcvMjRGlKPMbbiBSIiy/a/x2tPIqsrVd9TUeUe+\n\
KbuotxkD1R85VpxPwXQ3/Z4CkQKBgQDdjWB0GsEH5so8jPNSx5+HSNuDgNdcA9bJ\n\
mE6bUOED1EqBXvWWbcldEjX7VcKkB56udCrCjLpzYIMOU5v4KDcIdgwsKDG6bssL\n\
Z2Qhe6V1Y2jw6rADrajk3M9OtxzH7dM4NgmUPHCTedFu6MyFkvXaqtyPrSY2Zylm\n\
+n6pla/6ZwKBgQCCcv6KdmRJ6zKg+c/iYuy/zGVx5AvUeZLTdc43OC/M6nt6tAoF\n\
tvhVkbLwKkqkz8ISAviAndHQ4gfn4fnco7ow5Rp5Na/Q4hKte5Q/Gi+oWr/m7a/J\n\
R3xOIGSfitWY9rdWLy0mdfT2mjkreiI1TE+8/KjNHaUTHun+fZBhP7xWMQKBgHod\n\
wetdD8amLBSB8GBRTZoIy43JR2sdZpdJjxJG2y/8JHD4gU9ABjx5nC2DkLxOwuUP\n\
fL4tSVvs92+/H/oBWIweXQk9wmMrTFllzKgz+fghKieYhBoS70PufYm6nm+Io+KY\n\
zmDZi4eOHqUORiTd4wt7IAVFgAl+hTCQo54ftpbDAoGAN93k7/SOUgs6+nTaPJ0e\n\
bznhcygl53sZ9U8YvaXmcLIB3ChbrcbkWGwylwzZPUa2x0I66JTuN5St9Oup9o4H\n\
ijGkp8weu9bZxTs3yqG85HzuOV2mwJ0XykAh61hPI8si6xVwPDqFYhuR15rA1eat\n\
4xdGmidwTHlFHL/qNx1+na0=\n\
-----END PRIVATE KEY-----\n\
";

/// The public half of [`PRIVATE_KEY_PEM`], as ring's PKCS#1 `RSAPublicKey` DER.
fn public_key_der() -> &'static [u8] {
    static DER: OnceLock<Vec<u8>> = OnceLock::new();
    DER.get_or_init(|| {
        let der = pkcs8_der_from_pem(PRIVATE_KEY_PEM).expect("testkit key is PEM");
        let key = RsaKeyPair::from_pkcs8(&der).expect("testkit key is a PKCS#8 RSA key");
        key.public_key().as_ref().to_vec()
    })
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
    federated: Vec<String>,
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
            .route("/sts/v1/token", post(sts))
            .route(
                &format!("/v1/projects/-/serviceAccounts/{CLIENT_EMAIL}:generateAccessToken"),
                post(generate_access_token),
            )
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
            "private_key": PRIVATE_KEY_PEM,
            "token_uri": self.lock().token_uri,
        })
        .to_string()
    }

    /// A real [`HttpV1Sender`] whose token mint and sends go to this fake.
    pub fn sender(&self) -> HttpV1Sender {
        let account = ServiceAccount::from_json(&self.service_account_json())
            .expect("the testkit service account parses");
        HttpV1Sender::with_base(
            Credential::ServiceAccount(account),
            PROJECT_ID.to_owned(),
            self.base.clone(),
        )
        .expect("build testkit sender")
    }

    /// An `external_account` config (AWS subject) whose STS and
    /// impersonation endpoints are this fake, impersonating [`CLIENT_EMAIL`].
    pub fn external_account_json(&self) -> String {
        serde_json::json!({
            "type": "external_account",
            "audience": AUDIENCE,
            "subject_token_type": AWS_SUBJECT_TOKEN_TYPE,
            "service_account_impersonation_url": format!(
                "{}/v1/projects/-/serviceAccounts/{CLIENT_EMAIL}:generateAccessToken",
                self.base
            ),
            "token_url": format!("{}/sts/v1/token", self.base),
            "credential_source": {
                "environment_id": "aws1",
                "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
                "regional_cred_verification_url": VERIFICATION_URL,
            },
        })
        .to_string()
    }

    /// A real keyless [`HttpV1Sender`]: it signs its AWS subject with the
    /// fake role credentials ([`AWS_ACCESS_KEY_ID`] and the rest) and mints
    /// through this fake's STS and `generateAccessToken`, then sends here to
    /// [`PROJECT_ID`]. The same as `from_external_account_json(
    /// &fcm.external_account_json(), PROJECT_ID)` with those variables set,
    /// without touching the process environment.
    pub fn external_account_sender(&self) -> HttpV1Sender {
        self.external_account_sender_signing_as(fake_aws())
    }

    fn external_account_sender_signing_as(&self, aws: AwsCredentials) -> HttpV1Sender {
        let account = ExternalAccount::from_json(&self.external_account_json())
            .expect("the testkit external account parses");
        HttpV1Sender::from_external_account(account, aws, PROJECT_ID, self.base.clone())
            .expect("build testkit sender")
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

    /// How many FCM access tokens have been issued, by the token endpoint or
    /// by `generateAccessToken`.
    pub fn tokens_issued(&self) -> usize {
        self.lock().issued.len()
    }

    /// How many AWS subjects STS has accepted and exchanged.
    pub fn sts_exchanges(&self) -> usize {
        self.lock().federated.len()
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
    let signature = decode(sig)?;
    let signing_input = &assertion[..assertion.rfind('.').expect("three parts")];
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key_der())
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

/// Google STS: an RFC 8693 exchange of a signed AWS `GetCallerIdentity` for a
/// federated token.
async fn sts(State(inner): State<Shared>, Form(form): Form<HashMap<String, String>>) -> Answer {
    let invalid = |why: &str| {
        answer(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": "invalid_grant", "error_description": why }),
        )
    };
    let wants = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ),
        ("audience", AUDIENCE),
        ("scope", "https://www.googleapis.com/auth/cloud-platform"),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token",
        ),
        ("subject_token_type", AWS_SUBJECT_TOKEN_TYPE),
    ];
    for (name, want) in wants {
        if form.get(name).map(String::as_str) != Some(want) {
            return invalid(&format!("{name} is not {want}"));
        }
    }
    let Some(subject) = form.get("subject_token") else {
        return invalid("no subject_token");
    };
    if let Err(why) = check_subject(subject, now()) {
        return invalid(&why);
    }
    let mut inner = inner.lock().expect("fake FCM state");
    let issued = format!("fake-federated-token-{}", inner.federated.len() + 1);
    inner.federated.push(issued.clone());
    answer(
        StatusCode::OK,
        serde_json::json!({
            "access_token": issued,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }),
    )
}

/// Verify the subject the way Google STS does before it asks AWS: the
/// request is a POST of `GetCallerIdentity` to the region's STS host, names
/// the pool provider, carries the role's session token, is dated within AWS's
/// 15 minutes, and its SigV4 signature verifies with the role's secret.
fn check_subject(subject: &str, now: u64) -> Result<(), String> {
    let subject = percent_decode(subject).ok_or("subject_token is not percent-encoded UTF-8")?;
    let subject: serde_json::Value =
        serde_json::from_str(&subject).map_err(|_| "subject_token is not JSON".to_owned())?;
    let url = VERIFICATION_URL.replace("{region}", AWS_REGION);
    if subject["url"] != url.as_str() || subject["method"] != "POST" {
        return Err("subject is not a POST of GetCallerIdentity to the region's STS".into());
    }
    let headers: Vec<(String, String)> = subject["headers"]
        .as_array()
        .ok_or("subject has no headers")?
        .iter()
        .map(|h| {
            (
                h["key"].as_str().unwrap_or_default().to_owned(),
                h["value"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let expect = |name: &str, want: &str| match header(name) {
        Some(v) if v == want => Ok(()),
        other => Err(format!("{name} is {other:?}, want {want}")),
    };
    expect("x-goog-cloud-target-resource", AUDIENCE)?;
    expect("host", &format!("sts.{AWS_REGION}.amazonaws.com"))?;
    expect("x-amz-security-token", AWS_SESSION_TOKEN)?;
    let amz_date = header("x-amz-date").ok_or("no x-amz-date")?;
    // YYYYMMDDTHHMMSSZ sorts as it reads.
    if amz_date < sigv4::amz_date(now - 900).as_str()
        || amz_date > sigv4::amz_date(now + 900).as_str()
    {
        return Err(format!("x-amz-date {amz_date} is not within 15 minutes"));
    }
    let signed: Vec<(String, String)> = headers
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("authorization"))
        .cloned()
        .collect();
    let url = reqwest::Url::parse(&url).expect("the fake's verification URL parses");
    let want = sigv4::authorization("POST", &url, &signed, "sts", &fake_aws(), amz_date);
    if header("authorization") != Some(want.as_str()) {
        return Err("signature does not verify".into());
    }
    Ok(())
}

/// IAM credentials `generateAccessToken` for [`CLIENT_EMAIL`]: takes a
/// federated token STS issued and grants an FCM-scoped access token.
async fn generate_access_token(
    State(inner): State<Shared>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Answer {
    let mut inner = inner.lock().expect("fake FCM state");
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !bearer.is_some_and(|t| inner.federated.iter().any(|f| f == t)) {
        return answer(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({ "error": { "code": 401, "status": "UNAUTHENTICATED" } }),
        );
    }
    let scoped = body["scope"]
        .as_array()
        .is_some_and(|s| s.iter().any(|v| v == FCM_SCOPE));
    let lifetime = body["lifetime"]
        .as_str()
        .and_then(|l| l.strip_suffix('s'))
        .and_then(|l| l.parse::<u64>().ok())
        .filter(|l| (1..=43200).contains(l));
    let (true, Some(lifetime)) = (scoped, lifetime) else {
        return answer(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": { "code": 400, "status": "INVALID_ARGUMENT",
                "message": "scope must include firebase.messaging; lifetime is \"<1..43200>s\"" } }),
        );
    };
    let issued = format!("fake-access-token-{}", inner.issued.len() + 1);
    inner.issued.push(issued.clone());
    let (y, mo, d, h, mi, s) = sigv4::civil(now() + lifetime);
    answer(
        StatusCode::OK,
        serde_json::json!({
            "accessToken": issued,
            "expireTime": format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"),
        }),
    )
}

/// Undo one layer of percent-encoding.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn account(token_uri: &str) -> ServiceAccount {
        ServiceAccount::from_json(
            &serde_json::json!({
                "project_id": PROJECT_ID,
                "client_email": CLIENT_EMAIL,
                "private_key": PRIVATE_KEY_PEM,
                "token_uri": token_uri,
            })
            .to_string(),
        )
        .expect("the testkit service account parses")
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    /// The fixed key's own signature verifies, and a signature with one byte
    /// changed does not: the fake really checks RS256, not just the claims.
    #[test]
    fn the_signature_is_checked_with_the_fixed_key() {
        let uri = "http://fake/token";
        let assertion = account(uri).assertion(now()).expect("sign");
        assert_eq!(check_assertion(&assertion, uri), Ok(()));

        let (signing_input, sig) = assertion.rsplit_once('.').expect("three parts");
        let mut sig = URL_SAFE_NO_PAD.decode(sig).expect("base64url");
        sig[0] ^= 1;
        let tampered = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig));
        assert_eq!(
            check_assertion(&tampered, uri),
            Err("signature does not verify".to_owned())
        );
    }

    /// The fake STS really checks the SigV4 signature, date and session
    /// token: a subject signed with the wrong secret, dated too far back or
    /// without the session token is refused, and nothing is minted.
    #[tokio::test]
    async fn the_fake_sts_refuses_a_subject_it_cannot_verify() {
        let fcm = FakeFcm::start().await;
        let account = ExternalAccount::from_json(&fcm.external_account_json()).unwrap();
        let ok = account.subject_token(&fake_aws(), now()).unwrap();
        assert_eq!(check_subject(&ok, now()), Ok(()));

        let wrong_secret = AwsCredentials {
            secret_access_key: "not-the-secret".into(),
            ..fake_aws()
        };
        let subject = account.subject_token(&wrong_secret, now()).unwrap();
        assert_eq!(
            check_subject(&subject, now()),
            Err("signature does not verify".to_owned())
        );
        let stale = account.subject_token(&fake_aws(), now() - 1000).unwrap();
        assert!(check_subject(&stale, now())
            .unwrap_err()
            .contains("within 15 minutes"));
        let no_session = AwsCredentials {
            session_token: None,
            ..fake_aws()
        };
        let subject = account.subject_token(&no_session, now()).unwrap();
        assert!(check_subject(&subject, now())
            .unwrap_err()
            .starts_with("x-amz-security-token"));

        // End to end: the sender's push fails with STS's reason.
        let sender = fcm.external_account_sender_signing_as(wrong_secret);
        let message = crate::Message {
            priority: crate::Priority::Normal(None),
            data: HashMap::new(),
            ttl: std::time::Duration::from_secs(60),
        };
        match crate::FcmSender::send(&sender, "live-device", &message).await {
            crate::Delivery::Failed { reason } => {
                assert!(
                    reason.starts_with("access-token mint failed: STS token exchange 400"),
                    "{reason}"
                );
                assert!(reason.contains("signature does not verify"), "{reason}");
            }
            other => panic!("expected a mint failure, got {other:?}"),
        }
        assert_eq!((fcm.sts_exchanges(), fcm.tokens_issued()), (0, 0));
        assert!(fcm.sent().is_empty());
    }

    /// A service account the federated identity may not impersonate (the
    /// fake knows only its own) is refused by `generateAccessToken`, and the
    /// push fails with that reason after STS accepted the subject.
    #[tokio::test]
    async fn an_impersonation_google_refuses_is_a_failure() {
        let fcm = FakeFcm::start().await;
        let mut config: serde_json::Value =
            serde_json::from_str(&fcm.external_account_json()).unwrap();
        let url = config["service_account_impersonation_url"]
            .as_str()
            .unwrap()
            .replace(
                CLIENT_EMAIL,
                "someone-else@fake-project.iam.gserviceaccount.com",
            );
        config["service_account_impersonation_url"] = url.into();
        let account = ExternalAccount::from_json(&config.to_string()).unwrap();
        let sender =
            HttpV1Sender::from_external_account(account, fake_aws(), PROJECT_ID, fcm.base.clone())
                .unwrap();
        let message = crate::Message {
            priority: crate::Priority::Normal(None),
            data: HashMap::new(),
            ttl: std::time::Duration::from_secs(60),
        };
        match crate::FcmSender::send(&sender, "live-device", &message).await {
            crate::Delivery::Failed { reason } => assert!(
                reason.starts_with("access-token mint failed: generateAccessToken 404"),
                "{reason}"
            ),
            other => panic!("expected a mint failure, got {other:?}"),
        }
        assert_eq!((fcm.sts_exchanges(), fcm.tokens_issued()), (1, 0));
        assert!(fcm.sent().is_empty());
    }
}
