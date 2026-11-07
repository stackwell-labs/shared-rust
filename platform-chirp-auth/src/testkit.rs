//! Hermetic chirp-auth test tokens.
//!
//! A local JWKS server and real RS256 signing, so a service's tests exercise
//! the SAME verification code (`verify_chirp_id_token` / `verify_from_headers`)
//! production traffic goes through, instead of `decode_trusted_headers`'
//! unauthenticated header-trust bypass.
//!
//! Built on chirp-auth-client's own `testkit` (shared-rust#10): tokens are
//! signed with its fixed [`TestSigningKey`] and keys are served by its
//! [`JwksServer`], so the platform has one test-signing harness and no test
//! build generates an RSA key.
//!
//! ```no_run
//! # async fn example() {
//! use platform_chirp_auth::testkit;
//!
//! let jwks_url = testkit::start_jwks_server().await;
//! let config = testkit::config("https://signin.test.example", "cs_test_aud", jwks_url);
//! let token = testkit::mint_human_id_token("https://signin.test.example", "cs_test_aud", "sub_alice");
//! // Hand `token` to your service's real HTTP auth path (Authorization: Bearer <token>).
//! # let _ = config;
//! # }
//! ```

use std::sync::OnceLock;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{ChirpAuthConfig, ID_TOKEN_TYP};

/// ChirpAuth event tokens for a webhook receiver's tests (shared-rust#17):
/// chirp-auth-client's own event-signing kit, re-exported so those tests need
/// no direct chirp-auth-client dev-dependency. `JwksServer` serves the keys
/// and is the events issuer; `TestSigningKey::sign_event` signs
/// `user_deleted_claims` the way Chirp does, for `crate::verify_chirp_event`.
///
/// ```no_run
/// # async fn example() {
/// use platform_chirp_auth::testkit::{user_deleted_claims, JwksServer, TestSigningKey};
/// use platform_chirp_auth::ChirpAuthConfig;
///
/// let key = TestSigningKey::new("event_test_1");
/// let server = JwksServer::start(vec![key.jwk()]).await;
/// let config = ChirpAuthConfig::new(server.issuer(), "cs_test_app");
/// let now = std::time::SystemTime::now()
///     .duration_since(std::time::UNIX_EPOCH)
///     .unwrap()
///     .as_secs() as i64;
/// let token = key.sign_event(&user_deleted_claims(server.issuer(), "cs_test_app", "sub_1", "evt_1", now));
/// # let _ = (config, token);
/// # }
/// ```
pub use chirp_auth_client::testkit::{user_deleted_claims, JwksServer, TestSigningKey};

/// The `kid` every testkit-minted token and the testkit JWKS agree on.
pub const TEST_KID: &str = "platform-testkit-kid-1";

/// The one key every testkit-minted token is signed with and every testkit
/// JWKS publishes: chirp-auth-client's fixed primary test key, under
/// [`TEST_KID`].
fn signing_key() -> &'static TestSigningKey {
    static KEY: OnceLock<TestSigningKey> = OnceLock::new();
    KEY.get_or_init(|| TestSigningKey::new(TEST_KID))
}

/// Start a [`JwksServer`] publishing the testkit key on the current runtime.
async fn start_issuer() -> JwksServer {
    JwksServer::start(vec![signing_key().jwk()]).await
}

/// Bind `127.0.0.1:0` and serve the testkit JWKS to every request until the
/// test process exits. Returns the `http://host:port/jwks.json` URL to pass
/// to [`config`] (or directly to `ChirpAuthConfig::with_jwks_uri`).
///
/// The server runs on the CURRENT tokio runtime, so it dies with it: a
/// `#[tokio::test]` gets a fresh runtime per test. For a server shared across
/// tests, use [`Fixture::global`].
pub async fn start_jwks_server() -> String {
    format!("{}/jwks.json", start_issuer().await.issuer())
}

/// Answer every request on `listener` with API Gateway's 429 throttle,
/// whatever the path. (`JwksServer` only ever answers 200.)
async fn serve_throttled(listener: TcpListener) {
    const BODY: &str = r#"{"message":"Too Many Requests"}"#;
    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                BODY.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// A process-wide pair of local ChirpAuth issuers for tests: one serving the
/// testkit JWKS, one answering every JWKS fetch with a 429 throttle.
///
/// Both run on a dedicated thread with its own runtime that lives as long as
/// the test process, so every test in a binary, whatever its runtime, can use
/// them. (Services each carried a copy of that thread-plus-`pending` dance.)
///
/// An issuer here is a plain `http://127.0.0.1:{port}` base, so the JWKS URL
/// derives from it exactly as in production and an [`Authenticator`] needs no
/// test-only override:
///
/// ```ignore
/// let fixture = Fixture::global();
/// let auth = Authenticator::new(Policy { issuer: fixture.issuer().to_owned(), .. })?;
/// let token = mint_human_id_token(fixture.issuer(), "cs_my_rp", "sub_alice");
/// // and for the outage path, `fixture.throttled_issuer()`: a valid token gets a 503.
/// ```
///
/// [`Authenticator`]: crate::Authenticator
#[derive(Debug)]
pub struct Fixture {
    issuer: String,
    throttled_issuer: String,
}

impl Fixture {
    /// The process-wide fixture, started on first use.
    pub fn global() -> &'static Fixture {
        static FIXTURE: OnceLock<Fixture> = OnceLock::new();
        FIXTURE.get_or_init(|| {
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::Builder::new()
                .name("platform-chirp-auth-testkit".to_owned())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("testkit fixture runtime");
                    runtime.block_on(async move {
                        // The JwksServer's accept loop is a task on this
                        // runtime, which `serve_throttled` keeps alive forever.
                        let live = start_issuer().await;
                        let throttled = TcpListener::bind("127.0.0.1:0")
                            .await
                            .expect("bind testkit throttled issuer");
                        let urls = (
                            live.issuer().to_owned(),
                            format!("http://{}", throttled.local_addr().expect("throttled addr")),
                        );
                        sender.send(urls).expect("testkit fixture caller went away");
                        serve_throttled(throttled).await;
                    });
                })
                .expect("spawn testkit fixture thread");
            let (issuer, throttled_issuer) =
                receiver.recv().expect("testkit fixture failed to start");
            Fixture {
                issuer,
                throttled_issuer,
            }
        })
    }

    /// A production-style issuer whose JWKS verifies every testkit-minted token.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The test-keyset issuer for `tenant` (`{issuer}/test/{tenant}`), served
    /// by the same JWKS. Tokens for it come from [`mint_test_id_token`] (a
    /// person) or [`mint_machine_id_token`].
    pub fn test_issuer(&self, tenant: &str) -> String {
        format!("{}/test/{tenant}", self.issuer)
    }

    /// An issuer whose JWKS endpoint always answers 429, as ChirpAuth's API
    /// Gateway does when throttled. A valid token for it cannot be checked.
    pub fn throttled_issuer(&self) -> &str {
        &self.throttled_issuer
    }
}

/// An id_token with the header ChirpAuth stamps on one, signed by the testkit
/// key, carrying `claims` plus an `exp` an hour out.
fn mint_id_token(mut claims: Value) -> String {
    claims["exp"] = json!(now_unix() + 3600);
    signing_key().sign(
        &json!({"alg": "RS256", "typ": ID_TOKEN_TYP, "kid": TEST_KID}),
        &claims,
    )
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}

/// Mint a real, signed HUMAN chirp id_token: `{iss, sub, aud, exp}`, no
/// `act` claim — verifies as `ChirpVerifiedIdentity::Human`.
pub fn mint_human_id_token(iss: &str, aud: &str, sub: &str) -> String {
    mint_id_token(json!({"iss": iss, "sub": sub, "aud": aud}))
}

/// Mint a real, signed MACHINE chirp id_token: `{iss, sub, aud, exp,
/// act:"machine", owner_sub}` — verifies as `ChirpVerifiedIdentity::Machine`.
/// `sub` is the machine's own agent sub; `owner_sub` is the human who
/// registered the client; `aud` is conventionally the client_id.
pub fn mint_machine_id_token(iss: &str, aud: &str, sub: &str, owner_sub: &str) -> String {
    mint_id_token(json!({
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "act": "machine",
        "owner_sub": owner_sub,
    }))
}

/// Mint a real, signed TEST-keyset chirp id_token for a person: `{iss, sub,
/// aud, exp, test: true}`. Verifies as `ChirpVerifiedIdentity::Test` against a
/// `…/test/{tenant}` issuer (see [`Fixture::test_issuer`]).
pub fn mint_test_id_token(iss: &str, aud: &str, sub: &str) -> String {
    mint_id_token(json!({"iss": iss, "sub": sub, "aud": aud, "test": true}))
}

/// A `ChirpAuthConfig` pointed at the testkit's local mock JWKS server —
/// pass the URL [`start_jwks_server`] returned.
pub fn config(iss: &str, aud: &str, jwks_url: String) -> ChirpAuthConfig {
    ChirpAuthConfig::new(iss, aud).with_jwks_uri(jwks_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_chirp_id_token, ChirpVerifiedIdentity, VerifyOptions};

    #[tokio::test(flavor = "multi_thread")]
    async fn mints_a_human_token_that_verifies_for_real() {
        let jwks = start_jwks_server().await;
        let cfg = config("https://signin.test.example", "cs_test_aud", jwks);
        let token = mint_human_id_token("https://signin.test.example", "cs_test_aud", "sub_alice");
        let verified = verify_chirp_id_token(
            &reqwest::Client::new(),
            &cfg,
            &token,
            VerifyOptions::default(),
        )
        .await
        .expect("testkit token must verify against the testkit config");
        match verified.identity {
            ChirpVerifiedIdentity::Human { sub, .. } => assert_eq!(sub, "sub_alice"),
            other => panic!("expected Human, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mints_a_machine_token_that_verifies_for_real() {
        let jwks = start_jwks_server().await;
        let cfg = config("https://signin.test.example", "cs_test_client", jwks);
        let token = mint_machine_id_token(
            "https://signin.test.example",
            "cs_test_client",
            "agent_bot1",
            "sub_alice",
        );
        let opts = VerifyOptions::accept_machine_clients(["cs_test_client".to_owned()]);
        let verified = verify_chirp_id_token(&reqwest::Client::new(), &cfg, &token, opts)
            .await
            .expect("testkit machine token must verify");
        match verified.identity {
            ChirpVerifiedIdentity::Machine { sub, owner_sub, .. } => {
                assert_eq!(sub, "agent_bot1");
                assert_eq!(owner_sub, "sub_alice");
            }
            other => panic!("expected Machine, got {other:?}"),
        }
    }

    /// A token whose signature the testkit JWKS does not hold is rejected:
    /// the testkit path checks signatures for real.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_signed_by_another_key_fails_to_verify() {
        let jwks = start_jwks_server().await;
        let cfg = config("https://signin.test.example", "cs_test_aud", jwks);
        let foreign = TestSigningKey::other(TEST_KID).sign(
            &json!({"alg": "RS256", "typ": ID_TOKEN_TYP, "kid": TEST_KID}),
            &json!({
                "iss": "https://signin.test.example",
                "sub": "sub_alice",
                "aud": "cs_test_aud",
                "exp": now_unix() + 3600,
            }),
        );
        let result = verify_chirp_id_token(
            &reqwest::Client::new(),
            &cfg,
            &foreign,
            VerifyOptions::default(),
        )
        .await;
        assert!(result.is_err(), "a foreign signature must be rejected");
    }

    /// A well-signed token for another audience is rejected: the testkit path
    /// runs real claim validation, not just a signature check.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_for_another_audience_fails_to_verify() {
        let jwks = start_jwks_server().await;
        let cfg = config("https://signin.test.example", "cs_test_aud", jwks);
        let token = mint_human_id_token(
            "https://signin.test.example",
            "cs_someone_else",
            "sub_alice",
        );
        let result = verify_chirp_id_token(
            &reqwest::Client::new(),
            &cfg,
            &token,
            VerifyOptions::default(),
        )
        .await;
        assert!(result.is_err(), "wrong audience must be rejected");
    }
}
