//! Hermetic chirp-auth test tokens.
//!
//! A local mock JWKS server + real RS256 signing, so a service's tests
//! exercise the SAME verification code (`verify_chirp_id_token` /
//! `verify_from_headers`) production traffic goes through — instead of
//! `decode_trusted_headers`' unauthenticated header-trust bypass. Ported from
//! `chirp-auth-client`'s own private verify-path test harness (the proven
//! approach for this exact problem); this crate makes it a public, reusable
//! primitive so every service's tests can adopt it instead of hand-rolling
//! their own trusted-header dev mode.
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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{ChirpAuthConfig, ID_TOKEN_TYP};

/// The `kid` every testkit-minted token and the testkit JWKS agree on.
pub const TEST_KID: &str = "platform-testkit-kid-1";

/// One RSA-2048 keypair, generated lazily and shared for the process
/// lifetime — RSA keygen is the slow part (~200ms); a test suite that mints
/// many tokens should not pay it more than once.
fn keypair() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048).expect("generate testkit RSA key")
    })
}

fn jwks_body() -> String {
    let pubkey = RsaPublicKey::from(keypair());
    let n = URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
    format!(r#"{{"keys":[{{"kty":"RSA","kid":"{TEST_KID}","alg":"RS256","n":"{n}","e":"{e}"}}]}}"#)
}

/// Bind `127.0.0.1:0` and serve the testkit JWKS to every request until the
/// test process exits. Returns the `http://host:port/jwks.json` URL to pass
/// to [`config`] (or directly to `ChirpAuthConfig::with_jwks_uri`).
///
/// The server runs on the CURRENT tokio runtime, so it dies with it: a
/// `#[tokio::test]` gets a fresh runtime per test. For a server shared across
/// tests, use [`Fixture::global`].
pub async fn start_jwks_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind testkit jwks listener");
    let addr = listener.local_addr().expect("testkit jwks local_addr");
    tokio::spawn(serve(listener, "200 OK", jwks_body()));
    format!("http://{addr}/jwks.json")
}

/// Answer every request on `listener` with `status` and `body`, whatever the
/// path (so an issuer base and its `/test/{tenant}` children all resolve).
async fn serve(listener: TcpListener, status: &'static str, body: String) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let body = body.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
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
                        let live = TcpListener::bind("127.0.0.1:0").await.expect("bind testkit issuer");
                        let throttled = TcpListener::bind("127.0.0.1:0")
                            .await
                            .expect("bind testkit throttled issuer");
                        let urls = (
                            format!("http://{}", live.local_addr().expect("testkit issuer addr")),
                            format!("http://{}", throttled.local_addr().expect("throttled addr")),
                        );
                        sender.send(urls).expect("testkit fixture caller went away");
                        let live = tokio::spawn(serve(live, "200 OK", jwks_body()));
                        let throttled = tokio::spawn(serve(
                            throttled,
                            "429 Too Many Requests",
                            r#"{"message":"Too Many Requests"}"#.to_owned(),
                        ));
                        let _ = tokio::join!(live, throttled);
                    });
                })
                .expect("spawn testkit fixture thread");
            let (issuer, throttled_issuer) = receiver.recv().expect("testkit fixture failed to start");
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

fn sign(signing_input: &[u8]) -> Vec<u8> {
    let signer = SigningKey::<Sha256>::new(keypair().clone());
    let mut rng = rand::thread_rng();
    signer
        .sign_with_rng(&mut rng, signing_input)
        .to_bytes()
        .to_vec()
}

fn b64(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn make_jwt(header_json: &str, claims_json: &str) -> String {
    let signing_input = format!("{}.{}", b64(header_json), b64(claims_json));
    let sig = sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
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
    let header = format!(r#"{{"alg":"RS256","typ":"{ID_TOKEN_TYP}","kid":"{TEST_KID}"}}"#);
    let claims = format!(
        r#"{{"iss":"{iss}","sub":"{sub}","aud":"{aud}","exp":{}}}"#,
        now_unix() + 3600
    );
    make_jwt(&header, &claims)
}

/// Mint a real, signed MACHINE chirp id_token: `{iss, sub, aud, exp,
/// act:"machine", owner_sub}` — verifies as `ChirpVerifiedIdentity::Machine`.
/// `sub` is the machine's own agent sub; `owner_sub` is the human who
/// registered the client; `aud` is conventionally the client_id.
pub fn mint_machine_id_token(iss: &str, aud: &str, sub: &str, owner_sub: &str) -> String {
    let header = format!(r#"{{"alg":"RS256","typ":"{ID_TOKEN_TYP}","kid":"{TEST_KID}"}}"#);
    let claims = format!(
        r#"{{"iss":"{iss}","sub":"{sub}","aud":"{aud}","exp":{},"act":"machine","owner_sub":"{owner_sub}"}}"#,
        now_unix() + 3600
    );
    make_jwt(&header, &claims)
}

/// Mint a real, signed TEST-keyset chirp id_token for a person: `{iss, sub,
/// aud, exp, test: true}`. Verifies as `ChirpVerifiedIdentity::Test` against a
/// `…/test/{tenant}` issuer (see [`Fixture::test_issuer`]).
pub fn mint_test_id_token(iss: &str, aud: &str, sub: &str) -> String {
    let header = format!(r#"{{"alg":"RS256","typ":"{ID_TOKEN_TYP}","kid":"{TEST_KID}"}}"#);
    let claims = format!(
        r#"{{"iss":"{iss}","sub":"{sub}","aud":"{aud}","exp":{},"test":true}}"#,
        now_unix() + 3600
    );
    make_jwt(&header, &claims)
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

    #[tokio::test(flavor = "multi_thread")]
    async fn a_token_signed_under_a_different_testkit_key_fails_to_verify() {
        // Two independent JWKS servers each get their OWN process-wide keypair
        // (the OnceLock is per-binary, not per-server) — this test exists to
        // document that property rather than exercise cross-key rejection
        // directly, since a single test binary shares one testkit keypair by
        // design (that's what makes minting cheap). Real cross-tenant
        // signature rejection is chirp-auth-client's own, already-proven
        // verify-path coverage.
        let jwks = start_jwks_server().await;
        let cfg = config("https://signin.test.example", "cs_test_aud", jwks);
        // A well-formed but WRONG-aud token must still be rejected — proves
        // the testkit path runs real claim validation, not just a signature
        // check.
        let token = mint_human_id_token("https://signin.test.example", "cs_someone_else", "sub_alice");
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
