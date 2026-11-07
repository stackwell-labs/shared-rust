//! The synthetic user against a REAL ChirpAuth: `chirp-service` built with
//! `--features local-serve`, run as a hermetic local issuer (in-memory store,
//! generated keys, nothing leaves the machine).
//!
//! The only privileged call is registering the relying party through the
//! local control API, which is what an operator does for a real app. The
//! user's own steps use only the public flows.
//!
//! Ignored by default because it needs that binary:
//!
//! ```sh
//! CHIRP_AUTH_SERVICE_BIN=/path/to/chirp-service \
//!   cargo test -p platform-synthetic-user --test local_issuer -- --ignored --nocapture
//! ```

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chirp_auth_client::{
    verify_chirp_id_token, ChirpAuthConfig, ChirpVerifiedIdentity, VerifyOptions,
};
use platform_synthetic_user::{
    Error, FileStore, Issuer, PublicClient, StateStore, SyntheticUser, UserState,
};
use serde_json::{json, Value};

/// The fixed control token of chirp-auth's local issuer (`local_serve.rs`).
const LOCAL_CONTROL_TOKEN: &str = "local-control-token";
const CLIENT_ID: &str = "cs_dev_synthetic_user_journey";
const REDIRECT_URI: &str = "http://127.0.0.1:9/callback";

struct LocalIssuer {
    child: Child,
    issuer: String,
}

impl Drop for LocalIssuer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start_issuer() -> LocalIssuer {
    let bin = std::env::var("CHIRP_AUTH_SERVICE_BIN")
        .expect("set CHIRP_AUTH_SERVICE_BIN to a chirp-service built with --features local-serve");
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // `localhost`, not an IP: the issuer's host is its WebAuthn rpId.
    let addr = format!("localhost:{port}");
    let child = Command::new(bin)
        .env("CHIRP_AUTH_LOCAL_SERVE", "1")
        .env("CHIRP_AUTH_LOCAL_ADDR", &addr)
        // Hermetic: ignore any operator CLI config in $HOME.
        .env("CHIRP_AUTH_CLI_CONFIG", "/nonexistent/chirp-auth-cli.toml")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn chirp-service");
    let issuer = LocalIssuer {
        child,
        issuer: format!("http://{addr}"),
    };
    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let ready = http
            .get(format!(
                "{}/.well-known/openid-configuration",
                issuer.issuer
            ))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success());
        if ready {
            return issuer;
        }
        assert!(Instant::now() < deadline, "local issuer did not come up");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Register the relying party, as an operator would for a real app.
async fn register_public_client(issuer: &str) {
    let response = reqwest::Client::new()
        .post(format!("{issuer}/control/apps"))
        .bearer_auth(LOCAL_CONTROL_TOKEN)
        .header("origin", issuer)
        .json(&json!({
            "name": "Synthetic user journey", "issuer": issuer, "client_id": CLIENT_ID,
            "environment": "dev", "redirect_uris": [REDIRECT_URI],
            "type": "public", "access": "public",
        }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    assert!(
        status.is_success(),
        "register client: {status} {}",
        response.text().await.unwrap()
    );
}

fn client() -> PublicClient {
    PublicClient {
        client_id: CLIENT_ID.into(),
        redirect_uri: REDIRECT_URI.into(),
        scope: "openid".into(),
    }
}

/// Verify the ID token exactly as a platform RP does, then check its nonce.
async fn verified_sub(issuer: &str, signed_in: &platform_synthetic_user::SignIn) -> String {
    let config = ChirpAuthConfig::new(issuer, CLIENT_ID);
    let verified = verify_chirp_id_token(
        &reqwest::Client::new(),
        &config,
        &signed_in.id_token,
        VerifyOptions::default(),
    )
    .await
    .expect("id_token verifies against the local JWKS");
    let ChirpVerifiedIdentity::Human { sub } = verified.identity else {
        panic!("expected a human identity, got {:?}", verified.identity);
    };
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(signed_in.id_token.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        claims["nonce"],
        signed_in.nonce.as_str(),
        "nonce round-trips"
    );
    sub
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("synthetic-user-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn synthetic_user_enrolls_signs_in_and_cannot_replay_a_counter() {
    let local = start_issuer().await;
    let issuer = local.issuer.clone();
    register_public_client(&issuer).await;
    let dir = scratch_dir("journey");
    let live = dir.join("user.json");

    // 1. Enroll: a real ChirpAuth One account via the public signup ceremony.
    let user = SyntheticUser::enroll(
        Issuer::new(&issuer).unwrap(),
        "Synthetic journey",
        FileStore::new(&live),
    )
    .await
    .expect("enroll");
    let account_id = user.account_id().to_string();
    assert!(account_id.starts_with("usr_"), "account id {account_id}");
    assert!(!user.state().account().unwrap().recovery_codes.is_empty());
    eprintln!("enrolled {account_id}");
    drop(user);

    // Enrolling over an existing user is refused (it would lose the key).
    let again =
        SyntheticUser::enroll(Issuer::new(&issuer).unwrap(), "x", FileStore::new(&live)).await;
    assert!(matches!(again, Err(Error::State(_))), "re-enroll refused");

    // 2. Sign in to a public PKCE client; verify the id_token on the JWKS.
    let mut user = SyntheticUser::load(Issuer::new(&issuer).unwrap(), FileStore::new(&live))
        .await
        .expect("load");
    let first = verified_sub(&issuer, &user.sign_in(&client()).await.expect("sign-in 1")).await;
    assert_eq!(user.state().credential().sign_count(), 1);
    eprintln!("sign-in 1: sub {first}");
    drop(user);

    // Keep a copy of the state as it is now (counter 1), as a stale backup
    // or a second runner holding an old secret would.
    let stale = dir.join("stale.json");
    std::fs::copy(&live, &stale).unwrap();

    // 3. Sign in again from freshly loaded state: same pairwise sub.
    let mut user = SyntheticUser::load(Issuer::new(&issuer).unwrap(), FileStore::new(&live))
        .await
        .unwrap();
    let second = verified_sub(&issuer, &user.sign_in(&client()).await.expect("sign-in 2")).await;
    assert_eq!(first, second, "same user, same app, same sub");
    let persisted = FileStore::new(&live).load().await.unwrap().unwrap();
    assert_eq!(persisted.credential().sign_count(), 2, "counter persisted");
    eprintln!("sign-in 2: same sub, counter 2");
    drop(user);

    // 4. Counter monotonicity: the stale copy signs with counter 2, which the
    //    issuer has already seen. ChirpAuth must refuse it.
    let mut clone = SyntheticUser::load(Issuer::new(&issuer).unwrap(), FileStore::new(&stale))
        .await
        .unwrap();
    let replay = clone.sign_in(&client()).await;
    match &replay {
        Err(Error::Rejected {
            step: "passkey finish",
            status,
            body,
        }) => {
            eprintln!("stale counter refused at passkey finish: HTTP {status}: {body}");
            // A counter <= the stored one is the caller's assertion being
            // refused: ChirpAuth answers 400 and names the counter.
            assert_eq!(*status, 400, "refused as a client error: {body}");
            assert!(
                body.contains("signature counter did not advance"),
                "refused for the counter: {body}"
            );
        }
        other => panic!("a non-increasing counter must be refused, got {other:?}"),
    }
    // The clone's refused attempt was still persisted (write-ahead).
    let stale_state = FileStore::new(&stale).load().await.unwrap().unwrap();
    assert_eq!(stale_state.credential().sign_count(), 2);

    // ...and the refusal is the counter, not a broken issuer: the genuine
    //    state (counter 3) still signs in as the same user.
    let mut user = SyntheticUser::load(Issuer::new(&issuer).unwrap(), FileStore::new(&live))
        .await
        .unwrap();
    let third = verified_sub(&issuer, &user.sign_in(&client()).await.expect("sign-in 3")).await;
    assert_eq!(first, third);
    eprintln!("sign-in 3 with the genuine state: same sub, counter 3");

    std::fs::remove_dir_all(&dir).unwrap();
}

async fn enroll(issuer: &str, live: &std::path::Path) {
    SyntheticUser::enroll(
        Issuer::new(issuer).unwrap(),
        "Synthetic rotation",
        FileStore::new(live),
    )
    .await
    .expect("enroll");
}

async fn load<S: StateStore>(issuer: &str, store: S) -> SyntheticUser<S> {
    SyntheticUser::load(Issuer::new(issuer).unwrap(), store)
        .await
        .expect("load")
}

async fn sub_of(issuer: &str, live: &std::path::Path) -> String {
    let mut user = load(issuer, FileStore::new(live)).await;
    verified_sub(issuer, &user.sign_in(&client()).await.expect("sign-in")).await
}

fn credential_id(state: &UserState) -> Vec<u8> {
    state.credential().credential_id().to_vec()
}

/// A key the issuer no longer holds is refused. ChirpAuth's sign-in start
/// names the account's credentials; once the old one is gone it is not named,
/// so the authenticator refuses before any assertion leaves (as a browser
/// would, with no matching passkey).
async fn assert_refused(issuer: &str, stale: &std::path::Path) {
    let mut user = load(issuer, FileStore::new(stale)).await;
    match user.sign_in(&client()).await {
        Err(Error::Authenticator(why)) => {
            assert!(
                why.contains("allowCredentials"),
                "refused for the key: {why}"
            )
        }
        other => panic!("the old key must be refused, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn synthetic_user_rotates_its_passkey_in_place() {
    let local = start_issuer().await;
    let issuer = local.issuer.clone();
    register_public_client(&issuer).await;
    let dir = scratch_dir("rotate");
    let live = dir.join("user.json");
    let stale = dir.join("before.json");

    enroll(&issuer, &live).await;
    let sub = sub_of(&issuer, &live).await;
    std::fs::copy(&live, &stale).unwrap();
    let before = FileStore::new(&stale).load().await.unwrap().unwrap();

    // Rotate: a new passkey on the same account, the old one removed.
    let mut user = load(&issuer, FileStore::new(&live)).await;
    user.rotate_passkey().await.expect("rotate");
    let after = FileStore::new(&live).load().await.unwrap().unwrap();
    assert!(!after.is_rotating(), "the rotation finished");
    assert_ne!(credential_id(&after), credential_id(&before), "a new key");
    assert_eq!(
        after.account().unwrap().account_id,
        before.account().unwrap().account_id,
        "the same account"
    );
    eprintln!("rotated {}", after.account().unwrap().account_id);

    // The new key signs in as the same user; the old one is refused.
    assert_eq!(sub_of(&issuer, &live).await, sub, "same account, same sub");
    assert_refused(&issuer, &stale).await;
    eprintln!("new key signs in to the same sub; the old key is refused");

    // Rotation left exactly one passkey: a second one starts from there.
    let mut user = load(&issuer, FileStore::new(&live)).await;
    user.rotate_passkey().await.expect("rotate again");
    assert_eq!(sub_of(&issuer, &live).await, sub);
    eprintln!("rotated again: same sub");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// The crash model: every save is durable, and the process dies right after
/// save number `crash_at` (so nothing after it is sent).
struct CrashAfter {
    inner: FileStore,
    saves_left: usize,
}

impl StateStore for CrashAfter {
    async fn load(&self) -> Result<Option<UserState>, Error> {
        self.inner.load().await
    }

    async fn save(&mut self, state: &UserState) -> Result<(), Error> {
        assert!(self.saves_left > 0, "nothing runs after the crash");
        self.inner.save(state).await?;
        self.saves_left -= 1;
        if self.saves_left == 0 {
            return Err(std::io::Error::other("simulated crash after a durable save").into());
        }
        Ok(())
    }
}

/// A rotation saves five times: the old key's sign-in counter, the new key
/// (before its registration is sent), the new key's first counter, its
/// promotion, and the end. Cut it short after each, then resume from what
/// the store holds: the account always signs in as the same user, and once
/// the new key was registered it ends up the only one.
#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn a_rotation_cut_short_at_any_save_resumes_from_the_store() {
    for crash_at in 1..=5 {
        // A fresh issuer each round keeps every round inside the issuer's
        // per-IP sign-in rate limit.
        let local = start_issuer().await;
        let issuer = local.issuer.clone();
        register_public_client(&issuer).await;
        let dir = scratch_dir(&format!("crash-{crash_at}"));
        let live = dir.join("user.json");
        let stale = dir.join("before.json");
        enroll(&issuer, &live).await;
        let sub = sub_of(&issuer, &live).await;
        std::fs::copy(&live, &stale).unwrap();
        let before = FileStore::new(&stale).load().await.unwrap().unwrap();

        let mut user = load(
            &issuer,
            CrashAfter {
                inner: FileStore::new(&live),
                saves_left: crash_at,
            },
        )
        .await;
        let crashed = user.rotate_passkey().await;
        assert!(
            matches!(crashed, Err(Error::Store(_))),
            "crash after save {crash_at}: {crashed:?}"
        );
        drop(user);

        let mut user = load(&issuer, FileStore::new(&live)).await;
        let resumed = user.state().is_rotating();
        if resumed {
            user.rotate_passkey().await.expect("resume the rotation");
        }
        let after = FileStore::new(&live).load().await.unwrap().unwrap();
        assert!(!after.is_rotating());
        assert_eq!(sub_of(&issuer, &live).await, sub, "crash at {crash_at}");
        if crash_at == 1 {
            // Cut short before the new key existed: nothing changed.
            assert!(!resumed);
            assert_eq!(credential_id(&after), credential_id(&before));
        } else {
            assert_ne!(credential_id(&after), credential_id(&before));
            assert_refused(&issuer, &stale).await;
        }
        eprintln!("crash after save {crash_at}: resumed={resumed}, same sub");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
