//! The synthetic user against a REAL ChirpAuth: `chirp-service` built with
//! `--features local-serve`, run as a hermetic local issuer (in-memory store,
//! generated keys, nothing leaves the machine).
//!
//! The only privileged call is registering the relying party through the
//! local control API, which is what an operator does for a real app. The
//! user's own steps use only the public flows.
//!
//! Ignored by default because it needs that binary. `../issuer` builds it at
//! a pinned revision, and amber-ci's `synthetic-user` job runs these tests
//! against it:
//!
//! ```sh
//! cargo build --locked --manifest-path platform-synthetic-user/issuer/Cargo.toml
//! CHIRP_AUTH_SERVICE_BIN=platform-synthetic-user/issuer/target/debug/chirp-service \
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
    sign_in_by_link, Error, FileStore, Issuer, Mailbox, PublicClient, StateStore, SyntheticUser,
    UserState,
};
use serde_json::{json, Value};
use sha2::Digest;

/// The fixed control token of chirp-auth's local issuer (`local_serve.rs`).
const LOCAL_CONTROL_TOKEN: &str = "local-control-token";
const CLIENT_ID: &str = "cs_dev_synthetic_user_journey";
const REDIRECT_URI: &str = "http://127.0.0.1:9/callback";
/// The client the local issuer binds `chirp.control` to, as live binds it to
/// `cs_live_chirpcli`, with chirp-operator's loopback redirect.
const CLI_CLIENT_ID: &str = "cs_dev_synthetic_user_cli";
const CLI_REDIRECT_URI: &str = "http://127.0.0.1:3999/auth/callback";

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
        .env("CHIRP_AUTH_CLI_CLIENT_ID", CLI_CLIENT_ID)
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
    register(issuer, "Synthetic user journey", CLIENT_ID, REDIRECT_URI).await
}

async fn register(issuer: &str, name: &str, client_id: &str, redirect_uri: &str) {
    let response = reqwest::Client::new()
        .post(format!("{issuer}/control/apps"))
        .bearer_auth(LOCAL_CONTROL_TOKEN)
        .header("origin", issuer)
        .json(&json!({
            "name": name, "issuer": issuer, "client_id": client_id,
            "environment": "dev", "redirect_uris": [redirect_uri],
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
    verified_sub_for(issuer, CLIENT_ID, signed_in).await
}

async fn verified_sub_for(
    issuer: &str,
    client_id: &str,
    signed_in: &platform_synthetic_user::SignIn,
) -> String {
    let config = ChirpAuthConfig::new(issuer, client_id);
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

fn claims(jwt: &str) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(jwt.split('.').nth(1).unwrap())
            .unwrap(),
    )
    .unwrap()
}

/// `chirp.control` is granted only to a signed-in browser that then clicks
/// "Continue as": a fresh-browser sign-in is refused, and the consented one
/// returns a control access token ChirpAuth's control plane accepts.
#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn a_consented_sign_in_holds_a_control_token() {
    let local = start_issuer().await;
    let issuer = local.issuer.clone();
    register(&issuer, "Chirp CLI", CLI_CLIENT_ID, CLI_REDIRECT_URI).await;
    let dir = scratch_dir("consent");
    let live = dir.join("user.json");
    enroll(&issuer, &live).await;
    let cli = PublicClient {
        client_id: CLI_CLIENT_ID.into(),
        redirect_uri: CLI_REDIRECT_URI.into(),
        scope: "openid chirp.control".into(),
    };

    // A fresh browser is refused: the sign-in page has no consent step.
    let mut user = load(&issuer, FileStore::new(&live)).await;
    match user.sign_in(&cli).await {
        Err(Error::Protocol {
            step: "authorize",
            detail,
        }) => {
            assert!(detail.contains("login_required"), "{detail}")
        }
        other => panic!("chirp.control without a session must be refused, got {other:?}"),
    }

    // Through a session and the click: a code, and a control access token.
    let signed_in = user
        .sign_in_with_consent(&cli)
        .await
        .expect("consented sign-in");
    let id = claims(&signed_in.id_token);
    assert_eq!(id["aud"], CLI_CLIENT_ID);
    assert_eq!(id["nonce"], signed_in.nonce.as_str());
    let access = signed_in.token_response["access_token"]
        .as_str()
        .expect("a chirp.control sign-in returns an access token");
    let control = claims(access);
    assert_eq!(control["aud"], "chirp-control");
    assert_eq!(control["sub"], id["sub"], "the same pairwise sub");
    eprintln!("consented sign-in: control token for sub {}", id["sub"]);

    // The control plane verifies it: the account is simply not a developer
    // yet (403), where an unverifiable token is 401.
    let me = |token: &str| {
        reqwest::Client::new()
            .get(format!("{issuer}/control/developers/me"))
            .bearer_auth(token.to_string())
            .send()
    };
    assert_eq!(
        me(access).await.unwrap().status(),
        403,
        "verified, not a developer"
    );
    assert_eq!(
        me(&signed_in.id_token).await.unwrap().status(),
        401,
        "an RP id_token is not a control token"
    );

    // Each call makes and signs out its own session, so it repeats.
    let again = user.sign_in_with_consent(&cli).await.expect("again");
    assert_eq!(claims(&again.id_token)["sub"], id["sub"]);

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

/// Erasure end to end: a user who signed in to a client deletes the account
/// through the hosted page. Afterwards the store is refused, the account no
/// longer signs in, and the client has a deletion event for the user's `sub`
/// in the issuer's outbox.
#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn synthetic_user_deletes_its_account() {
    let local = start_issuer().await;
    let issuer = local.issuer.clone();
    register_public_client(&issuer).await;
    let dir = scratch_dir("delete");
    let live = dir.join("user.json");
    let stale = dir.join("before.json");

    enroll(&issuer, &live).await;
    let sub = sub_of(&issuer, &live).await;
    std::fs::copy(&live, &stale).unwrap();

    let mut user = load(&issuer, FileStore::new(&live)).await;
    user.delete_account().await.expect("delete");
    let deleted = FileStore::new(&live).load().await.unwrap().unwrap();
    assert!(deleted.is_deleted() && !deleted.is_deleting());
    eprintln!("deleted {}", deleted.account().unwrap().account_id);

    // The store, and this value, refuse every flow from now on.
    assert!(
        matches!(user.sign_in(&client()).await, Err(Error::State(_))),
        "a deleted user refuses to sign in"
    );
    assert!(
        matches!(
            SyntheticUser::load(Issuer::new(&issuer).unwrap(), FileStore::new(&live)).await,
            Err(Error::State(_))
        ),
        "a deleted store refuses to load"
    );
    user.delete_account()
        .await
        .expect("deleting again is a no-op");

    // ChirpAuth refuses the account: a copy of the state from before the
    // deletion, key and all, can no longer start a sign-in.
    let mut ghost = load(&issuer, FileStore::new(&stale)).await;
    match ghost.sign_in(&client()).await {
        Err(Error::Rejected {
            step: "passkey start",
            status,
            body,
        }) => {
            assert_eq!(status, 400, "{body}");
            assert!(body.contains("passkey unavailable"), "{body}");
        }
        other => panic!("a deleted account must not sign in, got {other:?}"),
    }
    eprintln!("the deleted account no longer signs in");

    // The client the user signed in to is told, under the user's sub there.
    let events: Value = reqwest::Client::new()
        .get(format!("{issuer}/control/apps/deletion-events"))
        .query(&[("client_id", CLIENT_ID)])
        .bearer_auth(LOCAL_CONTROL_TOKEN)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .expect("deletion events")
        .json()
        .await
        .unwrap();
    let events = events["events"].as_array().expect("an events list");
    assert_eq!(events.len(), 1, "one event for one deletion: {events:?}");
    assert_eq!(events[0]["client_id"], CLIENT_ID);
    assert_eq!(events[0]["sub"], sub.as_str());
    eprintln!("deletion event for {CLIENT_ID}: {}", events[0]);

    std::fs::remove_dir_all(&dir).unwrap();
}

/// A deletion saves three times: the sign-in's counter, the session that
/// will ask for the deletion, and the end. Cut short after the session is
/// saved, it resumes through that session with no new sign-in (the counter
/// does not move). A saved session ChirpAuth no longer knows is replaced by
/// a fresh sign-in.
#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn a_deletion_cut_short_resumes_from_the_store() {
    let local = start_issuer().await;
    let issuer = local.issuer.clone();
    let dir = scratch_dir("delete-resume");

    // Crash after saving the session, before the deletion is sent.
    let live = dir.join("user.json");
    enroll(&issuer, &live).await;
    let mut user = load(
        &issuer,
        CrashAfter {
            inner: FileStore::new(&live),
            saves_left: 2,
        },
    )
    .await;
    let crashed = user.delete_account().await;
    assert!(matches!(crashed, Err(Error::Store(_))), "{crashed:?}");
    drop(user);
    let cut = FileStore::new(&live).load().await.unwrap().unwrap();
    assert!(cut.is_deleting());
    let counter = cut.credential().sign_count();

    let mut user = load(&issuer, FileStore::new(&live)).await;
    assert!(
        matches!(user.sign_in(&client()).await, Err(Error::State(_))),
        "no flow but deletion while one is pending"
    );
    user.delete_account().await.expect("resume the deletion");
    let after = FileStore::new(&live).load().await.unwrap().unwrap();
    assert!(after.is_deleted());
    assert_eq!(
        after.credential().sign_count(),
        counter,
        "resumed through the saved session, not a new sign-in"
    );
    eprintln!("resumed through the saved session");

    // A saved session the issuer does not know: sign in afresh and finish.
    let live = dir.join("other.json");
    enroll(&issuer, &live).await;
    let mut state: Value = serde_json::from_slice(&std::fs::read(&live).unwrap()).unwrap();
    state["deletion"] = json!({ "requested": { "session": "chirp_auth_session=gone" } });
    std::fs::write(&live, serde_json::to_vec(&state).unwrap()).unwrap();
    let mut user = load(&issuer, FileStore::new(&live)).await;
    user.delete_account()
        .await
        .expect("delete after the saved session was refused");
    let after = FileStore::new(&live).load().await.unwrap().unwrap();
    assert!(after.is_deleted());
    assert_eq!(after.credential().sign_count(), 1, "one fresh sign-in");
    eprintln!("an unknown saved session was replaced by a fresh sign-in");

    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn an_open_session_reads_the_account_pages_until_signed_out() {
    let local = start_issuer().await;
    let issuer = local.issuer.clone();
    let dir = scratch_dir("session");
    let live = dir.join("user.json");
    enroll(&issuer, &live).await;

    let mut user = load(&issuer, FileStore::new(&live)).await;
    let session = user.open_session().await.expect("open session");
    assert!(session.cookie().starts_with("chirp_auth_session="));
    let cookie = session.cookie().to_string();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let consents = |cookie: String| {
        let http = http.clone();
        let url = format!("{issuer}/account/consents");
        async move { http.get(url).header("cookie", cookie).send().await.unwrap() }
    };
    let page = consents(cookie.clone()).await;
    assert_eq!(
        page.status(),
        200,
        "the session reads its own consents page"
    );

    session
        .sign_out(&Issuer::new(&issuer).unwrap())
        .await
        .expect("sign out");
    let after = consents(cookie).await;
    assert_ne!(after.status(), 200, "a signed-out session reads nothing");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// A stand-in for scrawl's mailbox-token API (`GET /v1/messages`,
/// `GET /v1/messages/:id`), fed from the local issuer's test outbox. The
/// local issuer mails nothing, but captures the link of a sign-in to a UUID
/// "address" under that UUID; the fake turns each new capture into the mail
/// ChirpAuth would send (its text part's link and reference).
mod fake_scrawl {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    pub const TOKEN: &str = "scrawl_mbx_fake";

    struct Inner {
        issuer: String,
        key: String,
        deliver: bool,
        /// Traces already turned into mail (or never to be).
        seen: HashSet<String>,
        /// Another sign-in's captured link, delivered as the newest mail
        /// right after the first real one.
        decoy: Option<Value>,
        /// (id, text), oldest first.
        mail: Vec<(String, String)>,
    }

    #[derive(Clone)]
    struct Fake(Arc<Mutex<Inner>>);

    /// Serve the fake; returns its origin. `decoy`'s trace is never
    /// delivered as itself, only as the decoy.
    pub async fn start(issuer: &str, key: &str, deliver: bool, decoy: Option<Value>) -> String {
        let seen = decoy
            .iter()
            .map(|link| link["trace_id"].as_str().unwrap().to_string())
            .collect();
        let fake = Fake(Arc::new(Mutex::new(Inner {
            issuer: issuer.into(),
            key: key.into(),
            deliver,
            seen,
            decoy,
            mail: Vec::new(),
        })));
        let app = Router::new()
            .route("/v1/messages", get(list))
            .route("/v1/messages/{id}", get(read))
            .with_state(fake);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        origin
    }

    fn authorized(headers: &HeaderMap) -> bool {
        headers.get("authorization").and_then(|v| v.to_str().ok())
            == Some(&format!("Bearer {TOKEN}"))
    }

    /// ChirpAuth's `reference_id_from_trace`.
    fn reference(trace: &str) -> String {
        const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
        let digest = Sha256::digest(trace.as_bytes());
        let mut out = String::new();
        for (i, &byte) in digest.iter().take(12).enumerate() {
            if i == 4 || i == 8 {
                out.push('-');
            }
            out.push(ALPHABET[usize::from(byte) % ALPHABET.len()] as char);
        }
        out
    }

    /// The text part of ChirpAuth's sign-in mail (`magic-link.txt`).
    fn text(link: &Value) -> String {
        format!(
            "ChirpAuth — sign-in link\n\nSign in to Synthetic link app.\n\nContinue sign-in:\n{}\n\n\
             This link expires in 15 minutes.\n\n---\nReference: {}\n---\n",
            link["verify_url"].as_str().unwrap(),
            reference(link["trace_id"].as_str().unwrap()),
        )
    }

    async fn list(State(fake): State<Fake>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
        if !authorized(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            );
        }
        let (issuer, key, deliver) = {
            let inner = fake.0.lock().unwrap();
            (inner.issuer.clone(), inner.key.clone(), inner.deliver)
        };
        let captured = if deliver {
            super::captured_link(&issuer, &key).await
        } else {
            None
        };
        let mut inner = fake.0.lock().unwrap();
        if let Some(link) = captured {
            if inner
                .seen
                .insert(link["trace_id"].as_str().unwrap().to_string())
            {
                let id = format!("msg_{}", inner.mail.len());
                inner.mail.push((id, text(&link)));
                if let Some(decoy) = inner.decoy.take() {
                    let id = format!("msg_{}", inner.mail.len());
                    inner.mail.push((id, text(&decoy)));
                }
            }
        }
        let summaries: Vec<Value> = inner
            .mail
            .iter()
            .rev()
            .map(|(id, _)| json!({"id": id, "direction": "in", "subject": "Sign in to Synthetic link app — Chirp"}))
            .collect();
        (StatusCode::OK, Json(json!(summaries)))
    }

    async fn read(
        State(fake): State<Fake>,
        headers: HeaderMap,
        Path(id): Path<String>,
    ) -> (StatusCode, Json<Value>) {
        if !authorized(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthorized"})),
            );
        }
        let inner = fake.0.lock().unwrap();
        match inner.mail.iter().find(|(known, _)| *known == id) {
            Some((id, text)) => (StatusCode::OK, Json(json!({"id": id, "text": text}))),
            None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))),
        }
    }
}

/// The link the local issuer captured for a sign-in to the UUID `key`.
async fn captured_link(issuer: &str, key: &str) -> Option<Value> {
    let response = reqwest::Client::new()
        .get(format!("{issuer}/control/test-outbox"))
        .query(&[("key", key)])
        .bearer_auth(LOCAL_CONTROL_TOKEN)
        .send()
        .await
        .unwrap();
    match response.status().as_u16() {
        200 => Some(response.json().await.unwrap()),
        404 => None,
        status => panic!("test outbox: {status}"),
    }
}

/// Start a sign-in by email to `address` for `client` the way the hosted
/// page does, and return the link the local issuer captured for it: another
/// request's mail, for the driver to tell apart from its own.
async fn another_requests_link(issuer: &str, client: &PublicClient, address: &str) -> Value {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(b"another request's verifier"));
    let page = http
        .get(format!("{issuer}/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", client.client_id.as_str()),
            ("redirect_uri", client.redirect_uri.as_str()),
            ("scope", "openid"),
            ("state", "another-request"),
            ("nonce", "another-request"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200, "login page");
    let login_id = page.headers()["x-chirp-auth-login-id"]
        .to_str()
        .unwrap()
        .to_string();
    let sent = http
        .post(format!("{issuer}/login/email"))
        .header("origin", issuer)
        .form(&[("login_id", login_id.as_str()), ("email", address)])
        .send()
        .await
        .unwrap();
    assert_eq!(sent.status(), 200, "email sent");
    captured_link(issuer, address).await.expect("link captured")
}

const LINK_CLIENT_ID: &str = "cs_dev_synthetic_user_link";
/// Not loopback, so the link ends on ChirpAuth's "Signing you in" page
/// rather than a plain redirect.
const LINK_REDIRECT_URI: &str = "https://app.example/callback";

#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn signs_in_by_link_following_its_own_mail() {
    let local = start_issuer().await;
    let issuer = local.issuer.clone();
    register_public_client(&issuer).await;
    register(
        &issuer,
        "Synthetic link app",
        LINK_CLIENT_ID,
        LINK_REDIRECT_URI,
    )
    .await;
    let link_client = PublicClient {
        client_id: LINK_CLIENT_ID.into(),
        redirect_uri: LINK_REDIRECT_URI.into(),
        scope: "openid".into(),
    };
    // A UUID is the local issuer's test mailbox: its link is captured, not
    // mailed. The fake scrawl serves it as mail.
    let address = "6f1c2c1e-6c55-4c0e-9d64-3a0f6d0c1b2a";
    // Another sign-in to the same address, whose mail arrives just after
    // ours and so is the newest: following it would hand back that
    // request's `state`, which the redeem refuses.
    let decoy = another_requests_link(&issuer, &link_client, address).await;
    let scrawl = fake_scrawl::start(&issuer, address, true, Some(decoy)).await;
    let mailbox = Mailbox::new(&scrawl, address, fake_scrawl::TOKEN).unwrap();
    let chirp = Issuer::new(&issuer).unwrap();

    let first = sign_in_by_link(&chirp, &link_client, &mailbox)
        .await
        .expect("link sign-in past a newer mail of another request");
    let sub = verified_sub_for(&issuer, LINK_CLIENT_ID, &first).await;
    eprintln!("signed in by link through the interstitial: sub {sub}");

    let again = sign_in_by_link(&chirp, &link_client, &mailbox)
        .await
        .expect("second link sign-in");
    assert_eq!(
        verified_sub_for(&issuer, LINK_CLIENT_ID, &again).await,
        sub,
        "the address is one account: same app, same sub"
    );

    let loopback = sign_in_by_link(&chirp, &client(), &mailbox)
        .await
        .expect("link sign-in to a loopback client (a plain redirect)");
    let other = verified_sub(&issuer, &loopback).await;
    assert_ne!(other, sub, "pairwise: another app, another sub");
    eprintln!("signed in by link through a redirect: sub {other}");
}

#[tokio::test]
#[ignore = "needs CHIRP_AUTH_SERVICE_BIN (chirp-service --features local-serve)"]
async fn a_link_sign_in_with_no_mail_fails_naming_what_it_waited_for() {
    let local = start_issuer().await;
    let issuer = local.issuer.clone();
    register_public_client(&issuer).await;
    let address = "0b0e9d36-1f86-4a8e-8f3c-2c7f5a1e9b44";
    let scrawl = fake_scrawl::start(&issuer, address, false, None).await;
    let chirp = Issuer::new(&issuer).unwrap();

    let mailbox = Mailbox::new(&scrawl, address, fake_scrawl::TOKEN)
        .unwrap()
        .with_wait(Duration::from_secs(3));
    let started = Instant::now();
    let error = sign_in_by_link(&chirp, &client(), &mailbox)
        .await
        .expect_err("no mail arrives");
    let message = error.to_string();
    eprintln!("{message}");
    assert!(
        matches!(
            error,
            Error::Protocol {
                step: "sign-in mail",
                ..
            }
        ),
        "{message}"
    );
    assert!(
        message.contains(address) && message.contains("with reference"),
        "names the address and the reference: {message}"
    );
    assert!(started.elapsed() < Duration::from_secs(10), "bounded");

    let wrong = Mailbox::new(&scrawl, address, "scrawl_mbx_wrong").unwrap();
    let refused = sign_in_by_link(&chirp, &client(), &wrong).await;
    assert!(
        matches!(
            refused,
            Err(Error::Rejected {
                step: "scrawl list",
                status: 401,
                ..
            })
        ),
        "a bad mailbox token fails at once: {refused:?}"
    );
}
