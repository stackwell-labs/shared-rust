//! ChirpAuth's human flows, driven over plain HTTP.
//!
//! Every request here is one the hosted pages' own scripts make
//! (`extended_signup_script`, `extended_signin_script` in chirp-auth's
//! `pages.rs`), with the browser's WebAuthn call answered by
//! [`crate::Credential`]. No control token, test outbox, or other bypass is
//! used. Each sign-in starts with no cookies, as a fresh browser would; the
//! consented sign-in makes its own session first and signs it out after.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::{redirect, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::authenticator::{
    b64_encode, random_bytes, CreationOptions, Credential, RequestOptions, WebOrigin,
};
use crate::error::protocol;
use crate::state::{Account, Deletion, Key, Rotation, StateStore, UserState};
use crate::Error;

/// The header ChirpAuth's `/authorize` login page carries its login id in;
/// the same id is the page's hidden `login_id` input.
const LOGIN_ID_HEADER: &str = "x-chirp-auth-login-id";
/// ChirpAuth's browser session cookie, which its account surface reads.
const SESSION_COOKIE: &str = "chirp_auth_session";
/// The path ChirpAuth's passkey list links each passkey's remove page under:
/// `/account/passkeys/{passkey_id}/remove`.
const PASSKEY_PATH: &str = "/account/passkeys/";
/// ChirpAuth's account deletion page and form (`account_delete`,
/// `account_delete_submit` in chirp-auth's `handlers/misc.rs`).
const DELETE_PATH: &str = "/account/delete";
/// What the deletion form asks the person to type.
const DELETE_PHRASE: &str = "delete my account";
/// The `<title>` of the page ChirpAuth answers a completed deletion with
/// (`account_deleted_page`). A refused phrase answers 200 too, with the form.
const DELETED_TITLE: &str = "<title>Account deleted</title>";
/// The empty form a bodiless POST from a hosted page submits.
const NO_FORM: &[(&str, &str)] = &[];
const MAX_ERROR_BODY: usize = 300;

/// A ChirpAuth issuer, addressed the way a browser reaches it.
#[derive(Debug, Clone)]
pub struct Issuer {
    issuer: String,
    origin: WebOrigin,
    http: reqwest::Client,
}

impl Issuer {
    /// `issuer` is the `iss` ChirpAuth signs with (no trailing slash), e.g.
    /// `https://signin.chirpauth.com`. It must be a secure context: `https`,
    /// or `http` on a loopback host.
    pub fn new(issuer: &str) -> Result<Self, Error> {
        let issuer = issuer.trim().trim_end_matches('/').to_string();
        let url = Url::parse(&issuer).map_err(|e| Error::State(format!("issuer url: {e}")))?;
        if url.path() != "/" || url.query().is_some() {
            return Err(Error::State("issuer must be a bare origin".into()));
        }
        let origin = WebOrigin::from_issuer(&url)?;
        let http = reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent(concat!(
                "platform-synthetic-user/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;
        Ok(Self {
            issuer,
            origin,
            http,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.issuer
    }

    fn url(&self, path: &str) -> Url {
        // Infallible: `issuer` parsed as a bare origin in `new`.
        Url::parse(&format!("{}{path}", self.issuer)).expect("issuer joins a path")
    }

    /// A POST as the hosted pages' scripts send it: from the issuer's own
    /// origin (which is also what passes ChirpAuth's CSRF gate for a
    /// cookie-bearing request), carrying the account session if there is one.
    fn post(&self, url: Url, session: Option<&AccountSession>) -> reqwest::RequestBuilder {
        let request = self.http.post(url).header("origin", self.issuer.as_str());
        match session {
            Some(session) => request.header("cookie", &session.cookie),
            None => request,
        }
    }

    async fn post_form<T: DeserializeOwned>(
        &self,
        step: &'static str,
        path: &str,
        session: Option<&AccountSession>,
        form: &[(&str, &str)],
    ) -> Result<T, Error> {
        let response = self.post(self.url(path), session).form(form).send().await?;
        json_ok(step, response).await
    }

    async fn post_ceremony(
        &self,
        path: &str,
        session: Option<&AccountSession>,
        ceremony_id: &str,
        body: &Value,
    ) -> Result<Response, Error> {
        let mut url = self.url(path);
        url.query_pairs_mut()
            .append_pair("ceremony_id", ceremony_id);
        Ok(self.post(url, session).json(body).send().await?)
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        step: &'static str,
        path: &str,
        session: Option<&AccountSession>,
        ceremony_id: &str,
        body: &Value,
    ) -> Result<T, Error> {
        let response = self.post_ceremony(path, session, ceremony_id, body).await?;
        json_ok(step, response).await
    }
}

async fn json_ok<T: DeserializeOwned>(step: &'static str, response: Response) -> Result<T, Error> {
    if response.status() != StatusCode::OK {
        return Err(rejected(step, response).await);
    }
    let bytes = response.bytes().await?;
    serde_json::from_slice(&bytes).map_err(|e| protocol(step, format!("response body: {e}")))
}

async fn rejected(step: &'static str, response: Response) -> Error {
    let status = response.status().as_u16();
    let mut body = response.text().await.unwrap_or_default();
    if body.len() > MAX_ERROR_BODY {
        let mut end = MAX_ERROR_BODY;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
        body.push('…');
    }
    Error::Rejected { step, status, body }
}

/// A WebAuthn ceremony as ChirpAuth's start endpoints return it.
#[derive(Deserialize)]
struct Ceremony<T> {
    ceremony_id: String,
    options: T,
}

#[derive(Deserialize)]
struct SignupFinished {
    status: String,
    account_id: String,
    persona_id: String,
    #[serde(default)]
    recovery_codes: Vec<String>,
}

#[derive(Deserialize)]
struct Status {
    status: String,
}

#[derive(Deserialize)]
struct SigninFinished {
    redirect_uri: Option<String>,
    status: Option<String>,
}

/// A relying party registered as a public PKCE client. The driver plays the
/// RP's part too: it builds the `/authorize` request and redeems the code.
#[derive(Debug, Clone)]
pub struct PublicClient {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
}

/// The result of a public-client sign-in. The caller verifies `id_token`
/// (signature, `iss`, `aud`, expiry) with the RP's own verifier, and checks
/// its `nonce` claim against `nonce`.
#[derive(Debug, Clone)]
pub struct SignIn {
    pub id_token: String,
    pub nonce: String,
    /// The full `/token` response.
    pub token_response: Value,
}

/// One `/authorize` request for a public client, with the secrets only its
/// caller holds: the PKCE verifier, and the `state` and `nonce` to check.
struct AuthorizeRequest {
    url: Url,
    verifier: String,
    state: String,
    nonce: String,
}

impl AuthorizeRequest {
    fn new(issuer: &Issuer, client: &PublicClient) -> Result<Self, Error> {
        let verifier = b64_encode(&random_bytes::<32>()?);
        let state = b64_encode(&random_bytes::<16>()?);
        let nonce = b64_encode(&random_bytes::<16>()?);
        let mut url = issuer.url("/authorize");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", &client.redirect_uri)
            .append_pair("scope", &client.scope)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair(
                "code_challenge",
                &b64_encode(&Sha256::digest(verifier.as_bytes())),
            )
            .append_pair("code_challenge_method", "S256");
        Ok(Self {
            url,
            verifier,
            state,
            nonce,
        })
    }

    /// Check the callback is this request's, and redeem its code.
    async fn redeem(
        self,
        issuer: &Issuer,
        client: &PublicClient,
        callback: &Url,
    ) -> Result<SignIn, Error> {
        let step = "callback";
        let mut bare = callback.clone();
        bare.set_query(None);
        if bare.as_str()
            != Url::parse(&client.redirect_uri)
                .map_err(|e| protocol(step, e.to_string()))?
                .as_str()
        {
            return Err(protocol(
                step,
                "code was sent somewhere other than redirect_uri",
            ));
        }
        let params: HashMap<_, _> = callback.query_pairs().into_owned().collect();
        if params.get("state") != Some(&self.state) {
            return Err(protocol(step, "state does not match"));
        }
        let code = params
            .get("code")
            .ok_or_else(|| protocol(step, "no code"))?;

        let response = issuer
            .http
            .post(issuer.url("/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &client.redirect_uri),
                ("client_id", &client.client_id),
                ("code_verifier", &self.verifier),
            ])
            .send()
            .await?;
        let token_response: Value = json_ok("token", response).await?;
        let id_token = token_response["id_token"]
            .as_str()
            .ok_or_else(|| protocol("token", "no id_token"))?
            .to_string();
        Ok(SignIn {
            id_token,
            nonce: self.nonce,
            token_response,
        })
    }
}

/// A real ChirpAuth account held by software, bound to one state store.
pub struct SyntheticUser<S: StateStore> {
    issuer: Issuer,
    state: UserState,
    account: Account,
    store: S,
}

impl<S: StateStore> SyntheticUser<S> {
    /// Create a ChirpAuth One account through the public signup ceremony.
    ///
    /// Refuses a store that already holds a user, so an existing account's
    /// key is never overwritten. The new credential is saved before the
    /// registration is sent, so an account can never exist whose key was
    /// lost; the account is saved again once the issuer confirms it.
    pub async fn enroll(issuer: Issuer, display_name: &str, mut store: S) -> Result<Self, Error> {
        if store.load().await?.is_some() {
            return Err(Error::State(
                "store already holds a synthetic user; refusing to enroll over it".into(),
            ));
        }
        let ceremony: Ceremony<CreationOptions> = issuer
            .post_form(
                "signup start",
                "/signup/passkey/start",
                None,
                &[("display_name", display_name)],
            )
            .await?;
        let (credential, registration) = Credential::register(&issuer.origin, &ceremony.options)?;
        let mut state = UserState::pending(issuer.as_str(), credential);
        store.save(&state).await?;

        let finished: SignupFinished = issuer
            .post_json(
                "signup finish",
                "/signup/passkey/finish",
                None,
                &ceremony.ceremony_id,
                &registration,
            )
            .await?;
        if finished.status != "created" {
            return Err(protocol(
                "signup finish",
                format!("status {:?}", finished.status),
            ));
        }
        let account = Account {
            account_id: finished.account_id,
            persona_id: finished.persona_id,
            recovery_codes: finished.recovery_codes,
        };
        state.set_account(account.clone());
        store.save(&state).await?;
        Ok(Self {
            issuer,
            state,
            account,
            store,
        })
    }

    /// Load an enrolled user. Never creates one: an empty store, a pending
    /// enrollment, a deleted account, or a state for another issuer is an
    /// error.
    pub async fn load(issuer: Issuer, store: S) -> Result<Self, Error> {
        let state = store
            .load()
            .await?
            .ok_or_else(|| Error::State("store holds no synthetic user".into()))?;
        if state.issuer() != issuer.as_str() {
            return Err(Error::State(format!(
                "state is for issuer {:?}, not {:?}",
                state.issuer(),
                issuer.as_str()
            )));
        }
        let account = state
            .account()
            .cloned()
            .ok_or_else(|| Error::State("enrollment never completed".into()))?;
        if state.is_deleted() {
            return Err(Error::State(format!(
                "account {} was deleted; the store is only a record of it",
                account.account_id
            )));
        }
        Ok(Self {
            issuer,
            state,
            account,
            store,
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account.account_id
    }

    pub fn state(&self) -> &UserState {
        &self.state
    }

    /// Complete an interactive `/authorize` request as this user and return
    /// the URL ChirpAuth sends the browser back to (the RP's `redirect_uri`
    /// with `code`, `state` and `iss`).
    ///
    /// `authorize_url` may come from anywhere: built by [`Self::sign_in`]
    /// for a public client, or taken from a server-side RP's login redirect.
    /// The passkey path mints the code itself; with no prior session there
    /// is no separate consent page.
    pub async fn authorize(&mut self, authorize_url: &Url) -> Result<Url, Error> {
        self.ensure_live()?;
        let step = "authorize";
        if authorize_url.origin().ascii_serialization() != self.issuer.as_str()
            || authorize_url.path() != "/authorize"
        {
            return Err(protocol(step, "not this issuer's /authorize endpoint"));
        }
        let response = self.issuer.http.get(authorize_url.clone()).send().await?;
        match response.status() {
            StatusCode::OK => {}
            status if status.is_redirection() => {
                // A fresh browser has no session, so a redirect here is an
                // RFC 6749 error redirect (bad scope, PKCE, ...).
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                return Err(protocol(
                    step,
                    format!("redirected instead of a login page: {}", error_of(location)),
                ));
            }
            _ => return Err(rejected(step, response).await),
        }
        let login_id = response
            .headers()
            .get(LOGIN_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| protocol(step, "login page carried no login id"))?
            .to_string();

        let ceremony: Ceremony<RequestOptions> = self
            .issuer
            .post_form(
                "passkey start",
                "/login/passkey/start",
                None,
                &[
                    ("login_id", &login_id),
                    ("account_id", &self.account.account_id),
                ],
            )
            .await?;
        let assertion = self
            .state
            .next_assertion(
                &mut self.store,
                Key::Current,
                &self.issuer.origin,
                &ceremony.options,
            )
            .await?;
        let finished: SigninFinished = self
            .issuer
            .post_json(
                "passkey finish",
                "/login/passkey/finish",
                None,
                &ceremony.ceremony_id,
                &assertion,
            )
            .await?;
        let Some(redirect) = finished.redirect_uri else {
            return Err(protocol(
                "passkey finish",
                format!("no redirect (status {:?})", finished.status),
            ));
        };
        let redirect =
            Url::parse(&redirect).map_err(|e| protocol("passkey finish", e.to_string()))?;
        let params: HashMap<_, _> = redirect.query_pairs().into_owned().collect();
        if let Some(error) = params.get("error") {
            return Err(protocol(
                "passkey finish",
                format!("RP redirect carries error {error:?}"),
            ));
        }
        // RFC 9207: the code must come from the issuer we meant to talk to.
        if params.get("iss").map(String::as_str) != Some(self.issuer.as_str()) {
            return Err(protocol(
                "passkey finish",
                "redirect iss is not this issuer",
            ));
        }
        if !params.contains_key("code") {
            return Err(protocol("passkey finish", "redirect carries no code"));
        }
        Ok(redirect)
    }

    /// Sign in to a public PKCE client end to end: build the `/authorize`
    /// request (S256, fresh `state` and `nonce`), complete it as this user,
    /// check the callback, and redeem the code at `/token`.
    pub async fn sign_in(&mut self, client: &PublicClient) -> Result<SignIn, Error> {
        let request = AuthorizeRequest::new(&self.issuer, client)?;
        let callback = self.authorize(&request.url).await?;
        request.redeem(&self.issuer, client, &callback).await
    }

    /// Sign in to a public PKCE client the way a returning person does: sign
    /// in to ChirpAuth itself first, open the client's `/authorize` request in
    /// that session, and click "Continue as" on the page it shows. Then the
    /// code is redeemed as in [`Self::sign_in`], and the session signed out.
    ///
    /// This is the only way to a scope ChirpAuth grants only to an
    /// already-signed-in browser after an explicit click: `chirp.control`,
    /// which its CLI client asks for and its operator routes require. A fresh
    /// browser asking for it is refused with `login_required`, because the
    /// sign-in page mints a code with no consent step.
    pub async fn sign_in_with_consent(&mut self, client: &PublicClient) -> Result<SignIn, Error> {
        self.ensure_live()?;
        let request = AuthorizeRequest::new(&self.issuer, client)?;
        let session = self.account_session(Key::Current).await?;
        let callback = session.consent(&self.issuer, &request.url).await;
        // Signed out whatever the outcome, so no live session outlasts the
        // call; a failed consent is the error worth reporting.
        let signed_out = session.sign_out(&self.issuer).await;
        let callback = callback?;
        signed_out?;
        request.redeem(&self.issuer, client, &callback).await
    }

    /// Rotate this account's passkey in place: register a new software
    /// passkey on the account, sign in with it once, then remove the old one.
    /// The account, its id and every grant keyed on it stay as they were;
    /// afterwards the old key is refused and the new one signs in.
    ///
    /// This uses ChirpAuth's own account surface, as a person adding and
    /// removing a passkey there would: a passkey sign-in with no relying
    /// party, `/passkeys/register/{start,finish}`, and the passkey list's
    /// remove form.
    ///
    /// The account must hold exactly one passkey, this user's: rotation
    /// replaces it and touches nothing else. The new key is saved beside the
    /// old one before its registration is sent, and replaces it in the store
    /// only after the issuer has accepted a sign-in from it, so the store
    /// always holds a key the account accepts. A rotation cut short at any
    /// step (see [`UserState::is_rotating`]) is finished by calling this
    /// again, from the same store.
    pub async fn rotate_passkey(&mut self) -> Result<(), Error> {
        self.ensure_live()?;
        let mut session = None;
        if self.state.rotation().is_none() {
            self.register_next().await?;
        }
        if let Some(Rotation::Registering { .. }) = self.state.rotation() {
            session = match self.prove_next().await? {
                Some(session) => Some(session),
                None => {
                    // The new key was saved but the issuer never registered
                    // it (its finish failed or never arrived). Nothing on the
                    // account refers to it, so drop it and register afresh.
                    self.state.abandon_rotation()?;
                    self.store.save(&self.state).await?;
                    self.register_next().await?;
                    Some(self.prove_next().await?.ok_or_else(|| {
                        protocol(
                            "rotate",
                            "the issuer does not offer the passkey it just registered",
                        )
                    })?)
                }
            };
        }
        let Some(Rotation::Retiring { retire }) = self.state.rotation().cloned() else {
            return Err(Error::State("rotation is not retiring the old key".into()));
        };
        let session = match session {
            Some(session) => session,
            None => self.account_session(Key::Current).await?,
        };
        session.remove_passkey(&self.issuer, &retire).await?;
        // ChirpAuth answers an unknown id with the same redirect as a removal,
        // so the list is the proof.
        let left = session.passkey_ids(&self.issuer).await?;
        if left.contains(&retire) || left.len() != 1 {
            return Err(protocol(
                "passkey remove",
                format!(
                    "after removing {retire} the account holds {} passkeys{}",
                    left.len(),
                    if left.contains(&retire) {
                        ", the old one among them"
                    } else {
                        ""
                    }
                ),
            ));
        }
        self.state.finish_rotation()?;
        self.store.save(&self.state).await?;
        session.sign_out(&self.issuer).await
    }

    /// Delete this account at ChirpAuth, the way a person does on its hosted
    /// page: an account sign-in with the current key and no app (fresh, so it
    /// passes the page's recent-sign-in gate), `GET /account/delete?armed=1`
    /// for the form's CSRF token, and `POST /account/delete` with the typed
    /// phrase. It succeeds only on ChirpAuth's "account deleted" page.
    ///
    /// The session is saved before the request is sent (see [`crate::state`]),
    /// because once ChirpAuth has recorded the deletion it makes no new
    /// sessions and that session alone can finish it. A deletion cut short
    /// (see [`UserState::is_deleting`]) is finished by calling this again from
    /// the same store: it retries through the saved session, with no new
    /// sign-in. Only if ChirpAuth no longer accepts that session for the
    /// deletion (401, or 403 for a sign-in no longer recent) does it sign in
    /// afresh. Afterwards the store is marked deleted: [`Self::load`] refuses
    /// it, and so does every flow on this value.
    ///
    /// ChirpAuth refuses (409) an account that owns apps or has a paid plan.
    pub async fn delete_account(&mut self) -> Result<(), Error> {
        match self.state.deletion() {
            Some(Deletion::Deleted) => return Ok(()),
            Some(Deletion::Requested { session }) => {
                let session = AccountSession {
                    cookie: session.clone(),
                };
                match self.submit_deletion(&session).await {
                    Err(Error::Rejected {
                        status: 401 | 403, ..
                    }) => {}
                    done => return done,
                }
            }
            None => {}
        }
        let session = self.account_session(Key::Current).await?;
        self.state.request_deletion(session.cookie.clone())?;
        self.store.save(&self.state).await?;
        self.submit_deletion(&session).await
    }

    /// Read the deletion form in `session` and submit it.
    async fn submit_deletion(&mut self, session: &AccountSession) -> Result<(), Error> {
        let step = "delete page";
        let mut url = self.issuer.url(DELETE_PATH);
        url.query_pairs_mut().append_pair("armed", "1");
        let response = self
            .issuer
            .http
            .get(url)
            .header("cookie", &session.cookie)
            .send()
            .await?;
        if response.status() != StatusCode::OK {
            return Err(rejected(step, response).await);
        }
        let csrf = hidden_input(&response.text().await?, "csrf")
            .ok_or_else(|| protocol(step, "no deletion form on the page"))?;

        let step = "account delete";
        let response = self
            .issuer
            .post(self.issuer.url(DELETE_PATH), Some(session))
            .form(&[("confirm", DELETE_PHRASE), ("csrf", csrf.as_str())])
            .send()
            .await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::CONFLICT => {
                return Err(Error::Rejected {
                    step,
                    status: 409,
                    body: "ChirpAuth refuses to delete an account that owns apps or has a \
                           paid plan"
                        .into(),
                })
            }
            _ => return Err(rejected(step, response).await),
        }
        if !response.text().await?.contains(DELETED_TITLE) {
            return Err(protocol(
                step,
                "the issuer answered without confirming the deletion",
            ));
        }
        self.state.finish_deletion()?;
        self.store.save(&self.state).await
    }

    /// Refuse any flow on an account whose deletion was requested.
    fn ensure_live(&self) -> Result<(), Error> {
        match self.state.deletion() {
            None => Ok(()),
            Some(Deletion::Requested { .. }) => Err(Error::State(
                "account deletion was requested; call delete_account to finish it".into(),
            )),
            Some(Deletion::Deleted) => Err(Error::State("the account was deleted".into())),
        }
    }

    /// Register a new key beside the current one, saving it first.
    async fn register_next(&mut self) -> Result<(), Error> {
        let session = self.account_session(Key::Current).await?;
        let ids = session.passkey_ids(&self.issuer).await?;
        let [retire] = ids.as_slice() else {
            return Err(Error::State(format!(
                "the account holds {} passkeys; rotation replaces exactly one",
                ids.len()
            )));
        };
        let ceremony: Ceremony<CreationOptions> = self
            .issuer
            .post_form(
                "passkey register start",
                "/passkeys/register/start",
                Some(&session),
                NO_FORM,
            )
            .await?;
        let (next, registration) = Credential::register(&self.issuer.origin, &ceremony.options)?;
        if next.user_handle() != self.state.credential().user_handle() {
            return Err(protocol(
                "passkey register start",
                "the new passkey would answer for another account",
            ));
        }
        self.state.begin_rotation(next, retire.clone())?;
        self.store.save(&self.state).await?;
        let finished: Status = self
            .issuer
            .post_json(
                "passkey register finish",
                "/passkeys/register/finish",
                Some(&session),
                &ceremony.ceremony_id,
                &registration,
            )
            .await?;
        if finished.status != "registered" {
            return Err(protocol(
                "passkey register finish",
                format!("status {:?}", finished.status),
            ));
        }
        session.sign_out(&self.issuer).await
    }

    /// Sign in with the registering new key and promote it. `None` if the
    /// issuer does not offer that key for this account, i.e. never
    /// registered it.
    async fn prove_next(&mut self) -> Result<Option<AccountSession>, Error> {
        let ceremony = self.start_account_sign_in().await?;
        let Some(Rotation::Registering { next, .. }) = self.state.rotation() else {
            return Err(Error::State("no new key is registering".into()));
        };
        match ceremony.options.names(next.credential_id()) {
            Some(true) => {}
            Some(false) => return Ok(None),
            None => {
                return Err(protocol(
                    "account sign-in start",
                    "the ceremony names no credentials",
                ))
            }
        }
        let session = self.finish_account_sign_in(ceremony, Key::Next).await?;
        self.state.promote_next()?;
        self.store.save(&self.state).await?;
        Ok(Some(session))
    }

    /// Sign in to ChirpAuth itself (no relying party) with `key`.
    async fn account_session(&mut self, key: Key) -> Result<AccountSession, Error> {
        let ceremony = self.start_account_sign_in().await?;
        self.finish_account_sign_in(ceremony, key).await
    }

    async fn start_account_sign_in(&self) -> Result<Ceremony<RequestOptions>, Error> {
        // No `login_id`: a sign-in to the account, which ends in a session
        // rather than a code for an app.
        self.issuer
            .post_form(
                "account sign-in start",
                "/login/passkey/start",
                None,
                &[("account_id", &self.account.account_id)],
            )
            .await
    }

    async fn finish_account_sign_in(
        &mut self,
        ceremony: Ceremony<RequestOptions>,
        key: Key,
    ) -> Result<AccountSession, Error> {
        let step = "account sign-in finish";
        let assertion = self
            .state
            .next_assertion(&mut self.store, key, &self.issuer.origin, &ceremony.options)
            .await?;
        let response = self
            .issuer
            .post_ceremony(
                "/login/passkey/finish",
                None,
                &ceremony.ceremony_id,
                &assertion,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(rejected(step, response).await);
        }
        let cookie =
            session_cookie(&response).ok_or_else(|| protocol(step, "no session cookie was set"))?;
        let finished: Status = json_ok(step, response).await?;
        if finished.status != "signed_in" {
            return Err(protocol(step, format!("status {:?}", finished.status)));
        }
        Ok(AccountSession { cookie })
    }
}

/// A signed-in session on ChirpAuth's own account surface. `Debug` is not
/// derived: the cookie is a bearer secret.
struct AccountSession {
    /// `chirp_auth_session=<token>`, as a `Cookie` header carries it.
    cookie: String,
}

impl AccountSession {
    /// Open `authorize_url` in this session and submit its "Continue as"
    /// form. Returns the callback URL the code is sent to, checked as
    /// [`SyntheticUser::authorize`] checks its own.
    async fn consent(&self, issuer: &Issuer, authorize_url: &Url) -> Result<Url, Error> {
        let step = "consent page";
        let response = issuer
            .http
            .get(authorize_url.clone())
            .header("cookie", &self.cookie)
            .send()
            .await?;
        if response.status().is_redirection() {
            let location = location(&response);
            return Err(protocol(
                step,
                format!(
                    "redirected instead of a consent page: {}",
                    error_of(&location)
                ),
            ));
        }
        if response.status() != StatusCode::OK {
            return Err(rejected(step, response).await);
        }
        let page = response.text().await?;
        let form = ConsentForm::parse(&page)
            .ok_or_else(|| protocol(step, "no \"Continue as\" form on the page"))?;

        let step = "consent";
        let response = issuer
            .post(issuer.url("/authorize/continue"), Some(self))
            .form(&[
                ("continuation_id", form.continuation_id.as_str()),
                ("csrf", form.csrf.as_str()),
            ])
            .send()
            .await?;
        // A loopback redirect_uri gets a plain redirect; any other gets an
        // interstitial page, which this driver does not follow.
        if !response.status().is_redirection() {
            return Err(rejected(step, response).await);
        }
        let callback =
            Url::parse(&location(&response)).map_err(|e| protocol(step, e.to_string()))?;
        let params: HashMap<_, _> = callback.query_pairs().into_owned().collect();
        if let Some(error) = params.get("error") {
            return Err(protocol(
                step,
                format!("RP redirect carries error {error:?}"),
            ));
        }
        if params.get("iss").map(String::as_str) != Some(issuer.as_str()) {
            return Err(protocol(step, "redirect iss is not this issuer"));
        }
        Ok(callback)
    }

    /// The issuer's ids of the account's passkeys, read off the passkey list
    /// page: the hosted page is the only listing a session can read, and its
    /// remove links are what a person follows to remove one.
    async fn passkey_ids(&self, issuer: &Issuer) -> Result<Vec<String>, Error> {
        let step = "passkey list";
        let response = issuer
            .http
            .get(issuer.url("/account/passkeys"))
            .header("cookie", &self.cookie)
            .send()
            .await?;
        if response.status() != StatusCode::OK {
            return Err(rejected(step, response).await);
        }
        let ids = passkey_ids(&response.text().await?);
        if ids.is_empty() {
            return Err(protocol(step, "the page lists no passkeys"));
        }
        Ok(ids)
    }

    /// Submit the passkey list's remove form for `passkey_id`.
    async fn remove_passkey(&self, issuer: &Issuer, passkey_id: &str) -> Result<(), Error> {
        let response = issuer
            .post(
                issuer.url(&format!("{PASSKEY_PATH}{passkey_id}/remove")),
                Some(self),
            )
            .form(NO_FORM)
            .send()
            .await?;
        if !response.status().is_redirection() {
            return Err(rejected("passkey remove", response).await);
        }
        Ok(())
    }

    /// End the session, so no live session outlasts the rotation.
    async fn sign_out(self, issuer: &Issuer) -> Result<(), Error> {
        let response = issuer
            .post(issuer.url("/logout"), Some(&self))
            .form(NO_FORM)
            .send()
            .await?;
        if !(response.status() == StatusCode::OK || response.status().is_redirection()) {
            return Err(rejected("sign out", response).await);
        }
        Ok(())
    }
}

/// The `name=value` of ChirpAuth's session cookie, from a response's
/// `Set-Cookie` headers.
fn session_cookie(response: &Response) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            let pair = cookie.split(';').next()?.trim();
            let (name, value) = pair.split_once('=')?;
            (name == SESSION_COOKIE && !value.is_empty()).then(|| pair.to_string())
        })
}

/// Every `{id}` in a `/account/passkeys/{id}/remove` link, in page order,
/// each once.
fn passkey_ids(html: &str) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for (at, _) in html.match_indices(PASSKEY_PATH) {
        let rest = &html[at + PASSKEY_PATH.len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(rest.len());
        let (id, tail) = rest.split_at(end);
        if !id.is_empty() && tail.starts_with("/remove") && !ids.iter().any(|known| known == id) {
            ids.push(id.to_string());
        }
    }
    ids
}

/// A response's `Location` header, or empty.
fn location(response: &Response) -> String {
    response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

/// The hidden fields of the "Continue as" form on ChirpAuth's returning-user
/// page (`returning_page` in chirp-auth's `pages.rs`).
#[derive(Debug, PartialEq, Eq)]
struct ConsentForm {
    continuation_id: String,
    csrf: String,
}

impl ConsentForm {
    /// The first form's fields. The page's other form ("Sign in as someone
    /// else") repeats them with an `action` of `switch`, so the first form is
    /// the one that continues.
    fn parse(html: &str) -> Option<Self> {
        Some(Self {
            continuation_id: hidden_input(html, "continuation_id")?,
            csrf: hidden_input(html, "csrf")?,
        })
    }
}

/// The value of the first `<input type="hidden" name="{name}" value="...">`,
/// with the HTML escapes the page writes undone.
fn hidden_input(html: &str, name: &str) -> Option<String> {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html.find(&marker)? + marker.len();
    let end = html[start..].find('"')?;
    let value = html[start..start + end]
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    (!value.is_empty()).then_some(value)
}

/// `error` and `error_description` of an error redirect, for the message.
fn error_of(location: &str) -> String {
    let Ok(url) = Url::parse(location) else {
        return "unparseable location".into();
    };
    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
    format!(
        "error={:?} description={:?}",
        params.get("error"),
        params.get("error_description")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_ids_come_from_the_remove_links_once_each() {
        let page = r#"<a href="/account/passkeys/add">ADD</a>
            <a href="/account/passkeys/pk_1a/rename">RENAME</a><a href="/account/passkeys/pk_1a/remove">REMOVE</a>
            <a href="/account/passkeys/pk_2b/rename">RENAME</a><a href="/account/passkeys/pk_2b/remove">REMOVE</a>
            <form action="/account/passkeys/pk_2b/remove"></form>"#;
        assert_eq!(passkey_ids(page), vec!["pk_1a", "pk_2b"]);
        assert!(passkey_ids("<p>No passkeys yet</p>").is_empty());
    }

    #[test]
    fn the_consent_form_is_the_first_forms_hidden_fields() {
        let page = r#"<form class="inline" method="post" action="/authorize/continue">
      <input type="hidden" name="continuation_id" value="cont_1a">
      <input type="hidden" name="csrf" value="a&amp;b">
      <button class="primary" type="submit"><span>Continue as x</span></button>
    </form>
    <form class="inline" method="post" action="/authorize/continue">
      <input type="hidden" name="continuation_id" value="cont_1a">
      <input type="hidden" name="csrf" value="a&amp;b">
      <input type="hidden" name="action" value="switch">
    </form>"#;
        assert_eq!(
            ConsentForm::parse(page),
            Some(ConsentForm {
                continuation_id: "cont_1a".into(),
                csrf: "a&b".into(),
            })
        );
        assert_eq!(ConsentForm::parse("<p>Sign in</p>"), None);
        assert_eq!(
            ConsentForm::parse(r#"name="continuation_id" value="" name="csrf" value="x""#),
            None,
            "an empty continuation id is no form"
        );
    }
}
