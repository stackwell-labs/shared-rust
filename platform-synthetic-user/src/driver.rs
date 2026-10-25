//! ChirpAuth's human flows, driven over plain HTTP.
//!
//! Every request here is one the hosted pages' own scripts make
//! (`extended_signup_script`, `extended_signin_script` in chirp-auth's
//! `pages.rs`), with the browser's WebAuthn call answered by
//! [`crate::Credential`]. No control token, test outbox, or other bypass is
//! used. Each sign-in starts with no cookies, as a fresh browser would.

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
use crate::state::{Account, StateStore, UserState};
use crate::Error;

/// The header ChirpAuth's `/authorize` login page carries its login id in;
/// the same id is the page's hidden `login_id` input.
const LOGIN_ID_HEADER: &str = "x-chirp-auth-login-id";
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

    async fn post_form<T: DeserializeOwned>(
        &self,
        step: &'static str,
        path: &str,
        form: &[(&str, &str)],
    ) -> Result<T, Error> {
        let response = self
            .http
            .post(self.url(path))
            .header("origin", self.issuer.as_str())
            .form(form)
            .send()
            .await?;
        json_ok(step, response).await
    }

    async fn post_json<T: DeserializeOwned>(
        &self,
        step: &'static str,
        path: &str,
        ceremony_id: &str,
        body: &Value,
    ) -> Result<T, Error> {
        let mut url = self.url(path);
        url.query_pairs_mut()
            .append_pair("ceremony_id", ceremony_id);
        let response = self
            .http
            .post(url)
            .header("origin", self.issuer.as_str())
            .json(body)
            .send()
            .await?;
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
    /// enrollment, or a state for another issuer is an error.
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
                &[
                    ("login_id", &login_id),
                    ("account_id", &self.account.account_id),
                ],
            )
            .await?;
        let assertion = self
            .state
            .next_assertion(&mut self.store, &self.issuer.origin, &ceremony.options)
            .await?;
        let finished: SigninFinished = self
            .issuer
            .post_json(
                "passkey finish",
                "/login/passkey/finish",
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
        let verifier = b64_encode(&random_bytes::<32>()?);
        let state = b64_encode(&random_bytes::<16>()?);
        let nonce = b64_encode(&random_bytes::<16>()?);
        let mut url = self.issuer.url("/authorize");
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

        let callback = self.authorize(&url).await?;
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
        if params.get("state") != Some(&state) {
            return Err(protocol(step, "state does not match"));
        }
        let code = params
            .get("code")
            .ok_or_else(|| protocol(step, "no code"))?;

        let response = self
            .issuer
            .http
            .post(self.issuer.url("/token"))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &client.redirect_uri),
                ("client_id", &client.client_id),
                ("code_verifier", &verifier),
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
            nonce,
            token_response,
        })
    }
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
