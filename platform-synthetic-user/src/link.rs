//! Sign in by magic link, the way launch users do: ChirpAuth emails a link to
//! an address the caller owns, and the mail is read through that address's
//! scrawl mailbox token (agent-platform--protocols
//! `docs/adr-synthetic-accounts-sign-in-by-link.md`).
//!
//! Unlike the passkey driver this holds no key and writes no state: the
//! account is whichever one ChirpAuth has for the address (it creates one on
//! the first sign-in). The address must be in ChirpAuth's
//! `bot_check_exempt_recipients`, since no Turnstile token is sent.
//!
//! Every request is one ChirpAuth's hosted pages make: `/authorize`, the
//! email form (`POST /login/email`), and the link's Continue button
//! (`POST /login/verify`).

use std::collections::HashSet;
use std::fmt;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::driver::{
    callback_with_code, location, login_page, rejected, session_cookie, unescape_html,
    AccountSession, AuthorizeRequest, Issuer, PublicClient, SignIn, NO_FORM,
};
use crate::error::protocol;
use crate::Error;

/// How long [`sign_in_by_link`] waits for the mail by default.
const DEFAULT_WAIT: Duration = Duration::from_secs(120);
const POLL_EVERY: Duration = Duration::from_secs(2);
/// The newest messages read on each poll. Mail that arrives during the wait
/// lands on top, so a page is enough unless more than this arrive at once.
const PAGE: &str = "25";
/// Where ChirpAuth's sign-in mail sends the person (`/login/verify`).
const VERIFY_PATH: &str = "/login/verify";
/// The waiting page's element that carries the sign-in's trace id
/// (`email_link_page` in chirp-auth's `pages.rs`).
const TRACE_MARKER: &str = r#"id="link-sent" data-trace=""#;
/// The tag on ChirpAuth's page for a request its bot check refused.
const BOT_CHECK_REFUSED: &str = "NOT_SENT";
/// The interstitial a non-loopback `redirect_uri` gets after the link
/// (`verify_success_page`): the redirect is its meta refresh.
const REFRESH_MARKER: &str = r#"http-equiv="refresh" content="0;url="#;

/// A scrawl mailbox, read with its own mailbox token (scrawl#1), which reads
/// only the mail that address sent or was delivered.
///
/// `Debug` shows the address, never the token.
#[derive(Clone)]
pub struct Mailbox {
    api: Url,
    address: String,
    token: String,
    wait: Duration,
}

impl Mailbox {
    /// `api` is scrawl's API origin (`https`, or `http` on loopback),
    /// `address` the mailbox (`smoke@scrawl.email`), and `token` its
    /// `scrawl_mbx_…` token from `scrawl-admin issue <address>`.
    pub fn new(api: &str, address: &str, token: impl Into<String>) -> Result<Self, Error> {
        let api = Url::parse(api.trim().trim_end_matches('/'))
            .map_err(|e| Error::State(format!("scrawl api url: {e}")))?;
        let loopback = matches!(api.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(api.scheme() == "https" || (api.scheme() == "http" && loopback)) {
            return Err(Error::State(
                "scrawl api must be https, or http on loopback".into(),
            ));
        }
        if api.path() != "/" || api.query().is_some() {
            return Err(Error::State("scrawl api must be a bare origin".into()));
        }
        let address = address.trim().to_string();
        let token = token.into();
        if address.is_empty() || token.is_empty() {
            return Err(Error::State("mailbox needs an address and a token".into()));
        }
        Ok(Self {
            api,
            address,
            token,
            wait: DEFAULT_WAIT,
        })
    }

    /// How long to wait for the sign-in mail before failing (default 120 s).
    pub fn with_wait(mut self, wait: Duration) -> Self {
        self.wait = wait;
        self
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    /// The ids of the newest inbound messages, newest first.
    async fn newest(&self, http: &reqwest::Client) -> Result<Vec<String>, Error> {
        let step = "scrawl list";
        let mut url = self.api.join("/v1/messages").expect("api joins a path");
        url.query_pairs_mut()
            .append_pair("dir", "in")
            .append_pair("limit", PAGE);
        let response = http.get(url).bearer_auth(&self.token).send().await?;
        if response.status() != StatusCode::OK {
            return Err(rejected(step, response).await);
        }
        let summaries: Vec<Summary> = response
            .json()
            .await
            .map_err(|e| protocol(step, format!("response body: {e}")))?;
        Ok(summaries
            .into_iter()
            .filter(|m| m.direction == "in")
            .map(|m| m.id)
            .collect())
    }

    /// A message's plain-text body (empty if it has none).
    async fn text(&self, http: &reqwest::Client, id: &str) -> Result<String, Error> {
        let step = "scrawl read";
        let mut url = self.api.clone();
        url.path_segments_mut()
            .expect("api is a base url")
            .extend(["v1", "messages", id]);
        let response = http.get(url).bearer_auth(&self.token).send().await?;
        if response.status() != StatusCode::OK {
            return Err(rejected(step, response).await);
        }
        let message: Full = response
            .json()
            .await
            .map_err(|e| protocol(step, format!("response body: {e}")))?;
        Ok(message.text.unwrap_or_default())
    }

    /// Wait for the mail that carries `reference`, reading each message not
    /// in `seen` once, and return its sign-in link.
    async fn link_for(
        &self,
        issuer: &Issuer,
        reference: &str,
        mut seen: HashSet<String>,
    ) -> Result<Url, Error> {
        let started = Instant::now();
        let mut read = 0usize;
        loop {
            for id in self.newest(&issuer.http).await? {
                if !seen.insert(id.clone()) {
                    continue;
                }
                read += 1;
                let text = self.text(&issuer.http, &id).await?;
                if text.contains(reference) {
                    return verify_link(issuer, &text);
                }
            }
            let waited = started.elapsed();
            if waited >= self.wait {
                return Err(protocol(
                    "sign-in mail",
                    format!(
                        "no sign-in mail to {} with reference {reference} after {}s \
                         ({read} new messages read). ChirpAuth shows the same waiting \
                         page when it suppresses a send (per-recipient or signup cap)",
                        self.address,
                        waited.as_secs()
                    ),
                ));
            }
            tokio::time::sleep(POLL_EVERY.min(self.wait - waited)).await;
        }
    }
}

impl fmt::Debug for Mailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mailbox")
            .field("api", &self.api.as_str())
            .field("address", &self.address)
            .field("wait", &self.wait)
            .finish_non_exhaustive()
    }
}

/// A message in scrawl's list (`GET /v1/messages`).
#[derive(Deserialize)]
struct Summary {
    id: String,
    direction: String,
}

/// A message as `GET /v1/messages/:id` returns it.
#[derive(Deserialize)]
struct Full {
    text: Option<String>,
}

/// Sign in to a public PKCE client by magic link, as the account whose
/// sign-in address is `mailbox`'s: build the `/authorize` request (S256,
/// fresh `state` and `nonce`), ask ChirpAuth to email the link, read that
/// mail through scrawl, follow the link, and redeem the code at `/token`.
///
/// The mail is matched to this request, not just taken as the newest: it
/// must arrive after the request and carry the reference ChirpAuth derives
/// from this sign-in's trace, so two sign-ins to one address at once each
/// follow their own link. With no such mail within the mailbox's wait
/// ([`Mailbox::with_wait`]) it fails, naming the reference it waited for.
///
/// The browser session ChirpAuth also opens is signed out before the code is
/// redeemed, so none outlasts the call. Verify the returned `id_token` with
/// the RP's own verifier and check its `nonce`.
pub async fn sign_in_by_link(
    issuer: &Issuer,
    client: &PublicClient,
    mailbox: &Mailbox,
) -> Result<SignIn, Error> {
    let request = AuthorizeRequest::new(issuer, client)?;
    let login_id = login_page(issuer, &request.url).await?;
    // What the mailbox holds before the request is never this request's.
    let before: HashSet<String> = mailbox.newest(&issuer.http).await?.into_iter().collect();
    let trace = request_link(issuer, &login_id, mailbox.address()).await?;
    let link = mailbox
        .link_for(issuer, &reference_id(&trace), before)
        .await?;
    let callback = follow_link(issuer, &link).await?;
    request.redeem(issuer, client, &callback).await
}

/// Submit the sign-in page's email form, and return the sign-in's trace id
/// from the "check your email" page.
async fn request_link(issuer: &Issuer, login_id: &str, address: &str) -> Result<String, Error> {
    let step = "sign-in email";
    let response = issuer
        .post(issuer.url("/login/email"), None)
        .form(&[("login_id", login_id), ("email", address)])
        .send()
        .await?;
    let status = response.status();
    if status != StatusCode::OK {
        let refused = rejected(step, response).await;
        return Err(match refused {
            Error::Rejected { body, .. } if body.contains(BOT_CHECK_REFUSED) => Error::Rejected {
                step,
                status: status.as_u16(),
                body: format!(
                    "the bot check refused it; {address} must be in ChirpAuth's \
                     bot_check_exempt_recipients"
                ),
            },
            other => other,
        });
    }
    let page = response.text().await?;
    let start = page
        .find(TRACE_MARKER)
        .map(|at| at + TRACE_MARKER.len())
        .ok_or_else(|| protocol(step, "no \"check your email\" page"))?;
    let end = page[start..]
        .find('"')
        .ok_or_else(|| protocol(step, "unterminated trace id"))?;
    let trace = unescape_html(&page[start..start + end]);
    if trace.is_empty() {
        return Err(protocol(step, "the page carries no trace id"));
    }
    Ok(trace)
}

/// The reference ChirpAuth prints in a sign-in mail for `trace_id`
/// (`reference_id_from_trace` in chirp-auth's `lib.rs`): the first 12 bytes
/// of its SHA-256, each a symbol of a 31-letter alphabet, as `XXXX-XXXX-XXXX`.
/// A change there makes every sign-in here time out naming the reference
/// it waited for. Only a live run catches that: the local issuer mails
/// nothing, so its test's fake scrawl writes the mail with its own copy.
/// chirp-auth#192 would put the reference on the waiting page instead.
fn reference_id(trace_id: &str) -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    let digest = Sha256::digest(trace_id.as_bytes());
    let mut out = String::with_capacity(14);
    for (i, &byte) in digest.iter().take(12).enumerate() {
        if i == 4 || i == 8 {
            out.push('-');
        }
        out.push(ALPHABET[usize::from(byte) % ALPHABET.len()] as char);
    }
    out
}

/// The sign-in link in a mail's text: this issuer's `/login/verify`, with
/// the challenge and token it names.
fn verify_link(issuer: &Issuer, text: &str) -> Result<Url, Error> {
    let step = "sign-in mail";
    let prefix = format!("{}{VERIFY_PATH}?", issuer.as_str());
    let start = text
        .find(&prefix)
        .ok_or_else(|| protocol(step, "the mail carries no sign-in link for this issuer"))?;
    let raw = text[start..]
        .split(|c: char| c.is_whitespace() || c == '<' || c == '"')
        .next()
        .unwrap_or_default();
    let link = Url::parse(raw).map_err(|e| protocol(step, format!("sign-in link: {e}")))?;
    let names = |name: &str| link.query_pairs().any(|(k, v)| k == name && !v.is_empty());
    if !(names("challenge_id") && names("token")) {
        return Err(protocol(
            step,
            "the sign-in link names no challenge or token",
        ));
    }
    Ok(link)
}

/// Press the link page's Continue (`POST /login/verify` with the link's own
/// query), sign out the session it opens, and return the RP callback.
async fn follow_link(issuer: &Issuer, link: &Url) -> Result<Url, Error> {
    let step = "sign-in link";
    let response = issuer.post(link.clone(), None).form(NO_FORM).send().await?;
    let status = response.status();
    if !(status.is_redirection() || status == StatusCode::OK) {
        return Err(rejected(step, response).await);
    }
    let session = session_cookie(&response).map(|cookie| AccountSession { cookie });
    // A loopback redirect_uri gets a plain redirect; any other gets the
    // "Signing you in" interstitial, whose meta refresh is the redirect.
    let callback = if status.is_redirection() {
        Ok(location(&response))
    } else {
        let page = response.text().await?;
        page.find(REFRESH_MARKER)
            .map(|at| &page[at + REFRESH_MARKER.len()..])
            .and_then(|rest| rest.split('"').next())
            .map(unescape_html)
            .ok_or_else(|| protocol(step, "the issuer did not send the browser back to the app"))
    }
    .and_then(|callback| callback_with_code(step, issuer, &callback));
    if let Some(session) = session {
        // Signed out whatever the outcome; a bad callback is the error worth
        // reporting.
        let signed_out = session.sign_out(issuer).await;
        let callback = callback?;
        signed_out?;
        return Ok(callback);
    }
    callback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_is_chirp_auths_derivation() {
        // Computed independently from chirp-auth's `reference_id_from_trace`
        // (sha256 → 12 symbols of 23456789ABCDEFGHJKMNPQRSTUVWXYZ).
        assert_eq!(reference_id("trace-abc-123"), "SZXN-SM3J-3CQT");
        assert_eq!(reference_id("authz_0123456789abcdef"), "XSPK-2AUF-8XBG");
    }

    #[test]
    fn the_link_is_this_issuers_verify_url() {
        let issuer = Issuer::new("https://signin.chirpauth.com").unwrap();
        let text = "Continue sign-in:\nhttps://signin.chirpauth.com/login/verify?challenge_id=email_1&token=ml_2\n\nReference: AAAA";
        assert_eq!(
            verify_link(&issuer, text).unwrap().as_str(),
            "https://signin.chirpauth.com/login/verify?challenge_id=email_1&token=ml_2"
        );
        let other = "https://evil.example/login/verify?challenge_id=email_1&token=ml_2";
        assert!(verify_link(&issuer, other).is_err());
        let bare = "https://signin.chirpauth.com/login/verify?challenge_id=email_1";
        assert!(verify_link(&issuer, bare).is_err());
    }

    #[test]
    fn a_mailbox_shows_no_token_and_needs_a_secure_api() {
        let mailbox = Mailbox::new(
            "https://scrawl.example",
            "a@scrawl.email",
            "scrawl_mbx_secret",
        )
        .unwrap();
        assert!(!format!("{mailbox:?}").contains("secret"));
        assert!(Mailbox::new("http://scrawl.example", "a@scrawl.email", "t").is_err());
        assert!(Mailbox::new("http://127.0.0.1:9", "a@scrawl.email", "t").is_ok());
        assert!(Mailbox::new("https://scrawl.example", "a@scrawl.email", "").is_err());
    }
}
