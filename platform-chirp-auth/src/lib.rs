//! Shared chirp-auth request-plumbing for agent-platform backends.
//!
//! Drive and Pigeon (and the others) carried near-identical auth glue:
//! - the same `Authorization: Bearer` extraction,
//! - the same trusted-header dev decoder (with the 128-char / no-control-char
//!   uid+agent validation),
//! - the same `x-user-id` / `x-agent-id` / `x-approval-grant` / `x-user-can-write`
//!   header names,
//! - the same "machine acting on behalf of a human via a grant" resolution.
//!
//! This crate is the single source of truth for that plumbing. The
//! product-specific parts (which token audiences to accept, how grants are
//! stored, the concrete `AuthenticatedUser` type) stay in each backend; this
//! crate generalizes only the parts that were genuinely duplicated.

use platform_http_error::ApiError;
use uuid::Uuid;

/// Re-export of the canonical bearer-token extractor. Both backends had a
/// hand-rolled `bearer_token`; `chirp-auth-client` already ships the RFC-7235
/// case-insensitive version, so we re-export it rather than fork it.
///
/// Returns the token with the `Bearer ` scheme stripped and trimmed, or
/// `None` when the header is absent / non-bearer / empty.
pub use chirp_auth_client::bearer_token;

/// Re-export the chirp-auth-client verification surface so a relying party that
/// already depends on `platform-chirp-auth` (for the grant/machine helpers) can
/// consume the whole ChirpAuth API through THIS crate and drop its own direct
/// `chirp-auth-client` dependency. A service that depends on both directly and
/// transitively can otherwise pin two different tags → two incompatible copies
/// of every chirp type (the `ApiError`/`ChirpAuthConfig` mismatch that bit the
/// v0.16.0 cascade). Depending only on `platform-chirp-auth` makes that drift
/// unrepresentable: there is exactly one `chirp-auth-client`, the version THIS
/// crate pins, and a bump is a single dependency edit.
pub use chirp_auth_client::{
    environment_from_issuer, verify_chirp_id_token, verify_chirp_resource_access_token,
    verify_from_headers, verify_rs256_jws, ChirpAuthConfig, ChirpAuthError, ChirpVerifiedIdentity,
    ChirpVerifiedResourceAccess, ChirpVerifiedToken, Claims, Environment, VerifyOptions,
    ACCESS_TOKEN_TYP, ID_TOKEN_TYP, KEYBIND_TYP,
};
/// Re-export the machine-token minting module too (client_credentials
/// `MachineTokenMinter` / `MintConfig`), so a consumer that mints machine tokens
/// (e.g. murmur) can also drop its direct chirp-auth-client dependency.
pub use chirp_auth_client::mint;

/// Hermetic test tokens (local mock JWKS + real RS256 signing) — the
/// replacement for `decode_trusted_headers`' unauthenticated dev-bypass path
/// in test suites. See the module doc for usage.
#[cfg(feature = "testkit")]
pub mod testkit;

// ---- Header name constants (single source of truth) --------------------

/// Trusted-header user id. Bypasses token verification — only honored when a
/// deployment explicitly opts into trusted-header auth.
pub const USER_ID_HEADER: &str = "x-user-id";
/// Software-actor (agent) id. Defaults to the user id when absent.
pub const AGENT_ID_HEADER: &str = "x-agent-id";
/// App-native approval grant id (the grant lives in the backend's own store).
pub const APPROVAL_GRANT_HEADER: &str = "x-approval-grant";
/// Granite-issued grant id; the backend consults Granite as the lifecycle
/// authority for the grant. Mutually exclusive with [`APPROVAL_GRANT_HEADER`].
pub const GRANITE_GRANT_HEADER: &str = "x-granite-grant";
/// Whether the trusted-header user may write. Truthy: `1`/`true`/`yes`.
pub const CAN_WRITE_HEADER: &str = "x-user-can-write";

/// Maximum length, in characters, of a trusted-header `uid`/`agent_id`. Caps
/// the size of an attacker-influenced identifier and rejects pathological
/// inputs before they reach the store.
///
const MAX_ID_CHARS: usize = 128;

// ---- Trusted-header dev decoder ----------------------------------------

/// A request identity decoded from trusted headers (`x-user-id` et al.),
/// produced by [`decode_trusted_headers`]. The headers carry no proof on their
/// own, so a backend must establish trust first — either an authenticated
/// impersonation path (e.g. a verified internal-service token, a production
/// use) or an explicitly opted-in dev bypass (gated behind the
/// `dev-trusted-headers` feature + a `*_TRUSTED_HEADER_AUTH` env flag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedHeaderUser {
    /// Human user id (`x-user-id`).
    pub uid: String,
    /// Software-actor id (`x-agent-id`); defaults to `uid` when absent.
    pub agent_id: String,
    /// Whether the caller may write (`x-user-can-write`).
    pub can_write: bool,
    /// App-native grant id (`x-approval-grant`), if present.
    pub approval_grant_id: Option<String>,
}

/// Validate a trusted-header identifier: non-empty after trim, at most
/// [`MAX_ID_CHARS`] characters, and free of control characters. Returns the
/// trimmed value, or `Unauthorized` on violation.
fn validated_id(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.chars().count() > MAX_ID_CHARS
        || trimmed.chars().any(char::is_control)
    {
        return Err(ApiError::Unauthorized);
    }
    Ok(trimmed.to_owned())
}

/// Decode a [`TrustedHeaderUser`] from request headers, applying the same
/// validation drive/pigeon used: `x-user-id` is required and validated;
/// `x-agent-id` (if present) is validated and otherwise defaults to the uid;
/// `x-user-can-write` is truthy for `1`/`true`/`yes`; `x-approval-grant` is
/// trimmed and dropped if empty.
///
/// Returns `Unauthorized` when `x-user-id` is missing/empty or any provided
/// id fails validation.
///
/// # Trust is the caller's responsibility
///
/// This function only *parses* `x-user-id` et al.; it performs no
/// authentication. It is dual-use: a legitimate caller decodes these headers
/// only AFTER establishing trust some other way (e.g. drive verifies its
/// internal-service token first, then decodes the impersonated uid — a
/// production path), while a dev/integration bypass trusts them with no token
/// at all. The unauthenticated-trust decision is what each backend gates
/// behind its `dev-trusted-headers` feature + `*_TRUSTED_HEADER_AUTH` env flag;
/// the primitive itself is unconditional so authenticated impersonation works
/// in release builds.
pub fn decode_trusted_headers(
    headers: &http::HeaderMap,
) -> Result<TrustedHeaderUser, ApiError> {
    let uid_raw = headers
        .get(USER_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ApiError::Unauthorized)?;
    let uid = validated_id(uid_raw)?;

    let can_write = headers
        .get(CAN_WRITE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(|value| matches!(value, "1" | "true" | "yes"))
        .unwrap_or(false);

    let agent_id = match headers.get(AGENT_ID_HEADER).and_then(|v| v.to_str().ok()) {
        Some(raw) => validated_id(raw)?,
        None => uid.clone(),
    };

    let approval_grant_id = headers
        .get(APPROVAL_GRANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());

    Ok(TrustedHeaderUser {
        uid,
        agent_id,
        can_write,
        approval_grant_id,
    })
}

// ---- Generic on-behalf-of grant resolution -----------------------------

/// A grant looked up from a backend's own store. The only field the shared
/// resolution logic needs is the owner the grant authorizes acting as.
pub trait Grant {
    /// The uid the grant authorizes the requester to act on behalf of.
    fn owner_uid(&self) -> &str;
}

/// Per-app grant lookup. Each backend implements this over its own store;
/// [`apply_on_behalf_of_grant`] is parameterized over it so the
/// machine-acting-on-behalf-of-a-human resolution lives in one place.
#[async_trait::async_trait]
pub trait GrantStore {
    /// The grant type this store yields.
    type Grant: Grant;

    /// Look up a grant by id that names `requester_chirp_sub` as its subject.
    /// Returns `Ok(None)` when no such grant exists; `Err` only on a real
    /// store failure.
    async fn lookup_grant_for_subject(
        &self,
        grant_id: Uuid,
        requester_chirp_sub: &str,
    ) -> Result<Option<Self::Grant>, ApiError>;
}

/// The identity inputs to [`apply_on_behalf_of_grant`], and the place it
/// writes its result. `uid` is overwritten with the grant's owner when the
/// machine is acting on a human's behalf; `approval_grant_id` is always
/// populated from the header (the chirp-auth path leaves it unset otherwise).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnBehalfOf {
    /// Effective owner uid. Starts as the token's owner_sub (for a machine,
    /// the human who registered the client) and is overridden to the grant's
    /// `owner_uid` when a valid grant names this caller as subject.
    pub uid: String,
    /// The machine's own chirp sub. Equal to `uid` for a human identity —
    /// which is exactly how this function detects "no grant resolution
    /// needed".
    pub agent_id: String,
    /// Populated from [`APPROVAL_GRANT_HEADER`].
    pub approval_grant_id: Option<String>,
}

/// Resolve the effective owner for a machine-identity request that presents
/// an `x-approval-grant` header, using the backend's own [`GrantStore`].
///
/// This is the byte-shared core of drive's and pigeon's
/// `apply_on_behalf_of_grant` (minus drive's extra Granite-bridge branch,
/// which stays in drive because it's drive-specific):
///
/// 1. Always copy the `x-approval-grant` header into `ctx.approval_grant_id`
///    — the chirp-auth verify path leaves it `None`, and the downstream
///    per-operation grant check needs it.
/// 2. No-op for human identities (`uid == agent_id`): a human acting as
///    itself needs no grant.
/// 3. No-op for a missing or malformed (non-UUID) grant header, a
///    lookup-miss, or a store error — preserving the un-escalated identity
///    (the per-operation check downstream will refuse if escalation was
///    actually required).
/// 4. On a valid grant naming this caller as subject, override `ctx.uid` with
///    the grant's `owner_uid`.
///
/// The per-operation scope/resource check still runs later in the route
/// handler; this only resolves *who* the machine is acting on behalf of.
pub async fn apply_on_behalf_of_grant<S: GrantStore + ?Sized>(
    store: &S,
    headers: &http::HeaderMap,
    ctx: &mut OnBehalfOf,
) -> Result<(), ApiError> {
    let grant_header = headers
        .get(APPROVAL_GRANT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    ctx.approval_grant_id = grant_header.clone();

    // Human identity: uid == agent_id. Acting as itself, no grant needed.
    if ctx.uid == ctx.agent_id {
        return Ok(());
    }
    let Some(grant_header) = grant_header else {
        return Ok(());
    };
    let Ok(grant_id) = Uuid::parse_str(&grant_header) else {
        return Ok(());
    };
    let grant = match store.lookup_grant_for_subject(grant_id, &ctx.agent_id).await {
        Ok(Some(grant)) => grant,
        Ok(None) => return Ok(()),
        Err(_) => return Ok(()),
    };
    ctx.uid = grant.owner_uid().to_owned();
    Ok(())
}

// ---- Shared chirp MACHINE-token verifier --------------------------------

use std::collections::BTreeSet;


/// The chirp **machine-token** verifier config plus the explicit `client_id`
/// allowlist — the single shared replacement for the byte-identical
/// `MachineAuth` Drive, Granite, and Spend-Core each hand-rolled.
///
/// `chirp-auth-client` deliberately does NOT gate `aud` for machine tokens: a
/// machine token's `aud` is its own minting client, presentable to any service.
/// So without naming an accepted set, ANY confidential client in the chirp
/// environment could mint a machine token and call an internal API. The
/// allowlist is the only gate on WHICH client may act as an internal caller.
///
/// As of chirp-auth-client v0.12.0 the membership check lives INSIDE the lib:
/// [`verify`] hands the accepted set to
/// [`VerifyOptions::accept_machine_clients`], and `verify_chirp_id_token`
/// rejects a non-member machine token with
/// [`ChirpAuthError::MachineAudienceNotAccepted`](chirp_auth_client::ChirpAuthError::MachineAudienceNotAccepted),
/// fail-closed on an empty set. We hold the accepted set here only to feed it
/// into the verify call — never to re-check it by hand.
#[derive(Clone, Debug)]
pub struct MachineAuth {
    config: ChirpAuthConfig,
    accepted_client_ids: BTreeSet<String>,
}

/// A verified machine-token caller. Carries everything the three consumers need
/// to reproduce their current behavior without this crate depending on any of
/// their environment types (`granite_client::Environment` /
/// `capability::Environment`):
///
/// - `sub` — the machine principal's chirp `sub` (e.g. `agent_xxx`). Drive uses
///   it as the agent/run id; Granite intentionally ignores it (it names the
///   acting user via `x-user-id`); Spend-Core uses it as the caller `uid`.
/// - `owner_sub` — the human chirp-sub who registered the confidential client.
///   Drive uses it as the resource-owning `uid`.
/// - `client_id` — the verified, already-allowlisted minting client.
/// - `environment` — the raw [`chirp_auth_client::Environment`] (provenance:
///   which keyset verified the token). Each consumer maps this onto its own
///   trust-env type (Drive → `granite_client::Environment`, Granite →
///   `capability::Environment`); Spend-Core ignores it.
/// - `issuer` — the issuer the token verified against. Granite parses this with
///   its own `deployment_environment_for_issuer` to derive a
///   `capability::Environment`; the other two ignore it.
#[derive(Clone, Debug)]
pub struct VerifiedMachine {
    pub sub: String,
    pub owner_sub: String,
    pub client_id: String,
    pub environment: Environment,
    pub issuer: String,
}

/// Why [`MachineAuth::verify`] did not yield a machine caller.
///
/// The two variants exist BECAUSE OF GRANITE: Granite's machine path is an
/// EITHER/OR dispatcher that must distinguish two outcomes a flat
/// `Err(Unauthorized)` would conflate —
///
/// - [`Rejected`](Self::Rejected) — a *verified machine token* that is a
///   DEFINITIVE rejection (its `client_id` is not in the allowlist, i.e. the
///   lib's `MachineAudienceNotAccepted`). This must 401 and must NOT fall
///   through to any other auth path: a verified non-allowlisted agent is not a
///   user.
/// - [`NotMachine`](Self::NotMachine) — the bearer is not a usable machine
///   token *for this issuer*: a human identity, or any non-allowlist
///   verification failure (bad signature / iss / exp / environment / malformed).
///   Granite FALLS THROUGH to its end-user token path on this; the user path
///   produces the canonical 401 if it too rejects.
/// - [`Unavailable`](Self::Unavailable) — the token could not be checked at all
///   because ChirpAuth's JWKS could not be fetched (the lib's `JwksFetch`:
///   transport error, timeout, a 429 throttle). This is NOT a verdict on the
///   token, so it is neither a 401 nor fall-through-eligible: it is a 503.
///   Folding it into `NotMachine` is what turned a throttled ChirpAuth into
///   silent 401s for valid tokens.
///
/// Drive and Spend-Core do not branch on the token-verdict distinction — they
/// collapse `Rejected`/`NotMachine` to [`ApiError::Unauthorized`] and
/// `Unavailable` to [`ApiError::ServiceUnavailable`] via
/// [`into_api_error`](Self::into_api_error) (or the `From` impl). Granite matches
/// on the variant to reproduce its `None` / `Some(Err)` dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineAuthError {
    /// A verified machine token whose `client_id` is not allowlisted — a
    /// definitive rejection (do not fall through to other auth).
    Rejected,
    /// Not a usable machine token for this issuer (human identity, or a
    /// verification failure) — a caller MAY fall through to another auth path.
    NotMachine,
    /// The JWKS needed to verify the token could not be fetched — upstream
    /// unavailable, not a bad token. Answer 503; do not fall through.
    Unavailable,
}

impl MachineAuthError {
    /// Map to the HTTP error: a token verdict (`Rejected`/`NotMachine`) is a 401,
    /// an unreachable ChirpAuth (`Unavailable`) is a 503.
    pub fn into_api_error(self) -> ApiError {
        match self {
            Self::Rejected | Self::NotMachine => ApiError::Unauthorized,
            Self::Unavailable => {
                ApiError::ServiceUnavailable("authentication service unavailable".to_owned())
            }
        }
    }
}

impl From<MachineAuthError> for ApiError {
    fn from(error: MachineAuthError) -> Self {
        error.into_api_error()
    }
}

impl MachineAuth {
    /// Build a machine-token verifier for `issuer` gated to `client_ids`.
    ///
    /// The accepted set both scopes acceptance (the lib rejects a verified
    /// machine token whose `client_id` is not a member) and is the config's
    /// `aud` allowlist (the minting clients), mirroring every consumer's
    /// `ChirpAuthConfig::with_audiences(issuer, client_ids)` +
    /// `accepted_client_ids` pairing.
    pub fn new(issuer: impl Into<String>, client_ids: impl IntoIterator<Item = String>) -> Self {
        let accepted_client_ids: BTreeSet<String> = client_ids
            .into_iter()
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty())
            .collect();
        let config = ChirpAuthConfig::with_audiences(
            issuer.into(),
            accepted_client_ids.iter().cloned(),
        );
        Self {
            config,
            accepted_client_ids,
        }
    }

    /// Build from the process environment, returning `None` (the machine path
    /// stays OFF, behavior-unchanged) unless BOTH an issuer AND a non-empty
    /// comma-separated audiences list are present.
    ///
    /// `issuer_env_vars` are tried in order, first non-empty wins — this is how
    /// Granite reproduces its `GRANITE_CHIRP_ISSUER` else `CHIRP_AUTH_ISSUER`
    /// fallback (pass `&["GRANITE_CHIRP_ISSUER", "CHIRP_AUTH_ISSUER"]`). Drive
    /// and Spend-Core pass a single-element slice (no fallback), exactly their
    /// current behavior.
    ///
    /// `audiences_env_var` holds the comma-separated accepted CG `client_id`(s);
    /// blanks are trimmed and dropped, and an all-empty list yields `None`
    /// (fail-closed off, not fail-closed accepting-nothing — matching every
    /// consumer's `from_env`).
    pub fn from_env(issuer_env_vars: &[&str], audiences_env_var: &str) -> Option<Self> {
        // Match the consumers' `var(primary).or_else(|| var(secondary)).filter(!empty)`
        // semantics EXACTLY: the first *set* var wins (even if blank — a set-but-blank
        // primary does NOT fall through to the secondary), then the result must be
        // non-empty. Filtering empties *inside* the find would wrongly fall a blank
        // primary through to the secondary, diverging from granite. Single-var
        // consumers (drive/spend) are unaffected.
        let issuer = issuer_env_vars
            .iter()
            .find_map(|name| std::env::var(name).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())?;
        let audiences: Vec<String> = std::env::var(audiences_env_var)
            .ok()?
            .split(',')
            .map(|audience| audience.trim().to_owned())
            .filter(|audience| !audience.is_empty())
            .collect();
        if audiences.is_empty() {
            return None;
        }
        Some(Self::new(issuer, audiences))
    }

    /// The normalized issuer this verifier roots tokens in. Granite parses this
    /// (its `…/test/{tenant}` form) to derive a `capability::Environment`.
    pub fn issuer(&self) -> &str {
        self.config.issuer()
    }

    /// The accepted machine `client_id` allowlist — the set fed into the lib's
    /// gate. Exposed for assertions / introspection; the membership check itself
    /// is the lib's job (see [`verify_options`](Self::verify_options)).
    pub fn accepted_client_ids(&self) -> &BTreeSet<String> {
        &self.accepted_client_ids
    }

    /// The [`VerifyOptions`] that opt into machine acceptance gated to the
    /// configured allowlist. The lib enforces the set: a machine token whose
    /// `client_id` is not a member is rejected, and an empty set accepts no
    /// machine token (fail-closed). This is the single place the configured set
    /// crosses into the lib gate, so prod and tests share it.
    pub fn verify_options(&self) -> VerifyOptions {
        VerifyOptions::accept_machine_clients(self.accepted_client_ids.iter().cloned())
    }

    /// Verify a chirp **machine token**, returning the verified machine caller
    /// or a two-way [`MachineAuthError`] (see that type for why the distinction
    /// exists — it is Granite's EITHER/OR dispatch).
    ///
    /// Outcomes:
    /// - `Ok(VerifiedMachine)` — a `Machine` identity whose `client_id` is in the
    ///   configured allowlist (the lib enforces membership).
    /// - `Err(MachineAuthError::Rejected)` — a *verified* machine token whose
    ///   `client_id` is NOT allowlisted (the lib's `MachineAudienceNotAccepted`):
    ///   a definitive 401, never fall-through-eligible.
    /// - `Err(MachineAuthError::NotMachine)` — a human identity, or any other
    ///   verification failure (bad signature / iss / exp / environment /
    ///   malformed): the bearer is not a usable machine token for this issuer, so
    ///   a caller may fall through to another auth path.
    /// - `Err(MachineAuthError::Unavailable)` — ChirpAuth's JWKS could not be
    ///   fetched (the lib's `JwksFetch`), so the token was never checked: a 503,
    ///   never fall-through-eligible.
    ///
    /// `client` is the caller's pooled `reqwest::Client` (the JWKS fetch reuses
    /// the connection pool); this crate does not own one.
    ///
    /// Drive/Spend-Core call `.map_err(MachineAuthError::into_api_error)` (or
    /// rely on the `From` impl): `Rejected`/`NotMachine` → 401, `Unavailable` →
    /// 503. Granite matches on the variant: `Rejected` →
    /// `Some(Err(Unauthorized))`, `NotMachine` → `None` (fall through to the
    /// user-token path), `Unavailable` → `Some(Err(ServiceUnavailable))`.
    pub async fn verify(
        &self,
        client: &reqwest::Client,
        token: &str,
    ) -> Result<VerifiedMachine, MachineAuthError> {
        let verified = match verify_chirp_id_token(
            client,
            &self.config,
            token,
            self.verify_options(),
        )
        .await
        {
            Ok(verified) => verified,
            // A machine token that verified but whose `client_id` is not in the
            // accepted set — the lib's definitive non-member rejection. This must
            // NOT be re-treated as a user token by a fall-through dispatcher.
            Err(chirp_auth_client::ChirpAuthError::MachineAudienceNotAccepted) => {
                return Err(MachineAuthError::Rejected);
            }
            // The JWKS could not be fetched (ChirpAuth throttled / unreachable):
            // no verdict on the token exists, so this is not NotMachine.
            Err(chirp_auth_client::ChirpAuthError::JwksFetch(_)) => {
                return Err(MachineAuthError::Unavailable);
            }
            // Any other verification failure (bad sig / iss / exp / env /
            // malformed). A human token from this issuer still verifies as
            // `Human` (handled below), so a hard error here means the bearer is
            // genuinely not a usable token for this issuer — fall-through eligible.
            Err(_) => return Err(MachineAuthError::NotMachine),
        };
        let environment = verified.environment;
        match verified.identity {
            ChirpVerifiedIdentity::Machine {
                sub,
                owner_sub,
                client_id,
            } => Ok(VerifiedMachine {
                sub,
                owner_sub,
                client_id,
                environment,
                issuer: self.config.issuer().to_owned(),
            }),
            // A human or test-environment token on the machine path is the wrong
            // identity type, but it is a VALID token — the caller falls through to
            // its human path. (`Test` is a non-machine principal verified against a
            // test-tenant keyset; added to ChirpVerifiedIdentity in client v0.13.)
            ChirpVerifiedIdentity::Human { .. } | ChirpVerifiedIdentity::Test { .. } => {
                Err(MachineAuthError::NotMachine)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn bearer_reexport_strips_scheme() {
        let h = hm(&[("authorization", "Bearer abc.def.ghi")]);
        assert_eq!(bearer_token(&h), Some("abc.def.ghi"));
    }

    #[test]
    fn trusted_headers_minimal() {
        let h = hm(&[("x-user-id", "user-1")]);
        let u = decode_trusted_headers(&h).unwrap();
        assert_eq!(u.uid, "user-1");
        assert_eq!(u.agent_id, "user-1"); // defaults to uid
        assert!(!u.can_write);
        assert_eq!(u.approval_grant_id, None);
    }

    #[test]
    fn trusted_headers_full() {
        let h = hm(&[
            ("x-user-id", "user-1"),
            ("x-agent-id", "agent-9"),
            ("x-user-can-write", "true"),
            ("x-approval-grant", "  grant-xyz  "),
        ]);
        let u = decode_trusted_headers(&h).unwrap();
        assert_eq!(u.agent_id, "agent-9");
        assert!(u.can_write);
        assert_eq!(u.approval_grant_id.as_deref(), Some("grant-xyz"));
    }

    #[test]
    fn trusted_headers_missing_uid_rejected() {
        assert!(matches!(
            decode_trusted_headers(&HeaderMap::new()),
            Err(ApiError::Unauthorized)
        ));
    }

    #[test]
    fn trusted_headers_control_char_rejected() {
        // A control char can't be set via HeaderValue::from_str, so build the
        // value from raw bytes (a tab is a visible-via-to_str control char)
        // to exercise the validation path directly.
        let mut h = HeaderMap::new();
        h.insert(
            http::HeaderName::from_static("x-user-id"),
            http::HeaderValue::from_static("ok"),
        );
        h.insert(
            http::HeaderName::from_static("x-agent-id"),
            http::HeaderValue::from_bytes(b"bad\tid").unwrap(),
        );
        assert!(matches!(
            decode_trusted_headers(&h),
            Err(ApiError::Unauthorized)
        ));
    }

    #[test]
    fn trusted_headers_overlong_uid_rejected() {
        let long = "x".repeat(MAX_ID_CHARS + 1);
        let h = hm(&[("x-user-id", long.as_str())]);
        assert!(matches!(
            decode_trusted_headers(&h),
            Err(ApiError::Unauthorized)
        ));
    }

    struct TestGrant {
        owner: String,
    }
    impl Grant for TestGrant {
        fn owner_uid(&self) -> &str {
            &self.owner
        }
    }

    struct TestStore {
        // grant_id -> (subject, owner) the store will match
        expect_subject: String,
        owner: String,
    }
    #[async_trait::async_trait]
    impl GrantStore for TestStore {
        type Grant = TestGrant;
        async fn lookup_grant_for_subject(
            &self,
            _grant_id: Uuid,
            requester_chirp_sub: &str,
        ) -> Result<Option<TestGrant>, ApiError> {
            if requester_chirp_sub == self.expect_subject {
                Ok(Some(TestGrant {
                    owner: self.owner.clone(),
                }))
            } else {
                Ok(None)
            }
        }
    }

    fn machine_ctx(grant: &str) -> (HeaderMap, OnBehalfOf) {
        (
            hm(&[("x-approval-grant", grant)]),
            OnBehalfOf {
                uid: "owner_sub_from_token".into(),
                agent_id: "agent_machine_sub".into(),
                approval_grant_id: None,
            },
        )
    }

    #[tokio::test]
    async fn human_identity_is_noop() {
        let store = TestStore {
            expect_subject: "anything".into(),
            owner: "should-not-apply".into(),
        };
        let h = hm(&[("x-approval-grant", "550e8400-e29b-41d4-a716-446655440000")]);
        let mut ctx = OnBehalfOf {
            uid: "human-1".into(),
            agent_id: "human-1".into(), // uid == agent_id => human
            approval_grant_id: None,
        };
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "human-1"); // unchanged
        // header still copied through
        assert!(ctx.approval_grant_id.is_some());
    }

    #[tokio::test]
    async fn valid_grant_overrides_uid() {
        let store = TestStore {
            expect_subject: "agent_machine_sub".into(),
            owner: "target-human".into(),
        };
        let (h, mut ctx) = machine_ctx("550e8400-e29b-41d4-a716-446655440000");
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "target-human");
        assert_eq!(
            ctx.approval_grant_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
    }

    #[tokio::test]
    async fn malformed_grant_id_is_noop() {
        let store = TestStore {
            expect_subject: "agent_machine_sub".into(),
            owner: "target-human".into(),
        };
        let (h, mut ctx) = machine_ctx("not-a-uuid");
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "owner_sub_from_token"); // unchanged
    }

    #[tokio::test]
    async fn lookup_miss_is_noop() {
        let store = TestStore {
            expect_subject: "some-other-subject".into(),
            owner: "target-human".into(),
        };
        let (h, mut ctx) = machine_ctx("550e8400-e29b-41d4-a716-446655440000");
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "owner_sub_from_token"); // unchanged
    }

    #[tokio::test]
    async fn missing_grant_header_is_noop() {
        let store = TestStore {
            expect_subject: "agent_machine_sub".into(),
            owner: "target-human".into(),
        };
        let h = HeaderMap::new();
        let mut ctx = OnBehalfOf {
            uid: "owner_sub_from_token".into(),
            agent_id: "agent_machine_sub".into(),
            approval_grant_id: None,
        };
        apply_on_behalf_of_grant(&store, &h, &mut ctx).await.unwrap();
        assert_eq!(ctx.uid, "owner_sub_from_token");
        assert_eq!(ctx.approval_grant_id, None);
    }
}

// ---- Shared MachineAuth: allowlist plumbing + from_env (no network) ------

#[cfg(test)]
mod machine_auth_config_tests {
    use super::MachineAuth;
    use std::collections::BTreeSet;

    /// The security-critical seam: the configured `client_id` allowlist is fed
    /// VERBATIM into the lib's machine gate (`VerifyOptions`). The lib owns the
    /// per-token membership decision (a verified non-member →
    /// `MachineAudienceNotAccepted`); this proves the set the lib gates on is
    /// exactly the configured one — the rule Drive/Granite/Spend each used to
    /// hand-roll.
    #[test]
    fn configured_allowlist_is_fed_to_the_lib_gate() {
        let machine = MachineAuth::new(
            "https://signin.chirpauth.com",
            ["cs_live_aaa".to_owned(), "cs_live_bbb".to_owned()],
        );
        let options = machine.verify_options();
        assert!(options.accept_machine, "opted into machine acceptance");
        assert!(options.accepted_machine_audiences.contains("cs_live_aaa"));
        assert!(options.accepted_machine_audiences.contains("cs_live_bbb"));
        // A different confidential client in the same environment — whose machine
        // token would pass sig/iss/exp and skip the human aud check — is NOT in
        // the set the lib gates on, so the lib rejects it.
        assert!(!options.accepted_machine_audiences.contains("cs_live_other"));
        assert!(!options.accepted_machine_audiences.contains(""));

        let want: BTreeSet<String> =
            ["cs_live_aaa".to_owned(), "cs_live_bbb".to_owned()].into_iter().collect();
        assert_eq!(machine.accepted_client_ids(), &want);
    }

    /// Fail-closed: an empty accepted set feeds the lib an empty
    /// `accepted_machine_audiences`, which accepts NO machine token. (`from_env`
    /// returns `None` for an empty list, so this path is unreachable from env —
    /// but the gate itself must still fail closed.)
    #[test]
    fn empty_allowlist_accepts_no_machine_token() {
        let machine = MachineAuth::new("https://signin.chirpauth.com", Vec::<String>::new());
        let options = machine.verify_options();
        assert!(options.accept_machine, "still an opt-in");
        assert!(
            options.accepted_machine_audiences.is_empty(),
            "but with no accepted client_id, the lib admits no machine token"
        );
        assert!(machine.accepted_client_ids().is_empty());
    }

    /// GRANITE ISSUER FALLBACK: `from_env` tries the issuer env vars in order,
    /// first non-empty wins. This is the prior blocker — Granite reads
    /// `GRANITE_CHIRP_ISSUER` else `CHIRP_AUTH_ISSUER`. The single-var (Drive /
    /// Spend) and the missing/off cases are exercised too. `from_env` is the only
    /// reader of these process-global vars in this module, guarded by clearing
    /// them around each step.
    #[test]
    fn from_env_issuer_fallback_and_off_by_default() {
        const PRIMARY: &str = "PLATFORM_TEST_GRANITE_CHIRP_ISSUER";
        const FALLBACK: &str = "PLATFORM_TEST_CHIRP_AUTH_ISSUER";
        const AUDS: &str = "PLATFORM_TEST_ACCEPTED_MACHINE_AUDIENCES";

        fn clear() {
            // SAFETY: single-threaded within this #[test]; the only test that
            // touches these uniquely-named vars.
            unsafe {
                std::env::remove_var(PRIMARY);
                std::env::remove_var(FALLBACK);
                std::env::remove_var(AUDS);
            }
        }

        // Nothing set → off (None), behavior-unchanged.
        clear();
        assert!(MachineAuth::from_env(&[PRIMARY, FALLBACK], AUDS).is_none());

        // Issuer present but no audiences → still off.
        clear();
        unsafe { std::env::set_var(PRIMARY, "https://signin.chirpauth.com") };
        assert!(
            MachineAuth::from_env(&[PRIMARY, FALLBACK], AUDS).is_none(),
            "issuer without audiences must stay off"
        );

        // Audiences present but no issuer → still off.
        clear();
        unsafe { std::env::set_var(AUDS, "cs_live_aaa") };
        assert!(
            MachineAuth::from_env(&[PRIMARY, FALLBACK], AUDS).is_none(),
            "audiences without an issuer must stay off"
        );

        // PRIMARY wins when both issuer vars are set (Granite's preference).
        clear();
        unsafe {
            std::env::set_var(PRIMARY, "https://primary.chirpauth.com");
            std::env::set_var(FALLBACK, "https://fallback.chirpauth.com");
            std::env::set_var(AUDS, "cs_live_aaa, cs_live_bbb");
        }
        let machine = MachineAuth::from_env(&[PRIMARY, FALLBACK], AUDS).expect("configured");
        assert_eq!(machine.issuer(), "https://primary.chirpauth.com");
        // Comma-split + trim of the audiences list.
        assert!(machine.accepted_client_ids().contains("cs_live_aaa"));
        assert!(machine.accepted_client_ids().contains("cs_live_bbb"));

        // FALLBACK is used only when PRIMARY is UNSET. A set-but-blank PRIMARY does
        // NOT fall through — it trims to empty and disables the machine path (None),
        // matching granite's `var(primary).or_else(var(secondary)).map(trim).filter(!empty)`.
        clear();
        unsafe {
            std::env::set_var(PRIMARY, "   "); // set-but-blank
            std::env::set_var(FALLBACK, "https://fallback.chirpauth.com");
            std::env::set_var(AUDS, "cs_live_aaa");
        }
        assert!(
            MachineAuth::from_env(&[PRIMARY, FALLBACK], AUDS).is_none(),
            "set-but-blank primary trims to empty and stays off (does NOT fall back)"
        );

        // PRIMARY genuinely UNSET → the fallback is used.
        clear();
        unsafe {
            std::env::set_var(FALLBACK, "https://fallback.chirpauth.com");
            std::env::set_var(AUDS, "cs_live_aaa");
        }
        let machine = MachineAuth::from_env(&[PRIMARY, FALLBACK], AUDS).expect("configured");
        assert_eq!(
            machine.issuer(),
            "https://fallback.chirpauth.com",
            "unset primary falls back to the secondary issuer var"
        );

        // Single-var form (Drive / Spend: no fallback) behaves identically.
        clear();
        unsafe {
            std::env::set_var(PRIMARY, "https://signin.chirpauth.com");
            std::env::set_var(AUDS, "cs_live_aaa");
        }
        let machine = MachineAuth::from_env(&[PRIMARY], AUDS).expect("configured");
        assert_eq!(machine.issuer(), "https://signin.chirpauth.com");

        clear();
    }
}

// ---- Shared MachineAuth: full verify path against an in-process JWKS -----
//
// The cryptographic verify path itself is chirp-auth-client's (and its own
// tests cover it). These prove only what the SHARED layer adds on top:
// identity-type dispatch (a Human token on the machine path is rejected), the
// Environment returned VERBATIM from the lib, the issuer threaded through, and
// the non-allowlisted-client rejection surfacing as `Unauthorized`.

#[cfg(test)]
mod machine_auth_verify_tests {
    use super::{MachineAuth, MachineAuthError, VerifiedMachine};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chirp_auth_client::Environment;
    use platform_http_error::ApiError;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const KID: &str = "test-kid-1";
    const CLIENT_ID: &str = "cs_live_accepted";

    fn keypair() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = rand::thread_rng();
            RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key")
        })
    }

    fn jwks_body() -> String {
        let pubkey = RsaPublicKey::from(keypair());
        let n = URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
        format!(r#"{{"keys":[{{"kty":"RSA","kid":"{KID}","alg":"RS256","n":"{n}","e":"{e}"}}]}}"#)
    }

    async fn start_jwks_server(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/jwks.json");
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        url
    }

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    fn sign(signing_input: &[u8]) -> Vec<u8> {
        let signer = SigningKey::<Sha256>::new(keypair().clone());
        let mut rng = rand::thread_rng();
        signer.sign_with_rng(&mut rng, signing_input).to_bytes().to_vec()
    }

    fn make_jwt(claims_json: &str) -> String {
        // The typ chirp actually stamps on ID tokens (machine tokens are ID tokens
        // with act:machine). client v0.13 made this typ REQUIRED on the verify path,
        // so a fixture minting the generic "JWT" typ is now rejected — mint what the
        // real issuer does.
        let header = format!(r#"{{"alg":"RS256","typ":"chirp-id+jwt","kid":"{KID}"}}"#);
        let signing_input = format!("{}.{}", b64(&header), b64(claims_json));
        let sig = sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Build a `MachineAuth` accepting `CLIENT_ID` whose JWKS fetch hits the
    /// in-process server at `jwks_url`.
    ///
    /// `MachineAuth::new` derives `jwks_uri = {issuer}/jwks.json` (there is no
    /// public override — production callers must let it derive). So we set the
    /// issuer to the server's base (the url minus the trailing `/jwks.json`),
    /// which makes the derived `jwks_uri` exactly `jwks_url`. The minted token's
    /// `iss` is then that same base, satisfying the lib's exact-issuer check.
    fn machine_for(jwks_url: &str) -> MachineAuth {
        let base = jwks_url.strip_suffix("/jwks.json").expect("jwks url shape");
        MachineAuth::new(base.to_owned(), [CLIENT_ID.to_owned()])
    }

    /// ENV VERBATIM + happy path: a well-formed allowlisted machine token from a
    /// production issuer verifies, the returned `Environment` is exactly what the
    /// lib derived (`Production`), and `sub`/`owner_sub`/`client_id`/`issuer` are
    /// threaded through unchanged.
    #[tokio::test(flavor = "multi_thread")]
    async fn verifies_machine_token_and_returns_env_verbatim() {
        let jwks = start_jwks_server(jwks_body()).await;
        let machine = machine_for(&jwks);
        let iss = machine.issuer().to_owned();
        let claims = format!(
            r#"{{"iss":"{iss}","sub":"agent_xyz","aud":"{CLIENT_ID}","exp":{},"act":"machine","owner_sub":"sub_owner"}}"#,
            now() + 3600
        );
        let token = make_jwt(&claims);
        let VerifiedMachine {
            sub,
            owner_sub,
            client_id,
            environment,
            issuer,
        } = machine
            .verify(&reqwest::Client::new(), &token)
            .await
            .expect("allowlisted machine token verifies");
        assert_eq!(sub, "agent_xyz");
        assert_eq!(owner_sub, "sub_owner");
        assert_eq!(client_id, CLIENT_ID);
        // Verbatim from the lib's provenance derivation, not remapped here.
        assert_eq!(environment, Environment::Prod);
        assert_eq!(issuer, iss);
    }

    /// HUMAN-TOKEN REJECTION: a valid human token from the same issuer is the
    /// wrong identity type for the machine path. It is `NotMachine` (a VALID
    /// token, so a Granite-style caller falls through to its user path), and
    /// collapses to `Unauthorized` for the simple consumers via `into_api_error`.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_human_token_on_machine_path() {
        let jwks = start_jwks_server(jwks_body()).await;
        let machine = machine_for(&jwks);
        let iss = machine.issuer().to_owned();
        // A human token's `aud` must match the config's accepted set (the lib
        // gates human `aud`); the accepted set is `CLIENT_ID`, so use it.
        let claims = format!(
            r#"{{"iss":"{iss}","sub":"sub_human","aud":"{CLIENT_ID}","exp":{}}}"#,
            now() + 3600
        );
        let token = make_jwt(&claims);
        let err = machine
            .verify(&reqwest::Client::new(), &token)
            .await
            .expect_err("a human token on the machine path is rejected");
        // Granite distinguishes this (fall through to the user path); the simple
        // consumers collapse it to a 401.
        assert_eq!(err, MachineAuthError::NotMachine);
        assert!(matches!(err.into_api_error(), ApiError::Unauthorized));
    }

    /// ALLOWLIST REJECT: a verified machine token whose `client_id` is NOT in the
    /// accepted set is rejected by the lib gate. This is the DEFINITIVE
    /// `Rejected` case — a verified-but-not-allowlisted agent must 401 and must
    /// NOT be re-treated as a user token (Granite's `Some(Err)` outcome).
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_non_allowlisted_machine_client() {
        let jwks = start_jwks_server(jwks_body()).await;
        let machine = machine_for(&jwks);
        let iss = machine.issuer().to_owned();
        // Mint a machine token for a DIFFERENT client_id (its own `aud`), not in
        // the accepted set. It passes sig/iss/exp but fails the machine gate.
        let claims = format!(
            r#"{{"iss":"{iss}","sub":"agent_other","aud":"cs_live_not_accepted","exp":{},"act":"machine","owner_sub":"sub_owner"}}"#,
            now() + 3600
        );
        let token = make_jwt(&claims);
        let err = machine
            .verify(&reqwest::Client::new(), &token)
            .await
            .expect_err("a non-allowlisted machine client is rejected");
        assert_eq!(err, MachineAuthError::Rejected);
        assert!(matches!(err.into_api_error(), ApiError::Unauthorized));
    }

    /// UPSTREAM UNAVAILABLE: when ChirpAuth's JWKS answers with API Gateway's
    /// 429 throttle, a perfectly valid allowlisted machine token cannot be
    /// checked. That is `Unavailable` → 503, never `NotMachine` → 401 (the
    /// silent-401 failure mode this variant exists to end).
    #[tokio::test(flavor = "multi_thread")]
    async fn throttled_jwks_is_unavailable_not_a_401() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let jwks = format!("http://{}/jwks.json", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let body = r#"{"message":"Too Many Requests"}"#;
                    let resp = format!(
                        "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let machine = machine_for(&jwks);
        let iss = machine.issuer().to_owned();
        let claims = format!(
            r#"{{"iss":"{iss}","sub":"agent_xyz","aud":"{CLIENT_ID}","exp":{},"act":"machine","owner_sub":"sub_owner"}}"#,
            now() + 3600
        );
        let err = machine
            .verify(&reqwest::Client::new(), &make_jwt(&claims))
            .await
            .expect_err("an unfetchable JWKS cannot verify anything");
        assert_eq!(err, MachineAuthError::Unavailable);
        assert!(matches!(err.into_api_error(), ApiError::ServiceUnavailable(_)));
        assert!(matches!(ApiError::from(err), ApiError::ServiceUnavailable(_)));
    }
}
