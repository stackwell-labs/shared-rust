//! One chirp bearer authenticator for every service (shared-rust#3).
//!
//! Ten services each hand-rolled the same dispatcher: read their own env vars,
//! verify the bearer as a machine token, fall through to a human verify, and
//! map the errors. The copies drifted on what matters: seven answered a
//! ChirpAuth outage with 401, test-keyset identities were accepted or refused
//! by whichever match arm a service happened to write, and a half-configured
//! issuer switched auth off instead of refusing to boot.
//!
//! [`Authenticator`] owns those rules, and only it:
//!
//! - **What is accepted is a [`Policy`] fixed at construction:** human
//!   audiences, which machine clients ([`Machines`]), and whether a test-keyset
//!   principal is honoured ([`TestIdentities`]). [`Authenticator::new`] refuses a
//!   policy that accepts nobody or names an empty set.
//! - **One verify call per request.** chirp-auth-client checks a human token's
//!   audience and a machine token's client in the same pass, so there is no
//!   machine-then-human fall-through to get wrong, and a rejected machine token
//!   is [`AuthFailure::RejectedMachine`], never retried as a human.
//! - **A ChirpAuth outage is [`AuthFailure::Unavailable`], a 503** (via
//!   [`VerifyFailure`]), never a 401.
//!
//! The JWKS cache and fetch timeout stay in chirp-auth-client. A service keeps
//! only the mapping from [`Caller`] to its own user type and any product
//! credential kinds it checks before or after the chirp bearer.
//!
//! ```ignore
//! use platform_chirp_auth::{env, Authenticator, Machines, Policy, TestIdentities};
//!
//! let auth = Authenticator::new(Policy {
//!     issuer: env::issuer("SPEND")?,
//!     humans: Some(env::human_audiences("SPEND")?),
//!     machines: Machines::Allow(env::machine_clients("SPEND")?),
//!     test_identities: TestIdentities::Reject,
//! })?;
//! // In a handler: `caller: Caller` (the axum extractor, with
//! // `Authenticator: FromRef<State>`), or `auth.authenticate(&headers).await?`.
//! ```

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::response::{IntoResponse, Response};
use http::request::Parts;
use platform_http_error::ApiError;

use crate::{
    bearer_token, verify_chirp_id_token, ChirpAuthConfig, ChirpAuthError, ChirpVerifiedIdentity,
    Environment, VerifyFailure, VerifyOptions,
};

/// Which chirp callers a service accepts. Every field is required, so each
/// service states its machine and test-identity policy in its own code.
#[derive(Clone, Debug)]
pub struct Policy {
    /// The ChirpAuth issuer. The JWKS URL derives from it
    /// (`{issuer}/jwks.json`); a `…/test/{tenant}` issuer verifies that test
    /// tenant's keyset instead of production's.
    pub issuer: String,
    /// Audiences (this service's RP client ids) a human id_token may be minted
    /// for. `None`: no human token verifies here (a machine-only service).
    pub humans: Option<BTreeSet<String>>,
    /// Which machine tokens are accepted.
    pub machines: Machines,
    /// Whether a test-keyset principal is honoured.
    pub test_identities: TestIdentities,
}

/// Which machine (`client_credentials`) tokens a service accepts, by the
/// minting `client_id`.
#[derive(Clone)]
pub enum Machines {
    /// No machine token is accepted.
    None,
    /// Only these clients. Membership is checked inside chirp-auth-client.
    Allow(BTreeSet<String>),
    /// Any client. Sound only where every operation is authorized by a
    /// separate grant rather than by which client authenticated (Pigeon).
    Any,
    /// A set that changes at runtime (relstore's tenant-provisioned clients,
    /// Shriek's CLIENTBIND registry). Consulted after the token verifies.
    Dynamic(Arc<dyn MachineAllowlist>),
}

impl fmt::Debug for Machines {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Allow(set) => f.debug_tuple("Allow").field(set).finish(),
            Self::Any => f.write_str("Any"),
            Self::Dynamic(_) => f.write_str("Dynamic(..)"),
        }
    }
}

/// A machine-client allowlist read at request time, for [`Machines::Dynamic`].
#[async_trait::async_trait]
pub trait MachineAllowlist: Send + Sync {
    /// Whether `client_id` may call this service. `Err` means the allowlist
    /// could not be read; the request gets a 503, not a 401.
    async fn allows(&self, client_id: &str) -> Result<bool, AllowlistUnavailable>;
}

/// The [`MachineAllowlist`] could not be read (its store is down).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowlistUnavailable;

/// Whether a test-keyset principal ([`Caller::Test`]) is honoured.
///
/// A test principal only verifies against a `…/test/{tenant}` issuer, and it is
/// kept apart from [`Caller::Human`] so a production surface cannot honour one
/// by forgetting to check the environment. Accept it only once the service's
/// stores are scoped by environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TestIdentities {
    /// A test principal gets a 401.
    Reject,
    /// A test principal is returned as [`Caller::Test`].
    Accept,
}

/// A verified chirp caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// A person signed in to this service: their pairwise `sub`.
    Human { sub: String, environment: Environment },
    /// A confidential client: the agent `sub`, the person who registered the
    /// client (`owner_sub`), and the minting `client_id`, already checked
    /// against [`Machines`].
    Machine {
        sub: String,
        owner_sub: String,
        client_id: String,
        environment: Environment,
    },
    /// A test-keyset principal. Only returned under [`TestIdentities::Accept`].
    Test { sub: String, environment: Environment },
}

impl Caller {
    /// The verified `sub`, whatever the variant.
    pub fn sub(&self) -> &str {
        match self {
            Self::Human { sub, .. } | Self::Machine { sub, .. } | Self::Test { sub, .. } => sub,
        }
    }

    /// Which ChirpAuth keyset verified the caller.
    pub fn environment(&self) -> &Environment {
        match self {
            Self::Human { environment, .. }
            | Self::Machine { environment, .. }
            | Self::Test { environment, .. } => environment,
        }
    }
}

/// Why [`Authenticator::authenticate`] yielded no caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFailure {
    /// No bearer, or a bearer this service does not accept. A service with
    /// another credential kind may try it next. 401.
    Unauthorized,
    /// A verified machine token from a client this service does not accept.
    /// Definitive: do not try the bearer as any other credential. 401.
    RejectedMachine,
    /// ChirpAuth's JWKS (or a [`MachineAllowlist`]) could not be read, so the
    /// token was never judged. Do not fall through. 503.
    Unavailable,
}

impl From<AuthFailure> for ApiError {
    fn from(failure: AuthFailure) -> Self {
        match failure {
            AuthFailure::Unauthorized | AuthFailure::RejectedMachine => VerifyFailure::Invalid.into(),
            AuthFailure::Unavailable => VerifyFailure::Unavailable.into(),
        }
    }
}

impl IntoResponse for AuthFailure {
    fn into_response(self) -> Response {
        ApiError::from(self).into_response()
    }
}

/// A [`Policy`] that cannot be served, or a missing or blank env var. Refuse to
/// boot on it: a half-configured service would otherwise 401 every request
/// while its health check stays green.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Verifies chirp bearers against one [`Policy`]. Cheap to clone (one `Arc`),
/// so it can sit in axum state.
#[derive(Clone, Debug)]
pub struct Authenticator {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: ChirpAuthConfig,
    options: VerifyOptions,
    machines: Machines,
    test_identities: TestIdentities,
    http: reqwest::Client,
}

impl Authenticator {
    /// Check `policy` and build the authenticator. Entries are trimmed. Refuses
    /// a blank issuer, an empty audience or client set (say `None` instead), and
    /// a policy accepting neither humans nor machines.
    pub fn new(policy: Policy) -> Result<Self, ConfigError> {
        let issuer = policy.issuer.trim().to_owned();
        if issuer.is_empty() {
            return Err(ConfigError("the chirp issuer is blank".to_owned()));
        }
        let humans = match policy.humans {
            None => None,
            Some(audiences) => Some(non_empty(audiences, "the human audience set")?),
        };
        let machines = match policy.machines {
            Machines::Allow(clients) => Machines::Allow(non_empty(clients, "the machine client set")?),
            other => other,
        };
        if humans.is_none() && matches!(machines, Machines::None) {
            return Err(ConfigError(
                "the policy accepts neither humans nor machines".to_owned(),
            ));
        }
        let options = match &machines {
            Machines::None => VerifyOptions::default(),
            Machines::Allow(clients) => VerifyOptions::accept_machine_clients(clients.iter().cloned()),
            Machines::Any | Machines::Dynamic(_) => {
                let mut options = VerifyOptions::accept_machine_clients(std::iter::empty());
                options.accept_any_machine_client = true;
                options
            }
        };
        // No human audience: an empty set, which no human id_token matches.
        let config = ChirpAuthConfig::with_audiences(issuer, humans.into_iter().flatten());
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                options,
                machines,
                test_identities: policy.test_identities,
                http: reqwest::Client::new(),
            }),
        })
    }

    /// The normalized issuer tokens are verified against.
    pub fn issuer(&self) -> &str {
        self.inner.config.issuer()
    }

    /// Authenticate the request's `Authorization: Bearer` token. No bearer is
    /// [`AuthFailure::Unauthorized`].
    pub async fn authenticate(&self, headers: &http::HeaderMap) -> Result<Caller, AuthFailure> {
        let token = bearer_token(headers).ok_or(AuthFailure::Unauthorized)?;
        self.verify(token).await
    }

    /// Verify a bearer token already taken from the request.
    pub async fn verify(&self, token: &str) -> Result<Caller, AuthFailure> {
        let inner = &*self.inner;
        let verified = verify_chirp_id_token(&inner.http, &inner.config, token, inner.options.clone())
            .await
            .map_err(|error| match error {
                ChirpAuthError::MachineAudienceNotAccepted => AuthFailure::RejectedMachine,
                other => match VerifyFailure::classify(&other) {
                    VerifyFailure::Invalid => AuthFailure::Unauthorized,
                    VerifyFailure::Unavailable => AuthFailure::Unavailable,
                },
            })?;
        let environment = verified.environment;
        match verified.identity {
            ChirpVerifiedIdentity::Human { sub } => Ok(Caller::Human { sub, environment }),
            ChirpVerifiedIdentity::Machine {
                sub,
                owner_sub,
                client_id,
            } => {
                if let Machines::Dynamic(allowlist) = &inner.machines {
                    match allowlist.allows(&client_id).await {
                        Ok(true) => {}
                        Ok(false) => return Err(AuthFailure::RejectedMachine),
                        Err(AllowlistUnavailable) => return Err(AuthFailure::Unavailable),
                    }
                }
                Ok(Caller::Machine {
                    sub,
                    owner_sub,
                    client_id,
                    environment,
                })
            }
            ChirpVerifiedIdentity::Test { sub } => match inner.test_identities {
                TestIdentities::Reject => Err(AuthFailure::Unauthorized),
                TestIdentities::Accept => Ok(Caller::Test { sub, environment }),
            },
        }
    }
}

fn non_empty(set: BTreeSet<String>, what: &str) -> Result<BTreeSet<String>, ConfigError> {
    let set: BTreeSet<String> = set
        .into_iter()
        .map(|entry| entry.trim().to_owned())
        .filter(|entry| !entry.is_empty())
        .collect();
    if set.is_empty() {
        return Err(ConfigError(format!(
            "{what} is empty; say None to accept none"
        )));
    }
    Ok(set)
}

/// The axum extractor: a handler taking a [`Caller`] gets a verified one, or
/// the request is answered with the [`AuthFailure`]'s status.
impl<S> FromRequestParts<S> for Caller
where
    Authenticator: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthFailure;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Authenticator::from_ref(state).authenticate(&parts.headers).await
    }
}

/// The one env-var naming scheme for chirp config: `{PREFIX}_CHIRP_ISSUER`,
/// `{PREFIX}_HUMAN_AUDIENCES` and `{PREFIX}_MACHINE_CLIENTS`, the last two
/// comma-separated. Each reader refuses a missing or blank value, so a service
/// reads only the vars its [`Policy`] needs and a missing one stops boot.
pub mod env {
    use std::collections::BTreeSet;

    use super::ConfigError;

    /// `{prefix}_CHIRP_ISSUER`.
    pub fn issuer(prefix: &str) -> Result<String, ConfigError> {
        read(&format!("{prefix}_CHIRP_ISSUER"))
    }

    /// `{prefix}_HUMAN_AUDIENCES`: this service's RP client ids.
    pub fn human_audiences(prefix: &str) -> Result<BTreeSet<String>, ConfigError> {
        list(&format!("{prefix}_HUMAN_AUDIENCES"))
    }

    /// `{prefix}_MACHINE_CLIENTS`: the machine clients for [`super::Machines::Allow`].
    pub fn machine_clients(prefix: &str) -> Result<BTreeSet<String>, ConfigError> {
        list(&format!("{prefix}_MACHINE_CLIENTS"))
    }

    fn read(name: &str) -> Result<String, ConfigError> {
        match std::env::var(name) {
            Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
            Ok(_) => Err(ConfigError(format!("{name} is blank"))),
            Err(_) => Err(ConfigError(format!("{name} is not set"))),
        }
    }

    fn list(name: &str) -> Result<BTreeSet<String>, ConfigError> {
        let set: BTreeSet<String> = read(name)?
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect();
        if set.is_empty() {
            return Err(ConfigError(format!("{name} names no entries")));
        }
        Ok(set)
    }
}
