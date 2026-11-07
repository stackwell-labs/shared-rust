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
//!   audiences, which machine clients ([`Machines`]), and which test tenants
//!   the deployment serves beside its own issuer. [`Authenticator::new`]
//!   refuses a policy that accepts nobody or names an empty set.
//! - **The environment is decided here, once** (agent-platform--protocols#39):
//!   each request gets its [`Plane`], `Prod` or `Test { tenant }`, from the
//!   keyset that verified its token. The service picks its store handle (and
//!   any downstream credentials) from the plane; [`Caller`] carries no
//!   environment, so nothing below the handle sees one (shared-rust#19).
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
//! use platform_chirp_auth::{env, Authenticated, Authenticator, Machines, Policy};
//!
//! let auth = Authenticator::new(Policy {
//!     issuer: env::issuer("GRANITE")?,
//!     humans: Some(env::human_audiences("GRANITE")?),
//!     machines: Machines::Allow(env::machine_clients("GRANITE")?),
//!     test_tenants: Some(["journeys".to_owned()].into()),
//! })?;
//! // At boot: one store handle per `auth.planes()`.
//! // In a handler: `Authenticated { caller, plane }` (the axum extractor, with
//! // `Authenticator: FromRef<State>`), or `auth.authenticate(&headers).await?`.
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use http::request::Parts;
use platform_http_error::ApiError;

use crate::{
    bearer_token, environment_from_issuer, verify_chirp_id_token, ChirpAuthConfig, ChirpAuthError,
    ChirpVerifiedIdentity, Environment, VerifyFailure, VerifyOptions,
};

/// Which data plane a request belongs to: `Prod`, or `Test { tenant }` for a
/// token one test tenant's keyset verified. A service picks its store handle
/// (and the credentials it calls other services with) from it, and passes the
/// handle down, never the plane (agent-platform--protocols#39).
///
/// Test is keyed by tenant: ChirpAuth lets every tenant mint any `test:` sub,
/// so tenant `a`'s `test:alice` and tenant `b`'s are different people, on
/// different planes.
///
/// The same type as [`Environment`] (one definition platform-wide,
/// capability#2), named for what it is used for here.
pub type Plane = Environment;

/// Which chirp callers a service accepts. Every field is required, so each
/// service states its machine and test-tenant policy in its own code.
#[derive(Clone, Debug)]
pub struct Policy {
    /// The deployment's ChirpAuth issuer. The JWKS URL derives from it
    /// (`{issuer}/jwks.json`). Production's issuer is the [`Plane::Prod`]
    /// plane; a `…/test/{tenant}` issuer makes a deployment that serves only
    /// that tenant's [`Plane::Test`] plane.
    pub issuer: String,
    /// Audiences (this service's RP client ids) a human id_token may be minted
    /// for. `None`: no human token verifies here (a machine-only service).
    pub humans: Option<BTreeSet<String>>,
    /// Which machine tokens are accepted, on every plane.
    pub machines: Machines,
    /// Test tenants served beside production, each verified against its own
    /// keyset at `{issuer}/test/{tenant}`, so a token from any other tenant
    /// gets a 401. `None`: only `issuer`'s plane. Declare one only once the
    /// service has a store for its plane. Needs a production `issuer`.
    pub test_tenants: Option<BTreeSet<String>>,
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

/// A verified chirp principal. Which plane it acts on is the [`Plane`] beside
/// it in [`Authenticated`], not part of it: the same `sub` on two planes is two
/// different callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// A person signed in to this service: their pairwise `sub`.
    Human { sub: String },
    /// A confidential client: the agent `sub`, the person who registered the
    /// client (`owner_sub`), and the minting `client_id`, already checked
    /// against [`Machines`].
    Machine {
        sub: String,
        owner_sub: String,
        client_id: String,
    },
}

impl Caller {
    /// The verified `sub`, whatever the variant.
    pub fn sub(&self) -> &str {
        match self {
            Self::Human { sub } | Self::Machine { sub, .. } => sub,
        }
    }
}

/// A verified request: who ([`Caller`]) and on which [`Plane`]. The plane is
/// one of [`Authenticator::planes`], decided by the keyset that verified the
/// token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticated {
    pub caller: Caller,
    pub plane: Plane,
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
            AuthFailure::Unauthorized | AuthFailure::RejectedMachine => {
                VerifyFailure::Invalid.into()
            }
            AuthFailure::Unavailable => VerifyFailure::Unavailable.into(),
        }
    }
}

impl IntoResponse for AuthFailure {
    fn into_response(self) -> Response {
        ApiError::from(self).into_response()
    }
}

/// A [`Policy`] that cannot be served, a missing or blank env var, or a chirp
/// control client ([`RootResolver`](crate::RootResolver),
/// [`OperatorIntrospector`](crate::OperatorIntrospector)) given a base URL it
/// cannot use. Refuse to boot on it: a half-configured service would otherwise
/// 401 or 503 every request while its health check stays green.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub(crate) String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Verifies chirp bearers against one [`Policy`], for each of its planes.
/// Cheap to clone (one `Arc`), so it can sit in axum state.
#[derive(Clone, Debug)]
pub struct Authenticator {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// The deployment's issuer, normalized.
    issuer: String,
    /// One config per served plane, keyed by its normalized issuer.
    configs: BTreeMap<String, ChirpAuthConfig>,
    planes: Vec<Plane>,
    options: VerifyOptions,
    machines: Machines,
    http: reqwest::Client,
}

impl Authenticator {
    /// Check `policy` and build the authenticator. Entries are trimmed. Refuses
    /// a blank issuer, an empty audience, client or tenant set (say `None`
    /// instead), a policy accepting neither humans nor machines, a tenant that
    /// is not one path segment, and test tenants beside a test issuer.
    pub fn new(policy: Policy) -> Result<Self, ConfigError> {
        let issuer = policy.issuer.trim().trim_end_matches('/').to_owned();
        if issuer.is_empty() {
            return Err(ConfigError("the chirp issuer is blank".to_owned()));
        }
        let mut issuers = vec![issuer.clone()];
        if let Some(tenants) = policy.test_tenants {
            if let Environment::Test { tenant } = environment_from_issuer(&issuer) {
                return Err(ConfigError(format!(
                    "{issuer} is test tenant {tenant}'s issuer; test tenants need the production issuer"
                )));
            }
            for tenant in non_empty(tenants, "the test tenant set")? {
                let test_issuer = format!("{issuer}/test/{tenant}");
                if environment_from_issuer(&test_issuer)
                    != (Environment::Test {
                        tenant: tenant.clone(),
                    })
                {
                    return Err(ConfigError(format!(
                        "test tenant {tenant:?} is not a single path segment"
                    )));
                }
                issuers.push(test_issuer);
            }
        }
        let humans = match policy.humans {
            None => None,
            Some(audiences) => Some(non_empty(audiences, "the human audience set")?),
        };
        let machines = match policy.machines {
            Machines::Allow(clients) => {
                Machines::Allow(non_empty(clients, "the machine client set")?)
            }
            other => other,
        };
        if humans.is_none() && matches!(machines, Machines::None) {
            return Err(ConfigError(
                "the policy accepts neither humans nor machines".to_owned(),
            ));
        }
        let options = match &machines {
            Machines::None => VerifyOptions::default(),
            Machines::Allow(clients) => {
                VerifyOptions::accept_machine_clients(clients.iter().cloned())
            }
            Machines::Any | Machines::Dynamic(_) => {
                let mut options = VerifyOptions::accept_machine_clients(std::iter::empty());
                options.accept_any_machine_client = true;
                options
            }
        };
        // No human audience: an empty set, which no human id_token matches.
        let audiences: Vec<String> = humans.into_iter().flatten().collect();
        let configs: BTreeMap<String, ChirpAuthConfig> = issuers
            .into_iter()
            .map(|issuer| {
                let config = ChirpAuthConfig::with_audiences(issuer, audiences.iter().cloned());
                (config.issuer().to_owned(), config)
            })
            .collect();
        let planes = configs.values().map(ChirpAuthConfig::environment).collect();
        Ok(Self {
            inner: Arc::new(Inner {
                issuer,
                configs,
                planes,
                options,
                machines,
                http: reqwest::Client::new(),
            }),
        })
    }

    /// The deployment's normalized issuer ([`Policy::issuer`]).
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// Every plane a request can be on: the issuer's, then each declared test
    /// tenant's. Build one store handle for each at boot.
    pub fn planes(&self) -> &[Plane] {
        &self.inner.planes
    }

    /// Authenticate the request's `Authorization: Bearer` token. No bearer is
    /// [`AuthFailure::Unauthorized`].
    pub async fn authenticate(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<Authenticated, AuthFailure> {
        let token = bearer_token(headers).ok_or(AuthFailure::Unauthorized)?;
        self.verify(token).await
    }

    /// Verify a bearer token already taken from the request.
    pub async fn verify(&self, token: &str) -> Result<Authenticated, AuthFailure> {
        let inner = &*self.inner;
        // The token's unverified `iss` only picks which keyset to try; that
        // keyset's signature check, and the `iss` check against it, decide.
        // An issuer this deployment does not serve is never fetched.
        let config = unverified_issuer(token)
            .and_then(|issuer| inner.configs.get(&issuer))
            .ok_or(AuthFailure::Unauthorized)?;
        let verified = verify_chirp_id_token(&inner.http, config, token, inner.options.clone())
            .await
            .map_err(|error| match error {
                ChirpAuthError::MachineAudienceNotAccepted => AuthFailure::RejectedMachine,
                other => match VerifyFailure::classify(&other) {
                    VerifyFailure::Invalid => AuthFailure::Unauthorized,
                    VerifyFailure::Unavailable => AuthFailure::Unavailable,
                },
            })?;
        // The plane is the verifying keyset's (provenance), never the token
        // kind's: chirp-auth-client returns a test-keyset machine token as
        // `Machine`, with a test environment.
        let caller = match (&verified.environment, verified.identity) {
            (Environment::Prod, ChirpVerifiedIdentity::Human { sub }) => Caller::Human { sub },
            // chirp-auth-client builds `Test` only from a test keyset; refuse
            // rather than trust a production one that claims it.
            (Environment::Prod, ChirpVerifiedIdentity::Test { .. }) => {
                return Err(AuthFailure::Unauthorized)
            }
            (
                Environment::Test { .. },
                ChirpVerifiedIdentity::Human { sub } | ChirpVerifiedIdentity::Test { sub },
            ) => Caller::Human { sub },
            (
                _,
                ChirpVerifiedIdentity::Machine {
                    sub,
                    owner_sub,
                    client_id,
                },
            ) => {
                self.admit_machine(&client_id).await?;
                Caller::Machine {
                    sub,
                    owner_sub,
                    client_id,
                }
            }
        };
        Ok(Authenticated {
            caller,
            plane: verified.environment,
        })
    }

    /// The [`Machines::Dynamic`] check, made after the token verifies. The
    /// other policies were already applied inside chirp-auth-client.
    async fn admit_machine(&self, client_id: &str) -> Result<(), AuthFailure> {
        let Machines::Dynamic(allowlist) = &self.inner.machines else {
            return Ok(());
        };
        match allowlist.allows(client_id).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(AuthFailure::RejectedMachine),
            Err(AllowlistUnavailable) => Err(AuthFailure::Unavailable),
        }
    }
}

/// The `iss` claim of a JWT, unverified. `None` for anything that is not a JWT
/// with a string `iss`.
fn unverified_issuer(token: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Iss {
        iss: String,
    }
    let claims = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(claims).ok()?;
    serde_json::from_slice::<Iss>(&bytes)
        .ok()
        .map(|claims| claims.iss)
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

/// The axum extractor: a handler taking [`Authenticated`] gets a verified
/// caller and its plane, or the request is answered with the [`AuthFailure`]'s
/// status. There is deliberately no extractor for [`Caller`] alone, so a
/// handler cannot drop the plane without writing `..`.
impl<S> FromRequestParts<S> for Authenticated
where
    Authenticator: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthFailure;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Authenticator::from_ref(state)
            .authenticate(&parts.headers)
            .await
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
