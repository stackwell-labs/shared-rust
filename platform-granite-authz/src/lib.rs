//! The one Granite authoriser (shared-rust#21, agent-platform--protocols#47 S1).
//!
//! "What may this caller do?" has one home: a Granite grant, checked with
//! Granite's `POST /v1/grants/verify`. Each service used to hand-roll that call
//! (Model Gateway, Compute Gateway, Drive) or skip it for a machine allowlist.
//! [`GraniteAuthz::authorize`] is the one copy:
//!
//! 1. the caller must be a machine (a grant's subject is a machine; person
//!    subjects wait on granite#82), name the person it acts for in `x-user-id`,
//!    and present the grant id in `x-approval-grant`;
//! 2. the service asks Granite, with its own machine token, whether that grant
//!    lets this caller (the grant's subject) use `scope` on `resource`;
//! 3. the grant Granite returns must be on the request's plane
//!    ([`Authenticated::plane`]).
//!
//! **Failure is never a 401.** The caller was already authenticated. A missing,
//! malformed or unapproved grant is [`Refusal::Denied`] (403). Granite being
//! unreachable, answering 5xx, refusing this service's own token, or the token
//! failing to mint is [`Refusal::Unavailable`] (503): no verdict on the grant.
//!
//! **Online, no cache** (agent-platform--protocols#47 §2, option (a)). Each call
//! writes one CloudWatch EMF line to stdout with its latency and whether Granite
//! answered, per service and calling client, so a later cache decision rests on
//! data (see [`METRIC_NAMESPACE`]).
//!
//! **Configuration is not optional.** [`GraniteAuthz::new`] takes the Granite
//! base URL and the service's [`MachineTokenMinter`] and refuses a blank or
//! non-http(s) URL, so a service that builds it at boot fails there.
//!
//! Granite accepts the service's token only if its client is in Granite's
//! accepted machine audiences, and answers for another actor only if the service
//! is a grant enforcer (`GRANITE_GRANT_ENFORCERS`, an operator grant once
//! granite#81 lands). Until then a non-enforcer gets [`Refusal::Unavailable`]:
//! that is this service's configuration, not the caller's grant.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use granite_client::{ActingUser, Auth, GraniteClient, GraniteError, VerifyGrantRequest};
use http::{HeaderMap, StatusCode};
use platform_chirp_auth::mint::{MachineTokenMinter, MintError};
use platform_chirp_auth::{Authenticated, Caller};
use platform_http_error::ApiError;
use uuid::Uuid;

pub use granite_client::ApprovalGrant;

/// The header a caller presents its Granite grant id in.
pub const GRANT_HEADER: &str = platform_chirp_auth::APPROVAL_GRANT_HEADER;

/// The header a caller names the person it acts for in. Granite binds it to the
/// grant's owner (the same person under another pairwise sub) before approving.
pub const ACTING_USER_HEADER: &str = platform_chirp_auth::USER_ID_HEADER;

/// The bound on one verify request to Granite. Granite's handler p99 was 81 ms
/// over 2026-10-31..11-07, so this only catches a hang. A mint is bounded by
/// the minter's own HTTP client, which the service configures.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// The CloudWatch namespace of the per-verify EMF line. Dimensions
/// `[Service, Caller]` (the calling client id); metrics `VerifyLatency`
/// (milliseconds, mint included) and `VerifyUnavailable` (1 when Granite gave
/// no verdict, else 0, so its average is the error rate). `Outcome`
/// (`approved`, `denied`, `unavailable`) rides along as a log field.
pub const METRIC_NAMESPACE: &str = "Stackwell/GraniteAuthz";

/// A [`GraniteAuthz`] that could not be built. Boot should stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Why [`GraniteAuthz::authorize`] refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The caller has no grant for this. 403.
    Denied(Denied),
    /// Granite could not answer. 503; says nothing about the grant.
    Unavailable(Unavailable),
}

/// What was wrong with the caller's grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// No `x-approval-grant` header.
    NoGrant,
    /// `x-approval-grant` is not a grant id.
    MalformedGrant,
    /// No valid `x-user-id`: the caller did not say whom it acts for.
    NoActingUser,
    /// A person, not a machine. Grants name a machine subject today.
    NotAMachine,
    /// Granite does not approve this grant for this caller, resource and scope
    /// (or knows no such grant). `reason` is Granite's, when it gave one.
    NotApproved { reason: Option<String> },
    /// The grant was minted on another plane than the request's.
    WrongPlane,
}

/// Granite gave no verdict. `reason` is for a log line and holds no token and
/// no response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    reason: String,
}

impl Unavailable {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// What went wrong.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Denied(denied) => write!(f, "granite grant denied: {denied:?}"),
            Refusal::Unavailable(u) => write!(f, "granite unavailable: {}", u.reason),
        }
    }
}

impl std::error::Error for Refusal {}

/// 403 or 503. Log the [`Refusal`] first if its detail matters: the body is
/// fixed text.
impl From<Refusal> for ApiError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Denied(_) => ApiError::Forbidden,
            Refusal::Unavailable(_) => {
                ApiError::ServiceUnavailable("granite unavailable".to_owned())
            }
        }
    }
}

/// A grant Granite approved for this caller, resource and scope, on the
/// request's plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    /// The grant, as Granite returned it.
    pub grant: ApprovalGrant,
    /// The person the caller acts for, as the caller named them in `x-user-id`
    /// (this service's id for them), which Granite bound to the grant's owner.
    pub on_behalf_of: String,
}

/// Verifies callers' grants against Granite as this service. Cheap to clone.
#[derive(Clone)]
pub struct GraniteAuthz {
    service: String,
    base_url: String,
    minter: Arc<MachineTokenMinter>,
    http: reqwest::Client,
}

impl GraniteAuthz {
    /// An authoriser for `service` (its name, the metric's `Service` dimension:
    /// lowercase letters, digits and `-`), asking the Granite at
    /// `granite_base_url` (e.g. `https://granite.stackwell.tech`) with
    /// `minter`'s machine token.
    pub fn new(
        service: &str,
        granite_base_url: &str,
        minter: Arc<MachineTokenMinter>,
    ) -> Result<Self, ConfigError> {
        if service.is_empty()
            || !service
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(ConfigError(format!(
                "service name {service:?} must be lowercase letters, digits and '-'"
            )));
        }
        let base_url = granite_base_url.trim().trim_end_matches('/');
        let parsed = reqwest::Url::parse(base_url)
            .map_err(|e| ConfigError(format!("granite base URL does not parse: {e}")))?;
        if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
            return Err(ConfigError(
                "granite base URL must be an http(s) URL with a host".to_owned(),
            ));
        }
        // Granite's CloudFront WAF refuses a request with no User-Agent, and
        // reqwest sends none by default; owning the client makes that unmissable.
        let http = reqwest::Client::builder()
            .user_agent(format!(
                "platform-granite-authz/{} ({service})",
                env!("CARGO_PKG_VERSION")
            ))
            .timeout(VERIFY_TIMEOUT)
            .build()
            .map_err(|e| ConfigError(format!("build granite http client: {e}")))?;
        Ok(Self {
            service: service.to_owned(),
            base_url: base_url.to_owned(),
            minter,
            http,
        })
    }

    /// Whether the authenticated caller holds a grant, named by its
    /// `x-approval-grant` header, for `scope` on `resource`, acting for the
    /// person its `x-user-id` names.
    pub async fn authorize(
        &self,
        who: &Authenticated,
        headers: &HeaderMap,
        resource: &str,
        scope: &str,
    ) -> Result<Authorized, Refusal> {
        let Caller::Machine { sub, client_id, .. } = &who.caller else {
            return Err(Refusal::Denied(Denied::NotAMachine));
        };
        let grant_id = grant_id(headers)?;
        let on_behalf_of = platform_chirp_auth::decode_trusted_headers(headers)
            .map_err(|_| Refusal::Denied(Denied::NoActingUser))?
            .uid;

        let started = Instant::now();
        let result = self
            .verify(grant_id, sub, &on_behalf_of, resource, scope)
            .await
            .and_then(|grant| match grant.assert_environment(&who.plane) {
                Ok(()) => Ok(grant),
                Err(_) => Err(Refusal::Denied(Denied::WrongPlane)),
            });
        println!(
            "{}",
            emf_line(
                &self.service,
                client_id,
                started.elapsed(),
                Outcome::of(&result),
                SystemTime::now(),
            )
        );
        result.map(|grant| Authorized {
            grant,
            on_behalf_of,
        })
    }

    async fn verify(
        &self,
        grant_id: Uuid,
        subject_sub: &str,
        on_behalf_of: &str,
        resource: &str,
        scope: &str,
    ) -> Result<ApprovalGrant, Refusal> {
        let token = self.minter.token().await.map_err(|e| {
            Refusal::Unavailable(Unavailable::new(match e {
                MintError::Rejected(_) => {
                    "chirp rejected this service's client credentials".to_owned()
                }
                MintError::Suppressed { retry_after } => format!(
                    "machine-token minting suppressed for {}s after a rejection",
                    retry_after.as_secs()
                ),
                MintError::Transient(_) => "machine-token mint failed".to_owned(),
            }))
        })?;
        let client = GraniteClient::with_http(
            self.base_url.as_str(),
            Auth::ChirpBearer(token),
            self.http.clone(),
        );
        let request = VerifyGrantRequest::for_grant(grant_id)
            .with_resource(resource)
            .with_scopes([scope.to_owned()])
            .with_subject_chirp_sub(subject_sub);
        match client
            .verify_grant(&ActingUser::new(on_behalf_of), &request)
            .await
        {
            Ok(verification) if verification.approved => verification.grant.ok_or_else(|| {
                Refusal::Unavailable(Unavailable::new("granite approved with no grant record"))
            }),
            Ok(verification) => Err(Refusal::Denied(Denied::NotApproved {
                reason: verification.reason,
            })),
            // An unknown grant id: Granite has no grant that approves this.
            Err(GraniteError::Status { status, .. }) if status == StatusCode::NOT_FOUND => {
                Err(Refusal::Denied(Denied::NotApproved { reason: None }))
            }
            Err(GraniteError::Status { status, .. }) => Err(Refusal::Unavailable(
                Unavailable::new(format!("granite verify answered {}", status.as_u16())),
            )),
            Err(GraniteError::Http(e)) => {
                Err(Refusal::Unavailable(Unavailable::new(if e.is_timeout() {
                    "granite verify timed out"
                } else if e.is_connect() {
                    "could not connect to granite"
                } else {
                    "granite verify request failed"
                })))
            }
            Err(GraniteError::Decode(_)) => Err(Refusal::Unavailable(Unavailable::new(
                "granite verify answer did not decode",
            ))),
            Err(e) => Err(Refusal::Unavailable(Unavailable::new(format!(
                "granite verify failed: {e}"
            )))),
        }
    }
}

fn grant_id(headers: &HeaderMap) -> Result<Uuid, Refusal> {
    let raw = headers
        .get(GRANT_HEADER)
        .map(|v| v.to_str().map(str::trim))
        .ok_or(Refusal::Denied(Denied::NoGrant))?
        .map_err(|_| Refusal::Denied(Denied::MalformedGrant))?;
    if raw.is_empty() {
        return Err(Refusal::Denied(Denied::NoGrant));
    }
    Uuid::parse_str(raw).map_err(|_| Refusal::Denied(Denied::MalformedGrant))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Approved,
    Denied,
    Unavailable,
}

impl Outcome {
    fn of<T>(result: &Result<T, Refusal>) -> Self {
        match result {
            Ok(_) => Outcome::Approved,
            Err(Refusal::Denied(_)) => Outcome::Denied,
            Err(Refusal::Unavailable(_)) => Outcome::Unavailable,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Outcome::Approved => "approved",
            Outcome::Denied => "denied",
            Outcome::Unavailable => "unavailable",
        }
    }
}

/// One CloudWatch embedded-metric-format line for one verify.
fn emf_line(
    service: &str,
    caller: &str,
    latency: Duration,
    outcome: Outcome,
    now: SystemTime,
) -> String {
    let timestamp_ms = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    serde_json::json!({
        "_aws": {
            "Timestamp": timestamp_ms,
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [["Service", "Caller"]],
                "Metrics": [
                    { "Name": "VerifyLatency", "Unit": "Milliseconds" },
                    { "Name": "VerifyUnavailable", "Unit": "Count" },
                ],
            }],
        },
        "Service": service,
        "Caller": caller,
        "VerifyLatency": latency.as_secs_f64() * 1000.0,
        "VerifyUnavailable": u8::from(outcome == Outcome::Unavailable),
        "Outcome": outcome.as_str(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emf_line_declares_what_it_sets() {
        let now = UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
        let line = emf_line(
            "model-gateway",
            "cs_live_cg",
            Duration::from_micros(12_500),
            Outcome::Unavailable,
            now,
        );
        assert!(!line.contains('\n'), "EMF must be one line");
        let emf: serde_json::Value = serde_json::from_str(&line).unwrap();
        let directive = &emf["_aws"]["CloudWatchMetrics"][0];
        assert_eq!(directive["Namespace"], METRIC_NAMESPACE);
        for dims in directive["Dimensions"].as_array().unwrap() {
            for dim in dims.as_array().unwrap() {
                assert!(emf.get(dim.as_str().unwrap()).is_some(), "{dim} unset");
            }
        }
        for metric in directive["Metrics"].as_array().unwrap() {
            let name = metric["Name"].as_str().unwrap();
            assert!(emf.get(name).is_some(), "{name} declared but not set");
        }
        assert_eq!(emf["_aws"]["Timestamp"], 1_700_000_000_123u64);
        assert_eq!(emf["Service"], "model-gateway");
        assert_eq!(emf["Caller"], "cs_live_cg");
        assert_eq!(emf["VerifyLatency"], 12.5);
        assert_eq!(emf["VerifyUnavailable"], 1);
        assert_eq!(emf["Outcome"], "unavailable");
    }

    #[test]
    fn only_unavailable_counts_as_an_error() {
        for (outcome, err) in [
            (Outcome::Approved, 0),
            (Outcome::Denied, 0),
            (Outcome::Unavailable, 1),
        ] {
            let line = emf_line("svc", "c", Duration::ZERO, outcome, UNIX_EPOCH);
            let emf: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(emf["VerifyUnavailable"], err, "{outcome:?}");
        }
    }

    #[test]
    fn new_refuses_bad_config() {
        let minter = || {
            Arc::new(MachineTokenMinter::new(
                platform_chirp_auth::mint::MintConfig::new("https://chirp.example", "c", "s"),
            ))
        };
        assert!(GraniteAuthz::new("svc", "", minter()).is_err());
        assert!(GraniteAuthz::new("svc", "   ", minter()).is_err());
        assert!(GraniteAuthz::new("svc", "ftp://granite.example", minter()).is_err());
        assert!(GraniteAuthz::new("svc", "granite.example", minter()).is_err());
        assert!(GraniteAuthz::new("", "https://granite.example", minter()).is_err());
        assert!(GraniteAuthz::new("Model Gateway", "https://granite.example", minter()).is_err());
        assert!(GraniteAuthz::new("model-gateway", "https://granite.example/", minter()).is_ok());
    }
}
