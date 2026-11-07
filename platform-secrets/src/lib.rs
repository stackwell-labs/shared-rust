//! The one secret loader for protocols `docs/adr-secret-storage.md`
//! (shared-rust#4): each service keeps its secrets in ONE Secrets Manager
//! secret per plane (`{service}/live-config`, `{service}/test-config`), a
//! JSON object with a `snake_case` key per value, read once at cold start.
//! The Lambda environment carries only the secret's id.
//!
//! ```no_run
//! use platform_secrets::Secret;
//!
//! #[derive(serde::Deserialize)]
//! struct Secrets {
//!     control_token: Secret,
//!     // Absent or blank ⇒ None.
//!     stripe_secret_key: Option<Secret>,
//! }
//!
//! # async fn boot() -> Result<(), platform_secrets::SecretsError> {
//! let secrets: Secrets = platform_secrets::load("DRIVE_CONFIG_SECRET").await?;
//! let bearer = secrets.control_token.expose();
//! # Ok(()) }
//! ```
//!
//! The contract, the same for every service:
//! - **Every failure refuses boot**: an unset or blank secret id, a failed
//!   read, JSON that is not an object, a declared key whose value is not a
//!   string or that the field's type rejects, a missing required key. There is
//!   no environment fallback.
//! - **No secret value is in any error or log line.** Errors name keys and what
//!   the field expected; a JSON syntax error is reported by position only.
//! - **Blank means absent.** Values are trimmed; an empty or whitespace value
//!   is the same as a missing key, so an `Option` field reads it as `None`.
//! - **Keys the type does not declare are set aside** and logged by name, so a
//!   key can be added to the secret before the code that reads it is deployed.
//!   They may hold any JSON type.
//! - **No plaintext copy beside the secret.** If any environment variable holds
//!   the value of a key read into a [`Secret`], boot refuses, naming the
//!   variable and the key. Deploy the code that reads the secret together with
//!   the removal of the env vars it replaces.
//!
//! Local runs and tests read a JSON file with [`from_file`], under the same
//! contract. Only a local or test binary calls it, and it logs a warning that
//! it did; there is deliberately no environment source and no "am I in
//! Lambda" switch, so no build of a service can read secrets from its env.
//!
//! `scripts/put-config-key.sh` writes one key of a service's secret without
//! printing any value.

mod de;

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use aws_sdk_secretsmanager::config::http::HttpResponse;
use aws_sdk_secretsmanager::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_secretsmanager::operation::get_secret_value::GetSecretValueError;
use serde::de::{DeserializeOwned, Deserializer, Visitor};
use serde::Deserialize;

/// Why the secret could not be loaded. Every variant names keys, env vars,
/// the secret's id or a file path: never a value. Each one should refuse boot.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretsError {
    #[error("{env} is unset or blank: the service reads its secrets only from Secrets Manager, by that id")]
    SecretIdUnset { env: String },
    #[error("secretsmanager:GetSecretValue on {secret_id} failed: {cause}")]
    Read { secret_id: String, cause: String },
    #[error("{secret_id} has no SecretString; it must be a JSON object")]
    NoSecretString { secret_id: String },
    #[error("reading {path}: {cause}", path = path.display())]
    File {
        path: PathBuf,
        cause: std::io::Error,
    },
    #[error("{origin} is not valid JSON (line {line}, column {column})")]
    NotJson {
        origin: String,
        line: usize,
        column: usize,
    },
    #[error("{origin} is not a JSON object")]
    NotObject { origin: String },
    #[error("key {key:?} in {origin} is not a string")]
    NotString { origin: String, key: String },
    #[error("required key {key:?} is missing or blank in {origin}")]
    Missing { origin: String, key: String },
    #[error("{}", invalid_message(origin, key.as_deref(), expected.as_deref()))]
    Invalid {
        origin: String,
        key: Option<String>,
        expected: Option<String>,
    },
    #[error(
        "env var {env_var} holds the value of key {key:?} from {origin}: remove the plaintext copy"
    )]
    PlaintextCopy {
        origin: String,
        key: String,
        env_var: String,
    },
}

fn invalid_message(origin: &str, key: Option<&str>, expected: Option<&str>) -> String {
    let what = key.map_or_else(|| "the secret".to_owned(), |k| format!("key {k:?}"));
    match expected {
        Some(expected) => format!("{what} in {origin} was rejected: expected {expected}"),
        None => format!("{what} in {origin} was rejected by its type (the message is withheld: it may quote the value)"),
    }
}

/// A secret value. `Debug` redacts it, and it has no `Display`, `Serialize` or
/// `PartialEq` (a token check should compare in constant time), so the value
/// leaves only through [`Secret::expose`].
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// For tests and for callers that obtain a secret some other way.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value. Call it where the value is used, not to store it elsewhere.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;
        impl<'de> Visitor<'de> for SecretVisitor {
            type Value = Secret;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a secret string")
            }
            fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Secret, D::Error> {
                String::deserialize(d).map(Secret)
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Secret, E> {
                Ok(Secret(v.to_owned()))
            }
        }
        // The marker name tells this crate's deserializer which keys hold
        // secrets (for the plaintext-copy check). Other deserializers ignore it.
        deserializer.deserialize_newtype_struct(de::SECRET_MARKER, SecretVisitor)
    }
}

/// Read the service's secrets: one `GetSecretValue` on the secret whose id
/// (ARN or name) is in the env var `secret_id_env`, deserialized into `S`.
/// Call it once, at cold start, and refuse boot on any error.
pub async fn load<S: DeserializeOwned>(secret_id_env: &str) -> Result<S, SecretsError> {
    let secret_id = secret_id(secret_id_env, std::env::var(secret_id_env).ok().as_deref())?;
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let client = aws_sdk_secretsmanager::Client::new(&config);
    let output = client
        .get_secret_value()
        .secret_id(&secret_id)
        .send()
        .await
        .map_err(|e| SecretsError::Read {
            secret_id: secret_id.clone(),
            cause: read_cause(&e),
        })?;
    let json = output
        .secret_string()
        .ok_or_else(|| SecretsError::NoSecretString {
            secret_id: secret_id.clone(),
        })?;
    decode(&secret_id, json, std::env::vars_os())
}

/// Why `GetSecretValue` failed, without the response: an `SdkError`'s full
/// `Display` includes the raw HTTP response, and a successful response the
/// SDK could not parse carries the secret in its body.
fn read_cause(e: &SdkError<GetSecretValueError, HttpResponse>) -> String {
    match e {
        SdkError::ServiceError(service) => {
            let err = service.err();
            format!(
                "{}: {}",
                err.code().unwrap_or("service error"),
                err.message().unwrap_or("no message")
            )
        }
        SdkError::DispatchFailure(failure) => match failure.as_connector_error() {
            Some(connector) => format!("dispatch failure: {}", DisplayErrorContext(connector)),
            None => "dispatch failure".to_owned(),
        },
        SdkError::TimeoutError(_) => "timed out".to_owned(),
        SdkError::ConstructionFailure(_) => format!("request not sent: {}", DisplayErrorContext(e)),
        SdkError::ResponseError(_) => {
            "the response could not be parsed (its content is withheld: it may hold the value)"
                .to_owned()
        }
        _ => "unrecognized SDK error".to_owned(),
    }
}

/// Read the secrets from a local JSON file, under the same contract as
/// [`load`]. Only for local runs and tests: point it at a copy of the
/// service's `test-config`. It logs a warning, so a deployed function that
/// calls it is visible in its logs.
pub fn from_file<S: DeserializeOwned>(path: impl AsRef<Path>) -> Result<S, SecretsError> {
    let path = path.as_ref();
    tracing::warn!(path = %path.display(), "platform-secrets: secrets read from a local file, not Secrets Manager");
    let json = std::fs::read_to_string(path).map_err(|cause| SecretsError::File {
        path: path.to_owned(),
        cause,
    })?;
    decode(&path.display().to_string(), &json, std::env::vars_os())
}

fn secret_id(env: &str, raw: Option<&str>) -> Result<String, SecretsError> {
    raw.map(str::trim)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| SecretsError::SecretIdUnset {
            env: env.to_owned(),
        })
}

/// The whole contract, apart from where the JSON comes from. `origin` names
/// the secret in errors and the log line; `env` is the process environment.
fn decode<S: DeserializeOwned>(
    origin: &str,
    json: &str,
    env: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<S, SecretsError> {
    let entries = de::entries(origin, json)?;
    let (value, report) = de::deserialize::<S>(origin, &entries)?;
    refuse_plaintext_copies(origin, &entries, &report.secrets, env)?;
    tracing::info!(
        secret = origin,
        present = ?report.present,
        ignored = ?report.ignored,
        "platform-secrets: loaded"
    );
    Ok(value)
}

fn refuse_plaintext_copies(
    origin: &str,
    entries: &de::Entries,
    secret_keys: &[String],
    env: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<(), SecretsError> {
    let secrets: Vec<(&str, &str)> = secret_keys
        .iter()
        .filter_map(|key| match entries.get(key) {
            Some(de::Entry::Str(value)) => Some((key.as_str(), value.as_str())),
            _ => None,
        })
        .collect();
    let mut copies: Vec<(String, &str)> = env
        .into_iter()
        .filter_map(|(name, value)| {
            let value = value.into_string().ok()?;
            let (key, _) = secrets.iter().find(|(_, secret)| *secret == value.trim())?;
            Some((name.to_string_lossy().into_owned(), *key))
        })
        .collect();
    copies.sort();
    match copies.into_iter().next() {
        None => Ok(()),
        Some((env_var, key)) => Err(SecretsError::PlaintextCopy {
            origin: origin.to_owned(),
            key: key.to_owned(),
            env_var,
        }),
    }
}

#[cfg(test)]
mod tests;
