/// Everything a synthetic user can fail at. Each variant names the step, so a
/// failed live check says where it stopped without printing secrets.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The software authenticator refused the ceremony, the way a real
    /// authenticator or browser would (wrong rpId, insecure origin, no ES256,
    /// credential not allowed).
    #[error("authenticator refused: {0}")]
    Authenticator(String),
    /// The issuer answered a step with a status the flow does not accept.
    /// `body` is the issuer's (short, non-secret) error text, truncated.
    #[error("{step}: issuer answered HTTP {status}: {body}")]
    Rejected {
        step: &'static str,
        status: u16,
        body: String,
    },
    /// The issuer answered, but not in the shape the real flow produces.
    #[error("{step}: {detail}")]
    Protocol { step: &'static str, detail: String },
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// The stored state is missing, incomplete, or for another issuer.
    #[error("state: {0}")]
    State(String),
    #[error("state store: {0}")]
    Store(#[from] std::io::Error),
}

pub(crate) fn protocol(step: &'static str, detail: impl Into<String>) -> Error {
    Error::Protocol {
        step,
        detail: detail.into(),
    }
}
