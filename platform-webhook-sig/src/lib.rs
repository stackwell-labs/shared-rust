//! One canonical webhook signature scheme for the whole platform.
//!
//! A signed delivery is `HMAC-SHA256(secret, "{timestamp}.{nonce}.{body}")`,
//! hex-encoded, accompanied by the timestamp and nonce. Binding a fresh
//! Unix-seconds timestamp AND a random nonce into the MAC lets a consumer bind
//! the signature to a single, time-bounded delivery and reject replays: a
//! captured body re-POSTed later carries the same signature but a stale
//! timestamp (rejected by the freshness window) and a re-seen nonce (which the
//! consumer can dedup within that window).
//!
//! This crate owns the SCHEME, not the header names. Each service maps the
//! returned [`Signed`] onto its own headers (`x-granite-*`, `x-pigeon-*`, …)
//! and feeds its own headers back into [`Presented`] to verify. Collapsing the
//! four hand-rolled HMAC copies (Granite + Pigeon sender + Loom + pigeon-commerce
//! consumers) into this one primitive makes the scheme identical by construction
//! — there is no second format to drift to.
//!
//! Replay defense is split deliberately: this crate enforces signature validity
//! and timestamp FRESHNESS (stateless, so it fits a Lambda). Deduping a re-seen
//! nonce within the freshness window is the consumer's concern — [`Verified`]
//! returns the nonce so a consumer with durable storage can record + reject it.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Default freshness window: a delivery whose timestamp is more than this many
/// seconds from the verifier's clock (either direction) is rejected as stale.
pub const DEFAULT_FRESHNESS_SECS: i64 = 300;

/// The output of signing: the three values a sender emits (under whatever header
/// names it likes). `signature` is the wire form, `sha256=<hex>`.
#[derive(Debug, Clone)]
pub struct Signed {
    pub signature: String,
    pub timestamp: String,
    pub nonce: String,
}

/// A signature scheme a [`Verifier`] can accept. The canonical scheme is the
/// only one a sender should EMIT; `LegacyNoNonce` exists solely so a consumer
/// can keep verifying a not-yet-migrated sender DURING an expand/contract
/// rollout (accept both → flip the sender → drop legacy). The two are
/// cryptographically distinct (different signed strings), so a verifier can
/// accept both safely: a canonical-signed body can never verify as legacy or
/// vice-versa, and an attacker cannot "downgrade" one to the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `HMAC(secret, "{timestamp}.{nonce}.{body}")` — requires a nonce. The
    /// canonical scheme; the only one to emit.
    Canonical,
    /// `HMAC(secret, "{timestamp}.{body}")` — no nonce. The pre-canonical
    /// Pigeon scheme; transitional, consumer-side, never emitted by this crate.
    LegacyNoNonce,
}

/// Signs deliveries with one secret under the canonical scheme.
pub struct Signer<'a> {
    secret: &'a [u8],
}

impl<'a> Signer<'a> {
    pub fn new(secret: &'a [u8]) -> Self {
        Self { secret }
    }

    /// Sign `body` with a fresh Unix-seconds timestamp and a random v4 nonce.
    pub fn sign(&self, body: &[u8]) -> Signed {
        let timestamp = now_unix_secs().to_string();
        let nonce = Uuid::new_v4().to_string();
        self.sign_with(body, &timestamp, &nonce)
    }

    /// Sign with a caller-supplied timestamp and nonce (deterministic — for
    /// tests, or a caller that mints its own anti-replay material).
    pub fn sign_with(&self, body: &[u8], timestamp: &str, nonce: &str) -> Signed {
        let mac = mac_over(self.secret, timestamp, nonce, body);
        Signed {
            signature: format!("sha256={}", hex_lower(&mac)),
            timestamp: timestamp.to_owned(),
            nonce: nonce.to_owned(),
        }
    }
}

/// The headers + body a verifier was handed, before validation. `signature` is
/// the raw header value (`sha256=<hex>`); `timestamp`/`nonce` are the raw header
/// values. `None` means the header was absent.
#[derive(Debug, Clone)]
pub struct Presented<'a> {
    pub signature: Option<&'a str>,
    pub timestamp: Option<&'a str>,
    pub nonce: Option<&'a str>,
    pub body: &'a [u8],
}

/// A delivery that passed signature + freshness checks. The `nonce` is returned
/// so a consumer can record it and reject a replay within the freshness window
/// (empty for [`Scheme::LegacyNoNonce`], which has none — dedup on a body field
/// instead). `scheme` tells the consumer which scheme matched (useful to log
/// during a migration, or to alert once legacy traffic has stopped).
#[derive(Debug, Clone)]
pub struct Verified {
    pub nonce: String,
    pub timestamp: i64,
    pub scheme: Scheme,
}

/// Why a delivery failed verification. All variants are fail-closed (reject).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    MissingSignature,
    MissingTimestamp,
    MissingNonce,
    /// The signature header was not `sha256=<hex>` or the hex did not decode.
    MalformedSignature,
    /// The timestamp header was not an integer.
    MalformedTimestamp,
    /// HMAC mismatch — forged, tampered, or wrong secret.
    SignatureMismatch,
    /// Timestamp outside the freshness window. `skew_secs` is the absolute gap.
    Stale {
        timestamp: i64,
        now: i64,
        skew_secs: i64,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::MissingSignature => write!(f, "missing signature header"),
            VerifyError::MissingTimestamp => write!(f, "missing timestamp header"),
            VerifyError::MissingNonce => write!(f, "missing nonce header"),
            VerifyError::MalformedSignature => {
                write!(f, "malformed signature (expected sha256=<hex>)")
            }
            VerifyError::MalformedTimestamp => {
                write!(f, "malformed timestamp (expected integer seconds)")
            }
            VerifyError::SignatureMismatch => write!(f, "signature mismatch"),
            VerifyError::Stale {
                timestamp,
                now,
                skew_secs,
            } => write!(
                f,
                "stale delivery: timestamp {timestamp} is {skew_secs}s from now ({now})"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verifies deliveries with one secret. Accepts [`Scheme::Canonical`] by
/// default; a consumer mid-migration can `.also_accept(Scheme::LegacyNoNonce)`
/// so it verifies a not-yet-flipped sender too, then drop it once the sender is
/// canonical (the expand/contract rollout — no lockstep deploy window).
pub struct Verifier<'a> {
    secret: &'a [u8],
    freshness_secs: i64,
    accepted: Vec<Scheme>,
}

impl<'a> Verifier<'a> {
    /// A verifier that accepts ONLY the canonical scheme, with the
    /// [`DEFAULT_FRESHNESS_SECS`] window. This is the end state.
    pub fn new(secret: &'a [u8]) -> Self {
        Self {
            secret,
            freshness_secs: DEFAULT_FRESHNESS_SECS,
            accepted: vec![Scheme::Canonical],
        }
    }

    pub fn with_freshness_secs(mut self, secs: i64) -> Self {
        self.freshness_secs = secs;
        self
    }

    /// Additionally accept `scheme` (in addition to the canonical default).
    /// Transitional: use during a migration, then remove.
    pub fn also_accept(mut self, scheme: Scheme) -> Self {
        if !self.accepted.contains(&scheme) {
            self.accepted.push(scheme);
        }
        self
    }

    fn accepts(&self, scheme: Scheme) -> bool {
        self.accepted.contains(&scheme)
    }

    /// Verify a presented delivery against `now_unix` (Unix seconds). The scheme
    /// is chosen by nonce-presence — a nonce header means canonical, its absence
    /// means legacy — constrained to the accepted set. Then: signature
    /// well-formed → HMAC matches (constant-time, over the chosen scheme's signed
    /// string) → timestamp within the freshness window. On success returns the
    /// matched [`Verified`] for the caller to dedup.
    ///
    /// Picking by nonce-presence is safe because the schemes sign different
    /// strings: stripping the nonce header to force the legacy path makes a
    /// canonical signature fail the legacy MAC (no downgrade), and a legacy
    /// delivery simply never carries a nonce.
    pub fn verify(&self, p: &Presented<'_>, now_unix: i64) -> Result<Verified, VerifyError> {
        let signature = p.signature.ok_or(VerifyError::MissingSignature)?.trim();
        let timestamp = p.timestamp.ok_or(VerifyError::MissingTimestamp)?.trim();
        let nonce = p.nonce.map(str::trim).filter(|n| !n.is_empty());

        // Choose the scheme from nonce-presence, within the accepted set.
        let scheme = match nonce {
            Some(_) if self.accepts(Scheme::Canonical) => Scheme::Canonical,
            // A nonce'd (canonical-shaped) delivery, but this verifier doesn't
            // accept canonical: reject as a mismatch.
            Some(_) => return Err(VerifyError::SignatureMismatch),
            None if self.accepts(Scheme::LegacyNoNonce) => Scheme::LegacyNoNonce,
            // No nonce and legacy isn't accepted → canonical requires one.
            None => return Err(VerifyError::MissingNonce),
        };

        let hex = signature
            .strip_prefix("sha256=")
            .ok_or(VerifyError::MalformedSignature)?;
        let expected = hex_decode(hex).ok_or(VerifyError::MalformedSignature)?;

        // Constant-time compare via the MAC's own verifier, over the chosen
        // scheme's signed string.
        let mut mac = HmacSha256::new_from_slice(self.secret).expect("HMAC accepts any key length");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        if scheme == Scheme::Canonical {
            mac.update(nonce.expect("canonical implies a nonce").as_bytes());
            mac.update(b".");
        }
        mac.update(p.body);
        mac.verify_slice(&expected)
            .map_err(|_| VerifyError::SignatureMismatch)?;

        // Only after authenticity do we trust the timestamp value.
        let ts: i64 = timestamp
            .parse()
            .map_err(|_| VerifyError::MalformedTimestamp)?;
        let skew = (now_unix - ts).abs();
        if skew > self.freshness_secs {
            return Err(VerifyError::Stale {
                timestamp: ts,
                now: now_unix,
                skew_secs: skew,
            });
        }

        Ok(Verified {
            nonce: nonce.map(str::to_owned).unwrap_or_default(),
            timestamp: ts,
            scheme,
        })
    }
}

fn mac_over(secret: &[u8], timestamp: &str, nonce: &str, body: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(nonce.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// Current Unix time in seconds (saturating to 0 before the epoch).
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a-shared-webhook-secret";

    fn present<'a>(s: &'a Signed, body: &'a [u8]) -> Presented<'a> {
        Presented {
            signature: Some(&s.signature),
            timestamp: Some(&s.timestamp),
            nonce: Some(&s.nonce),
            body,
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let body = br#"{"event":"x"}"#;
        let signed = Signer::new(SECRET).sign(body);
        let now: i64 = signed.timestamp.parse().unwrap();
        let v = Verifier::new(SECRET)
            .verify(&present(&signed, body), now)
            .unwrap();
        assert_eq!(v.nonce, signed.nonce);
        assert_eq!(v.timestamp, now);
    }

    #[test]
    fn signature_binds_timestamp_and_nonce() {
        // Two signatures over the same body differ (fresh nonce each time), and a
        // signature is over {ts}.{nonce}.{body}: changing ts or nonce breaks it.
        let body = b"body";
        let signer = Signer::new(SECRET);
        let a = signer.sign_with(body, "1000", "nonce-a");
        let b = signer.sign_with(body, "1000", "nonce-b");
        assert_ne!(a.signature, b.signature, "nonce is folded into the MAC");
        let c = signer.sign_with(body, "2000", "nonce-a");
        assert_ne!(a.signature, c.signature, "timestamp is folded into the MAC");
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let body = b"body";
        let signed = Signer::new(SECRET).sign_with(body, "1000", "n");
        let err = Verifier::new(b"other-secret")
            .verify(&present(&signed, body), 1000)
            .unwrap_err();
        assert_eq!(err, VerifyError::SignatureMismatch);
    }

    #[test]
    fn tampered_body_is_rejected() {
        let signed = Signer::new(SECRET).sign_with(b"original", "1000", "n");
        let err = Verifier::new(SECRET)
            .verify(&present(&signed, b"tampered"), 1000)
            .unwrap_err();
        assert_eq!(err, VerifyError::SignatureMismatch);
    }

    #[test]
    fn stale_timestamp_is_rejected_but_a_fresh_one_passes() {
        let body = b"body";
        let signed = Signer::new(SECRET).sign_with(body, "1000", "n");
        // Within the window.
        assert!(Verifier::new(SECRET)
            .verify(&present(&signed, body), 1000 + DEFAULT_FRESHNESS_SECS)
            .is_ok());
        // Just past it.
        let err = Verifier::new(SECRET)
            .verify(&present(&signed, body), 1000 + DEFAULT_FRESHNESS_SECS + 1)
            .unwrap_err();
        assert!(matches!(err, VerifyError::Stale { .. }), "got {err:?}");
    }

    #[test]
    fn missing_headers_are_rejected() {
        let body = b"body";
        let v = Verifier::new(SECRET);
        let base = Signer::new(SECRET).sign_with(body, "1000", "n");
        let mut p = present(&base, body);
        p.signature = None;
        assert_eq!(
            v.verify(&p, 1000).unwrap_err(),
            VerifyError::MissingSignature
        );
        let mut p = present(&base, body);
        p.timestamp = None;
        assert_eq!(
            v.verify(&p, 1000).unwrap_err(),
            VerifyError::MissingTimestamp
        );
        let mut p = present(&base, body);
        p.nonce = None;
        assert_eq!(v.verify(&p, 1000).unwrap_err(), VerifyError::MissingNonce);
    }

    #[test]
    fn malformed_signature_is_rejected() {
        let body = b"body";
        let signed = Signer::new(SECRET).sign_with(body, "1000", "n");
        let mut p = present(&signed, body);
        p.signature = Some("not-prefixed");
        assert_eq!(
            Verifier::new(SECRET).verify(&p, 1000).unwrap_err(),
            VerifyError::MalformedSignature
        );
        p.signature = Some("sha256=zzzz");
        assert_eq!(
            Verifier::new(SECRET).verify(&p, 1000).unwrap_err(),
            VerifyError::MalformedSignature
        );
    }

    #[test]
    fn hex_decode_roundtrips_encoding() {
        let bytes = [0x00u8, 0x0f, 0xa1, 0xff];
        assert_eq!(hex_decode(&hex_lower(&bytes)).unwrap(), bytes);
        assert!(hex_decode("abc").is_none(), "odd length");
        assert!(hex_decode("zz").is_none(), "non-hex");
    }

    /// A legacy `{timestamp}.{body}` signature (no nonce) — what a pre-canonical
    /// sender emitted. The crate never produces this; we forge it for the
    /// transitional-verify tests.
    fn legacy_sign(secret: &[u8], timestamp: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body);
        format!("sha256={}", hex_lower(&mac.finalize().into_bytes()))
    }

    #[test]
    fn tolerant_verifier_accepts_canonical_and_legacy() {
        let body = b"body";
        let tolerant = Verifier::new(SECRET).also_accept(Scheme::LegacyNoNonce);

        // Canonical (nonce present).
        let signed = Signer::new(SECRET).sign_with(body, "1000", "n");
        let v = tolerant.verify(&present(&signed, body), 1000).unwrap();
        assert_eq!(v.scheme, Scheme::Canonical);
        assert_eq!(v.nonce, "n");

        // Legacy (no nonce header).
        let sig = legacy_sign(SECRET, "1000", body);
        let legacy = Presented {
            signature: Some(&sig),
            timestamp: Some("1000"),
            nonce: None,
            body,
        };
        let v = tolerant.verify(&legacy, 1000).unwrap();
        assert_eq!(v.scheme, Scheme::LegacyNoNonce);
        assert_eq!(v.nonce, "", "legacy carries no nonce");
    }

    #[test]
    fn canonical_only_verifier_rejects_legacy() {
        let body = b"body";
        let sig = legacy_sign(SECRET, "1000", body);
        let legacy = Presented {
            signature: Some(&sig),
            timestamp: Some("1000"),
            nonce: None,
            body,
        };
        // The default verifier accepts canonical only → a no-nonce delivery is
        // rejected (canonical requires a nonce).
        assert_eq!(
            Verifier::new(SECRET).verify(&legacy, 1000).unwrap_err(),
            VerifyError::MissingNonce
        );
    }

    #[test]
    fn downgrade_canonical_to_legacy_is_rejected() {
        // A canonical signature presented WITHOUT its nonce header (an attacker
        // stripping it to force the legacy path) must NOT verify: the legacy MAC
        // over {ts}.{body} can't match a signature taken over {ts}.{nonce}.{body}.
        let body = b"body";
        let signed = Signer::new(SECRET).sign_with(body, "1000", "n");
        let stripped = Presented {
            signature: Some(&signed.signature),
            timestamp: Some(&signed.timestamp),
            nonce: None,
            body,
        };
        let tolerant = Verifier::new(SECRET).also_accept(Scheme::LegacyNoNonce);
        assert_eq!(
            tolerant.verify(&stripped, 1000).unwrap_err(),
            VerifyError::SignatureMismatch
        );
    }
}
