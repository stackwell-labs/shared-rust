//! The least-privilege Drive **deposit** client shared by third-party apps.
//!
//! A third-party app's only privilege into a recipient's Drive is an append-only,
//! non-owning, revocable **deposit-cap** the recipient mints over their own
//! partition. This crate is the two pieces every app needs to use it, extracted
//! from the copy-pasted (and drifting) per-app `clients/drive.rs`:
//!
//! - [`DriveClient::deposit`] — `POST {base}/v1/store/deposit`, authed by the
//!   app's chirp MACHINE token (bearer) + the recipient's cap. Sender-blind at
//!   Drive: the cap, not the caller's identity, is the authority, and it
//!   authorizes only append into the one partition it names.
//! - [`feed_op_bytes_by`] — encode a row as the base64 canonical bytes of a
//!   `FeedPostV1` store-core CRDT op at a key, naming the op's author, so the
//!   wire bytes match Drive's feed-fold exactly (no hand-rolled format). The
//!   recipient folds the feed via `GET /v1/store/deposits?key=`.
//!   [`feed_op_bytes`] is the same with an empty author, for keyspaces where
//!   Drive does not check it.
//!
//! What stays in each app: its feed-key constants, its row types, and its own
//! provenance (notary / attestation) — this crate is pure platform protocol, no
//! app logic. See `protocols/docs/adr-resource-scoped-access-tokens.md` and each
//! app's `docs/replica-migration.md`.

use serde::Serialize;

/// A deposit failure. Its own error type (not `anyhow`/`ApiError`) so every
/// consumer maps it however it likes: an anyhow app gets it via `?`, an app with
/// its own `ApiError` maps with `.map_err`.
#[derive(Debug)]
pub enum DepositError {
    /// The row could not be serialized to JSON before encoding.
    Encode(serde_json::Error),
    /// The HTTP request to Drive failed to send.
    Transport(reqwest::Error),
    /// Drive returned a non-success status. `body` is the (truncated) response.
    Status { code: u16, body: String },
}

impl std::fmt::Display for DepositError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DepositError::Encode(e) => write!(f, "encode deposit row: {e}"),
            DepositError::Transport(e) => write!(f, "drive deposit transport: {e}"),
            DepositError::Status { code, body } => write!(f, "drive deposit -> {code}: {body}"),
        }
    }
}

impl std::error::Error for DepositError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DepositError::Encode(e) => Some(e),
            DepositError::Transport(e) => Some(e),
            DepositError::Status { .. } => None,
        }
    }
}

/// A Drive deposit client: an HTTP client plus the Drive base URL.
pub struct DriveClient {
    http: reqwest::Client,
    base_url: String,
}

impl DriveClient {
    /// The `base_url` is normalized (trailing `/` trimmed) so URL joins are
    /// consistent regardless of how the caller configured it — reconciling the
    /// two per-app copies (one trimmed at the call site, one did not).
    pub fn new(http: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            http,
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    /// The normalized Drive base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Deposit already-encoded feed-op bytes into the partition the `cap` names.
    /// `machine_token` is the app's chirp machine bearer; `cap` is the recipient's
    /// deposit-cap (opaque here — minted by their client); `ops` are base64
    /// canonical CRDT op bytes from [`feed_op_bytes`]. The cap, not a broad grant,
    /// is the authority, and it authorizes only append.
    pub async fn deposit(
        &self,
        machine_token: &str,
        cap: &serde_json::Value,
        ops: Vec<String>,
    ) -> Result<(), DepositError> {
        let resp = self
            .http
            .post(format!("{}/v1/store/deposit", self.base_url))
            .bearer_auth(machine_token)
            .json(&serde_json::json!({ "cap": cap, "ops": ops }))
            .send()
            .await
            .map_err(DepositError::Transport)?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(DepositError::Status { code, body })
        }
    }
}

/// Encode `row` as the base64 canonical bytes of a `FeedPostV1` CRDT op at `key`,
/// with an empty `author` label — the body it is deposited as. The row rides as
/// **plaintext** JSON (this path is for recipient-readable feeds, not E2E; the
/// app's own notary/attestation provenance lives inside the row). Uses
/// store-core so the bytes match Drive's feed-fold exactly.
///
/// Only for keyspaces where Drive ignores the op's `author`: there the
/// authenticated author is the app's attestation inside the row. Under a
/// signed keyspace (Profile B, today `pigeon/`) Drive refuses an op whose
/// `author` is not its signer's Chirp sub (drive#26), so use
/// [`feed_op_bytes_by`] there.
pub fn feed_op_bytes<T: Serialize>(key: &str, row: &T) -> Result<String, DepositError> {
    feed_op_bytes_by(key, "", row)
}

/// [`feed_op_bytes`], with the op's `author` set to `author`.
///
/// Drive checks the author on signed (Profile B) keyspaces, today `pigeon/`
/// (drive#26, Drive's `docs/signed-authorship.md`): `author` must be the
/// signer's Chirp sub, a key registered for that sub must have signed the row,
/// and the row must carry that signature. Otherwise Drive refuses the whole
/// batch with 403. Elsewhere Drive ignores `author` and it is a self-declared
/// label. This crate only writes the label; signing the row is the caller's.
pub fn feed_op_bytes_by<T: Serialize>(
    key: &str,
    author: &str,
    row: &T,
) -> Result<String, DepositError> {
    use base64::Engine;
    use store_core::crdt::{CrdtKey, OpBody, Replica};
    use store_core::record::blake3::Blake3Hasher;
    use store_core::value::Value;

    let json = serde_json::to_string(row).map_err(DepositError::Encode)?;
    let mut replica = Replica::new(Blake3Hasher);
    replica.author(OpBody::FeedPostV1 {
        key: CrdtKey(key.to_owned()),
        author: author.to_owned(),
        body: Value::Text(json),
    });
    let op = replica
        .ops_in_causal_order()
        .into_iter()
        .next()
        .expect("one op was just authored");
    Ok(base64::engine::general_purpose::STANDARD.encode(op.canonical_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde::Deserialize;
    use store_core::crdt::{CrdtKey, Op, OpBody, Replica};
    use store_core::record::blake3::Blake3Hasher;
    use store_core::value::Value;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Row {
        id: String,
        text: String,
    }

    /// A row encoded as a feed-op folds back to the identical row — exactly what a
    /// recipient does via `GET /v1/store/deposits`. This is the canonical version
    /// of the round-trip test each app previously copy-pasted with its own row type.
    #[test]
    fn row_round_trips_through_a_feed_op() {
        let key = "app/feed";
        let row = Row {
            id: "r-1".into(),
            text: "hello 🌿".into(),
        };
        let op_b64 = feed_op_bytes(key, &row).expect("encode");

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&op_b64)
            .unwrap();
        let mut replica = Replica::new(Blake3Hasher);
        replica.apply(Op::decode(&bytes).unwrap()).unwrap();
        let folded = replica.feed(&CrdtKey(key.to_owned()));
        assert_eq!(folded.len(), 1);
        let Value::Text(body) = &folded[0].1 else {
            panic!("feed body should be text");
        };
        let back: Row = serde_json::from_str(body).unwrap();
        assert_eq!(back, row);
    }

    fn decode_feed_post(op_b64: &str) -> (String, String) {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(op_b64)
            .unwrap();
        let OpBody::FeedPostV1 {
            author,
            body: Value::Text(body),
            ..
        } = Op::decode(&bytes).unwrap().body
        else {
            panic!("expected a FeedPostV1 with a text body");
        };
        (author, body)
    }

    /// The author a caller names is the op's `author`, which Drive checks on
    /// `pigeon/` (drive#26); the row still rides unchanged in the body.
    #[test]
    fn feed_op_bytes_by_sets_the_author() {
        let row = Row {
            id: "m-1".into(),
            text: "signed".into(),
        };
        let (author, body) = decode_feed_post(
            &feed_op_bytes_by("pigeon/thread/t-1", "pairwise-sub-1", &row).expect("encode"),
        );
        assert_eq!(author, "pairwise-sub-1");
        assert_eq!(serde_json::from_str::<Row>(&body).unwrap(), row);
    }

    /// `feed_op_bytes` is `feed_op_bytes_by` with an empty author, byte for byte,
    /// so Porch's and gotta's deposits are unchanged.
    #[test]
    fn feed_op_bytes_is_the_empty_author() {
        let row = Row {
            id: "r-1".into(),
            text: "hi".into(),
        };
        let unlabelled = feed_op_bytes("app/feed", &row).expect("encode");
        assert_eq!(
            unlabelled,
            feed_op_bytes_by("app/feed", "", &row).expect("encode")
        );
        assert_eq!(decode_feed_post(&unlabelled).0, "");
    }

    /// base_url is normalized so a trailing slash never doubles in the deposit URL.
    #[test]
    fn base_url_is_normalized() {
        let c = DriveClient::new(reqwest::Client::new(), "https://drive.example/");
        assert_eq!(c.base_url(), "https://drive.example");
    }
}
