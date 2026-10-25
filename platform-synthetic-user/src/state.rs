//! The synthetic user's durable state and where it is kept.
//!
//! **Counter rule (write-ahead).** An assertion is released only after the
//! counter it carries has been saved. So whatever happens next (the issuer
//! refuses, the network drops, the process is killed), the stored counter is
//! never behind any counter the issuer has seen. Jot's live check saves the
//! counter in a `finally`; write-ahead covers that case and a crash as well.
//! [`UserState::next_assertion`] is the only way to obtain an assertion.

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::authenticator::{Credential, RequestOptions, WebOrigin};
use crate::Error;

/// Bumped on any incompatible change to the serialized shape.
const STATE_FORMAT: u32 = 1;

/// Everything needed to sign in as this user later. This is the secret: it
/// holds the private key and the recovery codes. `Debug` prints neither.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserState {
    format: u32,
    /// The issuer the credential was enrolled at (its rpId is that host).
    issuer: String,
    /// `None` only between saving a new credential and the issuer confirming
    /// the account. [`crate::SyntheticUser::load`] refuses such a state.
    account: Option<Account>,
    credential: Credential,
}

/// What ChirpAuth's signup returned for this account.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub account_id: String,
    pub persona_id: String,
    /// Shown once at signup. Kept so the account stays recoverable.
    pub recovery_codes: Vec<String>,
}

impl std::fmt::Debug for UserState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserState")
            .field("issuer", &self.issuer)
            .field("account_id", &self.account.as_ref().map(|a| &a.account_id))
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl UserState {
    pub(crate) fn pending(issuer: &str, credential: Credential) -> Self {
        Self {
            format: STATE_FORMAT,
            issuer: issuer.to_string(),
            account: None,
            credential,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn account(&self) -> Option<&Account> {
        self.account.as_ref()
    }

    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    pub(crate) fn set_account(&mut self, account: Account) {
        self.account = Some(account);
    }

    /// Sign the next assertion and save the advanced counter **before**
    /// returning it. If the save fails, the assertion is dropped unsent.
    pub(crate) async fn next_assertion<S: StateStore>(
        &mut self,
        store: &mut S,
        origin: &WebOrigin,
        options: &RequestOptions,
    ) -> Result<Value, Error> {
        let assertion = self.credential.assert(origin, options)?;
        store.save(self).await?;
        Ok(assertion)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec_pretty(self).map_err(|e| Error::State(format!("serialize: {e}")))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let state: Self =
            serde_json::from_slice(bytes).map_err(|e| Error::State(format!("parse: {e}")))?;
        if state.format != STATE_FORMAT {
            return Err(Error::State(format!(
                "state format {} is not {STATE_FORMAT}",
                state.format
            )));
        }
        Ok(state)
    }
}

/// Durable storage for one synthetic user. `save` must not return `Ok` until
/// the state would survive a crash; the counter rule depends on it.
pub trait StateStore {
    fn load(&self) -> impl Future<Output = Result<Option<UserState>, Error>> + Send;
    fn save(&mut self, state: &UserState) -> impl Future<Output = Result<(), Error>> + Send;
}

/// A single JSON file, written atomically (temp file, fsync, rename, fsync
/// the directory) with mode 0600. For local runs and tests; the live checks
/// will keep the same JSON in a secret store.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl StateStore for FileStore {
    async fn load(&self) -> Result<Option<UserState>, Error> {
        match std::fs::read(&self.path) {
            Ok(bytes) => UserState::from_json(&bytes).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn save(&mut self, state: &UserState) -> Result<(), Error> {
        let bytes = state.to_json()?;
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let tmp = self.path.with_extension("tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, &self.path)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::CreationOptions;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::json;
    use url::Url;

    fn enrolled() -> (UserState, WebOrigin) {
        let origin = WebOrigin::from_issuer(&Url::parse("http://localhost:1").unwrap()).unwrap();
        let options: CreationOptions = serde_json::from_value(json!({ "publicKey": {
            "rp": { "id": "localhost" },
            "user": { "id": URL_SAFE_NO_PAD.encode([1u8; 16]) },
            "challenge": URL_SAFE_NO_PAD.encode(b"c"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        }}))
        .unwrap();
        let (credential, _) = Credential::register(&origin, &options).unwrap();
        (UserState::pending("http://localhost:1", credential), origin)
    }

    fn request() -> RequestOptions {
        serde_json::from_value(json!({ "publicKey": {
            "challenge": URL_SAFE_NO_PAD.encode(b"g"), "rpId": "localhost",
        }}))
        .unwrap()
    }

    fn counter_of(assertion: &Value) -> u32 {
        let data = URL_SAFE_NO_PAD
            .decode(assertion["response"]["authenticatorData"].as_str().unwrap())
            .unwrap();
        u32::from_be_bytes(data[33..37].try_into().unwrap())
    }

    /// Records the counter of every saved state; can be told to fail.
    struct Recording {
        saved: Vec<u32>,
        fail: bool,
    }

    impl StateStore for Recording {
        async fn load(&self) -> Result<Option<UserState>, Error> {
            Ok(None)
        }
        async fn save(&mut self, state: &UserState) -> Result<(), Error> {
            if self.fail {
                return Err(std::io::Error::other("disk full").into());
            }
            self.saved.push(state.credential.sign_count());
            Ok(())
        }
    }

    #[tokio::test]
    async fn an_assertion_is_released_only_after_its_counter_is_saved() {
        let (mut state, origin) = enrolled();
        let mut store = Recording {
            saved: vec![],
            fail: false,
        };
        let a = state
            .next_assertion(&mut store, &origin, &request())
            .await
            .unwrap();
        assert_eq!(store.saved, vec![1]);
        assert_eq!(counter_of(&a), 1);

        store.fail = true;
        let refused = state.next_assertion(&mut store, &origin, &request()).await;
        assert!(
            refused.is_err(),
            "no assertion when the counter could not be saved"
        );

        // The unsaved in-memory step is skipped, never reused.
        store.fail = false;
        let a = state
            .next_assertion(&mut store, &origin, &request())
            .await
            .unwrap();
        assert_eq!(counter_of(&a), 3);
        assert_eq!(store.saved, vec![1, 3]);
    }

    #[tokio::test]
    async fn file_store_round_trips_privately() {
        let dir = std::env::temp_dir().join(format!("synthetic-user-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = FileStore::new(dir.join("state.json"));
        assert!(store.load().await.unwrap().is_none());

        let (mut state, origin) = enrolled();
        state.set_account(Account {
            account_id: "usr_1".into(),
            persona_id: "per_1".into(),
            recovery_codes: vec!["RC-SECRET-1".into()],
        });
        state
            .next_assertion(&mut store, &origin, &request())
            .await
            .unwrap();
        let loaded = store.load().await.unwrap().unwrap();
        assert_eq!(loaded.credential().sign_count(), 1);
        assert_eq!(loaded.account().unwrap().account_id, "usr_1");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!format!("{loaded:?}").contains("RC-SECRET-1"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unknown_formats_are_refused() {
        let (state, _) = enrolled();
        let mut value: Value = serde_json::from_slice(&state.to_json().unwrap()).unwrap();
        value["format"] = json!(2);
        assert!(UserState::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
