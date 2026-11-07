//! The synthetic user's durable state and where it is kept.
//!
//! **Counter rule (write-ahead).** An assertion is released only after the
//! counter it carries has been saved. So whatever happens next (the issuer
//! refuses, the network drops, the process is killed), the stored counter is
//! never behind any counter the issuer has seen. Jot's live check saves the
//! counter in a `finally`; write-ahead covers that case and a crash as well.
//! [`UserState::next_assertion`] is the only way to obtain an assertion.
//!
//! **Rotation rule (write-ahead too).** A new key is saved, beside the one in
//! use, before its registration is sent, and it replaces that key only once
//! the issuer has accepted a sign-in from it. So at every point the store
//! holds a key the account accepts, and a rotation cut short anywhere resumes
//! from the store (see [`crate::SyntheticUser::rotate_passkey`]).

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
    /// `Some` while a passkey rotation is in progress. Absent from a state
    /// that is not rotating, so such a state reads as it always has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rotation: Option<Rotation>,
}

/// A passkey rotation part way through.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Rotation {
    /// `next` was saved before its registration was sent, so the issuer may
    /// or may not hold it. `credential` is still the key in use.
    Registering {
        next: Credential,
        /// The issuer's id for the passkey being replaced.
        retire: String,
    },
    /// `credential` is the new key, and the issuer has accepted a sign-in
    /// from it. The old passkey `retire` is still on the account.
    Retiring { retire: String },
}

/// Which of the state's keys signs an assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Key {
    /// The key in use, [`UserState::credential`].
    Current,
    /// The new key of a rotation that is still registering.
    Next,
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
            .field("rotation", &self.rotation)
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
            rotation: None,
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

    /// Whether a passkey rotation was started and has not finished. Running
    /// [`crate::SyntheticUser::rotate_passkey`] again finishes it.
    pub fn is_rotating(&self) -> bool {
        self.rotation.is_some()
    }

    pub(crate) fn rotation(&self) -> Option<&Rotation> {
        self.rotation.as_ref()
    }

    /// Start a rotation: hold `next` beside the key in use. The caller saves
    /// this state before sending `next`'s registration.
    pub(crate) fn begin_rotation(&mut self, next: Credential, retire: String) -> Result<(), Error> {
        if self.rotation.is_some() {
            return Err(Error::State("a rotation is already in progress".into()));
        }
        self.rotation = Some(Rotation::Registering { next, retire });
        Ok(())
    }

    /// The issuer never registered `next` (its sign-in does not offer it):
    /// drop it. The key in use is untouched.
    pub(crate) fn abandon_rotation(&mut self) -> Result<(), Error> {
        match self.rotation {
            Some(Rotation::Registering { .. }) => {
                self.rotation = None;
                Ok(())
            }
            _ => Err(Error::State("no registering rotation to abandon".into())),
        }
    }

    /// The issuer accepted a sign-in from `next`: it becomes the key in use.
    pub(crate) fn promote_next(&mut self) -> Result<(), Error> {
        match self.rotation.take() {
            Some(Rotation::Registering { next, retire }) => {
                self.credential = next;
                self.rotation = Some(Rotation::Retiring { retire });
                Ok(())
            }
            other => {
                self.rotation = other;
                Err(Error::State("no registering rotation to promote".into()))
            }
        }
    }

    /// The old passkey is gone from the account: the rotation is done.
    pub(crate) fn finish_rotation(&mut self) -> Result<(), Error> {
        match self.rotation {
            Some(Rotation::Retiring { .. }) => {
                self.rotation = None;
                Ok(())
            }
            _ => Err(Error::State("no retiring rotation to finish".into())),
        }
    }

    /// Sign the next assertion with `key` and save the advanced counter
    /// **before** returning it. If the save fails, the assertion is dropped
    /// unsent.
    pub(crate) async fn next_assertion<S: StateStore>(
        &mut self,
        store: &mut S,
        key: Key,
        origin: &WebOrigin,
        options: &RequestOptions,
    ) -> Result<Value, Error> {
        let credential = match (key, &mut self.rotation) {
            (Key::Current, _) => &mut self.credential,
            (Key::Next, Some(Rotation::Registering { next, .. })) => next,
            (Key::Next, _) => {
                return Err(Error::State("no new key is registering".into()));
            }
        };
        let assertion = credential.assert(origin, options)?;
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
            .next_assertion(&mut store, Key::Current, &origin, &request())
            .await
            .unwrap();
        assert_eq!(store.saved, vec![1]);
        assert_eq!(counter_of(&a), 1);

        store.fail = true;
        let refused = state
            .next_assertion(&mut store, Key::Current, &origin, &request())
            .await;
        assert!(
            refused.is_err(),
            "no assertion when the counter could not be saved"
        );

        // The unsaved in-memory step is skipped, never reused.
        store.fail = false;
        let a = state
            .next_assertion(&mut store, Key::Current, &origin, &request())
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
            .next_assertion(&mut store, Key::Current, &origin, &request())
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

    #[tokio::test]
    async fn a_rotation_keeps_a_usable_key_at_every_step() {
        let (mut state, origin) = enrolled();
        let (next, _) = enrolled();
        let old_id = state.credential.credential_id().to_vec();
        let next_id = next.credential.credential_id().to_vec();
        let mut store = Recording {
            saved: vec![],
            fail: false,
        };
        assert!(
            state
                .next_assertion(&mut store, Key::Next, &origin, &request())
                .await
                .is_err(),
            "no new key before a rotation starts"
        );

        state
            .begin_rotation(next.credential.clone(), "pk_old".into())
            .unwrap();
        assert!(state.is_rotating());
        assert!(state
            .begin_rotation(next.credential.clone(), "pk_old".into())
            .is_err());
        // Mid-registration the state still reads back, with both keys.
        let read = UserState::from_json(&state.to_json().unwrap()).unwrap();
        assert!(matches!(
            read.rotation(),
            Some(Rotation::Registering { next, retire })
                if next.credential_id() == next_id && retire == "pk_old"
        ));
        assert_eq!(read.credential().credential_id(), old_id);

        // The new key's counter is write-ahead too, and the old key is untouched.
        let a = state
            .next_assertion(&mut store, Key::Next, &origin, &request())
            .await
            .unwrap();
        assert_eq!(counter_of(&a), 1);
        assert_eq!(state.credential().sign_count(), 0);

        state.promote_next().unwrap();
        assert_eq!(state.credential().credential_id(), next_id);
        assert_eq!(
            state.credential().sign_count(),
            1,
            "promoted with its counter"
        );
        assert!(
            matches!(state.rotation(), Some(Rotation::Retiring { retire }) if retire == "pk_old")
        );
        assert!(
            state.abandon_rotation().is_err(),
            "a proven key is never dropped"
        );
        assert!(state.promote_next().is_err());

        state.finish_rotation().unwrap();
        assert!(!state.is_rotating());
        let value: Value = serde_json::from_slice(&state.to_json().unwrap()).unwrap();
        assert!(
            value.get("rotation").is_none(),
            "a settled state has no rotation field"
        );
    }

    #[test]
    fn an_unregistered_new_key_is_abandoned_for_the_old_one() {
        let (mut state, _) = enrolled();
        let (next, _) = enrolled();
        let old_id = state.credential.credential_id().to_vec();
        state
            .begin_rotation(next.credential, "pk_old".into())
            .unwrap();
        state.abandon_rotation().unwrap();
        assert!(!state.is_rotating());
        assert_eq!(state.credential().credential_id(), old_id);
        assert!(state.finish_rotation().is_err());
    }

    #[test]
    fn unknown_formats_are_refused() {
        let (state, _) = enrolled();
        let mut value: Value = serde_json::from_slice(&state.to_json().unwrap()).unwrap();
        value["format"] = json!(2);
        assert!(UserState::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
