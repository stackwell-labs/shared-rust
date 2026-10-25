//! A **synthetic user**: a real ChirpAuth account whose passkey is software,
//! so a live check can sign in with no human and no test bypass.
//!
//! ChirpAuth refuses test tokens at production relying parties (keyset
//! separation), so the sanctioned way to exercise a prod RP unattended is a
//! real account. This crate is that account's two halves:
//!
//! - [`Credential`]: a minimal software WebAuthn authenticator (one ES256
//!   key, `none` attestation, forward-only counter, exact-host rpId).
//! - [`SyntheticUser`]: the browserless driver for ChirpAuth's public flows:
//!   [`SyntheticUser::enroll`] (passkey signup), [`SyntheticUser::authorize`]
//!   (any `/authorize` URL → the RP callback with a code), and
//!   [`SyntheticUser::sign_in`] (a public PKCE client end to end).
//!
//! State lives in a [`StateStore`]. An assertion is released only after its
//! counter is saved (see [`state`] for the rule).
//!
//! ```no_run
//! # async fn run() -> Result<(), platform_synthetic_user::Error> {
//! use platform_synthetic_user::{FileStore, Issuer, PublicClient, SyntheticUser};
//! let issuer = Issuer::new("http://localhost:8080")?;
//! let mut user = SyntheticUser::load(issuer, FileStore::new("user.json")).await?;
//! let signed_in = user
//!     .sign_in(&PublicClient {
//!         client_id: "my-app".into(),
//!         redirect_uri: "http://localhost:3000/callback".into(),
//!         scope: "openid".into(),
//!     })
//!     .await?;
//! // Verify signed_in.id_token with the RP's own verifier.
//! # Ok(()) }
//! ```

mod authenticator;
mod driver;
mod error;
pub mod state;

pub use authenticator::Credential;
pub use driver::{Issuer, PublicClient, SignIn, SyntheticUser};
pub use error::Error;
pub use state::{Account, FileStore, StateStore, UserState};
