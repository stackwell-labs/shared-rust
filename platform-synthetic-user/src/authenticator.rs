//! A minimal software WebAuthn authenticator: one ES256 (P-256) credential,
//! `none` attestation, user presence and verification always asserted, and a
//! signature counter that only moves forward.
//!
//! It plays both halves of what a browser plus platform authenticator do:
//! it builds `clientDataJSON` for the issuer's origin, and it refuses any
//! ceremony whose rpId is not exactly that origin's host. ChirpAuth derives its
//! rpId as the issuer's exact host (`rp_id_for_issuer`), so exact match is the
//! whole rule here. A registrable-parent rpId would be refused loudly rather
//! than guessed at.

use std::net::IpAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use url::Url;

use crate::Error;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const COSE_ALG_ES256: i64 = -7;
/// No attestation, so no model identity: the all-zero AAGUID.
const AAGUID_NONE: [u8; 16] = [0; 16];

/// The origin a ceremony runs on and the only rpId it may use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WebOrigin {
    /// `scheme://host[:port]`, as a browser puts it in `clientDataJSON`.
    origin: String,
    host: String,
}

impl WebOrigin {
    /// Browsers run WebAuthn only in a secure context: `https`, or plain
    /// `http` on a loopback host. The same rule here keeps the driver from
    /// ever producing an assertion for a non-TLS remote issuer.
    pub(crate) fn from_issuer(issuer: &Url) -> Result<Self, Error> {
        let host = issuer
            .host_str()
            .ok_or_else(|| Error::Authenticator("issuer has no host".into()))?
            .to_string();
        match issuer.scheme() {
            "https" => {}
            "http" if is_loopback(&host) => {}
            other => {
                return Err(Error::Authenticator(format!(
                    "{other}://{host} is not a secure context"
                )))
            }
        }
        Ok(Self {
            origin: issuer.origin().ascii_serialization(),
            host,
        })
    }

    fn check_rp_id(&self, rp_id: &str) -> Result<(), Error> {
        if rp_id == self.host {
            Ok(())
        } else {
            Err(Error::Authenticator(format!(
                "rpId {rp_id:?} is not the issuer host {:?}",
                self.host
            )))
        }
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The one passkey a synthetic user holds. Serializable so it can live in a
/// secret store; `Debug` never prints the key.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    rp_id: String,
    #[serde(with = "b64")]
    credential_id: Vec<u8>,
    /// The WebAuthn user handle the issuer chose at registration. ChirpAuth
    /// sets it to the account's root UUID.
    #[serde(with = "b64")]
    user_handle: Vec<u8>,
    /// The 32-byte P-256 private scalar.
    #[serde(with = "b64")]
    private_key: Vec<u8>,
    /// The counter value of the last signature this credential produced.
    sign_count: u32,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("rp_id", &self.rp_id)
            .field("credential_id", &b64_encode(&self.credential_id))
            .field("sign_count", &self.sign_count)
            .finish_non_exhaustive()
    }
}

impl Credential {
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    fn signing_key(&self) -> Result<SigningKey, Error> {
        SigningKey::from_slice(&self.private_key)
            .map_err(|_| Error::State("stored private key is not a P-256 scalar".into()))
    }

    /// Answer `navigator.credentials.create`: mint a new credential for the
    /// ceremony and the registration response the issuer's finish expects.
    pub(crate) fn register(
        origin: &WebOrigin,
        options: &CreationOptions,
    ) -> Result<(Credential, Value), Error> {
        let pk = &options.public_key;
        let rp_id = pk.rp.id.clone().unwrap_or_else(|| origin.host.clone());
        origin.check_rp_id(&rp_id)?;
        if !pk
            .pub_key_cred_params
            .iter()
            .any(|p| p.kind == "public-key" && p.alg == COSE_ALG_ES256)
        {
            return Err(Error::Authenticator("issuer does not offer ES256".into()));
        }
        // WebAuthn caps the user handle at 64 bytes.
        if pk.user.id.is_empty() || pk.user.id.len() > 64 {
            return Err(Error::Authenticator(
                "user handle must be 1..=64 bytes".into(),
            ));
        }
        let signing_key = random_signing_key()?;
        let credential_id = random_bytes::<32>()?.to_vec();
        if pk.exclude_credentials.iter().any(|d| d.id == credential_id) {
            return Err(Error::Authenticator("credential is excluded".into()));
        }

        let mut auth_data = authenticator_data(&rp_id, FLAG_UP | FLAG_UV | FLAG_AT, 0);
        auth_data.extend_from_slice(&AAGUID_NONE);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        auth_data.extend_from_slice(&cose_es256_key(signing_key.verifying_key()));
        let client_data = client_data_json("webauthn.create", &pk.challenge, origin)?;

        let response = json!({
            "id": b64_encode(&credential_id),
            "rawId": b64_encode(&credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": b64_encode(&none_attestation_object(&auth_data)),
                "clientDataJSON": b64_encode(&client_data),
            },
            // The credential is discoverable: it answers an empty
            // allowCredentials and always returns its user handle.
            "extensions": { "credProps": { "rk": true } },
        });
        let credential = Credential {
            rp_id,
            credential_id,
            user_handle: pk.user.id.clone(),
            private_key: signing_key.to_bytes().to_vec(),
            sign_count: 0,
        };
        Ok((credential, response))
    }

    /// Answer `navigator.credentials.get` with the next counter value.
    ///
    /// Crate-private on purpose: the only caller is
    /// [`crate::UserState::next_assertion`], which persists the advanced
    /// counter before the assertion can leave the process.
    pub(crate) fn assert(
        &mut self,
        origin: &WebOrigin,
        options: &RequestOptions,
    ) -> Result<Value, Error> {
        let pk = &options.public_key;
        let rp_id = pk.rp_id.clone().unwrap_or_else(|| origin.host.clone());
        origin.check_rp_id(&rp_id)?;
        if rp_id != self.rp_id {
            return Err(Error::Authenticator(format!(
                "credential is bound to {:?}, ceremony asks for {rp_id:?}",
                self.rp_id
            )));
        }
        if !pk.allow_credentials.is_empty()
            && !pk
                .allow_credentials
                .iter()
                .any(|d| d.id == self.credential_id)
        {
            return Err(Error::Authenticator(
                "credential is not in allowCredentials".into(),
            ));
        }
        let key = self.signing_key()?;
        let next = self
            .sign_count
            .checked_add(1)
            .ok_or_else(|| Error::Authenticator("signature counter exhausted".into()))?;

        let auth_data = authenticator_data(&self.rp_id, FLAG_UP | FLAG_UV, next);
        let client_data = client_data_json("webauthn.get", &pk.challenge, origin)?;
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = key.sign(&signed);
        self.sign_count = next;

        Ok(json!({
            "id": b64_encode(&self.credential_id),
            "rawId": b64_encode(&self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": b64_encode(&auth_data),
                "clientDataJSON": b64_encode(&client_data),
                "signature": b64_encode(signature.to_der().as_bytes()),
                "userHandle": b64_encode(&self.user_handle),
            },
            "extensions": {},
        }))
    }
}

/// `PublicKeyCredentialCreationOptions`, as the issuer serializes it under
/// `publicKey`. Only the fields the authenticator acts on.
#[derive(Debug, Deserialize)]
pub(crate) struct CreationOptions {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyCreation,
}

#[derive(Debug, Deserialize)]
struct PublicKeyCreation {
    rp: RpEntity,
    user: UserEntity,
    #[serde(with = "b64")]
    challenge: Vec<u8>,
    #[serde(rename = "pubKeyCredParams")]
    pub_key_cred_params: Vec<CredParam>,
    #[serde(default, rename = "excludeCredentials")]
    exclude_credentials: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct RpEntity {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserEntity {
    #[serde(with = "b64")]
    id: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct CredParam {
    #[serde(rename = "type")]
    kind: String,
    alg: i64,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(with = "b64")]
    id: Vec<u8>,
}

/// `PublicKeyCredentialRequestOptions`, under `publicKey`.
#[derive(Debug, Deserialize)]
pub(crate) struct RequestOptions {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyRequest,
}

#[derive(Debug, Deserialize)]
struct PublicKeyRequest {
    #[serde(with = "b64")]
    challenge: Vec<u8>,
    #[serde(rename = "rpId")]
    rp_id: Option<String>,
    #[serde(default, rename = "allowCredentials")]
    allow_credentials: Vec<Descriptor>,
}

fn authenticator_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
    let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

fn client_data_json(kind: &str, challenge: &[u8], origin: &WebOrigin) -> Result<Vec<u8>, Error> {
    #[derive(Serialize)]
    struct ClientData<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
        challenge: String,
        origin: &'a str,
        #[serde(rename = "crossOrigin")]
        cross_origin: bool,
    }
    serde_json::to_vec(&ClientData {
        kind,
        challenge: b64_encode(challenge),
        origin: &origin.origin,
        cross_origin: false,
    })
    .map_err(|e| Error::Authenticator(format!("clientDataJSON: {e}")))
}

/// CBOR head: major type plus argument, shortest form.
fn cbor_head(out: &mut Vec<u8>, major: u8, value: usize) {
    let m = major << 5;
    match value {
        0..=23 => out.push(m | value as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, value as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
    }
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len());
    out.extend_from_slice(bytes);
}

/// COSE_Key for an ES256 public key: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
fn cose_es256_key(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_sec1_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        unreachable!("an uncompressed P-256 point has both coordinates")
    };
    // map(5); kty: EC2; alg: ES256; crv: P-256
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01];
    out.push(0x21);
    cbor_bytes(&mut out, x);
    out.push(0x22);
    cbor_bytes(&mut out, y);
    out
}

/// `{"fmt": "none", "attStmt": {}, "authData": <bytes>}`.
fn none_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa3];
    cbor_text(&mut out, "fmt");
    cbor_text(&mut out, "none");
    cbor_text(&mut out, "attStmt");
    out.push(0xa0);
    cbor_text(&mut out, "authData");
    cbor_bytes(&mut out, auth_data);
    out
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| Error::Authenticator(format!("no OS randomness: {e}")))?;
    Ok(bytes)
}

fn random_signing_key() -> Result<SigningKey, Error> {
    // A uniformly random 32-byte string is a valid scalar except with
    // probability ~2^-32; draw again in that case.
    loop {
        if let Ok(key) = SigningKey::from_slice(&random_bytes::<32>()?) {
            return Ok(key);
        }
    }
}

pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Unpadded base64url, the encoding WebAuthn's JSON forms use.
mod b64 {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(text.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    fn origin(issuer: &str) -> WebOrigin {
        WebOrigin::from_issuer(&Url::parse(issuer).unwrap()).unwrap()
    }

    fn creation(rp_id: &str, alg: i64) -> CreationOptions {
        serde_json::from_value(json!({ "publicKey": {
            "rp": { "id": rp_id, "name": "Chirp" },
            "user": { "id": b64_encode(&[7u8; 16]), "name": "usr_x", "displayName": "x" },
            "challenge": b64_encode(b"create-challenge"),
            "pubKeyCredParams": [{ "type": "public-key", "alg": alg }],
        }}))
        .unwrap()
    }

    fn request(rp_id: &str, allow: &[&[u8]]) -> RequestOptions {
        let allow: Vec<_> = allow
            .iter()
            .map(|id| json!({ "type": "public-key", "id": b64_encode(id) }))
            .collect();
        serde_json::from_value(json!({ "publicKey": {
            "challenge": b64_encode(b"get-challenge"),
            "rpId": rp_id,
            "allowCredentials": allow,
            "userVerification": "required",
        }}))
        .unwrap()
    }

    fn field(value: &Value, name: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(value["response"][name].as_str().unwrap())
            .unwrap()
    }

    #[test]
    fn registration_encodes_the_credential_and_key() {
        let o = origin("https://signin.example.com");
        let (cred, response) =
            Credential::register(&o, &creation("signin.example.com", -7)).unwrap();
        assert_eq!(cred.sign_count(), 0);
        assert_eq!(
            response["rawId"].as_str().unwrap(),
            b64_encode(cred.credential_id())
        );

        let client: Value = serde_json::from_slice(&field(&response, "clientDataJSON")).unwrap();
        assert_eq!(client["type"], "webauthn.create");
        assert_eq!(client["origin"], "https://signin.example.com");
        assert_eq!(client["challenge"], b64_encode(b"create-challenge"));

        let att = field(&response, "attestationObject");
        // The authData is the trailing CBOR byte string; its layout is fixed.
        let auth_data = &att[att.len() - (37 + 16 + 2 + 32 + 77)..];
        assert_eq!(
            &auth_data[..32],
            Sha256::digest(b"signin.example.com").as_slice()
        );
        assert_eq!(auth_data[32], FLAG_UP | FLAG_UV | FLAG_AT);
        assert_eq!(&auth_data[33..37], &0u32.to_be_bytes());
        assert_eq!(&auth_data[55..87], cred.credential_id());
        let key = cred.signing_key().unwrap();
        assert_eq!(
            &auth_data[87..],
            cose_es256_key(key.verifying_key()).as_slice()
        );
    }

    #[test]
    fn assertions_verify_and_the_counter_only_moves_forward() {
        let o = origin("http://localhost:8080");
        let (mut cred, _) = Credential::register(&o, &creation("localhost", -7)).unwrap();
        let id = cred.credential_id().to_vec();
        for expected in 1..=3u32 {
            let a = cred.assert(&o, &request("localhost", &[&id])).unwrap();
            let auth_data = field(&a, "authenticatorData");
            assert_eq!(&auth_data[33..37], &expected.to_be_bytes());
            assert_eq!(auth_data[32], FLAG_UP | FLAG_UV);
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(field(&a, "clientDataJSON")));
            let sig = Signature::from_der(&field(&a, "signature")).unwrap();
            let key = cred.signing_key().unwrap();
            key.verifying_key().verify(&signed, &sig).unwrap();
            assert_eq!(field(&a, "userHandle"), vec![7u8; 16]);
            assert_eq!(cred.sign_count(), expected);
        }
    }

    #[test]
    fn refuses_what_a_browser_would_refuse() {
        let https = origin("https://signin.example.com");
        assert!(Credential::register(&https, &creation("example.com", -7)).is_err());
        assert!(Credential::register(&https, &creation("signin.example.com", -257)).is_err());
        assert!(WebOrigin::from_issuer(&Url::parse("http://signin.example.com").unwrap()).is_err());
        assert!(WebOrigin::from_issuer(&Url::parse("http://127.0.0.1:9").unwrap()).is_ok());

        let (mut cred, _) =
            Credential::register(&https, &creation("signin.example.com", -7)).unwrap();
        assert!(cred
            .assert(&https, &request("signin.example.com", &[b"other"]))
            .is_err());
        assert_eq!(
            cred.sign_count(),
            0,
            "a refused assertion must not advance the counter"
        );
        // Same credential, presented on another origin.
        let other = origin("https://evil.example.net");
        assert!(cred
            .assert(&other, &request("evil.example.net", &[]))
            .is_err());
        // Discoverable: an empty allow list is answered.
        assert!(cred
            .assert(&https, &request("signin.example.com", &[]))
            .is_ok());
    }

    #[test]
    fn debug_never_prints_the_key() {
        let o = origin("https://signin.example.com");
        let (cred, _) = Credential::register(&o, &creation("signin.example.com", -7)).unwrap();
        let printed = format!("{cred:?}");
        assert!(!printed.contains(&b64_encode(&cred.private_key)));
    }
}
