//! The keyless credential (shared-rust#38): a Google `external_account`
//! config whose subject is the AWS role the process runs as, through
//! Workload Identity Federation.
//!
//! Firebase project `chirp-push-4821`'s org policy forbids service-account
//! keys, so a Lambda proves who it is to Google with its own AWS role:
//!
//! 1. sign an STS `GetCallerIdentity` request (SigV4) with the role's
//!    credentials, without sending it;
//! 2. exchange that signed request at Google STS (`token_url`, RFC 8693) for a
//!    federated token, scoped to the pool's `audience`;
//! 3. call `generateAccessToken` on the impersonated service account
//!    (`service_account_impersonation_url`) for a token with the FCM scope.
//!
//! The AWS credentials come from the environment Lambda sets
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
//! `AWS_REGION`), read once at construction. The config's EC2 metadata URLs
//! (`credential_source.url`, `region_url`) are not used: Google's own
//! libraries also prefer those variables when they are set, and nothing here
//! runs where only the metadata server has them.

use std::fmt;

use ring::{digest, hmac};

use crate::{ConfigError, FCM_SCOPE};

/// The only subject this crate exchanges: a signed AWS `GetCallerIdentity`.
pub const AWS_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:aws:token-type:aws4_request";

/// The scope of the federated token STS issues; it is only ever used to call
/// `generateAccessToken`, which then narrows to [`FCM_SCOPE`].
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// `generateAccessToken`'s default lifetime, and Google's default for
/// `service_account_impersonation.token_lifetime_seconds`.
const DEFAULT_LIFETIME_SECS: u64 = 3600;

/// A Google `external_account` config with an AWS subject, validated.
///
/// It holds no secret (the config is a set of URLs), but errors still name
/// only the field, never its value, as [`crate::ServiceAccount`]'s do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAccount {
    audience: String,
    token_url: String,
    impersonation_url: String,
    /// `regional_cred_verification_url`, still holding its `{region}`.
    verification_url: String,
    lifetime_secs: u64,
}

fn err(message: impl Into<String>) -> ConfigError {
    ConfigError(format!("FCM external account: {}", message.into()))
}

impl ExternalAccount {
    /// Parse a Google `external_account` config file (what `gcloud iam
    /// workload-identity-pools create-cred-config --aws` writes). Needs
    /// `type: external_account`, an `audience`, a `token_url`, the AWS
    /// `subject_token_type`, a `service_account_impersonation_url` (FCM needs
    /// a token scoped to `firebase.messaging`, which only an impersonated
    /// service account can have), and a `credential_source` with
    /// `environment_id: aws1` and a `regional_cred_verification_url`.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
            err(format!(
                "not JSON (line {}, column {})",
                e.line(),
                e.column()
            ))
        })?;
        let string_at = |v: &serde_json::Value, path: &str| -> Result<String, ConfigError> {
            match v.as_str() {
                Some(s) if !s.trim().is_empty() => Ok(s.to_owned()),
                _ => Err(err(format!("`{path}` is missing, empty or not a string"))),
            }
        };
        let field = |name: &str| string_at(&value[name], name);
        let must_be = |name: &str, want: &str| -> Result<(), ConfigError> {
            if field(name)? == want {
                Ok(())
            } else {
                Err(err(format!("`{name}` is not `{want}`")))
            }
        };
        must_be("type", "external_account")?;
        must_be("subject_token_type", AWS_SUBJECT_TOKEN_TYPE)?;
        let audience = field("audience")?;
        let token_url = field("token_url")?;
        let impersonation_url = field("service_account_impersonation_url")?;
        let source = &value["credential_source"];
        if string_at(
            &source["environment_id"],
            "credential_source.environment_id",
        )? != "aws1"
        {
            return Err(err("`credential_source.environment_id` is not `aws1`"));
        }
        let verification_url = string_at(
            &source["regional_cred_verification_url"],
            "credential_source.regional_cred_verification_url",
        )?;
        // Checked now, with a placeholder region, so a URL that cannot be
        // signed fails at boot rather than at the first push.
        reqwest::Url::parse(&verification_url.replace("{region}", "us-east-1"))
            .map_err(|_| err("`credential_source.regional_cred_verification_url` is not a URL"))?;
        // Google's bounds for the impersonated token's lifetime.
        let lifetime_secs = match value
            .get("service_account_impersonation")
            .and_then(|v| v.get("token_lifetime_seconds"))
        {
            None => DEFAULT_LIFETIME_SECS,
            Some(v) => match v.as_u64() {
                Some(secs) if (600..=43200).contains(&secs) => secs,
                _ => return Err(err(
                    "`service_account_impersonation.token_lifetime_seconds` is not 600 to 43200",
                )),
            },
        };
        Ok(Self {
            audience,
            token_url,
            impersonation_url,
            verification_url,
            lifetime_secs,
        })
    }

    /// The workload identity pool provider this config federates through.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The signed `GetCallerIdentity` request, as the subject token Google
    /// STS takes: the URL, method and headers as JSON, percent-encoded (as
    /// Google's own libraries send it).
    pub(crate) fn subject_token(&self, aws: &AwsCredentials, now: u64) -> Result<String, String> {
        let url = self.verification_url.replace("{region}", &aws.region);
        let parsed = reqwest::Url::parse(&url).map_err(|e| format!("verification URL: {e}"))?;
        let extra = [(
            "x-goog-cloud-target-resource".to_owned(),
            self.audience.clone(),
        )];
        let mut headers = sigv4::sign("POST", &parsed, &extra, "sts", aws, now)?;
        // Google's libraries list the headers sorted by name.
        headers.sort();
        let token = serde_json::json!({
            "url": url,
            "method": "POST",
            "headers": headers
                .into_iter()
                .map(|(key, value)| serde_json::json!({ "key": key, "value": value }))
                .collect::<Vec<_>>(),
        });
        Ok(sigv4::uri_encode(&token.to_string()))
    }

    /// Mint an FCM-scoped access token: subject token, STS exchange,
    /// impersonation. Returns the token and how long it lives (seconds).
    pub(crate) async fn mint(
        &self,
        http: &reqwest::Client,
        aws: &AwsCredentials,
        now: u64,
    ) -> Result<(String, u64), String> {
        let subject_token = self.subject_token(aws, now)?;
        let resp = http
            .post(&self.token_url)
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("audience", self.audience.as_str()),
                ("scope", CLOUD_PLATFORM_SCOPE),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("subject_token_type", AWS_SUBJECT_TOKEN_TYPE),
                ("subject_token", subject_token.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("STS token exchange: {e}"))?;
        let body = json_or_status(resp, "STS token exchange").await?;
        let federated = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("STS response has no access_token")?;

        let resp = http
            .post(&self.impersonation_url)
            .bearer_auth(federated)
            .json(&serde_json::json!({
                "scope": [FCM_SCOPE],
                "lifetime": format!("{}s", self.lifetime_secs),
            }))
            .send()
            .await
            .map_err(|e| format!("generateAccessToken: {e}"))?;
        let body = json_or_status(resp, "generateAccessToken").await?;
        let token = body
            .get("accessToken")
            .and_then(|v| v.as_str())
            .ok_or("generateAccessToken response has no accessToken")?;
        // Granted for the lifetime asked, from no earlier than `now`.
        Ok((token.to_owned(), self.lifetime_secs))
    }
}

/// The body of a 2xx answer, or an error naming `what`, the status and the
/// body Google sent (its error, which never repeats the request).
async fn json_or_status(resp: reqwest::Response, what: &str) -> Result<serde_json::Value, String> {
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("{what} {status}, body not JSON: {e}"))?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("{what} {status}: {body}"))
    }
}

/// The AWS role credentials the subject is signed with.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AwsCredentials {
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
    pub(crate) session_token: Option<String>,
    pub(crate) region: String,
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("region", &self.region)
            .finish()
    }
}

impl AwsCredentials {
    /// The role credentials and region Lambda puts in the environment.
    pub(crate) fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |name: &str| var(name).filter(|v| !v.trim().is_empty());
        let required = |name: &str| {
            get(name).ok_or_else(|| {
                err(format!(
                    "`{name}` is unset or empty: the AWS subject is signed with the role \
                     credentials Lambda sets in the environment"
                ))
            })
        };
        Ok(Self {
            access_key_id: required("AWS_ACCESS_KEY_ID")?,
            secret_access_key: required("AWS_SECRET_ACCESS_KEY")?,
            session_token: get("AWS_SESSION_TOKEN"),
            region: required("AWS_REGION")?,
        })
    }
}

/// AWS Signature Version 4, for the one request this crate signs. Shared with
/// the testkit's fake STS, which verifies by signing again; the AWS test
/// vector below keeps that from being circular.
pub(crate) mod sigv4 {
    use super::*;

    /// The headers a request to `url` must carry to be signed for `service`:
    /// `host`, `x-amz-date`, `x-amz-security-token` (with a session token),
    /// the `extra` ones, and `Authorization`. The body is empty.
    pub(crate) fn sign(
        method: &str,
        url: &reqwest::Url,
        extra: &[(String, String)],
        service: &str,
        aws: &AwsCredentials,
        now: u64,
    ) -> Result<Vec<(String, String)>, String> {
        let host = match (url.host_str(), url.port()) {
            (Some(host), None) => host.to_owned(),
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (None, _) => return Err("verification URL has no host".to_owned()),
        };
        let amz_date = amz_date(now);
        let mut headers = vec![
            ("host".to_owned(), host),
            ("x-amz-date".to_owned(), amz_date.clone()),
        ];
        if let Some(token) = &aws.session_token {
            headers.push(("x-amz-security-token".to_owned(), token.clone()));
        }
        headers.extend(extra.iter().cloned());
        let authorization = authorization(method, url, &headers, service, aws, &amz_date);
        headers.push(("Authorization".to_owned(), authorization));
        Ok(headers)
    }

    /// The `Authorization` value for `headers` (every one of them signed),
    /// stamped `amz_date` (`YYYYMMDDTHHMMSSZ`).
    pub(crate) fn authorization(
        method: &str,
        url: &reqwest::Url,
        headers: &[(String, String)],
        service: &str,
        aws: &AwsCredentials,
        amz_date: &str,
    ) -> String {
        let mut canonical: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        canonical.sort();
        let signed_headers = canonical
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_headers: String = canonical
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect();
        let mut query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (uri_encode(&k), uri_encode(&v)))
            .collect();
        query.sort();
        let query = query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let path = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        let canonical_request = format!(
            "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{}",
            hex(digest::digest(&digest::SHA256, b"").as_ref())
        );
        let date = &amz_date[..8];
        let scope = format!("{date}/{}/{service}/aws4_request", aws.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(digest::digest(&digest::SHA256, canonical_request.as_bytes()).as_ref())
        );
        let mac = |key: &[u8], data: &str| {
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
        };
        let k = mac(format!("AWS4{}", aws.secret_access_key).as_bytes(), date);
        let k = mac(k.as_ref(), &aws.region);
        let k = mac(k.as_ref(), service);
        let k = mac(k.as_ref(), "aws4_request");
        let signature = hex(mac(k.as_ref(), &string_to_sign).as_ref());
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            aws.access_key_id
        )
    }

    /// `now` (Unix seconds) as SigV4's `YYYYMMDDTHHMMSSZ`.
    pub(crate) fn amz_date(now: u64) -> String {
        let (y, mo, d, h, mi, s) = civil(now);
        format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
    }

    /// `now` (Unix seconds) as UTC calendar fields (Hinnant's
    /// `civil_from_days`).
    pub(crate) fn civil(now: u64) -> (u64, u64, u64, u64, u64, u64) {
        let days = now / 86_400;
        let secs = now % 86_400;
        let z = days + 719_468;
        let era = z / 146_097;
        let doe = z % 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + u64::from(m <= 2);
        (y, m, d, secs / 3600, secs % 3600 / 60, secs % 60)
    }

    /// RFC 3986 percent-encoding of everything but the unreserved characters,
    /// as SigV4 encodes query parameters.
    pub(crate) fn uri_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> serde_json::Value {
        serde_json::json!({
            "type": "external_account",
            "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/devbox/providers/devbox-aws",
            "subject_token_type": AWS_SUBJECT_TOKEN_TYPE,
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken",
            "token_url": "https://sts.googleapis.com/v1/token",
            "credential_source": {
                "environment_id": "aws1",
                "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone",
                "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials",
                "regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15",
            },
        })
    }

    /// AWS's published SigV4 test vector `get-vanilla` (aws-sig-v4-test-suite):
    /// the signer agrees with AWS, so the fake STS, which verifies by signing
    /// again, is not checking the signer against itself.
    #[test]
    fn the_signer_matches_the_aws_test_vector() {
        let aws = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
            region: "us-east-1".into(),
        };
        let url = reqwest::Url::parse("https://example.amazonaws.com/").unwrap();
        let headers = [
            ("Host".to_owned(), "example.amazonaws.com".to_owned()),
            ("X-Amz-Date".to_owned(), "20150830T123600Z".to_owned()),
        ];
        assert_eq!(
            sigv4::authorization("GET", &url, &headers, "service", &aws, "20150830T123600Z"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn dates_are_utc_calendar_dates() {
        assert_eq!(sigv4::amz_date(1_440_938_160), "20150830T123600Z");
        assert_eq!(sigv4::amz_date(951_782_400), "20000229T000000Z");
        assert_eq!(sigv4::amz_date(0), "19700101T000000Z");
    }

    /// The subject token is the signed GetCallerIdentity for the Lambda's
    /// region, naming the pool provider in a signed header.
    #[test]
    fn the_subject_token_is_a_signed_get_caller_identity() {
        let account = ExternalAccount::from_json(&config().to_string()).unwrap();
        let aws = AwsCredentials {
            access_key_id: "AKID".into(),
            secret_access_key: "secret".into(),
            session_token: Some("session".into()),
            region: "us-west-2".into(),
        };
        let token = account.subject_token(&aws, 1_440_938_160).unwrap();
        assert!(!token.contains('{'), "percent-encoded: {token}");
        let decoded = String::from_utf8(
            token
                .split('%')
                .enumerate()
                .flat_map(|(i, part)| {
                    if i == 0 {
                        part.as_bytes().to_vec()
                    } else {
                        let mut v = vec![u8::from_str_radix(&part[..2], 16).unwrap()];
                        v.extend_from_slice(&part.as_bytes()[2..]);
                        v
                    }
                })
                .collect(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(
            json["url"],
            "https://sts.us-west-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
        );
        assert_eq!(json["method"], "POST");
        let header = |name: &str| {
            json["headers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|h| h["key"] == name)
                .map(|h| h["value"].as_str().unwrap().to_owned())
        };
        assert_eq!(header("host").unwrap(), "sts.us-west-2.amazonaws.com");
        assert_eq!(header("x-amz-date").unwrap(), "20150830T123600Z");
        assert_eq!(header("x-amz-security-token").unwrap(), "session");
        assert_eq!(
            header("x-goog-cloud-target-resource").unwrap(),
            account.audience()
        );
        let auth = header("Authorization").unwrap();
        assert!(
            auth.starts_with("AWS4-HMAC-SHA256 Credential=AKID/20150830/us-west-2/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token;x-goog-cloud-target-resource, Signature="),
            "{auth}"
        );
    }

    /// Every way the config can be unusable is an error at construction,
    /// naming the field and never repeating a value from it.
    #[test]
    fn an_unusable_config_fails_at_construction_without_echoing_it() {
        let marker = "ZZ-VALUE-ZZ";
        let mut cases: Vec<serde_json::Value> = Vec::new();
        let mut with = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut c = config();
            edit(&mut c);
            cases.push(c);
        };
        with(&|c| c["type"] = marker.into());
        with(&|c| c["subject_token_type"] = format!("urn:{marker}").into());
        with(&|c| c["audience"] = "".into());
        with(&|c| c["token_url"] = 7.into());
        with(&|c| {
            c.as_object_mut()
                .unwrap()
                .remove("service_account_impersonation_url");
        });
        with(&|c| c["credential_source"]["environment_id"] = marker.into());
        with(&|c| c["credential_source"] = serde_json::json!({ "file": marker }));
        with(&|c| c["credential_source"]["regional_cred_verification_url"] = marker.into());
        with(&|c| {
            c["service_account_impersonation"] = serde_json::json!({ "token_lifetime_seconds": 99 })
        });
        for case in cases {
            let err = ExternalAccount::from_json(&case.to_string())
                .expect_err(&case.to_string())
                .to_string();
            assert!(!err.contains(marker), "{err}");
            assert!(err.starts_with("FCM external account: "), "{err}");
        }
        let err = ExternalAccount::from_json(&format!("{{\"type\": \"{marker}")).unwrap_err();
        assert!(!err.to_string().contains(marker), "{err}");
    }

    #[test]
    fn a_lifetime_in_the_config_is_the_one_asked_for() {
        let mut c = config();
        c["service_account_impersonation"] = serde_json::json!({ "token_lifetime_seconds": 1200 });
        assert_eq!(
            ExternalAccount::from_json(&c.to_string())
                .unwrap()
                .lifetime_secs,
            1200
        );
    }

    #[test]
    fn missing_aws_credentials_fail_at_construction_without_echoing_them() {
        let vars = |missing: &'static str| {
            move |name: &str| (name != missing).then(|| format!("value-of-{name}-XYZZY"))
        };
        for missing in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"] {
            let err = AwsCredentials::from_vars(vars(missing))
                .unwrap_err()
                .to_string();
            assert!(err.contains(missing), "{err}");
            assert!(!err.contains("XYZZY"), "{err}");
        }
        let aws = AwsCredentials::from_vars(vars("AWS_SESSION_TOKEN")).unwrap();
        assert_eq!(aws.session_token, None);
        let aws = AwsCredentials::from_vars(vars("none")).unwrap();
        let debug = format!("{aws:?}");
        assert!(!debug.contains("value-of-AWS_SECRET_ACCESS_KEY"), "{debug}");
        assert!(!debug.contains("value-of-AWS_SESSION_TOKEN"), "{debug}");
    }
}
