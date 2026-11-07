use std::ffi::OsString;

use serde::Deserialize;

use super::*;

const VALUE: &str = "hunter2-very-secret";

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
enum Mode {
    Monitor,
    Enforce,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Config {
    control_token: Secret,
    stripe_secret_key: Option<Secret>,
    origin_url: Option<String>,
    mode: Option<Mode>,
    /// Every value is a string: a number field rejects it.
    port: Option<u16>,
    #[serde(default, deserialize_with = "picky")]
    picky: Option<String>,
}

/// A field parser whose own message quotes the value, as `FromStr` errors do.
fn picky<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let s = String::deserialize(d)?;
    Err(serde::de::Error::custom(format!("bad value {s}")))
}

fn no_env() -> Vec<(OsString, OsString)> {
    Vec::new()
}

fn decode_cfg(json: &str) -> Result<Config, SecretsError> {
    decode("test/live-config", json, no_env())
}

#[test]
fn reads_declared_keys_trimmed() {
    let cfg = decode_cfg(r#"{"control_token":"  ct \n","stripe_secret_key":"sk","origin_url":"https://x","mode":"Enforce"}"#).unwrap();
    assert_eq!(cfg.control_token.expose(), "ct");
    assert_eq!(cfg.stripe_secret_key.unwrap().expose(), "sk");
    assert_eq!(cfg.origin_url.as_deref(), Some("https://x"));
    assert!(matches!(cfg.mode, Some(Mode::Enforce)));
    assert!(cfg.port.is_none());
}

#[test]
fn blank_is_absent() {
    let cfg =
        decode_cfg(r#"{"control_token":"ct","stripe_secret_key":"","origin_url":"   "}"#).unwrap();
    assert!(cfg.stripe_secret_key.is_none());
    assert!(cfg.origin_url.is_none());
    let err = decode_cfg(r#"{"control_token":" \t "}"#).unwrap_err();
    assert!(
        matches!(&err, SecretsError::Missing { key, .. } if key == "control_token"),
        "{err}"
    );
}

#[test]
fn unknown_keys_are_set_aside() {
    let entries = de::entries(
        "t",
        r#"{"control_token":"ct","future_key":"x","retired":12,"nested":{"a":1}}"#,
    )
    .unwrap();
    let (cfg, report) = de::deserialize::<Config>("t", &entries).unwrap();
    assert_eq!(cfg.control_token.expose(), "ct");
    assert_eq!(report.present, vec!["control_token"]);
    assert_eq!(report.ignored, vec!["future_key", "nested", "retired"]);
    assert_eq!(report.secrets, vec!["control_token"]);
}

#[test]
fn only_secret_fields_count_as_secrets() {
    let entries = de::entries(
        "t",
        r#"{"control_token":"ct","stripe_secret_key":"sk","origin_url":"u"}"#,
    )
    .unwrap();
    let (_, report) = de::deserialize::<Config>("t", &entries).unwrap();
    assert_eq!(report.secrets, vec!["control_token", "stripe_secret_key"]);
    assert_eq!(
        report.present,
        vec!["control_token", "origin_url", "stripe_secret_key"]
    );
}

#[test]
fn every_failure_is_an_error() {
    type Check = fn(&SecretsError) -> bool;
    let cases: &[(&str, Check)] = &[
        (r#"{"control_token":"#, |e| {
            matches!(e, SecretsError::NotJson { .. })
        }),
        (r#"["ct"]"#, |e| matches!(e, SecretsError::NotObject { .. })),
        (r#""ct""#, |e| matches!(e, SecretsError::NotObject { .. })),
        (
            r#"{"control_token":12}"#,
            |e| matches!(e, SecretsError::NotString { key, .. } if key == "control_token"),
        ),
        (
            r#"{"control_token":null}"#,
            |e| matches!(e, SecretsError::NotString { key, .. } if key == "control_token"),
        ),
        (
            r#"{}"#,
            |e| matches!(e, SecretsError::Missing { key, .. } if key == "control_token"),
        ),
        (
            r#"{"control_token":"c","port":"eighty"}"#,
            |e| matches!(e, SecretsError::Invalid { key: Some(k), expected: Some(x), .. } if k == "port" && x == "u16"),
        ),
    ];
    for (json, expected) in cases {
        let err = decode_cfg(json).unwrap_err();
        assert!(expected(&err), "{json} gave {err:?}");
    }
}

/// The property this crate exists for: whatever goes wrong, the error's
/// `Display` and `Debug` never contain the value.
#[test]
fn errors_never_carry_values() {
    let cases = [
        format!(r#"{{"control_token":"{VALUE}"#), // unterminated: syntax error
        format!(r#"{{"control_token":"ct","port":"{VALUE}"}}"#), // wrong type
        format!(r#"{{"control_token":"ct","mode":"{VALUE}"}}"#), // unknown variant
        format!(r#"{{"control_token":"ct","picky":"{VALUE}"}}"#), // custom message quoting it
        format!(r#"{{"control_token":"ct","port":"{VALUE}","x":1}}"#),
        format!(r#"["{VALUE}"]"#),
        format!(r#"{{"stripe_secret_key":"{VALUE}"}}"#), // missing required
        r#"{"control_token": 98765432123}"#.to_owned(),
    ];
    for json in &cases {
        let err = decode_cfg(json).unwrap_err();
        let shown = format!("{err} {err:?}");
        assert!(
            !shown.contains(VALUE) && !shown.contains("98765432123"),
            "{json} leaked: {shown}"
        );
    }
    let err = decode_cfg(&format!(r#"{{"control_token":"ct","mode":"{VALUE}"}}"#)).unwrap_err();
    assert!(
        err.to_string().contains(r#"one of ["Monitor", "Enforce"]"#),
        "{err}"
    );
    let err = decode_cfg(&format!(r#"{{"control_token":"ct","picky":"{VALUE}"}}"#)).unwrap_err();
    assert!(
        err.to_string().contains(r#"key "picky""#) && err.to_string().contains("withheld"),
        "{err}"
    );

    let env = vec![(OsString::from("DRIVE_CONTROL_TOKEN"), OsString::from(VALUE))];
    let err = decode::<Config>("t", &format!(r#"{{"control_token":"{VALUE}"}}"#), env).unwrap_err();
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(VALUE), "{shown}");
}

#[test]
fn a_plaintext_copy_in_env_refuses() {
    let json = r#"{"control_token":"ct-value","origin_url":"https://x"}"#;
    let env = |pairs: &[(&str, &str)]| -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    };
    let err = decode::<Config>(
        "t",
        json,
        env(&[("PATH", "/bin"), ("ANY_NAME", " ct-value\n")]),
    )
    .unwrap_err();
    assert!(
        matches!(&err, SecretsError::PlaintextCopy { key, env_var, .. } if key == "control_token" && env_var == "ANY_NAME"),
        "{err}"
    );
    // A non-secret field may share a value with the env, and the secret id's
    // own env var is no copy.
    let cfg: Config = decode(
        "t",
        json,
        env(&[("ORIGIN_URL", "https://x"), ("X_SECRET_ID", "t")]),
    )
    .unwrap();
    assert_eq!(cfg.control_token.expose(), "ct-value");
}

#[test]
fn secret_id_must_be_set() {
    assert!(
        matches!(secret_id("X_ID", None), Err(SecretsError::SecretIdUnset { env }) if env == "X_ID")
    );
    assert!(secret_id("X_ID", Some("  ")).is_err());
    assert_eq!(secret_id("X_ID", Some(" arn:aws:x ")).unwrap(), "arn:aws:x");
}

#[test]
fn secret_debug_is_redacted() {
    let cfg = decode_cfg(&format!(
        r#"{{"control_token":"{VALUE}","stripe_secret_key":"{VALUE}"}}"#
    ))
    .unwrap();
    let shown = format!("{cfg:?}");
    assert!(!shown.contains(VALUE), "{shown}");
    assert!(shown.contains("Secret([redacted])"));
}

/// `Secret` still deserializes through other deserializers, e.g. a service
/// test parsing a fixture with serde_json directly.
#[test]
fn secret_deserializes_from_plain_serde_json() {
    let s: Secret = serde_json::from_str(r#""abc""#).unwrap();
    assert_eq!(s.expose(), "abc");
}

/// A map type reads every key, all as secrets.
#[test]
fn a_map_reads_every_key() {
    let m: std::collections::BTreeMap<String, Secret> =
        decode("t", r#"{"a":"1","b":" "}"#, no_env()).unwrap();
    assert_eq!(m.keys().collect::<Vec<_>>(), vec!["a"]);
}

#[test]
fn from_file_reads_and_reports_its_path() {
    let dir = std::env::temp_dir().join(format!("platform-secrets-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test-config.json");
    std::fs::write(&path, r#"{"control_token":"from-file-ct"}"#).unwrap();
    let cfg: Config = from_file(&path).unwrap();
    assert_eq!(cfg.control_token.expose(), "from-file-ct");
    let err = from_file::<Config>(dir.join("missing.json")).unwrap_err();
    assert!(matches!(err, SecretsError::File { .. }), "{err}");
    std::fs::remove_dir_all(&dir).unwrap();
}
