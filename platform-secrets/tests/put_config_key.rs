//! Drives `scripts/put-config-key.sh` against a fake `aws` that keeps the
//! secret in a file, and checks that it writes what it should and never
//! prints a value. Needs bash and jq, as the script does. amber-ci's image has
//! no jq, and adding it means changing a required job, which needs the owner
//! (shared-rust#13), so these are ignored by default: run them with
//! `cargo test -p platform-secrets --test put_config_key -- --ignored`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FAKE_AWS: &str = r#"#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  "sts get-caller-identity") echo 111122223333 ;;
  "secretsmanager get-secret-value")
    if [ -f "$FAKE_STORE" ]; then cat "$FAKE_STORE"; else
      echo "An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation: Secrets Manager can't find the specified secret value for staging label: AWSCURRENT" >&2
      exit 254
    fi ;;
  "secretsmanager put-secret-value")
    for a in "$@"; do case "$a" in *hunter*) echo "a value reached argv" >&2; exit 99 ;; esac; done
    cat > "$FAKE_STORE" ;;
  *) echo "fake aws: unexpected $*" >&2; exit 98 ;;
esac
"#;

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("put-config-key-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let aws = dir.join("bin/aws");
        std::fs::write(&aws, FAKE_AWS).unwrap();
        Command::new("chmod").arg("+x").arg(&aws).status().unwrap();
        Self { dir }
    }

    fn store(&self) -> PathBuf {
        self.dir.join("store.json")
    }

    fn stored(&self) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(self.store()).unwrap()).unwrap()
    }

    /// Run the script; returns (success, stdout + stderr).
    fn run(&self, args: &[&str], stdin: &str) -> (bool, String) {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/put-config-key.sh");
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        let mut child = Command::new("bash")
            .arg(script)
            .args(args)
            .env("PATH", path)
            .env("FAKE_STORE", self.store())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), shown)
    }
}

#[test]
#[ignore = "needs jq: cargo test -p platform-secrets --test put_config_key -- --ignored"]
fn writes_keys_and_never_prints_a_value() {
    let f = Fixture::new("writes");

    // No value yet: the first put creates the object.
    let (ok, shown) = f.run(&["svc/test-config", "control_token"], "hunter2-ct\n");
    assert!(ok, "{shown}");
    assert_eq!(
        f.stored(),
        serde_json::json!({"control_token": "hunter2-ct"})
    );

    // A second key keeps the first; a rotation replaces only its key.
    let (ok, shown2) = f.run(&["svc/test-config", "stripe_secret_key"], "hunter2-sk");
    assert!(ok, "{shown2}");
    let (ok, shown3) = f.run(&["svc/test-config", "control_token"], "hunter2-ct2");
    assert!(ok, "{shown3}");
    assert_eq!(
        f.stored(),
        serde_json::json!({"control_token": "hunter2-ct2", "stripe_secret_key": "hunter2-sk"})
    );

    let (ok, listed) = f.run(&["svc/test-config", "--list"], "");
    assert!(ok, "{listed}");
    assert!(
        listed.contains("control_token\tset") && listed.contains("stripe_secret_key\tset"),
        "{listed}"
    );

    for shown in [shown, shown2, shown3, listed] {
        assert!(!shown.contains("hunter2"), "a value was printed: {shown}");
    }
}

#[test]
#[ignore = "needs jq: cargo test -p platform-secrets --test put_config_key -- --ignored"]
fn refuses_blank_values_and_bad_keys() {
    let f = Fixture::new("refuses");
    let (ok, shown) = f.run(&["svc/test-config", "control_token"], "  \n");
    assert!(!ok && shown.contains("empty value"), "{shown}");
    let (ok, shown) = f.run(&["svc/test-config", "Control-Token"], "hunter2");
    assert!(!ok && shown.contains("not snake_case"), "{shown}");
    assert!(!f.store().exists(), "nothing may be written");

    std::fs::write(f.store(), r#"["not an object"]"#).unwrap();
    let (ok, shown) = f.run(&["svc/test-config", "control_token"], "hunter2");
    assert!(!ok && shown.contains("not a JSON object"), "{shown}");
}
