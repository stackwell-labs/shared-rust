//! Under Lambda, `init_tracing` writes plain text: CloudWatch shows ANSI codes
//! verbatim (shared-rust#26). Locally the log stays coloured.
//!
//! The global subscriber can be installed once per process, so each case runs
//! this test binary again as a child that calls `init_tracing` and logs one
//! event, and the parent reads the child's stdout.

use std::process::Command;

/// Set in the child: install tracing and log instead of running the test.
const CHILD_ENV: &str = "PLATFORM_LAMBDA_LOG_PLAIN_CHILD";
const CHILD_TEST: &str = "child";

#[test]
fn child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }
    platform_lambda::init_tracing("lambda_log_plain=info");
    tracing::info!(secret = "arn:x", "loaded");
}

/// The child's stdout, with `AWS_LAMBDA_RUNTIME_API` set to `runtime_api` or removed.
fn child_log(runtime_api: Option<&str>) -> String {
    let mut cmd = Command::new(std::env::current_exe().expect("test binary path"));
    cmd.args(["--exact", CHILD_TEST, "--nocapture", "--quiet"])
        .env(CHILD_ENV, "1")
        .env_remove("RUST_LOG")
        // tracing-subscriber turns colour off when NO_COLOR is set; the local
        // case must see the default.
        .env_remove("NO_COLOR");
    match runtime_api {
        Some(v) => cmd.env("AWS_LAMBDA_RUNTIME_API", v),
        None => cmd.env_remove("AWS_LAMBDA_RUNTIME_API"),
    };
    let out = cmd.output().expect("run child");
    assert!(out.status.success(), "child failed: {out:?}");
    String::from_utf8(out.stdout).expect("utf-8 stdout")
}

#[test]
fn under_lambda_the_log_has_no_ansi_codes() {
    let log = child_log(Some("127.0.0.1:9001"));
    let line = log
        .lines()
        .find(|l| l.contains("loaded"))
        .unwrap_or_else(|| panic!("no log line in {log:?}"));
    assert!(!line.contains('\x1b'), "ANSI codes under Lambda: {line:?}");
    assert!(line.contains(" INFO "), "level not plain: {line:?}");
    assert!(
        line.contains(r#"secret="arn:x""#),
        "field not plain: {line:?}"
    );
}

#[test]
fn locally_the_log_is_coloured() {
    let log = child_log(None);
    let line = log
        .lines()
        .find(|l| l.contains("loaded"))
        .unwrap_or_else(|| panic!("no log line in {log:?}"));
    assert!(line.contains('\x1b'), "no colour locally: {line:?}");
}
