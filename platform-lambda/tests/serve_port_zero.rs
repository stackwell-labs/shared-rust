//! `serve` started on port 0 reports the port it actually bound, as a parent
//! process would read it (shared-rust#1, for compute-gateway#28).
//!
//! The test runs this test binary again as a child that calls `serve` (which
//! never returns), reads the child's stdout the way a parent would, and makes a
//! real request to the reported address.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;

/// Set in the child: run `serve` instead of the test.
const CHILD_ENV: &str = "PLATFORM_LAMBDA_SERVE_PORT_ZERO_CHILD";
const BIND_ENV: &str = "PLATFORM_LAMBDA_TEST_BIND_ADDR";
const TEST_NAME: &str = "serve_on_port_zero_reports_the_bound_address";

/// Kills the child however the test ends.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn serve_on_port_zero_reports_the_bound_address() {
    if std::env::var_os(CHILD_ENV).is_some() {
        run_child();
    }

    let child = Command::new(std::env::current_exe().expect("test binary path"))
        // `--quiet`: libtest's default format writes `test <name> ... ` with no
        // newline before running the test, which would land in front of the
        // listening line; a real service's stdout has no such prefix.
        .args(["--exact", TEST_NAME, "--nocapture", "--quiet"])
        .env(CHILD_ENV, "1")
        .env(BIND_ENV, "127.0.0.1:0")
        .env_remove("AWS_LAMBDA_RUNTIME_API")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn child");
    let mut child = KillOnDrop(child);
    let stdout = child.0.stdout.take().expect("child stdout");

    // The first line with the documented prefix; libtest and the tracing log
    // may print other lines around it. Read on a thread so a child that never
    // prints the line fails the test instead of hanging it.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let found = BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .find(|l| l.starts_with(platform_lambda::LISTENING_PREFIX));
        let _ = tx.send(found);
    });
    let line = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("no listening line within 30s")
        .expect("child exited without printing the listening line");

    assert!(
        !line.contains('\x1b'),
        "listening line has ANSI codes: {line:?}"
    );
    let bound: SocketAddr = line[platform_lambda::LISTENING_PREFIX.len()..]
        .parse()
        .unwrap_or_else(|_| panic!("listening line is not `<prefix><addr>`: {line:?}"));
    assert_eq!(bound.ip().to_string(), "127.0.0.1");
    assert_ne!(
        bound.port(),
        0,
        "reported the configured port, not the bound one"
    );

    let mut conn = TcpStream::connect(bound).expect("connect to the reported address");
    conn.write_all(b"GET /probe HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .expect("send request");
    let mut response = String::new();
    conn.read_to_string(&mut response).expect("read response");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "response: {response:?}"
    );
    assert!(response.ends_with("served"), "response: {response:?}");
}

fn run_child() -> ! {
    let app = Router::new().route("/probe", get(|| async { "served" }));
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(platform_lambda::serve(
            app,
            platform_lambda::ServeConfig {
                bind_env: BIND_ENV,
                default_bind: "127.0.0.1:9",
                default_filter: "platform_lambda=info",
            },
        ));
    panic!("serve returned without a shutdown signal");
}
