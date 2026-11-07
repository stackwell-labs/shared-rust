//! `init_tracing` installs the process-global subscriber, so this runs in its own
//! test binary: one test, so nothing else in the process races it for the global.

#[test]
fn init_tracing_is_idempotent_and_refuses_a_different_filter() {
    platform_lambda::init_tracing("platform_lambda=info");
    // The second call `serve` makes after a backend already installed tracing at the
    // top of `main`: a no-op, not the "global default already set" panic.
    platform_lambda::init_tracing("platform_lambda=info");

    let different = std::panic::catch_unwind(|| platform_lambda::init_tracing("other=debug"));
    assert!(
        different.is_err(),
        "a different filter must not be silently ignored"
    );
}
