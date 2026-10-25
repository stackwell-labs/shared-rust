# agent-platform platform crates

A Cargo workspace of small, shared crates extracted from the agent-platform
backends (drive, pigeon, bowerbird, social-graph, granite, gotta). Each member
is published from this one repo; consumers depend on individual members by git
tag + package name, e.g.:

```toml
platform-http-error = { git = "https://github.com/coreygirard/agent-platform--platform-crates", tag = "v0.1.0" }
platform-lambda     = { git = "https://github.com/coreygirard/agent-platform--platform-crates", tag = "v0.1.0" }
platform-chirp-auth = { git = "https://github.com/coreygirard/agent-platform--platform-crates", tag = "v0.1.0" }
```

## Members

### `platform-lambda`
The axum-on-Lambda runtime glue that drive/pigeon/bowerbird carried
byte-identically: `run_lambda` (wraps a `Router` in `axum_aws_lambda::LambdaLayer`
and runs it under the Lambda runtime), `shutdown_signal` (Ctrl-C + SIGTERM),
`init_tracing(default_filter)`, and a one-call `serve(app, ServeConfig{ … })`
that owns the local-vs-Lambda detect.

### `platform-http-error`
The canonical `ApiError` enum plus a single `IntoResponse` that **always**
redacts 5xx bodies. Redaction is keyed off the status code, not the variant,
so it is true by construction — no 5xx message can leak internal detail, and
no future 5xx variant can reintroduce the leak. drive/bowerbird previously
leaked the raw `Internal` message; pigeon/social-graph hand-rolled the
redaction; gotta leaked anyhow chains. This crate ends that drift.

### `platform-chirp-auth`
Shared chirp-auth request plumbing:
- `bearer_token` — re-exported from `chirp-auth-client` (RFC-7235 extraction).
- `decode_trusted_headers` — the dev/integration-test trusted-header decoder
  with the 128-char / no-control-char uid + agent-id validation, behind a
  `dev-trusted-headers` cargo feature gate at the call site.
- header-name constants (`x-user-id`, `x-agent-id`, `x-approval-grant`,
  `x-granite-grant`, `x-user-can-write`).
- `apply_on_behalf_of_grant<S: GrantStore>` — the generic
  machine-acting-on-behalf-of-a-human grant resolution, parameterized over a
  per-app grant lookup.

### `platform-outbound-guard`
The one copy of the outbound-fetch (SSRF / DNS-rebinding) guard for
requester-supplied URLs. Two decisions: a public-address **allowlist**
(`ensure_public_ip`) rather than a private-range denylist, so an unenumerated
reserved range fails closed; and **resolve-then-pin** (`resolve_pinned` ->
`Destination::client_builder`), which re-resolves the host immediately before
each attempt, checks every returned address, and pins the client to exactly
those socket addresses. A create-time URL check alone is not a guarantee — a
hostname that passed it can later resolve to 169.254.169.254. Extracted from
chirp-auth's `messaging.rs`; granite previously carried a create-time-only
denylist with no resolution at all.

### `platform-synthetic-user`
A real ChirpAuth account driven by a software passkey, for unattended live
checks against production relying parties: a minimal ES256 WebAuthn
authenticator with a write-ahead counter, and a browserless driver for
ChirpAuth's public signup and PKCE sign-in flows. See its README.

## Building

```sh
cargo build
cargo test
```

## License

MIT OR Apache-2.0.
