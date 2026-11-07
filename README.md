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
`init_tracing(default_filter)` (idempotent, so a backend can install tracing as the
first line of `main`), and a one-call `serve(app, ServeConfig{ … })`
that owns the local-vs-Lambda detect. Locally, `serve` prints
`listening on <addr>` on stdout with the address it actually bound
(`LISTENING_PREFIX`), so a parent process can start a service on port 0 and read
its port from that line.

### `platform-http-error`
The canonical `ApiError` enum plus a single `IntoResponse` that **always**
redacts 5xx bodies. Redaction is keyed off the status code, not the variant,
so it is true by construction — no 5xx message can leak internal detail, and
no future 5xx variant can reintroduce the leak. drive/bowerbird previously
leaked the raw `Internal` message; pigeon/social-graph hand-rolled the
redaction; gotta leaked anyhow chains. This crate ends that drift.

### `platform-chirp-auth`
Shared chirp-auth request plumbing:
- `Authenticator` — the one chirp bearer dispatcher. A `Policy` fixed at
  construction says which humans (audiences), which machines
  (`Machines::None | Allow | Any | Dynamic`) and whether test-keyset principals
  (`TestIdentities`) are accepted; `authenticate(&headers)` returns a `Caller`
  or an `AuthFailure`. `Caller::Human` and `Caller::Machine` are production
  callers by construction; anything a test keyset verified, person or machine,
  is `Caller::Test { tenant, principal }`, so `TestIdentities::Reject` refuses
  it all. A ChirpAuth outage is a 503,
  never a 401, and a rejected machine token is never retried as a human. `Caller`
  is an axum extractor (state needs `Authenticator: FromRef<S>`). The `env`
  readers use one naming scheme, `{PREFIX}_CHIRP_ISSUER`,
  `{PREFIX}_HUMAN_AUDIENCES`, `{PREFIX}_MACHINE_CLIENTS`, and a missing or
  blank one is a boot error.
- `VerifyFailure` — the one classification of `ChirpAuthError`, for code that
  calls the verifier itself: `JwksFetch` is `Unavailable` (503), all else
  `Invalid` (401).
- `verify_chirp_event` / `ChirpEvent` / `EventRejection` — re-exported from
  `chirp-auth-client`, for a receiver of Chirp's `user.deleted` webhook.
- `testkit` (feature) — real RS256 tokens, and `Fixture::global()`: a local
  issuer and a throttled (429) one on a thread that outlives each test's
  runtime. Also re-exports chirp-auth-client's event-signing kit
  (`JwksServer`, `TestSigningKey`, `user_deleted_claims`) for webhook tests.
- `bearer_token` — re-exported from `chirp-auth-client` (RFC-7235 extraction).
- `decode_trusted_headers` — the dev/integration-test trusted-header decoder
  with the 128-char / no-control-char uid + agent-id validation, behind a
  `dev-trusted-headers` cargo feature gate at the call site.
- header-name constants (`x-user-id`, `x-agent-id`, `x-approval-grant`,
  `x-granite-grant`, `x-user-can-write`).
- `apply_on_behalf_of_grant<S: GrantStore>` — the generic
  machine-acting-on-behalf-of-a-human grant resolution, parameterized over a
  per-app grant lookup.
- `PairwiseSub` (`sub_…`) and `RootId` (`usr_…`) — chirp's two human-id
  namespaces as two types, serialized as the bare string, so mixing them is a
  compile error rather than a 403 or a lost file.
- `RootResolver` (`/control/root-for-sub`) and `OperatorIntrospector`
  (`/operator/introspect`) — authenticated by the service's own
  `MachineTokenMinter`, never a static bearer. Neither can be built
  unconfigured, and every failure is `Unavailable`, never "no root" or "not an
  operator" (shared-rust#5).

### `platform-outbound-guard`
The one copy of the outbound-fetch (SSRF / DNS-rebinding) guard for
requester-supplied URLs. Two decisions: a public-address **allowlist**
(`ensure_public_ip`) rather than a private-range denylist, so an unenumerated
reserved range fails closed; and **resolve-then-pin** (`resolve_pinned` ->
`Destination::client_builder`), which re-resolves the host immediately before
each attempt, checks every returned address, and pins the client to exactly
those socket addresses, with DNS bounded by `DNS_TIMEOUT`. IPv6 is held to
`2000::/3` minus 6to4 (`2002::/16`), the IETF block `2001::/23` (Teredo
included) and documentation; v4-mapped/compatible forms are judged by their v4
address, and NAT64 is refused. A create-time URL check alone is not a
guarantee — a hostname that passed it can later resolve to 169.254.169.254. Extracted from
chirp-auth's `messaging.rs`; granite previously carried a create-time-only
denylist with no resolution at all.

### `platform-secrets`
The one secret loader for `adr-secret-storage`: `load::<S>(secret_id_env)` does
one `GetSecretValue` and deserializes the service's JSON secret into its own
typed struct. No value can reach an error or a log line. Blank means absent,
undeclared keys are set aside by name, and every failure refuses boot,
including a plaintext env copy of a `Secret`. There is no env source;
`from_file` is for local runs. It ships `scripts/put-config-key.sh`. See its
README.

### `platform-synthetic-user`
A real ChirpAuth account driven by a software passkey, for unattended live
checks against production relying parties: a minimal ES256 WebAuthn
authenticator with a write-ahead counter, and a browserless driver for
ChirpAuth's public signup and PKCE sign-in flows. See its README.

### `platform-fcm`
The one FCM HTTP v1 sender, extracted from Shriek (shared-rust#2): service-account
parsing that fails at boot on a bad key, the RS256 OAuth mint and cache, and a
`send` that returns a typed `Delivery` (`Accepted`, `Failed`, `Unregistered`)
instead of logging and dropping. A `Message` must name its `Priority`, and
`Priority::High` can only carry a visible notification, so no caller inherits
FCM's Doze-delayed NORMAL by omission. The `testkit` feature adds a fake FCM
that verifies the signed assertion. See its README.

### `platform-sg-graph-client`
Social-Graph's graph-access protocol for third-party apps (gotta, porch):
`resolve_me`, `register_membership` and `connections_members` from an opaque
graph-access token. Every call reports SG rejecting the token (401/403) as
`SgError::Rejected`, any other non-2xx as `SgError::Status`, and only a request
that didn't complete as `SgError::Transport`, so an app maps one variant to its
Unauthorized (shared-rust#16).

## Building

```sh
cargo build
cargo test
```

## License

MIT OR Apache-2.0.
