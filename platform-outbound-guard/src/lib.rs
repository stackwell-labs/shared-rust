//! The canonical outbound-fetch guard for user-supplied URLs (SSRF /
//! DNS-rebinding).
//!
//! Any service that POSTs to an address a *requester* chose — a webhook
//! callback, a fetch-this-URL feature — is one bad hostname away from being a
//! proxy into its own VPC: the cloud metadata endpoint (169.254.169.254), a
//! private-range service, loopback. This crate is the one copy of the defense.
//!
//! Two decisions, both deliberate:
//!
//! 1. **ALLOWLIST, not denylist.** [`ensure_public_ip`] accepts only globally
//!    routable unicast addresses. A denylist enumerating "private" ranges is
//!    perpetually incomplete — it fails OPEN on every range it forgot (and on
//!    every range IANA reserves next). The allow-shape fails CLOSED.
//!
//! 2. **Resolve, then PIN.** Checking the URL at registration time proves
//!    nothing at delivery time: a hostname that passed the check can later
//!    resolve to 169.254.169.254. [`resolve_pinned`] resolves the host
//!    immediately before the request, checks *every* returned address, and
//!    hands back a [`Destination`] that pins the HTTP client to exactly those
//!    socket addresses — so the connection cannot go anywhere else, and the
//!    check is redone on every attempt (including retries).
//!
//! A [`Destination`] is only constructible by passing the check, so "I built a
//! client without validating" is not a reachable state.
//!
//! ```no_run
//! # async fn f() -> Result<(), Box<dyn std::error::Error>> {
//! let url = platform_outbound_guard::validate_url("https://app.example/hook")?;
//! let destination = platform_outbound_guard::resolve_pinned(&url).await?;
//! let http = destination
//!     .client_builder()
//!     .timeout(std::time::Duration::from_secs(15))
//!     .build()?;
//! http.post(url).send().await?;
//! # Ok(()) }
//! ```
//!
//! A synchronous caller (ureq, a wasmtime host import) uses
//! [`resolve_pinned_blocking`] instead and pins its own client to
//! [`Destination::addrs`].

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub use url::Url;

/// Why an outbound destination was refused. Opaque message, `std::error::Error`
/// so callers on `anyhow` can `?` it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardError(String);

impl GuardError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The human-readable reason.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GuardError {}

/// Parse and vet a requester-supplied destination URL: https only, a host,
/// no embedded userinfo, a known port, and — when the host is a literal IP —
/// a public address.
///
/// This is the cheap, synchronous half. It is NOT sufficient on its own: a
/// hostname is not resolved here, so [`resolve_pinned`] must run at request
/// time. Use this at registration time to give the requester a fast, clear
/// error; use `resolve_pinned` where the guarantee actually has to hold.
pub fn validate_url(raw: &str) -> Result<Url, GuardError> {
    let url = Url::parse(raw).map_err(|e| GuardError::new(format!("invalid URL: {e}")))?;
    check_url(&url)?;
    Ok(url)
}

/// [`validate_url`]'s checks against an already-parsed [`Url`].
pub fn check_url(url: &Url) -> Result<(), GuardError> {
    if url.scheme() != "https" {
        return Err(GuardError::new("URL must use https"));
    }
    if url.host().is_none() {
        return Err(GuardError::new("URL must include a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(GuardError::new("URL must not contain userinfo"));
    }
    if url.port_or_known_default().is_none() {
        return Err(GuardError::new("URL must include a valid port"));
    }
    if let Some(ip) = literal_host_ip(url) {
        ensure_public_ip(ip)?;
    }
    Ok(())
}

/// The host as a literal IP, or `None` when it is a domain name (which must be
/// resolved before it can be judged).
///
/// WHATWG host parsing has already normalized dotted/hex/octal IPv4 disguises
/// (`0x7f.0.0.1`) to an address by the time this sees it.
pub fn literal_host_ip(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        url::Host::Domain(_) => None,
    }
}

/// Only globally-routable unicast addresses are valid outbound destinations.
/// This explicit allow-shape is intentionally stricter than a private-range
/// denylist: newly introduced special ranges fail closed.
pub fn ensure_public_ip(ip: IpAddr) -> Result<(), GuardError> {
    let public = match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    };
    if public {
        Ok(())
    } else {
        Err(GuardError::new(
            "destination resolves to a non-public address",
        ))
    }
}

/// Whether `ip` is a globally-routable unicast IPv4 address.
///
/// Rejected, by leading octets: `0/8` (this-network), `10/8`, `100.64/10`
/// (CGNAT), `127/8` (loopback), `169.254/16` (link-local — the IMDS endpoint),
/// `172.16/12`, `192.0.0/24` (IETF protocol assignments), `192.0.2/24`
/// (TEST-NET-1), `192.88.99/24` (6to4 relay anycast), `192.168/16`,
/// `198.18/15` (benchmarking), `198.51.100/24` (TEST-NET-2), `203.0.113/24`
/// (TEST-NET-3), and everything from `224.0.0.0` up (multicast, reserved,
/// broadcast).
pub fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !matches!(
        (a, b, c),
        (0, _, _)
            | (10, _, _)
            | (100, 64..=127, _)
            | (127, _, _)
            | (169, 254, _)
            | (172, 16..=31, _)
            | (192, 0, 0)
            | (192, 0, 2)
            | (192, 88, 99)
            | (192, 168, _)
            | (198, 18..=19, _)
            | (198, 51, 100)
            | (203, 0, 113)
            | (224..=255, _, _)
    )
}

/// Whether `ip` is a globally-routable unicast IPv6 address.
///
/// A v4-mapped / v4-compatible form (`::ffff:a.b.c.d`, `::a.b.c.d`) is judged
/// by its embedded v4 address, so a v4 range cannot be smuggled through a v6
/// literal. Otherwise only global unicast (`2000::/3`) is accepted, minus three
/// globally shaped prefixes that are not ordinary unicast destinations:
///
/// - `2001::/23`, the IETF protocol-assignment block: Teredo (`2001::/32`,
///   which embeds an IPv4 address), benchmarking (`2001:2::/48`), ORCHID and
///   the rest. Excluded whole rather than one range at a time.
/// - `2001:db8::/32`, documentation.
/// - `2002::/16`, 6to4, which embeds an IPv4 address (`2002:a9fe:a9fe::` is
///   169.254.169.254) that a relay would unwrap.
///
/// Everything outside `2000::/3` is refused by construction: loopback (`::1`),
/// unspecified (`::`), NAT64 (`64:ff9b::/96`), unique-local (`fc00::/7`),
/// link-local (`fe80::/10`), and multicast (`ff00::/8`).
pub fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4() {
        return is_public_ipv4(v4);
    }
    let [a, b, ..] = ip.segments();
    let global_unicast = (a & 0xe000) == 0x2000;
    let ietf_protocol_assignments = a == 0x2001 && b < 0x0200;
    let documentation = a == 0x2001 && b == 0x0db8;
    let six_to_four = a == 0x2002;
    global_unicast && !ietf_protocol_assignments && !documentation && !six_to_four
}

/// How long [`resolve_pinned`] waits for DNS before refusing the destination,
/// so a hostile or dead resolver for a requester-chosen hostname cannot stall
/// the caller.
pub const DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// A destination that PASSED the guard: the host plus the exact socket
/// addresses it resolved to, every one of them checked public.
///
/// There is no public constructor other than [`resolve_pinned`] and
/// [`resolve_pinned_blocking`], so holding one of these is proof the check ran.
/// `addrs` is never empty: a literal-IP host pins its own (checked) address and
/// the URL's port, so a caller that hands the list to a custom resolver (ureq's
/// `AgentBuilder::resolver`) works the same for a literal IP as for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    host: String,
    addrs: Vec<SocketAddr>,
}

impl Destination {
    /// Sort, dedupe and check `addrs`; refuse unless there is at least one and
    /// EVERY one is public.
    fn checked(host: String, mut addrs: Vec<SocketAddr>) -> Result<Self, GuardError> {
        addrs.sort_unstable();
        addrs.dedup();
        if addrs.is_empty() {
            return Err(GuardError::new("host resolved to no addresses"));
        }
        for addr in &addrs {
            ensure_public_ip(addr.ip())?;
        }
        Ok(Self { host, addrs })
    }

    /// The URL's host, as it must be sent in `Host:`/SNI.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The checked socket addresses the connection is pinned to. Never empty.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// A [`reqwest::ClientBuilder`] pinned to this destination and hardened for
    /// outbound fetches of untrusted URLs: DNS is overridden to the addresses
    /// already checked (so the connection cannot land anywhere else, and no
    /// second resolution can return a different answer), redirects are refused
    /// (a 302 from an approved host must not bounce the request to an internal
    /// address), and proxies are ignored (a proxy would defeat the pin).
    ///
    /// The caller adds its own timeouts and headers. Build a fresh client per
    /// attempt so the resolve-and-check is redone on every retry.
    pub fn client_builder(&self) -> reqwest::ClientBuilder {
        // reqwest connects to a literal-IP host without resolving it, so for
        // one the override goes unused.
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(&self.host, &self.addrs)
    }
}

/// What is left to do for a URL that passed [`check_url`].
enum Pending {
    /// A literal-IP host: already checked, nothing to resolve.
    Literal(Destination),
    /// A domain name that must be resolved, then checked.
    Lookup { host: String, port: u16 },
}

impl Pending {
    fn of(url: &Url) -> Result<Self, GuardError> {
        check_url(url)?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| GuardError::new("URL must include a valid port"))?;
        let literal = |ip: IpAddr| {
            Destination::checked(ip.to_string(), vec![SocketAddr::new(ip, port)]).map(Self::Literal)
        };
        match url.host() {
            Some(url::Host::Domain(host)) => Ok(Self::Lookup {
                host: host.to_owned(),
                port,
            }),
            Some(url::Host::Ipv4(ip)) => literal(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => literal(IpAddr::V6(ip)),
            None => Err(GuardError::new("URL must include a host")),
        }
    }
}

/// Resolve `url`'s host and refuse it unless EVERY resolved address is public.
///
/// This is the DNS-rebinding defense and the load-bearing half of the guard:
/// call it immediately before each request (including each retry), then build
/// the client from the returned [`Destination`] so the connection is pinned to
/// the addresses that were actually checked.
///
/// Every address must pass — not merely one — so a hostname answering with a
/// mix of a public and an internal address is refused outright rather than
/// racing on which one the connector picks. Resolution is bounded by
/// [`DNS_TIMEOUT`].
pub async fn resolve_pinned(url: &Url) -> Result<Destination, GuardError> {
    match Pending::of(url)? {
        Pending::Literal(destination) => Ok(destination),
        Pending::Lookup { host, port } => {
            let addrs =
                lookup_within(tokio::net::lookup_host((host.as_str(), port)), DNS_TIMEOUT).await?;
            Destination::checked(host, addrs)
        }
    }
}

/// [`resolve_pinned`] for synchronous callers (a ureq client, a wasmtime host
/// import): the same checks and the same [`DNS_TIMEOUT`], resolving with the
/// system resolver (`std::net::ToSocketAddrs`) instead of tokio. Pin the
/// client to the result, for ureq
/// `.resolver(move |_| Ok(destination.addrs().to_vec()))`.
///
/// The lookup runs on its own thread so it can be abandoned at the timeout; a
/// lookup that outlives it finishes (or fails) in the background and its
/// answer is dropped.
pub fn resolve_pinned_blocking(url: &Url) -> Result<Destination, GuardError> {
    match Pending::of(url)? {
        Pending::Literal(destination) => Ok(destination),
        Pending::Lookup { host, port } => {
            let lookup_host = host.clone();
            let addrs = lookup_blocking_within(
                move || Ok((lookup_host.as_str(), port).to_socket_addrs()?.collect()),
                DNS_TIMEOUT,
            )?;
            Destination::checked(host, addrs)
        }
    }
}

/// Await a DNS lookup, refusing it if it fails or takes longer than `timeout`.
async fn lookup_within<I>(
    lookup: impl Future<Output = io::Result<I>>,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, GuardError>
where
    I: Iterator<Item = SocketAddr>,
{
    match tokio::time::timeout(timeout, lookup).await {
        Err(_) => Err(timed_out(timeout)),
        Ok(Err(e)) => Err(GuardError::new(format!("DNS resolution failed: {e}"))),
        Ok(Ok(addrs)) => Ok(addrs.collect()),
    }
}

/// Run a blocking DNS lookup on its own thread, refusing it if it fails or
/// takes longer than `timeout`.
fn lookup_blocking_within(
    lookup: impl FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, GuardError> {
    let (answer, answered) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("outbound-guard-dns".to_owned())
        .spawn(move || {
            // The receiver is gone once the caller has timed out; nothing to do.
            let _ = answer.send(lookup());
        })
        .map_err(|e| GuardError::new(format!("DNS resolution failed: no resolver thread: {e}")))?;
    match answered.recv_timeout(timeout) {
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(e)) => Err(GuardError::new(format!("DNS resolution failed: {e}"))),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(timed_out(timeout)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(GuardError::new(
            "DNS resolution failed: the resolver thread panicked",
        )),
    }
}

fn timed_out(timeout: Duration) -> GuardError {
    GuardError::new(format!("DNS resolution timed out after {timeout:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn rejects_private_loopback_linklocal_and_cgnat() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.5",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
        ] {
            assert!(
                ensure_public_ip(v4(ip)).is_err(),
                "{ip} must be refused as non-public"
            );
        }
    }

    /// The ranges granite's old DENYLIST omitted — the concrete reason this is
    /// an allowlist. Each of these passed the denylist and would have been
    /// fetched.
    #[test]
    fn rejects_the_ranges_a_denylist_forgets() {
        for ip in [
            "192.0.0.1",       // IETF protocol assignments 192.0.0.0/24
            "192.0.2.5",       // TEST-NET-1
            "192.88.99.1",     // 6to4 relay anycast
            "198.18.0.1",      // benchmarking 198.18.0.0/15
            "198.19.255.254",  // benchmarking, upper half
            "198.51.100.7",    // TEST-NET-2
            "203.0.113.7",     // TEST-NET-3
            "224.0.0.1",       // multicast
            "239.255.255.250", // multicast (SSDP)
            "240.0.0.1",       // reserved
            "255.255.255.255", // broadcast
        ] {
            assert!(
                ensure_public_ip(v4(ip)).is_err(),
                "{ip} must be refused as non-public"
            );
        }
        assert!(
            ensure_public_ip(v6("2001:db8::1")).is_err(),
            "the 2001:db8::/32 documentation prefix must be refused"
        );
    }

    #[test]
    fn rejects_non_public_ipv6_including_mapped_v4() {
        for ip in [
            "::1",
            "::",
            "fc00::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "::169.254.169.254",  // v4-compatible
            "64:ff9b::a9fe:a9fe", // NAT64 of 169.254.169.254
            "64:ff9b::808:808",   // NAT64 of a public v4: still refused
            "2001:db8::1",
        ] {
            assert!(
                ensure_public_ip(v6(ip)).is_err(),
                "{ip} must be refused as non-public"
            );
        }
    }

    /// Prefixes inside `2000::/3` that are not ordinary unicast destinations.
    /// 6to4 and Teredo embed an IPv4 address, so accepting them would let a v4
    /// range back in through a relay.
    #[test]
    fn rejects_6to4_and_the_ietf_protocol_assignment_block() {
        for ip in [
            "2002::1",
            "2002:a9fe:a9fe::",       // 6to4 of 169.254.169.254
            "2002:ffff:ffff:ffff::1", // top of 2002::/16
            "2001::1",                // Teredo 2001::/32
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:2::1",   // benchmarking 2001:2::/48
            "2001:10::1",  // ORCHID
            "2001:1ff::1", // top of 2001::/23
        ] {
            assert!(
                ensure_public_ip(v6(ip)).is_err(),
                "{ip} must be refused as non-public"
            );
        }
        for ip in ["2001:200::1", "2003::1", "2001:4860:4860::8888"] {
            assert!(
                ensure_public_ip(v6(ip)).is_ok(),
                "{ip} is just outside and must be accepted"
            );
        }
    }

    #[test]
    fn accepts_ordinary_public_addresses() {
        for ip in ["1.1.1.1", "8.8.8.8", "172.32.0.1", "100.128.0.1"] {
            assert!(ensure_public_ip(v4(ip)).is_ok(), "{ip} must be accepted");
        }
        for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(ensure_public_ip(v6(ip)).is_ok(), "{ip} must be accepted");
        }
    }

    #[test]
    fn url_policy_requires_https_a_host_and_no_userinfo() {
        assert!(validate_url("https://example.com/hook").is_ok());
        assert!(validate_url("http://example.com/hook").is_err());
        assert!(validate_url("ftp://example.com/hook").is_err());
        assert!(validate_url("not a url").is_err());
        assert!(validate_url("https://user:pass@example.com/x").is_err());
        assert!(validate_url("https://user@example.com/x").is_err());
    }

    /// A literal-IP host is judged without DNS — including the hex-octal
    /// disguises WHATWG parsing normalizes first.
    #[test]
    fn url_policy_rejects_internal_literal_hosts() {
        for raw in [
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/x",
            "https://[::ffff:169.254.169.254]/x",
            "https://10.0.0.5/x",
            "https://0x7f.0.0.1/x",
            "https://203.0.113.7/x",
            "https://[::169.254.169.254]/x",
            "https://[64:ff9b::a9fe:a9fe]/x",
            "https://[2002:a9fe:a9fe::]/x",
            "https://[2001::a9fe:a9fe]/x",
        ] {
            let err = validate_url(raw).expect_err("an internal literal host must be refused");
            assert!(
                err.to_string().contains("non-public"),
                "{raw} must be refused by the public-address guard, got: {err}"
            );
        }
    }

    /// A literal-IP host is pinned to itself and the URL's port, by both
    /// resolvers, so a custom resolver handed `addrs()` (ureq's) never gets an
    /// empty list.
    #[tokio::test]
    async fn a_literal_public_ip_pins_itself_and_the_port() {
        for (raw, host, pin) in [
            (
                "https://1.1.1.1/x",
                "1.1.1.1",
                SocketAddr::from(([1, 1, 1, 1], 443)),
            ),
            (
                "https://[2606:4700:4700::1111]:8443/x",
                "2606:4700:4700::1111",
                SocketAddr::new(v6("2606:4700:4700::1111"), 8443),
            ),
        ] {
            let url = validate_url(raw).unwrap();
            for destination in [
                resolve_pinned(&url).await.unwrap(),
                resolve_pinned_blocking(&url).unwrap(),
            ] {
                assert_eq!(destination.host(), host);
                assert_eq!(destination.addrs(), [pin], "{raw}");
            }
        }
    }

    /// A name's answer is pinned whole: sorted, deduped, every address kept.
    /// Stubbed, since the one name every box resolves (`localhost`) is
    /// refused by policy.
    #[test]
    fn a_blocking_lookup_returns_its_answer_and_pins_it() {
        let answer = vec![
            SocketAddr::from(([8, 8, 8, 8], 443)),
            SocketAddr::from(([1, 1, 1, 1], 443)),
            SocketAddr::from(([8, 8, 8, 8], 443)),
        ];
        let stub = answer.clone();
        let addrs = lookup_blocking_within(move || Ok(stub), DNS_TIMEOUT).unwrap();
        assert_eq!(addrs, answer);
        let destination = Destination::checked("app.example".to_owned(), addrs).unwrap();
        assert_eq!(
            destination.addrs(),
            [
                SocketAddr::from(([1, 1, 1, 1], 443)),
                SocketAddr::from(([8, 8, 8, 8], 443)),
            ],
            "sorted, deduped, every address kept"
        );
    }

    #[test]
    fn a_name_answering_with_any_internal_address_is_refused() {
        let mixed = vec![
            SocketAddr::from(([8, 8, 8, 8], 443)),
            SocketAddr::from(([169, 254, 169, 254], 443)),
        ];
        assert!(Destination::checked("app.example".to_owned(), mixed).is_err());
        assert!(Destination::checked("app.example".to_owned(), Vec::new()).is_err());
    }

    /// THE POINT OF THE CRATE. `localhost` is a DOMAIN, so it survives every
    /// syntactic check — nothing about the URL is internal-looking. Only the
    /// resolve step catches it. A real loopback listener stands behind it: the
    /// guard must refuse BEFORE any connection, so the listener sees nothing.
    ///
    /// This is the exact shape of a rebinding attack (`evil.example.com` with a
    /// 0-TTL A record pointing at 169.254.169.254), reproduced hermetically
    /// with the one hostname every machine resolves to an internal address.
    #[tokio::test]
    async fn refuses_a_hostname_that_resolves_to_an_internal_address() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().unwrap().port();
        let accepted: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                *counter.lock().unwrap() += 1;
            }
        });

        let url = validate_url(&format!("https://localhost:{port}/hook"))
            .expect("a hostname passes every syntactic check — that is the danger");
        let err = resolve_pinned(&url)
            .await
            .expect_err("a hostname resolving to loopback must be refused");
        assert!(
            err.to_string().contains("non-public"),
            "the resolve step must be what rejects it, got: {err}"
        );
        assert_eq!(
            *accepted.lock().unwrap(),
            0,
            "the guard must refuse BEFORE connecting — the listener saw nothing"
        );
    }

    /// A resolver that never answers is refused once the timeout passes, rather
    /// than stalling the caller.
    #[tokio::test]
    async fn a_lookup_that_never_answers_times_out() {
        let never = std::future::pending::<io::Result<std::vec::IntoIter<SocketAddr>>>();
        let err = lookup_within(never, Duration::from_millis(20))
            .await
            .expect_err("a hung lookup must be refused");
        assert!(err.to_string().contains("timed out"), "got: {err}");
    }

    /// The blocking resolver catches the same rebinding shape: `localhost`
    /// passes every syntactic check and is refused only once resolved.
    #[test]
    fn blocking_refuses_a_hostname_that_resolves_to_an_internal_address() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = validate_url(&format!("https://localhost:{port}/hook")).unwrap();
        let err = resolve_pinned_blocking(&url)
            .expect_err("a hostname resolving to loopback must be refused");
        assert!(err.to_string().contains("non-public"), "got: {err}");
        assert!(
            listener.accept().is_err(),
            "the guard must refuse BEFORE connecting — the listener saw nothing"
        );
    }

    #[test]
    fn a_blocking_lookup_that_never_answers_times_out() {
        let started = std::time::Instant::now();
        let err = lookup_blocking_within(
            || {
                thread::sleep(Duration::from_secs(5));
                Ok(Vec::new())
            },
            Duration::from_millis(20),
        )
        .expect_err("a hung lookup must be refused");
        assert!(err.to_string().contains("timed out"), "got: {err}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "it must not wait for the lookup"
        );
    }

    #[test]
    fn a_blocking_lookup_failure_is_refused() {
        let err = lookup_blocking_within(|| Err(io::Error::other("NXDOMAIN")), DNS_TIMEOUT)
            .expect_err("a failed lookup must be refused");
        assert!(err.to_string().contains("NXDOMAIN"), "got: {err}");
    }

    /// The pinned builder actually produces a usable client, and the pin is
    /// recorded for the resolved host.
    #[tokio::test]
    async fn a_passing_destination_builds_a_pinned_client() {
        let destination = Destination {
            host: "app.example".to_owned(),
            addrs: vec![SocketAddr::from(([93, 184, 216, 34], 443))],
        };
        assert_eq!(destination.addrs().len(), 1);
        destination
            .client_builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("the guarded builder produces a client");
    }
}
