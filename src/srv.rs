//! DNS `SRV` lookup for `mongodb+srv://` connection strings.
//!
//! MongoDB's [`mongodb+srv` URI scheme] resolves a single hostname into a
//! list of `host:port` pairs by querying `_mongodb._tcp.<hostname>` for
//! `SRV` records. Drivers use this to discover every member of a sharded
//! cluster or replica set without baking the topology into the URI.
//!
//! The proxy only ever forwards to a *single* upstream, so [`resolve`]
//! returns every SRV record and [`Proxy::from_srv`](crate::Proxy::from_srv)
//! picks the first one. The built-in
//! [`RewriteHelloLayer`](crate::RewriteHelloLayer) strips the topology
//! fields from `hello` replies, so the client driver classifies the
//! upstream as a `Standalone` and keeps every request on the proxy socket
//! rather than dialling the other replica-set members directly. See the
//! module docs on [`rewrite_hello`](crate::serve::rewrite_hello) for the
//! full rationale.
//!
//! ## What's *not* implemented
//!
//! The MongoDB SRV spec also defines a `TXT` lookup at the same hostname
//! that carries driver-side connection options (`authSource`,
//! `replicaSet`, `loadBalanced`). The proxy is wire-level and doesn't
//! act on those options, so the TXT lookup is skipped — pass any such
//! options through to the upstream in the client's connection string
//! instead.
//!
//! [`mongodb+srv` URI scheme]: https://www.mongodb.com/docs/manual/reference/connection-string/#dns-seed-list-connection-format

use hickory_resolver::{TokioResolver, proto::rr::RData};

/// One resolved SRV target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvHost {
    /// Hostname the SRV record points at (trailing `.` stripped).
    pub host: String,
    /// Port the SRV record advertises.
    pub port: u16,
}

/// Raw SRV record as returned by the resolver, before any domain
/// validation or trailing-dot normalisation.
///
/// Internal-only; used as the boundary between `resolve` and the
/// underlying [`SrvLookup`] so the lookup itself can be mocked in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawSrvRecord {
    /// SRV target as returned by the resolver (may end with `.`).
    pub target: String,
    /// SRV port.
    pub port: u16,
    /// SRV priority. Lower values are preferred; records are probed in
    /// ascending priority order per RFC 2782.
    pub priority: u16,
    /// SRV weight. Used to proportionally randomise the order of records
    /// that share the same priority per RFC 2782.
    pub weight: u16,
}

/// Opaque DNS lookup failure surfaced by the SRV-lookup backend.
///
/// Held by [`SrvResolveError::Lookup`] so callers can inspect the chain
/// via [`std::error::Error::source`] without [`srv`](self) leaking
/// `hickory_*` types into its public API.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct LookupFailure {
    message: String,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl LookupFailure {
    pub(crate) fn new(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Synthetic failure used by tests; production code should always
    /// pair the message with the underlying error via [`new`](Self::new).
    #[cfg(test)]
    pub(crate) fn synthetic(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }
}

/// Failure modes for [`resolve`].
#[derive(Debug, thiserror::Error)]
pub enum SrvResolveError {
    /// The OS-level resolver configuration (`/etc/resolv.conf` on Unix,
    /// the registry on Windows) could not be read or parsed.
    #[error("failed to initialise DNS resolver: {0}")]
    ResolverInit(#[source] LookupFailure),
    /// The `_mongodb._tcp.<hostname>` SRV query itself failed: `NXDOMAIN`,
    /// timeout, network failure, malformed response, etc.
    #[error("SRV lookup for `_mongodb._tcp.{hostname}` failed: {source}")]
    Lookup {
        /// The original hostname passed to [`resolve`].
        hostname: String,
        /// Underlying resolver error.
        #[source]
        source: LookupFailure,
    },
    /// The SRV query succeeded but returned zero usable records.
    #[error("SRV lookup for `_mongodb._tcp.{hostname}` returned no records")]
    NoRecords {
        /// The original hostname passed to [`resolve`].
        hostname: String,
    },
    /// An SRV record targeted a host outside the parent domain of the
    /// queried hostname. Matches the
    /// [Initial DNS Seedlist Discovery spec] rule: every returned host
    /// must share the original hostname's parent domain.
    ///
    /// [Initial DNS Seedlist Discovery spec]: https://github.com/mongodb/specifications/blob/master/source/initial-dns-seedlist-discovery/initial-dns-seedlist-discovery.md
    #[error(
        "SRV record target `{target}` for `{hostname}` is outside the parent domain `{parent}`"
    )]
    DomainMismatch {
        /// The original hostname passed to [`resolve`].
        hostname: String,
        /// The parent domain derived from `hostname`.
        parent: String,
        /// The offending SRV target.
        target: String,
    },
    /// SRV records all resolved, but none of the returned hosts
    /// responded as the replica-set primary within the per-host probe
    /// timeout. The proxy is single-upstream — without a primary it
    /// can't safely forward writes (a secondary would reject anything
    /// without an explicit `secondaryOk` flag the driver only sets when
    /// it knows it's talking to a replica set, which the
    /// [`RewriteHelloLayer`](crate::RewriteHelloLayer) deliberately
    /// hides).
    ///
    /// `attempts` pairs every probed host with the reason it was rejected
    /// (a [`ProbeOutcome`](crate::ProbeOutcome)) so an operator can tell apart "every host
    /// refused the TCP connect" (network policy), "the TLS handshake
    /// failed everywhere" (cert / SNI), and "every host answered but none
    /// is primary" (an election in progress). The
    /// [`Failed`](crate::ProbeOutcome::Failed) variant keeps the
    /// underlying [`ProbeError`](crate::ProbeError) chain — and through it
    /// the `io::Error` / TLS error — reachable via
    /// [`std::error::Error::source`].
    #[error(
        "no primary found among {} SRV-resolved hosts for `{hostname}` ({})",
        attempts.len(),
        summarise_attempts(attempts)
    )]
    NoPrimary {
        /// The original hostname passed to [`resolve`].
        hostname: String,
        /// Every probed host paired with why it was rejected, in
        /// probe-completion order. `attempts.len()` is the number of
        /// hosts tried.
        attempts: Vec<(SrvHost, crate::serve::probe::ProbeOutcome)>,
    },
}

/// Renders the per-host probe outcomes into a compact, single-line
/// summary for [`SrvResolveError::NoPrimary`]'s `Display`, e.g.
/// `a:27017 timed out; b:27017 responded as a non-primary member`. The
/// structured `attempts` field stays available for callers that want to
/// inspect each [`ProbeOutcome`](crate::serve::probe::ProbeOutcome)
/// programmatically.
pub(crate) fn summarise_attempts(
    attempts: &[(SrvHost, crate::serve::probe::ProbeOutcome)],
) -> String {
    if attempts.is_empty() {
        return "no hosts probed".to_owned();
    }
    attempts
        .iter()
        .map(|(host, outcome)| format!("{}:{} {outcome}", host.host, host.port))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Performs the underlying DNS SRV query.
///
/// Extracted from [`resolve`] purely to make the parser, domain-mismatch
/// rule, and trailing-dot normalisation in [`resolve_with`] unit-testable
/// without touching the network. The single production impl is
/// [`HickorySrvLookup`].
#[cfg_attr(test, mockall::automock)]
pub(crate) trait SrvLookup: Send + Sync {
    /// Looks up SRV records for `query` (the *full* DNS name including
    /// the `_mongodb._tcp.` prefix) and returns every SRV-typed answer.
    ///
    /// Non-SRV records in the response (e.g. `CNAME` chains the resolver
    /// included as additionals) must already be filtered out by the
    /// implementation. The returned `target` strings may still carry a
    /// trailing `.`; normalising that is the caller's job.
    async fn lookup(&self, query: String) -> Result<Vec<RawSrvRecord>, LookupFailure>;
}

/// Production [`SrvLookup`] backed by `hickory-resolver`'s
/// [`TokioResolver`].
pub(crate) struct HickorySrvLookup {
    resolver: TokioResolver,
}

impl HickorySrvLookup {
    /// Builds a resolver from the OS-level configuration
    /// (`/etc/resolv.conf` on Unix, registry on Windows).
    pub(crate) fn from_system_config() -> Result<Self, LookupFailure> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| LookupFailure::new("read system DNS config", e))?
            .build()
            .map_err(|e| LookupFailure::new("build DNS resolver", e))?;
        Ok(Self { resolver })
    }
}

impl SrvLookup for HickorySrvLookup {
    async fn lookup(&self, query: String) -> Result<Vec<RawSrvRecord>, LookupFailure> {
        let lookup = self
            .resolver
            .srv_lookup(query.as_str())
            .await
            .map_err(|e| LookupFailure::new("srv_lookup", e))?;

        Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| {
                let RData::SRV(srv) = &record.data else {
                    return None;
                };
                Some(RawSrvRecord {
                    target: srv.target.to_utf8(),
                    port: srv.port,
                    priority: srv.priority,
                    weight: srv.weight,
                })
            })
            .collect())
    }
}

/// Uniform randomness source for the RFC 2782 weighted SRV ordering.
///
/// Abstracted behind a trait so [`order_by_priority_weight`] can be
/// exercised deterministically in unit tests with a scripted RNG, while
/// production uses the entropy-seeded [`SplitMix64`].
pub(crate) trait WeightedRng {
    /// Returns a uniformly distributed value in `[0, max]` (inclusive).
    fn gen_range_inclusive(&mut self, max: u32) -> u32;
}

/// Tiny, dependency-free [`SplitMix64`] PRNG seeded from process entropy.
///
/// SRV weighted-shuffling needs only a cheap per-process random source —
/// not a cryptographic one — so rather than take a `rand` dependency we
/// seed [`SplitMix64`] from [`RandomState`], whose hasher keys are
/// randomised per process by the standard library.
pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seeds from [`RandomState`]: hashing the empty input yields a value
    /// derived purely from the process-random hasher keys.
    fn from_entropy() -> Self {
        use std::hash::{BuildHasher, Hasher, RandomState};
        Self {
            state: RandomState::new().build_hasher().finish(),
        }
    }

    /// Deterministic seed for unit tests that assert the PRNG sequence.
    #[cfg(test)]
    fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl WeightedRng for SplitMix64 {
    fn gen_range_inclusive(&mut self, max: u32) -> u32 {
        if max == 0 {
            return 0;
        }
        // `% (max + 1)` lands in `[0, max]`; the result is < 2^32 so the
        // truncating cast is lossless. A small modulo bias is acceptable
        // for weighted load distribution.
        (self.next_u64() % (u64::from(max) + 1)) as u32
    }
}

/// Orders SRV records per RFC 2782 / the [Initial DNS Seedlist Discovery
/// spec]: ascending `priority` first, then a weight-proportional shuffle
/// within each equal-priority group.
///
/// The proxy is single-upstream and uses the *first* surviving record,
/// so this ordering decides which host gets probed for the primary first.
/// A custom SRV deployment can therefore steer the proxy toward a
/// preferred region (lower priority) with a fall-back region behind it.
///
/// Against Atlas — where every record is `priority=0 weight=0` — the
/// weighted selection collapses to "keep input order" (every running sum
/// is `0 >= 0`), so the resolver's order is preserved unchanged.
///
/// [Initial DNS Seedlist Discovery spec]: https://github.com/mongodb/specifications/blob/master/source/initial-dns-seedlist-discovery/initial-dns-seedlist-discovery.md
pub(crate) fn order_by_priority_weight<R: WeightedRng>(
    mut records: Vec<RawSrvRecord>,
    rng: &mut R,
) -> Vec<RawSrvRecord> {
    // Stable sort keeps equal-priority records in resolver order before
    // the weighted shuffle reorders them.
    records.sort_by_key(|r| r.priority);

    let mut ordered = Vec::with_capacity(records.len());
    let mut rest = records.into_iter().peekable();
    while let Some(&RawSrvRecord { priority, .. }) = rest.peek() {
        let mut group = Vec::new();
        while rest.peek().is_some_and(|r| r.priority == priority) {
            if let Some(record) = rest.next() {
                group.push(record);
            }
        }
        weighted_shuffle_into(group, rng, &mut ordered);
    }
    ordered
}

/// Applies RFC 2782's weighted-selection algorithm to one equal-priority
/// `group`, appending the result to `out`.
///
/// Repeatedly: place `weight==0` records first, compute the running sum
/// of weights, draw a uniform number in `[0, total]`, and select the
/// first record whose running sum reaches it. When every weight is `0`
/// the draw is always `0` and the first remaining record wins each round,
/// preserving input order.
fn weighted_shuffle_into<R: WeightedRng>(
    mut group: Vec<RawSrvRecord>,
    rng: &mut R,
    out: &mut Vec<RawSrvRecord>,
) {
    while !group.is_empty() {
        // RFC 2782: weight-0 records sort to the front. `false < true`,
        // so this is stable and leaves equal-weight records in order.
        group.sort_by_key(|r| r.weight != 0);

        let total: u32 = group.iter().map(|r| u32::from(r.weight)).sum();
        let pick = rng.gen_range_inclusive(total);

        // `pick <= total`, so the running sum reaches `pick` by the last
        // record at the latest; index 0 is a safe default for the
        // all-zero-weight case where the first record always wins.
        let mut running = 0u32;
        let mut chosen = 0usize;
        for (idx, record) in group.iter().enumerate() {
            running += u32::from(record.weight);
            if running >= pick {
                chosen = idx;
                break;
            }
        }
        out.push(group.remove(chosen));
    }
}

/// Resolves `srv_hostname` via the MongoDB SRV convention.
///
/// Queries `_mongodb._tcp.<srv_hostname>` and returns every advertised
/// `(host, port)` pair. Records are ordered per RFC 2782 — ascending
/// `priority`, weight-randomised within each priority group (see
/// [`order_by_priority_weight`]) — so the first record callers use is the
/// most-preferred reachable target. The proxy is single-upstream, so only
/// the chosen primary among these is ultimately forwarded to.
///
/// The original hostname must have at least two labels (e.g.
/// `cluster.example.com`). Each returned target must share the original
/// hostname's parent domain — targets in an unrelated domain are
/// rejected with [`SrvResolveError::DomainMismatch`].
///
/// # Errors
///
/// See [`SrvResolveError`].
pub async fn resolve(srv_hostname: &str) -> Result<Vec<SrvHost>, SrvResolveError> {
    let lookup = HickorySrvLookup::from_system_config().map_err(SrvResolveError::ResolverInit)?;
    resolve_with(srv_hostname, &lookup).await
}

/// Pure parser/validator over an injected [`SrvLookup`]. All
/// `resolve()` behaviour is implemented here; `resolve()` itself just
/// supplies the real resolver. The test suite exercises every branch
/// of this function with a mocked [`SrvLookup`].
pub(crate) async fn resolve_with<L: SrvLookup + ?Sized>(
    srv_hostname: &str,
    lookup: &L,
) -> Result<Vec<SrvHost>, SrvResolveError> {
    let query = format!("_mongodb._tcp.{srv_hostname}");
    let raw = lookup
        .lookup(query)
        .await
        .map_err(|source| SrvResolveError::Lookup {
            hostname: srv_hostname.to_owned(),
            source,
        })?;

    let raw = order_by_priority_weight(raw, &mut SplitMix64::from_entropy());

    let parent = parent_domain(srv_hostname);

    let mut hosts = Vec::with_capacity(raw.len());
    for record in raw {
        let host = strip_trailing_dot(record.target);
        if !target_in_parent_domain(&host, &parent) {
            return Err(SrvResolveError::DomainMismatch {
                hostname: srv_hostname.to_owned(),
                parent,
                target: host,
            });
        }
        hosts.push(SrvHost {
            host,
            port: record.port,
        });
    }

    if hosts.is_empty() {
        return Err(SrvResolveError::NoRecords {
            hostname: srv_hostname.to_owned(),
        });
    }

    Ok(hosts)
}

fn strip_trailing_dot(mut s: String) -> String {
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Parent domain of `hostname` per the SRV spec: drop the leftmost label
/// when there are 3+ labels, otherwise return the hostname unchanged.
///
/// `cluster0.foo.mongodb.net` → `foo.mongodb.net`
/// `example.com`              → `example.com`
fn parent_domain(hostname: &str) -> String {
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() >= 3 {
        labels[1..].join(".")
    } else {
        hostname.to_owned()
    }
}

/// Returns true if `target`'s parent domain ends with `parent` (i.e.
/// `target` lives somewhere under the registered domain of the queried
/// hostname). Matches the rust driver's `LookupHosts::validate`.
fn target_in_parent_domain(target: &str, parent: &str) -> bool {
    let target_labels: Vec<&str> = target.split('.').collect();
    if target_labels.len() < 2 {
        return false;
    }
    let parent_labels: Vec<&str> = parent.split('.').collect();
    target_labels[1..].ends_with(&parent_labels[..])
}

#[cfg(test)]
mod tests {
    use mockall::predicate::eq;

    use super::*;

    fn raw(target: &str, port: u16) -> RawSrvRecord {
        raw_pw(target, port, 0, 0)
    }

    fn raw_pw(target: &str, port: u16, priority: u16, weight: u16) -> RawSrvRecord {
        RawSrvRecord {
            target: target.to_owned(),
            port,
            priority,
            weight,
        }
    }

    /// Deterministic [`WeightedRng`] that replays a scripted sequence of
    /// values (each clamped into the requested `[0, max]` range) so the
    /// weighted-shuffle ordering can be asserted exactly. Once the script
    /// is exhausted it yields `0`, which selects the first remaining
    /// record.
    struct ScriptedRng {
        values: std::collections::VecDeque<u32>,
    }

    impl ScriptedRng {
        fn new(values: impl IntoIterator<Item = u32>) -> Self {
            Self {
                values: values.into_iter().collect(),
            }
        }
    }

    impl WeightedRng for ScriptedRng {
        fn gen_range_inclusive(&mut self, max: u32) -> u32 {
            self.values.pop_front().unwrap_or(0).min(max)
        }
    }

    fn lookup_returning(records: Vec<RawSrvRecord>) -> MockSrvLookup {
        let mut mock = MockSrvLookup::new();
        mock.expect_lookup().returning(move |_| Ok(records.clone()));
        mock
    }

    // ---------- parent_domain ----------

    #[test]
    fn parent_domain_strips_leftmost_label_when_three_or_more_labels() {
        assert_eq!(parent_domain("cluster0.foo.mongodb.net"), "foo.mongodb.net");
        assert_eq!(parent_domain("a.b.c"), "b.c");
    }

    #[test]
    fn parent_domain_keeps_hostname_when_fewer_than_three_labels() {
        assert_eq!(parent_domain("example.com"), "example.com");
        assert_eq!(parent_domain("localhost"), "localhost");
    }

    // ---------- target_in_parent_domain ----------

    #[test]
    fn target_in_parent_domain_accepts_sibling_under_same_parent() {
        assert!(target_in_parent_domain(
            "cluster0-shard-00-00.foo.mongodb.net",
            "foo.mongodb.net"
        ));
    }

    #[test]
    fn target_in_parent_domain_rejects_unrelated_domain() {
        assert!(!target_in_parent_domain(
            "evil.attacker.com",
            "foo.mongodb.net"
        ));
    }

    #[test]
    fn target_in_parent_domain_rejects_bare_target() {
        assert!(!target_in_parent_domain("localhost", "example.com"));
    }

    #[test]
    fn target_in_parent_domain_accepts_deeper_subdomain() {
        assert!(target_in_parent_domain(
            "a.b.foo.mongodb.net",
            "foo.mongodb.net"
        ));
    }

    // ---------- strip_trailing_dot ----------

    #[test]
    fn strip_trailing_dot_removes_single_trailing_dot() {
        assert_eq!(
            strip_trailing_dot("host.example.com.".into()),
            "host.example.com"
        );
    }

    #[test]
    fn strip_trailing_dot_leaves_undotted_string_alone() {
        assert_eq!(
            strip_trailing_dot("host.example.com".into()),
            "host.example.com"
        );
    }

    #[test]
    fn strip_trailing_dot_only_strips_one_dot() {
        assert_eq!(strip_trailing_dot("host..".into()), "host.");
    }

    // ---------- resolve_with: happy paths ----------

    #[tokio::test]
    async fn resolve_returns_single_record_with_trailing_dot_stripped() {
        let lookup = lookup_returning(vec![raw("cluster0-shard-00-00.foo.mongodb.net.", 27017)]);

        let hosts = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .expect("ok");

        assert_eq!(
            hosts,
            vec![SrvHost {
                host: "cluster0-shard-00-00.foo.mongodb.net".into(),
                port: 27017,
            }]
        );
    }

    #[tokio::test]
    async fn resolve_preserves_record_order_for_multi_host_replica_set() {
        let lookup = lookup_returning(vec![
            raw("cluster0-shard-00-00.foo.mongodb.net.", 27017),
            raw("cluster0-shard-00-01.foo.mongodb.net.", 27018),
            raw("cluster0-shard-00-02.foo.mongodb.net.", 27019),
        ]);

        let hosts = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .expect("ok");

        let ports: Vec<u16> = hosts.iter().map(|h| h.port).collect();
        assert_eq!(ports, vec![27017, 27018, 27019]);
        assert!(
            hosts
                .iter()
                .all(|h| h.host.ends_with(".foo.mongodb.net") && !h.host.ends_with('.'))
        );
    }

    #[tokio::test]
    async fn resolve_accepts_target_without_trailing_dot() {
        let lookup = lookup_returning(vec![raw("host.foo.mongodb.net", 27017)]);

        let hosts = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .expect("ok");

        assert_eq!(hosts[0].host, "host.foo.mongodb.net");
    }

    #[tokio::test]
    async fn resolve_passes_full_underscore_prefixed_query_to_resolver() {
        let mut lookup = MockSrvLookup::new();
        lookup
            .expect_lookup()
            .with(eq(String::from("_mongodb._tcp.cluster0.foo.mongodb.net")))
            .returning(|_| Ok(vec![raw("host.foo.mongodb.net.", 27017)]));

        let _ = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .expect("ok");
    }

    // ---------- resolve_with: error paths ----------

    #[tokio::test]
    async fn resolve_propagates_lookup_failure_with_hostname_context() {
        let mut lookup = MockSrvLookup::new();
        lookup
            .expect_lookup()
            .returning(|_| Err(LookupFailure::synthetic("nxdomain")));

        let err = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .unwrap_err();

        match err {
            SrvResolveError::Lookup { hostname, .. } => {
                assert_eq!(hostname, "cluster0.foo.mongodb.net");
            }
            other => panic!("expected Lookup, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_returns_no_records_when_lookup_returns_empty_vec() {
        let lookup = lookup_returning(vec![]);

        let err = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .unwrap_err();

        match err {
            SrvResolveError::NoRecords { hostname } => {
                assert_eq!(hostname, "cluster0.foo.mongodb.net");
            }
            other => panic!("expected NoRecords, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_rejects_record_in_unrelated_domain() {
        let lookup = lookup_returning(vec![raw("evil.attacker.com.", 27017)]);

        let err = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .unwrap_err();

        match err {
            SrvResolveError::DomainMismatch {
                hostname,
                parent,
                target,
            } => {
                assert_eq!(hostname, "cluster0.foo.mongodb.net");
                assert_eq!(parent, "foo.mongodb.net");
                assert_eq!(target, "evil.attacker.com");
            }
            other => panic!("expected DomainMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_rejects_record_pointing_just_outside_parent_domain() {
        // `mongodb.net` is one label *above* the parent `foo.mongodb.net`,
        // so it must still be rejected even though it overlaps suffixes.
        let lookup = lookup_returning(vec![raw("other.mongodb.net.", 27017)]);

        let err = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .unwrap_err();

        assert!(matches!(err, SrvResolveError::DomainMismatch { .. }));
    }

    #[tokio::test]
    async fn resolve_short_hostname_uses_whole_hostname_as_parent_domain() {
        // hostname has only 2 labels -> parent is the hostname itself.
        // Target must therefore live under `example.com`.
        let lookup = lookup_returning(vec![raw("host.example.com.", 27017)]);

        let hosts = resolve_with("example.com", &lookup).await.expect("ok");
        assert_eq!(hosts[0].host, "host.example.com");
    }

    #[tokio::test]
    async fn resolve_rejects_first_bad_record_even_when_later_records_would_be_valid() {
        let lookup = lookup_returning(vec![
            raw("evil.attacker.com.", 27017),
            raw("good.foo.mongodb.net.", 27018),
        ]);

        let err = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .unwrap_err();

        match err {
            SrvResolveError::DomainMismatch { target, .. } => {
                assert_eq!(target, "evil.attacker.com");
            }
            other => panic!("expected DomainMismatch, got {other:?}"),
        }
    }

    // ---------- order_by_priority_weight: priority ----------

    fn ports(records: &[RawSrvRecord]) -> Vec<u16> {
        records.iter().map(|r| r.port).collect()
    }

    #[test]
    fn order_sorts_by_priority_ascending() {
        // Records arrive out of priority order; lower priority must win.
        let mut rng = ScriptedRng::new([]);
        let ordered = order_by_priority_weight(
            vec![
                raw_pw("c.example.com", 3, 2, 0),
                raw_pw("a.example.com", 1, 0, 0),
                raw_pw("b.example.com", 2, 1, 0),
            ],
            &mut rng,
        );
        assert_eq!(ports(&ordered), vec![1, 2, 3]);
    }

    #[test]
    fn order_preserves_input_order_for_equal_priority_zero_weight() {
        // Atlas case: every record is priority 0 / weight 0, so the
        // weighted shuffle must collapse to "keep resolver order".
        let mut rng = ScriptedRng::new([]);
        let ordered = order_by_priority_weight(
            vec![
                raw_pw("a.example.com", 1, 0, 0),
                raw_pw("b.example.com", 2, 0, 0),
                raw_pw("c.example.com", 3, 0, 0),
            ],
            &mut rng,
        );
        assert_eq!(ports(&ordered), vec![1, 2, 3]);
    }

    // ---------- order_by_priority_weight: weighted shuffle ----------

    #[test]
    fn order_weight_shuffle_selects_first_record_when_draw_is_low() {
        // Two equal-priority weight-1 records, total weight 2. A draw of
        // 1 reaches the first record's running sum, so it is selected.
        let mut rng = ScriptedRng::new([1]);
        let ordered = order_by_priority_weight(
            vec![
                raw_pw("a.example.com", 1, 0, 1),
                raw_pw("b.example.com", 2, 0, 1),
            ],
            &mut rng,
        );
        assert_eq!(ports(&ordered), vec![1, 2]);
    }

    #[test]
    fn order_weight_shuffle_selects_later_record_when_draw_is_high() {
        // A draw of 2 only reaches the second record's running sum, so
        // it is selected first and the order is reversed.
        let mut rng = ScriptedRng::new([2]);
        let ordered = order_by_priority_weight(
            vec![
                raw_pw("a.example.com", 1, 0, 1),
                raw_pw("b.example.com", 2, 0, 1),
            ],
            &mut rng,
        );
        assert_eq!(ports(&ordered), vec![2, 1]);
    }

    #[test]
    fn order_weight_shuffle_gives_zero_weight_record_the_lowest_running_sum() {
        // RFC 2782 places weight-0 records first; with a draw of 0 the
        // weight-0 record (`b`) is selected ahead of the weighted `a`,
        // even though `a` appeared first in the input.
        let mut rng = ScriptedRng::new([0]);
        let ordered = order_by_priority_weight(
            vec![
                raw_pw("a.example.com", 1, 0, 5),
                raw_pw("b.example.com", 2, 0, 0),
            ],
            &mut rng,
        );
        assert_eq!(ordered.first().map(|r| r.port), Some(2));
    }

    #[test]
    fn order_weight_shuffle_is_scoped_within_priority_group() {
        // The weighted reshuffle of the priority-0 pair must not pull the
        // priority-1 record forward: it always trails the lower priority.
        let mut rng = ScriptedRng::new([2]);
        let ordered = order_by_priority_weight(
            vec![
                raw_pw("a.example.com", 1, 0, 1),
                raw_pw("b.example.com", 2, 0, 1),
                raw_pw("c.example.com", 3, 1, 0),
            ],
            &mut rng,
        );
        assert_eq!(ports(&ordered), vec![2, 1, 3]);
    }

    #[test]
    fn order_weight_shuffle_favours_high_weight_records_with_real_rng() {
        // Statistical check over the production entropy RNG: a 9:1 weight
        // ratio should put the heavy record first the large majority of
        // the time. The 70% threshold is well below the ~82% expectation
        // (heavy wins unless the draw is 0 or 1 of 0..=10) to stay
        // non-flaky.
        let trials = 2000;
        let mut heavy_first = 0;
        for _ in 0..trials {
            let ordered = order_by_priority_weight(
                vec![
                    raw_pw("light.example.com", 1, 0, 1),
                    raw_pw("heavy.example.com", 2, 0, 9),
                ],
                &mut SplitMix64::from_entropy(),
            );
            if ordered.first().map(|r| r.port) == Some(2) {
                heavy_first += 1;
            }
        }
        assert!(
            heavy_first > trials * 7 / 10,
            "heavy record won first only {heavy_first}/{trials} times"
        );
    }

    // ---------- SplitMix64 ----------

    #[test]
    fn splitmix_gen_range_respects_bounds() {
        let mut rng = SplitMix64::from_entropy();
        assert_eq!(rng.gen_range_inclusive(0), 0);
        for _ in 0..1000 {
            assert!(rng.gen_range_inclusive(7) <= 7);
        }
    }

    #[test]
    fn splitmix_produces_varied_output() {
        // A fixed seed must still spread across the range rather than
        // getting stuck on a single value.
        let mut rng = SplitMix64::seeded(0x1234_5678_9ABC_DEF0);
        let mut seen_zero = false;
        let mut seen_one = false;
        for _ in 0..200 {
            match rng.gen_range_inclusive(1) {
                0 => seen_zero = true,
                1 => seen_one = true,
                other => panic!("value {other} out of [0, 1]"),
            }
        }
        assert!(seen_zero && seen_one);
    }

    #[test]
    fn splitmix_is_deterministic_for_a_fixed_seed() {
        let mut a = SplitMix64::seeded(42);
        let mut b = SplitMix64::seeded(42);
        for _ in 0..50 {
            assert_eq!(a.gen_range_inclusive(1_000), b.gen_range_inclusive(1_000));
        }
    }

    // ---------- resolve_with: ordering integration ----------

    #[tokio::test]
    async fn resolve_orders_records_by_srv_priority() {
        // End-to-end through resolve_with: the resolver hands back records
        // in priority order 2, 0, 1 and the proxy must reorder them so the
        // lowest-priority (most-preferred) host is probed first. Distinct
        // priorities make this independent of the weighted-shuffle RNG.
        let lookup = lookup_returning(vec![
            raw_pw("c.foo.mongodb.net.", 27019, 2, 0),
            raw_pw("a.foo.mongodb.net.", 27017, 0, 0),
            raw_pw("b.foo.mongodb.net.", 27018, 1, 0),
        ]);

        let hosts = resolve_with("cluster0.foo.mongodb.net", &lookup)
            .await
            .expect("ok");

        let resolved: Vec<(&str, u16)> = hosts.iter().map(|h| (h.host.as_str(), h.port)).collect();
        assert_eq!(
            resolved,
            vec![
                ("a.foo.mongodb.net", 27017),
                ("b.foo.mongodb.net", 27018),
                ("c.foo.mongodb.net", 27019),
            ]
        );
    }
}
