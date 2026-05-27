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
}

/// Opaque DNS lookup failure surfaced by [`SrvLookup`] implementations.
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
                })
            })
            .collect())
    }
}

/// Resolves `srv_hostname` via the MongoDB SRV convention.
///
/// Queries `_mongodb._tcp.<srv_hostname>` and returns every advertised
/// `(host, port)` pair, in the order the resolver delivered them. SRV
/// priority/weight selection is *not* applied: drivers normally connect
/// to every returned host in parallel, but the proxy is single-upstream
/// so the first record is what callers will use.
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
        RawSrvRecord {
            target: target.to_owned(),
            port,
        }
    }

    fn lookup_returning(records: Vec<RawSrvRecord>) -> MockSrvLookup {
        let mut mock = MockSrvLookup::new();
        mock.expect_lookup()
            .returning(move |_| Ok(records.clone()));
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
        assert_eq!(strip_trailing_dot("host.example.com.".into()), "host.example.com");
    }

    #[test]
    fn strip_trailing_dot_leaves_undotted_string_alone() {
        assert_eq!(strip_trailing_dot("host.example.com".into()), "host.example.com");
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
}
