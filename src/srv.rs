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

use std::time::Duration;

use hickory_resolver::{TokioResolver, proto::rr::RData};

/// One resolved SRV target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvHost {
    /// Hostname the SRV record points at (trailing `.` stripped).
    pub host: String,
    /// Port the SRV record advertises.
    pub port: u16,
}

/// Failure modes for [`resolve`].
#[derive(Debug, thiserror::Error)]
pub enum SrvResolveError {
    /// The OS-level resolver configuration (`/etc/resolv.conf` on Unix,
    /// the registry on Windows) could not be read or parsed.
    #[error("failed to initialise DNS resolver: {0}")]
    ResolverInit(hickory_resolver::net::NetError),
    /// The `_mongodb._tcp.<hostname>` SRV query itself failed.
    ///
    /// This wraps every transport / DNS error reported by `hickory`:
    /// `NXDOMAIN`, timeouts, network failures, malformed responses, …
    #[error("SRV lookup for `_mongodb._tcp.{hostname}` failed: {source}")]
    Lookup {
        /// The original hostname passed to [`resolve`].
        hostname: String,
        /// Underlying resolver error.
        #[source]
        source: hickory_resolver::net::NetError,
    },
    /// The SRV query succeeded but returned zero usable records, or every
    /// record was filtered out by the parent-domain check.
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
    let resolver = TokioResolver::builder_tokio()
        .map_err(SrvResolveError::ResolverInit)?
        .build()
        .map_err(SrvResolveError::ResolverInit)?;

    let query = format!("_mongodb._tcp.{srv_hostname}");
    let lookup = resolver
        .srv_lookup(query.as_str())
        .await
        .map_err(|source| SrvResolveError::Lookup {
            hostname: srv_hostname.to_owned(),
            source,
        })?;

    let parent = parent_domain(srv_hostname);

    let mut hosts = Vec::new();
    for record in lookup.answers() {
        let RData::SRV(srv) = &record.data else {
            continue;
        };
        let mut host = srv.target.to_utf8();
        if host.ends_with('.') {
            host.pop();
        }
        if !target_in_parent_domain(&host, &parent) {
            return Err(SrvResolveError::DomainMismatch {
                hostname: srv_hostname.to_owned(),
                parent,
                target: host,
            });
        }
        hosts.push(SrvHost {
            host,
            port: srv.port,
        });
    }

    if hosts.is_empty() {
        return Err(SrvResolveError::NoRecords {
            hostname: srv_hostname.to_owned(),
        });
    }

    Ok(hosts)
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

// Public for use in retry/refresh wrappers built on top of this module.
#[doc(hidden)]
pub const MIN_TTL: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn target_in_parent_domain_accepts_sibling_under_same_parent() {
        // cluster0-shard-00-00.foo.mongodb.net under foo.mongodb.net
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
        // Single-label target has no parent labels to match against.
        assert!(!target_in_parent_domain("localhost", "example.com"));
    }

    #[test]
    fn target_in_parent_domain_accepts_deeper_subdomain() {
        assert!(target_in_parent_domain(
            "a.b.foo.mongodb.net",
            "foo.mongodb.net"
        ));
    }
}
