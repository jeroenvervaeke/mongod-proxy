//! Pick the replica-set primary among SRV-resolved hosts.
//!
//! [`Proxy::from_srv`](crate::Proxy::from_srv) only forwards to a single
//! upstream, but a `mongodb+srv://` SRV record typically returns every
//! member of the replica set (3 nodes for an Atlas free-tier cluster).
//! Picking the first DNS-order host fails the moment that node is a
//! secondary — even a bare `ping` is rejected by the server with
//! `NotPrimaryNoSecondaryOk` because the driver, looking at a
//! [`RewriteHelloLayer`](crate::RewriteHelloLayer)-stripped reply, has
//! no signal that it's talking to a secondary and never sets the
//! wire-level `secondaryOk` flag.
//!
//! The fix here is what every full driver does internally: issue a
//! `hello` probe to each SRV candidate, find the one whose reply
//! reports `isWritablePrimary == true`, and use that node as the
//! upstream. The primary is selected at startup and then kept current
//! by a background loop in [`Proxy::from_srv`] that re-runs this
//! selection periodically (see
//! [`FailoverConfig`](crate::FailoverConfig)), so an Atlas failover
//! swaps the upstream target in place rather than requiring a restart.
//!
//! ## What lives here
//!
//! - [`PrimaryProbe`] — single-host probe trait; the production impl
//!   is [`HelloProbe`], which reuses the proxy's own wire-protocol
//!   [`ProxyClient`](crate::serve::service::ProxyClient) to dial, send
//!   `hello`, and read the reply.
//! - [`select_primary`] — probes every SRV host concurrently under a
//!   caller-supplied per-host timeout (default [`DEFAULT_PROBE_TIMEOUT`])
//!   and returns as soon as one reports itself primary, so selection
//!   converges in single-host latency rather than the sum of per-host
//!   timeouts.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use bson::Document;
use bson::doc;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio_rustls::TlsConnector;
use tower_service::Service;
use tracing::{debug, info};

use crate::ids::RequestId;
use crate::message::Message;
use crate::operation::{
    Operation,
    op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags},
};
use crate::serve::service::{ProxyClient, ProxyClientForwardError, ProxyClientRequestError};

/// Default per-host budget for the dial + `hello` round-trip during
/// primary selection. Hosts that don't reply in time are skipped rather
/// than stalling the proxy startup.
///
/// 5s suits the steady-state Atlas case, but a cold-starting free-tier
/// cluster can take 10-20s to answer its first `hello` and a
/// high-latency international link can exceed 5s on the TLS handshake
/// alone. Callers that talk to such deployments widen the budget via
/// [`FailoverConfig::with_probe_timeout`](crate::FailoverConfig::with_probe_timeout);
/// local-network tests can shorten it to fail fast. The value is plumbed
/// into [`select_primary`] rather than read from this constant directly.
pub(crate) const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Failure modes for a single primary probe.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    /// TCP / TLS connect to the candidate host failed.
    #[error("connect failed: {0}")]
    Connect(#[from] ProxyClientForwardError),
    /// Writing the `hello` request to the candidate's socket failed.
    #[error("hello request failed: {0}")]
    Request(ProxyClientRequestError),
    /// The candidate closed the socket without sending a `hello` reply.
    #[error("upstream closed before sending a hello reply")]
    NoReply,
    /// Reading the `hello` reply from the candidate's socket failed.
    #[error("hello response failed: {0}")]
    Response(ProxyClientRequestError),
    /// The reply is missing both `isWritablePrimary` (modern) and
    /// `ismaster` (legacy) boolean fields, or carries an unexpected
    /// op-code.
    #[error("hello reply has no `isWritablePrimary` / `ismaster` boolean")]
    MalformedReply,
}

/// Why a single SRV candidate was *not* chosen as the primary.
///
/// `select_primary` records one of these per host whenever no host
/// reports itself primary, so the
/// [`NoPrimary`](crate::SrvResolveError::NoPrimary) error returned to the
/// operator can explain *why* each candidate was rejected. The bare
/// attempted-count the proxy used to surface collapsed four very
/// different failures — a refused TCP connect, a TLS handshake error, a
/// healthy secondary, and a probe that never answered — into a single
/// opaque number; an operator could not tell a network-policy problem
/// from an in-progress election from a cert mismatch.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeOutcome {
    /// The host answered `hello` but reported `isWritablePrimary: false`
    /// (a secondary, arbiter, or other non-primary member) — the replica
    /// set is reachable but this node isn't currently the primary.
    #[error("responded as a non-primary member")]
    NotPrimary,
    /// The probe could not complete: the TCP/TLS connect was refused, the
    /// socket closed before a reply arrived, or the `hello` reply was
    /// malformed. The underlying [`ProbeError`] is kept as the error
    /// `source`, so the full `ProbeError` → `ProxyClientForwardError` →
    /// `io::Error` / TLS chain stays inspectable via
    /// [`std::error::Error::source`].
    #[error("probe failed: {0}")]
    Failed(#[from] ProbeError),
    /// The probe did not finish within the per-host timeout budget (see
    /// `DEFAULT_PROBE_TIMEOUT`). The host may simply be cold-starting and
    /// slow to answer its first `hello`.
    #[error("timed out")]
    TimedOut,
}

/// Outcome of probing every SRV candidate in [`select_primary`].
///
/// Either one host won the race by reporting itself primary, or every
/// host settled without one — in which case the per-host
/// [`ProbeOutcome`]s are carried out so the caller can build a
/// diagnostic [`NoPrimary`](crate::SrvResolveError::NoPrimary).
pub(crate) enum Selection {
    /// A candidate reported `isWritablePrimary == true`; it becomes the
    /// upstream.
    Primary(crate::srv::SrvHost),
    /// No candidate did. Carries each probed host paired with the reason
    /// it was rejected, in probe-completion order.
    NoPrimary(Vec<(crate::srv::SrvHost, ProbeOutcome)>),
}

impl Selection {
    /// The selected primary, or `None` when no host qualified.
    ///
    /// Used by the background failover loop, which only needs the winner
    /// and logs its own "kept current target" message on `None` — the
    /// per-host rejection reasons matter only for the *startup* error the
    /// caller surfaces, not for a steady-state re-probe tick.
    pub(crate) fn into_primary(self) -> Option<crate::srv::SrvHost> {
        match self {
            Selection::Primary(host) => Some(host),
            Selection::NoPrimary(_) => None,
        }
    }
}

/// Single-host probe used by [`select_primary`].
///
/// Behind a trait so [`select_primary`]'s iteration / timeout / error
/// handling can be unit-tested with a `mockall`-generated mock — the
/// production [`HelloProbe`] needs a real TCP socket which we can't
/// open in-process.
#[cfg_attr(test, mockall::automock)]
pub(crate) trait PrimaryProbe: Send + Sync {
    /// Returns `Ok(true)` when the candidate's `hello` reply identifies
    /// it as the primary, `Ok(false)` for a secondary / arbiter / other
    /// non-primary node, and `Err` when the probe itself failed (could
    /// not connect, malformed reply, etc.).
    ///
    /// `host` is owned because mockall's `#[automock]` derives most
    /// cleanly over owned arguments — the cost of one `String` clone
    /// per probe is irrelevant against the dial latency that follows.
    async fn is_primary(&self, host: String, port: u16) -> Result<bool, ProbeError>;
}

/// Production [`PrimaryProbe`]. Reuses the proxy's own
/// [`ProxyClient`] to perform the dial + `hello` round-trip, so the
/// probe socket goes through exactly the same TCP/TLS stack the
/// forwarding path will use after selection.
#[derive(Clone)]
pub(crate) struct HelloProbe {
    tls_connector: Option<Arc<TlsConnector>>,
}

impl HelloProbe {
    pub(crate) fn new(tls_connector: Option<Arc<TlsConnector>>) -> Self {
        Self { tls_connector }
    }
}

impl PrimaryProbe for HelloProbe {
    async fn is_primary(&self, host: String, port: u16) -> Result<bool, ProbeError> {
        // One event per branch keeps a 3-host startup readable while still
        // pinning down *where* a probe failed: a refused connect, a TLS
        // handshake error, a dropped socket, and a malformed reply all log
        // distinctly so an operator can tell a network-policy problem from a
        // cert mismatch without reconstructing the `Error::source` chain.
        debug!(host, port, "probing for primary");
        let mut client = ProxyClient::forward_to(host.clone(), port, self.tls_connector.clone())
            .await
            .inspect_err(|e| debug!(host, port, error = %e, "probe connect failed"))?;
        let req = build_hello_request();
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .map_err(|e| {
                debug!(host, port, error = %e, "probe request failed");
                ProbeError::Request(e)
            })?;
        let reply = stream
            .next()
            .await
            .ok_or_else(|| {
                debug!(host, port, "probe got no reply before the socket closed");
                ProbeError::NoReply
            })?
            .map_err(|e| {
                debug!(host, port, error = %e, "probe response failed");
                ProbeError::Response(e)
            })?;
        let Some(is_primary) = extract_is_writable_primary(&reply) else {
            debug!(host, port, "probe reply was malformed");
            return Err(ProbeError::MalformedReply);
        };
        debug!(host, port, is_primary, "probe replied");
        Ok(is_primary)
    }
}

/// Probe every host in `hosts` concurrently, returning as soon as one
/// reports `isWritablePrimary == true`.
///
/// Each probe runs under its own `timeout` budget (see
/// [`DEFAULT_PROBE_TIMEOUT`] for the default and the rationale for tuning
/// it), and they all race in parallel: the first confirmed primary wins
/// and the remaining probes are cancelled (dropped), so selection
/// converges in single-host latency rather than the sum of per-host
/// timeouts. A slow or unreachable replica-set member therefore can't
/// delay startup behind the host that actually answers.
///
/// The budget is per host, not for the whole call: a cold-starting
/// cluster where *every* host is slow at once would still time out at
/// `timeout` per probe (parallelism can't help when nothing answers
/// sooner), so a deployment known to cold-start slowly must widen
/// `timeout` rather than rely on the parallel race.
///
/// Because we keep draining until a primary appears, a primary that
/// merely responds slowly is still found rather than being missed by an
/// early [`NoPrimary`](Selection::NoPrimary); we report no primary only
/// once *every* probe has settled without one.
///
/// On that no-primary path each host is paired with the reason it was
/// rejected — a secondary reply ([`ProbeOutcome::NotPrimary`]), a probe
/// failure ([`ProbeOutcome::Failed`]), or a timeout
/// ([`ProbeOutcome::TimedOut`]) — so the caller can surface *why* startup
/// found no primary rather than just *how many* hosts it tried.
pub(crate) async fn select_primary<P>(
    hosts: &[crate::srv::SrvHost],
    probe: &P,
    timeout: Duration,
) -> Selection
where
    P: PrimaryProbe + ?Sized,
{
    let mut probes: FuturesUnordered<_> = hosts
        .iter()
        .map(|host| async move {
            let outcome =
                tokio::time::timeout(timeout, probe.is_primary(host.host.clone(), host.port)).await;
            (host, outcome)
        })
        .collect();

    let mut rejected = Vec::new();
    while let Some((host, outcome)) = probes.next().await {
        let reason = match outcome {
            // The first confirmed primary wins; remaining probes are
            // dropped, so their (now irrelevant) outcomes are never
            // gathered.
            Ok(Ok(true)) => {
                info!(host = %host.host, port = host.port, "selected primary");
                return Selection::Primary(host.clone());
            }
            Ok(Ok(false)) => ProbeOutcome::NotPrimary,
            Ok(Err(e)) => ProbeOutcome::Failed(e),
            Err(_elapsed) => ProbeOutcome::TimedOut,
        };
        // One rejection event per settled probe — the per-host outcome an
        // operator needs to read a no-primary startup, mirroring the reasons
        // carried in the eventual `NoPrimary`.
        debug!(host = %host.host, port = host.port, reason = %reason, "probe rejected");
        rejected.push((host.clone(), reason));
    }
    Selection::NoPrimary(rejected)
}

/// The `client` sub-document advertised on the primary-probe `hello`.
///
/// Real MongoDB drivers identify themselves on the handshake `hello` so
/// the server can log who's connecting; without it the proxy's probes
/// show up anonymously in Atlas monitoring and server ops logs. We send
/// the same shape a driver does — driver name/version, OS type/arch, and
/// platform — so those probes are attributable to `mongod-proxy`.
///
/// The doc is constant for the life of the process (the version, OS, and
/// arch are all compile-time constants), so it's built once and reused.
fn client_metadata() -> &'static Document {
    static CLIENT_METADATA: OnceLock<Document> = OnceLock::new();
    CLIENT_METADATA.get_or_init(|| {
        doc! {
            "driver": {
                "name": "mongod-proxy",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "os": {
                "type": std::env::consts::OS,
                "architecture": std::env::consts::ARCH,
            },
            "platform": "Rust",
        }
    })
}

/// Builds the `hello` probe sent to each SRV candidate during primary
/// selection.
///
/// Unlike forwarded client `hello`s — which carry the originating
/// driver's own `client` metadata — this probe is issued by the proxy
/// itself, so it attaches [`client_metadata`] to identify `mongod-proxy`
/// as the client. This is observability-only: servers don't reject a
/// probe that omits it.
fn build_hello_request() -> Message {
    Message {
        request_id: RequestId::new(1),
        response_to: None,
        operation: Operation::Message(OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: vec![OpMsgSection::Body(doc! {
                "hello": 1,
                "$db": "admin",
                "client": client_metadata().clone(),
            })],
            checksum: None,
        }),
    }
}

/// Looks for `isWritablePrimary` (modern) or `ismaster` (legacy) in the
/// reply's body section. Either field is canonical per the SDAM spec
/// and equally trustworthy; modern servers send both, very old ones
/// send only `ismaster`.
fn extract_is_writable_primary(msg: &Message) -> Option<bool> {
    let Operation::Message(op_msg) = &msg.operation else {
        return None;
    };
    for section in &op_msg.sections {
        let OpMsgSection::Body(doc) = section else {
            continue;
        };
        if let Ok(v) = doc.get_bool("isWritablePrimary") {
            return Some(v);
        }
        if let Ok(v) = doc.get_bool("ismaster") {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::srv::SrvHost;

    use super::*;

    fn host(name: &str, port: u16) -> SrvHost {
        SrvHost {
            host: name.into(),
            port,
        }
    }

    fn build_hello_reply(is_writable_primary: bool) -> Message {
        Message {
            request_id: RequestId::new(101),
            response_to: None,
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: vec![OpMsgSection::Body(doc! {
                    "isWritablePrimary": is_writable_primary,
                    "maxBsonObjectSize": 16_777_216_i32,
                    "ok": 1.0,
                })],
                checksum: None,
            }),
        }
    }

    // ---------- extract_is_writable_primary ----------

    #[test]
    fn extract_picks_up_modern_is_writable_primary_true() {
        assert_eq!(
            extract_is_writable_primary(&build_hello_reply(true)),
            Some(true)
        );
    }

    #[test]
    fn extract_picks_up_modern_is_writable_primary_false() {
        assert_eq!(
            extract_is_writable_primary(&build_hello_reply(false)),
            Some(false)
        );
    }

    #[test]
    fn extract_falls_back_to_legacy_ismaster_when_modern_field_absent() {
        let msg = Message {
            request_id: RequestId::new(1),
            response_to: None,
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: vec![OpMsgSection::Body(doc! { "ismaster": true, "ok": 1.0 })],
                checksum: None,
            }),
        };
        assert_eq!(extract_is_writable_primary(&msg), Some(true));
    }

    #[test]
    fn extract_returns_none_when_neither_field_present() {
        let msg = Message {
            request_id: RequestId::new(1),
            response_to: None,
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: vec![OpMsgSection::Body(doc! { "ok": 1.0 })],
                checksum: None,
            }),
        };
        assert_eq!(extract_is_writable_primary(&msg), None);
    }

    // ---------- build_hello_request client metadata (#24) ----------

    /// Pull the body section out of the probe request so the assertions
    /// can read the `hello`'s fields directly.
    fn hello_body(msg: &Message) -> &bson::Document {
        let Operation::Message(op_msg) = &msg.operation else {
            panic!("probe request must be an OP_MSG");
        };
        op_msg
            .sections
            .iter()
            .find_map(|section| match section {
                OpMsgSection::Body(doc) => Some(doc),
                _ => None,
            })
            .expect("probe request must have a body section")
    }

    #[test]
    fn build_hello_request_includes_client_metadata() {
        let msg = build_hello_request();
        let body = hello_body(&msg);

        // The bare probe fields stay intact alongside the new client doc.
        assert_eq!(body.get_i32("hello").unwrap(), 1);
        assert_eq!(body.get_str("$db").unwrap(), "admin");

        let client = body
            .get_document("client")
            .expect("probe hello must carry a client sub-document");

        let driver = client
            .get_document("driver")
            .expect("client must carry a driver sub-document");
        assert_eq!(driver.get_str("name").unwrap(), "mongod-proxy");
        assert_eq!(
            driver.get_str("version").unwrap(),
            env!("CARGO_PKG_VERSION"),
            "driver version must be the crate version",
        );
        assert!(
            !driver.get_str("version").unwrap().is_empty(),
            "driver version must be non-empty",
        );

        let os = client
            .get_document("os")
            .expect("client must carry an os sub-document");
        assert_eq!(os.get_str("type").unwrap(), std::env::consts::OS);
        assert!(
            !os.get_str("type").unwrap().is_empty(),
            "os.type must be present and non-empty",
        );
        assert_eq!(os.get_str("architecture").unwrap(), std::env::consts::ARCH);
        assert!(
            !os.get_str("architecture").unwrap().is_empty(),
            "os.architecture must be present and non-empty",
        );

        assert_eq!(client.get_str("platform").unwrap(), "Rust");
    }

    // ---------- select_primary ----------

    #[tokio::test]
    async fn select_primary_returns_first_host_when_it_is_primary() {
        let hosts = vec![host("a", 27017), host("b", 27017), host("c", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|name, _port| Ok(name == "a"));

        let picked = select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
            .await
            .into_primary()
            .expect("primary");
        assert_eq!(picked.host, "a");
    }

    #[tokio::test]
    async fn select_primary_skips_secondaries_to_find_primary() {
        // Atlas's actual SRV-order behaviour: secondaries first, primary
        // last. The probe loop must keep going.
        let hosts = vec![host("a", 27017), host("b", 27017), host("c", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|name, _port| Ok(name == "c"));

        let picked = select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
            .await
            .into_primary()
            .expect("primary");
        assert_eq!(picked.host, "c");
    }

    #[tokio::test]
    async fn select_primary_skips_probe_errors_to_find_primary() {
        // A single unreachable replica-set member must not block
        // startup — fall through to the next candidate.
        let hosts = vec![host("a", 27017), host("b", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe.expect_is_primary().returning(|name, _port| {
            if name == "a" {
                Err(ProbeError::NoReply)
            } else {
                Ok(true)
            }
        });

        let picked = select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
            .await
            .into_primary()
            .expect("primary");
        assert_eq!(picked.host, "b");
    }

    #[tokio::test]
    async fn select_primary_returns_none_when_no_host_is_primary() {
        let hosts = vec![host("a", 27017), host("b", 27017), host("c", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe.expect_is_primary().returning(|_, _| Ok(false));

        assert!(
            select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
                .await
                .into_primary()
                .is_none()
        );
    }

    #[tokio::test]
    async fn select_primary_returns_none_when_every_probe_errors() {
        let hosts = vec![host("a", 27017), host("b", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|_, _| Err(ProbeError::NoReply));

        assert!(
            select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
                .await
                .into_primary()
                .is_none()
        );
    }

    #[tokio::test]
    async fn select_primary_returns_none_for_empty_host_list() {
        let probe = MockPrimaryProbe::new();
        assert!(
            select_primary(&[], &probe, DEFAULT_PROBE_TIMEOUT)
                .await
                .into_primary()
                .is_none()
        );
    }

    // ---------- select_primary parallelism ----------
    //
    // These use a hand-rolled probe (rather than `MockPrimaryProbe`)
    // because mockall's `returning` closure can't `.await` a delay, and
    // run under `start_paused` so virtual time advances deterministically
    // when every task is idle — no wall-clock flakiness.

    /// Probe whose per-host behaviour is keyed off the host name:
    /// - `"primary"` answers `Ok(true)` immediately,
    /// - `"slow-primary"` answers `Ok(true)` only after a long sleep,
    /// - `"hang"` sleeps far past [`DEFAULT_PROBE_TIMEOUT`] before answering,
    /// - anything else is an immediate secondary (`Ok(false)`).
    struct ScriptedProbe;

    impl PrimaryProbe for ScriptedProbe {
        async fn is_primary(&self, host: String, _port: u16) -> Result<bool, ProbeError> {
            match host.as_str() {
                "primary" => Ok(true),
                "slow-primary" => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(true)
                }
                // An Atlas free-tier cluster cold-starting: the host is
                // healthy and is the primary, but doesn't answer its first
                // `hello` until ~8s in — past the 5s default budget.
                "cold-primary" => {
                    tokio::time::sleep(Duration::from_secs(8)).await;
                    Ok(true)
                }
                "hang" => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Ok(false)
                }
                _ => Ok(false),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_probes_concurrently_not_serially() {
        // The primary sits behind a host whose probe would block for an
        // hour. Serial probing would wait `DEFAULT_PROBE_TIMEOUT` on `hang`
        // before ever reaching the primary; parallel probing returns the
        // primary immediately, so no virtual time elapses.
        let hosts = vec![host("hang", 27017), host("primary", 27017)];
        let start = tokio::time::Instant::now();

        let picked = select_primary(&hosts, &ScriptedProbe, DEFAULT_PROBE_TIMEOUT)
            .await
            .into_primary()
            .expect("primary");

        assert_eq!(picked.host, "primary");
        assert!(
            start.elapsed() < DEFAULT_PROBE_TIMEOUT,
            "selection must not wait out the blocked host before returning the primary",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_waits_for_a_slow_primary() {
        // Two fast secondaries settle immediately; the only primary
        // responds slowly. We must keep draining instead of returning
        // `None` after the quick `Ok(false)`s.
        let hosts = vec![
            host("s1", 27017),
            host("s2", 27017),
            host("slow-primary", 27017),
        ];

        let picked = select_primary(&hosts, &ScriptedProbe, DEFAULT_PROBE_TIMEOUT)
            .await
            .into_primary()
            .expect("primary");
        assert_eq!(picked.host, "slow-primary");
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_returns_none_when_every_probe_times_out() {
        // Every host hangs well past DEFAULT_PROBE_TIMEOUT. Each probe's timeout
        // must elapse (`Err(Elapsed)`), be treated as non-primary, and
        // the call must still terminate with `None` rather than awaiting
        // the hour-long sleeps. The paused clock auto-advances to the
        // timeout instant once all tasks are idle.
        let hosts = vec![host("hang", 27017), host("hang", 27018)];

        assert!(
            select_primary(&hosts, &ScriptedProbe, DEFAULT_PROBE_TIMEOUT)
                .await
                .into_primary()
                .is_none()
        );
    }

    // ---------- select_primary configurable per-host timeout (#27) ----------

    #[tokio::test(start_paused = true)]
    async fn select_primary_misses_a_cold_primary_under_the_default_timeout() {
        // Regression for #27: an Atlas free-tier cluster can take 10-20s to
        // answer its first `hello` while it cold-starts, and *every* host is
        // slow at once — so parallel probing (#17) doesn't help. Under the
        // 5s default budget every probe times out and selection falsely
        // reports no primary for a perfectly healthy cluster.
        let hosts = vec![host("cold-primary", 27017)];
        assert!(
            select_primary(&hosts, &ScriptedProbe, DEFAULT_PROBE_TIMEOUT)
                .await
                .into_primary()
                .is_none(),
            "the 5s default is too short to reach a cold-starting primary",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_finds_a_cold_primary_under_a_longer_timeout() {
        // The fix: widening the per-host probe budget lets the same
        // cold-starting primary be selected instead of failing startup.
        let hosts = vec![host("cold-primary", 27017)];
        let picked = select_primary(&hosts, &ScriptedProbe, Duration::from_secs(15))
            .await
            .into_primary()
            .expect("a generous timeout must reach the cold-starting primary");
        assert_eq!(picked.host, "cold-primary");
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_honours_a_tight_per_host_timeout() {
        // The supplied timeout is the per-host budget: a primary answering
        // after it elapses is missed, and the call still terminates promptly
        // rather than waiting out the full 8s probe.
        let hosts = vec![host("cold-primary", 27017)];
        assert!(
            select_primary(&hosts, &ScriptedProbe, Duration::from_secs(3))
                .await
                .into_primary()
                .is_none(),
            "a 3s budget must elapse before the 8s cold primary answers",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_needs_the_budget_to_reach_a_cold_primary_behind_fast_secondaries() {
        // The realistic Atlas-order worst case: the secondaries answer
        // `Ok(false)` instantly, but the actual primary is the cold-starting
        // node that only replies after 8s. The default budget settles every
        // host as non-primary before it answers (→ `None`); only a widened
        // budget reaches it. This proves the budget — not the parallel race
        // — is what lets the cold primary through.
        let hosts = vec![
            host("s1", 27017),
            host("s2", 27017),
            host("cold-primary", 27017),
        ];
        assert!(
            select_primary(&hosts, &ScriptedProbe, DEFAULT_PROBE_TIMEOUT)
                .await
                .into_primary()
                .is_none(),
            "5s default must time out the cold primary even though secondaries answered",
        );
        let picked = select_primary(&hosts, &ScriptedProbe, Duration::from_secs(15))
            .await
            .into_primary()
            .expect("widened budget reaches the cold primary behind the secondaries");
        assert_eq!(picked.host, "cold-primary");
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_with_a_zero_budget_misses_a_slow_primary() {
        // The fail-fast extreme: a zero per-host budget elapses before any
        // host that isn't ready on the first poll, so a cold primary is
        // missed and the call returns immediately rather than hanging.
        let hosts = vec![host("cold-primary", 27017)];
        assert!(
            select_primary(&hosts, &ScriptedProbe, Duration::ZERO)
                .await
                .into_primary()
                .is_none(),
            "a zero budget must not wait for the cold primary",
        );
    }

    // ---------- select_primary per-host outcomes (#20) ----------
    //
    // When no host is the primary, the rejected hosts must be carried out
    // of the race paired with *why* — a secondary reply, a probe failure,
    // or a timeout — so the caller can turn the bare attempted-count into
    // an actionable diagnosis (network policy vs in-progress election vs
    // cert mismatch all looked identical before).

    /// Probe that produces a different rejection reason per host so a
    /// single race exercises all three [`ProbeOutcome`] variants:
    /// `"secondary"` answers `Ok(false)`, `"dead"` fails the probe, and
    /// `"hang"` never answers (→ timeout under a finite budget).
    struct MixedProbe;

    impl PrimaryProbe for MixedProbe {
        async fn is_primary(&self, host: String, _port: u16) -> Result<bool, ProbeError> {
            match host.as_str() {
                "secondary" => Ok(false),
                "dead" => Err(ProbeError::NoReply),
                "hang" => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Ok(false)
                }
                other => panic!("unexpected host {other}"),
            }
        }
    }

    fn no_primary(selection: Selection) -> Vec<(SrvHost, ProbeOutcome)> {
        match selection {
            Selection::NoPrimary(attempts) => attempts,
            Selection::Primary(host) => panic!("expected NoPrimary, got primary {host:?}"),
        }
    }

    fn outcome_for<'a>(attempts: &'a [(SrvHost, ProbeOutcome)], name: &str) -> &'a ProbeOutcome {
        &attempts
            .iter()
            .find(|(h, _)| h.host == name)
            .unwrap_or_else(|| panic!("no attempt recorded for host {name}"))
            .1
    }

    #[tokio::test]
    async fn select_primary_records_not_primary_for_every_secondary() {
        let hosts = vec![host("a", 27017), host("b", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe.expect_is_primary().returning(|_, _| Ok(false));

        let attempts = no_primary(select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT).await);
        assert_eq!(attempts.len(), 2, "every probed host must be reported");
        assert!(
            attempts
                .iter()
                .all(|(_, o)| matches!(o, ProbeOutcome::NotPrimary)),
            "a host answering isWritablePrimary:false is NotPrimary, got {attempts:?}",
        );
    }

    #[tokio::test]
    async fn select_primary_records_failed_and_preserves_the_probe_error_source() {
        let hosts = vec![host("a", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|_, _| Err(ProbeError::NoReply));

        let attempts = no_primary(select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT).await);
        assert_eq!(attempts.len(), 1);
        assert!(
            matches!(&attempts[0].1, ProbeOutcome::Failed(ProbeError::NoReply)),
            "a probe error must be carried as Failed, got {:?}",
            attempts[0].1,
        );
        // The original ProbeError (and its io/TLS chain) must stay reachable
        // via the standard error `source`, per the issue's "Care for" note.
        assert!(
            std::error::Error::source(&attempts[0].1).is_some(),
            "Failed must expose the ProbeError as its source",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_records_timed_out_for_a_host_past_the_budget() {
        // `hang` sleeps an hour; under a finite budget its probe elapses
        // and must be reported as TimedOut, distinct from a probe failure.
        let hosts = vec![host("hang", 27017)];
        let attempts =
            no_primary(select_primary(&hosts, &MixedProbe, Duration::from_secs(5)).await);
        assert_eq!(attempts.len(), 1);
        assert!(
            matches!(attempts[0].1, ProbeOutcome::TimedOut),
            "a probe exceeding the budget is TimedOut, got {:?}",
            attempts[0].1,
        );
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_keys_each_distinct_outcome_to_the_right_host() {
        // The realistic failed-startup picture: one secondary, one
        // unreachable host, one that never answers. All three reasons must
        // survive, keyed to the host they came from.
        let hosts = vec![
            host("secondary", 27017),
            host("dead", 27017),
            host("hang", 27017),
        ];
        let attempts =
            no_primary(select_primary(&hosts, &MixedProbe, Duration::from_secs(5)).await);

        assert_eq!(attempts.len(), 3);
        assert!(matches!(
            outcome_for(&attempts, "secondary"),
            ProbeOutcome::NotPrimary
        ));
        assert!(matches!(
            outcome_for(&attempts, "dead"),
            ProbeOutcome::Failed(_)
        ));
        assert!(matches!(
            outcome_for(&attempts, "hang"),
            ProbeOutcome::TimedOut
        ));
    }

    #[tokio::test]
    async fn select_primary_returns_primary_variant_without_collecting_outcomes() {
        // The happy path stays a clean `Primary`: finding the primary
        // short-circuits the race, so no rejection reasons are gathered.
        let hosts = vec![host("primary", 27017), host("secondary", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|name, _| Ok(name == "primary"));

        match select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT).await {
            Selection::Primary(host) => assert_eq!(host.host, "primary"),
            Selection::NoPrimary(attempts) => panic!("expected Primary, got {attempts:?}"),
        }
    }

    // ---------- tracing events (#19) ----------
    //
    // The probe path is best-effort observability, but operators rely on it
    // to tell a no-primary startup apart from an unreachable cluster, so we
    // pin down that the load-bearing events actually fire: a "selected
    // primary" for the winner and a per-host "probe rejected" when none
    // qualifies. We capture events with a tiny in-process `Layer` rather
    // than scraping formatted text, so the assertions key off the event's
    // `message` field directly.

    use std::sync::Mutex;

    use tracing::Subscriber;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::Registry;

    /// Collects the `message` of every event into a shared buffer. Only the
    /// human-readable message is captured — enough to assert *which* branch
    /// emitted, without coupling the test to field formatting.
    #[derive(Clone, Default)]
    struct CapturingLayer {
        messages: Arc<Mutex<Vec<String>>>,
    }

    /// Pulls the `message` field (the macro's positional string) out of an
    /// event, ignoring every structured field.
    struct MessageVisitor<'a>(&'a mut Option<String>);

    impl Visit for MessageVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                *self.0 = Some(format!("{value:?}"));
            }
        }
    }

    impl<S: Subscriber> Layer<S> for CapturingLayer {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut message = None;
            event.record(&mut MessageVisitor(&mut message));
            if let Some(message) = message
                && let Ok(mut buf) = self.messages.lock()
            {
                buf.push(message);
            }
        }
    }

    /// Runs `fut` with a capturing subscriber installed for the duration,
    /// then returns every captured event message. `set_default` returns a
    /// thread-scoped guard (rather than `with_default`, whose closure can't
    /// hold an `.await`) so concurrent tests don't cross-talk.
    async fn capture_events<Fut>(fut: Fut) -> Vec<String>
    where
        Fut: std::future::Future<Output = ()>,
    {
        let layer = CapturingLayer::default();
        let messages = layer.messages.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        fut.await;
        let buf = messages.lock().expect("messages mutex poisoned");
        buf.clone()
    }

    #[tokio::test]
    async fn select_primary_emits_selected_primary_event_for_the_winner() {
        let hosts = vec![host("a", 27017), host("primary", 27017)];
        let messages = capture_events(async {
            let mut probe = MockPrimaryProbe::new();
            probe
                .expect_is_primary()
                .returning(|name, _| Ok(name == "primary"));
            let picked = select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
                .await
                .into_primary()
                .expect("primary");
            assert_eq!(picked.host, "primary");
        })
        .await;

        assert!(
            messages.iter().any(|m| m.contains("selected primary")),
            "the chosen winner must emit a `selected primary` event, got {messages:?}",
        );
    }

    #[tokio::test]
    async fn select_primary_emits_a_rejected_event_per_host_when_no_primary() {
        let hosts = vec![host("a", 27017), host("b", 27017)];
        let messages = capture_events(async {
            let mut probe = MockPrimaryProbe::new();
            probe.expect_is_primary().returning(|_, _| Ok(false));
            assert!(
                select_primary(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
                    .await
                    .into_primary()
                    .is_none()
            );
        })
        .await;

        let rejected = messages
            .iter()
            .filter(|m| m.contains("probe rejected"))
            .count();
        assert_eq!(
            rejected, 2,
            "every rejected host must emit a `probe rejected` event, got {messages:?}",
        );
        assert!(
            !messages.iter().any(|m| m.contains("selected primary")),
            "no `selected primary` event must fire when no host qualifies, got {messages:?}",
        );
    }
}
