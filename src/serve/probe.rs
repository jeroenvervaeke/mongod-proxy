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
//!   fixed per-host timeout and returns as soon as one reports itself
//!   primary, so selection converges in single-host latency rather than
//!   the sum of per-host timeouts.

use std::sync::Arc;
use std::time::Duration;

use bson::doc;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::ids::RequestId;
use crate::message::Message;
use crate::operation::{
    Operation,
    op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags},
};
use crate::serve::service::{ProxyClient, ProxyClientForwardError, ProxyClientRequestError};

/// Per-host budget for the dial + `hello` round-trip during primary
/// selection. Hosts that don't reply in time are skipped rather than
/// stalling the proxy startup.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Failure modes for a single primary probe.
#[derive(Debug, thiserror::Error)]
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
        let mut client = ProxyClient::forward_to(host, port, self.tls_connector.clone()).await?;
        let req = build_hello_request();
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .map_err(ProbeError::Request)?;
        let reply = stream
            .next()
            .await
            .ok_or(ProbeError::NoReply)?
            .map_err(ProbeError::Response)?;
        extract_is_writable_primary(&reply).ok_or(ProbeError::MalformedReply)
    }
}

/// Probe every host in `hosts` concurrently, returning as soon as one
/// reports `isWritablePrimary == true`.
///
/// Each probe runs under its own [`PROBE_TIMEOUT`], and they all race in
/// parallel: the first confirmed primary wins and the remaining probes
/// are cancelled (dropped), so selection converges in single-host
/// latency rather than the sum of per-host timeouts. A slow or
/// unreachable replica-set member therefore can't delay startup behind
/// the host that actually answers.
///
/// Secondaries (`Ok(Ok(false))`), probe errors (`Ok(Err(_))`), and
/// timeouts (`Err(_)`) are all ignored. Because we keep draining until a
/// primary appears, a primary that merely responds slowly is still found
/// rather than being missed by an early `None`; we return `None` only
/// once *every* probe has settled without one.
pub(crate) async fn select_primary<P>(
    hosts: &[crate::srv::SrvHost],
    probe: &P,
) -> Option<crate::srv::SrvHost>
where
    P: PrimaryProbe + ?Sized,
{
    let mut probes: FuturesUnordered<_> = hosts
        .iter()
        .map(|host| async move {
            let outcome = tokio::time::timeout(
                PROBE_TIMEOUT,
                probe.is_primary(host.host.clone(), host.port),
            )
            .await;
            (host, outcome)
        })
        .collect();

    while let Some((host, outcome)) = probes.next().await {
        if let Ok(Ok(true)) = outcome {
            return Some(host.clone());
        }
    }
    None
}

fn build_hello_request() -> Message {
    Message {
        request_id: RequestId::new(1),
        response_to: None,
        operation: Operation::Message(OperationMessage {
            flags: OperationMessageFlags::empty(),
            sections: vec![OpMsgSection::Body(doc! {
                "hello": 1,
                "$db": "admin",
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

    // ---------- select_primary ----------

    #[tokio::test]
    async fn select_primary_returns_first_host_when_it_is_primary() {
        let hosts = vec![host("a", 27017), host("b", 27017), host("c", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|name, _port| Ok(name == "a"));

        let picked = select_primary(&hosts, &probe).await.expect("primary");
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

        let picked = select_primary(&hosts, &probe).await.expect("primary");
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

        let picked = select_primary(&hosts, &probe).await.expect("primary");
        assert_eq!(picked.host, "b");
    }

    #[tokio::test]
    async fn select_primary_returns_none_when_no_host_is_primary() {
        let hosts = vec![host("a", 27017), host("b", 27017), host("c", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe.expect_is_primary().returning(|_, _| Ok(false));

        assert!(select_primary(&hosts, &probe).await.is_none());
    }

    #[tokio::test]
    async fn select_primary_returns_none_when_every_probe_errors() {
        let hosts = vec![host("a", 27017), host("b", 27017)];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|_, _| Err(ProbeError::NoReply));

        assert!(select_primary(&hosts, &probe).await.is_none());
    }

    #[tokio::test]
    async fn select_primary_returns_none_for_empty_host_list() {
        let probe = MockPrimaryProbe::new();
        assert!(select_primary(&[], &probe).await.is_none());
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
    /// - `"hang"` sleeps far past [`PROBE_TIMEOUT`] before answering,
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
        // hour. Serial probing would wait `PROBE_TIMEOUT` on `hang`
        // before ever reaching the primary; parallel probing returns the
        // primary immediately, so no virtual time elapses.
        let hosts = vec![host("hang", 27017), host("primary", 27017)];
        let start = tokio::time::Instant::now();

        let picked = select_primary(&hosts, &ScriptedProbe).await.expect("primary");

        assert_eq!(picked.host, "primary");
        assert!(
            start.elapsed() < PROBE_TIMEOUT,
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

        let picked = select_primary(&hosts, &ScriptedProbe).await.expect("primary");
        assert_eq!(picked.host, "slow-primary");
    }

    #[tokio::test(start_paused = true)]
    async fn select_primary_returns_none_when_every_probe_times_out() {
        // Every host hangs well past PROBE_TIMEOUT. Each probe's timeout
        // must elapse (`Err(Elapsed)`), be treated as non-primary, and
        // the call must still terminate with `None` rather than awaiting
        // the hour-long sleeps. The paused clock auto-advances to the
        // timeout instant once all tasks are idle.
        let hosts = vec![host("hang", 27017), host("hang", 27018)];

        assert!(select_primary(&hosts, &ScriptedProbe).await.is_none());
    }
}
