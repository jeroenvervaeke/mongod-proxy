//! In-process end-to-end test.
//!
//! Boots a real `mongod` in Docker (either a vanilla standalone via
//! [`bollard`] or a single-node replica set via
//! [`atlas-local`](https://crates.io/crates/atlas-local)), runs the proxy
//! on a random local port in the same process, drives traffic through it
//! with the official [`mongodb`] Rust driver, and asserts on the exact
//! [`Message`] values the proxy intercepts.
//!
//! The test body is shared across the full {standalone, replica-set} ×
//! {default URI, `?directConnection=true`} matrix via `#[rstest]`, so a
//! regression in any one path is reported against the specific case
//! (e.g. `proxy_intercepts_every_command_we_send::case_3_replica_set_default`).
//!
//! - Standalone + default URI: `rewrite_hello` is a no-op (no `setName`
//!   on the wire); the case catches regressions on the proxy's standalone
//!   path.
//! - Standalone + `directConnection=true`: driver bypasses SDAM entirely;
//!   the case catches handshake regressions in the proxy.
//! - Replica-set + default URI: the case `rewrite_hello` exists for —
//!   verifies the driver stays on the proxy socket instead of dialling
//!   the upstream container hostname.
//! - Replica-set + `directConnection=true`: original supported URI shape;
//!   the case catches regressions to that path.
//!
//! Every step is statically typed and every assertion runs against the
//! structured wire-protocol model the proxy actually parses — no
//! `grep`-against-tracing-output fragility.
//!
//! ## Running
//!
//! Requires a running Docker daemon reachable via the local socket. The test
//! skips itself with a printed message when Docker is unreachable. Run
//! explicitly with:
//!
//! ```text
//! cargo test --test e2e_intercept -- --nocapture
//! ```

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::{Stream, StreamExt};
use mongod_proxy::{LogLayer, Proxy, message::Message, serve};
use mongodb::{Client, bson::doc, options::ClientOptions};
use rstest::rstest;
use tokio::net::TcpListener;
use tower_layer::Layer;
use tower_service::Service;

mod common;
use common::{DeploymentKind, TestDeployment, try_connect_docker};

#[rstest]
#[case::standalone_default(DeploymentKind::Standalone, false)]
#[case::standalone_direct(DeploymentKind::Standalone, true)]
#[case::replica_set_default(DeploymentKind::ReplicaSet, false)]
#[case::replica_set_direct(DeploymentKind::ReplicaSet, true)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_intercepts_every_command_we_send(
    #[case] kind: DeploymentKind,
    #[case] direct_connection: bool,
) {
    // Self-skip on hosts without a daemon (developer laptops without Docker).
    let Some(docker) = try_connect_docker().await else {
        return;
    };

    // ----- 1. Create the upstream deployment (standalone or replica set).
    let deployment = TestDeployment::start(&docker, kind)
        .await
        .expect("start deployment");
    let host_port = deployment.host_port;
    eprintln!(
        "[{} / directConnection={direct_connection}] {} listening on 127.0.0.1:{host_port}",
        kind.label(),
        deployment.label,
    );

    // Cleanup guard fires even on panic. We capture a cheap clone of the
    // cleanup handle so the happy-path `shutdown()` below can still own
    // `deployment` for the metadata access during the test body.
    let cleanup_handle = deployment.cleanup_handle();
    let cleanup_guard = scopeguard::guard(cleanup_handle, |h| {
        // Can't run async in Drop; spawn and rely on the runtime to
        // outlive us. The happy path explicitly awaits delete below.
        tokio::spawn(async move {
            let _ = h.shutdown().await;
        });
    });

    // ----- 2. Start the proxy on a random local port -----
    let recorder = Recorder::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_port = listener.local_addr().unwrap().port();
    eprintln!("proxy listening on 127.0.0.1:{proxy_port}");

    let proxy = Proxy::new("127.0.0.1", host_port, false)
        .rewrite_hello()
        .layer(LogLayer)
        .layer(recorder.layer());

    let proxy_task = tokio::spawn(async move {
        let _ = serve(listener, proxy).await;
    });

    // ----- 3. Drive traffic via the official driver, THROUGH the proxy.
    //          The URI shape is parameterised: when `direct_connection` is
    //          false (default URI) the driver runs SDAM and would dial
    //          upstream's container hostname directly against a replica
    //          set without `rewrite_hello()`. When true, the driver
    //          short-circuits SDAM and uses just this address. Both must
    //          work against both topologies.
    let proxy_uri = if direct_connection {
        format!("mongodb://127.0.0.1:{proxy_port}/?directConnection=true")
    } else {
        format!("mongodb://127.0.0.1:{proxy_port}/")
    };
    let mut options = ClientOptions::parse(&proxy_uri).await.expect("parse uri");
    options.server_selection_timeout = Some(Duration::from_secs(10));
    let client = Client::with_options(options).expect("client");

    let db = client.database("e2e_intercept");

    // ----- 4. Drive traffic one op at a time, verifying the proxy actually
    //          intercepted that op before moving on. -----
    //
    // Each phase follows the same pattern: drain any background events from
    // the recorder, run exactly one driver operation, drain again, and
    // assert what we just observed. That way a regression in any single
    // command is reported against *that* command rather than as a confusing
    // tally at the end of the test.

    // ----- Warm-up: trigger driver handshake + drop any leftover state from
    // a previous run, then flush so the assertions below see only fresh ops.
    let _ = db
        .collection::<mongodb::bson::Document>("movies")
        .drop()
        .await;
    let _ = db
        .collection::<mongodb::bson::Document>("docs")
        .drop()
        .await;
    let warmup = recorder.drain();
    eprintln!(
        "  warmup discarded {} background events (handshake/drop)",
        warmup.len()
    );

    let coll = db.collection::<mongodb::bson::Document>("movies");

    // ----- Phase 1: insert -----
    phase("insert (500 docs)");
    let mut docs = Vec::new();
    for i in 0..500i32 {
        let group = ["a", "b", "c", "d"][(i as usize) % 4];
        docs.push(doc! { "_id": i, "n": i, "g": group });
    }
    coll.insert_many(docs).await.expect("insert_many");
    let events = recorder.drain();
    assert_observed(&events, "insert", 1);

    // ----- Phase 2: find -----
    //
    // `find` opens the cursor and returns the first batch. Subsequent
    // `getMore` requests are issued lazily by the cursor iterator.
    phase("find (open cursor)");
    let mut cursor = coll.find(doc! {}).batch_size(50).await.expect("find");
    let events = recorder.drain();
    assert_observed(&events, "find", 1);

    // ----- Phase 3: getMore -----
    phase("getMore (drain 500 docs at batchSize 50)");
    let mut seen = 0usize;
    while cursor.advance().await.expect("advance") {
        seen += 1;
    }
    assert_eq!(seen, 500, "cursor must surface every inserted document");
    let events = recorder.drain();
    // 500 docs / batchSize 50 -> 10 batches; first one came from `find`, so
    // we expect 9 getMore round-trips. The driver may issue an extra one to
    // detect cursor exhaustion, so accept >= 9.
    let getmore_reqs = count_requests(&events, "getMore");
    let getmore_resps = count_responses(&events, "getMore");
    eprintln!("  observed getMore: {getmore_reqs} request(s), {getmore_resps} response(s)");
    assert!(
        getmore_reqs >= 9,
        "expected >=9 getMore requests, got {getmore_reqs}\nevents:\n{}",
        format_events(&events)
    );
    assert!(
        getmore_resps >= 9,
        "expected >=9 getMore responses, got {getmore_resps}\nevents:\n{}",
        format_events(&events)
    );

    // ----- Phase 4: aggregate -----
    phase("aggregate ($group on genre)");
    let _agg: Vec<_> = coll
        .aggregate(vec![doc! { "$group": { "_id": "$g", "n": { "$sum": 1 } } }])
        .await
        .expect("aggregate")
        .with_type::<mongodb::bson::Document>()
        .collect()
        .await;
    let events = recorder.drain();
    assert_observed(&events, "aggregate", 1);

    // ----- Phase 5: update -----
    phase("update (set touched=true on g=a)");
    coll.update_many(doc! { "g": "a" }, doc! { "$set": { "touched": true } })
        .await
        .expect("update");
    let events = recorder.drain();
    assert_observed(&events, "update", 1);

    // ----- Phase 6: delete -----
    phase("delete (g=b)");
    coll.delete_many(doc! { "g": "b" }).await.expect("delete");
    let events = recorder.drain();
    assert_observed(&events, "delete", 1);

    // ----- Phase 7: listCollections -----
    phase("listCollections");
    db.list_collection_names().await.expect("list cols");
    let events = recorder.drain();
    assert_observed(&events, "listCollections", 1);

    // ----- Phase 8: listDatabases -----
    phase("listDatabases");
    client.list_database_names().await.expect("list dbs");
    let events = recorder.drain();
    assert_observed(&events, "listDatabases", 1);

    // ----- Phase 9: raw runCommand(ping) -----
    phase("runCommand(ping)");
    db.run_command(doc! { "ping": 1 }).await.expect("ping");
    let events = recorder.drain();
    assert_observed(&events, "ping", 1);

    // ----- 4. Shut down the proxy and clean up the deployment -----
    drop(client);
    tokio::time::sleep(Duration::from_millis(500)).await;
    proxy_task.abort();
    let _ = proxy_task.await;

    // Defuse the panic-time cleanup guard so the happy-path explicit
    // shutdown below isn't racing the background-spawned one.
    let _ = scopeguard::ScopeGuard::into_inner(cleanup_guard);
    deployment.shutdown().await.expect("shutdown deployment");
}

fn phase(name: &str) {
    eprintln!("[phase] {name}");
}

fn count_requests(events: &[Event], cmd: &str) -> usize {
    events
        .iter()
        .filter(|e| e.direction == Direction::Request && e.command.as_deref() == Some(cmd))
        .count()
}

fn count_responses(events: &[Event], cmd: &str) -> usize {
    events
        .iter()
        .filter(|e| e.direction == Direction::Response && e.responds_to.as_deref() == Some(cmd))
        .count()
}

fn assert_observed(events: &[Event], cmd: &str, min: usize) {
    let req = count_requests(events, cmd);
    let resp = count_responses(events, cmd);
    eprintln!("  observed {cmd}: {req} request(s), {resp} response(s)");
    assert!(
        req >= min,
        "proxy never saw a request with command={cmd:?} (needed >= {min}, got {req})\nevents:\n{}",
        format_events(events)
    );
    assert!(
        resp >= min,
        "proxy never saw a response paired to a {cmd:?} request (needed >= {min}, got {resp})\nevents:\n{}",
        format_events(events)
    );
}

fn format_events(events: &[Event]) -> String {
    events
        .iter()
        .map(|e| {
            format!(
                "    {:?} op={} command={:?} responds_to={:?}",
                e.direction, e.op, e.command, e.responds_to
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Recorder: tower layer that captures every request and reply seen by the
// proxy, with the proxy's own classification of op-code and command name.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Direction {
    Request,
    Response,
}

#[derive(Debug, Clone)]
struct Event {
    direction: Direction,
    op: &'static str,
    /// First BSON key on the request side, or `None` for `OP_REPLY` and for
    /// responses.
    command: Option<String>,
    /// On the response side, the command name of the request this reply
    /// belongs to. Lets us assert response<->request pairing.
    responds_to: Option<String>,
    #[allow(dead_code)] // surfaced for debug logging on assertion failure
    request_id: i32,
}

#[derive(Clone)]
struct Recorder {
    events: Arc<Mutex<Vec<Event>>>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn layer(&self) -> RecorderLayer {
        RecorderLayer {
            events: self.events.clone(),
        }
    }

    /// Drains every event captured since the last `drain` (or construction).
    /// The internal buffer is left empty so subsequent operations can be
    /// asserted in isolation.
    fn drain(&self) -> Vec<Event> {
        std::mem::take(&mut self.events.lock().unwrap())
    }
}

#[derive(Clone)]
struct RecorderLayer {
    events: Arc<Mutex<Vec<Event>>>,
}

impl<S> Layer<S> for RecorderLayer {
    type Service = RecorderService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        RecorderService {
            inner,
            events: self.events.clone(),
        }
    }
}

struct RecorderService<S> {
    inner: S,
    events: Arc<Mutex<Vec<Event>>>,
}

impl<S, St, E> Service<Message> for RecorderService<S>
where
    S: Service<Message, Response = St, Error = E>,
    S::Future: Send + 'static,
    St: Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    E: Send + 'static,
{
    type Response = RecorderStream<St>;
    type Error = E;
    type Future = Pin<Box<dyn Future<Output = Result<RecorderStream<St>, E>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let command = req.operation.command_name().map(str::to_owned);
        self.events.lock().unwrap().push(Event {
            direction: Direction::Request,
            op: req.operation.op_kind(),
            command: command.clone(),
            responds_to: None,
            request_id: req.request_id.into(),
        });

        let fut = self.inner.call(req);
        let events = self.events.clone();
        Box::pin(async move {
            let inner = fut.await?;
            Ok(RecorderStream {
                inner,
                events,
                request_command: command,
            })
        })
    }
}

struct RecorderStream<St> {
    inner: St,
    events: Arc<Mutex<Vec<Event>>>,
    request_command: Option<String>,
}

impl<St, E> Stream for RecorderStream<St>
where
    St: Stream<Item = Result<Message, E>> + Unpin,
{
    type Item = Result<Message, E>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Ready(Some(Ok(msg))) => {
                self.events.lock().unwrap().push(Event {
                    direction: Direction::Response,
                    op: msg.operation.op_kind(),
                    command: None,
                    responds_to: self.request_command.clone(),
                    request_id: msg.request_id.into(),
                });
                std::task::Poll::Ready(Some(Ok(msg)))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
        }
    }
}
