//! In-process end-to-end test.
//!
//! Boots a real `mongod` in Docker via [`atlas-local`](https://crates.io/crates/atlas-local)
//! (MongoDB's own Atlas-Local management crate), runs the proxy on a random
//! local port in the same process, drives traffic through it with the
//! official [`mongodb`] Rust driver, and asserts on the exact [`Message`]
//! values the proxy intercepts.
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
    time::{Duration, Instant},
};

use atlas_local::{
    Client as AtlasClient,
    models::{BindingType, CreateDeploymentOptions, Deployment, MongoDBPortBinding},
};
use bollard::Docker;
use futures::{Stream, StreamExt};
use mongod_proxy::{LogLayer, Proxy, message::Message, operation::Operation, serve};
use mongodb::{Client, bson::doc, options::ClientOptions};
use tokio::net::TcpListener;
use tower_layer::Layer;
use tower_service::Service;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_intercepts_every_command_we_send() {
    // Detect Docker before doing anything else. Lets the test self-skip on
    // hosts without a daemon (developer laptops without Docker installed).
    let docker = match Docker::connect_with_local_defaults() {
        Ok(d) => match d.ping().await {
            Ok(_) => d,
            Err(e) => {
                eprintln!("skipping: docker daemon unreachable ({e})");
                return;
            }
        },
        Err(e) => {
            eprintln!("skipping: docker not configured ({e})");
            return;
        }
    };

    let atlas = AtlasClient::new(docker);

    // ----- 1. Create the upstream Atlas-Local deployment -----
    //
    // `atlas-local` handles image pull, container create + start, and the
    // wait-for-healthy loop for us. We pin the port binding to loopback so
    // we can speak to it without `--network host`.
    let deployment = atlas
        .create_deployment(CreateDeploymentOptions {
            wait_until_healthy: Some(true),
            wait_until_healthy_timeout: Some(Duration::from_secs(120)),
            mongodb_port_binding: Some(MongoDBPortBinding {
                port: None, // let the daemon pick an ephemeral host port
                binding_type: BindingType::Loopback,
            }),
            ..Default::default()
        })
        .await
        .expect("create atlas-local deployment");

    let deployment_name = deployment
        .name
        .clone()
        .expect("atlas-local always assigns a name");
    let host_port = mongo_port(&deployment).expect("deployment exposes a host port");

    eprintln!(
        "atlas-local deployment {} ({}) listening on 127.0.0.1:{host_port}",
        deployment_name,
        &deployment.container_id[..12]
    );

    // Cleanup guard fires even on panic — `atlas-local` removes the
    // container for us via `delete_deployment`.
    let cleanup_atlas = atlas.clone();
    let cleanup_name = deployment_name.clone();
    let cleanup_guard = scopeguard::guard((), |_| {
        let atlas = cleanup_atlas.clone();
        let name = cleanup_name.clone();
        // We can't run async in Drop; spawn and rely on the runtime to
        // outlive us. The happy path explicitly awaits delete below.
        tokio::spawn(async move {
            let _ = atlas.delete_deployment(&name).await;
        });
    });

    // ----- 2. (atlas-local already waited for HEALTHY; verify with the driver) -----
    let direct_uri = format!("mongodb://127.0.0.1:{host_port}/?directConnection=true");
    wait_ready(&direct_uri).await.expect("mongo never ready");

    // ----- 3. Start the proxy on a random local port -----
    let recorder = Recorder::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_port = listener.local_addr().unwrap().port();
    eprintln!("proxy listening on 127.0.0.1:{proxy_port}");

    let proxy = Proxy::new("127.0.0.1", host_port, false)
        .layer(LogLayer)
        .layer(recorder.layer());

    let proxy_task = tokio::spawn(async move {
        let _ = serve(listener, proxy).await;
    });

    // ----- 4. Drive traffic via the official driver, THROUGH the proxy -----
    let proxy_uri = format!("mongodb://127.0.0.1:{proxy_port}/?directConnection=true");
    let mut options = ClientOptions::parse(&proxy_uri).await.expect("parse uri");
    options.server_selection_timeout = Some(Duration::from_secs(10));
    let client = Client::with_options(options).expect("client");

    let db = client.database("e2e_intercept");
    let _ = db
        .collection::<mongodb::bson::Document>("movies")
        .drop()
        .await;
    let _ = db
        .collection::<mongodb::bson::Document>("docs")
        .drop()
        .await;

    // Insert -> proxy must see at least one OP_MSG with command="insert"
    let coll = db.collection::<mongodb::bson::Document>("movies");
    let mut docs = Vec::new();
    for i in 0..500i32 {
        let group = ["a", "b", "c", "d"][(i as usize) % 4];
        docs.push(doc! { "_id": i, "n": i, "g": group });
    }
    coll.insert_many(docs).await.expect("insert_many");

    // Find with explicit batchSize -> drives multiple getMore round-trips.
    let mut cursor = coll.find(doc! {}).batch_size(50).await.expect("find");
    let mut seen = 0usize;
    while cursor.advance().await.expect("advance") {
        seen += 1;
    }
    assert_eq!(seen, 500, "cursor must surface every inserted document");

    // Aggregate -> command="aggregate"
    let _agg: Vec<_> = coll
        .aggregate(vec![doc! { "$group": { "_id": "$g", "n": { "$sum": 1 } } }])
        .await
        .expect("aggregate")
        .with_type::<mongodb::bson::Document>()
        .collect()
        .await;

    // Mutation commands -> command="update" / "delete"
    coll.update_many(doc! { "g": "a" }, doc! { "$set": { "touched": true } })
        .await
        .expect("update");
    coll.delete_many(doc! { "g": "b" }).await.expect("delete");

    // Metadata commands
    db.list_collection_names().await.expect("list cols");
    client.list_database_names().await.expect("list dbs");

    // Hand-rolled runCommand to assert we can also push raw commands through.
    db.run_command(doc! { "ping": 1 }).await.expect("ping");

    // ----- 5. Drain the proxy -----
    drop(client);
    tokio::time::sleep(Duration::from_millis(500)).await;
    proxy_task.abort();
    let _ = proxy_task.await;

    // ----- 6. Assert on what the proxy actually saw -----
    let events = recorder.snapshot();
    eprintln!("recorded {} events", events.len());

    let request_count = |cmd: &str| -> usize {
        events
            .iter()
            .filter(|e| e.direction == Direction::Request && e.command.as_deref() == Some(cmd))
            .count()
    };
    let response_count = |cmd: &str| -> usize {
        events
            .iter()
            .filter(|e| e.direction == Direction::Response && e.responds_to.as_deref() == Some(cmd))
            .count()
    };
    let request_op_count = |op: &str| -> usize {
        events
            .iter()
            .filter(|e| e.direction == Direction::Request && e.op == op)
            .count()
    };

    for cmd in [
        "insert",
        "find",
        "getMore",
        "aggregate",
        "update",
        "delete",
        "listCollections",
        "listDatabases",
        "ping",
    ] {
        let req = request_count(cmd);
        let resp = response_count(cmd);
        eprintln!("  {cmd:<18} request={req:<3} response_to_request={resp}");
        assert!(
            req >= 1,
            "proxy never saw a request with command={cmd:?} (events: {events:#?})",
        );
        assert!(
            resp >= 1,
            "proxy never saw a response paired to a {cmd:?} request (events: {events:#?})",
        );
    }

    assert!(
        request_count("getMore") >= 9,
        "expected >=9 getMore requests for 500/50 batches, got {}",
        request_count("getMore")
    );

    assert!(
        request_op_count("OP_MSG") >= 10,
        "expected many OP_MSG requests, got {}",
        request_op_count("OP_MSG")
    );

    let total_requests = events
        .iter()
        .filter(|e| e.direction == Direction::Request)
        .count();
    let total_responses = events
        .iter()
        .filter(|e| e.direction == Direction::Response)
        .count();
    let gap = total_requests.abs_diff(total_responses);
    assert!(
        gap <= 4,
        "request/response imbalance too large: {total_requests} vs {total_responses}"
    );

    // ----- 7. Cleanup -----
    // Defuse the panic-safety guard first so we don't double-delete.
    cleanup_guard.defuse();
    atlas
        .delete_deployment(&deployment_name)
        .await
        .expect("delete deployment");
}

fn mongo_port(deployment: &Deployment) -> Option<u16> {
    deployment.port_bindings.as_ref().and_then(|b| b.port)
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

    fn snapshot(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
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
        let command = first_command_key(&req.operation).map(str::to_owned);
        self.events.lock().unwrap().push(Event {
            direction: Direction::Request,
            op: op_kind(&req.operation),
            command: command.clone(),
            responds_to: None,
            request_id: req.request_id,
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
                    op: op_kind(&msg.operation),
                    command: None,
                    responds_to: self.request_command.clone(),
                    request_id: msg.request_id,
                });
                std::task::Poll::Ready(Some(Ok(msg)))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
        }
    }
}

fn op_kind(op: &Operation) -> &'static str {
    match op {
        Operation::Message(_) => "OP_MSG",
        Operation::Query(_) => "OP_QUERY",
        Operation::Reply(_) => "OP_REPLY",
    }
}

fn first_command_key(op: &Operation) -> Option<&str> {
    match op {
        Operation::Message(m) => m.command_name(),
        Operation::Query(q) => q.query.keys().next().map(String::as_str),
        Operation::Reply(_) => None,
    }
}

async fn wait_ready(uri: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = ClientOptions::parse(uri).await?;
    options.server_selection_timeout = Some(Duration::from_secs(2));
    let client = Client::with_options(options)?;

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_err: Option<mongodb::error::Error> = None;
    while Instant::now() < deadline {
        match client
            .database("admin")
            .run_command(doc! { "ping": 1 })
            .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    Err(format!("mongo never accepted ping: last error = {last_err:?}").into())
}

// Tiny inline scopeguard so we don't need another crate.
//
// The guard fires its closure on `Drop` *unless* `defuse` is called first —
// the happy-path explicit cleanup defuses the guard so we don't double-delete.
mod scopeguard {
    pub fn guard<T, F: FnOnce(T)>(value: T, on_drop: F) -> Guard<T, F> {
        Guard {
            value: Some(value),
            on_drop: Some(on_drop),
        }
    }

    pub struct Guard<T, F: FnOnce(T)> {
        value: Option<T>,
        on_drop: Option<F>,
    }

    impl<T, F: FnOnce(T)> Guard<T, F> {
        /// Disarm the guard so its `Drop` does nothing. Returns the wrapped
        /// value back to the caller.
        pub fn defuse(mut self) -> T {
            self.on_drop = None;
            self.value.take().expect("value lives until defuse")
        }
    }

    impl<T, F: FnOnce(T)> Drop for Guard<T, F> {
        fn drop(&mut self) {
            if let (Some(v), Some(f)) = (self.value.take(), self.on_drop.take()) {
                f(v);
            }
        }
    }
}
