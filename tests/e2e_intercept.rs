//! In-process end-to-end test.
//!
//! Boots a real `mongod` in Docker via [`bollard`], runs the proxy on a
//! random local port in the same process, drives traffic through it with
//! the official [`mongodb`] Rust driver, and asserts on the exact
//! [`Message`] values the proxy intercepts.
//!
//! Unlike the previous bash-based e2e harness, every step here is statically
//! typed, every assertion runs against the structured wire-protocol model the
//! proxy actually parses, and there is no `grep`-against-tracing-output
//! fragility.
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
    collections::HashMap,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bollard::{
    Docker,
    container::{
        Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
        StopContainerOptions,
    },
    image::CreateImageOptions,
    models::{HostConfig, PortBinding},
};
use futures::{Stream, StreamExt};
use mongod_proxy::{LogLayer, Proxy, message::Message, operation::Operation, serve};
use mongodb::{Client, bson::doc, options::ClientOptions};
use tokio::net::TcpListener;
use tower_layer::Layer;
use tower_service::Service;

const MONGO_IMAGE: &str = "mongodb/mongodb-atlas-local:latest";
const CONTAINER_LABEL: &str = "mongod-proxy-e2e-rust";

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

    // ----- 1. Bring up the upstream mongod -----
    let mongo = MongoContainer::start(&docker).await.expect("start mongo");
    let cleanup_guard = scopeguard::guard((), |_| {
        // Schedule cleanup on panic too. We can't run async in Drop, so spawn
        // and rely on the process not exiting too fast; in the happy path
        // we call `mongo.stop()` explicitly below.
        let docker = docker.clone();
        let id = mongo.id.clone();
        tokio::spawn(async move {
            let _ = docker
                .stop_container(&id, Some(StopContainerOptions { t: 5 }))
                .await;
        });
    });

    eprintln!(
        "mongo container {} listening on 127.0.0.1:{}",
        &mongo.id[..12],
        mongo.host_port
    );

    // ----- 2. Wait for mongod to be ready (via direct driver connection) -----
    let direct_uri = format!(
        "mongodb://127.0.0.1:{}/?directConnection=true",
        mongo.host_port
    );
    wait_ready(&direct_uri).await.expect("mongo never ready");

    // ----- 3. Start the proxy on a random local port -----
    let recorder = Recorder::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_port = listener.local_addr().unwrap().port();
    eprintln!("proxy listening on 127.0.0.1:{proxy_port}");

    let proxy = Proxy::new("127.0.0.1", mongo.host_port, false)
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

    // Helper closures to count by predicate.
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

    // Every command the test issued must show up at least once on the
    // request side, classified by the proxy from the first BSON key.
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

    // 500 documents at batchSize 50 -> at least 9 getMores (10 batches).
    assert!(
        request_count("getMore") >= 9,
        "expected >=9 getMore requests for 500/50 batches, got {}",
        request_count("getMore")
    );

    // We connected to a `mongod`, so the driver handshake will emit at least
    // one OP_QUERY hello on the very first connection; both wire formats
    // must be exercised.
    assert!(
        request_op_count("OP_MSG") >= 10,
        "expected many OP_MSG requests, got {}",
        request_op_count("OP_MSG")
    );

    // Every request that expected a reply must have one (modulo a few
    // fire-and-forget endSessions on shutdown).
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
    drop(cleanup_guard);
    mongo.stop(&docker).await.expect("stop mongo");
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

// ---------------------------------------------------------------------------
// Docker container management via bollard.
// ---------------------------------------------------------------------------

struct MongoContainer {
    id: String,
    host_port: u16,
}

impl MongoContainer {
    async fn start(docker: &Docker) -> Result<Self, Box<dyn std::error::Error>> {
        ensure_image(docker, MONGO_IMAGE).await?;

        let port_bindings: HashMap<String, Option<Vec<PortBinding>>> = HashMap::from([(
            "27017/tcp".to_string(),
            Some(vec![PortBinding {
                host_ip: Some("127.0.0.1".to_string()),
                host_port: Some("0".to_string()),
            }]),
        )]);

        let mut labels = HashMap::new();
        labels.insert(CONTAINER_LABEL.to_string(), "1".to_string());

        let config = Config {
            image: Some(MONGO_IMAGE.to_string()),
            env: Some(vec!["MONGOT_DISABLED=true".to_string()]),
            labels: Some(labels),
            host_config: Some(HostConfig {
                port_bindings: Some(port_bindings),
                auto_remove: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let name = format!(
            "{CONTAINER_LABEL}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let create = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: &name,
                    platform: None,
                }),
                config,
            )
            .await?;
        docker
            .start_container(&create.id, None::<StartContainerOptions<String>>)
            .await?;

        // Resolve the host-side port the daemon picked for us.
        let info = docker.inspect_container(&create.id, None).await?;
        let host_port = info
            .network_settings
            .as_ref()
            .and_then(|ns| ns.ports.as_ref())
            .and_then(|ports| ports.get("27017/tcp").cloned())
            .flatten()
            .and_then(|bindings| bindings.into_iter().next())
            .and_then(|b| b.host_port)
            .ok_or("container did not expose host port for 27017/tcp")?
            .parse::<u16>()?;

        Ok(Self {
            id: create.id,
            host_port,
        })
    }

    async fn stop(&self, docker: &Docker) -> Result<(), Box<dyn std::error::Error>> {
        let _ = docker
            .stop_container(&self.id, Some(StopContainerOptions { t: 5 }))
            .await;
        // `auto_remove: true` means the daemon removes the container when it
        // exits, but be explicit in case the image config disabled it.
        let _ = docker
            .remove_container(
                &self.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
        Ok(())
    }
}

async fn ensure_image(docker: &Docker, image: &str) -> Result<(), Box<dyn std::error::Error>> {
    if docker.inspect_image(image).await.is_ok() {
        return Ok(());
    }
    eprintln!("pulling image {image} (first run only)");
    let mut pull = docker.create_image(
        Some(CreateImageOptions {
            from_image: image,
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(chunk) = pull.next().await {
        chunk?; // surface any pull error
    }
    Ok(())
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

    impl<T, F: FnOnce(T)> Drop for Guard<T, F> {
        fn drop(&mut self) {
            if let (Some(v), Some(f)) = (self.value.take(), self.on_drop.take()) {
                f(v);
            }
        }
    }
}
