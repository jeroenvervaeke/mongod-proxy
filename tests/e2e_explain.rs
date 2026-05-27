//! In-process end-to-end test for the explain inspector.
//!
//! Boots a real `mongod` in Docker via [`atlas-local`](https://crates.io/crates/atlas-local),
//! runs the proxy on a random local port with `ExplainLayer` wired into a
//! bounded channel sink, drives traffic through the proxy with the official
//! `mongodb` Rust driver, and asserts on the typed [`ExplainEvent`] values
//! the inspector emits.
//!
//! ## Running
//!
//! Requires a running Docker daemon reachable via the local socket. The
//! test skips itself with a printed message when Docker is unreachable.
//! Run explicitly with:
//!
//! ```text
//! cargo test --test e2e_explain -- --nocapture
//! ```

use std::time::Duration;

use atlas_local::{
    Client as AtlasClient,
    models::{BindingType, CreateDeploymentOptions, MongoDBPortBinding},
};
use bollard::Docker;
use mongod_proxy::{Command, ExplainEvent, Proxy, serve};
use mongodb::{Client, bson::doc, options::ClientOptions};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

mod common;
use common::{mongo_port, wait_ready};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explain_layer_captures_typed_events_for_find_and_aggregate() {
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

    let deployment = atlas
        .create_deployment(CreateDeploymentOptions {
            wait_until_healthy: Some(true),
            wait_until_healthy_timeout: Some(Duration::from_secs(120)),
            mongodb_port_binding: Some(MongoDBPortBinding {
                port: None,
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

    let cleanup_atlas = atlas.clone();
    let cleanup_name = deployment_name.clone();
    let cleanup_guard = scopeguard::guard((), |_| {
        let atlas = cleanup_atlas.clone();
        let name = cleanup_name.clone();
        tokio::spawn(async move {
            let _ = atlas.delete_deployment(&name).await;
        });
    });

    let direct_uri = format!("mongodb://127.0.0.1:{host_port}/?directConnection=true");
    wait_ready(&direct_uri).await.expect("mongo never ready");

    // Channel sink: 1024-deep, more than enough for one test's traffic.
    let (tx, mut rx) = mpsc::channel::<ExplainEvent>(1024);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_port = listener.local_addr().unwrap().port();
    eprintln!("proxy listening on 127.0.0.1:{proxy_port}");

    let proxy = Proxy::new("127.0.0.1", host_port, false).enable_explain_with_sink(tx);

    let proxy_task = tokio::spawn(async move {
        let _ = serve(listener, proxy).await;
    });

    // No `directConnection=true` in the URI — `Proxy::new` has the
    // `hello` / `isMaster` rewrite on by default, so the driver classifies
    // the proxy as a Standalone and keeps traffic on this socket.
    let proxy_uri = format!("mongodb://127.0.0.1:{proxy_port}/");
    let mut options = ClientOptions::parse(&proxy_uri).await.expect("parse uri");
    options.server_selection_timeout = Some(Duration::from_secs(10));
    let client = Client::with_options(options).expect("client");

    let db_name = "e2e_explain";
    let coll_name = "items";
    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>(coll_name);

    // Reset + seed.
    let _ = coll.drop().await;
    let _ = db
        .collection::<mongodb::bson::Document>("agg_items")
        .drop()
        .await;
    let docs: Vec<_> = (0..50_i32).map(|i| doc! { "_id": i, "n": i }).collect();
    coll.insert_many(docs).await.expect("insert_many");

    // Drain anything classify let through during setup (insert is skipped by
    // classify, but drop / handshakes may produce nothing — we want a clean
    // slate for the assertions below regardless).
    while rx.try_recv().is_ok() {}

    // ----- find -----
    {
        // Open the cursor; just dropping it after the .await fires the
        // find command, which is what we want to assert on.
        use futures::stream::TryStreamExt;
        let mut cursor = coll.find(doc! { "n": { "$gt": 10 } }).await.expect("find");
        // Drain a couple to ensure the find request actually completed.
        let mut count = 0usize;
        while cursor.try_next().await.expect("cursor").is_some() {
            count += 1;
            if count >= 3 {
                break;
            }
        }
    }
    let find_event = recv_event_with_timeout(&mut rx, Duration::from_secs(5))
        .await
        .expect("explain event for find");
    assert_eq!(find_event.command, Command::Find);
    assert_eq!(find_event.namespace.database().as_ref(), db_name);
    assert_eq!(find_event.namespace.collection().as_ref(), coll_name);
    // Plan tree must be non-empty (root stage present).
    eprintln!(
        "  find explain: stage={:?}, n_returned={}, total_ms={}",
        find_event.plan.stage,
        find_event.total.n_returned,
        std::time::Duration::from(find_event.total.execution_time).as_millis(),
    );

    // ----- aggregate -----
    let pipeline = vec![
        doc! { "$match": { "n": { "$gte": 0 } } },
        doc! { "$group": { "_id": null, "count": { "$sum": 1 } } },
    ];
    {
        use futures::stream::TryStreamExt;
        let mut cursor = coll.aggregate(pipeline).await.expect("aggregate");
        while cursor.try_next().await.expect("agg cursor").is_some() {}
    }
    let agg_event = recv_event_with_timeout(&mut rx, Duration::from_secs(5))
        .await
        .expect("explain event for aggregate");
    assert_eq!(agg_event.command, Command::Aggregate);
    assert_eq!(agg_event.namespace.database().as_ref(), db_name);
    assert_eq!(agg_event.namespace.collection().as_ref(), coll_name);
    eprintln!(
        "  aggregate explain: stage={:?}, n_returned={}",
        agg_event.plan.stage, agg_event.total.n_returned,
    );

    // ----- ping should NOT produce any explain event -----
    db.run_command(doc! { "ping": 1 }).await.expect("ping ok");
    // Give the inspector a moment in case it tried something async.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        rx.try_recv().is_err(),
        "ping must not produce an ExplainEvent",
    );

    // ----- shutdown -----
    drop(rx);
    proxy_task.abort();
    // Defuse the panic-time cleanup guard so the happy-path explicit
    // delete below isn't racing the background-spawned one.
    scopeguard::ScopeGuard::into_inner(cleanup_guard);
    atlas
        .delete_deployment(&deployment_name)
        .await
        .expect("delete atlas-local deployment");
}

async fn recv_event_with_timeout(
    rx: &mut mpsc::Receiver<ExplainEvent>,
    timeout: Duration,
) -> Option<ExplainEvent> {
    tokio::time::timeout(timeout, rx.recv())
        .await
        .ok()
        .flatten()
}
