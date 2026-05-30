//! In-process end-to-end test of *real* primary selection against a
//! multi-node replica set.
//!
//! The unit tests in `src/serve/probe.rs` exercise [`select_primary`]'s
//! iteration / timeout / parallelism logic through a `MockPrimaryProbe`,
//! and `tests/e2e_intercept.rs` runs against a *single*-node replica set
//! (`atlas-local`) where the only host is always the primary. Neither
//! exercises the case the multi-host `select_primary` / `HelloProbe` code
//! path actually exists for: a seed / SRV list whose earlier entries are
//! *secondaries*, where the proxy must probe past them to find the real
//! primary.
//!
//! This test closes that hole. It boots a genuine 3-member replica set in
//! Docker, discovers the elected primary, then builds the proxy from a
//! `mongodb://h1,h2,h3/` seed list deliberately ordered so the primary is
//! *last* — so the proxy can only succeed by probing every host and
//! selecting the writable one. It then drives a WRITE through the proxy
//! with the official [`mongodb`] driver: a secondary would reject the
//! write with `NotWritablePrimary`, so a successful insert proves the
//! proxy selected the primary.
//!
//! As a bonus it then steps the primary down, rebuilds the proxy, and
//! asserts the proxy now selects the *new* primary (whose port differs
//! from the original).
//!
//! ## Running
//!
//! Requires a reachable Docker daemon and host networking (Linux). The
//! test self-skips with a printed message when Docker is unreachable, so
//! it stays green on developer laptops without a daemon and runs for real
//! in CI (the `test` job on ubuntu-latest). Run explicitly with:
//!
//! ```text
//! cargo test --test e2e_probe -- --nocapture
//! ```

use std::time::Duration;

use mongod_proxy::{Proxy, serve};
use mongodb::{Client, bson::doc, options::ClientOptions};
use tokio::net::TcpListener;

mod common;
use common::{ReplicaSet, start_replica_set, try_connect_docker};

/// Boxed error type shared with the `common` helpers. Using the same
/// `Send + Sync` bound everywhere lets `?` convert between them without an
/// intermediate `map_err`.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Fallible setup short-circuits through `?`; genuine assertions stay as
/// `assert!`, matching the pattern in `e2e_from_uri.rs` / `e2e_intercept.rs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_selects_primary_from_multi_node_replica_set() -> Result<(), BoxError> {
    // Self-skip on hosts without a reachable daemon.
    let Some(docker) = try_connect_docker().await else {
        return Ok(());
    };

    // ----- 1. Boot a real 3-member replica set -----
    let rs = start_replica_set(&docker).await?;
    eprintln!("replica set up on loopback ports {:?}", rs.ports());

    // Panic-safe teardown: fires even if an assertion below panics.
    let cleanup_handle = rs.cleanup_handle();
    let cleanup_guard = scopeguard::guard(cleanup_handle, |h| {
        // Drop can't be async; spawn and rely on the runtime to outlive us.
        // The happy path awaits an explicit shutdown at the end.
        tokio::spawn(async move {
            let _ = h.shutdown().await;
        });
    });

    // ----- 2. Identify the current primary via the official driver -----
    let original_primary = rs.current_primary_port().await?;
    eprintln!("driver reports primary on 127.0.0.1:{original_primary}");

    // ----- 3. Build the proxy with the primary ordered LAST -----
    //
    // The seed list's earlier entries are secondaries, so the proxy can
    // only forward writes successfully if `select_primary` probes past
    // them to the writable node. This is exactly the multi-host path
    // `MockPrimaryProbe` and the single-node e2e never reach.
    let ordered = rs.ports_primary_last().await?;
    assert_eq!(
        ordered.last().copied(),
        Some(original_primary),
        "test wiring: primary must be ordered last in the seed list"
    );
    build_and_assert_write(&rs, &ordered, "phase1").await?;

    // ----- 4. BONUS: step the primary down and re-select -----
    //
    // Stepping the primary down forces an election; a different member
    // becomes primary. Rebuilding the proxy must now select that new
    // primary — proving selection isn't pinned to a fixed host.
    eprintln!("stepping primary down to force a new election");
    rs.step_down_primary(30).await?;

    let new_primary = wait_for_new_primary(&rs, original_primary).await?;
    eprintln!("new primary elected on 127.0.0.1:{new_primary}");
    assert_ne!(
        new_primary, original_primary,
        "step-down should have moved the primary to a different member"
    );

    // Rebuild with the *new* primary ordered last and verify a write again.
    let ordered_after = rs.ports_primary_last().await?;
    assert_eq!(
        ordered_after.last().copied(),
        Some(new_primary),
        "new primary must be ordered last in the rebuilt seed list"
    );
    build_and_assert_write(&rs, &ordered_after, "phase2").await?;

    // ----- 5. Happy-path teardown -----
    let _ = scopeguard::ScopeGuard::into_inner(cleanup_guard);
    rs.shutdown().await?;
    Ok(())
}

/// Build a proxy over `ordered` (primary last), run it on a random local
/// port, and assert that a WRITE through it succeeds — which can only
/// happen if the proxy selected the writable primary. `tag` disambiguates
/// the per-phase write so the two phases don't collide.
async fn build_and_assert_write(
    rs: &ReplicaSet,
    ordered: &[u16],
    tag: &str,
) -> Result<(), BoxError> {
    let seed_uri = rs.seed_uri(ordered);
    eprintln!("[{tag}] building proxy from seed list {seed_uri}");

    // The multi-host `mongodb://` path probes the seed list and selects
    // the primary — the code path under test.
    let proxy = Proxy::from_uri(&seed_uri).await?;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = listener.local_addr()?.port();
    eprintln!("[{tag}] proxy listening on 127.0.0.1:{proxy_port}");

    let proxy_task = tokio::spawn(async move {
        let _ = serve(listener, proxy.enable_logging()).await;
    });

    // Point the driver at the proxy. `directConnection=true` keeps the
    // driver from running SDAM against the (hello-rewritten) reply, so
    // every op goes straight through the proxy to its selected upstream.
    let driver_uri = format!("mongodb://127.0.0.1:{proxy_port}/?directConnection=true");
    let mut options = ClientOptions::parse(&driver_uri).await?;
    options.server_selection_timeout = Some(Duration::from_secs(15));
    let client = Client::with_options(options)?;

    // The load-bearing assertion: a write only succeeds against the
    // primary. A secondary answers with NotWritablePrimary, so a clean
    // insert proves the proxy forwarded to the elected primary.
    let coll = client
        .database("e2e_probe")
        .collection::<mongodb::bson::Document>("writes");
    let result = coll
        .insert_one(doc! { "phase": tag, "marker": "primary-selection" })
        .await;
    assert!(
        result.is_ok(),
        "[{tag}] write through proxy failed — proxy did not select the primary: {:?}",
        result.err()
    );

    // Read it back so the response path is exercised too.
    let found = coll
        .find_one(doc! { "phase": tag, "marker": "primary-selection" })
        .await?;
    assert!(
        found.is_some(),
        "[{tag}] round-tripped write should be visible via find"
    );

    drop(client);
    tokio::time::sleep(Duration::from_millis(300)).await;
    proxy_task.abort();
    let _ = proxy_task.await;
    Ok(())
}

/// Poll until a primary distinct from `previous` is elected, or time out.
async fn wait_for_new_primary(rs: &ReplicaSet, previous: u16) -> Result<u16, BoxError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        if let Ok(port) = rs.current_primary_port().await
            && port != previous
        {
            return Ok(port);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Err("no new primary was elected after step-down within the timeout".into())
}
