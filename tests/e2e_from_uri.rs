//! Real-world end-to-end test for [`Proxy::from_uri`].
//!
//! Reads a MongoDB connection string from the `MONGOD_PROXY_E2E_ATLAS_URI`
//! environment variable (typically populated from a CI secret), spins the
//! proxy up against it via [`Proxy::from_uri`], drives a handful of
//! commands through it with the official [`mongodb`] driver, and asserts
//! they round-trip. The point is to exercise everything the unit tests
//! can't:
//!
//! - the actual DNS SRV lookup for `mongodb+srv://` URIs,
//! - the upstream TLS handshake against the resolved host,
//! - real wire-protocol forwarding under driver-side SDAM
//!   (suppressed by the default [`RewriteHelloLayer`]).
//!
//! ## Skipping
//!
//! Self-skips with a printed line on stderr when the env var is unset,
//! so the test stays green on developer laptops and on forked PRs where
//! the secret isn't available. CI wires the secret via:
//!
//! ```yaml
//! - run: cargo test --workspace --all-targets --all-features
//!   env:
//!     MONGOD_PROXY_E2E_ATLAS_URI: ${{ secrets.MONGOD_PROXY_E2E_ATLAS_URI }}
//! ```
//!
//! ## Running locally
//!
//! ```text
//! MONGOD_PROXY_E2E_ATLAS_URI='mongodb+srv://user:pwd@cluster.foo.mongodb.net/' \
//!     cargo test --test e2e_from_uri -- --nocapture
//! ```

use std::{env, time::Duration};

use futures::TryStreamExt;
use mongod_proxy::{Proxy, serve};
use mongodb::{
    Client,
    bson::doc,
    options::{ClientOptions, Credential},
};
use tokio::net::TcpListener;

const ENV_URI: &str = "MONGOD_PROXY_E2E_ATLAS_URI";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_forwards_traffic_when_built_from_uri_secret() {
    // Self-skip when the secret isn't wired. Forked PRs and local
    // `cargo test` runs hit this path.
    let atlas_uri = match env::var(ENV_URI) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("skipping: {ENV_URI} not set");
            return;
        }
    };

    // ----- 1. Build the proxy directly from the connection string -----
    //
    // Both `mongodb://` and `mongodb+srv://` are valid here; for SRV
    // URIs `from_uri` issues the `_mongodb._tcp.<hostname>` lookup,
    // picks the first record, and configures the upstream socket for
    // TLS (the SRV-spec default).
    let proxy = Proxy::from_uri(atlas_uri.trim())
        .await
        .expect("Proxy::from_uri must accept the secret URI");

    // ----- 2. Bind a local proxy port and start serving -----
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_port = listener.local_addr().unwrap().port();
    eprintln!("proxy listening on 127.0.0.1:{proxy_port}");

    let proxy_task = tokio::spawn(async move {
        let _ = serve(listener, proxy.enable_logging()).await;
    });

    // ----- 3. Build driver options pointing at the proxy ---------------
    //
    // The driver URI we hand to `ClientOptions::parse` deliberately
    // carries NO credentials: if parsing ever panicked (it shouldn't —
    // the URI is statically valid), the panic message would otherwise
    // echo the secret in plaintext, and GitHub Actions' secret masking
    // only matches the exact stored value. Credentials are set on the
    // resulting `ClientOptions` directly — `Credential`'s `Debug` impl
    // is hardcoded to `REDACTED`, so even `{options:?}` is safe.
    //
    // `directConnection=true` keeps the driver from running SDAM
    // against the (rewritten) hello reply.
    let mut options = ClientOptions::parse(format!(
        "mongodb://127.0.0.1:{proxy_port}/?directConnection=true"
    ))
    .await
    .expect("static driver URI must parse");

    if let Some((user, pass)) = extract_user_password(&atlas_uri) {
        // Atlas needs the real credentials to complete SASL upstream.
        // Username always present, password optional (matches MongoDB's
        // own credential parsing).
        options.credential = Some(
            Credential::builder()
                .username(user.to_owned())
                .password(pass.map(str::to_owned))
                .build(),
        );
    }
    // The upstream connect over TLS + the SRV resolution above already
    // burn a few hundred ms; give server selection some headroom over
    // the driver's 30s default to absorb a slow Atlas cold-start.
    options.server_selection_timeout = Some(Duration::from_secs(30));
    let client = Client::with_options(options).expect("build mongodb client");

    // ----- 4. Drive a few representative commands through the proxy --
    //
    // Each command exercises a different part of the wire path:
    //   - ping            → minimal admin round-trip
    //   - hello           → hits the RewriteHelloLayer
    //   - listDatabases   → returns a non-trivial reply we can inspect
    //   - find on a tmp   → write + read round-trip in one collection
    //
    // We don't assert against the *contents* of any reply (those depend
    // on the specific cluster behind the URI); only that every command
    // returns Ok. The proxy succeeds iff every step of the chain —
    // SRV → TLS upstream → wire forwarding → hello rewrite — works.
    let admin = client.database("admin");

    admin
        .run_command(doc! { "ping": 1 })
        .await
        .expect("admin.ping must succeed through the proxy");

    let hello = admin
        .run_command(doc! { "hello": 1 })
        .await
        .expect("admin.hello must succeed through the proxy");
    // RewriteHelloLayer is on by default — these fields must not appear
    // in the reply, regardless of how the upstream is configured. If
    // they leak through, the driver would have re-SDAMed and broken
    // every subsequent call; verifying their absence catches a
    // regression early.
    for stripped in ["setName", "hosts", "primary", "me"] {
        assert!(
            !hello.contains_key(stripped),
            "hello reply still carried `{stripped}` after RewriteHelloLayer ran: {hello:?}",
        );
    }

    let dbs = client
        .list_database_names()
        .await
        .expect("listDatabases must succeed through the proxy");
    eprintln!("listDatabases returned {} databases", dbs.len());

    // ----- 5. Round-trip a document so wire-level read+write paths run -
    //
    // We isolate writes in a per-run db so concurrent test runs don't
    // race, and drop it on the way out. The driver's cursor exercise
    // is what proves the response stream (and the moreToCome path, if
    // the result spills batches) flows back through the proxy.
    let db_name = format!("mongod_proxy_e2e_{}", random_suffix());
    let db = client.database(&db_name);
    let coll = db.collection::<mongodb::bson::Document>("ping");

    coll.insert_one(doc! { "marker": "from_uri-e2e", "n": 1i32 })
        .await
        .expect("insert_one must succeed through the proxy");

    let found: Vec<_> = coll
        .find(doc! { "marker": "from_uri-e2e" })
        .await
        .expect("find must succeed through the proxy")
        .try_collect()
        .await
        .expect("cursor drain must succeed through the proxy");
    assert!(
        !found.is_empty(),
        "round-tripped insert should be visible via find"
    );

    // Best-effort cleanup. We don't assert on this — if the test user
    // lacks dropDatabase permission, the leftover db is named uniquely
    // per run and easy to clean up out of band.
    let _ = db.drop().await;

    // ----- 6. Shut down the proxy -----
    drop(client);
    tokio::time::sleep(Duration::from_millis(200)).await;
    proxy_task.abort();
    let _ = proxy_task.await;
}

/// Pulls `(user, Option<pass>)` out of `mongodb[+srv]://user:pass@host/...`.
///
/// Mirrors the rightmost-`@` rule the URI parser applies, so passwords
/// containing literal `@` survive without percent-decoding. The username
/// is always present in the user-info segment; the password is optional
/// (URIs of the shape `mongodb://user@host` are valid).
///
/// Returns `None` if the URI has no user-info segment at all.
fn extract_user_password(uri: &str) -> Option<(&str, Option<&str>)> {
    let after_scheme = uri.split_once("://").map(|(_, r)| r).unwrap_or(uri);
    let before_query = after_scheme
        .split_once('?')
        .map(|(b, _)| b)
        .unwrap_or(after_scheme);
    let (user_info, _) = before_query.rsplit_once('@')?;
    match user_info.split_once(':') {
        Some((user, pass)) => Some((user, Some(pass))),
        None => Some((user_info, None)),
    }
}

/// 16 hex chars sourced from the nanosecond clock. Cheap, distinct per
/// run, and avoids pulling in another dev-dependency just for a name.
fn random_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:016x}")
}
