# mongod-proxy

A pluggable transparent proxy for the MongoDB wire protocol, written in Rust.

> ## ⚠️ Experimental
>
> **This crate is experimental and unstable.** It has not been audited, is not
> production-ready, and the public API may change at any time without notice.
> Wire-protocol coverage, error handling, and performance characteristics are
> still evolving. Do **not** rely on it for anything that matters (data
> integrity, security, uptime, billing, …). Use at your own risk.
>
> Bug reports, feedback, and PRs are very welcome — but please do not deploy
> this in front of a real database you care about.

## What it does

`mongod-proxy` accepts MongoDB driver connections, parses the wire-protocol
frames on each connection, optionally passes them through a stack of
[`tower`](https://crates.io/crates/tower) layers (for logging, inspection,
rate limiting, query-plan capture, …), and forwards them to a real `mongod`.

Both modern `OP_MSG` and legacy `OP_QUERY` / `OP_REPLY` frames are supported,
including:

- fire-and-forget writes (request flagged `moreToCome`)
- streaming-SDAM / exhaust cursors (multiple responses per request, each
  flagged `moreToCome` until a terminal reply)
- checksum-bearing `OP_MSG` frames

Built-in layers shipping with the crate:

- `LogLayer` — logs every parsed request and response via `tracing`.
- `ExplainLayer` — transparently re-issues every explainable command as
  `explain`, parses the plan tree, and forwards the typed `ExplainEvent` to a
  sink (channel, file, custom observer). See `examples/explain.rs`.
- `RewriteHelloLayer` — strips the replica-set discovery fields (`setName`,
  `hosts`, `primary`, `me`, …) from every `hello` / `isMaster` reply so
  SDAM-enabled drivers keep their traffic on the proxy socket instead of
  reconnecting directly to upstream. **Enabled by default** on `Proxy::new`;
  see [why you should leave it on](#hello--ismaster-rewrite-on-by-default)
  below.

## Example

Accept driver connections on `:27018` and forward to a local `mongod` on
`:27017`, logging every frame:

```rust
use mongod_proxy::{LogLayer, Proxy, serve};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:27018").await?;

    // `Proxy` is a tower `Service<SocketAddr>` that produces a fresh
    // `Service<Message>` for every incoming client connection. The
    // `hello` / `isMaster` rewrite is on by default — driver URIs
    // without `directConnection=true` just work.
    let proxy = Proxy::new("127.0.0.1", 27017, /* use_tls = */ false)
        .layer(LogLayer); // log every parsed request and response

    serve(listener, proxy).await
}
```

Point any MongoDB driver at `mongodb://127.0.0.1:27018/` and traffic flows
through the proxy unchanged, with every frame parsed and logged.

## Connection strings (`mongodb://` and `mongodb+srv://`)

When you already have a MongoDB connection string in hand, hand the whole
thing to `Proxy::from_uri` — both schemes are accepted, no scheme-sniffing
on your side:

```rust
use mongod_proxy::{Proxy, serve};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:27018").await?;

    // `mongodb://` and `mongodb+srv://` both work. For SRV URIs the
    // `_mongodb._tcp.<hostname>` record is resolved at startup and the
    // first advertised host is used as the upstream. TLS defaults match
    // the URI scheme — off for `mongodb://`, on for `mongodb+srv://` —
    // and can be overridden via `?tls=true|false` in the URI itself.
    let proxy = Proxy::from_uri("mongodb+srv://cluster0.foo.mongodb.net/")
        .await?
        .enable_logging();

    serve(listener, proxy).await?;
    Ok(())
}
```

For SRV URIs the proxy is still single-upstream, so subsequent records
are ignored; the default [`hello`
rewrite](#hello--ismaster-rewrite-on-by-default) keeps the client driver
pinned to the proxy socket rather than dialling the other replica-set
members it would otherwise discover. SRV resolution runs once at
construction — restart the process to pick up changes to the records.

Everything else in the URI — user/password, database name, every option
beyond `tls` / `ssl` — is intentionally *dropped*. The proxy is
wire-level; the client driver forwards those options to the upstream
itself in the handshake. The MongoDB `TXT` record (which carries
driver-side `authSource` / `replicaSet` / `loadBalanced` options) is
similarly not fetched.

For callers that don't have a connection string —
`Proxy::new(host, port, use_tls)` and `Proxy::from_srv(hostname, use_tls)`
remain available with explicit arguments.

The `logger` binary picks the URI up via the `MONGOD_PROXY_UPSTREAM_URI`
env var (defaults to `mongodb://localhost:27017/`).

## `hello` / `isMaster` rewrite (on by default)

Without help, an SDAM-enabled MongoDB driver
(`mongodb://host:port/` with **no** `directConnection=true`) doesn't stay
on the connection it just opened. The first thing it does is send
`hello` / `isMaster`, read the topology fields from the reply
(`setName`, `hosts`, `primary`, `me`, `passives`, `arbiters`), and
*open fresh TCP connections directly to those addresses*. Against a
real replica set, those addresses point to the upstream `mongod`, not
the proxy — so the proxy sees the handshake and then nothing else.
Every tower layer on the stack (logging, explain, custom middleware)
silently stops seeing traffic.

`Proxy::new` mitigates this by baking a `RewriteHelloLayer` into every
connection: every `hello` / `isMaster` reply gets its topology-discovery
fields stripped before it leaves the proxy, so the driver classifies
the upstream as a `Standalone` and keeps issuing requests on the
original socket. Application-level metadata (`maxBsonObjectSize`,
`maxWireVersion`, `logicalSessionTimeoutMinutes`, …) is preserved
verbatim.

**Almost every user should leave the default on.** Opt out with
`.disable_rewrite_hello()` only when you specifically need the
upstream's real topology visible to drivers — e.g. testing
driver-side SDAM behaviour against the proxy, or using the proxy as a
transparent observability tap. With the rewrite off you must arrange
for the driver to reach the proxy explicitly (typically
`?directConnection=true` in the URI), otherwise it will bypass the
proxy as described above.

A runnable example that captures executed query plans lives at
[`examples/explain.rs`](examples/explain.rs):

```bash
cargo run --example explain
```

## How it works

```mermaid
flowchart LR
    Client["MongoDB driver"]
    Mongod[("mongod")]

    subgraph Proxy["mongod-proxy (per connection)"]
        direction TB
        Decoder["Wire decoder<br/>OP_MSG / OP_QUERY / OP_REPLY"]
        Stack["Tower service stack<br/>LogLayer · ExplainLayer · user layers"]
        Upstream["Upstream client<br/>TCP / TLS"]
        Decoder --> Stack --> Upstream
        Upstream -- "reply (incl. streamed moreToCome)" --> Stack
        Stack -- "observed / mutated frames" --> Decoder
    end

    Client -- "TCP" --> Decoder
    Upstream -- "TCP / TLS" --> Mongod
    Mongod -- "reply" --> Upstream
    Decoder -- "reply" --> Client
```

For each accepted client connection, the proxy:

1. **Decodes** the inbound byte stream into typed wire-protocol `Message`s
   (one type per OP code, in the [`operation`] module).
2. **Passes each `Message`** through the configured tower service stack. Layers
   can inspect, log, mutate, or short-circuit the request, and they see every
   response — including each frame of a streamed `moreToCome` exchange.
3. **Forwards** the resulting request to upstream `mongod` over TCP or TLS,
   and streams every reply back to the client.

Because the library is a `tower::Service<SocketAddr>` factory, you can compose
it with any `tower::Layer`, mix it with your own middleware, or embed it in a
larger application.

## Crate layout

- `mongod-proxy/` — the library crate.
- `logger/` — small standalone binary that proxies and logs (workspace
  member).
- `examples/explain.rs` — runnable explain-plan inspector.
- `tests/e2e_*.rs` — end-to-end tests that boot a real `mongod` in Docker
  via [`atlas-local`](https://crates.io/crates/atlas-local). They self-skip
  when Docker is unreachable.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
