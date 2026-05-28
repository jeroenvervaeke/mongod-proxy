//! A pluggable transparent proxy for the MongoDB wire protocol.
//!
//! `mongod-proxy` accepts MongoDB driver connections, parses the wire-protocol
//! frames on each connection, optionally passes them through a stack of
//! `tower` layers (for logging, inspection, rate limiting, etc.), and
//! forwards them to a real `mongod`. Both modern OP_MSG and legacy
//! OP_QUERY / OP_REPLY frames are supported, including:
//!
//! * fire-and-forget writes (request flagged `moreToCome`)
//! * streaming-SDAM / exhaust cursors (multiple responses per request, each
//!   flagged `moreToCome` until a terminal reply)
//! * checksum-bearing OP_MSG frames
//!
//! # Quick start
//!
//! ```no_run
//! use mongod_proxy::{LogLayer, Proxy, serve};
//! use tokio::net::TcpListener;
//!
//! # async fn run() -> std::io::Result<()> {
//! // Accept driver connections on :27018 and forward to a local mongod on :27017.
//! let listener = TcpListener::bind("127.0.0.1:27018").await?;
//!
//! // Build the upstream factory. `Proxy` is a tower `Service<SocketAddr>` that
//! // produces a fresh `Service<Message>` for every incoming client connection.
//! // The `hello` / `isMaster` rewrite is on by default; opt out via
//! // `.disable_rewrite_hello()` if you want the upstream's real topology
//! // visible to drivers.
//! let proxy = Proxy::new("127.0.0.1", 27017, /* use_tls = */ false)
//!     .layer(LogLayer); // log every parsed request and response
//!
//! serve(listener, proxy).await.unwrap();
//! # Ok(()) }
//! ```
//!
//! If you already have a connection string in hand, use
//! [`Proxy::from_uri`] instead of `Proxy::new`: it handles both
//! `mongodb://host[:port][,host…]/…` and `mongodb+srv://hostname/…`
//! (resolving the SRV record at startup), and picks scheme-appropriate
//! TLS defaults that the URI itself can override via `?tls=true|false`.
//! [`Proxy::from_srv`] remains available for SRV with explicit
//! arguments; the [`srv`] module exposes the lookup itself.
//!
//! # Architecture
//!
//! ```text
//!  Client (driver)  <----TCP---->  mongod-proxy  <----TCP/TLS---->  mongod
//!                                       |
//!                                       v
//!                                Tower service stack
//!                              (e.g. LogLayer -> ProxyClient)
//! ```
//!
//! The library is split into wire-level types (one type per OP code in
//! [`operation`]) and a runtime ([`mod@serve`]) that wires those types onto
//! a `tokio` listener and a tower service stack.

pub mod decoder;
pub mod encoder;
pub mod header;
pub mod ids;
pub mod message;
pub mod op_code;
pub mod operation;
pub mod serve;
pub mod srv;
mod uri;

#[cfg(test)]
mod fixtures;

pub use serve::explain::{
    AggregateTime, AndKind, BoundValue, Collection, CollectionError, Command, Database,
    DatabaseError, Direction, DocsExamined, DocsExaminedError, DocsReturned, DocsReturnedError,
    ErrorLabel, ExplainError, ExplainEvent, ExplainLayer, ExplainParseError, ExplainServerError,
    ExplainSink, ExplainTotals, Filter, Inclusivity, IndexBoundRange, IndexBounds,
    IndexBoundsParseError, IndexFieldKind, IndexName, IndexNameError, KeyPattern, KeyPatternField,
    KeysExamined, KeysExaminedError, MalformedOkShape, Namespace, NamespaceParseError,
    NamespaceParseErrorKind, NegativeDurationError, NodeTime, OtherName, PlanNode, ProjectionKind,
    ReplayStream, RequestIdExhausted, ServerErrorCode, ServerErrorCodeError, ServerErrorCodeName,
    Stage, TracingOnly, UnsupportedShape,
};
pub use serve::{
    log::LogLayer,
    rewrite_hello::{RewriteHelloLayer, RewriteHelloService, RewriteHelloStream},
    serve,
    service::{FromUriError, Proxy},
};
pub use srv::{LookupFailure, SrvHost, SrvResolveError};
pub use uri::ConnectionUriError;
