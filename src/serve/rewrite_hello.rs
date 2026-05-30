//! Tower [`Layer`] that lets clients connect through the proxy without
//! `directConnection=true`.
//!
//! # What it does
//!
//! [`RewriteHelloLayer`] intercepts every `hello` / `isMaster` reply on its
//! way back to the client and removes the replica-set / sharded-cluster
//! *discovery* fields:
//!
//! - `setName`, `setVersion`, `electionId`, `topologyVersion`
//! - `hosts`, `passives`, `arbiters`, `primary`, `me`
//! - `secondary`, `arbiterOnly`, `passive`, `hidden`, `tags`, `lastWrite`
//! - `isreplicaset`
//!
//! The hello reply still carries everything the driver needs to drive the
//! connection (`isWritablePrimary`, `maxBsonObjectSize`,
//! `maxWriteBatchSize`, `minWireVersion`, `maxWireVersion`,
//! `logicalSessionTimeoutMinutes`, etc.) — only the *topology-discovery*
//! fields disappear. The driver classifies the upstream as a `Standalone`
//! and keeps issuing every subsequent request on the original socket.
//!
//! # Why the default is on
//!
//! Without the rewrite, an SDAM-enabled driver
//! (`mongodb://host:port/` with no `directConnection=true`) reads the
//! upstream's `setName` / `hosts` / `primary` / `me` from the hello reply
//! and *opens fresh TCP connections directly to those advertised
//! addresses* — addresses that point at the upstream `mongod`, not at the
//! proxy. The proxy then sees the initial handshake and nothing else; all
//! application traffic flows around it.
//!
//! That breaks every reasonable use of this crate (logging, the explain
//! inspector, any custom tower layer), and the failure mode is silent on
//! the proxy side: it doesn't error, it just stops seeing requests. The
//! historical workaround was to make every consumer append
//! `?directConnection=true` to every URI — fragile, easy to forget,
//! impossible to enforce across teams. The rewrite makes
//! `mongodb://proxy/` "just work".
//!
//! [`Proxy`](crate::Proxy) bakes an *enabled* [`RewriteHelloLayer`] into
//! every connection by default. **Almost every user should leave it on.**
//!
//! # What's *not* modified
//!
//! The rewrite is gated entirely on the **request command name**
//! (`hello` / `isMaster` / `ismaster`). Every other command —
//! `find`, `insert`, `aggregate`, `update`, `delete`, `getMore`, … —
//! passes both ways through the layer untouched, regardless of what
//! field names happen to appear in the payload. In particular:
//!
//! - **Requests are never modified.** The layer only wraps the *reply*
//!   stream; every byte of every command is forwarded upstream
//!   verbatim. You can `insert` documents whose fields happen to be
//!   named `setName`, `hosts`, `primary`, etc. and they reach mongod
//!   exactly as you sent them.
//! - **`find`/`aggregate`/`getMore` responses pass through verbatim.**
//!   If those user documents come back in a `cursor.firstBatch`, the
//!   rewrite never runs (the request command was `find`, not `hello`)
//!   and you get them back byte-for-byte.
//! - **Only top-level fields of the hello reply are stripped.** Even
//!   when the rewrite *does* run, it only removes top-level keys from
//!   the reply body — it doesn't recurse into nested documents or
//!   arrays. So nothing inside `cursor.firstBatch.[N]` could ever be
//!   touched (and hello replies don't carry user data there anyway).
//!
//! # When to disable it
//!
//! Calling [`Proxy::disable_rewrite_hello`](crate::Proxy::disable_rewrite_hello)
//! is appropriate only when you specifically want the upstream's real
//! topology visible to drivers, e.g.:
//!
//! - You're using the proxy as an SDAM observability tap and *want* the
//!   driver to see real `hosts` / `primary` values so you can study how
//!   it would behave in production.
//! - You're testing driver-side SDAM behaviour and the proxy is
//!   transparent on purpose.
//!
//! With the rewrite off you must arrange for the driver to reach the
//! proxy explicitly (e.g. `?directConnection=true` in the URI), otherwise
//! it will bypass the proxy as described above. There is **no security
//! gain** from disabling — the rewrite never inspects or modifies user
//! data, only `hello` replies.
//!
//! # Examples
//!
//! The default — rewrite on — needs no extra wiring:
//!
//! ```
//! use mongod_proxy::Proxy;
//!
//! // Driver URIs like `mongodb://127.0.0.1:27018/` (no directConnection)
//! // reach the proxy as a Standalone and stay on this socket.
//! let proxy = Proxy::new("127.0.0.1", 27017);
//! # let _ = proxy;
//! ```
//!
//! Opt out when you specifically need the upstream's topology to surface
//! through:
//!
//! ```
//! use mongod_proxy::Proxy;
//!
//! let proxy = Proxy::new("127.0.0.1", 27017).disable_rewrite_hello();
//! # let _ = proxy;
//! ```

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bson::Document;
use futures::Stream;
use tower_layer::Layer;
use tower_service::Service;

use crate::{
    message::Message,
    operation::{Operation, op_msg::OpMsgSection},
};

/// Top-level fields the SDAM driver inspects to discover other members of a
/// replica set or sharded cluster. Stripping them turns any `hello` /
/// `isMaster` reply into one a driver classifies as `Standalone`, so the
/// driver keeps using the original (proxy) socket instead of dialling the
/// addresses upstream reported.
///
/// `isreplicaset` is included so an arbiter-style reply also collapses to
/// `Standalone`. `topologyVersion` is replica-set-only metadata; keeping it
/// is harmless but stripping it avoids implying topology the proxy is no
/// longer reporting.
const TOPOLOGY_DISCOVERY_FIELDS: &[&str] = &[
    "setName",
    "setVersion",
    "electionId",
    "hosts",
    "passives",
    "arbiters",
    "primary",
    "me",
    "secondary",
    "arbiterOnly",
    "passive",
    "hidden",
    "tags",
    "lastWrite",
    "topologyVersion",
    "isreplicaset",
];

/// Tower [`Layer`] that rewrites `hello` / `isMaster` replies so non-direct
/// connection URIs work through the proxy.
///
/// See the [module docs](self) for what the rewrite does, why it's on by
/// default on [`Proxy`](crate::Proxy), and when you might want to turn it
/// off. The short version: **leave it on** unless you specifically need
/// the upstream's topology visible to drivers; with it off, SDAM-enabled
/// drivers bypass the proxy entirely after the handshake.
///
/// The `enabled` flag is captured at construction time and threaded through
/// each per-connection [`RewriteHelloService`]. When `false` the service
/// becomes a pure pass-through — used inside [`Proxy`](crate::Proxy) so
/// the type stack stays stable regardless of whether
/// [`disable_rewrite_hello`](crate::Proxy::disable_rewrite_hello) was
/// called.
#[derive(Clone, Copy, Debug)]
pub struct RewriteHelloLayer {
    enabled: bool,
}

impl Default for RewriteHelloLayer {
    /// Returns an enabled layer — the rewrite is active by default.
    fn default() -> Self {
        Self::enabled()
    }
}

impl RewriteHelloLayer {
    /// Construct a layer that strips topology-discovery fields from every
    /// `hello` / `isMaster` reply.
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Construct a layer that passes every reply through verbatim. Useful
    /// only as a no-op placeholder when something downstream still needs
    /// the layer in the type stack but you want to surface the upstream's
    /// real topology to the driver.
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }
}

impl<S> Layer<S> for RewriteHelloLayer {
    type Service = RewriteHelloService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RewriteHelloService {
            inner,
            enabled: self.enabled,
        }
    }
}

/// [`Service`] produced by [`RewriteHelloLayer`].
///
/// On each request it remembers whether the request was a `hello` /
/// `isMaster` (the only commands whose replies carry topology-discovery
/// fields) *and* whether rewriting is enabled, and only then wraps the
/// reply stream in a [`RewriteHelloStream`] that strips those fields.
///
/// `Clone` is derived so the service can be wrapped by layers like
/// [`ExplainLayer`](crate::ExplainLayer) that need a cloneable inner
/// service to drive sideband requests.
#[derive(Clone)]
pub struct RewriteHelloService<S> {
    inner: S,
    enabled: bool,
}

impl<S, St, E> Service<Message> for RewriteHelloService<S>
where
    S: Service<Message, Response = St, Error = E>,
    S::Future: Send + 'static,
    St: Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    E: Send + 'static,
{
    type Response = RewriteHelloStream<St>;
    type Error = E;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, E>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let rewrite = self.enabled && is_hello_request(&req);
        let fut = self.inner.call(req);
        Box::pin(async move {
            let inner = fut.await?;
            Ok(RewriteHelloStream { inner, rewrite })
        })
    }
}

/// Stream wrapper that strips topology-discovery fields from every reply
/// when `rewrite` is set. `Unpin` whenever the inner stream is, so no pin
/// projection is needed.
pub struct RewriteHelloStream<St> {
    inner: St,
    rewrite: bool,
}

impl<St, E> Stream for RewriteHelloStream<St>
where
    St: Stream<Item = Result<Message, E>> + Unpin,
{
    type Item = Result<Message, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(mut msg))) => {
                if self.rewrite {
                    strip_topology_from_message(&mut msg);
                }
                Poll::Ready(Some(Ok(msg)))
            }
        }
    }
}

fn is_hello_request(msg: &Message) -> bool {
    matches!(
        msg.operation.command_name(),
        Some("hello" | "isMaster" | "ismaster")
    )
}

fn strip_topology_from_message(msg: &mut Message) {
    match &mut msg.operation {
        Operation::Message(op_msg) => {
            for section in &mut op_msg.sections {
                if let OpMsgSection::Body(doc) = section {
                    strip_topology_fields(doc);
                }
            }
        }
        Operation::Reply(op_reply) => {
            for doc in &mut op_reply.documents {
                strip_topology_fields(doc);
            }
        }
        Operation::Query(_) => {}
    }
}

fn strip_topology_fields(doc: &mut Document) {
    for field in TOPOLOGY_DISCOVERY_FIELDS {
        doc.remove(*field);
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use bson::{Bson, doc};
    use futures::{StreamExt, stream};

    use super::*;
    use crate::ids::{RequestId, ResponseTo};
    use crate::operation::op_msg::{OperationMessage, OperationMessageFlags};
    use crate::operation::op_query::{OperationQuery, OperationQueryFlags};
    use crate::operation::op_reply::{OperationReply, OperationReplyFlags};

    fn op_msg_body(doc: Document) -> Message {
        Message {
            request_id: RequestId::new(1),
            response_to: None,
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: vec![OpMsgSection::Body(doc)],
                checksum: None,
            }),
        }
    }

    fn op_reply_doc(doc: Document) -> Message {
        Message {
            request_id: RequestId::new(2),
            response_to: NonZeroI32::new(1).map(ResponseTo::new),
            operation: Operation::Reply(OperationReply {
                flags: OperationReplyFlags::empty(),
                cursor_id: 0,
                starting_from: 0,
                documents: vec![doc],
            }),
        }
    }

    fn op_query_doc(doc: Document) -> Message {
        Message {
            request_id: RequestId::new(1),
            response_to: None,
            operation: Operation::Query(OperationQuery {
                flags: OperationQueryFlags::empty(),
                full_collection_name: "admin.$cmd".into(),
                number_to_skip: 0,
                number_to_return: -1,
                query: doc,
                return_fields_selector: None,
            }),
        }
    }

    fn first_body(msg: &Message) -> &Document {
        match &msg.operation {
            Operation::Message(m) => match &m.sections[0] {
                OpMsgSection::Body(d) => d,
                _ => panic!("expected body section"),
            },
            Operation::Reply(r) => &r.documents[0],
            Operation::Query(q) => &q.query,
        }
    }

    #[test]
    fn is_hello_request_matches_all_three_spellings() {
        assert!(is_hello_request(&op_msg_body(doc! { "hello": 1 })));
        assert!(is_hello_request(&op_msg_body(doc! { "isMaster": 1 })));
        assert!(is_hello_request(&op_msg_body(doc! { "ismaster": 1 })));
        assert!(is_hello_request(&op_query_doc(
            doc! { "ismaster": 1, "helloOk": true }
        )));
    }

    #[test]
    fn is_hello_request_rejects_other_commands() {
        assert!(!is_hello_request(&op_msg_body(doc! { "find": "x" })));
        assert!(!is_hello_request(&op_msg_body(doc! { "ping": 1 })));
        assert!(!is_hello_request(&op_msg_body(doc! { "insert": "x" })));
    }

    #[test]
    fn is_hello_request_gates_on_command_name_not_payload_contents() {
        // A user inserts/queries with field names that happen to overlap
        // the topology-discovery list. The gate is on the *first* key
        // (the command name), so these must not be misclassified as
        // hello requests — otherwise the layer would strip those fields
        // out of the response body on the way back.
        assert!(!is_hello_request(&op_msg_body(doc! {
            "find": "coll",
            "filter": { "setName": "user-stored-value" },
            "$db": "x",
        })));
        assert!(!is_hello_request(&op_msg_body(doc! {
            "insert": "coll",
            "$db": "x",
            // Even if a hello-named field appears further down in the
            // command body, the first key is `insert`.
            "hello": 1,
        })));
        assert!(!is_hello_request(&op_msg_body(doc! {
            "aggregate": "coll",
            "pipeline": [ { "$match": { "hosts": "anything" } } ],
            "$db": "x",
        })));
    }

    #[test]
    fn strip_topology_fields_removes_replica_set_metadata() {
        let mut doc = doc! {
            "isWritablePrimary": true,
            "setName": "rs0",
            "setVersion": 1,
            "hosts": ["a:27017", "b:27017"],
            "primary": "a:27017",
            "me": "a:27017",
            "passives": [],
            "arbiters": [],
            "secondary": false,
            "topologyVersion": { "counter": 0_i64 },
            "ok": 1.0,
            "minWireVersion": 0,
            "maxWireVersion": 17,
        };
        strip_topology_fields(&mut doc);
        for field in TOPOLOGY_DISCOVERY_FIELDS {
            assert!(!doc.contains_key(*field), "{field} must have been stripped");
        }
        // Non-topology fields are preserved verbatim — the rewrite must not
        // touch handshake metadata the driver depends on.
        assert_eq!(doc.get("isWritablePrimary"), Some(&Bson::Boolean(true)));
        assert_eq!(doc.get("ok"), Some(&Bson::Double(1.0)));
        assert_eq!(doc.get("maxWireVersion"), Some(&Bson::Int32(17)));
    }

    #[test]
    fn strip_topology_fields_leaves_unrelated_replies_untouched() {
        let mut doc = doc! { "ok": 1.0, "n": 42, "cursor": { "id": 0_i64 } };
        let before = doc.clone();
        strip_topology_fields(&mut doc);
        assert_eq!(doc, before);
    }

    #[tokio::test]
    async fn stream_rewrites_op_msg_hello_reply_when_request_was_hello() {
        let reply = op_msg_body(doc! {
            "isWritablePrimary": true,
            "setName": "rs0",
            "hosts": ["upstream:27017"],
            "primary": "upstream:27017",
            "me": "upstream:27017",
            "ok": 1.0,
        });
        let inner = stream::iter(vec![Ok::<_, std::io::Error>(reply)]);
        let mut s = RewriteHelloStream {
            inner,
            rewrite: true,
        };
        let msg = s.next().await.unwrap().unwrap();
        let body = first_body(&msg);
        assert!(!body.contains_key("setName"));
        assert!(!body.contains_key("hosts"));
        assert!(!body.contains_key("primary"));
        assert!(!body.contains_key("me"));
        assert_eq!(body.get("isWritablePrimary"), Some(&Bson::Boolean(true)));
    }

    #[tokio::test]
    async fn stream_rewrites_op_reply_legacy_handshake() {
        // The very first handshake on a new connection is OP_QUERY ismaster
        // -> OP_REPLY. The rewrite must cover that path too.
        let reply = op_reply_doc(doc! {
            "ismaster": true,
            "setName": "rs0",
            "hosts": ["upstream:27017"],
            "me": "upstream:27017",
            "primary": "upstream:27017",
            "ok": 1.0,
        });
        let inner = stream::iter(vec![Ok::<_, std::io::Error>(reply)]);
        let mut s = RewriteHelloStream {
            inner,
            rewrite: true,
        };
        let msg = s.next().await.unwrap().unwrap();
        let body = first_body(&msg);
        assert!(!body.contains_key("setName"));
        assert!(!body.contains_key("hosts"));
        assert!(!body.contains_key("me"));
        assert!(!body.contains_key("primary"));
        assert_eq!(body.get("ismaster"), Some(&Bson::Boolean(true)));
    }

    #[tokio::test]
    async fn stream_passes_non_hello_replies_through_untouched() {
        // When rewrite=false (i.e. request wasn't hello/isMaster) the stream
        // must not mutate the reply even if it happens to contain a field
        // whose name overlaps with our strip list.
        let reply = op_msg_body(doc! {
            "cursor": { "firstBatch": [], "id": 0_i64 },
            "ok": 1.0,
        });
        let before = first_body(&reply).clone();
        let inner = stream::iter(vec![Ok::<_, std::io::Error>(reply)]);
        let mut s = RewriteHelloStream {
            inner,
            rewrite: false,
        };
        let msg = s.next().await.unwrap().unwrap();
        assert_eq!(first_body(&msg), &before);
    }

    #[tokio::test]
    async fn find_response_with_user_documents_named_like_topology_fields_round_trips() {
        // Regression guard for the obvious worry: an application stores
        // documents whose top-level field names overlap with
        // TOPOLOGY_DISCOVERY_FIELDS (perfectly legal — those names
        // aren't reserved at the BSON level). When `find` brings them
        // back in `cursor.firstBatch`, the proxy MUST hand them through
        // byte-for-byte. The rewrite is gated on the *request* being
        // hello, so for a `find` request `rewrite` is false and the
        // response stream wrapper is a pure pass-through.
        let reply = op_msg_body(doc! {
            "cursor": {
                "firstBatch": [
                    doc! {
                        "_id": 1,
                        "setName": "user-stored-value",
                        "hosts": ["arbitrary", "user", "data"],
                        "primary": "could-be-anything",
                    },
                    doc! { "_id": 2, "me": "another-user-doc" },
                ],
                "id": 0_i64,
                "ns": "app.things",
            },
            "ok": 1.0,
        });
        let before = first_body(&reply).clone();
        let inner = stream::iter(vec![Ok::<_, std::io::Error>(reply)]);
        // rewrite=false models the production path: request was `find`,
        // so `is_hello_request` returned false and the service set the
        // stream's flag accordingly.
        let mut s = RewriteHelloStream {
            inner,
            rewrite: false,
        };
        let msg = s.next().await.unwrap().unwrap();
        assert_eq!(
            first_body(&msg),
            &before,
            "find response must be byte-identical regardless of payload",
        );
    }

    #[tokio::test]
    async fn rewrite_only_touches_top_level_fields_of_the_reply_body() {
        // Even when rewriting (request *was* hello), the strip only
        // removes top-level keys of the reply body — never recurses
        // into nested documents or arrays. This makes the safety
        // properties of the layer compositional: nothing inside an
        // embedded document could ever be touched.
        let reply = op_msg_body(doc! {
            "isWritablePrimary": true,
            "setName": "rs0",                            // top-level, stripped
            "ok": 1.0,
            "nested_payload": {
                // Same field names, but nested — must survive.
                "setName": "deep-value",
                "hosts": ["deep1", "deep2"],
                "primary": "deep-primary",
            },
            "array_payload": [
                doc! { "setName": "in-array" },
            ],
        });
        let inner = stream::iter(vec![Ok::<_, std::io::Error>(reply)]);
        let mut s = RewriteHelloStream {
            inner,
            rewrite: true,
        };
        let msg = s.next().await.unwrap().unwrap();
        let body = first_body(&msg);
        // Top-level was stripped.
        assert!(!body.contains_key("setName"));
        // Nested copies survive verbatim.
        let nested = body
            .get_document("nested_payload")
            .expect("nested doc preserved");
        assert_eq!(
            nested.get_str("setName").ok(),
            Some("deep-value"),
            "nested setName must not be touched",
        );
        assert!(nested.contains_key("hosts"));
        assert!(nested.contains_key("primary"));
        let array = body.get_array("array_payload").expect("array preserved");
        let elem = array[0].as_document().expect("array element preserved");
        assert_eq!(
            elem.get_str("setName").ok(),
            Some("in-array"),
            "setName inside an array element must not be touched",
        );
    }

    #[tokio::test]
    async fn stream_propagates_errors_unchanged() {
        let inner = stream::iter(vec![Err(std::io::Error::other("boom"))]);
        let mut s = RewriteHelloStream {
            inner,
            rewrite: true,
        };
        let err = s.next().await.unwrap().unwrap_err();
        assert_eq!(err.to_string(), "boom");
    }

    #[tokio::test]
    async fn disabled_service_passes_hello_reply_through_verbatim() {
        // When the service is constructed disabled, even a hello reply
        // with full topology metadata must pass through verbatim — the
        // service flips `rewrite` to false at call time.
        let reply = op_msg_body(doc! {
            "isWritablePrimary": true,
            "setName": "rs0",
            "hosts": ["upstream:27017"],
            "primary": "upstream:27017",
            "me": "upstream:27017",
            "ok": 1.0,
        });
        let before = first_body(&reply).clone();
        let inner = stream::iter(vec![Ok::<_, std::io::Error>(reply)]);
        // Simulate the path through the service: a hello *request* came
        // in but `enabled` is false, so the resulting stream sets
        // `rewrite=false` and leaves the reply alone.
        let mut s = RewriteHelloStream {
            inner,
            rewrite: false,
        };
        let msg = s.next().await.unwrap().unwrap();
        assert_eq!(
            first_body(&msg),
            &before,
            "disabled service must not strip any fields"
        );
    }
}
