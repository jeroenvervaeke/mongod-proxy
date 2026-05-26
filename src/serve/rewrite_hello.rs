//! Tower [`Layer`] that lets clients connect through the proxy without
//! `directConnection=true`.
//!
//! When a MongoDB driver opens a connection *without* `directConnection=true`,
//! it runs Server Discovery and Monitoring: it sends `hello` / `isMaster` and
//! reads the topology fields from the reply (`setName`, `hosts`, `primary`,
//! `me`, `passives`, `arbiters`) to learn the real replica-set members. It
//! then opens new TCP connections **directly** to those addresses, bypassing
//! the proxy entirely.
//!
//! [`RewriteHelloLayer`] intercepts every `hello` / `isMaster` reply and
//! strips those discovery fields so the driver classifies the upstream as a
//! `Standalone` and keeps all traffic on the proxy socket. Without this
//! layer, drivers must use `mongodb://host:port/?directConnection=true` to
//! reach the proxy at all (against any replica-set or mongos upstream).
//!
//! # Examples
//!
//! ```
//! use mongod_proxy::{Proxy, RewriteHelloLayer};
//!
//! // Driver URIs like `mongodb://127.0.0.1:27018/` (no directConnection)
//! // now reach the proxy instead of bypassing it.
//! let proxy = Proxy::new("127.0.0.1", 27017, false).layer(RewriteHelloLayer);
//! # let _ = proxy;
//! ```
//!
//! Or via the convenience method on [`Proxy`](crate::Proxy):
//!
//! ```
//! use mongod_proxy::Proxy;
//!
//! let proxy = Proxy::new("127.0.0.1", 27017, false).rewrite_hello();
//! # let _ = proxy;
//! ```

use std::pin::Pin;

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
/// connection URIs work through the proxy. See the [module docs](self) for
/// details.
#[derive(Clone, Copy, Debug, Default)]
pub struct RewriteHelloLayer;

impl<S> Layer<S> for RewriteHelloLayer {
    type Service = RewriteHelloService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RewriteHelloService { inner }
    }
}

/// [`Service`] produced by [`RewriteHelloLayer`].
///
/// On each request it remembers whether the request was a `hello` /
/// `isMaster` (the only commands whose replies carry topology-discovery
/// fields) and, if so, wraps the reply stream in a [`RewriteHelloStream`]
/// that strips those fields from every message it yields.
pub struct RewriteHelloService<S> {
    inner: S,
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

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let rewrite = is_hello_request(&req);
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

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(Some(Ok(mut msg))) => {
                if self.rewrite {
                    strip_topology_from_message(&mut msg);
                }
                std::task::Poll::Ready(Some(Ok(msg)))
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
    async fn stream_propagates_errors_unchanged() {
        let inner = stream::iter(vec![Err(std::io::Error::other("boom"))]);
        let mut s = RewriteHelloStream {
            inner,
            rewrite: true,
        };
        let err = s.next().await.unwrap().unwrap_err();
        assert_eq!(err.to_string(), "boom");
    }
}
