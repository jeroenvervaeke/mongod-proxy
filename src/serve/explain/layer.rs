//! Tower [`Layer`] + [`Service`] that wraps any `Service<Message>` to
//! capture explain output for explainable client commands.
//!
//! # Preconditions
//!
//! - The inner `Service<Message>` MUST serialise calls. Stacking
//!   `ExplainLayer` under `tower::buffer::Buffer` or any fan-out layer
//!   that issues concurrent calls against `ProxyClient`'s upstream mutex
//!   will deadlock (rule 22).
//! - The outer `Service::call` future is NOT cancellation-safe. From the
//!   moment `call` is invoked until the returned [`ReplayStream`] is
//!   fully drained, the future MUST NOT be dropped — cancellation during
//!   `inner.call(req).await` tears a wire frame on the upstream socket;
//!   cancellation after the stream resolves leaves a stale reply on the
//!   socket (rule 21).

use std::collections::VecDeque;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::task::{Context, Poll};

use futures::Stream;
use futures::stream::StreamExt;
use tower_layer::Layer;
use tower_service::Service;

use crate::ids::{ExplainRequestId, RequestId};
use crate::message::Message;

use super::build::{BuildExplainOutcome, build_explain};
use super::classify::classify;
use super::error::{ExplainError, ExplainParseError, RequestIdExhausted};
use super::model::{Command, ExplainEvent};
use super::parse::{i64_ms_to_duration, parse_reply_doc, to_plan_node};
use super::sink::{ExplainSink, TracingOnly};
use super::wire::RawExplainReply;

/// Tower [`Layer`] for the explain inspector. Default sink is
/// [`TracingOnly`] (events only emitted via `tracing`); use
/// [`with_sink`](ExplainLayer::with_sink) to wire a typed sink.
#[derive(Clone, Debug, Default)]
pub struct ExplainLayer<Sk: Clone = TracingOnly> {
    sink: Sk,
}

impl ExplainLayer<TracingOnly> {
    /// Creates an explain layer with the default [`TracingOnly`] sink.
    pub fn new() -> Self {
        Self { sink: TracingOnly }
    }
}

impl<Sk: Clone> ExplainLayer<Sk> {
    /// Creates an explain layer that emits captured events to `sink`.
    pub fn with_sink(sink: Sk) -> Self {
        Self { sink }
    }
}

/// Per-connection service produced by [`ExplainLayer`].
///
/// `next_request_id` is wrapped in [`Arc`] so the service can be cloned
/// into a `'static` boxed future and every clone keeps allocating ids
/// from the same shared counter. `AtomicI32` is not `Copy`, so a non-`Arc`
/// field would not survive the clone.
pub struct ExplainService<S, Sk> {
    inner: S,
    sink: Sk,
    next_request_id: Arc<AtomicI32>,
}

impl<S: Clone, Sk: Clone> Clone for ExplainService<S, Sk> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            sink: self.sink.clone(),
            next_request_id: self.next_request_id.clone(),
        }
    }
}

impl<S, Sk: Clone> Layer<S> for ExplainLayer<Sk> {
    type Service = ExplainService<S, Sk>;
    fn layer(&self, inner: S) -> Self::Service {
        ExplainService {
            inner,
            sink: self.sink.clone(),
            // Seed at -1 so the first compare_exchange decrement yields
            // -2 (strictly negative, satisfies alloc_request_id's guard).
            // Driver-issued ids are typically non-negative, so negative
            // ids stay disjoint by convention until exhaustion (~2.1B
            // requests on a single connection).
            next_request_id: Arc::new(AtomicI32::new(-1)),
        }
    }
}

impl<S, Sk, St, E> Service<Message> for ExplainService<S, Sk>
where
    S: Service<Message, Response = St, Error = E> + Clone + Send + 'static,
    S::Future: Send + 'static,
    St: Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    Sk: ExplainSink<E> + Clone + Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
{
    type Response = ReplayStream<E>;
    type Error = E;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, E>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), E>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let mut inner = self.inner.clone();
        let sink = self.sink.clone();
        let counter = self.next_request_id.clone();
        Box::pin(async move {
            let replies = handle_request(&mut inner, &sink, &counter, req).await?;
            Ok(ReplayStream {
                inner: replies,
                _err: PhantomData,
            })
        })
    }
}

/// Buffered replies for one client request.
pub(crate) type Replies = VecDeque<Message>;

/// Stream returned to the client side that replays the buffered replies
/// in FIFO order. `Unpin` and `Send` whenever `Message` is.
pub struct ReplayStream<E> {
    inner: Replies,
    _err: PhantomData<fn() -> E>,
}

// PhantomData<E> would force E: Unpin to make ReplayStream Unpin, but `E`
// is the inner error type and not used at runtime. Use `fn() -> E` so the
// PhantomData itself is always Unpin regardless of `E`.
impl<E> Stream for ReplayStream<E> {
    type Item = Result<Message, E>;
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        Poll::Ready(this.inner.pop_front().map(Ok))
    }
}

/// Drain a reply stream into a [`Replies`] buffer. Takes the stream by
/// value so it is guaranteed to be dropped at end of scope (releasing
/// any upstream mutex guard held by the stream — load-bearing per rule
/// 20).
async fn drain_stream<St, E>(mut stream: St) -> Result<Replies, E>
where
    St: Stream<Item = Result<Message, E>> + Unpin,
{
    let mut out = VecDeque::with_capacity(1);
    while let Some(msg) = stream.next().await {
        out.push_back(msg?);
    }
    Ok(out)
}

/// Allocate a strictly-negative [`ExplainRequestId`] from a per-connection
/// atomic counter. Refuses to cross zero or wrap to `i32::MAX`.
fn alloc_request_id(c: &AtomicI32) -> Result<ExplainRequestId, RequestIdExhausted> {
    let mut cur = c.load(Ordering::Relaxed);
    loop {
        if cur >= 0 || cur == i32::MIN {
            return Err(RequestIdExhausted);
        }
        let next = cur - 1;
        match c.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => {
                // The guard above proves `next < 0`, so `try_new` cannot
                // fail in practice. Map the would-be validation error to
                // `RequestIdExhausted` rather than `.expect()` so the
                // function stays panic-free even if the newtype's
                // predicate is tightened later.
                return ExplainRequestId::try_new(next).map_err(|_| RequestIdExhausted);
            }
            Err(observed) => cur = observed,
        }
    }
}

/// Core orchestration for one client request. Drives the inner service
/// twice (original request, then sideband explain), drops each stream
/// before issuing the next call (rule 20 enforcement), and dispatches
/// the result through [`emit_or_log`].
///
/// The classify/build phase runs *before* the request is moved into
/// `inner.call(req)` so the typed `ClassifiedRequest` (which borrows
/// `req`) is dropped before `req` itself is consumed.
async fn handle_request<S, Sk, St, E>(
    inner: &mut S,
    sink: &Sk,
    counter: &AtomicI32,
    req: Message,
) -> Result<Replies, E>
where
    S: Service<Message, Response = St, Error = E>,
    St: Stream<Item = Result<Message, E>> + Unpin,
    Sk: ExplainSink<E>,
    E: std::error::Error + Send + Sync + 'static,
{
    let client_request_id = req.request_id;

    // Phase 1: classify + build explain. Borrows `req`; drops before
    // we consume `req` below.
    type Prepared<E> = (
        Command,
        Option<ExplainRequestId>,
        Result<Message, ExplainError<E>>,
    );
    let prepared: Option<Prepared<E>> = classify(&req).map(|plan| {
        let (rid, result) = match alloc_request_id(counter) {
            Err(e) => (None, Err(ExplainError::RequestIdExhausted(e))),
            Ok(rid) => match build_explain(&plan, rid) {
                BuildExplainOutcome::Built(msg) => (Some(rid), Ok(*msg)),
                BuildExplainOutcome::UnsupportedShape(r) => {
                    (Some(rid), Err(ExplainError::UnsupportedShape(r)))
                }
            },
        };
        (plan.into_command(), rid, result)
    });

    // Phase 2: forward original request. Stream is dropped at end of
    // this block, releasing any upstream guard before the explain call.
    let replies = {
        let stream = inner.call(req).await?;
        drain_stream(stream).await?
    };

    // Phase 3: run explain if prepared.
    let Some((command, explain_request_id, build_outcome)) = prepared else {
        return Ok(replies);
    };
    let result = match build_outcome {
        Err(prebuilt_err) => Err(prebuilt_err),
        Ok(explain_msg) => {
            run_explain(
                inner,
                command.clone(),
                explain_msg,
                client_request_id,
                explain_request_id,
            )
            .await
        }
    };
    emit_or_log(sink, &command, result);
    Ok(replies)
}

/// Pure orchestration of the sideband explain. No `tracing`, no sink —
/// returns either the typed event or a typed [`ExplainError<E>`].
async fn run_explain<S, St, E>(
    inner: &mut S,
    command: Command,
    explain_msg: Message,
    client_request_id: RequestId,
    explain_request_id: Option<ExplainRequestId>,
) -> Result<ExplainEvent, ExplainError<E>>
where
    S: Service<Message, Response = St, Error = E>,
    St: Stream<Item = Result<Message, E>> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    let explain_replies = {
        let stream = inner
            .call(explain_msg)
            .await
            .map_err(ExplainError::InnerService)?;
        drain_stream(stream)
            .await
            .map_err(ExplainError::InnerService)?
    };

    let body = extract_body(explain_replies)?;
    let raw = match parse_reply_doc(body)? {
        Ok(r) => r,
        Err(server_err) => return Err(ExplainError::Server(server_err)),
    };
    Ok(raw_into_event(
        command,
        raw,
        client_request_id,
        explain_request_id,
    )?)
}

/// Pop the first reply, unwrap its OP_MSG body, return the body document.
fn extract_body(mut replies: Replies) -> Result<bson::Document, ExplainParseError> {
    let Some(first) = replies.pop_front() else {
        return Err(ExplainParseError::MissingBody);
    };
    let crate::operation::Operation::Message(op_msg) = first.operation else {
        return Err(ExplainParseError::MissingBody);
    };
    op_msg
        .sections
        .into_iter()
        .find_map(crate::operation::op_msg::OpMsgSection::into_body)
        .ok_or(ExplainParseError::MissingBody)
}

/// Map a [`RawExplainReply`] to a public [`ExplainEvent`], parsing the
/// namespace via [`Namespace::parse`](super::model::Namespace::parse) so
/// the typed [`NamespaceParseError`](super::model::NamespaceParseError)
/// survives.
fn raw_into_event(
    command: Command,
    raw: RawExplainReply,
    client_request_id: RequestId,
    explain_request_id: Option<ExplainRequestId>,
) -> Result<ExplainEvent, ExplainParseError> {
    use super::model::{AggregateTime, ExplainTotals, Namespace};

    let namespace = Namespace::parse(raw.query_planner.namespace)?;
    let execution_time = AggregateTime::from(i64_ms_to_duration(
        "executionTimeMillis",
        raw.execution_stats.execution_time_millis,
    )?);
    let plan = to_plan_node(raw.execution_stats.execution_stages, 0)?;
    Ok(ExplainEvent {
        command,
        namespace,
        total: ExplainTotals {
            n_returned: raw.execution_stats.n_returned,
            docs_examined: raw.execution_stats.total_docs_examined,
            keys_examined: raw.execution_stats.total_keys_examined,
            execution_time,
        },
        plan,
        client_request_id,
        explain_request_id,
    })
}

/// Side-effect: tracing + sink dispatch. Unit-testable with a mock sink.
fn emit_or_log<Sk, E>(sink: &Sk, command: &Command, result: Result<ExplainEvent, ExplainError<E>>)
where
    Sk: ExplainSink<E>,
    E: std::error::Error + Send + Sync + 'static,
{
    match result {
        Ok(event) => {
            let total_ms = std::time::Duration::from(event.total.execution_time).as_millis() as u64;
            tracing::info!(
                target: "mongod_proxy::serve::explain",
                command = ?event.command,
                db = %event.namespace.database(),
                collection = %event.namespace.collection(),
                n_returned = %event.total.n_returned,
                total_ms,
                "explain",
            );
            // Move event into sink AFTER tracing borrows scalars. DO NOT REORDER.
            sink.record(event);
        }
        Err(err) => {
            match &err {
                ExplainError::InnerService(e) => tracing::warn!(
                    target: "mongod_proxy::serve::explain",
                    command = ?command,
                    error = %e,
                    "explain inner service error",
                ),
                ExplainError::Parse(e) => tracing::warn!(
                    target: "mongod_proxy::serve::explain",
                    command = ?command,
                    error = %e,
                    "explain parse failed",
                ),
                ExplainError::Server(e) => tracing::warn!(
                    target: "mongod_proxy::serve::explain",
                    command = ?command,
                    error = %e,
                    "server rejected explain",
                ),
                ExplainError::RequestIdExhausted(_) => tracing::warn!(
                    target: "mongod_proxy::serve::explain",
                    command = ?command,
                    "explain request id space exhausted",
                ),
                ExplainError::UnsupportedShape(reason) => tracing::debug!(
                    target: "mongod_proxy::serve::explain",
                    command = ?command,
                    ?reason,
                    "skipping explain for unsupported shape",
                ),
            }
            sink.record_error(&err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_request_id_produces_strictly_negative_nonzero() {
        let c = AtomicI32::new(-1);
        for _ in 0..1000 {
            let id = alloc_request_id(&c).expect("alloc succeeds");
            let n: i32 = id.into_inner();
            assert!(n < 0, "id must be strictly negative, got {n}");
            assert_ne!(n, 0, "id must be non-zero");
        }
    }

    #[test]
    fn alloc_request_id_at_floor_returns_exhausted() {
        let c = AtomicI32::new(i32::MIN);
        assert!(alloc_request_id(&c).is_err());
    }

    #[test]
    fn alloc_request_id_at_zero_returns_exhausted() {
        let c = AtomicI32::new(0);
        assert!(alloc_request_id(&c).is_err());
    }

    #[test]
    fn alloc_request_id_positive_seed_returns_exhausted() {
        let c = AtomicI32::new(1);
        assert!(alloc_request_id(&c).is_err());
    }

    #[tokio::test]
    async fn drain_stream_collects_in_order_then_eof() {
        use futures::stream;
        let s = stream::iter(vec![
            Ok::<_, std::io::Error>(synth_msg(1)),
            Ok(synth_msg(2)),
            Ok(synth_msg(3)),
        ]);
        let out = drain_stream(s).await.expect("drain ok");
        assert_eq!(out.len(), 3);
        let ids: Vec<i32> = out.iter().map(|m| m.request_id.into_inner()).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn drain_stream_propagates_first_error() {
        use futures::stream;
        let s = stream::iter(vec![
            Ok::<_, std::io::Error>(synth_msg(1)),
            Err(std::io::Error::other("boom")),
            Ok(synth_msg(2)),
        ]);
        let err = drain_stream(s).await.unwrap_err();
        assert_eq!(err.to_string(), "boom");
    }

    #[tokio::test]
    async fn replay_stream_yields_messages_then_none() {
        let mut replies = VecDeque::new();
        replies.push_back(synth_msg(1));
        replies.push_back(synth_msg(2));
        let mut rs = ReplayStream::<std::io::Error> {
            inner: replies,
            _err: PhantomData,
        };
        let m1 = rs.next().await.unwrap().unwrap();
        let m2 = rs.next().await.unwrap().unwrap();
        assert_eq!(m1.request_id.into_inner(), 1);
        assert_eq!(m2.request_id.into_inner(), 2);
        assert!(rs.next().await.is_none());
    }

    fn synth_msg(req_id: i32) -> Message {
        use crate::ids::RequestId;
        use crate::operation::Operation;
        use crate::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};
        use bson::doc;
        Message {
            request_id: RequestId::new(req_id),
            response_to: None,
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: vec![OpMsgSection::Body(doc! { "n": req_id })],
                checksum: None,
            }),
        }
    }
}
