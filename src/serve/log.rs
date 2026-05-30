//! Tower layer that logs every parsed request and reply.
//!
//! [`LogLayer`] wraps any inner [`Service<Message, Response = St>`] (where
//! `St` is a [`Stream`] of replies) and emits a structured `tracing` event for
//! each request entering the layer and each reply yielded by the response
//! stream.
//!
//! Per-frame events are emitted at `DEBUG` (connection lifecycle is logged
//! separately at `INFO`) and carry only safe scalar fields. Message bodies can
//! contain credentials — SCRAM/PLAIN SASL payloads, query filter values — so
//! the full [`Debug`](std::fmt::Debug) of the [`Message`] is **never** emitted
//! at `INFO`/`DEBUG`. Each per-frame event includes:
//!
//! * `direction` — `"request"` or `"response"`
//! * `op` — `"OP_MSG"` / `"OP_QUERY"` / `"OP_REPLY"`
//! * `command` — the first BSON key of the body (e.g. `"find"`, `"insert"`),
//!   when one is identifiable
//! * `request_id` / `response_id` — message identifiers
//!
//! A full `Debug` view of the [`Message`] is emitted only at `TRACE` level, so
//! it is off by default and must be opted into deliberately. Each request and
//! its streamed responses share a per-request [span][tracing::Span] named
//! `request`, so a reply chain can be correlated back to its request.
//!
//! # Examples
//!
//! ```
//! use mongod_proxy::{LogLayer, Proxy};
//!
//! let proxy = Proxy::new("127.0.0.1", 27017).layer(LogLayer);
//! # let _ = proxy;
//! ```

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::message::Message;
use futures::Stream;
use tower_layer::Layer;
use tower_service::Service;
use tracing::Span;

/// Tower [`Layer`] that wraps a service in [`LogService`].
///
/// `LogLayer` is a unit struct: it has no configuration. If you need
/// per-instance settings (sampling, redaction, log level overrides) build
/// your own layer following the same pattern.
///
/// Like any [`Layer`], `LogLayer` is inert on its own; it only takes effect
/// once added to a service stack (e.g. via `Proxy::layer`).
#[derive(Clone, Default)]
#[must_use]
pub struct LogLayer;

impl<S> Layer<S> for LogLayer {
    type Service = LogService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LogService { service: inner }
    }
}

/// [`Service`] produced by [`LogLayer`].
///
/// Logs requests on the way in and replies on the way out, then delegates
/// to the wrapped inner service. The reply stream is transparently
/// re-wrapped in a [`LoggedStream`] so streamed responses (moreToCome
/// chains) get one event per intermediate reply.
pub struct LogService<S> {
    service: S,
}

impl<S, St, E> Service<Message> for LogService<S>
where
    S: Service<Message, Response = St, Error = E>,
    S::Future: Send + 'static,
    St: Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    E: Send + 'static,
{
    type Response = LoggedStream<St>;
    type Error = E;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, E>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        // Per-request span so a request and its streamed responses correlate.
        let span = tracing::info_span!(
            "request",
            request_id = %req.request_id,
            op = req.operation.op_kind(),
        );
        // Log the request inside the span. The full body goes out only at
        // TRACE, so it stays off by default and never leaks credentials at
        // INFO/DEBUG.
        span.in_scope(|| {
            tracing::debug!(
                direction = "request",
                op = req.operation.op_kind(),
                command = req.operation.command_name().unwrap_or(""),
                request_id = %req.request_id,
                "received request"
            );
            tracing::trace!(direction = "request", ?req, "request body");
        });

        let fut = self.service.call(req);
        Box::pin(async move {
            let inner = fut.await?;
            Ok(LoggedStream { inner, span })
        })
    }
}

/// Wraps a stream of upstream replies and logs each one as it is yielded.
///
/// `LoggedStream` is `Unpin` whenever its inner stream is, so no pin projection
/// (and therefore no `unsafe`) is needed: `Pin::new(&mut self.inner)` is sound
/// because the inner field is `Unpin` and [`Span`] is `Unpin`.
///
/// The captured [`Span`] is the per-request span created in
/// [`LogService::call`]; response events are logged inside it so they correlate
/// with the originating request.
pub struct LoggedStream<St> {
    inner: St,
    span: Span,
}

impl<St, E> Stream for LoggedStream<St>
where
    St: Stream<Item = Result<Message, E>> + Unpin,
{
    type Item = Result<Message, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(message))) => {
                self.span.in_scope(|| {
                    tracing::debug!(
                        direction = "response",
                        op = message.operation.op_kind(),
                        command = message.operation.command_name().unwrap_or(""),
                        request_id = ?message.response_to,
                        response_id = %message.request_id,
                        "received response"
                    );
                    tracing::trace!(direction = "response", ?message, "response body");
                });
                Poll::Ready(Some(Ok(message)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use futures::StreamExt;
    use tracing::field::{Field, Visit};
    use tracing::subscriber::with_default;
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::Layer as SubscriberLayer;
    use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;

    use super::*;
    use crate::ids::RequestId;
    use crate::operation::Operation;
    use crate::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};

    const SECRET: &str = "hunter2supersecretpassword";

    type ReplyStream = futures::stream::Iter<std::vec::IntoIter<Result<Message, Infallible>>>;

    /// A captured tracing event: its level, a flattened dump of every field
    /// (including the message), and whether it fired inside a `request` span.
    #[derive(Clone)]
    struct CapturedEvent {
        level: Level,
        text: String,
        in_request_span: bool,
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<CapturedEvent>>>);

    impl Captured {
        fn events(&self) -> Vec<CapturedEvent> {
            self.0.lock().expect("lock poisoned").clone()
        }
    }

    /// Visitor that flattens every field of an event into a single string.
    struct FieldDump(String);

    impl Visit for FieldDump {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={:?}", field.name(), value));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.push_str(&format!(" {}={}", field.name(), value));
        }
    }

    struct CaptureLayer(Captured);

    impl<S> SubscriberLayer<S> for CaptureLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &Event<'_>, ctx: LayerContext<'_, S>) {
            let mut dump = FieldDump(String::new());
            event.record(&mut dump);
            let in_request_span = ctx
                .event_scope(event)
                .map(|scope| scope.from_root().any(|s| s.name() == "request"))
                .unwrap_or(false);
            self.0.0.lock().expect("lock poisoned").push(CapturedEvent {
                level: *event.metadata().level(),
                text: dump.0,
                in_request_span,
            });
        }
    }

    /// Inner service that replies with exactly one frame echoing the request.
    struct EchoInner;

    impl Service<Message> for EchoInner {
        type Response = ReplyStream;
        type Error = Infallible;
        type Future =
            Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Message) -> Self::Future {
            // Echo the request body straight back as a single reply frame.
            let reply = Message {
                request_id: req.request_id,
                response_to: None,
                operation: req.operation,
            };
            let stream = futures::stream::iter(vec![Ok(reply)]);
            Box::pin(async move { Ok(stream) })
        }
    }

    /// An OP_MSG whose body carries a credential-bearing SASL payload.
    fn sensitive_request() -> Message {
        let body = bson::doc! {
            "saslContinue": 1,
            "payload": format!("p={SECRET}"),
        };
        Message {
            request_id: RequestId::new(7),
            response_to: None,
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: vec![OpMsgSection::Body(body)],
                checksum: None,
            }),
        }
    }

    #[test]
    fn per_frame_events_are_debug_and_omit_secrets() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry()
            .with(CaptureLayer(captured.clone()))
            .with(tracing_subscriber::filter::LevelFilter::DEBUG);

        with_default(subscriber, || {
            futures::executor::block_on(async {
                let mut svc = LogLayer.layer(EchoInner);
                let stream = svc.call(sensitive_request()).await.expect("infallible");
                let frames: Vec<_> = stream.collect().await;
                assert_eq!(frames.len(), 1);
            });
        });

        let events = captured.events();
        assert!(!events.is_empty(), "expected captured events");

        // Both the request and response per-frame events are present.
        assert!(
            events.iter().any(|e| e.text.contains("direction=request")),
            "missing request event"
        );
        assert!(
            events.iter().any(|e| e.text.contains("direction=response")),
            "missing response event"
        );

        for e in &events {
            // Per-frame events fire at DEBUG, never INFO (#51).
            assert_ne!(e.level, Level::INFO, "unexpected INFO event: {}", e.text);
            // No DEBUG-level event may carry the secret; the body view is
            // TRACE-gated and filtered out before it reaches the layer (#39).
            assert!(!e.text.contains(SECRET), "secret leaked: {}", e.text);
            // Events correlate via the per-request span (#41).
            assert!(
                e.in_request_span,
                "event not inside request span: {}",
                e.text
            );
        }
    }

    #[test]
    fn drives_request_response_without_panicking() {
        futures::executor::block_on(async {
            let mut svc = LogLayer.layer(EchoInner);
            let stream = svc.call(sensitive_request()).await.expect("infallible");
            let frames: Vec<_> = stream.collect().await;
            assert_eq!(frames.len(), 1);
        });
    }
}
