//! Tower layer that logs every parsed request and reply.
//!
//! [`LogLayer`] wraps any inner [`Service<Message, Response = St>`] (where
//! `St` is a [`Stream`] of replies) and emits a structured `tracing::info!`
//! event for each request entering the layer and each reply yielded by the
//! response stream. The events include:
//!
//! * `direction` — `"request"` or `"response"`
//! * `op` — `"OP_MSG"` / `"OP_QUERY"` / `"OP_REPLY"`
//! * `command` — the first BSON key of the body (e.g. `"find"`, `"insert"`),
//!   when one is identifiable
//! * `request_id` / `response_id` — message identifiers
//! * `req` / `message` — full [`Debug`](std::fmt::Debug) of the [`Message`]
//!
//! # Examples
//!
//! ```
//! use mongod_proxy::{LogLayer, Proxy};
//!
//! let proxy = Proxy::new("127.0.0.1", 27017, false).layer(LogLayer);
//! # let _ = proxy;
//! ```

use std::pin::Pin;

use crate::message::Message;
use futures::Stream;
use tower_layer::Layer;
use tower_service::Service;
use tracing::info;

/// Tower [`Layer`] that wraps a service in [`LogService`].
///
/// `LogLayer` is a unit struct: it has no configuration. If you need
/// per-instance settings (sampling, redaction, log level overrides) build
/// your own layer following the same pattern.
#[derive(Clone, Default)]
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

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Message) -> Self::Future {
        info!(
            direction = "request",
            op = req.operation.op_kind(),
            command = req.operation.command_name().unwrap_or(""),
            request_id = %req.request_id,
            ?req,
            "received request"
        );

        let fut = self.service.call(req);
        Box::pin(async move {
            let inner = fut.await?;
            Ok(LoggedStream { inner })
        })
    }
}

/// Wraps a stream of upstream replies and logs each one as it is yielded.
///
/// `LoggedStream` is `Unpin` whenever its inner stream is, so no pin projection
/// (and therefore no `unsafe`) is needed: `Pin::new(&mut self.inner)` is sound
/// because the inner field is `Unpin`.
pub struct LoggedStream<St> {
    inner: St,
}

impl<St, E> Stream for LoggedStream<St>
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
            std::task::Poll::Ready(Some(Ok(message))) => {
                info!(
                    direction = "response",
                    op = message.operation.op_kind(),
                    request_id = ?message.response_to,
                    response_id = %message.request_id,
                    ?message,
                    "received response"
                );
                std::task::Poll::Ready(Some(Ok(message)))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
        }
    }
}
