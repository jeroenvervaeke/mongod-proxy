//! Runtime that drives the proxy: an accept loop, per-connection upstream
//! services, and the tower [`Service`] glue that ties them together.
//!
//! Most consumers only need [`serve`] together with
//! [`Proxy`](crate::Proxy) / [`LogLayer`](crate::LogLayer). The lower-level
//! [`service`] module is exposed for users who want to build their own
//! upstream service.

use std::{
    fmt::Display,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Stream, sink::SinkExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite};
use tower_service::Service;
use tracing::error;

use crate::{
    decoder::{WireDecoder, WireDecoderError},
    encoder::{WireEncoder, WireEncoderError},
    message::Message,
};

pub mod explain;
pub mod log;
pub(crate) mod probe;
pub mod rewrite_hello;
pub mod service;

/// Failure modes for the [`Serve`] future.
///
/// Per-connection failures (parse errors, upstream disconnects, etc.) are
/// logged and do *not* terminate the run; only catastrophic accept-loop
/// failures bubble up here.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// `TcpListener::accept` returned an unrecoverable error.
    #[error("failed to accept incoming connection: {0}")]
    Accept(#[from] std::io::Error),
}

/// Constructs a [`Serve`] that drives `listener` against the upstream
/// `make_service` factory.
///
/// `make_service` is a tower [`Service<SocketAddr>`] that produces a fresh
/// per-connection [`Service<Message>`] for each accepted client. In typical
/// use, that is a [`Proxy`](crate::Proxy) (optionally with a
/// [`LogLayer`](crate::LogLayer) chained on).
///
/// The returned [`Serve`] is a `Future` (also a manually polled struct) that
/// loops forever accepting connections. Drop it to stop accepting.
///
/// # Examples
///
/// ```no_run
/// use mongod_proxy::{LogLayer, Proxy, serve};
/// use tokio::net::TcpListener;
///
/// # async fn run() {
/// let listener = TcpListener::bind("127.0.0.1:27018").await.unwrap();
/// let proxy = Proxy::new("127.0.0.1", 27017, false).layer(LogLayer);
/// serve(listener, proxy).await.unwrap();
/// # }
/// ```
pub fn serve<M, ME, S, E, St>(listener: TcpListener, make_service: M) -> Serve<M, ME, S, E, St>
where
    M: Service<SocketAddr, Error = ME, Response = S>,
    ME: Display,
    S: Service<Message, Response = St, Error = E> + Send + 'static,
    S::Future: Send,
    St: Stream<Item = Result<Message, E>> + Send + Unpin + 'static,
{
    Serve {
        listener,
        make_service,
        _marker: PhantomData,
    }
}

/// Long-running future returned by [`serve`].
///
/// Holds the listener and the upstream make-service. Implements both
/// [`IntoFuture`] (so it can be `.await`ed directly) and exposes a manual
/// [`Serve::run`] for callers who want explicit error handling without going
/// through the boxed-future indirection.
pub struct Serve<M, ME, S, E, St> {
    listener: TcpListener,
    make_service: M,
    _marker: PhantomData<(ME, S, E, St)>,
}

impl<M, ME, S, E, St> IntoFuture for Serve<M, ME, S, E, St>
where
    M: Service<SocketAddr, Error = ME, Response = S> + Send + 'static,
    M::Future: Send,
    ME: Display + Send + 'static,
    S: Service<Message, Response = St, Error = E> + Send + 'static,
    S::Future: Send,
    St: Stream<Item = Result<Message, E>> + Send + Unpin + 'static,
    E: Display + Send + 'static,
{
    type Output = Result<(), ServeError>;

    type IntoFuture = ServeFuture;

    fn into_future(self) -> Self::IntoFuture {
        ServeFuture(Box::pin(async move { self.run().await }))
    }
}

/// Concrete boxed future returned by [`Serve::into_future`].
///
/// Hand-rolled rather than using `BoxFuture` so the type appears in
/// documentation and call sites without an opaque `impl Future`.
pub struct ServeFuture(Pin<Box<dyn Future<Output = Result<(), ServeError>> + Send + 'static>>);

impl Future for ServeFuture {
    type Output = Result<(), ServeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

impl<M, ME, S, E, St> Serve<M, ME, S, E, St>
where
    M: Service<SocketAddr, Error = ME, Response = S>,
    ME: Display + Send + 'static,
    M::Future: Send + 'static,
    S: Service<Message, Response = St, Error = E> + Send + 'static,
    S::Future: Send,
    St: Stream<Item = Result<Message, E>> + Send + Unpin + 'static,
    E: Display + Send + 'static,
{
    /// Runs the accept loop until the listener returns an error.
    ///
    /// For each accepted TCP connection the upstream service is built in a
    /// dedicated tokio task so a slow upstream connect cannot stall the
    /// accept loop. Once the upstream service is ready, the per-connection
    /// forwarding loop runs in the same spawned task. Per-connection
    /// errors are logged via `tracing::error!` and never bubble up.
    ///
    /// # Errors
    ///
    /// Returns [`ServeError::Accept`] when `TcpListener::accept` itself
    /// fails. Tokio internally retries transient `EAGAIN`, so anything that
    /// surfaces here indicates the listening socket is broken (e.g. file
    /// descriptor closed, kernel resource exhaustion). Callers that want to
    /// keep serving across such failures must reopen the listener and call
    /// [`serve`] again.
    pub async fn run(mut self) -> Result<(), ServeError> {
        loop {
            let (client_stream, addr) = self.listener.accept().await.map_err(|e| {
                error!(error = %e, "failed to accept incoming connection; shutting down");
                ServeError::Accept(e)
            })?;

            // Build the upstream service in a dedicated task so a slow upstream
            // connect cannot stall the accept loop.
            let service_fut = self.make_service.call(addr);
            tokio::spawn(async move {
                match service_fut.await {
                    Ok(service) => accept_client(service, client_stream).await,
                    Err(e) => error!(error = %e, %addr, "failed to create upstream service"),
                }
            });
        }
    }
}

async fn accept_client<S, St, E>(service: S, client_stream: TcpStream)
where
    S: Service<Message, Response = St, Error = E> + Send + 'static,
    S::Future: Send,
    St: Stream<Item = Result<Message, E>> + Send + Unpin + 'static,
    E: Display + Send + 'static,
{
    if let Err(e) = accept_client_inner(service, client_stream).await {
        error!(error = %e, "connection terminated");
    }
}

#[derive(Debug, thiserror::Error)]
enum AcceptClientError<E: Display> {
    #[error("failed to decode wire message from client: {0}")]
    DecodeFromClient(#[from] WireDecoderError),
    #[error("upstream service rejected request: {0}")]
    UpstreamRequest(E),
    #[error("upstream service errored while streaming response: {0}")]
    UpstreamResponse(E),
    #[error("failed to forward response to client: {0}")]
    EncodeToClient(#[from] WireEncoderError),
}

async fn accept_client_inner<S, St, E>(
    mut service: S,
    client_stream: TcpStream,
) -> Result<(), AcceptClientError<E>>
where
    S: Service<Message, Response = St, Error = E> + Send + 'static,
    S::Future: Send,
    St: Stream<Item = Result<Message, E>> + Send + Unpin + 'static,
    E: Display + Send + 'static,
{
    let (client_reader, client_writer) = client_stream.into_split();

    let mut client_reader = FramedRead::new(client_reader, WireDecoder::default());
    let mut client_writer = FramedWrite::new(client_writer, WireEncoder::default());

    while let Some(req) = client_reader.next().await {
        let client_req = req?;
        let mut response_stream = service
            .call(client_req)
            .await
            .map_err(AcceptClientError::UpstreamRequest)?;

        // Forward every reply the upstream produces for this request. In the
        // common case there is exactly one. In streaming-SDAM / exhaust mode
        // the upstream emits multiple replies (each with moreToCome) and we
        // must shuttle every one to the client until the terminal reply.
        while let Some(resp) = response_stream.next().await {
            let resp = resp.map_err(AcceptClientError::UpstreamResponse)?;
            client_writer.send(resp).await?;
        }
    }

    Ok(())
}
