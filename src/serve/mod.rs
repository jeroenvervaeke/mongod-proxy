//! Runtime that drives the proxy: an accept loop, per-connection upstream
//! services, and the tower [`Service`] glue that ties them together.
//!
//! Most consumers only need [`serve`] together with
//! [`Proxy`](crate::Proxy) / [`LogLayer`](crate::LogLayer). The lower-level
//! [`service`] module is exposed for users who want to build their own
//! upstream service.

use std::{
    fmt::Display,
    future::Future,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

use futures::{Stream, sink::SinkExt};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite};
use tower_service::Service;
use tracing::{Instrument, debug, error, info, info_span};

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
#[non_exhaustive]
pub enum ServeError {
    /// `TcpListener::accept` returned an unrecoverable error.
    #[error("failed to accept incoming connection: {0}")]
    Accept(#[from] std::io::Error),
}

/// Process-global allocator for monotonic connection identifiers.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(0);

/// Returns the next monotonically increasing connection id.
///
/// The counter is process-global; it is used purely to tag per-connection
/// tracing spans so log lines from concurrent connections can be correlated.
/// Wrap-around after `u64::MAX` connections is not reachable in practice.
fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
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
/// let proxy = Proxy::new("127.0.0.1", 27017).layer(LogLayer);
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
#[must_use = "Serve is lazy; await it or call run()"]
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
#[must_use]
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
    /// forwarding loop runs in the same spawned task. Each connection runs
    /// under its own tracing span carrying `client_addr` and a monotonic
    /// `conn_id`. Per-connection errors are logged via `tracing::error!` and
    /// never bubble up.
    ///
    /// This loops forever; use [`run_until`](Self::run_until) for a variant
    /// that supports graceful shutdown and connection draining.
    ///
    /// # Errors
    ///
    /// Returns [`ServeError::Accept`] when `TcpListener::accept` itself
    /// fails. Tokio internally retries transient `EAGAIN`, so anything that
    /// surfaces here indicates the listening socket is broken (e.g. file
    /// descriptor closed, kernel resource exhaustion). Callers that want to
    /// keep serving across such failures must reopen the listener and call
    /// [`serve`] again.
    pub async fn run(self) -> Result<(), ServeError> {
        // Delegate to `run_until` with a future that never resolves, so the
        // accept loop runs forever (matching the historical behaviour).
        self.run_until(std::future::pending()).await
    }

    /// Runs the accept loop until either the listener errors or `shutdown`
    /// resolves, then drains in-flight connections.
    ///
    /// This behaves exactly like [`run`](Self::run) while `shutdown` is
    /// pending. Once `shutdown` resolves, the proxy stops accepting new
    /// connections and awaits every already-spawned per-connection task to
    /// run to completion before returning `Ok(())`. In-flight connections are
    /// therefore *drained*, not abruptly aborted: a client with an open
    /// request/response exchange gets to finish it (and is then bounded only
    /// by that connection's own liveness).
    ///
    /// Per-connection tasks are tracked in a [`JoinSet`], which also reaps
    /// completed connections during normal operation so the set does not grow
    /// unbounded over the lifetime of the server.
    ///
    /// `shutdown` can be any `Future<Output = ()>`, e.g. a
    /// [`tokio::signal::ctrl_c`] wrapper, a [`tokio::sync::Notify::notified`]
    /// wait, or a [`tokio::sync::watch`] receiver change. No additional
    /// dependency is required.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mongod_proxy::{Proxy, serve};
    /// use tokio::net::TcpListener;
    ///
    /// # async fn run() {
    /// let listener = TcpListener::bind("127.0.0.1:27018").await.unwrap();
    /// let proxy = Proxy::new("127.0.0.1", 27017);
    /// serve(listener, proxy)
    ///     .run_until(async {
    ///         tokio::signal::ctrl_c().await.ok();
    ///     })
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`ServeError::Accept`] when `TcpListener::accept` itself fails;
    /// see [`run`](Self::run) for the failure semantics. A clean shutdown via
    /// the `shutdown` future returns `Ok(())` after draining.
    pub async fn run_until<F>(mut self, shutdown: F) -> Result<(), ServeError>
    where
        F: Future<Output = ()>,
    {
        let mut connections: JoinSet<()> = JoinSet::new();
        let mut shutdown = std::pin::pin!(shutdown);
        // Once `shutdown` resolves we `break` out of the loop immediately, so
        // it is never polled again after completion (no `Fuse` needed).

        loop {
            tokio::select! {
                () = &mut shutdown => {
                    debug!("shutdown requested; draining in-flight connections");
                    break;
                }
                accepted = self.listener.accept() => {
                    let (client_stream, addr) = accepted.map_err(|e| {
                        error!(error = %e, "failed to accept incoming connection; shutting down");
                        ServeError::Accept(e)
                    })?;

                    let span = info_span!(
                        "connection",
                        client_addr = %addr,
                        conn_id = next_conn_id(),
                    );

                    // Build the upstream service in a dedicated task so a slow
                    // upstream connect cannot stall the accept loop.
                    let service_fut = self.make_service.call(addr);
                    connections.spawn(
                        async move {
                            info!("connection accepted");
                            match service_fut.await {
                                Ok(service) => accept_client(service, client_stream).await,
                                Err(e) => {
                                    error!(error = %e, "failed to create upstream service");
                                }
                            }
                        }
                        .instrument(span),
                    );
                }
                // Reap finished connections as we go so `connections` does not
                // grow without bound. Guarded on non-emptiness because
                // `join_next` resolves immediately to `None` on an empty set,
                // which would otherwise busy-loop this branch.
                Some(_joined) = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        // Drain: wait for every in-flight connection task to finish.
        let drained = connections.len();
        while connections.join_next().await.is_some() {}
        debug!(drained, "all in-flight connections drained");

        Ok(())
    }
}

async fn accept_client<S, St, E>(service: S, client_stream: TcpStream)
where
    S: Service<Message, Response = St, Error = E> + Send + 'static,
    S::Future: Send,
    St: Stream<Item = Result<Message, E>> + Send + Unpin + 'static,
    E: Display + Send + 'static,
{
    match accept_client_inner(service, client_stream).await {
        Ok(()) => info!("connection closed"),
        Err(e) => error!(error = %e, "connection terminated"),
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

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use futures::stream;
    use tokio::{net::TcpStream, sync::Notify};
    use tower_service::Service;

    use super::*;

    /// Empty per-connection upstream service: accepts a `Message` and yields
    /// an empty response stream. Used to exercise the accept/drain loop without
    /// a real mongod.
    #[derive(Clone)]
    struct NoopService;

    impl Service<Message> for NoopService {
        type Response = stream::Empty<Result<Message, Infallible>>;
        type Error = Infallible;
        type Future =
            std::future::Ready<Result<stream::Empty<Result<Message, Infallible>>, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Message) -> Self::Future {
            std::future::ready(Ok(stream::empty()))
        }
    }

    /// Make-service that hands out [`NoopService`] and counts how many
    /// connections it has been asked to build.
    #[derive(Clone)]
    struct CountingMakeService {
        built: Arc<AtomicU64>,
    }

    impl Service<SocketAddr> for CountingMakeService {
        type Response = NoopService;
        type Error = Infallible;
        type Future = std::future::Ready<Result<NoopService, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _addr: SocketAddr) -> Self::Future {
            self.built.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(NoopService))
        }
    }

    /// `next_conn_id` hands out strictly increasing values.
    #[test]
    fn conn_ids_are_monotonic() {
        let a = next_conn_id();
        let b = next_conn_id();
        let c = next_conn_id();
        assert!(a < b, "expected {a} < {b}");
        assert!(b < c, "expected {b} < {c}");
    }

    /// `run_until` returns `Ok(())` once the shutdown future fires, even with
    /// zero connections ever accepted.
    #[tokio::test]
    async fn run_until_exits_on_shutdown_with_no_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let make = CountingMakeService {
            built: Arc::new(AtomicU64::new(0)),
        };

        let notify = Arc::new(Notify::new());
        let server_notify = Arc::clone(&notify);
        let handle = tokio::spawn(async move {
            serve(listener, make)
                .run_until(async move {
                    server_notify.notified().await;
                })
                .await
        });

        // Fire shutdown immediately; the accept loop should exit and drain.
        notify.notify_one();

        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run_until did not return within timeout")
            .expect("server task panicked");
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    /// `run_until` accepts a real client connection, drives it through the
    /// no-op upstream, and then drains cleanly on shutdown.
    #[tokio::test]
    async fn run_until_accepts_then_drains_on_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let built = Arc::new(AtomicU64::new(0));
        let make = CountingMakeService {
            built: Arc::clone(&built),
        };

        let notify = Arc::new(Notify::new());
        let server_notify = Arc::clone(&notify);
        let handle = tokio::spawn(async move {
            serve(listener, make)
                .run_until(async move {
                    server_notify.notified().await;
                })
                .await
        });

        // Connect a client and keep the connection open briefly so the server
        // observes the accept and builds an upstream service.
        let client = TcpStream::connect(local_addr).await.unwrap();

        // Give the accept loop a moment to spawn the connection task.
        for _ in 0..50 {
            if built.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            built.load(Ordering::SeqCst),
            1,
            "make_service should have built exactly one upstream service"
        );

        // Close the client so its connection task can complete, then trigger
        // shutdown and assert the server drains and returns Ok.
        drop(client);
        notify.notify_one();

        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run_until did not drain within timeout")
            .expect("server task panicked");
        assert!(result.is_ok(), "expected Ok after drain, got {result:?}");
    }
}
