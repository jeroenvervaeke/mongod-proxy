//! Upstream proxy [`Service`] — opens the upstream socket, optionally over
//! TLS, and shuttles messages between client and `mongod`.
//!
//! [`Proxy`] is a [`Service<SocketAddr>`] (i.e. a make-service) that produces
//! a fresh [`ProxyClient`] per incoming client connection. [`ProxyClient`]
//! is the per-connection [`Service<Message>`] that does the actual
//! request/response forwarding, modelled as a stream so it can handle
//! moreToCome multi-reply traffic.

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Once},
    task::{Context, Poll},
};

use futures::{SinkExt, Stream, StreamExt};
use rustls_pki_types::{InvalidDnsNameError, ServerName};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, split},
    net::TcpStream,
    sync::{Mutex, OwnedMutexGuard},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore},
};
use tokio_util::codec::{FramedRead, FramedWrite};
use tower_layer::{Identity, Layer, Stack};
use tower_service::Service;

use crate::{
    LogLayer,
    decoder::{WireDecoder, WireDecoderError},
    encoder::{WireEncoder, WireEncoderError},
    message::Message,
    operation::{Operation, op_msg::OperationMessageFlags},
    serve::rewrite_hello::{RewriteHelloLayer, RewriteHelloService},
};

/// Ensures rustls has a usable [`CryptoProvider`](tokio_rustls::rustls::crypto::CryptoProvider).
///
/// rustls 0.23+ refuses to pick a provider when more than one is compiled
/// in (which happens whenever transitive dependencies enable both the `ring`
/// and `aws-lc-rs` features — common in mixed dependency trees). We pick
/// `aws_lc_rs` deterministically here. `install_default` errors after the
/// first successful install, so we ignore the error to be idempotent.
fn install_default_crypto_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

type BoxedAsyncRead = Pin<Box<dyn AsyncRead + Send + Sync + 'static>>;
type BoxedAsyncWrite = Pin<Box<dyn AsyncWrite + Send + Sync + 'static>>;
type ServerReader = FramedRead<BoxedAsyncRead, WireDecoder>;
type ServerWriter = FramedWrite<BoxedAsyncWrite, WireEncoder>;

/// Upstream proxy configuration and make-service.
///
/// Implements [`Service<SocketAddr>`], producing one fresh
/// [`L::Service`](Layer::Service) wrapping a [`ProxyClient`] per call. The
/// type parameter `L` carries the tower [`Layer`] stack applied around the
/// inner [`ProxyClient`]; `Identity` (the default returned by
/// [`Proxy::new`]) applies no layers.
///
/// # Examples
///
/// Build a plain-TCP proxy and wrap a [`LogLayer`] around it:
///
/// ```
/// use mongod_proxy::{LogLayer, Proxy};
///
/// // For the doctest we pass `use_tls = false` to avoid a network-dependent
/// // rustls config; switch to `true` to forward over TLS in real use.
/// let proxy = Proxy::new("mongo.example.com", 27017, /* use_tls = */ false)
///     .layer(LogLayer);
/// // `proxy` is now a `Service<SocketAddr>` ready to hand to `serve(...)`.
/// # let _ = proxy;
/// ```
pub struct Proxy<L> {
    destination_name: String,
    destination_port: u16,
    tls_connector: Option<Arc<TlsConnector>>,
    /// When true, every per-connection service has a [`RewriteHelloLayer`]
    /// inserted *between* the user-supplied layer stack and the inner
    /// [`ProxyClient`], so `hello` / `isMaster` replies get their
    /// topology-discovery fields stripped. On by default; flip via
    /// [`disable_rewrite_hello`](Self::disable_rewrite_hello).
    rewrite_hello: bool,

    proxy_layer: L,
}

impl Proxy<Identity> {
    /// Creates a new proxy that forwards every incoming client connection
    /// to `destination_name:destination_port`.
    ///
    /// When `use_tls` is true the upstream socket is wrapped in a `rustls`
    /// TLS client using the standard `webpki-roots` trust anchors and SNI
    /// derived from `destination_name`. When false the upstream socket is
    /// plain TCP.
    ///
    /// The resulting proxy has the `hello` / `isMaster` rewrite **on by
    /// default** so SDAM-enabled drivers (`mongodb://host:port/` with no
    /// `directConnection=true`) classify the proxy as a `Standalone` and
    /// keep every request on this socket instead of dialling the
    /// upstream addresses they would otherwise discover. Almost every
    /// user wants this — see the [`rewrite_hello`](crate::serve::rewrite_hello)
    /// module for the full rationale and the list of fields stripped.
    /// Opt out with [`disable_rewrite_hello`](Proxy::disable_rewrite_hello)
    /// only when you specifically need the upstream's topology visible to
    /// drivers.
    pub fn new(destination_name: impl Into<String>, destination_port: u16, use_tls: bool) -> Self {
        let tls_connector = if use_tls {
            install_default_crypto_provider();
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            config.enable_sni = true;

            Some(Arc::new(TlsConnector::from(Arc::new(config))))
        } else {
            None
        };

        Self {
            destination_name: destination_name.into(),
            destination_port,
            tls_connector,
            rewrite_hello: true,

            proxy_layer: Identity::new(),
        }
    }

    /// Creates a new proxy whose upstream is the first host returned by
    /// an SRV lookup for `srv_hostname` — i.e. the `mongodb+srv://`
    /// connection-string convention.
    ///
    /// Queries `_mongodb._tcp.<srv_hostname>` (see [`crate::srv`]) and
    /// uses the first record as the upstream `host:port`. Per the SRV
    /// spec, TLS to the upstream defaults to enabled; pass `use_tls =
    /// false` only when forwarding to a test deployment that does not
    /// terminate TLS itself.
    ///
    /// The proxy is single-upstream, so subsequent SRV records are
    /// ignored. The default `hello` / `isMaster` rewrite (see
    /// [`Proxy::new`]) keeps the driver pinned to this socket instead of
    /// trying to dial the other replica-set members.
    ///
    /// SRV resolution happens once, here. If the underlying records
    /// change while the proxy is running, restart the process to
    /// re-resolve.
    ///
    /// # Errors
    ///
    /// See [`crate::srv::SrvResolveError`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mongod_proxy::Proxy;
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// // `mongodb+srv://cluster0.foo.mongodb.net/` → SRV lookup, first host wins.
    /// let proxy = Proxy::from_srv("cluster0.foo.mongodb.net", true).await?;
    /// # let _ = proxy;
    /// # Ok(()) }
    /// ```
    pub async fn from_srv(
        srv_hostname: &str,
        use_tls: bool,
    ) -> Result<Self, crate::srv::SrvResolveError> {
        let hosts = crate::srv::resolve(srv_hostname).await?;
        // `resolve` returns Err(NoRecords) on an empty vec, so first is always Some.
        let first = hosts
            .into_iter()
            .next()
            .expect("srv::resolve guarantees at least one record on Ok");
        Ok(Self::new(first.host, first.port, use_tls))
    }
}

impl<L> Proxy<L> {
    /// Chains another tower [`Layer`] around the inner [`ProxyClient`].
    ///
    /// Layers are applied outer-most last (same convention as tower's
    /// `ServiceBuilder`). Use this to add custom middleware (rate limiting,
    /// auth, redaction, etc.) without writing a new [`Service`].
    pub fn layer<T>(self, layer: T) -> Proxy<Stack<T, L>> {
        Proxy {
            destination_name: self.destination_name,
            destination_port: self.destination_port,
            tls_connector: self.tls_connector,
            rewrite_hello: self.rewrite_hello,

            proxy_layer: Stack::new(layer, self.proxy_layer),
        }
    }

    /// Turns off the default `hello` / `isMaster` rewrite.
    ///
    /// **You probably don't want to call this.** With the rewrite off,
    /// SDAM-enabled drivers read the upstream's `setName` / `hosts` /
    /// `primary` / `me` from the hello reply and *open fresh TCP
    /// connections directly to those advertised addresses* — bypassing
    /// the proxy entirely for everything after the handshake. The proxy
    /// won't error; it just stops seeing requests, silently breaking
    /// every layer in the stack (logging, explain, custom middleware).
    ///
    /// Disabling is appropriate only when you specifically need the
    /// upstream's topology visible to drivers (driver-side SDAM testing,
    /// using the proxy as a transparent observability tap), and you've
    /// arranged for the driver to reach the proxy some other way (e.g.
    /// `?directConnection=true` in the URI).
    ///
    /// See [`RewriteHelloLayer`] for the full rationale and the list of
    /// fields the rewrite strips.
    pub fn disable_rewrite_hello(mut self) -> Self {
        self.rewrite_hello = false;
        self
    }

    /// Convenience for `self.layer(LogLayer)`.
    ///
    /// Every request and every reply (including intermediate replies of a
    /// streamed response) is logged at `info` level with structured
    /// `direction`, `op`, `command`, and identifier fields.
    pub fn enable_logging(self) -> Proxy<Stack<LogLayer, L>> {
        self.layer(LogLayer)
    }

    /// Convenience for `self.layer(ExplainLayer::new())`.
    ///
    /// Captures explainable client commands (`find`, `aggregate`, …) and
    /// emits a typed `tracing::info!` event with the executed plan and
    /// per-stage timing. No user-supplied sink is wired — use
    /// [`enable_explain_with_sink`](Self::enable_explain_with_sink) to
    /// consume typed [`ExplainEvent`](crate::ExplainEvent)s programmatically.
    pub fn enable_explain(
        self,
    ) -> Proxy<Stack<crate::serve::explain::ExplainLayer<crate::serve::explain::TracingOnly>, L>>
    {
        self.layer(crate::serve::explain::ExplainLayer::new())
    }

    /// Convenience for `self.layer(ExplainLayer::with_sink(sink))`.
    ///
    /// `sink` receives a typed [`ExplainEvent`](crate::ExplainEvent) for
    /// every explainable client command and a typed
    /// [`ExplainError`](crate::ExplainError) for every failure. The sink
    /// `Clone`s once per accepted connection — keep it O(1) (refcount or
    /// `Copy`).
    pub fn enable_explain_with_sink<Sk>(
        self,
        sink: Sk,
    ) -> Proxy<Stack<crate::serve::explain::ExplainLayer<Sk>, L>>
    where
        Sk: Clone,
    {
        self.layer(crate::serve::explain::ExplainLayer::with_sink(sink))
    }
}

impl<L> Service<SocketAddr> for Proxy<L>
where
    L: Clone + Layer<RewriteHelloService<ProxyClient>> + Send + 'static,
    L::Service: Service<Message>,
{
    type Response = L::Service;
    type Error = ProxyClientForwardError;
    type Future = ProxyClientCreationFuture<L::Service>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: SocketAddr) -> Self::Future {
        let destination_name = self.destination_name.clone();
        let destination_port = self.destination_port;
        let tls_connector = self.tls_connector.clone();

        let layer = self.proxy_layer.clone();
        // Innermost wrap. When disabled the layer becomes a pass-through
        // (still walks every reply but never mutates), so the type stack
        // stays stable regardless of the toggle.
        let rewrite_layer = if self.rewrite_hello {
            RewriteHelloLayer::enabled()
        } else {
            RewriteHelloLayer::disabled()
        };

        ProxyClientCreationFuture(Box::pin(async move {
            ProxyClient::forward_to(destination_name, destination_port, tls_connector)
                .await
                .map(|s| layer.layer(rewrite_layer.layer(s)))
        }))
    }
}

/// Future returned by `<Proxy as Service<SocketAddr>>::call`.
///
/// Resolves to the per-connection [`Service<Message>`] (typically a
/// layered [`ProxyClient`]) once the upstream socket is fully established.
pub struct ProxyClientCreationFuture<S>(
    Pin<Box<dyn Future<Output = Result<S, ProxyClientForwardError>> + Send + 'static>>,
)
where
    S: Service<Message>;

impl<S> Future for ProxyClientCreationFuture<S>
where
    S: Service<Message>,
{
    type Output = Result<S, ProxyClientForwardError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

/// Per-connection [`Service<Message>`] holding one upstream socket.
///
/// Implements [`Service<Message>`] with `Response = `[`ProxyResponseStream`].
/// Each `call` writes the request to the upstream socket and returns a
/// stream that yields zero or more replies until the upstream signals end
/// of stream (or fewer replies in fire-and-forget mode).
///
/// Construct via [`ProxyClient::forward_to`]; or via [`Proxy::call`] which
/// builds one per accepted client connection.
///
/// `Clone` is cheap (single `Arc::clone`) and exists so middleware layers
/// that need to issue more than one call through the per-connection
/// service (e.g. `ExplainLayer`'s sideband explain) can move a handle
/// into their boxed future.
#[derive(Clone)]
pub struct ProxyClient {
    inner: Arc<Mutex<ProxyClientInner>>,
}

struct ProxyClientInner {
    server_reader: ServerReader,
    server_writer: ServerWriter,
}

/// Failure modes for [`ProxyClient::forward_to`].
#[derive(Debug, thiserror::Error)]
pub enum ProxyClientForwardError {
    /// `TcpStream::connect` to the upstream failed (DNS, refused, etc.).
    #[error("failed to connect to proxied server: {0}")]
    FailedToConnectToProxiedServer(io::Error),
    /// `destination_name` is not a valid DNS name for use with TLS SNI.
    #[error("invalid server name: {0}")]
    InvalidServerName(InvalidDnsNameError),
    /// The TLS handshake itself failed (cert validation, protocol, etc.).
    #[error("tls handshake failed: {0}")]
    TlsHandshake(io::Error),
}

impl ProxyClient {
    /// Opens an upstream TCP (and optionally TLS) socket and wraps it in
    /// the proxy's framed reader / writer pair.
    ///
    /// `destination_name` is used both for DNS resolution and (when
    /// `tls_connector` is `Some`) for SNI. Passing `None` produces a
    /// plain-TCP proxy.
    ///
    /// # Errors
    ///
    /// See [`ProxyClientForwardError`].
    pub async fn forward_to(
        destination_name: String,
        destination_port: u16,
        tls_connector: Option<Arc<TlsConnector>>,
    ) -> Result<Self, ProxyClientForwardError> {
        let addr = format!("{destination_name}:{destination_port}");
        let server_stream = TcpStream::connect(addr)
            .await
            .map_err(ProxyClientForwardError::FailedToConnectToProxiedServer)?;

        let (server_reader, server_writer): (BoxedAsyncRead, BoxedAsyncWrite) =
            if let Some(connector) = tls_connector {
                let domain = ServerName::try_from(destination_name)
                    .map_err(ProxyClientForwardError::InvalidServerName)?;
                let tls_stream = connector
                    .connect(domain, server_stream)
                    .await
                    .map_err(ProxyClientForwardError::TlsHandshake)?;
                let (reader, writer) = split(tls_stream);
                (Box::pin(reader), Box::pin(writer))
            } else {
                let (reader, writer) = server_stream.into_split();
                (Box::pin(reader), Box::pin(writer))
            };

        let server_reader = FramedRead::new(server_reader, WireDecoder::default());
        let server_writer = FramedWrite::new(server_writer, WireEncoder::default());

        Ok(Self {
            inner: Arc::new(Mutex::new(ProxyClientInner {
                server_reader,
                server_writer,
            })),
        })
    }
}

/// Returns true if `op` is an OP_MSG carrying the moreToCome flag.
///
/// On a *request* this means fire-and-forget: the server will not reply.
/// On a *response* it means another reply will follow on the same socket.
fn more_to_come(op: &Operation) -> bool {
    matches!(
        op,
        Operation::Message(m) if m.flags.contains(OperationMessageFlags::MORE_TO_COME)
    )
}

/// Stream of upstream replies for a single client request.
///
/// In the common case this yields exactly one message and then `None`. When
/// the upstream sets `moreToCome` on its reply (streaming SDAM / exhaust
/// cursors), the stream keeps yielding until a terminal message arrives.
/// For fire-and-forget requests the stream is empty.
///
/// The stream owns the upstream mutex guard for its lifetime, which prevents
/// other request/response pairs on the same `ProxyClient` from interleaving
/// with an in-flight streamed reply.
pub struct ProxyResponseStream {
    state: ProxyResponseStreamState,
}

enum ProxyResponseStreamState {
    /// No further reads expected (fire-and-forget request or stream done).
    Done,
    /// Holding the upstream guard; reads from `server_reader`.
    Streaming(OwnedMutexGuard<ProxyClientInner>),
}

impl ProxyResponseStream {
    fn empty() -> Self {
        Self {
            state: ProxyResponseStreamState::Done,
        }
    }

    fn streaming(guard: OwnedMutexGuard<ProxyClientInner>) -> Self {
        Self {
            state: ProxyResponseStreamState::Streaming(guard),
        }
    }
}

impl Stream for ProxyResponseStream {
    type Item = Result<Message, ProxyClientRequestError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let guard = match &mut self.state {
            ProxyResponseStreamState::Done => return Poll::Ready(None),
            ProxyResponseStreamState::Streaming(guard) => guard,
        };

        match guard.server_reader.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.state = ProxyResponseStreamState::Done;
                Poll::Ready(Some(Err(ProxyClientRequestError::EndOfStream)))
            }
            Poll::Ready(Some(Err(e))) => {
                self.state = ProxyResponseStreamState::Done;
                Poll::Ready(Some(Err(e.into())))
            }
            Poll::Ready(Some(Ok(msg))) => {
                if !more_to_come(&msg.operation) {
                    self.state = ProxyResponseStreamState::Done;
                }
                Poll::Ready(Some(Ok(msg)))
            }
        }
    }
}

impl Service<Message> for ProxyClient {
    type Response = ProxyResponseStream;
    type Error = ProxyClientRequestError;

    type Future = ProxyClientRequestFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // ProxyClient owns a single upstream socket and is used by exactly one
        // accept_client_inner task that issues request/response serially. The
        // Arc<Mutex<...>> exists only to satisfy the 'static bound on the future;
        // it is never contended, so always-ready is correct.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let inner = self.inner.clone();
        let fire_and_forget = more_to_come(&req.operation);
        ProxyClientRequestFuture(Box::pin(async move {
            let mut guard = inner.lock_owned().await;
            guard.server_writer.send(req).await?;
            if fire_and_forget {
                drop(guard);
                Ok(ProxyResponseStream::empty())
            } else {
                Ok(ProxyResponseStream::streaming(guard))
            }
        }))
    }
}

/// Failure modes for an in-flight request against [`ProxyClient`].
#[derive(Debug, thiserror::Error)]
pub enum ProxyClientRequestError {
    /// Underlying socket I/O failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Upstream closed the socket while a reply was still pending.
    #[error("end of stream")]
    EndOfStream,
    /// Encoding the request before sending it upstream failed.
    #[error("wire encode error: {0}")]
    WireEncode(#[from] WireEncoderError),
    /// Decoding an upstream reply failed.
    #[error("wire decode error: {0}")]
    WireDecode(#[from] WireDecoderError),
}

/// Future returned by `<ProxyClient as Service<Message>>::call`.
///
/// Resolves to a [`ProxyResponseStream`] once the request has been written
/// to the upstream and the proxy has acquired the upstream guard. The
/// caller then drains the stream to receive replies.
pub struct ProxyClientRequestFuture(
    Pin<
        Box<
            dyn Future<Output = Result<ProxyResponseStream, ProxyClientRequestError>>
                + Send
                + 'static,
        >,
    >,
);

impl Future for ProxyClientRequestFuture {
    type Output = Result<ProxyResponseStream, ProxyClientRequestError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use bson::doc;
    use futures::StreamExt;
    use tokio::io::{AsyncWriteExt, duplex};
    use tokio_util::bytes::BytesMut;

    use super::*;
    use crate::ids::{RequestId, ResponseTo};
    use crate::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};

    fn build_msg(
        flags: OperationMessageFlags,
        request_id: i32,
        response_to: Option<NonZeroI32>,
    ) -> Message {
        Message {
            request_id: RequestId::new(request_id),
            response_to: response_to.map(ResponseTo::new),
            operation: Operation::Message(OperationMessage {
                flags,
                sections: vec![OpMsgSection::Body(doc! { "n": request_id })],
                checksum: None,
            }),
        }
    }

    /// Build a `ProxyClient` whose upstream socket is a `duplex` pipe so tests
    /// can script byte-level reply sequences without touching the network.
    fn proxy_against_duplex() -> (ProxyClient, tokio::io::DuplexStream) {
        let (upstream_side, proxy_side) = duplex(64 * 1024);
        let (proxy_read, proxy_write) = tokio::io::split(proxy_side);

        let server_reader = FramedRead::new(
            Box::pin(proxy_read) as BoxedAsyncRead,
            WireDecoder::default(),
        );
        let server_writer = FramedWrite::new(
            Box::pin(proxy_write) as BoxedAsyncWrite,
            WireEncoder::default(),
        );

        let client = ProxyClient {
            inner: Arc::new(Mutex::new(ProxyClientInner {
                server_reader,
                server_writer,
            })),
        };
        (client, upstream_side)
    }

    fn encode_messages(messages: &[Message]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        for m in messages {
            m.write_bytes(&mut buf).expect("encode succeeds");
        }
        buf.to_vec()
    }

    #[tokio::test]
    async fn streaming_response_yields_until_terminal_reply() {
        let (mut client, mut upstream) = proxy_against_duplex();

        let replies = vec![
            build_msg(OperationMessageFlags::MORE_TO_COME, 101, NonZeroI32::new(1)),
            build_msg(OperationMessageFlags::MORE_TO_COME, 102, NonZeroI32::new(1)),
            build_msg(OperationMessageFlags::empty(), 103, NonZeroI32::new(1)),
        ];
        let bytes = encode_messages(&replies);
        // Push the scripted replies onto the upstream side. Spawn so the
        // proxy can begin reading concurrently.
        tokio::spawn(async move {
            upstream.write_all(&bytes).await.expect("upstream write");
        });

        let req = build_msg(OperationMessageFlags::empty(), 1, None);
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .expect("call succeeds");

        let r1 = stream.next().await.expect("first reply").expect("ok");
        let r2 = stream.next().await.expect("second reply").expect("ok");
        let r3 = stream.next().await.expect("third reply").expect("ok");
        assert_eq!(r1.request_id, RequestId::new(101));
        assert_eq!(r2.request_id, RequestId::new(102));
        assert_eq!(r3.request_id, RequestId::new(103));
        assert!(more_to_come(&r1.operation));
        assert!(more_to_come(&r2.operation));
        assert!(!more_to_come(&r3.operation));

        // After the terminal reply the stream must complete.
        assert!(
            stream.next().await.is_none(),
            "stream must end after non-MORE_TO_COME reply"
        );
    }

    #[tokio::test]
    async fn single_reply_response_completes_after_one_message() {
        let (mut client, mut upstream) = proxy_against_duplex();

        let replies = vec![build_msg(
            OperationMessageFlags::empty(),
            200,
            NonZeroI32::new(1),
        )];
        let bytes = encode_messages(&replies);
        tokio::spawn(async move {
            upstream.write_all(&bytes).await.expect("upstream write");
        });

        let req = build_msg(OperationMessageFlags::empty(), 1, None);
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .expect("call succeeds");

        let r = stream.next().await.expect("reply").expect("ok");
        assert_eq!(r.request_id, RequestId::new(200));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn fire_and_forget_request_returns_empty_stream() {
        let (mut client, _upstream) = proxy_against_duplex();

        // Request carries MORE_TO_COME -> server will not reply, proxy must
        // return an empty response stream rather than blocking on a read.
        let req = build_msg(OperationMessageFlags::MORE_TO_COME, 1, None);
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .expect("call succeeds");

        assert!(
            stream.next().await.is_none(),
            "fire-and-forget request must produce no reply"
        );
    }

    #[tokio::test]
    async fn upstream_eof_mid_stream_surfaces_as_end_of_stream_error() {
        let (mut client, mut upstream) = proxy_against_duplex();

        let req = build_msg(OperationMessageFlags::empty(), 1, None);
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .expect("call succeeds");

        // Send one MORE_TO_COME reply then close the upstream socket without
        // ever sending the terminal reply.
        let partial = encode_messages(&[build_msg(
            OperationMessageFlags::MORE_TO_COME,
            100,
            NonZeroI32::new(1),
        )]);
        upstream.write_all(&partial).await.expect("write reply");
        upstream.shutdown().await.expect("shutdown");
        drop(upstream);

        let first = stream.next().await.expect("first reply").expect("ok reply");
        assert_eq!(first.request_id, RequestId::new(100));
        assert!(more_to_come(&first.operation));

        let eof = stream
            .next()
            .await
            .expect("stream yields the EOF before terminating");
        assert!(matches!(eof, Err(ProxyClientRequestError::EndOfStream)));
        assert!(stream.next().await.is_none());
    }
}
