//! Upstream proxy [`Service`] — opens the upstream socket, optionally over
//! TLS, and shuttles messages between client and `mongod`.
//!
//! [`Proxy`] is a [`Service<SocketAddr>`] (i.e. a make-service) that produces
//! a fresh [`ProxyClient`] per incoming client connection. [`ProxyClient`]
//! is the per-connection [`Service<Message>`] that does the actual
//! request/response forwarding, modelled as a stream so it can handle
//! moreToCome multi-reply traffic.

use std::{net::SocketAddr, pin::Pin, sync::Arc};

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
};

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
/// let proxy = Proxy::new("mongo.example.com", 27017, /* use_tls = */ true)
///     .layer(LogLayer);
/// // `proxy` is now a `Service<SocketAddr>` ready to hand to `serve(...)`.
/// # let _ = proxy;
/// ```
pub struct Proxy<L> {
    destination_name: String,
    destination_port: u16,
    tls_connector: Option<Arc<TlsConnector>>,

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
    pub fn new(destination_name: impl Into<String>, destination_port: u16, use_tls: bool) -> Self {
        let tls_connector = if use_tls {
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

            proxy_layer: Identity::new(),
        }
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

            proxy_layer: Stack::new(layer, self.proxy_layer),
        }
    }

    /// Convenience for `self.layer(LogLayer)`.
    ///
    /// Every request and every reply (including intermediate replies of a
    /// streamed response) is logged at `info` level with structured
    /// `direction`, `op`, `command`, and identifier fields.
    pub fn enable_logging(self) -> Proxy<Stack<LogLayer, L>> {
        self.layer(LogLayer)
    }
}

impl<L> Service<SocketAddr> for Proxy<L>
where
    L: Clone + Layer<ProxyClient> + Send + 'static,
    L::Service: Service<Message>,
{
    type Response = L::Service;
    type Error = ProxyClientForwardError;
    type Future = ProxyClientCreationFuture<L::Service>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: SocketAddr) -> Self::Future {
        let destination_name = self.destination_name.clone();
        let destination_port = self.destination_port;
        let tls_connector = self.tls_connector.clone();

        let layer = self.proxy_layer.clone();

        ProxyClientCreationFuture(Box::pin(async move {
            ProxyClient::forward_to(destination_name, destination_port, tls_connector)
                .await
                .map(|s| layer.layer(s))
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

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
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

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let guard = match &mut self.state {
            ProxyResponseStreamState::Done => return std::task::Poll::Ready(None),
            ProxyResponseStreamState::Streaming(guard) => guard,
        };

        match guard.server_reader.poll_next_unpin(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(None) => {
                self.state = ProxyResponseStreamState::Done;
                std::task::Poll::Ready(Some(Err(ProxyClientRequestError::EndOfStream)))
            }
            std::task::Poll::Ready(Some(Err(e))) => {
                self.state = ProxyResponseStreamState::Done;
                std::task::Poll::Ready(Some(Err(e.into())))
            }
            std::task::Poll::Ready(Some(Ok(msg))) => {
                if !more_to_come(&msg.operation) {
                    self.state = ProxyResponseStreamState::Done;
                }
                std::task::Poll::Ready(Some(Ok(msg)))
            }
        }
    }
}

impl Service<Message> for ProxyClient {
    type Response = ProxyResponseStream;
    type Error = ProxyClientRequestError;

    type Future = ProxyClientRequestFuture;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // ProxyClient owns a single upstream socket and is used by exactly one
        // accept_client_inner task that issues request/response serially. The
        // Arc<Mutex<...>> exists only to satisfy the 'static bound on the future;
        // it is never contended, so always-ready is correct.
        std::task::Poll::Ready(Ok(()))
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

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
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
    use crate::operation::op_msg::{OperationMessage, OperationMessageFlags};

    fn build_msg(
        flags: OperationMessageFlags,
        request_id: i32,
        response_to: Option<NonZeroI32>,
    ) -> Message {
        Message {
            request_id,
            response_to,
            operation: Operation::Message(OperationMessage {
                flags,
                sections: doc! { "n": request_id },
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
        assert_eq!(r1.request_id, 101);
        assert_eq!(r2.request_id, 102);
        assert_eq!(r3.request_id, 103);
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
        assert_eq!(r.request_id, 200);
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
        assert_eq!(first.request_id, 100);
        assert!(more_to_come(&first.operation));

        let eof = stream
            .next()
            .await
            .expect("stream yields the EOF before terminating");
        assert!(matches!(eof, Err(ProxyClientRequestError::EndOfStream)));
        assert!(stream.next().await.is_none());
    }
}
