use std::{net::SocketAddr, pin::Pin, sync::Arc};

use futures::{SinkExt, StreamExt};
use rustls_pki_types::{InvalidDnsNameError, ServerName};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, split},
    net::TcpStream,
    sync::Mutex,
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
};

type BoxedAsyncRead = Pin<Box<dyn AsyncRead + Send + Sync + 'static>>;
type BoxedAsyncWrite = Pin<Box<dyn AsyncWrite + Send + Sync + 'static>>;
type ServerReader = FramedRead<BoxedAsyncRead, WireDecoder>;
type ServerWriter = FramedWrite<BoxedAsyncWrite, WireEncoder>;

pub struct Proxy<L> {
    destination_name: String,
    destination_port: u16,
    tls_connector: Option<Arc<TlsConnector>>,

    proxy_layer: L,
}

impl Proxy<Identity> {
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
    pub fn layer<T>(self, layer: T) -> Proxy<Stack<T, L>> {
        Proxy {
            destination_name: self.destination_name,
            destination_port: self.destination_port,
            tls_connector: self.tls_connector,

            proxy_layer: Stack::new(layer, self.proxy_layer),
        }
    }

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

pub struct ProxyClient {
    inner: Arc<Mutex<ProxyClientInner>>,
}

struct ProxyClientInner {
    server_reader: ServerReader,
    server_writer: ServerWriter,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyClientForwardError {
    #[error("failed to connect to proxied server: {0}")]
    FailedToConnectToProxiedServer(io::Error),
    #[error("invalid server name: {0}")]
    InvalidServerName(InvalidDnsNameError),
    #[error("tls handshake failed: {0}")]
    TlsHandshake(io::Error),
}

impl ProxyClient {
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

impl Service<Message> for ProxyClient {
    type Response = Message;
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
        ProxyClientRequestFuture(Box::pin(async move {
            let mut inner = inner.lock().await;
            inner.server_writer.send(req).await?;
            let response = inner
                .server_reader
                .next()
                .await
                .ok_or(ProxyClientRequestError::EndOfStream)??;
            Ok(response)
        }))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyClientRequestError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("end of stream")]
    EndOfStream,
    #[error("wire encode error: {0}")]
    WireEncode(#[from] WireEncoderError),
    #[error("wire decode error: {0}")]
    WireDecode(#[from] WireDecoderError),
}

pub struct ProxyClientRequestFuture(
    Pin<Box<dyn Future<Output = Result<Message, ProxyClientRequestError>> + Send + 'static>>,
);

impl Future for ProxyClientRequestFuture {
    type Output = Result<Message, ProxyClientRequestError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
