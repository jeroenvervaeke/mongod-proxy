use std::{
    net::{IpAddr, SocketAddr}, pin::Pin, sync::Arc
};

use bson::{doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use hickory_resolver::{
    ResolveError, Resolver, config::ResolverConfig, name_server::TokioConnectionProvider,
    proto::rr::RData,
};
use rand::{rng, seq::IndexedRandom};
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

pub struct Proxy<L> {
    hosts: Vec<Host>,
    tls_connector: Option<Arc<TlsConnector>>,

    proxy_layer: L,
}

#[derive(Clone)]
struct Host {
    domain: Option<String>,
    ip: IpAddr,
    port: u16,
}

pub enum ProxyDestination {
    Ip { ip: IpAddr, port: u16 },
    Srv { domain: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyConnectToError {
    #[error("failed to connect to srv: {0}")]
    ConnectToSrv(#[from] ProxyConnectToSrvError),
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyConnectToSrvError {
    #[error("srv lookup failed: {0}")]
    SrvLookup(ResolveError),
    #[error("ip lookup failed: {0}")]
    IpLookup(ResolveError),
    #[error("ip lookup returned no IPs")]
    IpLookupReturnedNoIPs,
    #[error("found no IPs")]
    NoIPs,
}

impl Proxy<Identity> {
    pub async fn connect_to(
        destination: ProxyDestination,
    ) -> Result<Self, ProxyConnectToError> {
        match destination {
            ProxyDestination::Ip { ip, port } => Ok(Self::connect_to_ip(ip, port).await),
            ProxyDestination::Srv { domain } => Ok(Self::connect_to_srv(domain).await?),
        }
    }

    pub async fn connect_to_ip(ip: IpAddr, port: u16) -> Self {
        Self {
            hosts: vec![Host {
                domain: None,
                ip,
                port,
            }],
            tls_connector: None,

            proxy_layer: Identity::new(),
        }
    }

    pub async fn connect_to_srv(
        domain: impl Into<String>,
    ) -> Result<Self, ProxyConnectToSrvError> {
        let domain = domain.into();

        let tls_connector = {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            config.enable_sni = true;

            Some(Arc::new(TlsConnector::from(Arc::new(config))))
        };

        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        let srv_lookup_result = resolver
            .srv_lookup(format!("_mongodb._tcp.{domain}"))
            .await
            .map_err(ProxyConnectToSrvError::SrvLookup)?;
        let mut hosts = vec![];
        for record in srv_lookup_result.as_lookup().record_iter() {
            let srv = match record.data() {
                RData::SRV(s) => s,
                _ => continue,
            };
            let mut host = srv.target().to_utf8();
            // Remove the trailing '.'
            if host.ends_with('.') {
                host.pop();
            }

            let lookup_ip = resolver
                .lookup_ip(&host)
                .await
                .map_err(ProxyConnectToSrvError::IpLookup)?;
            let ip = lookup_ip
                .iter()
                .next()
                .ok_or(ProxyConnectToSrvError::IpLookupReturnedNoIPs)?;
            let port = srv.port();
            hosts.push(Host {
                domain: Some(host),
                ip,
                port,
            });
        }

        if hosts.is_empty() {
            return Err(ProxyConnectToSrvError::NoIPs);
        }

        Ok(Self {
            hosts,
            tls_connector,

            proxy_layer: Identity::new(),
        })
    }
}

impl<L> Proxy<L> {
    pub fn layer<T>(self, layer: T) -> Proxy<Stack<T, L>> {
        Proxy {
            hosts: self.hosts,
            tls_connector: self.tls_connector,

            proxy_layer: Stack::new(layer, self.proxy_layer),
        }
    }

    pub fn enable_logging(self) -> Proxy<Stack<LogLayer, L>> {
        self.layer(LogLayer::new())
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
        let mut rng = rng();
        let destination = self
            .hosts
            .choose(&mut rng)
            .expect("thre is always at least 1 host")
            .to_owned();
        let tls_connector = self.tls_connector.clone();

        let layer = self.proxy_layer.clone();

        ProxyClientCreationFuture(Box::pin(async move {
            ProxyClient::forward_to(destination, tls_connector)
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
    server_reader: FramedRead<Pin<Box<dyn AsyncRead + Send + Sync + 'static>>, WireDecoder>,
    server_writer: FramedWrite<Pin<Box<dyn AsyncWrite + Send + Sync + 'static>>, WireEncoder>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyClientForwardError {
    #[error("invalid socket address: {0}")]
    InvalidSocketAddress(io::Error),
    #[error("socket address not found")]
    SocketAddressNotFound,
    #[error("failed to connect to proxied server: {0}")]
    FailedToConnectToProxiedServer(io::Error),
    #[error("invalid server name: {0}")]
    InvalidServerName(InvalidDnsNameError),
}

impl ProxyClient {
    async fn forward_to(
        destination: Host,
        tls_connector: Option<Arc<TlsConnector>>,
    ) -> Result<Self, ProxyClientForwardError> {
        // open a tcp stream to the server
        let server_stream = TcpStream::connect((destination.ip, destination.port))
            .await
            .map_err(ProxyClientForwardError::FailedToConnectToProxiedServer)?;

        // upgrade the tcp stream if nesseseary
        let (server_reader, server_writer): (
            Pin<Box<dyn AsyncRead + Send + Sync>>,
            Pin<Box<dyn AsyncWrite + Send + Sync>>,
        ) = if let (Some(connector), Some(domain)) = (tls_connector, destination.domain) {
            let domain =
                ServerName::try_from(domain).map_err(ProxyClientForwardError::InvalidServerName)?;

            let tls_stream = connector.connect(domain, server_stream).await.unwrap();
            let (server_reader, server_writer) = split(tls_stream);
            (Box::pin(server_reader), Box::pin(server_writer))
        } else {
            let (server_reader, server_writer) = server_stream.into_split();
            (Box::pin(server_reader), Box::pin(server_writer))
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
        if self.inner.try_lock().is_ok() {
            std::task::Poll::Ready(Ok(()))
        } else {
            std::task::Poll::Pending
        }
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let inner = self.inner.clone();
        ProxyClientRequestFuture(Box::pin(async move {
            let mut inner = inner.lock().await;
            inner.server_writer.send(req).await?;
            let response_result = inner
                .server_reader
                .next()
                .await
                .ok_or(ProxyClientRequestError::EndOfStream)?;
            Ok(response_result?)
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
