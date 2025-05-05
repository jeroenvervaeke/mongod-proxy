use std::{net::SocketAddr, pin::Pin, sync::Arc};

use futures::{SinkExt, StreamExt};
use tokio::{
    io,
    net::{
        TcpStream, ToSocketAddrs,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use tower_service::Service;

use crate::{
    decoder::{WireDecoder, WireDecoderError},
    encoder::{WireEncoder, WireEncoderError},
    message::Message,
};

pub struct Proxy {
    destination: SocketAddr,
}

impl Proxy {
    pub fn new(destination: SocketAddr) -> Self {
        Self { destination }
    }
}

impl Service<SocketAddr> for Proxy {
    type Response = ProxyClient;
    type Error = ProxyClientForwardError;
    type Future = ProxyClientCreationFuture;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: SocketAddr) -> Self::Future {
        let dst = self.destination.clone();
        ProxyClientCreationFuture(Box::pin(async move { ProxyClient::forward_to(dst).await }))
    }
}

pub struct ProxyClientCreationFuture(
    Pin<Box<dyn Future<Output = Result<ProxyClient, ProxyClientForwardError>> + Send + 'static>>,
);

impl Future for ProxyClientCreationFuture {
    type Output = Result<ProxyClient, ProxyClientForwardError>;

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
    server_reader: FramedRead<OwnedReadHalf, WireDecoder>,
    server_writer: FramedWrite<OwnedWriteHalf, WireEncoder>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyClientForwardError {
    #[error("failed to connect to proxied server: {0}")]
    FailedToConnectToProxiedServer(#[from] io::Error),
}

impl ProxyClient {
    pub async fn forward_to<A: ToSocketAddrs>(addr: A) -> Result<Self, ProxyClientForwardError> {
        let server_stream = TcpStream::connect(addr).await?;
        let (server_reader, server_writer) = server_stream.into_split();

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
