use std::{fmt::Display, marker::PhantomData, net::SocketAddr, pin::Pin};

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

pub mod log;
pub mod service;

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("failed to accept incoming connection: {0}")]
    Accept(#[from] std::io::Error),
}

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

pub struct ServeFuture(Pin<Box<dyn Future<Output = Result<(), ServeError>> + Send + 'static>>);

impl Future for ServeFuture {
    type Output = Result<(), ServeError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
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
    pub async fn run(mut self) -> Result<(), ServeError> {
        loop {
            let (client_stream, addr) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    error!(error = %e, "failed to accept incoming connection");
                    continue;
                }
            };

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
    #[error("failed to forward request to server: {0}")]
    ForwardToRequestServer(E),
    #[error("failed to forward response to client: {0}")]
    ForwardToResponseClient(#[from] WireEncoderError),
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
            .map_err(AcceptClientError::ForwardToRequestServer)?;

        // Forward every reply the upstream produces for this request. In the
        // common case there is exactly one. In streaming-SDAM / exhaust mode
        // the upstream emits multiple replies (each with moreToCome) and we
        // must shuttle every one to the client until the terminal reply.
        while let Some(resp) = response_stream.next().await {
            let resp = resp.map_err(AcceptClientError::ForwardToRequestServer)?;
            client_writer.send(resp).await?;
        }
    }

    Ok(())
}
