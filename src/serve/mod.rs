use std::{fmt::Display, marker::PhantomData, net::SocketAddr, pin::Pin};

use futures::sink::SinkExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite};
use tower_service::Service;

use crate::{
    decoder::WireDecoder,
    encoder::{WireEncoder, WireEncoderError},
    message::Message,
};

pub mod service;

#[derive(Debug, thiserror::Error)]
pub enum ServeError<ME: Display> {
    #[error("create client error: {0}")]
    CreateClientError(ME),
}

pub fn serve<M, ME, S, E>(listener: TcpListener, make_service: M) -> Serve<M, ME, S, E>
where
    M: Service<SocketAddr, Error = ME, Response = S>,
    ME: Display,
    S: Service<Message, Response = Message, Error = E> + Send + 'static,
    S::Future: Send,
{
    Serve {
        listener,
        make_service,
        _marker: PhantomData,
    }
}

pub struct Serve<M, ME, S, E> {
    listener: TcpListener,
    make_service: M,
    _marker: PhantomData<(ME, S, E)>,
}

impl<M, ME, S, E> IntoFuture for Serve<M, ME, S, E>
where
    M: Service<SocketAddr, Error = ME, Response = S> + Send + 'static,
    M::Future: Send,
    ME: Display + Send + 'static,
    S: Service<Message, Response = Message, Error = E> + Send + 'static,
    S::Future: Send,
    E: Display + Send + 'static,
{
    type Output = Result<(), ServeError<ME>>;

    type IntoFuture = ServeFuture<ME>;

    fn into_future(self) -> Self::IntoFuture {
        ServeFuture(Box::pin(async move { self.run().await }))
    }
}

pub struct ServeFuture<ME: Display>(
    Pin<Box<dyn Future<Output = Result<(), ServeError<ME>>> + Send + 'static>>,
);

impl<ME: Display> Future for ServeFuture<ME> {
    type Output = Result<(), ServeError<ME>>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

impl<M, ME, S, E> Serve<M, ME, S, E>
where
    M: Service<SocketAddr, Error = ME, Response = S>,
    ME: Display,
    S: Service<Message, Response = Message, Error = E> + Send + 'static,
    S::Future: Send,
    E: Display + Send + 'static,
{
    pub async fn run(mut self) -> Result<(), ServeError<ME>> {
        loop {
            match self.listener.accept().await {
                Ok((client_stream, addr)) => {
                    let service = self
                        .make_service
                        .call(addr)
                        .await
                        .map_err(ServeError::CreateClientError)?;
                    tokio::spawn(accept_client(service, client_stream));
                }
                Err(e) => println!("couldn't get client: {:?}", e),
            }
        }
    }
}

async fn accept_client<S, E>(service: S, client_stream: TcpStream)
where
    S: Service<Message, Response = Message, Error = E> + Send + 'static,
    S::Future: Send,
    E: Display + Send + 'static,
{
    if let Err(e) = accept_client_inner(service, client_stream).await {
        eprintln!("error occured, stopping connection. error = {e}")
    }
}

#[derive(Debug, thiserror::Error)]
enum AcceptClientError<E: Display> {
    #[error("failed to forward request to server: {0}")]
    ForwardToRequestServer(E),
    #[error("failed to forward response to client: {0}")]
    ForwardToResponseClient(WireEncoderError),
}

async fn accept_client_inner<S, E>(
    mut service: S,
    client_stream: TcpStream,
) -> Result<(), AcceptClientError<E>>
where
    S: Service<Message, Response = Message, Error = E> + Send + 'static,
    S::Future: Send,
    E: Display + Send + 'static,
{
    let (client_reader, client_writer) = client_stream.into_split();

    let mut client_reader = FramedRead::new(client_reader, WireDecoder::default());
    let mut client_writer = FramedWrite::new(client_writer, WireEncoder::default());

    while let Some(Ok(client_req)) = client_reader.next().await {
        let response = service
            .call(client_req)
            .await
            .map_err(AcceptClientError::ForwardToRequestServer)?;

        client_writer
            .send(response)
            .await
            .map_err(AcceptClientError::ForwardToResponseClient)?;
    }

    Ok(())
}
