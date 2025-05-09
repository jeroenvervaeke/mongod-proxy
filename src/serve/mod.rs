use std::{fmt::Display, marker::PhantomData, net::SocketAddr, num::NonZeroI32, pin::Pin};

use bson::{DateTime, doc, oid::ObjectId};
use futures::sink::SinkExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite};
use tower_service::Service;
use tracing::error;

use crate::{
    decoder::WireDecoder,
    encoder::{WireEncoder, WireEncoderError},
    message::Message,
    operation::{
        Operation,
        op_msg::{OperationMessage, OperationMessageFlags},
    },
};

pub mod log;
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
        process_id: ObjectId::new(),
        _marker: PhantomData,
    }
}

pub struct Serve<M, ME, S, E> {
    listener: TcpListener,
    make_service: M,
    process_id: ObjectId,
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
                    let process_id = self.process_id.clone();

                    tokio::spawn(accept_client(service, process_id, client_stream));
                }
                Err(e) => println!("couldn't get client: {:?}", e),
            }
        }
    }
}

async fn accept_client<S, E>(service: S, process_id: ObjectId, client_stream: TcpStream)
where
    S: Service<Message, Response = Message, Error = E> + Send + 'static,
    S::Future: Send,
    E: Display + Send + 'static,
{
    if let Err(e) = accept_client_inner(service, process_id, client_stream).await {
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
    process_id: ObjectId,

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

    while let Some(client_result) = client_reader.next().await {
        match client_result {
            Ok(client_req) => {
                let response = match handle_hello(&client_req, process_id) {
                    Some(hello_response) => {
                        service
                            .call(client_req)
                            .await
                            .map_err(AcceptClientError::ForwardToRequestServer)?;
                        hello_response
                    }
                    None => service
                        .call(client_req)
                        .await
                        .map_err(AcceptClientError::ForwardToRequestServer)?,
                };

                client_writer
                    .send(response)
                    .await
                    .map_err(AcceptClientError::ForwardToResponseClient)?;
            }
            Err(e) => {
                error!(?e, "wire decode error");
                break;
            }
        }
    }

    Ok(())
}

fn handle_hello(message: &Message, process_id: ObjectId) -> Option<Message> {
    match &message.operation {
        Operation::Query(query)
            if query.full_collection_name == "admin.$cmd"
                && query.query.contains_key("helloOk") =>
        {
            Some(Message {
                request_id: message.request_id + 1_000_000,
                response_to: NonZeroI32::new(message.request_id),
                operation: Operation::Message(OperationMessage {
                    flags: OperationMessageFlags::empty(),
                    sections: doc! {
                        "helloOk": true,
                        "ismaster": true,
                        "topologyVersion": {
                            "processId": process_id,
                            "counter": 0,
                        },
                        "maxBsonObjectSize": 16777216,
                        "maxMessageSizeBytes": 48000000,
                        "maxWriteBatchSize": 100000,
                        "localTime": DateTime::now(),
                        "logicalSessionTimeoutMinutes": 30,
                        "connectionId": 1,
                        "minWireVersion": 0,
                        "maxWireVersion": 17,
                        "readOnly": false,
                        "ok": 1
                    },
                    checksum: None,
                }),
            })
        }
        Operation::Message(mesage) if mesage.sections.contains_key("hello") => Some(Message {
            request_id: message.request_id + 1_000_000,
            response_to: NonZeroI32::new(message.request_id),
            operation: Operation::Message(OperationMessage {
                flags: OperationMessageFlags::empty(),
                sections: doc! {
                    "helloOk": true,
                    "ismaster": true,
                    "topologyVersion": {
                        "processId": process_id,
                        "counter": 0,
                    },
                    "maxBsonObjectSize": 16777216,
                    "maxMessageSizeBytes": 48000000,
                    "maxWriteBatchSize": 100000,
                    "localTime": DateTime::now(),
                    "logicalSessionTimeoutMinutes": 30,
                    "connectionId": 1,
                    "minWireVersion": 0,
                    "maxWireVersion": 17,
                    "readOnly": false,
                    "ok": 1
                },
                checksum: None,
            }),
        }),
        _ => None,
    }
}
