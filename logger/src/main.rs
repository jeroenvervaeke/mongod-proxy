use anyhow::{Context, Result};
use futures::sink::SinkExt;
use mongod_proxy::{decoder::WireDecoder, encoder::WireEncoder};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite};

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:27018")
        .await
        .context("bind tcp socket")?;

    loop {
        match listener.accept().await {
            Ok((socket, _addr)) => {
                tokio::spawn(accept_client(socket));
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}

async fn accept_client(client_stream: TcpStream) {
    let (client_reader, client_writer) = client_stream.into_split();

    let mut client_reader = FramedRead::new(client_reader, WireDecoder::default());
    let mut client_writer = FramedWrite::new(client_writer, WireEncoder::default());

    let server_stream = TcpStream::connect("127.0.0.1:27017").await.unwrap();
    let (server_reader, server_writer) = server_stream.into_split();

    let mut server_reader = FramedRead::new(server_reader, WireDecoder::default());
    let mut server_writer = FramedWrite::new(server_writer, WireEncoder::default());

    while let Some(Ok(client_req)) = client_reader.next().await {
        println!("-->\t{client_req:?}");
        server_writer.send(client_req).await.unwrap();
        let response = server_reader.next().await.unwrap().unwrap();
        println!("<--\t{response:?}");
        client_writer.send(response).await.unwrap();
    }
}
