use anyhow::{Context, Result};
use core::net::SocketAddr;
use mongod_proxy::decoder::WireDecoder;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:27017")
        .await
        .context("bind tcp socket")?;

    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                tokio::spawn(accept_client(socket, addr));
            }
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }
}

async fn accept_client(socket: TcpStream, addr: SocketAddr) {
    println!("new client: {}", addr.ip());

    let mut reader = FramedRead::new(socket, WireDecoder::default());

    let message = reader.try_next().await;
    println!("message: {message:#?}");

    println!("done");
}
