use std::{net::SocketAddr, str::FromStr};

use anyhow::{Context, Result};
use mongod_proxy::{Proxy, serve};
use tokio::net::TcpListener;

mod log;

#[tokio::main]
async fn main() -> Result<()> {
    log::setup();

    let listener = TcpListener::bind("127.0.0.1:27018")
        .await
        .context("bind tcp socket")?;

    let proxy = Proxy::new(SocketAddr::from_str("127.0.0.1:27017").unwrap()).enable_logging();

    serve(listener, proxy).await.context("run mongodb proxy")?;

    Ok(())
}
