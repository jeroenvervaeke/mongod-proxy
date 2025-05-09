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

    let proxy = Proxy::connect_to_srv("autoembeddingtest.7aoyd.mongodb-qa.net")
        .await
        .context("resolve host info")?
        .enable_logging();

    serve(listener, proxy).await.context("run mongodb proxy")?;

    Ok(())
}
