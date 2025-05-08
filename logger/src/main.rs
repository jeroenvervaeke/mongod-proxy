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

    let proxy = Proxy::new(
        "autoembeddingtest-shard-00-01.7aoyd.mongodb-qa.net",
        27017,
        true,
    )
    .enable_logging();

    serve(listener, proxy).await.context("run mongodb proxy")?;

    Ok(())
}
