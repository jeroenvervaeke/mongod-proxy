use std::env;

use anyhow::{Context, Result};
use mongod_proxy::{Proxy, serve};
use tokio::net::TcpListener;

mod log;

const ENV_LISTEN: &str = "MONGOD_PROXY_LISTEN";
const ENV_UPSTREAM_URI: &str = "MONGOD_PROXY_UPSTREAM_URI";

const DEFAULT_LISTEN: &str = "127.0.0.1:27018";
const DEFAULT_UPSTREAM_URI: &str = "mongodb://localhost:27017/";

#[tokio::main]
async fn main() -> Result<()> {
    log::setup();

    let listen_addr = env::var(ENV_LISTEN).unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let upstream_uri =
        env::var(ENV_UPSTREAM_URI).unwrap_or_else(|_| DEFAULT_UPSTREAM_URI.to_owned());

    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("bind tcp socket on {listen_addr}"))?;

    let proxy = Proxy::from_uri(upstream_uri.trim())
        .await
        .with_context(|| format!("build proxy from {ENV_UPSTREAM_URI}=`{upstream_uri}`"))?
        .enable_logging();

    serve(listener, proxy).await.context("run mongodb proxy")?;

    Ok(())
}
