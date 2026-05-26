use std::env;

use anyhow::{Context, Result};
use mongod_proxy::{Proxy, serve};
use tokio::net::TcpListener;

mod log;

const ENV_LISTEN: &str = "MONGOD_PROXY_LISTEN";
const ENV_UPSTREAM_HOST: &str = "MONGOD_PROXY_UPSTREAM_HOST";
const ENV_UPSTREAM_PORT: &str = "MONGOD_PROXY_UPSTREAM_PORT";
const ENV_TLS: &str = "MONGOD_PROXY_TLS";

const DEFAULT_LISTEN: &str = "127.0.0.1:27018";
const DEFAULT_UPSTREAM_HOST: &str = "localhost";
const DEFAULT_UPSTREAM_PORT: u16 = 27017;
const DEFAULT_TLS: bool = false;

#[tokio::main]
async fn main() -> Result<()> {
    log::setup();

    let listen_addr = env::var(ENV_LISTEN).unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let upstream_host =
        env::var(ENV_UPSTREAM_HOST).unwrap_or_else(|_| DEFAULT_UPSTREAM_HOST.to_owned());
    let upstream_port = match env::var(ENV_UPSTREAM_PORT) {
        Ok(v) => v
            .parse::<u16>()
            .with_context(|| format!("invalid {ENV_UPSTREAM_PORT}: {v}"))?,
        Err(_) => DEFAULT_UPSTREAM_PORT,
    };
    let use_tls = match env::var(ENV_TLS) {
        Ok(v) => v
            .parse::<bool>()
            .with_context(|| format!("invalid {ENV_TLS}: {v}"))?,
        Err(_) => DEFAULT_TLS,
    };

    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("bind tcp socket on {listen_addr}"))?;

    let proxy = Proxy::new(upstream_host, upstream_port, use_tls)
        .rewrite_hello()
        .enable_logging();

    serve(listener, proxy).await.context("run mongodb proxy")?;

    Ok(())
}
