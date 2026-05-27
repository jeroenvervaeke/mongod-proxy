use std::env;

use anyhow::{Context, Result};
use mongod_proxy::{Proxy, serve};
use tokio::net::TcpListener;

mod log;

const ENV_LISTEN: &str = "MONGOD_PROXY_LISTEN";
const ENV_UPSTREAM_HOST: &str = "MONGOD_PROXY_UPSTREAM_HOST";
const ENV_UPSTREAM_PORT: &str = "MONGOD_PROXY_UPSTREAM_PORT";
const ENV_UPSTREAM_SRV: &str = "MONGOD_PROXY_UPSTREAM_SRV";
const ENV_TLS: &str = "MONGOD_PROXY_TLS";

const DEFAULT_LISTEN: &str = "127.0.0.1:27018";
const DEFAULT_UPSTREAM_HOST: &str = "localhost";
const DEFAULT_UPSTREAM_PORT: u16 = 27017;
const DEFAULT_TLS: bool = false;
// Per the mongodb+srv spec, SRV URIs default to TLS = true. Match that
// default when ENV_TLS is unset.
const DEFAULT_TLS_SRV: bool = true;

#[tokio::main]
async fn main() -> Result<()> {
    log::setup();

    let listen_addr = env::var(ENV_LISTEN).unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let explicit_tls = match env::var(ENV_TLS) {
        Ok(v) => Some(
            v.parse::<bool>()
                .with_context(|| format!("invalid {ENV_TLS}: {v}"))?,
        ),
        Err(_) => None,
    };

    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("bind tcp socket on {listen_addr}"))?;

    // SRV upstream takes precedence — the SRV hostname yields both host
    // and port via DNS, so the host/port env vars are ignored when SRV
    // is set.
    let proxy = match env::var(ENV_UPSTREAM_SRV) {
        Ok(srv_hostname) => {
            let use_tls = explicit_tls.unwrap_or(DEFAULT_TLS_SRV);
            Proxy::from_srv(srv_hostname.trim(), use_tls)
                .await
                .with_context(|| format!("resolve SRV upstream `{srv_hostname}`"))?
                .enable_logging()
        }
        Err(_) => {
            let upstream_host = env::var(ENV_UPSTREAM_HOST)
                .unwrap_or_else(|_| DEFAULT_UPSTREAM_HOST.to_owned());
            let upstream_port = match env::var(ENV_UPSTREAM_PORT) {
                Ok(v) => v
                    .parse::<u16>()
                    .with_context(|| format!("invalid {ENV_UPSTREAM_PORT}: {v}"))?,
                Err(_) => DEFAULT_UPSTREAM_PORT,
            };
            let use_tls = explicit_tls.unwrap_or(DEFAULT_TLS);
            Proxy::new(upstream_host, upstream_port, use_tls).enable_logging()
        }
    };

    serve(listener, proxy).await.context("run mongodb proxy")?;

    Ok(())
}
