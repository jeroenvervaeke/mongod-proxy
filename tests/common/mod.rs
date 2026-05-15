//! Shared helpers for `tests/e2e_*.rs`.

use std::time::{Duration, Instant};

use atlas_local::models::Deployment;
use mongodb::{Client, bson::doc, options::ClientOptions};

/// Return the loopback host port the deployment exposes, when present.
pub fn mongo_port(deployment: &Deployment) -> Option<u16> {
    deployment.port_bindings.as_ref().and_then(|b| b.port)
}

/// Block until a `ping` against `uri` succeeds, with a fixed 60s deadline
/// and 200ms backoff between attempts.
pub async fn wait_ready(uri: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = ClientOptions::parse(uri).await?;
    options.server_selection_timeout = Some(Duration::from_secs(2));
    let client = Client::with_options(options)?;

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last_err: Option<mongodb::error::Error> = None;
    while Instant::now() < deadline {
        match client
            .database("admin")
            .run_command(doc! { "ping": 1 })
            .await
        {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    Err(format!("mongo never accepted ping: last error = {last_err:?}").into())
}
