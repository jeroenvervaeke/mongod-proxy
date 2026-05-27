//! Shared helpers for `tests/e2e_*.rs`.
//!
//! Most of the surface is the [`TestDeployment`] abstraction: it boots a
//! real MongoDB process inside Docker — either as a vanilla standalone
//! `mongod` (via [`bollard`] directly, image `mongo:latest`) or as a
//! single-node replica set (via [`atlas_local`]) — so each e2e test can be
//! parameterised over both topologies from one body.

// Each test binary in `tests/` compiles its own copy of this module and
// only references a subset of the helpers; the others would otherwise
// surface as `dead_code` warnings in every other test binary.
#![allow(dead_code)]

use std::{collections::HashMap, time::Duration, time::Instant};

use atlas_local::{
    Client as AtlasClient,
    models::{BindingType, CreateDeploymentOptions, Deployment, MongoDBPortBinding},
};
use bollard::{
    Docker,
    models::{ContainerCreateBody, HostConfig, PortBinding},
    query_parameters::{
        CreateContainerOptionsBuilder, CreateImageOptionsBuilder, RemoveContainerOptionsBuilder,
        StartContainerOptions,
    },
};
use futures::TryStreamExt;
use mongodb::{Client, bson::doc, options::ClientOptions};

/// Plain `mongod` image used for the standalone case. `mongo:latest`
/// follows the same convention as `atlas-local`'s default
/// `quay.io/mongodb/mongodb-atlas-local:latest`, keeping the test setup
/// symmetric between the two upstream types.
const STANDALONE_IMAGE: &str = "mongo:latest";

/// MongoDB topology each e2e case can exercise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeploymentKind {
    /// Vanilla `mongod` with no replica set. Hello replies carry no
    /// `setName`/`hosts`/`primary`/`me`, so drivers classify the upstream
    /// as `Standalone` even without `directConnection=true`. The
    /// `rewrite_hello` layer is a no-op on this path; the case exists to
    /// catch regressions where the layer or proxy plumbing accidentally
    /// breaks the (already-working) standalone topology.
    Standalone,
    /// Single-node replica set spun up via `atlas-local`. The hello reply
    /// advertises the container hostname as the sole replica-set member,
    /// so without `rewrite_hello` an SDAM-enabled driver would dial that
    /// hostname directly (unreachable from the host) instead of staying on
    /// the proxy socket. This case exercises the layer end-to-end.
    ReplicaSet,
}

impl DeploymentKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::ReplicaSet => "replica_set",
        }
    }
}

/// Return the loopback host port the deployment exposes, when present.
pub fn mongo_port(deployment: &Deployment) -> Option<u16> {
    deployment.port_bindings.as_ref().and_then(|b| b.port)
}

/// Block until a `ping` against `uri` succeeds, with a fixed 60s deadline
/// and 200ms backoff between attempts.
pub async fn wait_ready(uri: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

/// Connect to the Docker daemon, returning `None` (with a `skipping: …`
/// message on stderr) if it isn't reachable. Tests use this to self-skip
/// on developer machines without a running daemon.
pub async fn try_connect_docker() -> Option<Docker> {
    match Docker::connect_with_local_defaults() {
        Ok(d) => match d.ping().await {
            Ok(_) => Some(d),
            Err(e) => {
                eprintln!("skipping: docker daemon unreachable ({e})");
                None
            }
        },
        Err(e) => {
            eprintln!("skipping: docker not configured ({e})");
            None
        }
    }
}

/// A running MongoDB process in Docker plus the bits needed to talk to it
/// and shut it down again.
///
/// Construct via [`TestDeployment::start`]; tear down via either
/// [`shutdown`](Self::shutdown) on the happy path or a [`CleanupHandle`]
/// captured in a `scopeguard` for panic-safe cleanup.
pub struct TestDeployment {
    pub kind: DeploymentKind,
    pub host_port: u16,
    /// Short human-readable identifier for log lines (container id prefix,
    /// deployment name, etc.). Lets each parameterised case make it
    /// obvious in test output which upstream it's running against.
    pub label: String,
    handle: DeploymentHandle,
}

/// Cleanup-only view of a [`TestDeployment`]. Cheap to clone (both
/// variants wrap `Arc`-backed clients), so a test can hand one to a
/// `scopeguard` for panic-safe teardown without giving up access to the
/// live deployment's metadata.
pub struct CleanupHandle(DeploymentHandle);

#[derive(Clone)]
enum DeploymentHandle {
    AtlasLocal {
        atlas: AtlasClient,
        name: String,
    },
    Standalone {
        docker: Docker,
        container_id: String,
    },
}

impl TestDeployment {
    /// Boot a deployment of the requested `kind` and wait for it to accept
    /// pings on its loopback host port.
    pub async fn start(
        docker: &Docker,
        kind: DeploymentKind,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        match kind {
            DeploymentKind::ReplicaSet => start_atlas_local(docker.clone()).await,
            DeploymentKind::Standalone => start_standalone(docker.clone()).await,
        }
    }

    /// Returns a cheap-to-clone cleanup-only view. Use it to register
    /// panic-safe teardown via `scopeguard` while keeping `self` available
    /// for the happy-path test body.
    pub fn cleanup_handle(&self) -> CleanupHandle {
        CleanupHandle(self.handle.clone())
    }

    /// Happy-path teardown: removes the container / atlas-local deployment
    /// and waits for the daemon's confirmation. Tests should defuse the
    /// `scopeguard` first so the cleanup doesn't race itself.
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.handle.shutdown().await
    }
}

impl CleanupHandle {
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.0.shutdown().await
    }
}

impl DeploymentHandle {
    async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::AtlasLocal { atlas, name } => {
                atlas.delete_deployment(&name).await?;
            }
            Self::Standalone {
                docker,
                container_id,
            } => {
                docker
                    .remove_container(
                        &container_id,
                        Some(RemoveContainerOptionsBuilder::default().force(true).build()),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

async fn start_atlas_local(
    docker: Docker,
) -> Result<TestDeployment, Box<dyn std::error::Error + Send + Sync>> {
    let atlas = AtlasClient::new(docker);
    let deployment = atlas
        .create_deployment(CreateDeploymentOptions {
            wait_until_healthy: Some(true),
            wait_until_healthy_timeout: Some(Duration::from_secs(120)),
            mongodb_port_binding: Some(MongoDBPortBinding {
                port: None,
                binding_type: BindingType::Loopback,
            }),
            ..Default::default()
        })
        .await?;

    let name = deployment
        .name
        .clone()
        .ok_or("atlas-local deployment has no name")?;
    let host_port = mongo_port(&deployment).ok_or("atlas-local deployment exposes no host port")?;
    let label = format!(
        "atlas-local {name} ({})",
        &deployment.container_id.get(..12).unwrap_or("?")
    );

    Ok(TestDeployment {
        kind: DeploymentKind::ReplicaSet,
        host_port,
        label,
        handle: DeploymentHandle::AtlasLocal { atlas, name },
    })
}

async fn start_standalone(
    docker: Docker,
) -> Result<TestDeployment, Box<dyn std::error::Error + Send + Sync>> {
    // Ensure the image is present locally. `create_image` is a no-op when
    // the tag is already cached; this is essentially `docker pull`.
    let _: Vec<_> = docker
        .create_image(
            Some(
                CreateImageOptionsBuilder::default()
                    .from_image(STANDALONE_IMAGE)
                    .build(),
            ),
            None,
            None,
        )
        .try_collect()
        .await?;

    let port_bindings = HashMap::from([(
        "27017/tcp".to_string(),
        Some(vec![PortBinding {
            host_ip: Some("127.0.0.1".to_string()),
            // None lets Docker pick an ephemeral host port so parallel
            // test runs don't collide on a fixed port.
            host_port: None,
        }]),
    )]);

    let create_options = CreateContainerOptionsBuilder::default().build();
    let container = docker
        .create_container(
            Some(create_options),
            ContainerCreateBody {
                image: Some(STANDALONE_IMAGE.to_string()),
                host_config: Some(HostConfig {
                    port_bindings: Some(port_bindings),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await?;

    docker
        .start_container(&container.id, None::<StartContainerOptions>)
        .await?;

    let info = docker.inspect_container(&container.id, None).await?;
    let host_port_str = info
        .network_settings
        .as_ref()
        .and_then(|ns| ns.ports.as_ref())
        .and_then(|ports| ports.get("27017/tcp"))
        .and_then(|opt| opt.as_ref())
        .and_then(|bindings| bindings.first())
        .and_then(|b| b.host_port.as_ref())
        .ok_or("standalone container has no 27017/tcp host port binding")?;
    let host_port: u16 = host_port_str.parse()?;

    // mongod boots quickly but not synchronously with container start;
    // block until `admin.ping` round-trips so the caller can assume the
    // process is serving traffic.
    let uri = format!("mongodb://127.0.0.1:{host_port}/?directConnection=true");
    wait_ready(&uri).await?;

    let label = format!("mongo standalone ({})", &container.id[..12]);

    Ok(TestDeployment {
        kind: DeploymentKind::Standalone,
        host_port,
        label,
        handle: DeploymentHandle::Standalone {
            docker,
            container_id: container.id,
        },
    })
}
