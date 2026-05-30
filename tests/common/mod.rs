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
use mongodb::{Client, bson::Bson, bson::Document, bson::doc, options::ClientOptions};

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

// ===========================================================================
// Multi-node replica set
//
// `atlas-local` 0.6.1 can only create a single-node replica set (its
// `CreateDeploymentOptions` has no member-count knob), and a single-node set
// always reports its one host as primary. That can't exercise the multi-host
// `select_primary` / `HelloProbe` path the proxy uses when an earlier seed /
// SRV record is a *secondary*. So we hand-roll a real 3-member replica set
// from plain `mongo:latest` containers and `rs.initiate` it via the driver.
//
// Networking: every node runs with Docker host networking and binds a
// distinct loopback port (27117/27118/27119). Host networking makes the
// members reach one another at the *same* `127.0.0.1:<port>` the host (and
// thus the in-process proxy) uses, so the replica-set config addresses are
// valid from both sides. This is Linux-only, which matches the CI `test`
// job (ubuntu-latest) where this actually runs; on a machine without a
// reachable daemon the caller self-skips before getting here.
// ===========================================================================

/// Replica-set name used for the hand-rolled multi-node deployment.
const REPLICA_SET_NAME: &str = "rs0";

/// Loopback ports the three members bind, in member order. Picked high to
/// avoid colliding with a developer's local `mongod` on 27017.
const REPLICA_SET_PORTS: [u16; 3] = [27117, 27118, 27119];

/// A hand-rolled multi-node replica set: three `mongo:latest` containers
/// wired into one `rs.initiate`d set, exposed on loopback ports.
///
/// Construct via [`start_replica_set`]; tear every container down via
/// [`shutdown`](Self::shutdown) on the happy path or a
/// [`ReplicaSetCleanup`] captured in a `scopeguard` for panic-safe cleanup.
pub struct ReplicaSet {
    docker: Docker,
    /// Container ids in member order (parallel to [`REPLICA_SET_PORTS`]).
    container_ids: Vec<String>,
    /// Loopback ports each member binds, in member order.
    ports: Vec<u16>,
}

/// Cleanup-only view of a [`ReplicaSet`]; force-removes every member
/// container. Cheap to construct and `Send` so it can ride in a `scopeguard`.
pub struct ReplicaSetCleanup {
    docker: Docker,
    container_ids: Vec<String>,
}

impl ReplicaSet {
    /// Loopback ports of every member, in member order.
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// Build a `mongodb://h1,h2,h3/` seed list pointing at every member,
    /// with `directConnection` left off so the driver / proxy treats it as
    /// a seed list to probe.
    pub fn seed_uri(&self, ports: &[u16]) -> String {
        let hosts = ports
            .iter()
            .map(|p| format!("127.0.0.1:{p}"))
            .collect::<Vec<_>>()
            .join(",");
        format!("mongodb://{hosts}/")
    }

    /// Discover the current primary's loopback port by issuing `hello` to
    /// each member directly until one reports `isWritablePrimary`.
    ///
    /// Retries with backoff: immediately after `rs.initiate` (or a
    /// step-down) an election is in flight and there is briefly no primary.
    pub async fn current_primary_port(
        &self,
    ) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut last: Option<String> = None;
        while Instant::now() < deadline {
            for &port in &self.ports {
                match member_is_primary(port).await {
                    Ok(true) => return Ok(port),
                    Ok(false) => {}
                    Err(e) => last = Some(e.to_string()),
                }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        Err(format!("no member reported itself primary in time; last error = {last:?}").into())
    }

    /// Order the member ports so the current primary comes *last*. Feeding
    /// this to [`seed_uri`](Self::seed_uri) yields a seed list whose earlier
    /// entries are all secondaries, forcing the proxy's `select_primary`
    /// path to skip them and probe its way to the primary.
    pub async fn ports_primary_last(
        &self,
    ) -> Result<Vec<u16>, Box<dyn std::error::Error + Send + Sync>> {
        let primary = self.current_primary_port().await?;
        let mut ordered: Vec<u16> = self
            .ports
            .iter()
            .copied()
            .filter(|&p| p != primary)
            .collect();
        ordered.push(primary);
        Ok(ordered)
    }

    /// Step the current primary down for `seconds`, forcing a new election.
    ///
    /// `replSetStepDown` closes the command connection by design, so the
    /// driver surfaces an error even on success; we treat that as expected
    /// and let the caller re-discover the new primary.
    pub async fn step_down_primary(
        &self,
        seconds: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let primary = self.current_primary_port().await?;
        let client = direct_client(primary).await?;
        // The server drops the connection as part of stepping down, so an
        // Err here is the normal outcome — only a clean Ok or a dropped
        // connection both mean "stepped down".
        let _ = client
            .database("admin")
            .run_command(doc! { "replSetStepDown": i32::try_from(seconds).unwrap_or(i32::MAX) })
            .await;
        Ok(())
    }

    /// Cheap-to-clone cleanup-only view for panic-safe `scopeguard` teardown.
    pub fn cleanup_handle(&self) -> ReplicaSetCleanup {
        ReplicaSetCleanup {
            docker: self.docker.clone(),
            container_ids: self.container_ids.clone(),
        }
    }

    /// Happy-path teardown: force-remove every member container.
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        remove_containers(&self.docker, &self.container_ids).await
    }
}

impl ReplicaSetCleanup {
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        remove_containers(&self.docker, &self.container_ids).await
    }
}

async fn remove_containers(
    docker: &Docker,
    container_ids: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for id in container_ids {
        // Best-effort: keep removing the rest even if one is already gone.
        let _ = docker
            .remove_container(
                id,
                Some(RemoveContainerOptionsBuilder::default().force(true).build()),
            )
            .await;
    }
    Ok(())
}

/// Direct (`directConnection=true`) client to a single member on `port`.
/// Bypasses SDAM so the driver talks to exactly that mongod, even when it's
/// a secondary, which is what the `hello`/step-down probes need.
async fn direct_client(port: u16) -> Result<Client, Box<dyn std::error::Error + Send + Sync>> {
    let uri = format!("mongodb://127.0.0.1:{port}/?directConnection=true");
    let mut options = ClientOptions::parse(&uri).await?;
    options.server_selection_timeout = Some(Duration::from_secs(5));
    Ok(Client::with_options(options)?)
}

/// `true` iff the member on `port` answers `hello` with
/// `isWritablePrimary: true` (the modern field; falls back to the legacy
/// `ismaster`).
async fn member_is_primary(port: u16) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let client = direct_client(port).await?;
    let reply = client
        .database("admin")
        .run_command(doc! { "hello": 1 })
        .await?;
    // `get(..).and_then(Bson::as_bool)` reads the same way across bson
    // major versions (unlike the typed `get_bool`, whose return shape and
    // availability shifted between 2.x and 3.x). Modern servers send
    // `isWritablePrimary`; the legacy `ismaster` is the fallback.
    let primary = reply
        .get("isWritablePrimary")
        .or_else(|| reply.get("ismaster"))
        .and_then(Bson::as_bool)
        .unwrap_or(false);
    Ok(primary)
}

/// Boot a 3-member replica set from plain `mongo:latest` containers and
/// `rs.initiate` it, returning once a primary has been elected.
///
/// See the module-level comment on the multi-node section for the
/// host-networking rationale.
pub async fn start_replica_set(
    docker: &Docker,
) -> Result<ReplicaSet, Box<dyn std::error::Error + Send + Sync>> {
    // Ensure the image is present (no-op when already cached).
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

    let ports: Vec<u16> = REPLICA_SET_PORTS.to_vec();
    let mut container_ids = Vec::with_capacity(ports.len());

    // Register a defensive cleanup: if any later step fails, the containers
    // we already started must still be torn down. We collect ids as we go.
    for &port in &ports {
        let container = docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().build()),
                ContainerCreateBody {
                    image: Some(STANDALONE_IMAGE.to_string()),
                    cmd: Some(vec![
                        "mongod".to_string(),
                        "--replSet".to_string(),
                        REPLICA_SET_NAME.to_string(),
                        "--port".to_string(),
                        port.to_string(),
                        // Bind all interfaces; with host networking the proxy
                        // and the peer members all reach it via 127.0.0.1.
                        "--bind_ip_all".to_string(),
                    ]),
                    host_config: Some(HostConfig {
                        // Host networking so member<->member addresses
                        // (127.0.0.1:<port>) are valid from inside the
                        // containers *and* from the host-side proxy.
                        network_mode: Some("host".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await;

        let container = match container {
            Ok(c) => c,
            Err(e) => {
                let _ = remove_containers(docker, &container_ids).await;
                return Err(e.into());
            }
        };

        if let Err(e) = docker
            .start_container(&container.id, None::<StartContainerOptions>)
            .await
        {
            container_ids.push(container.id);
            let _ = remove_containers(docker, &container_ids).await;
            return Err(e.into());
        }
        container_ids.push(container.id);
    }

    // From here on, errors must tear down every started container.
    let result = initiate_replica_set(&ports).await;
    if let Err(e) = result {
        let _ = remove_containers(docker, &container_ids).await;
        return Err(e);
    }

    let rs = ReplicaSet {
        docker: docker.clone(),
        container_ids,
        ports,
    };

    // Block until an actual primary exists (election completes) so the
    // caller can immediately query topology.
    if let Err(e) = rs.current_primary_port().await {
        let _ = remove_containers(&rs.docker, &rs.container_ids).await;
        return Err(e);
    }

    Ok(rs)
}

/// Wait for every member to accept pings, then `replSetInitiate` a config
/// listing all three as `127.0.0.1:<port>` voting members.
async fn initiate_replica_set(
    ports: &[u16],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for &port in ports {
        let uri = format!("mongodb://127.0.0.1:{port}/?directConnection=true");
        wait_ready(&uri).await?;
    }

    let members: Vec<Document> = ports
        .iter()
        .enumerate()
        .map(|(i, p)| doc! { "_id": i as i32, "host": format!("127.0.0.1:{p}") })
        .collect();

    let config = doc! {
        "_id": REPLICA_SET_NAME,
        "members": members,
    };

    // Initiate against the first member. The set has no config yet, so a
    // direct connection is required (SDAM would refuse an uninitialised set).
    let client = direct_client(ports[0]).await?;
    client
        .database("admin")
        .run_command(doc! { "replSetInitiate": config })
        .await?;

    Ok(())
}
