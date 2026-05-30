//! Upstream proxy [`Service`] — opens the upstream socket, optionally over
//! TLS, and shuttles messages between client and `mongod`.
//!
//! [`Proxy`] is a [`Service<SocketAddr>`] (i.e. a make-service) that produces
//! a fresh [`ProxyClient`] per incoming client connection. [`ProxyClient`]
//! is the per-connection [`Service<Message>`] that does the actual
//! request/response forwarding, modelled as a stream so it can handle
//! moreToCome multi-reply traffic.

use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Once, PoisonError, RwLock, Weak},
    task::{Context, Poll},
    time::Duration,
};

use futures::{SinkExt, Stream, StreamExt};
use rustls_pki_types::{InvalidDnsNameError, ServerName};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, split},
    net::TcpStream,
    sync::{Mutex, OwnedMutexGuard},
};
#[cfg(feature = "dangerous-insecure-tls")]
use tokio_rustls::rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, ServerName as RustlsServerName, UnixTime},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore},
};
use tokio_util::codec::{FramedRead, FramedWrite};
use tower_layer::{Identity, Layer, Stack};
use tower_service::Service;
use tracing::{debug, info, warn};

use crate::{
    LogLayer,
    decoder::{WireDecoder, WireDecoderError},
    encoder::{WireEncoder, WireEncoderError},
    message::Message,
    operation::{Operation, op_msg::OperationMessageFlags},
    serve::rewrite_hello::{RewriteHelloLayer, RewriteHelloService},
};

/// Ensures rustls has a usable [`CryptoProvider`](tokio_rustls::rustls::crypto::CryptoProvider).
///
/// rustls 0.23+ refuses to pick a provider when more than one is compiled
/// in (which happens whenever transitive dependencies enable both the `ring`
/// and `aws-lc-rs` features — common in mixed dependency trees). We pick
/// `aws_lc_rs` deterministically here. `install_default` errors after the
/// first successful install, so we ignore the error to be idempotent.
fn install_default_crypto_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// How the proxy should establish (or skip) TLS to its upstream `mongod`.
///
/// Passed to [`Proxy::with_tls`] to pick a trust policy for the upstream
/// socket. The legacy `use_tls: bool` of [`Proxy::new`] maps onto the two
/// most common variants: `false` → [`TlsConfig::Disabled`], `true` →
/// [`TlsConfig::System`].
///
/// # Examples
///
/// ```
/// use mongod_proxy::{Proxy, TlsConfig};
///
/// // Forward to a TLS-terminating upstream using the OS-bundled
/// // `webpki-roots` trust anchors (the same config `Proxy::new(.., true)`
/// // builds).
/// let proxy = Proxy::with_tls("mongo.example.com", 27017, TlsConfig::System);
/// # let _ = proxy;
/// ```
#[non_exhaustive]
pub enum TlsConfig {
    /// Plain TCP — no TLS. Equivalent to `Proxy::new(.., false)`.
    Disabled,
    /// Standard `webpki-roots` trust anchors, no client cert, SNI on.
    /// The default TLS behaviour and what `Proxy::new(.., true)` selects.
    System,
    /// Validate the upstream certificate against a caller-supplied
    /// [`RootCertStore`] instead of the bundled `webpki-roots` anchors.
    ///
    /// Use this to forward to a deployment whose certificate chains to an
    /// internal/private CA: load the CA into the store and hand it in.
    /// Client auth stays off and SNI on, matching [`TlsConfig::System`].
    WithRoots(RootCertStore),
    /// **Dangerous.** Disable upstream certificate verification entirely —
    /// any certificate (self-signed, expired, wrong host) is accepted.
    ///
    /// This defeats the authentication TLS provides and exposes the
    /// connection to man-in-the-middle attacks; it exists only to forward
    /// to throwaway self-signed test deployments. Constructing a proxy with
    /// this variant emits a prominent [`tracing::warn!`].
    ///
    /// Gated behind the `dangerous-insecure-tls` cargo feature so it can't
    /// be reached by accident — the variant does not even exist unless that
    /// feature is enabled.
    #[cfg(feature = "dangerous-insecure-tls")]
    Insecure,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `RootCertStore` isn't `Debug`; render variants by name so a
        // `Proxy`/`TlsConfig` can sit in `#[derive(Debug)]` contexts.
        match self {
            TlsConfig::Disabled => f.write_str("Disabled"),
            TlsConfig::System => f.write_str("System"),
            TlsConfig::WithRoots(_) => f.write_str("WithRoots(..)"),
            #[cfg(feature = "dangerous-insecure-tls")]
            TlsConfig::Insecure => f.write_str("Insecure"),
        }
    }
}

/// Builds the upstream rustls [`TlsConnector`] for a [`TlsConfig`], or
/// `None` for [`TlsConfig::Disabled`] (plain TCP).
///
/// [`TlsConfig::System`] keeps the historical behaviour: `webpki-roots`
/// trust anchors, no client cert, SNI on. [`TlsConfig::WithRoots`] swaps in
/// the caller-supplied store. [`TlsConfig::Insecure`] installs a no-op
/// certificate verifier and logs a loud warning. Every config runs
/// [`install_default_crypto_provider`] first so rustls always has a usable
/// provider.
pub(crate) fn build_tls_connector(tls: TlsConfig) -> Option<Arc<TlsConnector>> {
    let config = match tls {
        TlsConfig::Disabled => return None,
        TlsConfig::System => {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            roots_config(root_cert_store)
        }
        TlsConfig::WithRoots(root_cert_store) => roots_config(root_cert_store),
        #[cfg(feature = "dangerous-insecure-tls")]
        TlsConfig::Insecure => insecure_config(),
    };
    Some(Arc::new(TlsConnector::from(Arc::new(config))))
}

/// Builds a verifying [`ClientConfig`] over `root_cert_store`: no client
/// auth, SNI on. Shared by [`TlsConfig::System`] and
/// [`TlsConfig::WithRoots`].
fn roots_config(root_cert_store: RootCertStore) -> ClientConfig {
    install_default_crypto_provider();
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    config.enable_sni = true;
    config
}

/// Builds the standard verifying [`TlsConnector`] used by the SRV
/// primary-selection probes and any caller that just wants the historical
/// `webpki-roots` behaviour. Equivalent to
/// `build_tls_connector(TlsConfig::System)` but infallible (always `Some`).
pub(crate) fn default_tls_connector() -> Arc<TlsConnector> {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(TlsConnector::from(Arc::new(roots_config(root_cert_store))))
}

/// Builds a [`ClientConfig`] that accepts *any* server certificate.
///
/// Logs a prominent warning before returning — see
/// [`TlsConfig::Insecure`]. Wires the no-op [`InsecureServerVerifier`] via
/// rustls's `dangerous()` builder; client auth stays off and SNI on so the
/// only difference from [`roots_config`] is the dropped verification.
#[cfg(feature = "dangerous-insecure-tls")]
fn insecure_config() -> ClientConfig {
    install_default_crypto_provider();
    warn!(
        "TLS certificate verification is DISABLED (TlsConfig::Insecure): the upstream \
         connection is NOT authenticated and is vulnerable to man-in-the-middle attacks. \
         Use this only against throwaway self-signed test deployments."
    );
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureServerVerifier))
        .with_no_client_auth();
    config.enable_sni = true;
    config
}

/// A [`ServerCertVerifier`] that accepts every certificate and signature
/// without checking anything. Backs [`TlsConfig::Insecure`].
///
/// Signature *schemes* are still reported from the active crypto provider
/// so the handshake can negotiate, but the signatures themselves are
/// rubber-stamped as valid. Never construct this outside the explicit,
/// feature-gated `Insecure` opt-in.
#[cfg(feature = "dangerous-insecure-tls")]
#[derive(Debug)]
struct InsecureServerVerifier;

#[cfg(feature = "dangerous-insecure-tls")]
impl ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &RustlsServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The upstream `host:port` the proxy currently forwards to.
///
/// Held behind an [`Arc<RwLock<Target>>`] inside [`Proxy`] so the
/// background failover loop spawned by [`Proxy::from_srv`] can swap it
/// out atomically when the replica-set primary changes, without
/// disturbing connections already in flight (each [`ProxyClient`] keeps
/// the socket it dialled; only *new* connections read the swapped value).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    host: String,
    port: u16,
}

/// Reads the current upstream target, tolerating a poisoned lock.
///
/// The only writer is the single-threaded failover loop and its critical
/// section can't panic, so poisoning is effectively impossible — but the
/// no-panic policy still forbids `unwrap()`, so we recover the guard via
/// [`PoisonError::into_inner`] rather than risk a panic.
fn read_target(target: &RwLock<Target>) -> (String, u16) {
    let guard = target.read().unwrap_or_else(PoisonError::into_inner);
    (guard.host.clone(), guard.port)
}

/// Default cadence for the background failover re-probe loop. Re-resolving
/// SRV and re-selecting the primary once a minute keeps the steady-state
/// cost negligible while bounding how long a stale primary can linger
/// after an Atlas failover.
const DEFAULT_REPROBE_INTERVAL: Duration = Duration::from_secs(60);

type BoxedAsyncRead = Pin<Box<dyn AsyncRead + Send + Sync + 'static>>;
type BoxedAsyncWrite = Pin<Box<dyn AsyncWrite + Send + Sync + 'static>>;
type ServerReader = FramedRead<BoxedAsyncRead, WireDecoder>;
type ServerWriter = FramedWrite<BoxedAsyncWrite, WireEncoder>;

/// Upstream proxy configuration and make-service.
///
/// Implements [`Service<SocketAddr>`], producing one fresh
/// [`L::Service`](Layer::Service) wrapping a [`ProxyClient`] per call. The
/// type parameter `L` carries the tower [`Layer`] stack applied around the
/// inner [`ProxyClient`]; `Identity` (the default returned by
/// [`Proxy::new`]) applies no layers.
///
/// # Examples
///
/// Build a plain-TCP proxy and wrap a [`LogLayer`] around it:
///
/// ```
/// use mongod_proxy::{LogLayer, Proxy};
///
/// // For the doctest we pass `use_tls = false` to avoid a network-dependent
/// // rustls config; switch to `true` to forward over TLS in real use.
/// let proxy = Proxy::new("mongo.example.com", 27017, /* use_tls = */ false)
///     .layer(LogLayer);
/// // `proxy` is now a `Service<SocketAddr>` ready to hand to `serve(...)`.
/// # let _ = proxy;
/// ```
pub struct Proxy<L> {
    /// Current upstream target, read fresh for every accepted connection.
    ///
    /// For [`Proxy::new`] this never changes. For [`Proxy::from_srv`] a
    /// background task swaps it on replica-set failover (see
    /// [`Proxy::from_srv_with`] and [`FailoverConfig`]).
    target: Arc<RwLock<Target>>,
    tls_connector: Option<Arc<TlsConnector>>,
    /// When true, every per-connection service has a [`RewriteHelloLayer`]
    /// inserted *between* the user-supplied layer stack and the inner
    /// [`ProxyClient`], so `hello` / `isMaster` replies get their
    /// topology-discovery fields stripped. On by default; flip via
    /// [`disable_rewrite_hello`](Self::disable_rewrite_hello).
    rewrite_hello: bool,

    proxy_layer: L,
}

impl Proxy<Identity> {
    /// Creates a new proxy that forwards every incoming client connection
    /// to `destination_name:destination_port`.
    ///
    /// When `use_tls` is true the upstream socket is wrapped in a `rustls`
    /// TLS client using the standard `webpki-roots` trust anchors and SNI
    /// derived from `destination_name`. When false the upstream socket is
    /// plain TCP.
    ///
    /// The resulting proxy has the `hello` / `isMaster` rewrite **on by
    /// default** so SDAM-enabled drivers (`mongodb://host:port/` with no
    /// `directConnection=true`) classify the proxy as a `Standalone` and
    /// keep every request on this socket instead of dialling the
    /// upstream addresses they would otherwise discover. Almost every
    /// user wants this — see the [`rewrite_hello`](crate::serve::rewrite_hello)
    /// module for the full rationale and the list of fields stripped.
    /// Opt out with [`disable_rewrite_hello`](Proxy::disable_rewrite_hello)
    /// only when you specifically need the upstream's topology visible to
    /// drivers.
    pub fn new(destination_name: impl Into<String>, destination_port: u16, use_tls: bool) -> Self {
        let tls = if use_tls {
            TlsConfig::System
        } else {
            TlsConfig::Disabled
        };
        Self::with_tls(destination_name, destination_port, tls)
    }

    /// Creates a new proxy forwarding to `destination_name:destination_port`
    /// with explicit control over the upstream TLS trust policy via
    /// [`TlsConfig`].
    ///
    /// This is the general form of [`Proxy::new`]: `new(.., false)` is
    /// [`TlsConfig::Disabled`] and `new(.., true)` is [`TlsConfig::System`].
    /// Reach for `with_tls` to forward to an internal-CA deployment
    /// ([`TlsConfig::WithRoots`]) or — when the `dangerous-insecure-tls`
    /// feature is enabled — a throwaway self-signed test deployment
    /// ([`TlsConfig::Insecure`]).
    ///
    /// The `hello` / `isMaster` rewrite is on by default exactly as in
    /// [`Proxy::new`]; see that method for the rationale and
    /// [`disable_rewrite_hello`](Proxy::disable_rewrite_hello) to opt out.
    ///
    /// # Examples
    ///
    /// ```
    /// use mongod_proxy::{Proxy, TlsConfig};
    ///
    /// // Plain TCP, equivalent to `Proxy::new(.., false)`.
    /// let proxy = Proxy::with_tls("127.0.0.1", 27017, TlsConfig::Disabled);
    /// # let _ = proxy;
    /// ```
    pub fn with_tls(
        destination_name: impl Into<String>,
        destination_port: u16,
        tls: TlsConfig,
    ) -> Self {
        let tls_connector = build_tls_connector(tls);
        let target = Arc::new(RwLock::new(Target {
            host: destination_name.into(),
            port: destination_port,
        }));
        Self::with_target(target, tls_connector)
    }

    /// Inner constructor over a pre-built, swappable [`Target`] cell and a
    /// shared `Arc<TlsConnector>`. [`Proxy::from_srv`] hands in a cell it
    /// also wired a background failover loop to; [`Proxy::new`] hands in a
    /// cell that never changes.
    fn with_target(target: Arc<RwLock<Target>>, tls_connector: Option<Arc<TlsConnector>>) -> Self {
        Self {
            target,
            tls_connector,
            rewrite_hello: true,

            proxy_layer: Identity::new(),
        }
    }

    /// Creates a new proxy whose upstream is the replica-set primary
    /// among the hosts returned by an SRV lookup for `srv_hostname` —
    /// i.e. the `mongodb+srv://` connection-string convention.
    ///
    /// Queries `_mongodb._tcp.<srv_hostname>` (see [`crate::srv`]),
    /// then sends a `hello` probe to each candidate in DNS order and
    /// uses the first node whose reply reports
    /// `isWritablePrimary == true`. Picking the primary (rather than
    /// the first SRV record blindly) is what makes the proxy work
    /// against multi-node Atlas clusters: a secondary would otherwise
    /// reject every operation with `NotPrimaryNoSecondaryOk` because
    /// the driver, looking at a [`RewriteHelloLayer`]-stripped hello
    /// reply, has no signal that it should set the wire-level
    /// `secondaryOk` flag.
    ///
    /// Per the SRV spec, TLS to the upstream defaults to enabled; pass
    /// `use_tls = false` only when forwarding to a test deployment that
    /// does not terminate TLS itself.
    ///
    /// The primary is selected at startup *and kept current*: a
    /// background task re-resolves SRV and re-runs the probe on a fixed
    /// interval (default 60s — see [`FailoverConfig`]), swapping the
    /// upstream target if the replica set fails over to a new primary.
    /// New client connections pick up the swapped target automatically,
    /// so the proxy recovers from an Atlas failover without a restart.
    /// Connections already in flight keep the socket they dialled and
    /// drain naturally; a driver that hits `NotPrimary` on the old
    /// primary reconnects, and the fresh connection lands on the new one.
    /// Use [`from_srv_with`](Self::from_srv_with) to tune the interval or
    /// opt out of the background loop.
    ///
    /// # Errors
    ///
    /// See [`crate::srv::SrvResolveError`]. New here:
    /// [`SrvResolveError::NoPrimary`](crate::srv::SrvResolveError::NoPrimary)
    /// fires when every SRV-resolved host responds (or fails to
    /// respond) without identifying itself as the primary.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mongod_proxy::Proxy;
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// // SRV lookup → probe each candidate → use the primary.
    /// let proxy = Proxy::from_srv("cluster0.foo.mongodb.net", true).await?;
    /// # let _ = proxy;
    /// # Ok(()) }
    /// ```
    pub async fn from_srv(
        srv_hostname: &str,
        use_tls: bool,
    ) -> Result<Self, crate::srv::SrvResolveError> {
        Self::from_srv_with(srv_hostname, use_tls, FailoverConfig::default()).await
    }

    /// Like [`from_srv`](Self::from_srv) but with explicit
    /// [`FailoverConfig`] control over the background re-probe loop.
    ///
    /// Pass [`FailoverConfig::disabled`] to capture the primary exactly
    /// once and never re-probe (the pre-failover-handling behaviour: a
    /// failover then requires a proxy restart). Pass
    /// [`FailoverConfig::every`] to choose a non-default re-probe
    /// interval.
    ///
    /// # Errors
    ///
    /// Same as [`from_srv`](Self::from_srv): see
    /// [`crate::srv::SrvResolveError`]. Only the *initial* selection can
    /// fail here — once the proxy is built, later re-probe failures are
    /// logged via `tracing` and leave the current target in place rather
    /// than tearing the proxy down.
    pub async fn from_srv_with(
        srv_hostname: &str,
        use_tls: bool,
        failover: FailoverConfig,
    ) -> Result<Self, crate::srv::SrvResolveError> {
        Self::from_srv_inner(
            srv_hostname,
            crate::srv::DEFAULT_SRV_SERVICE_NAME,
            use_tls,
            failover,
        )
        .await
    }

    /// Inner SRV constructor carrying an explicit SRV `service_name`
    /// (the `srvServiceName` URI override; `mongodb` for the default).
    ///
    /// [`from_srv`](Self::from_srv) / [`from_srv_with`](Self::from_srv_with)
    /// delegate here with the default service name; the
    /// `mongodb+srv://?srvServiceName=...` arm of
    /// [`from_uri`](Self::from_uri) passes the override through. The
    /// background re-probe loop reuses the same service name on every tick.
    async fn from_srv_inner(
        srv_hostname: &str,
        service_name: &str,
        use_tls: bool,
        failover: FailoverConfig,
    ) -> Result<Self, crate::srv::SrvResolveError> {
        let hosts = crate::srv::resolve_with_service_name(srv_hostname, service_name).await?;
        let tls_connector = use_tls.then(default_tls_connector);
        let probe = crate::serve::probe::HelloProbe::new(tls_connector.clone());
        let probe_timeout = failover.probe_timeout;
        let target = select_target(&hosts, &probe, probe_timeout)
            .await
            .map_err(|attempts| crate::srv::SrvResolveError::NoPrimary {
                hostname: srv_hostname.to_owned(),
                attempts,
            })?;

        if let Some(interval) = failover.reprobe_interval {
            let hostname = srv_hostname.to_owned();
            let service_name = service_name.to_owned();
            let tls = tls_connector.clone();
            // The loop owns only a `Weak` handle to the target, so it
            // self-terminates once the `Proxy` (and its serve loop) is
            // dropped. Each tick builds a self-contained future that
            // re-resolves SRV and re-selects the primary.
            spawn_reprobe_loop(interval, &target, move || {
                let hostname = hostname.clone();
                let service_name = service_name.clone();
                let probe = crate::serve::probe::HelloProbe::new(tls.clone());
                async move { resolve_and_select(&hostname, &service_name, &probe, probe_timeout).await }
            });
        }

        Ok(Self::with_target(target, tls_connector))
    }

    /// Constructs a proxy from any MongoDB connection string — both
    /// `mongodb://host[:port][,host[:port]…]/…` and
    /// `mongodb+srv://hostname/…` are accepted.
    ///
    /// Callers don't have to inspect the scheme themselves; this routes
    /// by scheme and host count:
    ///
    /// - **Single-host `mongodb://host[:port]/`** → [`Proxy::new`], no
    ///   probe. The caller named exactly one host, so it's used verbatim.
    /// - **Multi-host `mongodb://h1,h2,h3/`** → the same probe-and-select
    ///   path as the SRV branch: each host is sent a `hello` and the one
    ///   reporting `isWritablePrimary == true` becomes the upstream. A
    ///   replica-set seed list lists every member, so forwarding to the
    ///   first one blindly would land on a secondary and break every
    ///   operation with `NotPrimaryNoSecondaryOk` (the
    ///   [`hello` rewrite](crate::RewriteHelloLayer) deliberately hides
    ///   the topology signal a driver would otherwise use to set
    ///   `secondaryOk`). The selected primary is also kept current by the
    ///   same background failover loop as [`from_srv`](Self::from_srv),
    ///   re-probing the seed list on the default interval.
    /// - **`mongodb+srv://hostname/`** → [`Proxy::from_srv`].
    ///
    /// The default [`hello` rewrite](crate::RewriteHelloLayer) keeps the
    /// client driver pinned to the proxy socket in every case.
    ///
    /// TLS follows the URI:
    ///
    /// - `mongodb://` defaults to **off** unless the URI carries
    ///   `?tls=true` or `?ssl=true`.
    /// - `mongodb+srv://` defaults to **on** (per the SRV spec) unless
    ///   the URI carries `?tls=false` / `?ssl=false`.
    ///
    /// Everything else in the URI — user/password, database name, every
    /// other query option — is intentionally ignored. The proxy is
    /// wire-level; the client driver forwards those options to the
    /// upstream itself.
    ///
    /// # Errors
    ///
    /// Returns [`FromUriError::Parse`] for any URI shape rejected by
    /// [`crate::uri::ConnectionUriError`], [`FromUriError::Srv`] if the
    /// SRV lookup fails on a `mongodb+srv://` URI, or
    /// [`FromUriError::NoPrimary`] if a multi-host seed list resolves but
    /// none of its hosts responds as the primary.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use mongod_proxy::Proxy;
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// // Plain URI: TLS defaults to off, port defaults to 27017.
    /// let proxy = Proxy::from_uri("mongodb://127.0.0.1:27017/").await?;
    /// # let _ = proxy;
    /// // SRV URI: TLS defaults to on; the SRV record supplies the port.
    /// let proxy = Proxy::from_uri("mongodb+srv://cluster0.foo.mongodb.net/").await?;
    /// # let _ = proxy;
    /// # Ok(()) }
    /// ```
    pub async fn from_uri(uri: &str) -> Result<Self, FromUriError> {
        let parsed = crate::uri::parse(uri).map_err(FromUriError::Parse)?;
        match route(parsed)? {
            UriRoute::Single {
                host,
                port,
                use_tls,
            } => Ok(Self::new(host, port, use_tls)),
            UriRoute::SeedList { hosts, use_tls } => {
                Self::from_seed_list(hosts, use_tls, FailoverConfig::default()).await
            }
            UriRoute::Srv {
                hostname,
                use_tls,
                service_name,
            } => {
                let service_name = service_name
                    .as_deref()
                    .unwrap_or(crate::srv::DEFAULT_SRV_SERVICE_NAME);
                Self::from_srv_inner(&hostname, service_name, use_tls, FailoverConfig::default())
                    .await
                    .map_err(FromUriError::Srv)
            }
        }
    }

    /// Builds a proxy from an explicit replica-set seed list by probing
    /// each host for the primary, then (unless disabled) keeping it
    /// current with the same background failover loop as
    /// [`from_srv`](Self::from_srv) — except there's no DNS to re-resolve,
    /// so each tick re-probes the same static `hosts`.
    ///
    /// This is the multi-host `mongodb://h1,h2,h3/` arm of
    /// [`from_uri`](Self::from_uri). Single-host URIs don't come through
    /// here: with one named host there's nothing to select.
    async fn from_seed_list(
        hosts: Vec<crate::srv::SrvHost>,
        use_tls: bool,
        failover: FailoverConfig,
    ) -> Result<Self, FromUriError> {
        let tls_connector = use_tls.then(default_tls_connector);
        let probe = crate::serve::probe::HelloProbe::new(tls_connector.clone());
        let probe_timeout = failover.probe_timeout;
        let target = select_target(&hosts, &probe, probe_timeout)
            .await
            .map_err(|attempts| FromUriError::NoPrimary { attempts })?;

        if let Some(interval) = failover.reprobe_interval {
            let tls = tls_connector.clone();
            // The seed list is static — no DNS to re-resolve — so each
            // tick simply re-probes the same hosts for the current primary.
            spawn_reprobe_loop(interval, &target, move || {
                let probe = crate::serve::probe::HelloProbe::new(tls.clone());
                let hosts = hosts.clone();
                async move { reselect_seed_list(&hosts, &probe, probe_timeout).await }
            });
        }

        Ok(Self::with_target(target, tls_connector))
    }
}

/// Controls the background failover re-probe loop spawned by
/// [`Proxy::from_srv`] / [`Proxy::from_srv_with`].
///
/// A replica set may fail over to a new primary at any time. Without
/// re-probing, the proxy keeps forwarding to the node it picked at
/// startup; once that node is demoted it rejects writes with
/// `NotPrimary` and the proxy is stuck until an operator restarts it.
/// The loop re-resolves SRV and re-selects the primary on
/// [`reprobe_interval`](Self::reprobe_interval), swapping the upstream
/// target in place when it changes.
///
/// It also carries the per-host
/// [`probe_timeout`](Self::probe_timeout) used by *both* the one-shot
/// startup selection and every background re-probe, so a deployment that
/// cold-starts slowly (Atlas free-tier) or sits behind a high-latency
/// link can widen the budget instead of failing startup with a spurious
/// [`SrvResolveError::NoPrimary`](crate::srv::SrvResolveError::NoPrimary).
///
/// Construct it via [`default`](Self::default), [`every`](Self::every), or
/// [`disabled`](Self::disabled) and tune with the builder methods
/// (e.g. [`with_probe_timeout`](Self::with_probe_timeout)); the struct is
/// `#[non_exhaustive]` so new knobs can be added without breaking callers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FailoverConfig {
    /// How often to re-resolve SRV and re-select the primary. `None`
    /// disables the background loop entirely: the startup-selected
    /// primary is used for the proxy's whole lifetime and a failover
    /// requires a restart.
    pub reprobe_interval: Option<Duration>,
    /// Per-host budget for the dial + `hello` round-trip during primary
    /// selection (startup and every re-probe). Hosts slower than this are
    /// treated as non-primary. Defaults to 5s; raise it for clusters that
    /// cold-start slowly (Atlas free-tier), lower it to fail fast on a
    /// local network.
    pub probe_timeout: Duration,
}

impl Default for FailoverConfig {
    /// Re-probe every 60 seconds with the default per-host probe timeout.
    fn default() -> Self {
        Self {
            reprobe_interval: Some(DEFAULT_REPROBE_INTERVAL),
            probe_timeout: crate::serve::probe::DEFAULT_PROBE_TIMEOUT,
        }
    }
}

impl FailoverConfig {
    /// Re-probe on the given interval, keeping the default per-host probe
    /// timeout. Chain [`with_probe_timeout`](Self::with_probe_timeout) to
    /// also widen the budget.
    pub fn every(interval: Duration) -> Self {
        Self {
            reprobe_interval: Some(interval),
            ..Self::default()
        }
    }

    /// Never re-probe: capture the primary once at startup and keep it
    /// for the proxy's whole lifetime (a failover then needs a restart).
    /// The per-host probe timeout still applies to that one-shot startup
    /// selection.
    pub fn disabled() -> Self {
        Self {
            reprobe_interval: None,
            ..Self::default()
        }
    }

    /// Sets the per-host probe timeout (see
    /// [`probe_timeout`](Self::probe_timeout)), used by both the startup
    /// selection and any background re-probe. Returns `self` for
    /// chaining:
    ///
    /// ```
    /// use std::time::Duration;
    /// use mongod_proxy::FailoverConfig;
    ///
    /// // A cluster that cold-starts slowly: widen the budget to 20s.
    /// let cfg = FailoverConfig::default().with_probe_timeout(Duration::from_secs(20));
    /// assert_eq!(cfg.probe_timeout, Duration::from_secs(20));
    /// ```
    pub fn with_probe_timeout(mut self, probe_timeout: Duration) -> Self {
        self.probe_timeout = probe_timeout;
        self
    }
}

/// Probe `hosts` for the replica-set primary and, when one is found,
/// wrap it in the swappable [`Target`] cell every constructor shares.
///
/// Returns `None` when no host responds as the primary. Generic over the
/// probe so the multi-host selection wiring can be unit-tested with a
/// mock instead of real sockets.
async fn select_target<P>(
    hosts: &[crate::srv::SrvHost],
    probe: &P,
    probe_timeout: Duration,
) -> Result<Arc<RwLock<Target>>, Vec<(crate::srv::SrvHost, crate::serve::probe::ProbeOutcome)>>
where
    P: crate::serve::probe::PrimaryProbe + ?Sized,
{
    match crate::serve::probe::select_primary(hosts, probe, probe_timeout).await {
        crate::serve::probe::Selection::Primary(primary) => Ok(Arc::new(RwLock::new(Target {
            host: primary.host,
            port: primary.port,
        }))),
        // No host is currently the primary: hand the per-host rejection
        // reasons back so the constructor can build a diagnostic
        // `NoPrimary` rather than collapsing them into a bare count.
        crate::serve::probe::Selection::NoPrimary(attempts) => Err(attempts),
    }
}

/// Re-probe a static seed list for the current primary, returning the
/// chosen host or `None` (logging the reason) when none responds as
/// primary. The seed-list counterpart of [`resolve_and_select`]; used as
/// the per-tick body of the background failover loop for multi-host
/// `mongodb://` URIs, which have no DNS to re-resolve.
async fn reselect_seed_list<P>(
    hosts: &[crate::srv::SrvHost],
    probe: &P,
    probe_timeout: Duration,
) -> Option<crate::srv::SrvHost>
where
    P: crate::serve::probe::PrimaryProbe + ?Sized,
{
    let picked = crate::serve::probe::select_primary(hosts, probe, probe_timeout)
        .await
        .into_primary();
    if picked.is_none() {
        warn!(
            hosts = hosts.len(),
            "failover re-probe found no primary among seed-list hosts; keeping current upstream target"
        );
    }
    picked
}

/// Re-resolve SRV for `hostname` (under `service_name`) and re-select the
/// replica-set primary, returning the chosen host or `None` (logging the
/// reason) when the lookup fails or no primary is currently reachable.
///
/// Used as the per-tick body of the background failover loop. Failures
/// are non-fatal: the caller keeps the current target on `None`.
async fn resolve_and_select<P>(
    hostname: &str,
    service_name: &str,
    probe: &P,
    probe_timeout: Duration,
) -> Option<crate::srv::SrvHost>
where
    P: crate::serve::probe::PrimaryProbe + ?Sized,
{
    match crate::srv::resolve_with_service_name(hostname, service_name).await {
        Ok(hosts) => {
            let picked = crate::serve::probe::select_primary(&hosts, probe, probe_timeout)
                .await
                .into_primary();
            if picked.is_none() {
                warn!(
                    hostname,
                    hosts = hosts.len(),
                    "failover re-probe found no primary; keeping current upstream target"
                );
            }
            picked
        }
        Err(e) => {
            warn!(
                hostname,
                error = %e,
                "failover re-probe SRV resolution failed; keeping current upstream target"
            );
            None
        }
    }
}

/// Overwrites `target` with `primary` when it differs from the current
/// value, returning whether a swap happened. The swap is logged at
/// `info` so operators can see failovers in the proxy's own logs.
fn apply_primary(target: &RwLock<Target>, primary: crate::srv::SrvHost) -> bool {
    let mut guard = target.write().unwrap_or_else(PoisonError::into_inner);
    if guard.host == primary.host && guard.port == primary.port {
        return false;
    }
    info!(
        old_host = %guard.host,
        old_port = guard.port,
        new_host = %primary.host,
        new_port = primary.port,
        "replica-set primary changed; swapping upstream target",
    );
    *guard = Target {
        host: primary.host,
        port: primary.port,
    };
    true
}

/// Spawns the background failover loop. It sleeps `interval`, then —
/// while the `Proxy` is still alive (checked via a `Weak` upgrade) —
/// runs `select` and applies any new primary, until the proxy is dropped.
///
/// Generic over `select` so the loop's timing / lifecycle can be unit
/// tested without real DNS or sockets; production passes a closure that
/// calls [`resolve_and_select`].
fn spawn_reprobe_loop<S, Fut>(
    interval: Duration,
    target: &Arc<RwLock<Target>>,
    mut select: S,
) -> tokio::task::JoinHandle<()>
where
    S: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Option<crate::srv::SrvHost>> + Send,
{
    let weak: Weak<RwLock<Target>> = Arc::downgrade(target);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            // Upgrade only momentarily: the loop must not itself keep the
            // target (and thus the proxy) alive across the sleep above.
            let Some(target) = weak.upgrade() else {
                debug!("proxy dropped; stopping failover re-probe loop");
                break;
            };
            if let Some(primary) = select().await {
                apply_primary(&target, primary);
            }
            drop(target);
        }
    })
}

/// Which [`Proxy`] constructor a parsed connection string routes to.
///
/// Separated from [`Proxy::from_uri`] so the scheme/host-count dispatch —
/// the crux of *which* URIs get primary-probed (#26) — is unit-testable
/// without opening sockets or hitting DNS. The async constructors that
/// actually probe live behind this pure decision.
#[derive(Debug, PartialEq, Eq)]
enum UriRoute {
    /// One named host: forwarded to verbatim, no probe (the caller chose
    /// exactly one host, so there's nothing to select).
    Single {
        host: String,
        port: u16,
        use_tls: bool,
    },
    /// A `mongodb://h1,h2,h3/` seed list: probe every host and forward to
    /// the replica-set primary.
    SeedList {
        hosts: Vec<crate::srv::SrvHost>,
        use_tls: bool,
    },
    /// A `mongodb+srv://hostname/` URI: resolve SRV, then probe.
    Srv {
        hostname: String,
        use_tls: bool,
        /// The `srvServiceName` override, or `None` to use the default
        /// `mongodb` service name.
        service_name: Option<String>,
    },
}

/// Classifies a parsed URI into the constructor path it should take,
/// applying the per-scheme TLS default and the per-host default port.
///
/// The only error is a defensive [`FromUriError::Parse`] for an empty
/// host list — [`crate::uri::parse`] already rejects that, so it's
/// unreachable in practice, but routing without an `unwrap`/`expect`
/// keeps the no-panic policy intact.
fn route(parsed: crate::uri::ParsedConnectionUri) -> Result<UriRoute, FromUriError> {
    let crate::uri::ParsedConnectionUri {
        scheme,
        hosts,
        tls,
        srv_service_name,
    } = parsed;
    match scheme {
        crate::uri::Scheme::Mongodb => {
            // Spec default for non-SRV URIs: TLS off.
            let use_tls = tls.unwrap_or(false);
            if hosts.len() > 1 {
                // Replica-set seed list: probe every host and forward to
                // the primary (default port 27017 per host).
                let hosts = hosts
                    .into_iter()
                    .map(|h| crate::srv::SrvHost {
                        host: h.host,
                        port: h.port.unwrap_or(27017),
                    })
                    .collect();
                Ok(UriRoute::SeedList { hosts, use_tls })
            } else {
                // Exactly one host (the parser rejects an empty host list).
                match hosts.into_iter().next() {
                    Some(h) => Ok(UriRoute::Single {
                        host: h.host,
                        port: h.port.unwrap_or(27017),
                        use_tls,
                    }),
                    None => Err(FromUriError::Parse(
                        crate::uri::ConnectionUriError::MissingHost,
                    )),
                }
            }
        }
        crate::uri::Scheme::MongodbSrv => {
            // Spec default for SRV URIs: TLS on. The parser guarantees
            // exactly one host for the SRV scheme.
            let use_tls = tls.unwrap_or(true);
            match hosts.into_iter().next() {
                Some(h) => Ok(UriRoute::Srv {
                    hostname: h.host,
                    use_tls,
                    service_name: srv_service_name,
                }),
                None => Err(FromUriError::Parse(
                    crate::uri::ConnectionUriError::MissingHost,
                )),
            }
        }
    }
}

/// Failure modes for [`Proxy::from_uri`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FromUriError {
    /// The URI did not parse: bad scheme, missing host, invalid port,
    /// invalid `tls=` value, etc. See
    /// [`ConnectionUriError`](crate::ConnectionUriError) for the full
    /// list.
    #[error("invalid connection string: {0}")]
    Parse(#[from] crate::uri::ConnectionUriError),
    /// The SRV lookup for a `mongodb+srv://` URI failed. See
    /// [`SrvResolveError`](crate::SrvResolveError) for the full list.
    #[error("SRV resolution failed: {0}")]
    Srv(#[from] crate::srv::SrvResolveError),
    /// A multi-host `mongodb://h1,h2,h3/` seed list parsed, but none of
    /// the listed hosts responded as the replica-set primary within the
    /// per-host probe timeout. The proxy is single-upstream — without a
    /// primary it can't safely forward writes (a secondary rejects
    /// anything lacking the `secondaryOk` flag the
    /// [`RewriteHelloLayer`] deliberately hides). Analogous to
    /// [`SrvResolveError::NoPrimary`](crate::SrvResolveError::NoPrimary)
    /// for the non-SRV case.
    ///
    /// `attempts` pairs every probed seed-list host with the reason it was
    /// rejected (a [`ProbeOutcome`](crate::ProbeOutcome)), so the operator
    /// can tell a refused connection from a healthy secondary from a probe
    /// timeout instead of seeing only a count.
    #[error(
        "no primary found among {} seed-list hosts ({})",
        attempts.len(),
        crate::srv::summarise_attempts(attempts)
    )]
    NoPrimary {
        /// Every probed seed-list host paired with why it was rejected, in
        /// probe-completion order. `attempts.len()` is the number tried.
        attempts: Vec<(crate::srv::SrvHost, crate::serve::probe::ProbeOutcome)>,
    },
}

impl<L> Proxy<L> {
    /// Chains another tower [`Layer`] around the inner [`ProxyClient`].
    ///
    /// Layers are applied outer-most last (same convention as tower's
    /// `ServiceBuilder`). Use this to add custom middleware (rate limiting,
    /// auth, redaction, etc.) without writing a new [`Service`].
    pub fn layer<T>(self, layer: T) -> Proxy<Stack<T, L>> {
        Proxy {
            target: self.target,
            tls_connector: self.tls_connector,
            rewrite_hello: self.rewrite_hello,

            proxy_layer: Stack::new(layer, self.proxy_layer),
        }
    }

    /// Turns off the default `hello` / `isMaster` rewrite.
    ///
    /// **You probably don't want to call this.** With the rewrite off,
    /// SDAM-enabled drivers read the upstream's `setName` / `hosts` /
    /// `primary` / `me` from the hello reply and *open fresh TCP
    /// connections directly to those advertised addresses* — bypassing
    /// the proxy entirely for everything after the handshake. The proxy
    /// won't error; it just stops seeing requests, silently breaking
    /// every layer in the stack (logging, explain, custom middleware).
    ///
    /// Disabling is appropriate only when you specifically need the
    /// upstream's topology visible to drivers (driver-side SDAM testing,
    /// using the proxy as a transparent observability tap), and you've
    /// arranged for the driver to reach the proxy some other way (e.g.
    /// `?directConnection=true` in the URI).
    ///
    /// See [`RewriteHelloLayer`] for the full rationale and the list of
    /// fields the rewrite strips.
    pub fn disable_rewrite_hello(mut self) -> Self {
        self.rewrite_hello = false;
        self
    }

    /// Convenience for `self.layer(LogLayer)`.
    ///
    /// Every request and every reply (including intermediate replies of a
    /// streamed response) is logged at `info` level with structured
    /// `direction`, `op`, `command`, and identifier fields.
    pub fn enable_logging(self) -> Proxy<Stack<LogLayer, L>> {
        self.layer(LogLayer)
    }

    /// Convenience for `self.layer(ExplainLayer::new())`.
    ///
    /// Captures explainable client commands (`find`, `aggregate`, …) and
    /// emits a typed `tracing::info!` event with the executed plan and
    /// per-stage timing. No user-supplied sink is wired — use
    /// [`enable_explain_with_sink`](Self::enable_explain_with_sink) to
    /// consume typed [`ExplainEvent`](crate::ExplainEvent)s programmatically.
    pub fn enable_explain(
        self,
    ) -> Proxy<Stack<crate::serve::explain::ExplainLayer<crate::serve::explain::TracingOnly>, L>>
    {
        self.layer(crate::serve::explain::ExplainLayer::new())
    }

    /// Convenience for `self.layer(ExplainLayer::with_sink(sink))`.
    ///
    /// `sink` receives a typed [`ExplainEvent`](crate::ExplainEvent) for
    /// every explainable client command and a typed
    /// [`ExplainError`](crate::ExplainError) for every failure. The sink
    /// `Clone`s once per accepted connection — keep it O(1) (refcount or
    /// `Copy`).
    pub fn enable_explain_with_sink<Sk>(
        self,
        sink: Sk,
    ) -> Proxy<Stack<crate::serve::explain::ExplainLayer<Sk>, L>>
    where
        Sk: Clone,
    {
        self.layer(crate::serve::explain::ExplainLayer::with_sink(sink))
    }
}

impl<L> Service<SocketAddr> for Proxy<L>
where
    L: Clone + Layer<RewriteHelloService<ProxyClient>> + Send + 'static,
    L::Service: Service<Message>,
{
    type Response = L::Service;
    type Error = ProxyClientForwardError;
    type Future = ProxyClientCreationFuture<L::Service>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: SocketAddr) -> Self::Future {
        // Read the target fresh per connection so a failover swap by the
        // background loop is picked up without retargeting in-flight ones.
        let (destination_name, destination_port) = read_target(&self.target);
        let tls_connector = self.tls_connector.clone();

        let layer = self.proxy_layer.clone();
        // Innermost wrap. When disabled the layer becomes a pass-through
        // (still walks every reply but never mutates), so the type stack
        // stays stable regardless of the toggle.
        let rewrite_layer = if self.rewrite_hello {
            RewriteHelloLayer::enabled()
        } else {
            RewriteHelloLayer::disabled()
        };

        ProxyClientCreationFuture(Box::pin(async move {
            ProxyClient::forward_to(destination_name, destination_port, tls_connector)
                .await
                .map(|s| layer.layer(rewrite_layer.layer(s)))
        }))
    }
}

/// Future returned by `<Proxy as Service<SocketAddr>>::call`.
///
/// Resolves to the per-connection [`Service<Message>`] (typically a
/// layered [`ProxyClient`]) once the upstream socket is fully established.
pub struct ProxyClientCreationFuture<S>(
    Pin<Box<dyn Future<Output = Result<S, ProxyClientForwardError>> + Send + 'static>>,
)
where
    S: Service<Message>;

impl<S> Future for ProxyClientCreationFuture<S>
where
    S: Service<Message>,
{
    type Output = Result<S, ProxyClientForwardError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

/// Per-connection [`Service<Message>`] holding one upstream socket.
///
/// Implements [`Service<Message>`] with `Response = `[`ProxyResponseStream`].
/// Each `call` writes the request to the upstream socket and returns a
/// stream that yields zero or more replies until the upstream signals end
/// of stream (or fewer replies in fire-and-forget mode).
///
/// Construct via [`ProxyClient::forward_to`]; or via [`Proxy::call`] which
/// builds one per accepted client connection.
///
/// `Clone` is cheap (single `Arc::clone`) and exists so middleware layers
/// that need to issue more than one call through the per-connection
/// service (e.g. `ExplainLayer`'s sideband explain) can move a handle
/// into their boxed future.
#[derive(Clone)]
pub struct ProxyClient {
    inner: Arc<Mutex<ProxyClientInner>>,
}

struct ProxyClientInner {
    server_reader: ServerReader,
    server_writer: ServerWriter,
}

/// Failure modes for [`ProxyClient::forward_to`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyClientForwardError {
    /// `TcpStream::connect` to the upstream failed (DNS, refused, etc.).
    #[error("failed to connect to proxied server: {0}")]
    FailedToConnectToProxiedServer(io::Error),
    /// `destination_name` is not a valid DNS name for use with TLS SNI.
    #[error("invalid server name: {0}")]
    InvalidServerName(InvalidDnsNameError),
    /// The TLS handshake itself failed (cert validation, protocol, etc.).
    #[error("tls handshake failed: {0}")]
    TlsHandshake(io::Error),
}

impl ProxyClient {
    /// Opens an upstream TCP (and optionally TLS) socket and wraps it in
    /// the proxy's framed reader / writer pair.
    ///
    /// `destination_name` is used both for DNS resolution and (when
    /// `tls_connector` is `Some`) for SNI. Passing `None` produces a
    /// plain-TCP proxy.
    ///
    /// # Errors
    ///
    /// See [`ProxyClientForwardError`].
    pub async fn forward_to(
        destination_name: String,
        destination_port: u16,
        tls_connector: Option<Arc<TlsConnector>>,
    ) -> Result<Self, ProxyClientForwardError> {
        let addr = format!("{destination_name}:{destination_port}");
        let server_stream = TcpStream::connect(addr)
            .await
            .map_err(ProxyClientForwardError::FailedToConnectToProxiedServer)?;

        let (server_reader, server_writer): (BoxedAsyncRead, BoxedAsyncWrite) =
            if let Some(connector) = tls_connector {
                let domain = ServerName::try_from(destination_name)
                    .map_err(ProxyClientForwardError::InvalidServerName)?;
                let tls_stream = connector
                    .connect(domain, server_stream)
                    .await
                    .map_err(ProxyClientForwardError::TlsHandshake)?;
                let (reader, writer) = split(tls_stream);
                (Box::pin(reader), Box::pin(writer))
            } else {
                let (reader, writer) = server_stream.into_split();
                (Box::pin(reader), Box::pin(writer))
            };

        let server_reader = FramedRead::new(server_reader, WireDecoder::default());
        let server_writer = FramedWrite::new(server_writer, WireEncoder::default());

        Ok(Self {
            inner: Arc::new(Mutex::new(ProxyClientInner {
                server_reader,
                server_writer,
            })),
        })
    }
}

/// Returns true if `op` is an OP_MSG carrying the moreToCome flag.
///
/// On a *request* this means fire-and-forget: the server will not reply.
/// On a *response* it means another reply will follow on the same socket.
fn more_to_come(op: &Operation) -> bool {
    matches!(
        op,
        Operation::Message(m) if m.flags.contains(OperationMessageFlags::MORE_TO_COME)
    )
}

/// Stream of upstream replies for a single client request.
///
/// In the common case this yields exactly one message and then `None`. When
/// the upstream sets `moreToCome` on its reply (streaming SDAM / exhaust
/// cursors), the stream keeps yielding until a terminal message arrives.
/// For fire-and-forget requests the stream is empty.
///
/// The stream owns the upstream mutex guard for its lifetime, which prevents
/// other request/response pairs on the same `ProxyClient` from interleaving
/// with an in-flight streamed reply.
pub struct ProxyResponseStream {
    state: ProxyResponseStreamState,
}

enum ProxyResponseStreamState {
    /// No further reads expected (fire-and-forget request or stream done).
    Done,
    /// Holding the upstream guard; reads from `server_reader`.
    Streaming(OwnedMutexGuard<ProxyClientInner>),
}

impl ProxyResponseStream {
    fn empty() -> Self {
        Self {
            state: ProxyResponseStreamState::Done,
        }
    }

    fn streaming(guard: OwnedMutexGuard<ProxyClientInner>) -> Self {
        Self {
            state: ProxyResponseStreamState::Streaming(guard),
        }
    }
}

impl Stream for ProxyResponseStream {
    type Item = Result<Message, ProxyClientRequestError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let guard = match &mut self.state {
            ProxyResponseStreamState::Done => return Poll::Ready(None),
            ProxyResponseStreamState::Streaming(guard) => guard,
        };

        match guard.server_reader.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.state = ProxyResponseStreamState::Done;
                Poll::Ready(Some(Err(ProxyClientRequestError::EndOfStream)))
            }
            Poll::Ready(Some(Err(e))) => {
                self.state = ProxyResponseStreamState::Done;
                Poll::Ready(Some(Err(e.into())))
            }
            Poll::Ready(Some(Ok(msg))) => {
                if !more_to_come(&msg.operation) {
                    self.state = ProxyResponseStreamState::Done;
                }
                Poll::Ready(Some(Ok(msg)))
            }
        }
    }
}

impl Service<Message> for ProxyClient {
    type Response = ProxyResponseStream;
    type Error = ProxyClientRequestError;

    type Future = ProxyClientRequestFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // ProxyClient owns a single upstream socket and is used by exactly one
        // accept_client_inner task that issues request/response serially. The
        // Arc<Mutex<...>> exists only to satisfy the 'static bound on the future;
        // it is never contended, so always-ready is correct.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Message) -> Self::Future {
        let inner = self.inner.clone();
        let fire_and_forget = more_to_come(&req.operation);
        ProxyClientRequestFuture(Box::pin(async move {
            let mut guard = inner.lock_owned().await;
            guard.server_writer.send(req).await?;
            if fire_and_forget {
                drop(guard);
                Ok(ProxyResponseStream::empty())
            } else {
                Ok(ProxyResponseStream::streaming(guard))
            }
        }))
    }
}

/// Failure modes for an in-flight request against [`ProxyClient`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProxyClientRequestError {
    /// Underlying socket I/O failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// Upstream closed the socket while a reply was still pending.
    #[error("end of stream")]
    EndOfStream,
    /// Encoding the request before sending it upstream failed.
    #[error("wire encode error: {0}")]
    WireEncode(#[from] WireEncoderError),
    /// Decoding an upstream reply failed.
    #[error("wire decode error: {0}")]
    WireDecode(#[from] WireDecoderError),
}

/// Future returned by `<ProxyClient as Service<Message>>::call`.
///
/// Resolves to a [`ProxyResponseStream`] once the request has been written
/// to the upstream and the proxy has acquired the upstream guard. The
/// caller then drains the stream to receive replies.
pub struct ProxyClientRequestFuture(
    Pin<
        Box<
            dyn Future<Output = Result<ProxyResponseStream, ProxyClientRequestError>>
                + Send
                + 'static,
        >,
    >,
);

impl Future for ProxyClientRequestFuture {
    type Output = Result<ProxyResponseStream, ProxyClientRequestError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroI32;

    use bson::doc;
    use futures::StreamExt;
    use tokio::io::{AsyncWriteExt, duplex};
    use tokio_util::bytes::BytesMut;

    use super::*;
    use crate::ids::{RequestId, ResponseTo};
    use crate::operation::op_msg::{OpMsgSection, OperationMessage, OperationMessageFlags};

    fn build_msg(
        flags: OperationMessageFlags,
        request_id: i32,
        response_to: Option<NonZeroI32>,
    ) -> Message {
        Message {
            request_id: RequestId::new(request_id),
            response_to: response_to.map(ResponseTo::new),
            operation: Operation::Message(OperationMessage {
                flags,
                sections: vec![OpMsgSection::Body(doc! { "n": request_id })],
                checksum: None,
            }),
        }
    }

    /// Build a `ProxyClient` whose upstream socket is a `duplex` pipe so tests
    /// can script byte-level reply sequences without touching the network.
    fn proxy_against_duplex() -> (ProxyClient, tokio::io::DuplexStream) {
        let (upstream_side, proxy_side) = duplex(64 * 1024);
        let (proxy_read, proxy_write) = tokio::io::split(proxy_side);

        let server_reader = FramedRead::new(
            Box::pin(proxy_read) as BoxedAsyncRead,
            WireDecoder::default(),
        );
        let server_writer = FramedWrite::new(
            Box::pin(proxy_write) as BoxedAsyncWrite,
            WireEncoder::default(),
        );

        let client = ProxyClient {
            inner: Arc::new(Mutex::new(ProxyClientInner {
                server_reader,
                server_writer,
            })),
        };
        (client, upstream_side)
    }

    fn encode_messages(messages: &[Message]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        for m in messages {
            m.write_bytes(&mut buf).expect("encode succeeds");
        }
        buf.to_vec()
    }

    #[tokio::test]
    async fn streaming_response_yields_until_terminal_reply() {
        let (mut client, mut upstream) = proxy_against_duplex();

        let replies = vec![
            build_msg(OperationMessageFlags::MORE_TO_COME, 101, NonZeroI32::new(1)),
            build_msg(OperationMessageFlags::MORE_TO_COME, 102, NonZeroI32::new(1)),
            build_msg(OperationMessageFlags::empty(), 103, NonZeroI32::new(1)),
        ];
        let bytes = encode_messages(&replies);
        // Push the scripted replies onto the upstream side. Spawn so the
        // proxy can begin reading concurrently.
        tokio::spawn(async move {
            upstream.write_all(&bytes).await.expect("upstream write");
        });

        let req = build_msg(OperationMessageFlags::empty(), 1, None);
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .expect("call succeeds");

        let r1 = stream.next().await.expect("first reply").expect("ok");
        let r2 = stream.next().await.expect("second reply").expect("ok");
        let r3 = stream.next().await.expect("third reply").expect("ok");
        assert_eq!(r1.request_id, RequestId::new(101));
        assert_eq!(r2.request_id, RequestId::new(102));
        assert_eq!(r3.request_id, RequestId::new(103));
        assert!(more_to_come(&r1.operation));
        assert!(more_to_come(&r2.operation));
        assert!(!more_to_come(&r3.operation));

        // After the terminal reply the stream must complete.
        assert!(
            stream.next().await.is_none(),
            "stream must end after non-MORE_TO_COME reply"
        );
    }

    #[tokio::test]
    async fn single_reply_response_completes_after_one_message() {
        let (mut client, mut upstream) = proxy_against_duplex();

        let replies = vec![build_msg(
            OperationMessageFlags::empty(),
            200,
            NonZeroI32::new(1),
        )];
        let bytes = encode_messages(&replies);
        tokio::spawn(async move {
            upstream.write_all(&bytes).await.expect("upstream write");
        });

        let req = build_msg(OperationMessageFlags::empty(), 1, None);
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .expect("call succeeds");

        let r = stream.next().await.expect("reply").expect("ok");
        assert_eq!(r.request_id, RequestId::new(200));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn fire_and_forget_request_returns_empty_stream() {
        let (mut client, _upstream) = proxy_against_duplex();

        // Request carries MORE_TO_COME -> server will not reply, proxy must
        // return an empty response stream rather than blocking on a read.
        let req = build_msg(OperationMessageFlags::MORE_TO_COME, 1, None);
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .expect("call succeeds");

        assert!(
            stream.next().await.is_none(),
            "fire-and-forget request must produce no reply"
        );
    }

    #[tokio::test]
    async fn upstream_eof_mid_stream_surfaces_as_end_of_stream_error() {
        let (mut client, mut upstream) = proxy_against_duplex();

        let req = build_msg(OperationMessageFlags::empty(), 1, None);
        let mut stream = <ProxyClient as Service<Message>>::call(&mut client, req)
            .await
            .expect("call succeeds");

        // Send one MORE_TO_COME reply then close the upstream socket without
        // ever sending the terminal reply.
        let partial = encode_messages(&[build_msg(
            OperationMessageFlags::MORE_TO_COME,
            100,
            NonZeroI32::new(1),
        )]);
        upstream.write_all(&partial).await.expect("write reply");
        upstream.shutdown().await.expect("shutdown");
        drop(upstream);

        let first = stream.next().await.expect("first reply").expect("ok reply");
        assert_eq!(first.request_id, RequestId::new(100));
        assert!(more_to_come(&first.operation));

        let eof = stream
            .next()
            .await
            .expect("stream yields the EOF before terminating");
        assert!(matches!(eof, Err(ProxyClientRequestError::EndOfStream)));
        assert!(stream.next().await.is_none());
    }

    // ---------- TLS config -> connector wiring ----------

    #[test]
    fn with_tls_disabled_yields_no_connector() {
        let proxy = Proxy::with_tls("mongo.example.com", 27017, TlsConfig::Disabled);
        assert!(
            proxy.tls_connector.is_none(),
            "TlsConfig::Disabled must produce a plain-TCP proxy with no connector"
        );
    }

    #[test]
    fn with_tls_system_builds_a_connector() {
        let proxy = Proxy::with_tls("mongo.example.com", 27017, TlsConfig::System);
        assert!(
            proxy.tls_connector.is_some(),
            "TlsConfig::System must build a TLS connector"
        );
    }

    #[test]
    fn with_tls_with_roots_builds_a_connector() {
        // An empty custom store is still a valid (if unusable) verifying
        // config — what we assert here is that the connector is built, not
        // that any particular chain verifies.
        let proxy = Proxy::with_tls(
            "mongo.example.com",
            27017,
            TlsConfig::WithRoots(RootCertStore::empty()),
        );
        assert!(
            proxy.tls_connector.is_some(),
            "TlsConfig::WithRoots must build a TLS connector"
        );
    }

    #[test]
    fn new_with_use_tls_true_matches_system() {
        let proxy = Proxy::new("mongo.example.com", 27017, true);
        assert!(
            proxy.tls_connector.is_some(),
            "Proxy::new(.., true) must still build a TLS connector"
        );
    }

    #[test]
    fn new_with_use_tls_false_matches_disabled() {
        let proxy = Proxy::new("mongo.example.com", 27017, false);
        assert!(
            proxy.tls_connector.is_none(),
            "Proxy::new(.., false) must still be plain TCP"
        );
    }

    #[test]
    fn build_tls_connector_disabled_is_none() {
        assert!(build_tls_connector(TlsConfig::Disabled).is_none());
    }

    #[test]
    fn build_tls_connector_system_is_some() {
        assert!(build_tls_connector(TlsConfig::System).is_some());
    }

    #[cfg(feature = "dangerous-insecure-tls")]
    #[test]
    fn with_tls_insecure_builds_a_connector() {
        let proxy = Proxy::with_tls("mongo.example.com", 27017, TlsConfig::Insecure);
        assert!(
            proxy.tls_connector.is_some(),
            "TlsConfig::Insecure must build a TLS connector"
        );
    }

    // ---------- failover: target cell + apply_primary ----------

    fn target_cell(host: &str, port: u16) -> Arc<RwLock<Target>> {
        Arc::new(RwLock::new(Target {
            host: host.into(),
            port,
        }))
    }

    fn srv_host(host: &str, port: u16) -> crate::srv::SrvHost {
        crate::srv::SrvHost {
            host: host.into(),
            port,
        }
    }

    #[test]
    fn apply_primary_swaps_target_when_host_changes() {
        let cell = target_cell("old.example.com", 27017);
        let swapped = apply_primary(&cell, srv_host("new.example.com", 27017));
        assert!(swapped, "differing host must trigger a swap");
        assert_eq!(read_target(&cell), ("new.example.com".to_owned(), 27017));
    }

    #[test]
    fn apply_primary_swaps_target_when_only_port_changes() {
        let cell = target_cell("host.example.com", 27017);
        let swapped = apply_primary(&cell, srv_host("host.example.com", 27018));
        assert!(swapped, "differing port must trigger a swap");
        assert_eq!(read_target(&cell), ("host.example.com".to_owned(), 27018));
    }

    #[test]
    fn apply_primary_is_noop_when_target_unchanged() {
        let cell = target_cell("host.example.com", 27017);
        let swapped = apply_primary(&cell, srv_host("host.example.com", 27017));
        assert!(!swapped, "identical host:port must not swap");
        assert_eq!(read_target(&cell), ("host.example.com".to_owned(), 27017));
    }

    // ---------- multi-host seed-list selection: select_target ----------
    //
    // `from_uri`'s multi-host arm and `from_srv` both build their
    // swappable target via `select_target`. These drive that selection
    // with a `MockPrimaryProbe` so the "probe the seed list, pick the
    // primary" wiring is verified without real sockets — the same gap
    // `from_uri` would otherwise only exercise against a live cluster.

    use crate::serve::probe::{DEFAULT_PROBE_TIMEOUT, MockPrimaryProbe};

    #[tokio::test]
    async fn select_target_builds_cell_for_the_probed_primary() {
        // Seed list with the primary last (the Atlas-order worst case):
        // the first two hosts are secondaries, the third is primary.
        let hosts = vec![
            srv_host("secondary-a.example.com", 27017),
            srv_host("secondary-b.example.com", 27017),
            srv_host("primary.example.com", 27017),
        ];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|host, _port| Ok(host == "primary.example.com"));

        let cell = select_target(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
            .await
            .expect("a primary must be selected");
        assert_eq!(
            read_target(&cell),
            ("primary.example.com".to_owned(), 27017)
        );
    }

    #[tokio::test]
    async fn select_target_errors_with_per_host_outcomes_when_no_host_is_primary() {
        let hosts = vec![
            srv_host("a.example.com", 27017),
            srv_host("b.example.com", 27017),
        ];
        let mut probe = MockPrimaryProbe::new();
        probe.expect_is_primary().returning(|_, _| Ok(false));

        // No primary must surface the per-host reasons (here: both are
        // healthy secondaries) so the constructor can build a diagnostic
        // `NoPrimary` rather than a bare count.
        let attempts = select_target(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
            .await
            .expect_err("no primary among the seed list must be an Err carrying outcomes");
        assert_eq!(attempts.len(), 2);
        assert!(
            attempts
                .iter()
                .all(|(_, o)| matches!(o, crate::serve::probe::ProbeOutcome::NotPrimary)),
            "both secondaries must be reported as NotPrimary, got {attempts:?}",
        );
    }

    #[tokio::test]
    async fn reselect_seed_list_picks_the_current_primary_on_reprobe() {
        // The failover loop's per-tick body for a static seed list must
        // re-pick the primary after it moves to a different host.
        let hosts = vec![
            srv_host("a.example.com", 27017),
            srv_host("b.example.com", 27017),
        ];
        let mut probe = MockPrimaryProbe::new();
        probe
            .expect_is_primary()
            .returning(|host, _port| Ok(host == "b.example.com"));

        let picked = reselect_seed_list(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
            .await
            .expect("re-probe finds the new primary");
        assert_eq!(picked, srv_host("b.example.com", 27017));
    }

    // ---------- configurable per-host probe timeout (#27) ----------
    //
    // `select_target` (shared by `from_srv` and the multi-host `from_uri`
    // arm) must thread the configured budget into `select_primary`, so a
    // cold-starting cluster is reached under a widened timeout instead of
    // failing startup with a spurious `NoPrimary`. A hand-rolled probe
    // that sleeps before answering lets `start_paused` virtual time prove
    // the budget is honoured without wall-clock flakiness.

    /// Primary that only answers its first `hello` after `delay` —
    /// stands in for an Atlas free-tier node cold-starting.
    struct ColdPrimaryProbe {
        delay: Duration,
    }

    impl crate::serve::probe::PrimaryProbe for ColdPrimaryProbe {
        async fn is_primary(
            &self,
            _host: String,
            _port: u16,
        ) -> Result<bool, crate::serve::probe::ProbeError> {
            tokio::time::sleep(self.delay).await;
            Ok(true)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn select_target_misses_a_cold_primary_under_the_default_timeout() {
        let hosts = vec![srv_host("cold.example.com", 27017)];
        let probe = ColdPrimaryProbe {
            delay: Duration::from_secs(8),
        };
        let attempts = select_target(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
            .await
            .expect_err("the 5s default must time out before the cold primary answers");
        assert!(
            matches!(
                attempts.as_slice(),
                [(_, crate::serve::probe::ProbeOutcome::TimedOut)]
            ),
            "the cold primary must be reported as a timeout, got {attempts:?}",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn select_target_reaches_a_cold_primary_under_a_widened_timeout() {
        let hosts = vec![srv_host("cold.example.com", 27017)];
        let probe = ColdPrimaryProbe {
            delay: Duration::from_secs(8),
        };
        let cell = select_target(&hosts, &probe, Duration::from_secs(15))
            .await
            .expect("a widened budget must reach the cold-starting primary");
        assert_eq!(read_target(&cell), ("cold.example.com".to_owned(), 27017));
    }

    #[tokio::test(start_paused = true)]
    async fn reselect_seed_list_honours_the_supplied_probe_timeout() {
        // The seed-list re-probe is the per-tick body of the background
        // failover loop, which captures `failover.probe_timeout`. A cold
        // primary mid-failover must still be reachable under a widened
        // budget — and missed under the default — so the re-probe path is
        // proven to thread the budget, not just the startup selection.
        let hosts = vec![srv_host("cold.example.com", 27017)];
        let probe = ColdPrimaryProbe {
            delay: Duration::from_secs(8),
        };
        assert!(
            reselect_seed_list(&hosts, &probe, DEFAULT_PROBE_TIMEOUT)
                .await
                .is_none(),
            "default budget must time out the cold primary on re-probe",
        );
        let picked = reselect_seed_list(&hosts, &probe, Duration::from_secs(15))
            .await
            .expect("widened budget must reach the cold primary on re-probe");
        assert_eq!(picked, srv_host("cold.example.com", 27017));
    }

    // ---------- FailoverConfig probe-timeout knob ----------

    #[test]
    fn failover_config_default_uses_the_standard_probe_timeout() {
        assert_eq!(
            FailoverConfig::default().probe_timeout,
            DEFAULT_PROBE_TIMEOUT
        );
    }

    #[test]
    fn failover_config_every_keeps_the_default_probe_timeout() {
        let cfg = FailoverConfig::every(Duration::from_secs(30));
        assert_eq!(cfg.reprobe_interval, Some(Duration::from_secs(30)));
        assert_eq!(cfg.probe_timeout, DEFAULT_PROBE_TIMEOUT);
    }

    #[test]
    fn failover_config_disabled_keeps_a_probe_timeout_for_startup_selection() {
        // Turning the re-probe loop off must not disable the per-host
        // budget the one-shot startup selection still relies on.
        let cfg = FailoverConfig::disabled();
        assert_eq!(cfg.reprobe_interval, None);
        assert_eq!(cfg.probe_timeout, DEFAULT_PROBE_TIMEOUT);
    }

    #[test]
    fn failover_config_with_probe_timeout_overrides_only_the_timeout() {
        let cfg = FailoverConfig::default().with_probe_timeout(Duration::from_secs(20));
        assert_eq!(cfg.probe_timeout, Duration::from_secs(20));
        assert_eq!(cfg.reprobe_interval, Some(DEFAULT_REPROBE_INTERVAL));
    }

    // ---------- from_uri routing: route() ----------
    //
    // `from_uri`'s scheme/host-count dispatch is the crux of #26: a
    // single named host must be used verbatim, but a multi-host seed list
    // must be probed for the primary. `route` is the pure decision behind
    // the async constructors, so these assert that decision (and the
    // per-scheme TLS / per-host port defaults) without sockets or DNS.

    fn route_uri(uri: &str) -> UriRoute {
        route(crate::uri::parse(uri).expect("uri parses")).expect("uri routes")
    }

    #[test]
    fn route_single_host_plain_uri_is_used_verbatim_without_probing() {
        assert_eq!(
            route_uri("mongodb://only.example.com:27017/"),
            UriRoute::Single {
                host: "only.example.com".to_owned(),
                port: 27017,
                use_tls: false,
            }
        );
    }

    #[test]
    fn route_single_host_plain_uri_defaults_port_and_tls() {
        // No port -> 27017; no `tls=` -> off for the `mongodb://` scheme.
        assert_eq!(
            route_uri("mongodb://only.example.com/"),
            UriRoute::Single {
                host: "only.example.com".to_owned(),
                port: 27017,
                use_tls: false,
            }
        );
    }

    #[test]
    fn route_single_host_plain_uri_honours_tls_query() {
        assert_eq!(
            route_uri("mongodb://only.example.com/?tls=true"),
            UriRoute::Single {
                host: "only.example.com".to_owned(),
                port: 27017,
                use_tls: true,
            }
        );
    }

    #[test]
    fn route_multi_host_plain_uri_becomes_a_probed_seed_list() {
        // The #26 regression guard: more than one host must route to the
        // probe-and-select path, *not* be silently truncated to host #1.
        assert_eq!(
            route_uri("mongodb://a.example.com:27017,b.example.com:27018,c.example.com/"),
            UriRoute::SeedList {
                hosts: vec![
                    srv_host("a.example.com", 27017),
                    srv_host("b.example.com", 27018),
                    // No explicit port -> default 27017.
                    srv_host("c.example.com", 27017),
                ],
                use_tls: false,
            }
        );
    }

    #[test]
    fn route_multi_host_plain_uri_honours_tls_query() {
        match route_uri("mongodb://a.example.com,b.example.com/?tls=true") {
            UriRoute::SeedList { use_tls, hosts } => {
                assert!(use_tls, "explicit tls=true must propagate to the seed list");
                assert_eq!(hosts.len(), 2);
            }
            other => panic!("expected SeedList, got {other:?}"),
        }
    }

    #[test]
    fn route_srv_uri_defaults_tls_on() {
        assert_eq!(
            route_uri("mongodb+srv://cluster0.foo.mongodb.net/"),
            UriRoute::Srv {
                hostname: "cluster0.foo.mongodb.net".to_owned(),
                use_tls: true,
                service_name: None,
            }
        );
    }

    #[test]
    fn route_srv_uri_carries_srv_service_name_override() {
        assert_eq!(
            route_uri("mongodb+srv://cluster0.foo.mongodb.net/?srvServiceName=customdb"),
            UriRoute::Srv {
                hostname: "cluster0.foo.mongodb.net".to_owned(),
                use_tls: true,
                service_name: Some("customdb".to_owned()),
            }
        );
    }

    #[test]
    fn route_srv_uri_honours_tls_false_query() {
        assert_eq!(
            route_uri("mongodb+srv://cluster0.foo.mongodb.net/?tls=false"),
            UriRoute::Srv {
                hostname: "cluster0.foo.mongodb.net".to_owned(),
                use_tls: false,
                service_name: None,
            }
        );
    }

    // ---------- from_seed_list: NoPrimary error path ----------

    #[tokio::test]
    async fn from_seed_list_errors_no_primary_when_every_host_is_unreachable() {
        // Bind two loopback listeners to grab free ports, then drop them
        // so connections are refused immediately. Every probe fails to
        // connect, so selection finds no primary and `from_seed_list`
        // surfaces `NoPrimary` carrying the per-host failure reasons —
        // each a `Failed` connect, not just an opaque count.
        let (listener_a, port_a) = bound_listener().await;
        let (listener_b, port_b) = bound_listener().await;
        drop(listener_a);
        drop(listener_b);

        let hosts = vec![srv_host("127.0.0.1", port_a), srv_host("127.0.0.1", port_b)];
        match Proxy::from_seed_list(hosts, false, FailoverConfig::disabled()).await {
            Err(FromUriError::NoPrimary { attempts }) => {
                assert_eq!(attempts.len(), 2, "both seed-list hosts must be reported");
                assert!(
                    attempts
                        .iter()
                        .all(|(_, o)| matches!(o, crate::serve::probe::ProbeOutcome::Failed(_))),
                    "a refused TCP connect must be carried as Failed, got {attempts:?}",
                );
                // The refused-connect io::Error must remain reachable
                // through the error chain for operator diagnostics.
                let err = FromUriError::NoPrimary { attempts };
                assert!(
                    err.to_string().contains("127.0.0.1"),
                    "the Display summary must name the failed hosts: {err}",
                );
            }
            Err(other) => panic!("expected NoPrimary, got {other:?}"),
            Ok(_) => panic!("expected NoPrimary, got a proxy"),
        }
    }

    // ---------- failover: spawn_reprobe_loop ----------

    #[tokio::test(start_paused = true)]
    async fn reprobe_loop_swaps_target_when_select_returns_new_primary() {
        let cell = target_cell("old.example.com", 27017);
        let _handle = spawn_reprobe_loop(Duration::from_secs(60), &cell, || async {
            Some(srv_host("new.example.com", 27017))
        });

        // Nothing happens before the first interval elapses.
        tokio::task::yield_now().await;
        assert_eq!(read_target(&cell).0, "old.example.com");

        // Advance past one interval; the loop should re-select and swap.
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert_eq!(read_target(&cell), ("new.example.com".to_owned(), 27017));
    }

    #[tokio::test(start_paused = true)]
    async fn reprobe_loop_keeps_target_when_select_returns_none() {
        let cell = target_cell("old.example.com", 27017);
        let _handle = spawn_reprobe_loop(Duration::from_secs(60), &cell, || async { None });

        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        // `None` means "no primary found" — keep the current target.
        assert_eq!(read_target(&cell).0, "old.example.com");
    }

    #[tokio::test(start_paused = true)]
    async fn reprobe_loop_stops_after_proxy_dropped() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cell = target_cell("old.example.com", 27017);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_in_loop = calls.clone();
        let handle = spawn_reprobe_loop(Duration::from_secs(60), &cell, move || {
            let calls = calls_in_loop.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                None
            }
        });

        // Let the task register its first sleep before advancing the clock.
        tokio::task::yield_now().await;
        // One tick runs while the cell (the sole strong ref) is alive.
        tokio::time::advance(Duration::from_secs(61)).await;
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Drop the only strong reference — the loop holds just a `Weak`.
        drop(cell);
        // Next wake fails to upgrade and the task returns.
        tokio::time::advance(Duration::from_secs(61)).await;
        handle.await.expect("loop task joins cleanly after drop");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "select must not run again once the proxy is dropped"
        );
    }

    // ---------- failover: end-to-end through Service::call ----------
    //
    // The unit tests above prove the *decision* (apply_primary) and the
    // *loop* (spawn_reprobe_loop) in isolation. These two tie that
    // decision to an actually-forwarded connection: a swap must be
    // observed by the next `Service<SocketAddr>::call`, including after
    // the proxy has been wrapped in a layer stack. We use paired local
    // `TcpListener`s (rather than the `duplex` helper) because
    // `ProxyClient::forward_to` dials a real socket, and which listener
    // accepts is the observable signal of which target was used.

    async fn bound_listener() -> (tokio::net::TcpListener, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let port = listener.local_addr().expect("local addr").port();
        (listener, port)
    }

    #[tokio::test]
    async fn service_call_follows_a_target_swap_on_the_next_connection() {
        let (listener_a, port_a) = bound_listener().await;
        let (listener_b, port_b) = bound_listener().await;

        let cell = target_cell("127.0.0.1", port_a);
        let mut proxy = Proxy::with_target(cell.clone(), None);

        let dummy: SocketAddr = "127.0.0.1:1".parse().expect("parse client addr");

        // First connection lands on A (the current target).
        let call_fut = proxy.call(dummy);
        let (accept_a, client_a) = tokio::join!(listener_a.accept(), call_fut);
        accept_a.expect("listener A accepts the first connection");
        client_a.expect("proxy connects to A");

        // Swap the target out from under the live proxy.
        assert!(apply_primary(&cell, srv_host("127.0.0.1", port_b)));

        // The next connection must land on B, not A. If `Service::call`
        // had cached the original host instead of reading the cell fresh,
        // this accept on B would hang (and the test would time out).
        let call_fut = proxy.call(dummy);
        let (accept_b, client_b) = tokio::join!(listener_b.accept(), call_fut);
        accept_b.expect("listener B accepts after the swap");
        client_b.expect("proxy connects to B");
    }

    #[tokio::test]
    async fn layered_proxy_still_follows_target_swaps() {
        // `layer()` moves `self.target` into the new `Proxy`. This guards
        // the documented `from_srv(...).enable_logging()` promise: the
        // shared cell the background loop swaps must remain the same one
        // the *layered, served* proxy reads.
        let (listener_a, port_a) = bound_listener().await;
        let (listener_b, port_b) = bound_listener().await;

        let cell = target_cell("127.0.0.1", port_a);
        // Build, then wrap in a layer stack, keeping our own `cell` clone
        // to stand in for the background loop's handle.
        let mut proxy = Proxy::with_target(cell.clone(), None).enable_logging();

        let dummy: SocketAddr = "127.0.0.1:1".parse().expect("parse client addr");

        let call_fut = proxy.call(dummy);
        let (accept_a, built_a) = tokio::join!(listener_a.accept(), call_fut);
        accept_a.expect("layered proxy connects to A first");
        built_a.expect("layered service builds against A");

        assert!(apply_primary(&cell, srv_host("127.0.0.1", port_b)));

        let call_fut = proxy.call(dummy);
        let (accept_b, built_b) = tokio::join!(listener_b.accept(), call_fut);
        accept_b.expect("layered proxy follows the swap to B");
        built_b.expect("layered service builds against B");
    }
}
