//! railscale library - HTTP handlers and application setup.
//!
//! this crate provides the http server and handlers for the railscale control server:
//! - [`handlers`]: HTTP request handlers for Tailscale protocol endpoints
//! - [`cli`]: Command-line interface implementation
//! - [`oidc`]: OpenID Connect authentication provider
//! - [`derp`]: DERP relay map management
//! - [`derp_server`]: Embedded DERP relay server
//! - [`resolver`]: Grants-based access control resolver

#![warn(missing_docs)]

/// command-line interface for railscale.
pub mod cli;
/// derp map loading and generation utilities.
pub mod derp;
/// embedded derp relay server implementation.
pub mod derp_server;
mod dns;
mod dns_challenge_gc;
/// dns provider implementations for ACME dns-01 challenges
pub mod dns_provider;
mod ephemeral;
/// http request handlers for tailscale protocol endpoints.
pub mod handlers;
/// shared map response cache for node/user snapshots
pub mod map_cache;
/// per-connection session state for delta map responses
pub mod map_session;
mod noise_stream;
mod notifier;
/// openid connect authentication provider.
pub mod oidc;
mod presence;
mod rate_limit;
/// grants-based access control resolver.
pub mod resolver;
/// minimal stun server for nat traversal.
pub mod stun;

pub use derp::{
    DerpError, fetch_derp_map_from_url, generate_derp_map, load_derp_map_from_path,
    load_external_derp_maps, merge_derp_maps, spawn_derp_map_updater,
};
pub use ephemeral::EphemeralGarbageCollector;
pub use noise_stream::NoiseStream;
pub use notifier::StateNotifier;
pub use presence::PresenceTracker;
pub use railscale_proto::Keypair;

use std::path::Path;
use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use std::time::Duration;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};

use moka::sync::Cache;
use railscale_db::{Database, IpAllocator, RailscaleDb};
use railscale_grants::{GrantsEngine, Policy};
use railscale_proto::DerpMap;
use railscale_types::{Config, RegistrationId};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

use crate::oidc::PendingRegistration;

/// handle for hot-reloading policy at runtime.
///
/// obtained from [`create_app_with_policy_handle`] and can be used to update
/// the policy without restarting the server.
#[derive(Clone)]
pub struct PolicyHandle {
    engine: Arc<RwLock<GrantsEngine>>,
}

impl PolicyHandle {
    /// reload the policy with a new one.
    ///
    /// this atomically updates the policy used by all handlers.
    /// existing in-flight requests will complete with the old policy;
    /// new requests will use the new policy.
    pub async fn reload(&self, policy: Policy) {
        let mut engine = self.engine.write().await;
        engine.update_policy(policy);
    }

    /// reload the policy synchronously (for use outside async context).
    ///
    /// # Panics
    /// panics if called from within a tokio runtime. use [`reload`] instead.
    pub fn reload_blocking(&self, policy: Policy) {
        let mut engine = self.engine.blocking_write();
        engine.update_policy(policy);
    }

    /// get a clone of the inner grants engine.
    ///
    /// useful for creating compatible handles in other crates (e.g., admin service).
    pub fn engine(&self) -> Arc<RwLock<GrantsEngine>> {
        Arc::clone(&self.engine)
    }
}

/// application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    /// database connection for persistent storage.
    pub db: RailscaleDb,
    /// grants engine for access control evaluation (shared for hot-reload).
    pub grants: Arc<RwLock<GrantsEngine>>,
    /// server configuration.
    pub config: Config,
    /// oidc authentication provider (none if oidc is disabled).
    pub oidc: Option<oidc::AuthProviderOidc>,
    /// notifier for broadcasting state changes to connected clients.
    pub notifier: StateNotifier,
    /// ip address allocator for new nodes.
    pub ip_allocator: Arc<Mutex<IpAllocator>>,
    /// server's noise public key for ts2021 protocol.
    pub noise_public_key: Vec<u8>,
    /// server's noise private key for ts2021 protocol handshakes.
    /// wrapped in zeroizing for secure memory clearing on drop.
    pub noise_private_key: Zeroizing<Vec<u8>>,
    /// cache of pending registrations waiting for oidc completion.
    /// maps registrationid -> arc<pendingregistration>.
    pub pending_registrations: Cache<RegistrationId, Arc<PendingRegistration>>,
    /// derp map for relay coordination (shared for dynamic updates).
    pub derp_map: Arc<RwLock<DerpMap>>,
    /// dns resolution cache for /bootstrap-dns endpoint
    /// maps hostname -> resolved ip addresses. entries expire after 60 seconds.
    pub dns_cache: Cache<String, Vec<std::net::IpAddr>>,
    /// presence tracker for connected nodes (for online status).
    pub presence: PresenceTracker,
    /// geoip resolver for ip:country posture checks (None if not configured).
    pub geoip: Option<Arc<railscale_grants::MaxmindDbResolver>>,
    /// garbage collector for ephemeral nodes.
    pub ephemeral_gc: EphemeralGarbageCollector,
    /// shared map response cache for node/user snapshots
    pub map_cache: Arc<map_cache::MapCache>,
    /// dns provider for ACME dns-01 challenges (None if not configured)
    pub dns_provider: Option<Arc<dyn dns_provider::DnsProviderBoxed>>,
    /// cached TKA public key to avoid re-parsing genesis AUM on every request
    pub tka_public_key: Arc<RwLock<Option<railscale_tka::NlPublicKey>>>,
}

/// routers for the application, potentially running on separate listeners.
///
/// when `api.listen_host` is configured, the api router runs on a separate
/// listener from the protocol router. Otherwise, they're merged.
pub struct AppRouters {
    /// protocol router (tailscale client endpoints).
    pub protocol: Router,
    /// api router (rest admin endpoints), if api is enabled.
    pub api: Option<Router>,
    /// whether the api should run on a separate listener.
    pub api_separate: bool,
    /// shared derp map for dynamic updates (e.g., periodic refresh from URL/path).
    pub derp_map: Arc<RwLock<DerpMap>>,
}

/// load a noise keypair from file, or generate and save a new one.
///
/// if the file exists, reads the 64-byte keypair (32 private + 32 public).
/// if the file does not exist, generates a new keypair and saves it.
///
/// # Arguments
/// * `path` - Path to the key file
///
/// # Returns
/// the loaded or generated keypair.
pub async fn load_or_generate_noise_keypair(path: &Path) -> std::io::Result<Keypair> {
    if path.exists() {
        // load existing key
        let data = fs::read(path).await?;
        if data.len() != 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("noise key file should be 64 bytes, got {}", data.len()),
            ));
        }
        Ok(Keypair {
            private: data[..32].to_vec(),
            public: data[32..].to_vec(),
        })
    } else {
        // generate new keypair
        let keypair = railscale_proto::generate_keypair()
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // write keypair: private (32 bytes) + public (32 bytes)
        // use sync std::fs::openoptions to set restrictive permissions at creation time
        // (avoids a brief window with insecure default permissions)
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            let std_file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600) // Restrictive permissions at creation
                .open(path)?;
            fs::File::from_std(std_file)
        };

        #[cfg(not(unix))]
        let mut file = fs::File::create(path).await?;

        file.write_all(&keypair.private).await?;
        file.write_all(&keypair.public).await?;
        file.sync_all().await?;

        Ok(keypair)
    }
}

/// create the axum application with all routes.
///
/// if `keypair` is none, a new keypair will be generated (not persisted).
/// if `derp_map` is none, a default empty map will be used.
pub async fn create_app(
    db: RailscaleDb,
    grants: GrantsEngine,
    config: Config,
    oidc: Option<oidc::AuthProviderOidc>,
    notifier: StateNotifier,
    keypair: Option<Keypair>,
) -> Router {
    // generate derp map from config so tests and callers get a usable default
    let derp_map = derp::generate_derp_map(&config);
    let (app, _handle) = create_app_with_policy_handle(
        db,
        grants.policy().clone(),
        config,
        oidc,
        notifier,
        keypair,
        Some(derp_map),
    )
    .await;
    app
}

/// create the axum application with a handle for policy hot-reload.
///
/// returns both the router and a [`policyhandle`] that can be used to
/// reload the policy at runtime (e.g., in response to SIGHUP).
///
/// if `keypair` is none, a new keypair will be generated (not persisted).
/// if `derp_map` is none, a default empty map will be used.
///
/// NOTE: this function always merges api routes onto the protocol router.
/// for separate api listener support, use [`create_app_routers_with_policy_handle`].
pub async fn create_app_with_policy_handle(
    db: RailscaleDb,
    policy: Policy,
    config: Config,
    oidc: Option<oidc::AuthProviderOidc>,
    notifier: StateNotifier,
    keypair: Option<Keypair>,
    derp_map: Option<DerpMap>,
) -> (Router, PolicyHandle) {
    let (routers, handle) = create_app_routers_with_policy_handle(
        db, policy, config, oidc, notifier, keypair, derp_map,
    )
    .await;

    // merge api router onto protocol router if present
    let router = if let Some(api_router) = routers.api {
        routers.protocol.merge(api_router)
    } else {
        routers.protocol
    };

    (router, handle)
}

/// create separate routers for protocol and api endpoints.
///
/// returns [`approuters`] containing:
/// - Protocol router (Tailscale client endpoints)
/// - API router (REST admin endpoints), if API is enabled
/// - Flag indicating whether API should run on a separate listener
///
/// use this when you need to run the api on a separate port from the protocol.
/// the caller is responsible for starting the appropriate listeners based on
/// the `api_separate` flag.
///
/// if `keypair` is none, a new keypair will be generated (not persisted).
/// if `derp_map` is none, a default empty map will be used.
pub async fn create_app_routers_with_policy_handle(
    db: RailscaleDb,
    policy: Policy,
    config: Config,
    oidc: Option<oidc::AuthProviderOidc>,
    notifier: StateNotifier,
    keypair: Option<Keypair>,
    derp_map: Option<DerpMap>,
) -> (AppRouters, PolicyHandle) {
    let (state, handle) =
        build_app_state(db, policy, config, oidc, notifier, keypair, derp_map).await;

    let api_separate = state.config.api.enabled && state.config.api.listen_host.is_some();

    let protocol_router = build_protocol_router(&state);
    let api_router = if state.config.api.enabled {
        Some(build_api_router(&state))
    } else {
        None
    };

    let routers = AppRouters {
        protocol: protocol_router,
        api: api_router,
        api_separate,
        derp_map: state.derp_map.clone(),
    };

    (routers, handle)
}

/// construct AppState and PolicyHandle from config, spawning background tasks
async fn build_app_state(
    db: RailscaleDb,
    policy: Policy,
    config: Config,
    oidc: Option<oidc::AuthProviderOidc>,
    notifier: StateNotifier,
    keypair: Option<Keypair>,
    derp_map: Option<DerpMap>,
) -> (AppState, PolicyHandle) {
    let keypair = keypair.unwrap_or_else(|| {
        railscale_proto::generate_keypair().expect("failed to generate noise keypair")
    });

    // initialise ip allocator and load existing allocations
    let mut ip_allocator =
        IpAllocator::new(config.prefix_v4, config.prefix_v6, config.ip_allocation);

    if let Ok(nodes) = db.list_nodes().await {
        let allocated_ips: Vec<std::net::IpAddr> = nodes
            .iter()
            .flat_map(|n| [n.ipv4, n.ipv6])
            .flatten()
            .collect();
        ip_allocator.load_allocated(allocated_ips);
    }

    let grants = Arc::new(RwLock::new(GrantsEngine::new(policy)));
    let handle = PolicyHandle {
        engine: Arc::clone(&grants),
    };

    let pending_registrations = Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(900))
        .build();

    let derp_map = Arc::new(RwLock::new(derp_map.unwrap_or_default()));

    let dns_cache = Cache::builder()
        .max_capacity(1000)
        .time_to_live(Duration::from_secs(60))
        .build();

    let geoip = config.geoip_database_path.as_ref().and_then(|path| {
        match railscale_grants::MaxmindDbResolver::from_path(path) {
            Some(resolver) => {
                tracing::info!(?path, "loaded geoip database for ip:country posture checks");
                Some(Arc::new(resolver))
            }
            None => {
                tracing::warn!(
                    ?path,
                    "geoip_database_path configured but database not found or invalid"
                );
                None
            }
        }
    });

    let ip_allocator = Arc::new(Mutex::new(ip_allocator));

    // ephemeral node garbage collector
    let ephemeral_gc =
        EphemeralGarbageCollector::new(db.clone(), config.ephemeral_node_inactivity_timeout_secs)
            .with_ip_allocator(ip_allocator.clone());

    if ephemeral_gc.is_enabled() {
        let gc = ephemeral_gc.clone();
        tokio::spawn(async move {
            let _ = gc.spawn_collector(Duration::from_secs(30)).await;
        });
    }

    // map response cache with pre-computed dns config
    let cached_dns_config = dns::generate_dns_config(&config);
    let map_cache = Arc::new(map_cache::MapCache::new(cached_dns_config));
    notifier.set_map_cache(Arc::clone(&map_cache));

    // dns provider for ACME dns-01 challenges
    let dns_provider_boxed: Option<Arc<dyn dns_provider::DnsProviderBoxed>> =
        config.dns_provider.as_ref().map(|provider_config| {
            tracing::info!(
                ?provider_config,
                "dns provider configured for tailscale cert"
            );
            Arc::from(dns_provider::from_config(
                provider_config,
                &config.base_domain,
            ))
        });

    if let Some(ref provider) = dns_provider_boxed {
        let gc = dns_challenge_gc::DnsChallengeGarbageCollector::new(
            db.clone(),
            Arc::clone(provider),
            600,
        );
        gc.spawn_collector(Duration::from_secs(60));
    }

    let state = AppState {
        db,
        grants,
        config,
        oidc,
        notifier,
        ip_allocator,
        noise_public_key: keypair.public,
        noise_private_key: Zeroizing::new(keypair.private),
        pending_registrations,
        derp_map,
        dns_cache,
        presence: PresenceTracker::new(),
        geoip,
        ephemeral_gc,
        map_cache,
        dns_provider: dns_provider_boxed,
        tka_public_key: Arc::new(RwLock::new(None)),
    };

    (state, handle)
}

/// build the protocol router (tailscale client endpoints).
fn build_protocol_router(state: &AppState) -> Router {
    // protocol routes with body size limits (64kb) to prevent memory exhaustion
    let protocol_routes = Router::new()
        .route(
            "/ts2021",
            get(handlers::ts2021).post(handlers::ts2021_http_upgrade),
        )
        .route("/machine/register", post(handlers::register))
        .route("/machine/map", post(handlers::map))
        // tka (tailnet lock) endpoints
        .route("/machine/tka/init/begin", post(handlers::tka_init_begin))
        .route("/machine/tka/init/finish", post(handlers::tka_init_finish))
        .route("/machine/tka/bootstrap", post(handlers::tka_bootstrap))
        .route("/machine/tka/sync/offer", post(handlers::tka_sync_offer))
        .route("/machine/tka/sync/send", post(handlers::tka_sync_send))
        .route("/machine/tka/disable", post(handlers::tka_disable))
        .route("/machine/tka/sign", post(handlers::tka_sign))
        // client audit log submission
        .route("/machine/audit-log", post(handlers::audit_log))
        // posture attribute updates from client
        .route(
            "/machine/set-device-attr",
            axum::routing::patch(handlers::set_device_attr),
        )
        // dns challenge for tailscale cert
        .route("/machine/set-dns", post(handlers::set_dns))
        .layer(DefaultBodyLimit::max(64 * 1024));

    // build verify router with rate limiting and IP allowlist
    let verify_router = build_verify_router(state);

    let mut router = Router::new()
        .route("/health", get(handlers::health))
        .route("/version", get(handlers::version))
        .route("/bootstrap-dns", get(handlers::bootstrap_dns))
        .route("/key", get(handlers::key))
        .merge(protocol_routes)
        .merge(verify_router);

    // add oidc routes (rate limited if configured)
    let oidc_router = Router::new()
        .route(
            "/register/{registration_id}",
            get(handlers::oidc::register_redirect),
        )
        .route("/oidc/callback", get(handlers::oidc::oidc_callback));

    // apply rate limiting to oidc routes if configured
    if let Some(oidc_config) = &state.config.oidc {
        if oidc_config.rate_limit_per_minute > 0 {
            let replenish_interval_ms = 60_000 / oidc_config.rate_limit_per_minute as u64;
            let burst_size = (oidc_config.rate_limit_per_minute / 6).clamp(3, 20);

            let governor_conf = GovernorConfigBuilder::default()
                .per_millisecond(replenish_interval_ms)
                .burst_size(burst_size)
                .use_headers()
                .finish()
                .expect("valid OIDC rate limit config");

            router = router.merge(oidc_router.layer(GovernorLayer::new(Arc::new(governor_conf))));
        } else {
            router = router.merge(oidc_router);
        }
    } else {
        router = router.merge(oidc_router);
    }

    router.with_state(state.clone())
}

/// build the verify router with rate limiting and IP allowlist.
fn build_verify_router(state: &AppState) -> Router<AppState> {
    let verify_config = &state.config.verify;

    // create the base verify router with body limit
    let verify_route = Router::new()
        .route("/verify", post(handlers::verify))
        .layer(DefaultBodyLimit::max(64 * 1024));

    // wrap with IP allowlist filter if configured
    let verify_route = if !verify_config.allowed_ips.is_empty() {
        let filter = rate_limit::IpAllowlistFilter::new(&verify_config.allowed_ips)
            .with_trusted_proxies(&verify_config.trusted_proxies);
        verify_route.layer(axum::middleware::from_fn_with_state(
            filter,
            rate_limit::ip_allowlist_middleware,
        ))
    } else {
        verify_route
    };

    // apply rate limiting if configured
    if verify_config.rate_limit_per_minute > 0 {
        let params = rate_limit::RateLimitParams::from_requests_per_minute(
            verify_config.rate_limit_per_minute,
        );

        let governor_conf = GovernorConfigBuilder::default()
            .per_millisecond(params.replenish_interval_ms)
            .burst_size(params.burst_size)
            .key_extractor(rate_limit::SimpleIpKeyExtractor)
            .use_headers()
            .finish()
            .expect("valid verify rate limit config");

        verify_route.layer(GovernorLayer::new(Arc::new(governor_conf)))
    } else {
        verify_route
    }
}

/// spawn a periodic cleanup task for a governor rate limiter.
macro_rules! spawn_limiter_cleanup {
    ($conf:expr) => {{
        let limiter = $conf.limiter().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                limiter.retain_recent();
            }
        });
    }};
}

/// build the api router (rest admin endpoints).
fn build_api_router(state: &AppState) -> Router {
    // apply body size limit (64kb) to prevent memory exhaustion
    let api_router = handlers::api_v1::router().layer(DefaultBodyLimit::max(64 * 1024));

    // apply rate limiting if enabled
    let nested = if state.config.api.rate_limit_enabled {
        let params = rate_limit::RateLimitParams::from_requests_per_minute(
            state.config.api.rate_limit_per_minute,
        );

        if state.config.api.behind_proxy {
            let key_extractor =
                rate_limit::TrustedProxyKeyExtractor::new(&state.config.api.trusted_proxies);

            let conf = GovernorConfigBuilder::default()
                .per_millisecond(params.replenish_interval_ms)
                .burst_size(params.burst_size)
                .key_extractor(key_extractor)
                .use_headers()
                .finish()
                .expect("valid governor config");

            spawn_limiter_cleanup!(conf);
            api_router.layer(GovernorLayer::new(Arc::new(conf)))
        } else {
            let conf = GovernorConfigBuilder::default()
                .per_millisecond(params.replenish_interval_ms)
                .burst_size(params.burst_size)
                .use_headers()
                .finish()
                .expect("valid governor config");

            spawn_limiter_cleanup!(conf);
            api_router.layer(GovernorLayer::new(Arc::new(conf)))
        }
    } else {
        api_router
    };

    Router::new()
        .nest("/api/v1", nested)
        .with_state(state.clone())
}
