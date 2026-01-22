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
/// http request handlers for tailscale protocol endpoints.
pub mod handlers;
mod noise_stream;
mod notifier;
/// openid connect authentication provider.
pub mod oidc;
/// grants-based access control resolver.
pub mod resolver;
/// minimal stun server for nat traversal.
pub mod stun;

pub use derp::{
    DerpError, fetch_derp_map_from_url, generate_derp_map, load_derp_map_from_path, merge_derp_maps,
};
pub use noise_stream::NoiseStream;
pub use notifier::StateNotifier;
pub use railscale_proto::Keypair;

use std::path::Path;
use std::sync::Arc;

use axum::{
    Router,
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
    pub noise_private_key: Vec<u8>,
    /// cache of pending registrations waiting for oidc completion.
    /// maps registrationid -> arc<pendingregistration>.
    pub pending_registrations: Cache<RegistrationId, Arc<PendingRegistration>>,
    /// derp map for relay coordination (shared for dynamic updates).
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
    let (app, _handle) = create_app_with_policy_handle(
        db,
        grants.policy().clone(),
        config,
        oidc,
        notifier,
        keypair,
        None,
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
pub async fn create_app_with_policy_handle(
    db: RailscaleDb,
    policy: Policy,
    config: Config,
    oidc: Option<oidc::AuthProviderOidc>,
    notifier: StateNotifier,
    keypair: Option<Keypair>,
    derp_map: Option<DerpMap>,
) -> (Router, PolicyHandle) {
    // generate keypair if not provided
    let keypair = keypair.unwrap_or_else(|| {
        railscale_proto::generate_keypair().expect("failed to generate noise keypair")
    });

    // initialize ip allocator with configured prefixes
    let mut ip_allocator = IpAllocator::new(config.prefix_v4, config.prefix_v6);

    // load already-allocated ips from the database
    if let Ok(nodes) = db.list_nodes().await {
        let allocated_ips: Vec<std::net::IpAddr> = nodes
            .iter()
            .flat_map(|n| [n.ipv4, n.ipv6])
            .flatten()
            .collect();
        ip_allocator.load_allocated(allocated_ips);
    }

    // create shared grants engine
    let grants = Arc::new(RwLock::new(GrantsEngine::new(policy)));
    let handle = PolicyHandle {
        engine: Arc::clone(&grants),
    };

    // create pending registrations cache with 15 minute ttl
    let pending_registrations = Cache::builder()
        .time_to_live(Duration::from_secs(900))
        .build();

    // initialize derp map (default to empty if not provided)
    let derp_map = Arc::new(RwLock::new(derp_map.unwrap_or_default()));

    let state = AppState {
        db,
        grants,
        config,
        oidc,
        notifier,
        ip_allocator: Arc::new(Mutex::new(ip_allocator)),
        noise_public_key: keypair.public,
        noise_private_key: keypair.private,
        pending_registrations,
        derp_map,
    };

    let mut router = Router::new()
        .route("/health", get(handlers::health))
        .route("/version", get(handlers::version))
        .route("/verify", post(handlers::verify))
        .route("/bootstrap-dns", get(handlers::bootstrap_dns))
        .route("/key", get(handlers::key))
        .route(
            "/ts2021",
            get(handlers::ts2021).post(handlers::ts2021_http_upgrade),
        )
        .route("/machine/register", post(handlers::register))
        .route("/machine/map", post(handlers::map))
        .route(
            "/register/{registration_id}",
            get(handlers::oidc::register_redirect),
        )
        .route("/oidc/callback", get(handlers::oidc::oidc_callback));

    // add rest api v1 routes if enabled
    if state.config.api.enabled {
        let api_router = handlers::api_v1::router();

        // apply rate limiting if enabled
        if state.config.api.rate_limit_enabled {
            // convert per-minute rate to per-second (gcra algorithm works in seconds)
            let requests_per_minute = state.config.api.rate_limit_per_minute;
            let replenish_interval_ms = if requests_per_minute > 0 {
                60_000 / requests_per_minute as u64
            } else {
                1000 // Default to 1 request/second if somehow 0
            };

            let governor_conf = GovernorConfigBuilder::default()
                .per_millisecond(replenish_interval_ms)
                .burst_size(requests_per_minute.min(10)) // Allow small burst, max 10
                .use_headers() // Add x-ratelimit-* headers
                .finish()
                .expect("valid governor config");

            // start background task to clean up rate limiter storage
            let governor_limiter = governor_conf.limiter().clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    governor_limiter.retain_recent();
                }
            });

            router = router.nest(
                "/api/v1",
                api_router.layer(GovernorLayer::new(Arc::new(governor_conf))),
            );
        } else {
            router = router.nest("/api/v1", api_router);
        }
    }

    let router = router.with_state(state);

    (router, handle)
}
