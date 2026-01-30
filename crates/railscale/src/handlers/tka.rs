//! handlers for tailnet key authority (tka) endpoints.
//!
//! these endpoints implement the tka protocol for tailnet lock:
//! - /machine/tka/init/begin - start tka initialisation
//! - /machine/tka/init/finish - complete tka initialisation
//! - /machine/tka/bootstrap - get bootstrap info for enabling/disabling
//! - /machine/tka/sync/offer - offer sync state
//! - /machine/tka/sync/send - send missing aums
//! - /machine/tka/disable - disable tka with secret
//! - /machine/tka/sign - submit node-key signature

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use railscale_db::Database;
use railscale_proto::{
    TkaBootstrapRequest, TkaBootstrapResponse, TkaDisableRequest, TkaDisableResponse,
    TkaInitBeginRequest, TkaInitBeginResponse, TkaInitFinishRequest, TkaInitFinishResponse,
    TkaSubmitSignatureRequest, TkaSubmitSignatureResponse, TkaSyncOfferRequest,
    TkaSyncOfferResponse, TkaSyncSendRequest, TkaSyncSendResponse,
};
use tracing::{debug, info};

use crate::AppState;

/// POST /machine/tka/init/begin
///
/// start tka initialisation by submitting genesis aum.
/// returns list of nodes that need signatures.
pub async fn tka_init_begin(
    State(_state): State<AppState>,
    Json(req): Json<TkaInitBeginRequest>,
) -> impl IntoResponse {
    info!(
        node_key = ?req.node_key,
        "tka init begin request (not yet implemented)"
    );
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(TkaInitBeginResponse::default()),
    )
}

/// POST /machine/tka/init/finish
///
/// complete tka initialisation with node-key signatures.
pub async fn tka_init_finish(
    State(_state): State<AppState>,
    Json(req): Json<TkaInitFinishRequest>,
) -> impl IntoResponse {
    info!(
        node_key = ?req.node_key,
        signatures = req.signatures.len(),
        "tka init finish request (not yet implemented)"
    );
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(TkaInitFinishResponse::default()),
    )
}

/// POST /machine/tka/bootstrap
///
/// get bootstrap info for enabling or disabling tka.
///
/// returns genesis aum if tka is enabled and client needs to bootstrap,
/// or disablement secret if tka has been disabled.
pub async fn tka_bootstrap(
    State(state): State<AppState>,
    Json(req): Json<TkaBootstrapRequest>,
) -> impl IntoResponse {
    debug!(
        node_key = ?req.node_key,
        head = %req.head,
        "tka bootstrap request"
    );

    // fetch tka state from database
    let tka_state = match state.db.get_tka_state().await {
        Ok(Some(s)) => s,
        Ok(None) => {
            // no tka state, return empty response
            debug!("tka not initialised");
            return Json(TkaBootstrapResponse::default());
        }
        Err(e) => {
            info!(error = %e, "failed to get tka state");
            return Json(TkaBootstrapResponse::default());
        }
    };

    if !tka_state.enabled {
        // tka not enabled, return empty response
        debug!("tka not enabled");
        return Json(TkaBootstrapResponse::default());
    }

    // tka is enabled - return genesis_aum if available
    let genesis_aum = tka_state.genesis_aum.map(|bytes| bytes.into());

    debug!(head = ?tka_state.head, has_genesis = genesis_aum.is_some(), "tka bootstrap response");
    Json(TkaBootstrapResponse {
        genesis_aum,
        disablement_secret: vec![],
    })
}

/// POST /machine/tka/sync/offer
///
/// offer sync state to control plane.
pub async fn tka_sync_offer(
    State(_state): State<AppState>,
    Json(req): Json<TkaSyncOfferRequest>,
) -> impl IntoResponse {
    info!(
        node_key = ?req.node_key,
        head = %req.head,
        ancestors = req.ancestors.len(),
        "tka sync offer request (not yet implemented)"
    );
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(TkaSyncOfferResponse::default()),
    )
}

/// POST /machine/tka/sync/send
///
/// send missing aums to control plane.
pub async fn tka_sync_send(
    State(_state): State<AppState>,
    Json(req): Json<TkaSyncSendRequest>,
) -> impl IntoResponse {
    info!(
        node_key = ?req.node_key,
        head = %req.head,
        missing_aums = req.missing_aums.len(),
        "tka sync send request (not yet implemented)"
    );
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(TkaSyncSendResponse::default()),
    )
}

/// POST /machine/tka/disable
///
/// disable tka with disablement secret.
pub async fn tka_disable(
    State(_state): State<AppState>,
    Json(req): Json<TkaDisableRequest>,
) -> impl IntoResponse {
    info!(
        node_key = ?req.node_key,
        head = %req.head,
        "tka disable request (not yet implemented)"
    );
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(TkaDisableResponse::default()),
    )
}

/// POST /machine/tka/sign
///
/// submit a node-key signature.
pub async fn tka_sign(
    State(_state): State<AppState>,
    Json(req): Json<TkaSubmitSignatureRequest>,
) -> impl IntoResponse {
    info!(
        node_key = ?req.node_key,
        "tka sign request (not yet implemented)"
    );
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(TkaSubmitSignatureResponse::default()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use railscale_db::RailscaleDb;
    use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
    use railscale_proto::CapabilityVersion;
    use railscale_types::NodeKey;
    use tower::ServiceExt;

    fn default_grants() -> GrantsEngine {
        let mut policy = Policy::empty();
        policy.grants.push(Grant {
            src: vec![Selector::Wildcard],
            dst: vec![Selector::Wildcard],
            ip: vec![NetworkCapability::Wildcard],
            app: vec![],
            src_posture: vec![],
            via: vec![],
        });
        GrantsEngine::new(policy)
    }

    #[tokio::test]
    async fn tka_init_begin_returns_not_implemented() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let req = TkaInitBeginRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![0u8; 32]),
            genesis_aum: Default::default(),
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/init/begin")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn tka_bootstrap_returns_empty_when_tka_not_enabled() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let req = TkaBootstrapRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![0u8; 32]),
            head: String::new(),
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/bootstrap")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: TkaBootstrapResponse = serde_json::from_slice(&body).unwrap();

        // when tka not enabled, both fields should be empty/none
        assert!(resp.genesis_aum.is_none());
        assert!(resp.disablement_secret.is_empty());
    }

    #[tokio::test]
    async fn tka_bootstrap_returns_genesis_when_tka_enabled() {
        use railscale_db::{Database, TkaState};

        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        // enable tka with a genesis aum
        let genesis_bytes = vec![0xca, 0xfe, 0xba, 0xbe];
        let tka_state = TkaState {
            id: 0,
            enabled: true,
            head: Some("abc123".to_string()),
            state_checkpoint: None,
            disablement_secrets: None,
            genesis_aum: Some(genesis_bytes.clone()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        db.upsert_tka_state(&tka_state).await.unwrap();

        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let req = TkaBootstrapRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![0u8; 32]),
            head: String::new(), // client has no head, needs bootstrap
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/bootstrap")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: TkaBootstrapResponse = serde_json::from_slice(&body).unwrap();

        // when tka enabled with genesis, should return genesis_aum
        assert!(resp.genesis_aum.is_some());
        assert_eq!(resp.genesis_aum.unwrap().as_bytes(), genesis_bytes);
    }
}
