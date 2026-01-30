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
    TkaSignInfo, TkaSubmitSignatureRequest, TkaSubmitSignatureResponse, TkaSyncOfferRequest,
    TkaSyncOfferResponse, TkaSyncSendRequest, TkaSyncSendResponse,
};
use tracing::{debug, info};

use crate::AppState;

/// POST /machine/tka/init/begin
///
/// start tka initialisation by submitting genesis aum.
/// returns list of nodes that need signatures.
pub async fn tka_init_begin(
    State(state): State<AppState>,
    Json(req): Json<TkaInitBeginRequest>,
) -> impl IntoResponse {
    debug!(
        node_key = ?req.node_key,
        genesis_len = req.genesis_aum.as_bytes().len(),
        "tka init begin request"
    );

    // verify requesting node exists
    let _node = match state.db.get_node_by_node_key(&req.node_key).await {
        Ok(Some(n)) => n,
        Ok(None) => {
            info!(node_key = ?req.node_key, "tka init begin: node not found");
            return (
                StatusCode::UNAUTHORIZED,
                Json(TkaInitBeginResponse::default()),
            );
        }
        Err(e) => {
            info!(error = %e, "tka init begin: db error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaInitBeginResponse::default()),
            );
        }
    };

    // store genesis AUM in database (not enabled yet, just storing)
    let now = chrono::Utc::now();
    let tka_state = railscale_db::TkaState {
        id: 0,
        enabled: false, // not enabled until init_finish
        head: None,
        state_checkpoint: None,
        disablement_secrets: None,
        genesis_aum: Some(req.genesis_aum.as_bytes().to_vec()),
        created_at: now,
        updated_at: now,
    };

    if let Err(e) = state.db.upsert_tka_state(&tka_state).await {
        info!(error = %e, "tka init begin: failed to store genesis");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TkaInitBeginResponse::default()),
        );
    }

    // get all nodes that need signatures
    let nodes = match state.db.list_nodes().await {
        Ok(n) => n,
        Err(e) => {
            info!(error = %e, "tka init begin: failed to list nodes");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaInitBeginResponse::default()),
            );
        }
    };

    // convert to TkaSignInfo
    let need_signatures: Vec<TkaSignInfo> = nodes
        .into_iter()
        .map(|n| TkaSignInfo {
            node_id: n.id,
            node_public: n.node_key,
            rotation_pubkey: vec![], // TODO: rotation keys not implemented
        })
        .collect();

    debug!(
        nodes = need_signatures.len(),
        "tka init begin: returning nodes needing signatures"
    );
    (
        StatusCode::OK,
        Json(TkaInitBeginResponse { need_signatures }),
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
    async fn tka_init_begin_returns_nodes_needing_signatures() {
        use railscale_db::Database;
        use railscale_tka::{Aum, AumKind, AumSignature, Key, KeyKind, NlPrivateKey};
        use railscale_types::{DiscoKey, MachineKey, Node, NodeId, RegisterMethod, User, UserId};

        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        // create a user and node
        let user = User::new(UserId(1), "test-user".to_string());
        let user = db.create_user(&user).await.unwrap();

        let node_key = NodeKey::from_bytes(vec![1u8; 32]);
        let now = chrono::Utc::now();
        let node = Node {
            id: NodeId(0),
            machine_key: MachineKey::from_bytes(vec![2u8; 32]),
            node_key: node_key.clone(),
            disco_key: DiscoKey::from_bytes(vec![3u8; 32]),
            ipv4: Some("100.64.0.1".parse().unwrap()),
            ipv6: None,
            endpoints: vec![],
            hostinfo: None,
            hostname: "test-node".to_string(),
            given_name: "test-node".to_string(),
            user_id: Some(user.id),
            register_method: RegisterMethod::AuthKey,
            tags: vec![],
            auth_key_id: None,
            last_seen: Some(now),
            expiry: None,
            approved_routes: vec![],
            created_at: now,
            updated_at: now,
            is_online: None,
        };
        let node = db.create_node(&node).await.unwrap();

        // create a valid genesis AUM
        let nl_private = NlPrivateKey::generate();
        let nl_public = nl_private.public_key();
        let key = Key {
            kind: KeyKind::Ed25519,
            public: nl_public.as_bytes().to_vec(),
            votes: 1,
            meta: None,
        };
        let key_id = key.id().unwrap();

        let genesis = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let hash = genesis.hash().unwrap();
        let sig = nl_private.sign(hash.as_bytes());
        let signed_genesis = Aum {
            signatures: vec![AumSignature {
                key_id: key_id.as_bytes().to_vec(),
                signature: sig.to_vec(),
            }],
            ..genesis
        };
        let genesis_bytes = signed_genesis.to_cbor().unwrap();

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
            node_key: node_key.clone(),
            genesis_aum: genesis_bytes.into(),
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

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: TkaInitBeginResponse = serde_json::from_slice(&body).unwrap();

        // should return the node needing a signature
        assert_eq!(resp.need_signatures.len(), 1);
        assert_eq!(resp.need_signatures[0].node_id, node.id);
        assert_eq!(resp.need_signatures[0].node_public, node_key);
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
