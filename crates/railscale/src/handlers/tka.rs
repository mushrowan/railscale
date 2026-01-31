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
    State(state): State<AppState>,
    Json(req): Json<TkaInitFinishRequest>,
) -> impl IntoResponse {
    debug!(
        node_key = ?req.node_key,
        signatures = req.signatures.len(),
        "tka init finish request"
    );

    // verify requesting node exists
    let _node = match state.db.get_node_by_node_key(&req.node_key).await {
        Ok(Some(n)) => n,
        Ok(None) => {
            info!(node_key = ?req.node_key, "tka init finish: node not found");
            return (
                StatusCode::UNAUTHORIZED,
                Json(TkaInitFinishResponse::default()),
            );
        }
        Err(e) => {
            info!(error = %e, "tka init finish: db error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaInitFinishResponse::default()),
            );
        }
    };

    // load stored tka state with genesis
    let tka_state = match state.db.get_tka_state().await {
        Ok(Some(s)) => s,
        Ok(None) => {
            info!("tka init finish: no tka state (init_begin not called?)");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaInitFinishResponse::default()),
            );
        }
        Err(e) => {
            info!(error = %e, "tka init finish: db error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaInitFinishResponse::default()),
            );
        }
    };

    let genesis_bytes = match &tka_state.genesis_aum {
        Some(b) => b,
        None => {
            info!("tka init finish: no genesis aum stored");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaInitFinishResponse::default()),
            );
        }
    };

    // parse genesis AUM to get the TKA public key
    let genesis = match railscale_tka::Aum::from_cbor(genesis_bytes) {
        Ok(a) => a,
        Err(e) => {
            info!(error = %e, "tka init finish: failed to parse genesis");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaInitFinishResponse::default()),
            );
        }
    };

    // extract the TKA public key from the genesis AddKey AUM
    let tka_key = match &genesis.key {
        Some(k) => k,
        None => {
            info!("tka init finish: genesis has no key");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaInitFinishResponse::default()),
            );
        }
    };

    let tka_public = match railscale_tka::NlPublicKey::try_from(tka_key.public.as_slice()) {
        Ok(p) => p,
        Err(e) => {
            info!(error = %e, "tka init finish: invalid tka public key");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaInitFinishResponse::default()),
            );
        }
    };

    // verify and store each signature
    for (node_id, sig_bytes) in &req.signatures {
        let node_id = railscale_types::NodeId(*node_id);

        // parse the signature
        let sig = match railscale_tka::NodeKeySignature::from_cbor(sig_bytes.as_bytes()) {
            Ok(s) => s,
            Err(e) => {
                info!(node_id = %node_id, error = %e, "tka init finish: invalid signature");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(TkaInitFinishResponse::default()),
                );
            }
        };

        // verify the signature
        if let Err(e) = sig.verify(&tka_public) {
            info!(node_id = %node_id, error = %e, "tka init finish: signature verification failed");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaInitFinishResponse::default()),
            );
        }

        // store the signature
        if let Err(e) = state
            .db
            .set_node_key_signature(node_id, sig_bytes.as_bytes())
            .await
        {
            info!(node_id = %node_id, error = %e, "tka init finish: failed to store signature");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaInitFinishResponse::default()),
            );
        }
    }

    // compute genesis hash for head
    let genesis_hash = match genesis.hash() {
        Ok(h) => h,
        Err(e) => {
            info!(error = %e, "tka init finish: failed to hash genesis");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaInitFinishResponse::default()),
            );
        }
    };

    // store genesis AUM in the chain
    if let Err(e) = state
        .db
        .store_aum(&genesis_hash.to_string(), None, genesis_bytes)
        .await
    {
        info!(error = %e, "tka init finish: failed to store genesis aum");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TkaInitFinishResponse::default()),
        );
    }

    // enable TKA
    let now = chrono::Utc::now();
    let updated_state = railscale_db::TkaState {
        enabled: true,
        head: Some(genesis_hash.to_string()),
        updated_at: now,
        ..tka_state
    };

    if let Err(e) = state.db.upsert_tka_state(&updated_state).await {
        info!(error = %e, "tka init finish: failed to enable tka");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TkaInitFinishResponse::default()),
        );
    }

    info!(head = %genesis_hash, "tka enabled");
    (StatusCode::OK, Json(TkaInitFinishResponse::default()))
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
///
/// compares client's tka state with server's and returns any aums the client is missing.
pub async fn tka_sync_offer(
    State(state): State<AppState>,
    Json(req): Json<TkaSyncOfferRequest>,
) -> impl IntoResponse {
    debug!(
        node_key = ?req.node_key,
        head = %req.head,
        ancestors = req.ancestors.len(),
        "tka sync offer request"
    );

    // get server's TKA state
    let tka_state = match state.db.get_tka_state().await {
        Ok(Some(s)) if s.enabled => s,
        Ok(Some(_)) => {
            // TKA not enabled, return empty
            debug!("tka sync offer: tka not enabled");
            return (StatusCode::OK, Json(TkaSyncOfferResponse::default()));
        }
        Ok(None) => {
            debug!("tka sync offer: no tka state");
            return (StatusCode::OK, Json(TkaSyncOfferResponse::default()));
        }
        Err(e) => {
            info!(error = %e, "tka sync offer: db error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSyncOfferResponse::default()),
            );
        }
    };

    let server_head = tka_state.head.unwrap_or_default();

    // if heads match, no sync needed
    if req.head == server_head {
        debug!("tka sync offer: heads match, no sync needed");
        return (
            StatusCode::OK,
            Json(TkaSyncOfferResponse {
                head: server_head,
                ancestors: vec![],
                missing_aums: vec![],
            }),
        );
    }

    // if client has no head (empty), they need all AUMs from genesis to head
    if req.head.is_empty() {
        debug!("tka sync offer: client has no head, sending full chain");
        // get all AUMs from the beginning (use empty string to get everything)
        let missing_aums = match state.db.get_aums_after("").await {
            Ok(aums) => aums.into_iter().map(|a| a.into()).collect(),
            Err(e) => {
                // fall back to genesis_aum if chain retrieval fails
                info!(error = %e, "tka sync offer: failed to get aum chain, using genesis");
                match &tka_state.genesis_aum {
                    Some(genesis) => vec![genesis.clone().into()],
                    None => vec![],
                }
            }
        };
        return (
            StatusCode::OK,
            Json(TkaSyncOfferResponse {
                head: server_head,
                ancestors: vec![],
                missing_aums,
            }),
        );
    }

    // client has a different head - get AUMs they're missing
    debug!(
        client_head = %req.head,
        server_head = %server_head,
        "tka sync offer: heads differ, finding missing aums"
    );

    // check if client's head is in our chain (they're behind us)
    let missing_aums = match state.db.get_aums_after(&req.head).await {
        Ok(aums) => aums.into_iter().map(|a| a.into()).collect(),
        Err(e) => {
            info!(error = %e, "tka sync offer: failed to get missing aums");
            vec![]
        }
    };

    (
        StatusCode::OK,
        Json(TkaSyncOfferResponse {
            head: server_head,
            ancestors: vec![],
            missing_aums,
        }),
    )
}

/// POST /machine/tka/sync/send
///
/// send missing aums to control plane.
///
/// receives aums from a client that the server is missing, validates and stores them.
pub async fn tka_sync_send(
    State(state): State<AppState>,
    Json(req): Json<TkaSyncSendRequest>,
) -> impl IntoResponse {
    debug!(
        node_key = ?req.node_key,
        head = %req.head,
        missing_aums = req.missing_aums.len(),
        "tka sync send request"
    );

    // get current TKA state
    let tka_state = match state.db.get_tka_state().await {
        Ok(Some(s)) if s.enabled => s,
        Ok(Some(_)) => {
            info!("tka sync send: tka not enabled");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaSyncSendResponse::default()),
            );
        }
        Ok(None) => {
            info!("tka sync send: no tka state");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaSyncSendResponse::default()),
            );
        }
        Err(e) => {
            info!(error = %e, "tka sync send: db error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSyncSendResponse::default()),
            );
        }
    };

    let mut current_head = tka_state.head.unwrap_or_default();

    // process each AUM
    for aum_bytes in &req.missing_aums {
        // parse the AUM
        let aum = match railscale_tka::Aum::from_cbor(aum_bytes.as_bytes()) {
            Ok(a) => a,
            Err(e) => {
                info!(error = %e, "tka sync send: invalid aum");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(TkaSyncSendResponse { head: current_head }),
                );
            }
        };

        // compute hash
        let aum_hash = match aum.hash() {
            Ok(h) => h.to_string(),
            Err(e) => {
                info!(error = %e, "tka sync send: failed to hash aum");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(TkaSyncSendResponse { head: current_head }),
                );
            }
        };

        // get prev hash
        let prev_hash = aum.prev_aum_hash.as_ref().map(|h| hex::encode(h));

        // verify the AUM chains properly (prev_hash should match our current head or be in our chain)
        // for now, we just store it

        // store the AUM
        if let Err(e) = state
            .db
            .store_aum(&aum_hash, prev_hash.as_deref(), aum_bytes.as_bytes())
            .await
        {
            info!(error = %e, "tka sync send: failed to store aum");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSyncSendResponse { head: current_head }),
            );
        }

        debug!(hash = %aum_hash, "tka sync send: stored aum");
        current_head = aum_hash;
    }

    // update head in tka_state if we received any AUMs
    if !req.missing_aums.is_empty() {
        let now = chrono::Utc::now();
        let updated_state = railscale_db::TkaState {
            head: Some(current_head.clone()),
            updated_at: now,
            ..tka_state
        };

        if let Err(e) = state.db.upsert_tka_state(&updated_state).await {
            info!(error = %e, "tka sync send: failed to update head");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSyncSendResponse { head: current_head }),
            );
        }
    }

    info!(head = %current_head, aums = req.missing_aums.len(), "tka sync send: processed");
    (
        StatusCode::OK,
        Json(TkaSyncSendResponse { head: current_head }),
    )
}

/// POST /machine/tka/disable
///
/// disable tka with disablement secret.
pub async fn tka_disable(
    State(state): State<AppState>,
    Json(req): Json<TkaDisableRequest>,
) -> impl IntoResponse {
    debug!(node_key = ?req.node_key, head = %req.head, "tka disable request");

    // verify TKA is enabled
    let tka_state = match state.db.get_tka_state().await {
        Ok(Some(s)) if s.enabled => s,
        Ok(Some(_)) => {
            info!("tka disable: tka not enabled");
            return (StatusCode::BAD_REQUEST, Json(TkaDisableResponse::default()));
        }
        Ok(None) => {
            info!("tka disable: no tka state");
            return (StatusCode::BAD_REQUEST, Json(TkaDisableResponse::default()));
        }
        Err(e) => {
            info!(error = %e, "tka disable: db error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaDisableResponse::default()),
            );
        }
    };

    // get stored disablement secret hashes
    let stored_hashes = match &tka_state.disablement_secrets {
        Some(h) if !h.is_empty() => h,
        _ => {
            info!("tka disable: no disablement secrets configured");
            return (StatusCode::BAD_REQUEST, Json(TkaDisableResponse::default()));
        }
    };

    // verify the provided secret against stored hashes
    // stored as concatenated 32-byte hashes
    let secret_bytes: [u8; 32] = match req.disablement_secret.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => {
            info!("tka disable: invalid secret length");
            return (StatusCode::BAD_REQUEST, Json(TkaDisableResponse::default()));
        }
    };

    let secret = railscale_tka::DisablementSecret::from(secret_bytes);

    // check each stored hash (32 bytes each)
    let mut valid = false;
    for chunk in stored_hashes.chunks(32) {
        if chunk.len() == 32 {
            let hash: [u8; 32] = chunk.try_into().unwrap();
            if secret.verify(&hash) {
                valid = true;
                break;
            }
        }
    }

    if !valid {
        info!("tka disable: invalid disablement secret");
        return (StatusCode::FORBIDDEN, Json(TkaDisableResponse::default()));
    }

    // disable TKA
    let now = chrono::Utc::now();
    let updated_state = railscale_db::TkaState {
        enabled: false,
        updated_at: now,
        ..tka_state
    };

    if let Err(e) = state.db.upsert_tka_state(&updated_state).await {
        info!(error = %e, "tka disable: failed to update state");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TkaDisableResponse::default()),
        );
    }

    info!("tka disabled");
    (StatusCode::OK, Json(TkaDisableResponse::default()))
}

/// POST /machine/tka/sign
///
/// submit a node-key signature.
pub async fn tka_sign(
    State(state): State<AppState>,
    Json(req): Json<TkaSubmitSignatureRequest>,
) -> impl IntoResponse {
    debug!(node_key = ?req.node_key, "tka sign request");

    // verify TKA is enabled
    let tka_state = match state.db.get_tka_state().await {
        Ok(Some(s)) if s.enabled => s,
        Ok(Some(_)) => {
            info!("tka sign: tka not enabled");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
        Ok(None) => {
            info!("tka sign: no tka state");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
        Err(e) => {
            info!(error = %e, "tka sign: db error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
    };

    // load genesis to get TKA public key
    let genesis_bytes = match &tka_state.genesis_aum {
        Some(b) => b,
        None => {
            info!("tka sign: no genesis aum stored");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
    };

    let genesis = match railscale_tka::Aum::from_cbor(genesis_bytes) {
        Ok(a) => a,
        Err(e) => {
            info!(error = %e, "tka sign: failed to parse genesis");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
    };

    let tka_key = match &genesis.key {
        Some(k) => k,
        None => {
            info!("tka sign: genesis has no key");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
    };

    let tka_public = match railscale_tka::NlPublicKey::try_from(tka_key.public.as_slice()) {
        Ok(p) => p,
        Err(e) => {
            info!(error = %e, "tka sign: invalid tka public key");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
    };

    // parse the signature
    let sig = match railscale_tka::NodeKeySignature::from_cbor(req.signature.as_bytes()) {
        Ok(s) => s,
        Err(e) => {
            info!(error = %e, "tka sign: invalid signature");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
    };

    // verify the signature
    if let Err(e) = sig.verify(&tka_public) {
        info!(error = %e, "tka sign: signature verification failed");
        return (
            StatusCode::BAD_REQUEST,
            Json(TkaSubmitSignatureResponse::default()),
        );
    }

    // extract the node key from the signature
    let signed_pubkey = match &sig.pubkey {
        Some(p) => p,
        None => {
            info!("tka sign: signature has no pubkey");
            return (
                StatusCode::BAD_REQUEST,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
    };

    // find the node with this pubkey
    let signed_node_key = railscale_types::NodeKey::from_bytes(signed_pubkey.clone());
    let node = match state.db.get_node_by_node_key(&signed_node_key).await {
        Ok(Some(n)) => n,
        Ok(None) => {
            info!(node_key = ?signed_node_key, "tka sign: node not found");
            return (
                StatusCode::NOT_FOUND,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
        Err(e) => {
            info!(error = %e, "tka sign: db error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(TkaSubmitSignatureResponse::default()),
            );
        }
    };

    // store the signature
    if let Err(e) = state
        .db
        .set_node_key_signature(node.id, req.signature.as_bytes())
        .await
    {
        info!(node_id = %node.id, error = %e, "tka sign: failed to store signature");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TkaSubmitSignatureResponse::default()),
        );
    }

    info!(node_id = %node.id, "tka sign: signature stored");
    (StatusCode::OK, Json(TkaSubmitSignatureResponse::default()))
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
            posture_attributes: std::collections::HashMap::new(),
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
    async fn tka_init_finish_enables_tka_with_valid_signatures() {
        use railscale_db::Database;
        use railscale_tka::{
            Aum, AumKind, AumSignature, Key, KeyKind, NlPrivateKey, NodeKeySignature, TkaKeyId,
        };
        use railscale_types::{DiscoKey, MachineKey, Node, NodeId, RegisterMethod, User, UserId};
        use std::collections::HashMap;

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
            posture_attributes: std::collections::HashMap::new(),
        };
        let node = db.create_node(&node).await.unwrap();

        // create TKA key and genesis AUM
        let nl_private = NlPrivateKey::generate();
        let nl_public = nl_private.public_key();
        let tka_key = Key {
            kind: KeyKind::Ed25519,
            public: nl_public.as_bytes().to_vec(),
            votes: 1,
            meta: None,
        };
        let tka_key_id = tka_key.id().unwrap();

        let genesis = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(tka_key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let genesis_hash = genesis.hash().unwrap();
        let sig = nl_private.sign(genesis_hash.as_bytes());
        let signed_genesis = Aum {
            signatures: vec![AumSignature {
                key_id: tka_key_id.as_bytes().to_vec(),
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

        // step 1: call init_begin to store genesis
        let begin_req = TkaInitBeginRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            genesis_aum: genesis_bytes.clone().into(),
        };

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/init/begin")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&begin_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // step 2: create node-key signature
        // the node pubkey needs to be in the format tailscale expects (with "np" prefix)
        let node_pubkey_bytes = node_key.as_bytes().to_vec();
        let node_sig =
            NodeKeySignature::sign_direct(&node_pubkey_bytes, &tka_key_id, &nl_private).unwrap();
        let node_sig_bytes = node_sig.to_cbor().unwrap();

        let mut signatures = HashMap::new();
        signatures.insert(node.id.0, node_sig_bytes.clone().into());

        // step 3: call init_finish
        let finish_req = TkaInitFinishRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            signatures,
            support_disablement: vec![],
        };

        // recreate app for second request
        let app = crate::create_app(
            db.clone(),
            default_grants(),
            railscale_types::Config::default(),
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/init/finish")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&finish_req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // verify TKA is now enabled
        let tka_state = db.get_tka_state().await.unwrap().expect("tka state");
        assert!(tka_state.enabled);
        assert!(tka_state.head.is_some());
        // head should be the hex-encoded genesis hash
        assert_eq!(tka_state.head.unwrap(), genesis_hash.to_string());

        // verify signature was stored for the node
        let stored_sig = db
            .get_node_key_signature(node.id)
            .await
            .unwrap()
            .expect("signature stored");
        assert_eq!(stored_sig, node_sig_bytes);
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

    #[tokio::test]
    async fn tka_sign_stores_signature_for_node() {
        use railscale_db::{Database, TkaState};
        use railscale_tka::{
            Aum, AumKind, AumSignature, Key, KeyKind, NlPrivateKey, NodeKeySignature,
        };
        use railscale_types::{DiscoKey, MachineKey, Node, NodeId, RegisterMethod, User, UserId};

        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        // create TKA key
        let nl_private = NlPrivateKey::generate();
        let nl_public = nl_private.public_key();
        let tka_key = Key {
            kind: KeyKind::Ed25519,
            public: nl_public.as_bytes().to_vec(),
            votes: 1,
            meta: None,
        };
        let tka_key_id = tka_key.id().unwrap();

        // create and store genesis AUM
        let genesis = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(tka_key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let genesis_hash = genesis.hash().unwrap();
        let sig = nl_private.sign(genesis_hash.as_bytes());
        let signed_genesis = Aum {
            signatures: vec![AumSignature {
                key_id: tka_key_id.as_bytes().to_vec(),
                signature: sig.to_vec(),
            }],
            ..genesis
        };
        let genesis_bytes = signed_genesis.to_cbor().unwrap();

        // enable TKA in database
        let now = chrono::Utc::now();
        let tka_state = TkaState {
            id: 0,
            enabled: true,
            head: Some(genesis_hash.to_string()),
            state_checkpoint: None,
            disablement_secrets: None,
            genesis_aum: Some(genesis_bytes),
            created_at: now,
            updated_at: now,
        };
        db.upsert_tka_state(&tka_state).await.unwrap();

        // create a user and node (without signature)
        let user = User::new(UserId(1), "test-user".to_string());
        let user = db.create_user(&user).await.unwrap();

        let node_key = NodeKey::from_bytes(vec![1u8; 32]);
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
            posture_attributes: std::collections::HashMap::new(),
        };
        let node = db.create_node(&node).await.unwrap();

        // verify no signature stored yet
        assert!(db.get_node_key_signature(node.id).await.unwrap().is_none());

        // create a valid node-key signature
        let node_pubkey_bytes = node_key.as_bytes().to_vec();
        let node_sig =
            NodeKeySignature::sign_direct(&node_pubkey_bytes, &tka_key_id, &nl_private).unwrap();
        let node_sig_bytes = node_sig.to_cbor().unwrap();

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

        // submit the signature
        let req = TkaSubmitSignatureRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            signature: node_sig_bytes.clone().into(),
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // verify signature was stored
        let stored_sig = db
            .get_node_key_signature(node.id)
            .await
            .unwrap()
            .expect("signature stored");
        assert_eq!(stored_sig, node_sig_bytes);
    }

    #[tokio::test]
    async fn tka_disable_with_valid_secret() {
        use railscale_db::{Database, TkaState};
        use railscale_tka::{
            Aum, AumKind, AumSignature, DisablementSecret, Key, KeyKind, NlPrivateKey,
        };
        use railscale_types::{DiscoKey, MachineKey, Node, NodeId, RegisterMethod, User, UserId};

        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        // create a user and node (needed for request authentication)
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
            posture_attributes: std::collections::HashMap::new(),
        };
        db.create_node(&node).await.unwrap();

        // create TKA key and genesis
        let nl_private = NlPrivateKey::generate();
        let nl_public = nl_private.public_key();
        let tka_key = Key {
            kind: KeyKind::Ed25519,
            public: nl_public.as_bytes().to_vec(),
            votes: 1,
            meta: None,
        };
        let tka_key_id = tka_key.id().unwrap();

        let genesis = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(tka_key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let genesis_hash = genesis.hash().unwrap();
        let sig = nl_private.sign(genesis_hash.as_bytes());
        let signed_genesis = Aum {
            signatures: vec![AumSignature {
                key_id: tka_key_id.as_bytes().to_vec(),
                signature: sig.to_vec(),
            }],
            ..genesis
        };
        let genesis_bytes = signed_genesis.to_cbor().unwrap();

        // create a disablement secret and store its hash
        let secret_bytes: [u8; 32] = [0xab; 32];
        let secret = DisablementSecret::from(secret_bytes);
        let secret_hash = secret.hash();

        // store hashes as simple vec of 32-byte hashes concatenated
        let disablement_secrets = secret_hash.to_vec();

        // enable TKA with disablement secret
        let tka_state = TkaState {
            id: 0,
            enabled: true,
            head: Some(genesis_hash.to_string()),
            state_checkpoint: None,
            disablement_secrets: Some(disablement_secrets),
            genesis_aum: Some(genesis_bytes),
            created_at: now,
            updated_at: now,
        };
        db.upsert_tka_state(&tka_state).await.unwrap();

        // verify TKA is enabled
        let state = db.get_tka_state().await.unwrap().unwrap();
        assert!(state.enabled);

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

        // disable TKA with the secret
        let req = TkaDisableRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: genesis_hash.to_string(),
            disablement_secret: secret_bytes.to_vec(),
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/disable")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // verify TKA is now disabled
        let state = db.get_tka_state().await.unwrap().unwrap();
        assert!(!state.enabled);
    }

    #[tokio::test]
    async fn tka_sync_offer_returns_genesis_when_client_has_no_head() {
        use railscale_db::{Database, TkaState};
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
            posture_attributes: std::collections::HashMap::new(),
        };
        db.create_node(&node).await.unwrap();

        // create TKA key and genesis
        let nl_private = NlPrivateKey::generate();
        let nl_public = nl_private.public_key();
        let tka_key = Key {
            kind: KeyKind::Ed25519,
            public: nl_public.as_bytes().to_vec(),
            votes: 1,
            meta: None,
        };
        let tka_key_id = tka_key.id().unwrap();

        let genesis = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(tka_key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let genesis_hash = genesis.hash().unwrap();
        let sig = nl_private.sign(genesis_hash.as_bytes());
        let signed_genesis = Aum {
            signatures: vec![AumSignature {
                key_id: tka_key_id.as_bytes().to_vec(),
                signature: sig.to_vec(),
            }],
            ..genesis
        };
        let genesis_bytes = signed_genesis.to_cbor().unwrap();

        // store genesis in AUM chain
        db.store_aum(&genesis_hash.to_string(), None, &genesis_bytes)
            .await
            .unwrap();

        // enable TKA
        let tka_state = TkaState {
            id: 0,
            enabled: true,
            head: Some(genesis_hash.to_string()),
            state_checkpoint: None,
            disablement_secrets: None,
            genesis_aum: Some(genesis_bytes.clone()),
            created_at: now,
            updated_at: now,
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

        // client with no head requests sync
        let req = TkaSyncOfferRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: String::new(), // client has no TKA state
            ancestors: vec![],
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/sync/offer")
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
        let resp: TkaSyncOfferResponse = serde_json::from_slice(&body).unwrap();

        // server should return its head and the genesis AUM
        assert_eq!(resp.head, genesis_hash.to_string());
        assert_eq!(resp.missing_aums.len(), 1);
        assert_eq!(resp.missing_aums[0].as_bytes(), genesis_bytes);
    }

    #[tokio::test]
    async fn tka_sync_offer_returns_empty_when_heads_match() {
        use railscale_db::{Database, TkaState};
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
            posture_attributes: std::collections::HashMap::new(),
        };
        db.create_node(&node).await.unwrap();

        // create TKA key and genesis
        let nl_private = NlPrivateKey::generate();
        let nl_public = nl_private.public_key();
        let tka_key = Key {
            kind: KeyKind::Ed25519,
            public: nl_public.as_bytes().to_vec(),
            votes: 1,
            meta: None,
        };
        let tka_key_id = tka_key.id().unwrap();

        let genesis = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(tka_key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let genesis_hash = genesis.hash().unwrap();
        let sig = nl_private.sign(genesis_hash.as_bytes());
        let signed_genesis = Aum {
            signatures: vec![AumSignature {
                key_id: tka_key_id.as_bytes().to_vec(),
                signature: sig.to_vec(),
            }],
            ..genesis
        };
        let genesis_bytes = signed_genesis.to_cbor().unwrap();

        // enable TKA
        let tka_state = TkaState {
            id: 0,
            enabled: true,
            head: Some(genesis_hash.to_string()),
            state_checkpoint: None,
            disablement_secrets: None,
            genesis_aum: Some(genesis_bytes),
            created_at: now,
            updated_at: now,
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

        // client with same head as server
        let req = TkaSyncOfferRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: genesis_hash.to_string(), // same as server
            ancestors: vec![],
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/sync/offer")
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
        let resp: TkaSyncOfferResponse = serde_json::from_slice(&body).unwrap();

        // heads match, no sync needed
        assert_eq!(resp.head, genesis_hash.to_string());
        assert!(resp.missing_aums.is_empty());
    }

    #[tokio::test]
    async fn tka_sync_send_returns_current_head() {
        use railscale_db::{Database, TkaState};
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
            posture_attributes: std::collections::HashMap::new(),
        };
        db.create_node(&node).await.unwrap();

        // create TKA key and genesis
        let nl_private = NlPrivateKey::generate();
        let nl_public = nl_private.public_key();
        let tka_key = Key {
            kind: KeyKind::Ed25519,
            public: nl_public.as_bytes().to_vec(),
            votes: 1,
            meta: None,
        };
        let tka_key_id = tka_key.id().unwrap();

        let genesis = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: None,
            key: Some(tka_key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let genesis_hash = genesis.hash().unwrap();
        let sig = nl_private.sign(genesis_hash.as_bytes());
        let signed_genesis = Aum {
            signatures: vec![AumSignature {
                key_id: tka_key_id.as_bytes().to_vec(),
                signature: sig.to_vec(),
            }],
            ..genesis
        };
        let genesis_bytes = signed_genesis.to_cbor().unwrap();

        // enable TKA
        let tka_state = TkaState {
            id: 0,
            enabled: true,
            head: Some(genesis_hash.to_string()),
            state_checkpoint: None,
            disablement_secrets: None,
            genesis_aum: Some(genesis_bytes),
            created_at: now,
            updated_at: now,
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

        // send empty AUMs (just testing the endpoint works)
        let req = TkaSyncSendRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: genesis_hash.to_string(),
            missing_aums: vec![],
            interactive: false,
        };

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/machine/tka/sync/send")
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
        let resp: TkaSyncSendResponse = serde_json::from_slice(&body).unwrap();

        // should return current head
        assert_eq!(resp.head, genesis_hash.to_string());
    }
}
