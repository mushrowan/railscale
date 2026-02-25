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

use axum::{Json, extract::State};
use railscale_db::Database;
use railscale_proto::{
    TkaBootstrapRequest, TkaBootstrapResponse, TkaDisableRequest, TkaDisableResponse,
    TkaInitBeginRequest, TkaInitBeginResponse, TkaInitFinishRequest, TkaInitFinishResponse,
    TkaSignInfo, TkaSubmitSignatureRequest, TkaSubmitSignatureResponse, TkaSyncOfferRequest,
    TkaSyncOfferResponse, TkaSyncSendRequest, TkaSyncSendResponse,
};
use tracing::{debug, info};

use super::{ApiError, JsonBody, OptionExt, ResultExt};
use crate::AppState;

/// max size of a single AUM in bytes (32 KiB)
const MAX_AUM_SIZE: usize = 32 * 1024;

/// max number of AUMs in a single sync_send request
const MAX_AUMS_PER_REQUEST: usize = 100;

/// parsed genesis AUM with its public key and hash
struct ParsedGenesis {
    public_key: railscale_tka::NlPublicKey,
    hash: railscale_tka::AumHash,
}

/// parse a stored genesis AUM, extracting the TKA public key and hash
fn parse_genesis(genesis_bytes: &[u8], endpoint: &str) -> Result<ParsedGenesis, ApiError> {
    let genesis = railscale_tka::Aum::from_cbor(genesis_bytes).map_err(|e| {
        info!(error = %e, "{endpoint}: failed to parse genesis");
        ApiError::internal(format!("{endpoint}: failed to parse genesis"))
    })?;

    let tka_key = genesis.key.as_ref().ok_or_else(|| {
        info!("{endpoint}: genesis has no key");
        ApiError::bad_request(format!("{endpoint}: genesis has no key"))
    })?;

    let public_key =
        railscale_tka::NlPublicKey::try_from(tka_key.public.as_slice()).map_err(|e| {
            info!(error = %e, "{endpoint}: invalid tka public key");
            ApiError::bad_request(format!("{endpoint}: invalid tka public key"))
        })?;

    let hash = genesis.hash().map_err(|e| {
        info!(error = %e, "{endpoint}: failed to hash genesis");
        ApiError::internal(format!("{endpoint}: failed to hash genesis"))
    })?;

    Ok(ParsedGenesis { public_key, hash })
}

async fn verify_requesting_node(
    db: &impl Database,
    node_key: &railscale_types::NodeKey,
    machine_key_ctx: &Option<super::MachineKeyContext>,
    endpoint: &str,
) -> Result<(), ApiError> {
    match db.get_node_by_node_key(node_key).await {
        Ok(Some(node)) => {
            super::VerifiedNode::verify(node, machine_key_ctx)?;
            Ok(())
        }
        Ok(None) => {
            info!(node_key = ?node_key, "{endpoint}: node not found");
            Err(ApiError::unauthorized(format!(
                "{endpoint}: node not found"
            )))
        }
        Err(e) => {
            info!(error = %e, "{endpoint}: db error looking up node");
            Err(ApiError::internal(format!("{endpoint}: db error")))
        }
    }
}

/// verify the requesting node exists and tka is enabled, returning the state
async fn require_tka_enabled(
    db: &impl Database,
    node_key: &railscale_types::NodeKey,
    machine_key_ctx: &Option<super::MachineKeyContext>,
    endpoint: &str,
) -> Result<railscale_db::TkaState, ApiError> {
    verify_requesting_node(db, node_key, machine_key_ctx, endpoint).await?;
    db.get_tka_state()
        .await
        .map_internal()?
        .filter(|s| s.enabled)
        .ok_or_else(|| ApiError::bad_request("tka not enabled"))
}

/// POST /machine/tka/init/begin
///
/// start tka initialisation by submitting genesis aum.
/// returns list of nodes that need signatures.
pub async fn tka_init_begin(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    JsonBody(req): JsonBody<TkaInitBeginRequest>,
) -> Result<Json<TkaInitBeginResponse>, ApiError> {
    debug!(
        node_key = ?req.node_key,
        genesis_len = req.genesis_aum.as_bytes().len(),
        "tka init begin request"
    );

    verify_requesting_node(&state.db, &req.node_key, &machine_key_ctx, "tka init begin").await?;

    if req.genesis_aum.as_bytes().len() > MAX_AUM_SIZE {
        info!(
            size = req.genesis_aum.as_bytes().len(),
            max = MAX_AUM_SIZE,
            "tka init begin: genesis aum too large"
        );
        return Err(ApiError::bad_request("genesis aum too large"));
    }

    // reject if TKA is already enabled
    match state.db.get_tka_state().await {
        Ok(Some(s)) if s.enabled => {
            info!("tka init begin: tka already enabled, rejecting");
            return Err(ApiError::conflict("tka already enabled"));
        }
        Ok(_) => {}
        Err(e) => {
            return Err(ApiError::internal(format!("tka init begin: db error: {e}")));
        }
    }

    let now = chrono::Utc::now();
    let tka_state = railscale_db::TkaState {
        id: 0,
        enabled: false,
        head: None,
        state_checkpoint: None,
        disablement_secrets: None,
        genesis_aum: Some(req.genesis_aum.as_bytes().to_vec()),
        created_at: now,
        updated_at: now,
    };

    state.db.upsert_tka_state(&tka_state).await.map_internal()?;

    let nodes = state.db.list_nodes().await.map_internal()?;

    let need_signatures: Vec<TkaSignInfo> = nodes
        .into_iter()
        .map(|n| TkaSignInfo {
            node_id: n.id,
            node_public: n.node_key,
            rotation_pubkey: n.nl_public_key.unwrap_or_default(),
        })
        .collect();

    debug!(
        nodes = need_signatures.len(),
        "tka init begin: returning nodes needing signatures"
    );
    Ok(Json(TkaInitBeginResponse { need_signatures }))
}

/// POST /machine/tka/init/finish
///
/// complete tka initialisation with node-key signatures.
pub async fn tka_init_finish(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    JsonBody(req): JsonBody<TkaInitFinishRequest>,
) -> Result<Json<TkaInitFinishResponse>, ApiError> {
    debug!(
        node_key = ?req.node_key,
        signatures = req.signatures.len(),
        "tka init finish request"
    );

    verify_requesting_node(
        &state.db,
        &req.node_key,
        &machine_key_ctx,
        "tka init finish",
    )
    .await?;

    let tka_state = state
        .db
        .get_tka_state()
        .await
        .map_internal()?
        .ok_or_else(|| ApiError::bad_request("no tka state (init_begin not called?)"))?;

    let genesis_bytes = tka_state
        .genesis_aum
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("no genesis aum stored"))?;

    let parsed = parse_genesis(genesis_bytes, "tka init finish")?;

    for (node_id, sig_bytes) in &req.signatures {
        let node_id = railscale_types::NodeId(*node_id);

        let sig =
            railscale_tka::NodeKeySignature::from_cbor(sig_bytes.as_bytes()).map_err(|e| {
                info!(node_id = %node_id, error = %e, "tka init finish: invalid signature");
                ApiError::bad_request("invalid signature")
            })?;

        sig.verify(&parsed.public_key).map_err(|e| {
            info!(node_id = %node_id, error = %e, "tka init finish: signature verification failed");
            ApiError::bad_request("signature verification failed")
        })?;

        state
            .db
            .set_node_key_signature(node_id, sig_bytes.as_bytes())
            .await
            .map_internal()?;
    }

    state
        .db
        .store_aum(&parsed.hash.to_string(), None, genesis_bytes)
        .await
        .map_internal()?;

    let now = chrono::Utc::now();
    let updated_state = railscale_db::TkaState {
        enabled: true,
        head: Some(parsed.hash.to_string()),
        updated_at: now,
        ..tka_state
    };

    state
        .db
        .upsert_tka_state(&updated_state)
        .await
        .map_internal()?;

    // cache the parsed TKA public key for future sign requests
    *state.tka_public_key.write().await = Some(parsed.public_key);

    info!(head = %parsed.hash, "tka enabled");
    Ok(Json(TkaInitFinishResponse::default()))
}

/// POST /machine/tka/bootstrap
///
/// get bootstrap info for enabling or disabling tka.
///
/// returns genesis aum if tka is enabled and client needs to bootstrap,
/// or disablement secret if tka has been disabled.
pub async fn tka_bootstrap(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    JsonBody(req): JsonBody<TkaBootstrapRequest>,
) -> Result<Json<TkaBootstrapResponse>, ApiError> {
    debug!(
        node_key = ?req.node_key,
        head = %req.head,
        "tka bootstrap request"
    );

    verify_requesting_node(&state.db, &req.node_key, &machine_key_ctx, "tka bootstrap").await?;

    let tka_state = match state.db.get_tka_state().await {
        Ok(Some(s)) if s.enabled => s,
        _ => {
            debug!("tka not initialised or not enabled");
            return Ok(Json(TkaBootstrapResponse::default()));
        }
    };

    let genesis_aum = tka_state.genesis_aum.map(|bytes| bytes.into());

    debug!(head = ?tka_state.head, has_genesis = genesis_aum.is_some(), "tka bootstrap response");
    Ok(Json(TkaBootstrapResponse {
        genesis_aum,
        disablement_secret: vec![],
    }))
}

/// POST /machine/tka/sync/offer
///
/// offer sync state to control plane.
///
/// compares client's tka state with server's and returns any aums the client is missing.
pub async fn tka_sync_offer(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    JsonBody(req): JsonBody<TkaSyncOfferRequest>,
) -> Result<Json<TkaSyncOfferResponse>, ApiError> {
    debug!(
        node_key = ?req.node_key,
        head = %req.head,
        ancestors = req.ancestors.len(),
        "tka sync offer request"
    );

    verify_requesting_node(&state.db, &req.node_key, &machine_key_ctx, "tka sync offer").await?;

    let tka_state = match state.db.get_tka_state().await {
        Ok(Some(s)) if s.enabled => s,
        Ok(_) => {
            debug!("tka sync offer: tka not enabled or no state");
            return Ok(Json(TkaSyncOfferResponse::default()));
        }
        Err(e) => return Err(ApiError::internal(format!("tka sync offer: db error: {e}"))),
    };

    let server_head = tka_state.head.unwrap_or_default();

    if req.head == server_head {
        debug!("tka sync offer: heads match, no sync needed");
        return Ok(Json(TkaSyncOfferResponse {
            head: server_head,
            ancestors: vec![],
            missing_aums: vec![],
        }));
    }

    if req.head.is_empty() {
        debug!("tka sync offer: client has no head, sending full chain");
        let missing_aums = match state.db.get_aums_after("").await {
            Ok(aums) => aums.into_iter().map(|a| a.into()).collect(),
            Err(e) => {
                info!(error = %e, "tka sync offer: failed to get aum chain, using genesis");
                match &tka_state.genesis_aum {
                    Some(genesis) => vec![genesis.clone().into()],
                    None => vec![],
                }
            }
        };
        return Ok(Json(TkaSyncOfferResponse {
            head: server_head,
            ancestors: vec![],
            missing_aums,
        }));
    }

    debug!(
        client_head = %req.head,
        server_head = %server_head,
        "tka sync offer: heads differ, finding missing aums"
    );

    let missing_aums = match state.db.get_aums_after(&req.head).await {
        Ok(aums) => aums.into_iter().map(|a| a.into()).collect(),
        Err(e) => {
            info!(error = %e, "tka sync offer: failed to get missing aums");
            vec![]
        }
    };

    Ok(Json(TkaSyncOfferResponse {
        head: server_head,
        ancestors: vec![],
        missing_aums,
    }))
}

/// POST /machine/tka/sync/send
///
/// send missing aums to control plane.
///
/// receives aums from a client that the server is missing, validates and stores them.
pub async fn tka_sync_send(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    JsonBody(req): JsonBody<TkaSyncSendRequest>,
) -> Result<Json<TkaSyncSendResponse>, ApiError> {
    debug!(
        node_key = ?req.node_key,
        head = %req.head,
        missing_aums = req.missing_aums.len(),
        "tka sync send request"
    );

    let tka_state =
        require_tka_enabled(&state.db, &req.node_key, &machine_key_ctx, "tka sync send").await?;

    if req.missing_aums.len() > MAX_AUMS_PER_REQUEST {
        return Err(ApiError::bad_request("too many aums"));
    }

    for (i, aum) in req.missing_aums.iter().enumerate() {
        if aum.as_bytes().len() > MAX_AUM_SIZE {
            info!(index = i, size = aum.as_bytes().len(), "aum too large");
            return Err(ApiError::bad_request("aum too large"));
        }
    }

    let mut current_head = tka_state.head.unwrap_or_default();

    for aum_bytes in &req.missing_aums {
        let aum = railscale_tka::Aum::from_cbor(aum_bytes.as_bytes())
            .map_err(|e| ApiError::bad_request(format!("invalid aum: {e}")))?;

        let aum_hash = aum
            .hash()
            .map_err(|e| ApiError::bad_request(format!("failed to hash aum: {e}")))?
            .to_string();

        let prev_hash = aum.prev_aum_hash.as_ref().map(hex::encode);

        match &prev_hash {
            Some(ph) if *ph != current_head => {
                info!(prev_hash = %ph, current_head = %current_head, "broken chain");
                return Err(ApiError::bad_request(
                    "aum prev_hash doesn't chain to current head",
                ));
            }
            None => {
                return Err(ApiError::bad_request(
                    "aum has no prev_hash (unexpected in sync)",
                ));
            }
            _ => {}
        }

        state
            .db
            .store_aum(&aum_hash, prev_hash.as_deref(), aum_bytes.as_bytes())
            .await
            .map_internal()?;

        debug!(hash = %aum_hash, "tka sync send: stored aum");
        current_head = aum_hash;
    }

    if !req.missing_aums.is_empty() {
        let now = chrono::Utc::now();
        let updated_state = railscale_db::TkaState {
            head: Some(current_head.clone()),
            updated_at: now,
            ..tka_state
        };

        state
            .db
            .upsert_tka_state(&updated_state)
            .await
            .map_internal()?;
    }

    info!(head = %current_head, aums = req.missing_aums.len(), "tka sync send: processed");
    Ok(Json(TkaSyncSendResponse { head: current_head }))
}

/// POST /machine/tka/disable
///
/// disable tka with disablement secret.
pub async fn tka_disable(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    JsonBody(req): JsonBody<TkaDisableRequest>,
) -> Result<Json<TkaDisableResponse>, ApiError> {
    debug!(node_key = ?req.node_key, head = %req.head, "tka disable request");

    let tka_state =
        require_tka_enabled(&state.db, &req.node_key, &machine_key_ctx, "tka disable").await?;

    let stored_hashes = tka_state
        .disablement_secrets
        .as_ref()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| ApiError::bad_request("no disablement secrets configured"))?;

    let secret_bytes: [u8; 32] = req
        .disablement_secret
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::bad_request("invalid secret length"))?;

    let secret = railscale_tka::DisablementSecret::from(secret_bytes);

    let valid = stored_hashes.chunks(32).any(|chunk| {
        chunk.len() == 32 && {
            let hash: [u8; 32] = chunk.try_into().unwrap();
            secret.verify(&hash)
        }
    });

    if !valid {
        return Err(ApiError::forbidden("invalid disablement secret"));
    }

    let now = chrono::Utc::now();
    let updated_state = railscale_db::TkaState {
        enabled: false,
        updated_at: now,
        ..tka_state
    };

    state
        .db
        .upsert_tka_state(&updated_state)
        .await
        .map_internal()?;

    // clear cached TKA public key
    *state.tka_public_key.write().await = None;

    info!("tka disabled");
    Ok(Json(TkaDisableResponse::default()))
}

/// POST /machine/tka/sign
///
/// submit a node-key signature.
pub async fn tka_sign(
    State(state): State<AppState>,
    super::OptionalMachineKeyContext(machine_key_ctx): super::OptionalMachineKeyContext,
    JsonBody(req): JsonBody<TkaSubmitSignatureRequest>,
) -> Result<Json<TkaSubmitSignatureResponse>, ApiError> {
    debug!(node_key = ?req.node_key, "tka sign request");

    let tka_state =
        require_tka_enabled(&state.db, &req.node_key, &machine_key_ctx, "tka sign").await?;

    // use cached TKA public key, falling back to parsing genesis
    let cached = state.tka_public_key.read().await.clone();
    let tka_public_key = if let Some(key) = cached {
        key
    } else {
        let genesis_bytes = tka_state
            .genesis_aum
            .as_ref()
            .ok_or_else(|| ApiError::internal("no genesis aum stored"))?;
        let parsed = parse_genesis(genesis_bytes, "tka sign")?;
        *state.tka_public_key.write().await = Some(parsed.public_key.clone());
        parsed.public_key
    };

    let sig = railscale_tka::NodeKeySignature::from_cbor(req.signature.as_bytes())
        .map_err(|e| ApiError::bad_request(format!("invalid signature: {e}")))?;

    sig.verify(&tka_public_key).map_err(|e| {
        info!(error = %e, "tka sign: signature verification failed");
        ApiError::bad_request("signature verification failed")
    })?;

    let signed_pubkey = sig
        .pubkey
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("signature has no pubkey"))?;

    let signed_node_key = railscale_types::NodeKey::from_bytes(signed_pubkey.clone());
    let node = state
        .db
        .get_node_by_node_key(&signed_node_key)
        .await
        .map_internal()?
        .or_not_found("signed node not found")?;

    state
        .db
        .set_node_key_signature(node.id, req.signature.as_bytes())
        .await
        .map_internal()?;

    info!(node_id = %node.id, "tka sign: signature stored");
    Ok(Json(TkaSubmitSignatureResponse::default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::test_helpers::default_grants;
    use axum::{body::Body, http::Request, http::StatusCode};
    use railscale_db::{Database, RailscaleDb, TkaState};
    use railscale_proto::CapabilityVersion;
    use railscale_tka::{Aum, AumKind, AumSignature, Key, KeyKind, NlPrivateKey};
    use railscale_types::{NodeKey, User, UserId, test_utils::TestNodeBuilder};
    use tower::ServiceExt;

    /// create a test app with default grants from a database
    async fn test_app(db: &RailscaleDb) -> axum::Router {
        crate::create_app(
            db.clone(),
            default_grants(),
            railscale_types::Config::default(),
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await
    }

    /// create a migrated in-memory db with a user and node, returning (db, node_key, node)
    async fn setup_db_with_node(key_byte: u8) -> (RailscaleDb, NodeKey, railscale_types::Node) {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let user = User::new(UserId(1), "test-user".to_string());
        let user = db.create_user(&user).await.unwrap();
        let node_key = NodeKey::from_bytes(vec![key_byte; 32]);
        let node = TestNodeBuilder::new(0)
            .with_user_id(user.id)
            .with_node_key(node_key.clone())
            .with_ipv4("100.64.0.1".parse().unwrap())
            .build();
        let node = db.create_node(&node).await.unwrap();
        (db, node_key, node)
    }

    /// create a migrated in-memory db (no nodes)
    async fn setup_db() -> RailscaleDb {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();
        db
    }

    /// generated tka key material and signed genesis AUM
    struct TkaGenesis {
        nl_private: NlPrivateKey,
        key_id: railscale_tka::TkaKeyId,
        genesis_hash: railscale_tka::AumHash,
        genesis_bytes: Vec<u8>,
    }

    /// generate a signed genesis AUM with a fresh tka keypair
    fn make_genesis() -> TkaGenesis {
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
        let signed = Aum {
            signatures: vec![AumSignature {
                key_id: key_id.as_bytes().to_vec(),
                signature: sig.to_vec(),
            }],
            ..genesis
        };
        TkaGenesis {
            nl_private,
            key_id,
            genesis_hash: hash,
            genesis_bytes: signed.to_cbor().unwrap(),
        }
    }

    /// enable tka in the database with a genesis AUM
    async fn enable_tka(db: &RailscaleDb, g: &TkaGenesis) {
        enable_tka_with(db, g, None).await;
    }

    /// enable tka with optional disablement secrets
    async fn enable_tka_with(
        db: &RailscaleDb,
        g: &TkaGenesis,
        disablement_secrets: Option<Vec<u8>>,
    ) {
        let now = chrono::Utc::now();
        let state = TkaState {
            id: 0,
            enabled: true,
            head: Some(g.genesis_hash.to_string()),
            state_checkpoint: None,
            disablement_secrets,
            genesis_aum: Some(g.genesis_bytes.clone()),
            created_at: now,
            updated_at: now,
        };
        db.upsert_tka_state(&state).await.unwrap();
    }

    /// POST json to a uri and return (status, body bytes)
    async fn post_json(
        app: axum::Router,
        uri: &str,
        body: &impl serde::Serialize,
    ) -> (StatusCode, bytes::Bytes) {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, body)
    }

    #[tokio::test]
    async fn tka_init_begin_returns_nodes_needing_signatures() {
        let (db, node_key, node) = setup_db_with_node(1).await;
        let g = make_genesis();
        let app = test_app(&db).await;

        let req = TkaInitBeginRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            genesis_aum: g.genesis_bytes.into(),
        };
        let (status, body) = post_json(app, "/machine/tka/init/begin", &req).await;
        assert_eq!(status, StatusCode::OK);

        let resp: TkaInitBeginResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.need_signatures.len(), 1);
        assert_eq!(resp.need_signatures[0].node_id, node.id);
        assert_eq!(resp.need_signatures[0].node_public, node_key);
    }

    #[tokio::test]
    async fn tka_bootstrap_returns_empty_when_tka_not_enabled() {
        let (db, node_key, _) = setup_db_with_node(0).await;
        let app = test_app(&db).await;

        let req = TkaBootstrapRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: String::new(),
        };
        let (status, body) = post_json(app, "/machine/tka/bootstrap", &req).await;
        assert_eq!(status, StatusCode::OK);

        let resp: TkaBootstrapResponse = serde_json::from_slice(&body).unwrap();
        assert!(resp.genesis_aum.is_none());
        assert!(resp.disablement_secret.is_empty());
    }

    #[tokio::test]
    async fn tka_init_finish_enables_tka_with_valid_signatures() {
        use railscale_tka::NodeKeySignature;
        use std::collections::HashMap;

        let (db, node_key, node) = setup_db_with_node(1).await;
        let g = make_genesis();
        let app = test_app(&db).await;

        // step 1: init_begin
        let begin_req = TkaInitBeginRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            genesis_aum: g.genesis_bytes.clone().into(),
        };
        let (status, _) = post_json(app.clone(), "/machine/tka/init/begin", &begin_req).await;
        assert_eq!(status, StatusCode::OK);

        // step 2: create node-key signature
        let node_sig =
            NodeKeySignature::sign_direct(&node_key.as_bytes().to_vec(), &g.key_id, &g.nl_private)
                .unwrap();
        let node_sig_bytes = node_sig.to_cbor().unwrap();

        let mut signatures = HashMap::new();
        signatures.insert(node.id.0, node_sig_bytes.clone().into());

        // step 3: init_finish (recreate app to clear cached tka key)
        let app = test_app(&db).await;
        let finish_req = TkaInitFinishRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            signatures,
            support_disablement: vec![],
        };
        let (status, _) = post_json(app, "/machine/tka/init/finish", &finish_req).await;
        assert_eq!(status, StatusCode::OK);

        let tka_state = db.get_tka_state().await.unwrap().expect("tka state");
        assert!(tka_state.enabled);
        assert_eq!(tka_state.head.unwrap(), g.genesis_hash.to_string());

        let stored_sig = db
            .get_node_key_signature(node.id)
            .await
            .unwrap()
            .expect("signature stored");
        assert_eq!(stored_sig, node_sig_bytes);
    }

    #[tokio::test]
    async fn tka_bootstrap_returns_genesis_when_tka_enabled() {
        let (db, node_key, _) = setup_db_with_node(0).await;
        let genesis_bytes = vec![0xca, 0xfe, 0xba, 0xbe];
        let now = chrono::Utc::now();
        let tka_state = TkaState {
            id: 0,
            enabled: true,
            head: Some("abc123".to_string()),
            state_checkpoint: None,
            disablement_secrets: None,
            genesis_aum: Some(genesis_bytes.clone()),
            created_at: now,
            updated_at: now,
        };
        db.upsert_tka_state(&tka_state).await.unwrap();

        let app = test_app(&db).await;
        let req = TkaBootstrapRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: String::new(),
        };
        let (status, body) = post_json(app, "/machine/tka/bootstrap", &req).await;
        assert_eq!(status, StatusCode::OK);

        let resp: TkaBootstrapResponse = serde_json::from_slice(&body).unwrap();
        assert!(resp.genesis_aum.is_some());
        assert_eq!(resp.genesis_aum.unwrap().as_bytes(), genesis_bytes);
    }

    #[tokio::test]
    async fn tka_sign_stores_signature_for_node() {
        use railscale_tka::NodeKeySignature;

        let (db, node_key, node) = setup_db_with_node(1).await;
        let g = make_genesis();
        enable_tka(&db, &g).await;

        assert!(db.get_node_key_signature(node.id).await.unwrap().is_none());

        let node_sig =
            NodeKeySignature::sign_direct(&node_key.as_bytes().to_vec(), &g.key_id, &g.nl_private)
                .unwrap();
        let node_sig_bytes = node_sig.to_cbor().unwrap();

        let app = test_app(&db).await;
        let req = TkaSubmitSignatureRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            signature: node_sig_bytes.clone().into(),
        };
        let (status, _) = post_json(app, "/machine/tka/sign", &req).await;
        assert_eq!(status, StatusCode::OK);

        let stored_sig = db
            .get_node_key_signature(node.id)
            .await
            .unwrap()
            .expect("signature stored");
        assert_eq!(stored_sig, node_sig_bytes);
    }

    #[tokio::test]
    async fn tka_disable_with_valid_secret() {
        use railscale_tka::DisablementSecret;

        let (db, node_key, _) = setup_db_with_node(1).await;
        let g = make_genesis();

        let secret_bytes: [u8; 32] = [0xab; 32];
        let secret = DisablementSecret::from(secret_bytes);
        enable_tka_with(&db, &g, Some(secret.hash().to_vec())).await;

        let state = db.get_tka_state().await.unwrap().unwrap();
        assert!(state.enabled);

        let app = test_app(&db).await;
        let req = TkaDisableRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: g.genesis_hash.to_string(),
            disablement_secret: secret_bytes.to_vec(),
        };
        let (status, _) = post_json(app, "/machine/tka/disable", &req).await;
        assert_eq!(status, StatusCode::OK);

        let state = db.get_tka_state().await.unwrap().unwrap();
        assert!(!state.enabled);
    }

    #[tokio::test]
    async fn tka_sync_offer_returns_genesis_when_client_has_no_head() {
        let (db, node_key, _) = setup_db_with_node(1).await;
        let g = make_genesis();

        db.store_aum(&g.genesis_hash.to_string(), None, &g.genesis_bytes)
            .await
            .unwrap();
        enable_tka(&db, &g).await;

        let app = test_app(&db).await;
        let req = TkaSyncOfferRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: String::new(),
            ancestors: vec![],
        };
        let (status, body) = post_json(app, "/machine/tka/sync/offer", &req).await;
        assert_eq!(status, StatusCode::OK);

        let resp: TkaSyncOfferResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.head, g.genesis_hash.to_string());
        assert_eq!(resp.missing_aums.len(), 1);
        assert_eq!(resp.missing_aums[0].as_bytes(), g.genesis_bytes);
    }

    #[tokio::test]
    async fn tka_sync_offer_returns_empty_when_heads_match() {
        let (db, node_key, _) = setup_db_with_node(1).await;
        let g = make_genesis();
        enable_tka(&db, &g).await;

        let app = test_app(&db).await;
        let req = TkaSyncOfferRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: g.genesis_hash.to_string(),
            ancestors: vec![],
        };
        let (status, body) = post_json(app, "/machine/tka/sync/offer", &req).await;
        assert_eq!(status, StatusCode::OK);

        let resp: TkaSyncOfferResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.head, g.genesis_hash.to_string());
        assert!(resp.missing_aums.is_empty());
    }

    // --- unauthenticated endpoints must reject unknown node_key ---

    #[tokio::test]
    async fn tka_bootstrap_rejects_unknown_node_key() {
        let db = setup_db().await;
        let app = test_app(&db).await;

        let req = TkaBootstrapRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![0xdeu8; 32]),
            head: String::new(),
        };
        let (status, _) = post_json(app, "/machine/tka/bootstrap", &req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tka_sync_offer_rejects_unknown_node_key() {
        let db = setup_db().await;
        let app = test_app(&db).await;

        let req = TkaSyncOfferRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![0xdeu8; 32]),
            head: String::new(),
            ancestors: vec![],
        };
        let (status, _) = post_json(app, "/machine/tka/sync/offer", &req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tka_sync_send_rejects_unknown_node_key() {
        let db = setup_db().await;
        let app = test_app(&db).await;

        let req = TkaSyncSendRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![0xdeu8; 32]),
            head: "abc".to_string(),
            missing_aums: vec![],
            interactive: false,
        };
        let (status, _) = post_json(app, "/machine/tka/sync/send", &req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tka_disable_rejects_unknown_node_key() {
        let db = setup_db().await;
        let g = make_genesis();
        enable_tka_with(&db, &g, Some(vec![0xab; 32])).await;
        let app = test_app(&db).await;

        let req = TkaDisableRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![0xdeu8; 32]),
            head: "abc".to_string(),
            disablement_secret: vec![0xab; 32],
        };
        let (status, _) = post_json(app, "/machine/tka/disable", &req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tka_sign_rejects_unknown_requesting_node_key() {
        let db = setup_db().await;
        let g = make_genesis();
        enable_tka(&db, &g).await;
        let app = test_app(&db).await;

        let req = TkaSubmitSignatureRequest {
            version: CapabilityVersion(106),
            node_key: NodeKey::from_bytes(vec![0xdeu8; 32]),
            signature: vec![0u8; 10].into(),
        };
        let (status, _) = post_json(app, "/machine/tka/sign", &req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // --- init_begin must reject when TKA already enabled ---

    #[tokio::test]
    async fn tka_init_begin_rejects_when_tka_already_enabled() {
        let (db, node_key, _) = setup_db_with_node(1).await;
        let g = make_genesis();
        enable_tka(&db, &g).await;

        let new_genesis = make_genesis();
        let app = test_app(&db).await;
        let req = TkaInitBeginRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            genesis_aum: new_genesis.genesis_bytes.into(),
        };
        let (status, _) = post_json(app, "/machine/tka/init/begin", &req).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    // --- sync_send must reject AUM with broken prev_hash chain ---

    #[tokio::test]
    async fn tka_sync_send_rejects_aum_with_broken_chain() {
        let (db, node_key, _) = setup_db_with_node(1).await;
        let g = make_genesis();
        enable_tka(&db, &g).await;

        // create an AUM with a prev_hash that doesn't match current head
        let bad_key = Key {
            kind: KeyKind::Ed25519,
            public: g.nl_private.public_key().as_bytes().to_vec(),
            votes: 1,
            meta: None,
        };
        let bad_aum = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: Some(vec![0xffu8; 32]),
            key: Some(bad_key),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let bad_hash = bad_aum.hash().unwrap();
        let bad_sig = g.nl_private.sign(bad_hash.as_bytes());
        let signed_bad = Aum {
            signatures: vec![AumSignature {
                key_id: g.key_id.as_bytes().to_vec(),
                signature: bad_sig.to_vec(),
            }],
            ..bad_aum
        };
        let bad_bytes = signed_bad.to_cbor().unwrap();

        let app = test_app(&db).await;
        let req = TkaSyncSendRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: g.genesis_hash.to_string(),
            missing_aums: vec![bad_bytes.into()],
            interactive: false,
        };
        let (status, _) = post_json(app, "/machine/tka/sync/send", &req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn tka_sync_send_returns_current_head() {
        let (db, node_key, _) = setup_db_with_node(1).await;
        let g = make_genesis();
        enable_tka(&db, &g).await;

        let app = test_app(&db).await;
        let req = TkaSyncSendRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: g.genesis_hash.to_string(),
            missing_aums: vec![],
            interactive: false,
        };
        let (status, body) = post_json(app, "/machine/tka/sync/send", &req).await;
        assert_eq!(status, StatusCode::OK);

        let resp: TkaSyncSendResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.head, g.genesis_hash.to_string());
    }

    // --- aum size limits ---

    #[tokio::test]
    async fn tka_init_begin_rejects_oversized_genesis_aum() {
        let (db, node_key, _) = setup_db_with_node(1).await;
        let app = test_app(&db).await;

        let oversized = vec![0xffu8; super::MAX_AUM_SIZE + 1];
        let req = TkaInitBeginRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            genesis_aum: oversized.into(),
        };
        let (status, _) = post_json(app, "/machine/tka/init/begin", &req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn tka_sync_send_rejects_oversized_aum() {
        let (db, node_key, _) = setup_db_with_node(1).await;
        let g = make_genesis();
        enable_tka(&db, &g).await;

        let app = test_app(&db).await;
        let oversized_aum: Vec<u8> = vec![0xffu8; super::MAX_AUM_SIZE + 1];
        let req = TkaSyncSendRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: "abc".to_string(),
            missing_aums: vec![oversized_aum.into()],
            interactive: false,
        };
        let (status, _) = post_json(app, "/machine/tka/sync/send", &req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn tka_sync_send_rejects_too_many_aums() {
        let (db, node_key, _) = setup_db_with_node(1).await;
        let g = make_genesis();
        enable_tka(&db, &g).await;

        let app = test_app(&db).await;
        let too_many: Vec<_> = (0..super::MAX_AUMS_PER_REQUEST + 1)
            .map(|_| vec![0u8; 10].into())
            .collect();
        let req = TkaSyncSendRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            head: "abc".to_string(),
            missing_aums: too_many,
            interactive: false,
        };
        let (status, _) = post_json(app, "/machine/tka/sync/send", &req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn tka_init_begin_returns_rotation_pubkey_from_nl_key() {
        let db = setup_db().await;
        let user = User::new(UserId(1), "test-user".to_string());
        let user = db.create_user(&user).await.unwrap();

        let node_nl_private = NlPrivateKey::generate();
        let nl_public_bytes = node_nl_private.public_key().as_bytes().to_vec();

        let node_key = NodeKey::from_bytes(vec![1u8; 32]);
        let node = TestNodeBuilder::new(0)
            .with_user_id(user.id)
            .with_node_key(node_key.clone())
            .with_ipv4("100.64.0.1".parse().unwrap())
            .with_nl_public_key(nl_public_bytes.clone())
            .build();
        let node = db.create_node(&node).await.unwrap();

        let g = make_genesis();
        let app = test_app(&db).await;
        let req = TkaInitBeginRequest {
            version: CapabilityVersion(106),
            node_key: node_key.clone(),
            genesis_aum: g.genesis_bytes.into(),
        };
        let (status, body) = post_json(app, "/machine/tka/init/begin", &req).await;
        assert_eq!(status, StatusCode::OK);

        let resp: TkaInitBeginResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.need_signatures.len(), 1);
        assert_eq!(resp.need_signatures[0].node_id, node.id);
        assert_eq!(
            resp.need_signatures[0].rotation_pubkey, nl_public_bytes,
            "rotation_pubkey should be populated from node's nl_public_key"
        );
    }
}
