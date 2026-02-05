//! derp client verification endpoint handler.
//!
//! # security considerations
//!
//! **this endpoint is intentionally unauthenticated** for compatibility with
//! tailscale's `derper --verify-client-url` flag. the derp server calls this
//! endpoint to check if a client is registered with this control server before
//! allowing relay connections.
//!
//! ## deployment recommendations
//!
//! since this endpoint has no authentication, it should be protected at the
//! network layer:
//!
//! 1. **firewall rules**: restrict access to only your derp server IPs
//! 2. **reverse proxy ACLs**: if behind nginx/caddy, limit by source IP
//! 3. **internal network**: deploy on a private network segment
//!
//! ## example nginx configuration
//!
//! ```nginx
//! location /verify {
//!     # only allow from derp servers
//!     allow 10.0.0.0/8;      # internal network
//!     allow 192.168.0.0/16;  # local network
//!     deny all;
//!     proxy_pass http://localhost:8080;
//! }
//! ```
//!
//! ## rate limiting
//!
//! this endpoint is covered by the protocol route body limit (64kb).
//! for additional protection, consider adding rate limiting at your
//! reverse proxy layer.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::AppState;
use railscale_db::Database;
use railscale_types::NodeKey;

/// request body for derp client verification.
///
/// matches `tailcfg.derpadmitclientrequest`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VerifyRequest {
    /// the client's public node key.
    pub node_public: NodeKey,
    /// the client's ip address (informational).
    #[allow(dead_code)]
    pub source: String,
}

/// response for derp client verification.
///
/// matches `tailcfg.derpadmitclientresponse`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VerifyResponse {
    /// whether to allow this client to connect to the derp server.
    pub allow: bool,
}

/// post /verify - verify a derp client is registered.
///
/// # security
///
/// this endpoint is **intentionally unauthenticated** for derp server
/// compatibility. protect it via network-layer controls (firewalls,
/// reverse proxy ACLs) rather than application-level authentication.
/// see module documentation for deployment recommendations.
pub async fn verify(
    State(state): State<AppState>,
    Json(request): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
    use tracing::{debug, warn};

    // check if the node key exists in the database
    let node = match state.db.get_node_by_node_key(&request.node_public).await {
        Ok(Some(n)) => Some(n),
        Ok(None) => {
            debug!(node_key = ?request.node_public, "verify: node not found");
            None
        }
        Err(e) => {
            warn!(error = %e, node_key = ?request.node_public, "verify: db error");
            None
        }
    };

    // check node exists and is not expired
    let allow = match node {
        Some(n) => {
            if let Some(expiry) = n.expiry {
                if chrono::Utc::now() > expiry {
                    debug!(node_key = ?request.node_public, expiry = %expiry, "verify: node expired");
                    false
                } else {
                    true
                }
            } else {
                true // no expiry set, allow
            }
        }
        None => false,
    };

    Json(VerifyResponse { allow })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use railscale_db::RailscaleDb;
    use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};
    use railscale_types::{DiscoKey, MachineKey, Node, NodeId, RegisterMethod, User, UserId};
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

    async fn setup_db_with_node(
        expiry: Option<chrono::DateTime<chrono::Utc>>,
    ) -> (RailscaleDb, NodeKey) {
        use railscale_db::Database;

        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let user = User::new(UserId(1), "test".to_string());
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
            expiry,
            approved_routes: vec![],
            created_at: now,
            updated_at: now,
            is_online: None,
            posture_attributes: std::collections::HashMap::new(),
            nl_public_key: None,
            last_seen_country: None,
            ephemeral: false,
        };
        db.create_node(&node).await.unwrap();

        (db, node_key)
    }

    #[tokio::test]
    async fn verify_rejects_expired_node() {
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let (db, node_key) = setup_db_with_node(Some(past)).await;

        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db,
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let req_body = serde_json::json!({
            "NodePublic": node_key,
            "Source": "1.2.3.4:1234"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(!resp.allow, "expired node should be denied");
    }

    #[tokio::test]
    async fn verify_allows_valid_node() {
        let future = chrono::Utc::now() + chrono::Duration::hours(24);
        let (db, node_key) = setup_db_with_node(Some(future)).await;

        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db,
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let req_body = serde_json::json!({
            "NodePublic": node_key,
            "Source": "1.2.3.4:1234"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(resp.allow, "valid node should be allowed");
    }

    #[tokio::test]
    async fn verify_rejects_unknown_node() {
        let db = RailscaleDb::new_in_memory().await.unwrap();
        db.migrate().await.unwrap();

        let config = railscale_types::Config::default();
        let app = crate::create_app(
            db,
            default_grants(),
            config,
            None,
            crate::StateNotifier::default(),
            None,
        )
        .await;

        let req_body = serde_json::json!({
            "NodePublic": NodeKey::from_bytes(vec![0xdeu8; 32]),
            "Source": "1.2.3.4:1234"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(!resp.allow, "unknown node should be denied");
    }
}
