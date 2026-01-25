//! admin service implementation.

use std::path::PathBuf;
use std::sync::Arc;

use railscale_db::{Database, RailscaleDb};
use railscale_grants::Policy;
use railscale_types::{MAX_POLICY_SIZE, MAX_TAGS, NodeName, Username};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::pb::{self, admin_service_server::AdminService};

/// policy handle for hot-reload (mirrors railscale::policyhandle).
#[derive(Clone)]
pub struct PolicyHandle {
    engine: Arc<RwLock<railscale_grants::GrantsEngine>>,
}

impl PolicyHandle {
    /// create a new policy handle from a shared grants engine.
    pub fn new(engine: Arc<RwLock<railscale_grants::GrantsEngine>>) -> Self {
        Self { engine }
    }

    /// reload the policy.
    pub async fn reload(&self, policy: Policy) {
        let mut engine = self.engine.write().await;
        engine.update_policy(policy);
    }

    /// get the current policy.
    pub async fn get_policy(&self) -> Policy {
        let engine = self.engine.read().await;
        engine.policy().clone()
    }
}

/// admin service implementation.
pub struct AdminServiceImpl {
    db: RailscaleDb,
    policy_handle: PolicyHandle,
    policy_file_path: Option<PathBuf>,
}

impl AdminServiceImpl {
    /// create a new admin service.
    pub fn new(
        db: RailscaleDb,
        policy_handle: PolicyHandle,
        policy_file_path: Option<PathBuf>,
    ) -> Self {
        Self {
            db,
            policy_handle,
            policy_file_path,
        }
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    // ============ policy ============

    async fn reload_policy(
        &self,
        _request: Request<pb::ReloadPolicyRequest>,
    ) -> Result<Response<pb::ReloadPolicyResponse>, Status> {
        let Some(ref path) = self.policy_file_path else {
            return Err(Status::failed_precondition(
                "No policy file configured for reload",
            ));
        };

        let content = std::fs::read_to_string(path)
            .map_err(|e| Status::internal(format!("Failed to read policy file: {}", e)))?;

        let policy: Policy = serde_json::from_str(&content)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse policy: {}", e)))?;

        let grants_loaded = policy.grants.len() as u32;
        self.policy_handle.reload(policy).await;

        info!("Policy reloaded via admin API ({} grants)", grants_loaded);

        Ok(Response::new(pb::ReloadPolicyResponse {
            success: true,
            message: format!("Policy reloaded from {:?}", path),
            grants_loaded,
        }))
    }

    async fn get_policy(
        &self,
        _request: Request<pb::GetPolicyRequest>,
    ) -> Result<Response<pb::GetPolicyResponse>, Status> {
        let policy = self.policy_handle.get_policy().await;
        let policy_json = serde_json::to_string_pretty(&policy)
            .map_err(|e| Status::internal(format!("Failed to serialize policy: {}", e)))?;

        Ok(Response::new(pb::GetPolicyResponse { policy_json }))
    }

    async fn set_policy(
        &self,
        request: Request<pb::SetPolicyRequest>,
    ) -> Result<Response<pb::SetPolicyResponse>, Status> {
        let policy_json = request.into_inner().policy_json;

        // check size limit
        if policy_json.len() > MAX_POLICY_SIZE {
            return Err(Status::invalid_argument("policy exceeds maximum size"));
        }

        let policy: Policy = serde_json::from_str(&policy_json).map_err(|e| {
            info!("Invalid policy submitted via gRPC: {}", e);
            Status::invalid_argument("invalid policy format")
        })?;

        let grants_loaded = policy.grants.len() as u32;
        self.policy_handle.reload(policy).await;

        info!("Policy set via admin API ({} grants)", grants_loaded);

        Ok(Response::new(pb::SetPolicyResponse {
            success: true,
            message: "Policy updated".to_string(),
            grants_loaded,
        }))
    }

    // ============ Users ============

    async fn create_user(
        &self,
        request: Request<pb::CreateUserRequest>,
    ) -> Result<Response<pb::User>, Status> {
        let req = request.into_inner();

        // validate and sanitise user name, but preserve original email
        let name = Username::sanitise(&req.email)
            .map(|u| u.into_inner())
            .ok_or_else(|| Status::invalid_argument("invalid email/username format"))?;

        let mut user = railscale_types::User::new(railscale_types::UserId(0), name);
        user.email = Some(req.email.clone());

        let created = self
            .db
            .create_user(&user)
            .await
            .map_err(|e| Status::internal(format!("Failed to create user: {}", e)))?;

        Ok(Response::new(user_to_pb(&created)))
    }

    async fn get_user(
        &self,
        request: Request<pb::GetUserRequest>,
    ) -> Result<Response<pb::User>, Status> {
        let id = railscale_types::UserId(request.into_inner().id);

        let user = self
            .db
            .get_user(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        Ok(Response::new(user_to_pb(&user)))
    }

    async fn list_users(
        &self,
        _request: Request<pb::ListUsersRequest>,
    ) -> Result<Response<pb::ListUsersResponse>, Status> {
        let users = self
            .db
            .list_users()
            .await
            .map_err(|e| Status::internal(format!("Failed to list users: {}", e)))?;

        Ok(Response::new(pb::ListUsersResponse {
            users: users.iter().map(user_to_pb).collect(),
        }))
    }

    async fn delete_user(
        &self,
        request: Request<pb::DeleteUserRequest>,
    ) -> Result<Response<pb::DeleteUserResponse>, Status> {
        let id = railscale_types::UserId(request.into_inner().id);

        // check if user exists
        let _user = self
            .db
            .get_user(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        // check if user has nodes (headscale behavior: refuse to delete if nodes exist)
        let nodes = self
            .db
            .list_nodes_for_user(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list nodes: {}", e)))?;

        if !nodes.is_empty() {
            return Err(Status::failed_precondition(format!(
                "user not empty: {} node(s) found. Delete the nodes first.",
                nodes.len()
            )));
        }

        // delete preauth keys for this user (Headscale behavior)
        let preauth_keys = self
            .db
            .list_preauth_keys(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list preauth keys: {}", e)))?;

        for key in preauth_keys {
            self.db
                .delete_preauth_key(key.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to delete preauth key: {}", e)))?;
        }

        // delete API keys for this user
        let api_keys = self
            .db
            .list_api_keys(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to list API keys: {}", e)))?;

        for key in api_keys {
            self.db
                .delete_api_key(key.id)
                .await
                .map_err(|e| Status::internal(format!("Failed to delete API key: {}", e)))?;
        }

        // now delete the user
        self.db
            .delete_user(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete user: {}", e)))?;

        Ok(Response::new(pb::DeleteUserResponse {}))
    }

    async fn rename_user(
        &self,
        request: Request<pb::RenameUserRequest>,
    ) -> Result<Response<pb::User>, Status> {
        let req = request.into_inner();
        let id = railscale_types::UserId(req.id);

        // sanitise new username, preserving original as email
        let sanitised_name = Username::sanitise(&req.new_name)
            .map(|u| u.into_inner())
            .ok_or_else(|| Status::invalid_argument("invalid username format"))?;

        let mut user = self
            .db
            .get_user(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get user: {}", e)))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        user.name = sanitised_name;
        user.email = Some(req.new_name);

        let updated = self
            .db
            .update_user(&user)
            .await
            .map_err(|e| Status::internal(format!("Failed to update user: {}", e)))?;

        Ok(Response::new(user_to_pb(&updated)))
    }

    // ============ Nodes ============

    async fn get_node(
        &self,
        request: Request<pb::GetNodeRequest>,
    ) -> Result<Response<pb::Node>, Status> {
        let id = railscale_types::NodeId(request.into_inner().id);

        let node = self
            .db
            .get_node(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get node: {}", e)))?
            .ok_or_else(|| Status::not_found("Node not found"))?;

        Ok(Response::new(node_to_pb(&node)))
    }

    async fn list_nodes(
        &self,
        request: Request<pb::ListNodesRequest>,
    ) -> Result<Response<pb::ListNodesResponse>, Status> {
        let req = request.into_inner();

        let nodes = if let Some(user_id) = req.user_id {
            self.db
                .list_nodes_for_user(railscale_types::UserId(user_id))
                .await
                .map_err(|e| Status::internal(format!("Failed to list nodes: {}", e)))?
        } else {
            self.db
                .list_nodes()
                .await
                .map_err(|e| Status::internal(format!("Failed to list nodes: {}", e)))?
        };

        // filter by tag if specified
        let nodes: Vec<_> = if let Some(ref tag) = req.tag {
            nodes
                .into_iter()
                .filter(|n| n.tags.iter().any(|t| t == tag.as_str()))
                .collect()
        } else {
            nodes
        };

        Ok(Response::new(pb::ListNodesResponse {
            nodes: nodes.iter().map(node_to_pb).collect(),
        }))
    }

    async fn delete_node(
        &self,
        request: Request<pb::DeleteNodeRequest>,
    ) -> Result<Response<pb::DeleteNodeResponse>, Status> {
        let id = railscale_types::NodeId(request.into_inner().id);

        self.db
            .delete_node(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete node: {}", e)))?;

        Ok(Response::new(pb::DeleteNodeResponse {}))
    }

    async fn expire_node(
        &self,
        request: Request<pb::ExpireNodeRequest>,
    ) -> Result<Response<pb::Node>, Status> {
        let id = railscale_types::NodeId(request.into_inner().id);

        let mut node = self
            .db
            .get_node(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get node: {}", e)))?
            .ok_or_else(|| Status::not_found("Node not found"))?;

        node.expiry = Some(chrono::Utc::now());

        let updated = self
            .db
            .update_node(&node)
            .await
            .map_err(|e| Status::internal(format!("Failed to update node: {}", e)))?;

        Ok(Response::new(node_to_pb(&updated)))
    }

    async fn rename_node(
        &self,
        request: Request<pb::RenameNodeRequest>,
    ) -> Result<Response<pb::Node>, Status> {
        let req = request.into_inner();
        let id = railscale_types::NodeId(req.id);

        // validate new node name
        let validated_name = NodeName::new(&req.new_name)
            .map_err(|e| Status::invalid_argument(format!("invalid node name: {}", e)))?;

        let mut node = self
            .db
            .get_node(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get node: {}", e)))?
            .ok_or_else(|| Status::not_found("Node not found"))?;

        node.given_name = validated_name.into_inner();

        let updated = self
            .db
            .update_node(&node)
            .await
            .map_err(|e| Status::internal(format!("Failed to update node: {}", e)))?;

        Ok(Response::new(node_to_pb(&updated)))
    }

    async fn set_tags(
        &self,
        request: Request<pb::SetTagsRequest>,
    ) -> Result<Response<pb::Node>, Status> {
        let req = request.into_inner();
        let id = railscale_types::NodeId(req.id);

        // check tag count limit
        if req.tags.len() > MAX_TAGS {
            return Err(Status::invalid_argument(format!(
                "too many tags ({}, max {})",
                req.tags.len(),
                MAX_TAGS
            )));
        }

        // parse tags from request
        let tags: Vec<railscale_types::Tag> = req
            .tags
            .into_iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| Status::invalid_argument(format!("Invalid tag: {}", e)))?;

        let mut node = self
            .db
            .get_node(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get node: {}", e)))?
            .ok_or_else(|| Status::not_found("Node not found"))?;

        node.tags = tags;

        let updated = self
            .db
            .update_node(&node)
            .await
            .map_err(|e| Status::internal(format!("Failed to update node: {}", e)))?;

        Ok(Response::new(node_to_pb(&updated)))
    }

    async fn set_approved_routes(
        &self,
        request: Request<pb::SetApprovedRoutesRequest>,
    ) -> Result<Response<pb::Node>, Status> {
        let req = request.into_inner();
        let id = railscale_types::NodeId(req.id);

        let mut node = self
            .db
            .get_node(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to get node: {}", e)))?
            .ok_or_else(|| Status::not_found("Node not found"))?;

        // parse and validate cidr routes
        let routes: Vec<ipnet::IpNet> = req
            .routes
            .iter()
            .map(|r| {
                r.parse().map_err(|e| {
                    info!("Invalid route submitted via gRPC: '{}': {}", r, e);
                    Status::invalid_argument("invalid CIDR route format")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        node.approved_routes = routes;

        let updated = self
            .db
            .update_node(&node)
            .await
            .map_err(|e| Status::internal(format!("Failed to update node: {}", e)))?;

        Ok(Response::new(node_to_pb(&updated)))
    }

    // ============ PreAuth Keys ============

    async fn create_preauth_key(
        &self,
        request: Request<pb::CreatePreauthKeyRequest>,
    ) -> Result<Response<pb::PreauthKey>, Status> {
        let req = request.into_inner();

        // check tag count limit
        if req.tags.len() > MAX_TAGS {
            return Err(Status::invalid_argument(format!(
                "too many tags ({}, max {})",
                req.tags.len(),
                MAX_TAGS
            )));
        }

        // parse tags from request
        let tags: Vec<railscale_types::Tag> = req
            .tags
            .into_iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| Status::invalid_argument(format!("Invalid tag: {}", e)))?;

        let expiration = req
            .expiration_days
            .map(|days| chrono::Utc::now() + chrono::Duration::days(days));

        // generate a random token
        let token = railscale_types::PreAuthKeyToken::generate();

        let mut key = railscale_types::PreAuthKey::from_token(
            0, // Will be assigned by DB
            &token,
            railscale_types::UserId(req.user_id),
        );
        key.reusable = req.reusable;
        key.ephemeral = req.ephemeral;
        key.tags = tags;
        key.expiration = expiration;

        let created = self
            .db
            .create_preauth_key(&key)
            .await
            .map_err(|e| Status::internal(format!("Failed to create preauth key: {}", e)))?;

        // at creation, return the full token (this is the only time it's available)
        Ok(Response::new(preauth_key_to_pb_with_full_key(
            &created,
            token.as_str(),
        )))
    }

    async fn list_preauth_keys(
        &self,
        request: Request<pb::ListPreauthKeysRequest>,
    ) -> Result<Response<pb::ListPreauthKeysResponse>, Status> {
        let req = request.into_inner();

        let keys = if let Some(user_id) = req.user_id {
            self.db
                .list_preauth_keys(railscale_types::UserId(user_id))
                .await
                .map_err(|e| Status::internal(format!("Failed to list preauth keys: {}", e)))?
        } else {
            self.db
                .get_all_preauth_keys()
                .await
                .map_err(|e| Status::internal(format!("Failed to list preauth keys: {}", e)))?
        };

        // filter expired if needed
        let keys: Vec<_> = if req.show_expired {
            keys
        } else {
            keys.into_iter().filter(|k| k.is_valid()).collect()
        };

        Ok(Response::new(pb::ListPreauthKeysResponse {
            keys: keys.iter().map(preauth_key_to_pb).collect(),
        }))
    }

    async fn expire_preauth_key(
        &self,
        request: Request<pb::ExpirePreauthKeyRequest>,
    ) -> Result<Response<pb::ExpirePreauthKeyResponse>, Status> {
        let id = request.into_inner().id;

        self.db
            .expire_preauth_key(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to expire preauth key: {}", e)))?;

        Ok(Response::new(pb::ExpirePreauthKeyResponse {}))
    }

    async fn delete_preauth_key(
        &self,
        request: Request<pb::DeletePreauthKeyRequest>,
    ) -> Result<Response<pb::DeletePreauthKeyResponse>, Status> {
        let id = request.into_inner().id;

        self.db
            .delete_preauth_key(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete preauth key: {}", e)))?;

        Ok(Response::new(pb::DeletePreauthKeyResponse {}))
    }

    // ============ api keys ============

    async fn create_api_key(
        &self,
        request: Request<pb::CreateApiKeyRequest>,
    ) -> Result<Response<pb::ApiKeyWithSecret>, Status> {
        let req = request.into_inner();

        let expiration = req
            .expiration_days
            .map(|days| chrono::Utc::now() + chrono::Duration::days(days));

        // generate a new api key secret (split-token pattern)
        let secret = railscale_types::ApiKeySecret::generate();

        let mut key = railscale_types::ApiKey::new(
            0, // Will be assigned by DB
            &secret,
            req.name,
            railscale_types::UserId(req.user_id),
        );
        key.expiration = expiration;

        let created = self
            .db
            .create_api_key(&key)
            .await
            .map_err(|e| Status::internal(format!("Failed to create API key: {}", e)))?;

        Ok(Response::new(pb::ApiKeyWithSecret {
            id: created.id,
            key: secret.full_key.clone(), // Full key shown only on create (cloned for zeroize)
            name: created.name,
            user_id: created.user_id.0,
            expiration: created.expiration.map(|e| e.to_rfc3339()),
            created_at: created.created_at.to_rfc3339(),
        }))
    }

    async fn list_api_keys(
        &self,
        request: Request<pb::ListApiKeysRequest>,
    ) -> Result<Response<pb::ListApiKeysResponse>, Status> {
        let req = request.into_inner();

        let keys = if let Some(user_id) = req.user_id {
            self.db
                .list_api_keys(railscale_types::UserId(user_id))
                .await
                .map_err(|e| Status::internal(format!("Failed to list API keys: {}", e)))?
        } else {
            self.db
                .get_all_api_keys()
                .await
                .map_err(|e| Status::internal(format!("Failed to list API keys: {}", e)))?
        };

        // filter expired if needed
        let keys: Vec<_> = if req.show_expired {
            keys
        } else {
            keys.into_iter().filter(|k| k.is_valid()).collect()
        };

        Ok(Response::new(pb::ListApiKeysResponse {
            keys: keys.iter().map(api_key_to_pb).collect(),
        }))
    }

    async fn expire_api_key(
        &self,
        request: Request<pb::ExpireApiKeyRequest>,
    ) -> Result<Response<pb::ExpireApiKeyResponse>, Status> {
        let id = request.into_inner().id;

        self.db
            .expire_api_key(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to expire API key: {}", e)))?;

        Ok(Response::new(pb::ExpireApiKeyResponse {}))
    }

    async fn delete_api_key(
        &self,
        request: Request<pb::DeleteApiKeyRequest>,
    ) -> Result<Response<pb::DeleteApiKeyResponse>, Status> {
        let id = request.into_inner().id;

        self.db
            .delete_api_key(id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete API key: {}", e)))?;

        Ok(Response::new(pb::DeleteApiKeyResponse {}))
    }
}

// ============ Conversion helpers ============

fn user_to_pb(user: &railscale_types::User) -> pb::User {
    pb::User {
        id: user.id.0,
        email: user.email.clone().unwrap_or_else(|| user.name.clone()),
        display_name: user.display_name.clone().unwrap_or_default(),
        created_at: user.created_at.to_rfc3339(),
        oidc_groups: user.oidc_groups.clone(),
    }
}

fn node_to_pb(node: &railscale_types::Node) -> pb::Node {
    pb::Node {
        id: node.id.0,
        machine_key: hex::encode(node.machine_key.as_bytes()),
        node_key: hex::encode(node.node_key.as_bytes()),
        hostname: node.hostname.clone(),
        given_name: node.given_name.clone(),
        ipv4: node.ipv4.map(|ip| ip.to_string()),
        ipv6: node.ipv6.map(|ip| ip.to_string()),
        user_id: node.user_id.map(|id| id.0),
        tags: node.tags.iter().map(|t| t.to_string()).collect(),
        last_seen: node.last_seen.map(|t| t.to_rfc3339()),
        expiry: node.expiry.map(|t| t.to_rfc3339()),
        approved_routes: node.approved_routes.iter().map(|r| r.to_string()).collect(),
        created_at: node.created_at.to_rfc3339(),
        online: node.is_online.unwrap_or(false),
    }
}

/// convert preauthkey to protobuf with prefix only (for list operations).
fn preauth_key_to_pb(key: &railscale_types::PreAuthKey) -> pb::PreauthKey {
    pb::PreauthKey {
        id: key.id,
        key: key.key_prefix.clone(), // Only show prefix, not full key
        user_id: key.user_id.0,
        reusable: key.reusable,
        ephemeral: key.ephemeral,
        tags: key.tags.iter().map(|t| t.to_string()).collect(),
        expiration: key.expiration.map(|e| e.to_rfc3339()),
        created_at: key.created_at.to_rfc3339(),
        use_count: if key.used { 1 } else { 0 },
    }
}

/// convert preauthkey to protobuf with full key (for creation response only).
fn preauth_key_to_pb_with_full_key(
    key: &railscale_types::PreAuthKey,
    full_key: &str,
) -> pb::PreauthKey {
    pb::PreauthKey {
        id: key.id,
        key: full_key.to_string(), // Full key returned only at creation
        user_id: key.user_id.0,
        reusable: key.reusable,
        ephemeral: key.ephemeral,
        tags: key.tags.iter().map(|t| t.to_string()).collect(),
        expiration: key.expiration.map(|e| e.to_rfc3339()),
        created_at: key.created_at.to_rfc3339(),
        use_count: if key.used { 1 } else { 0 },
    }
}

fn api_key_to_pb(key: &railscale_types::ApiKey) -> pb::ApiKey {
    pb::ApiKey {
        id: key.id,
        prefix: key.prefix().to_string(),
        name: key.name.clone(),
        user_id: key.user_id.0,
        expiration: key.expiration.map(|e| e.to_rfc3339()),
        last_used_at: key.last_used_at.map(|t| t.to_rfc3339()),
        created_at: key.created_at.to_rfc3339(),
    }
}
