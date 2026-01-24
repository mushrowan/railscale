//! node endpoints for api v1 (headscale-compatible).
//!
//! endpoints:
//! - `GET /api/v1/node` - list all nodes
//! - `GET /api/v1/node/{id}` - get a specific node
//! - `DELETE /api/v1/node/{id}` - delete a node
//! - `POST /api/v1/node/{id}/expire` - expire a node
//! - `POST /api/v1/node/{id}/rename/{new_name}` - rename a node
//! - `POST /api/v1/node/{id}/tags` - set node tags
//! - `POST /api/v1/node/{id}/routes` - set approved routes

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::Utc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::handlers::{ApiError, ApiKeyContext};
use railscale_db::Database;
use railscale_types::{Node, NodeId, NodeName};

/// response wrapper for list nodes endpoint.
#[derive(Debug, Serialize)]
pub struct ListNodesResponse {
    pub nodes: Vec<NodeResponse>,
}

/// response wrapper for single node endpoint.
#[derive(Debug, Serialize)]
pub struct GetNodeResponse {
    pub node: NodeResponse,
}

/// node representation in api responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeResponse {
    pub id: String,
    pub machine_key: String,
    pub node_key: String,
    pub disco_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub hostname: String,
    pub given_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    pub register_method: String,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    pub approved_routes: Vec<String>,
    pub created_at: String,
    pub online: bool,
}

/// format a key as "prefix:<hex>"
fn format_key(prefix: &str, bytes: &[u8]) -> String {
    format!("{}:{}", prefix, hex::encode(bytes))
}

impl From<Node> for NodeResponse {
    fn from(node: Node) -> Self {
        Self {
            id: node.id.0.to_string(),
            machine_key: format_key("mkey", node.machine_key.as_bytes()),
            node_key: format_key("nodekey", node.node_key.as_bytes()),
            disco_key: format_key("discokey", node.disco_key.as_bytes()),
            ipv4: node.ipv4.map(|ip| ip.to_string()),
            ipv6: node.ipv6.map(|ip| ip.to_string()),
            hostname: node.hostname,
            given_name: node.given_name,
            user_id: node.user_id.map(|id| id.0.to_string()),
            register_method: format!("{:?}", node.register_method).to_lowercase(),
            tags: node.tags.iter().map(|t| t.to_string()).collect(),
            expiry: node.expiry.map(|dt| dt.to_rfc3339()),
            last_seen: node.last_seen.map(|dt| dt.to_rfc3339()),
            approved_routes: node.approved_routes.iter().map(|r| r.to_string()).collect(),
            created_at: node.created_at.to_rfc3339(),
            online: node.is_online.unwrap_or(false),
        }
    }
}

/// response for delete/expire operations.
#[derive(Debug, Serialize)]
pub struct EmptyResponse {}

/// request for expire endpoint.
#[derive(Debug, Deserialize)]
pub struct ExpireNodeRequest {
    /// optional expiry time; if not provided, expires immediately.
    #[serde(default)]
    pub expiry: Option<String>,
}

/// request for setting tags.
#[derive(Debug, Deserialize)]
pub struct SetTagsRequest {
    /// tags are validated during deserialization via the tag type.
    pub tags: Vec<railscale_types::Tag>,
}

/// response for set tags endpoint.
#[derive(Debug, Serialize)]
pub struct SetTagsResponse {
    pub node: NodeResponse,
}

/// request for setting approved routes.
#[derive(Debug, Deserialize)]
pub struct SetRoutesRequest {
    pub routes: Vec<String>,
}

/// response for set routes endpoint.
#[derive(Debug, Serialize)]
pub struct SetRoutesResponse {
    pub node: NodeResponse,
}

/// response for rename endpoint.
#[derive(Debug, Serialize)]
pub struct RenameNodeResponse {
    pub node: NodeResponse,
}

/// create the nodes router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_nodes))
        .route("/{id}", get(get_node).delete(delete_node))
        .route("/{id}/expire", post(expire_node))
        .route("/{id}/rename/{new_name}", post(rename_node))
        .route("/{id}/tags", post(set_tags))
        .route("/{id}/routes", post(set_routes))
}

/// list all nodes.
///
/// `GET /api/v1/node`
async fn list_nodes(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
) -> Result<Json<ListNodesResponse>, ApiError> {
    let nodes = state.db.list_nodes().await.map_err(ApiError::internal)?;

    let nodes: Vec<NodeResponse> = nodes.into_iter().map(NodeResponse::from).collect();

    Ok(Json(ListNodesResponse { nodes }))
}

/// get a specific node.
///
/// `GET /api/v1/node/{id}`
async fn get_node(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<GetNodeResponse>, ApiError> {
    let node_id = NodeId(id);

    let node = state
        .db
        .get_node(node_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("node {} not found", id)))?;

    Ok(Json(GetNodeResponse {
        node: NodeResponse::from(node),
    }))
}

/// delete a node.
///
/// `DELETE /api/v1/node/{id}`
async fn delete_node(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> Result<Json<EmptyResponse>, ApiError> {
    let node_id = NodeId(id);

    // check node exists
    if state
        .db
        .get_node(node_id)
        .await
        .map_err(ApiError::internal)?
        .is_none()
    {
        return Err(ApiError::not_found(format!("node {} not found", id)));
    }

    state
        .db
        .delete_node(node_id)
        .await
        .map_err(ApiError::internal)?;

    // notify connected clients about the change
    state.notifier.notify_state_changed();

    Ok(Json(EmptyResponse {}))
}

/// expire a node.
///
/// `POST /api/v1/node/{id}/expire`
async fn expire_node(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(req): Json<ExpireNodeRequest>,
) -> Result<Json<GetNodeResponse>, ApiError> {
    let node_id = NodeId(id);

    let mut node = state
        .db
        .get_node(node_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("node {} not found", id)))?;

    // parse expiry or use now
    let expiry = if let Some(expiry_str) = req.expiry {
        chrono::DateTime::parse_from_rfc3339(&expiry_str)
            .map_err(|_| ApiError::bad_request("invalid expiration format, expected RFC3339"))?
            .with_timezone(&Utc)
    } else {
        Utc::now()
    };

    node.expiry = Some(expiry);
    let node = state
        .db
        .update_node(&node)
        .await
        .map_err(ApiError::internal)?;

    // notify connected clients
    state.notifier.notify_state_changed();

    Ok(Json(GetNodeResponse {
        node: NodeResponse::from(node),
    }))
}

/// rename a node.
///
/// `POST /api/v1/node/{id}/rename/{new_name}`
async fn rename_node(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path((id, new_name)): Path<(u64, String)>,
) -> Result<Json<RenameNodeResponse>, ApiError> {
    // validate new node name
    let new_name = NodeName::new(&new_name).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let node_id = NodeId(id);

    let mut node = state
        .db
        .get_node(node_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("node {} not found", id)))?;

    node.given_name = new_name.into_inner();
    let node = state
        .db
        .update_node(&node)
        .await
        .map_err(ApiError::internal)?;

    // notify connected clients
    state.notifier.notify_state_changed();

    Ok(Json(RenameNodeResponse {
        node: NodeResponse::from(node),
    }))
}

/// set node tags.
///
/// `POST /api/v1/node/{id}/tags`
///
/// NOTE: once a node has tags, it becomes a "tagged node" and tags
/// cannot be completely removed (tags-as-identity model).
async fn set_tags(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(req): Json<SetTagsRequest>,
) -> Result<Json<SetTagsResponse>, ApiError> {
    let node_id = NodeId(id);

    // check tag count limit (individual tags validated by tag type during deserialization)
    if req.tags.len() > railscale_types::MAX_TAGS {
        return Err(ApiError::bad_request(format!(
            "too many tags (max {})",
            railscale_types::MAX_TAGS
        )));
    }

    let mut node = state
        .db
        .get_node(node_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("node {} not found", id)))?;

    // once tagged, cannot remove all tags (tags-as-identity)
    if !node.tags.is_empty() && req.tags.is_empty() {
        return Err(ApiError::bad_request(
            "cannot remove all tags from a tagged node - tagged nodes must have at least one tag",
        ));
    }

    node.tags = req.tags;
    let node = state
        .db
        .update_node(&node)
        .await
        .map_err(ApiError::internal)?;

    // notify connected clients
    state.notifier.notify_state_changed();

    Ok(Json(SetTagsResponse {
        node: NodeResponse::from(node),
    }))
}

/// set approved routes for a node.
///
/// `POST /api/v1/node/{id}/routes`
async fn set_routes(
    _auth: ApiKeyContext,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(req): Json<SetRoutesRequest>,
) -> Result<Json<SetRoutesResponse>, ApiError> {
    let node_id = NodeId(id);

    let mut node = state
        .db
        .get_node(node_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("node {} not found", id)))?;

    // parse routes
    let mut routes = Vec::new();
    for route_str in &req.routes {
        let route: IpNet = route_str.parse().map_err(|e| {
            tracing::warn!("Invalid route submitted: '{}': {}", route_str, e);
            ApiError::bad_request("invalid CIDR route format")
        })?;
        routes.push(route);
    }

    node.approved_routes = routes;
    let node = state
        .db
        .update_node(&node)
        .await
        .map_err(ApiError::internal)?;

    // notify connected clients
    state.notifier.notify_state_changed();

    Ok(Json(SetRoutesResponse {
        node: NodeResponse::from(node),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use railscale_types::test_utils::TestNodeBuilder;

    #[test]
    fn test_node_response_from_node() {
        let node = TestNodeBuilder::new(42).with_hostname("test-node").build();
        let response = NodeResponse::from(node);

        assert_eq!(response.id, "42");
        assert_eq!(response.hostname, "test-node");
        assert!(response.tags.is_empty());
    }

    #[test]
    fn test_node_response_serialization() {
        let node = TestNodeBuilder::new(1)
            .with_hostname("mynode")
            .with_tags(vec!["tag:server".parse().unwrap()])
            .build();
        let response = NodeResponse::from(node);

        let json = serde_json::to_string(&response).unwrap();

        // verify snake_case field names
        assert!(json.contains("\"id\""));
        assert!(json.contains("\"hostname\""));
        assert!(json.contains("\"given_name\""));
        assert!(json.contains("\"machine_key\""));
        assert!(json.contains("\"node_key\""));
        assert!(json.contains("\"tags\""));
        assert!(json.contains("\"tag:server\""));
    }

    #[test]
    fn test_list_nodes_response() {
        let response = ListNodesResponse { nodes: vec![] };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"nodes\""));
    }

    #[test]
    fn test_set_tags_request_deserialization() {
        let json = r#"{"tags": ["tag:web", "tag:prod"]}"#;
        let req: SetTagsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.tags.len(), 2);
        assert_eq!(req.tags[0], "tag:web");
    }

    #[test]
    fn test_set_routes_request_deserialization() {
        let json = r#"{"routes": ["10.0.0.0/8", "192.168.1.0/24"]}"#;
        let req: SetRoutesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.routes.len(), 2);
    }

    #[test]
    fn test_expire_request_empty() {
        let json = r#"{}"#;
        let req: ExpireNodeRequest = serde_json::from_str(json).unwrap();
        assert!(req.expiry.is_none());
    }

    #[test]
    fn test_expire_request_with_time() {
        let json = r#"{"expiry": "2024-12-31T23:59:59Z"}"#;
        let req: ExpireNodeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.expiry.as_deref(), Some("2024-12-31T23:59:59Z"));
    }
}
