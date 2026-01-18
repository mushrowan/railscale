//! admin gRPC service for railscale
//!
//! provides a Unix socket-based admin api for cli commands and remote administration
//!
//! # Usage
//!
//! server:
//! ```ignore
//! use railscale_admin::{AdminServiceServer, AdminServiceImpl};
//! use tokio::net::UnixListener;
//! use tonic::transport::Server;
//!
//! let admin = AdminServiceImpl::new(db, policy_handle, policy_path);
//! let uds = UnixListener::bind("/run/railscale/admin.sock")?;
//!
//! server::builder()
//! .add_service(AdminServiceServer::new(admin))
//! .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(uds))
//! .await?;
//! ```
//!
//! client:
//! ```ignore
//! use railscale_admin::AdminClient;
//!
//! let client = AdminClient::connect_unix("/run/railscale/admin.sock").await?;
//! let response = client.reload_policy().await?;
//! ```

mod server;

pub use server::AdminServiceImpl;

/// generated protobuf types and service definitions
pub mod pb {
    tonic::include_proto!("railscale.admin.v1");
}

pub use pb::admin_service_client::AdminServiceClient;
pub use pb::admin_service_server::{AdminService, AdminServiceServer};

/// default path for the admin Unix socket
pub const DEFAULT_SOCKET_PATH: &str = "/run/railscale/admin.sock";

/// client wrapper for the admin service with Unix socket support
pub struct AdminClient {
    inner: AdminServiceClient<tonic::transport::Channel>,
}

impl AdminClient {
    /// connect to the admin service via Unix socket
    pub async fn connect_unix(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, tonic::transport::Error> {
        use hyper_util::rt::TokioIo;
        use tokio::net::UnixStream;
        use tower::service_fn;

        let path = path.as_ref().to_owned();

        // create a channel that connects via unix socket
        // we wrap unixstream with tokioio to satisfy hyper's read/write traits
        let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(service_fn(move |_| {
                let path = path.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await?;

        Ok(Self {
            inner: AdminServiceClient::new(channel),
        })
    }

    /// reload policy from the configured file
    pub async fn reload_policy(&mut self) -> Result<pb::ReloadPolicyResponse, tonic::Status> {
        let request = tonic::Request::new(pb::ReloadPolicyRequest {});
        self.inner
            .reload_policy(request)
            .await
            .map(|r| r.into_inner())
    }

    /// get the current policy as json
    pub async fn get_policy(&mut self) -> Result<pb::GetPolicyResponse, tonic::Status> {
        let request = tonic::Request::new(pb::GetPolicyRequest {});
        self.inner.get_policy(request).await.map(|r| r.into_inner())
    }

    /// set policy from json string
    pub async fn set_policy(
        &mut self,
        policy_json: String,
    ) -> Result<pb::SetPolicyResponse, tonic::Status> {
        let request = tonic::Request::new(pb::SetPolicyRequest { policy_json });
        self.inner.set_policy(request).await.map(|r| r.into_inner())
    }

    // ============ Users ============

    /// create a new user
    pub async fn create_user(
        &mut self,
        email: String,
        display_name: Option<String>,
    ) -> Result<pb::User, tonic::Status> {
        let request = tonic::Request::new(pb::CreateUserRequest {
            email,
            display_name,
        });
        self.inner
            .create_user(request)
            .await
            .map(|r| r.into_inner())
    }

    /// get a user by id
    pub async fn get_user(&mut self, id: u64) -> Result<pb::User, tonic::Status> {
        let request = tonic::Request::new(pb::GetUserRequest { id });
        self.inner.get_user(request).await.map(|r| r.into_inner())
    }

    /// list all users
    pub async fn list_users(&mut self) -> Result<Vec<pb::User>, tonic::Status> {
        let request = tonic::Request::new(pb::ListUsersRequest {});
        self.inner
            .list_users(request)
            .await
            .map(|r| r.into_inner().users)
    }

    /// delete a user
    pub async fn delete_user(&mut self, id: u64) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(pb::DeleteUserRequest { id });
        self.inner.delete_user(request).await.map(|_| ())
    }

    /// rename a user
    pub async fn rename_user(
        &mut self,
        id: u64,
        new_name: String,
    ) -> Result<pb::User, tonic::Status> {
        let request = tonic::Request::new(pb::RenameUserRequest { id, new_name });
        self.inner
            .rename_user(request)
            .await
            .map(|r| r.into_inner())
    }

    // ============ Nodes ============

    /// get a node by id
    pub async fn get_node(&mut self, id: u64) -> Result<pb::Node, tonic::Status> {
        let request = tonic::Request::new(pb::GetNodeRequest { id });
        self.inner.get_node(request).await.map(|r| r.into_inner())
    }

    /// list nodes with optional filters
    pub async fn list_nodes(
        &mut self,
        user_id: Option<u64>,
        tag: Option<String>,
    ) -> Result<Vec<pb::Node>, tonic::Status> {
        let request = tonic::Request::new(pb::ListNodesRequest { user_id, tag });
        self.inner
            .list_nodes(request)
            .await
            .map(|r| r.into_inner().nodes)
    }

    /// delete a node
    pub async fn delete_node(&mut self, id: u64) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(pb::DeleteNodeRequest { id });
        self.inner.delete_node(request).await.map(|_| ())
    }

    /// expire a node
    pub async fn expire_node(&mut self, id: u64) -> Result<pb::Node, tonic::Status> {
        let request = tonic::Request::new(pb::ExpireNodeRequest { id });
        self.inner
            .expire_node(request)
            .await
            .map(|r| r.into_inner())
    }

    /// rename a node
    pub async fn rename_node(
        &mut self,
        id: u64,
        new_name: String,
    ) -> Result<pb::Node, tonic::Status> {
        let request = tonic::Request::new(pb::RenameNodeRequest { id, new_name });
        self.inner
            .rename_node(request)
            .await
            .map(|r| r.into_inner())
    }

    /// set tags on a node
    pub async fn set_tags(
        &mut self,
        id: u64,
        tags: Vec<String>,
    ) -> Result<pb::Node, tonic::Status> {
        let request = tonic::Request::new(pb::SetTagsRequest { id, tags });
        self.inner.set_tags(request).await.map(|r| r.into_inner())
    }

    /// set approved routes on a node
    pub async fn set_approved_routes(
        &mut self,
        id: u64,
        routes: Vec<String>,
    ) -> Result<pb::Node, tonic::Status> {
        let request = tonic::Request::new(pb::SetApprovedRoutesRequest { id, routes });
        self.inner
            .set_approved_routes(request)
            .await
            .map(|r| r.into_inner())
    }

    // ============ PreAuth Keys ============

    /// create a preauth key
    pub async fn create_preauth_key(
        &mut self,
        user_id: u64,
        reusable: bool,
        ephemeral: bool,
        tags: Vec<String>,
        expiration_days: Option<i64>,
    ) -> Result<pb::PreauthKey, tonic::Status> {
        let request = tonic::Request::new(pb::CreatePreauthKeyRequest {
            user_id,
            reusable,
            ephemeral,
            tags,
            expiration_days,
        });
        self.inner
            .create_preauth_key(request)
            .await
            .map(|r| r.into_inner())
    }

    /// list preauth keys
    pub async fn list_preauth_keys(
        &mut self,
        user_id: Option<u64>,
        show_expired: bool,
    ) -> Result<Vec<pb::PreauthKey>, tonic::Status> {
        let request = tonic::Request::new(pb::ListPreauthKeysRequest {
            user_id,
            show_expired,
        });
        self.inner
            .list_preauth_keys(request)
            .await
            .map(|r| r.into_inner().keys)
    }

    /// expire a preauth key
    pub async fn expire_preauth_key(&mut self, id: u64) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(pb::ExpirePreauthKeyRequest { id });
        self.inner.expire_preauth_key(request).await.map(|_| ())
    }

    /// delete a preauth key
    pub async fn delete_preauth_key(&mut self, id: u64) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(pb::DeletePreauthKeyRequest { id });
        self.inner.delete_preauth_key(request).await.map(|_| ())
    }

    // ============ api keys ============

    /// create an api key
    pub async fn create_api_key(
        &mut self,
        user_id: u64,
        name: String,
        expiration_days: Option<i64>,
    ) -> Result<pb::ApiKeyWithSecret, tonic::Status> {
        let request = tonic::Request::new(pb::CreateApiKeyRequest {
            user_id,
            name,
            expiration_days,
        });
        self.inner
            .create_api_key(request)
            .await
            .map(|r| r.into_inner())
    }

    /// list api keys
    pub async fn list_api_keys(
        &mut self,
        user_id: Option<u64>,
        show_expired: bool,
    ) -> Result<Vec<pb::ApiKey>, tonic::Status> {
        let request = tonic::Request::new(pb::ListApiKeysRequest {
            user_id,
            show_expired,
        });
        self.inner
            .list_api_keys(request)
            .await
            .map(|r| r.into_inner().keys)
    }

    /// expire an api key
    pub async fn expire_api_key(&mut self, id: u64) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(pb::ExpireApiKeyRequest { id });
        self.inner.expire_api_key(request).await.map(|_| ())
    }

    /// delete an api key
    pub async fn delete_api_key(&mut self, id: u64) -> Result<(), tonic::Status> {
        let request = tonic::Request::new(pb::DeleteApiKeyRequest { id });
        self.inner.delete_api_key(request).await.map(|_| ())
    }
}
