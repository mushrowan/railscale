//! core types for railscale - a tailscale control server implementation in rust.
//!
//! this crate provides the fundamental data structures used throughout railscale:
//! - [`node`]: represents a tailscale client/device
//! - [`user`]: user/namespace management
//! - [`preauthkey`]: pre-authentication keys for automated registration
//! - [`config`]: application configuration

#![warn(missing_docs)]

mod api_key;
mod config;
mod email;
mod error;
mod keys;
mod node;
mod node_name;
mod oidc;
mod policy_json;
mod preauth_key;
mod tag;
pub mod test_utils;
mod user;
mod username;

pub use api_key::{ApiKey, ApiKeySecret};
pub use config::{
    ApiConfig, Config, DEFAULT_DERP_IDLE_TIMEOUT_SECS, DEFAULT_DERP_MAX_CONNECTIONS,
    DatabaseConfig, EmbeddedDerpConfig, EmbeddedDerpRuntime, OidcConfig, PkceConfig, PkceMethod,
};
pub use email::{Email, EmailError};
pub use error::Error;
pub use keys::{DiscoKey, MachineKey, NodeKey};
pub use node::{HostInfo, NetInfo, Node, NodeId, NodeView, RegisterMethod};
pub use node_name::{MAX_NODE_NAME_LEN, NodeName, NodeNameError};
pub use oidc::{OidcClaims, RegistrationId};
pub use policy_json::{MAX_POLICY_SIZE, PolicyJson, PolicyJsonError};
pub use preauth_key::PreAuthKey;
pub use tag::{MAX_TAG_NAME_LEN, MAX_TAGS, Tag, TagError};
pub use user::{User, UserId};
pub use username::{MAX_USERNAME_LEN, Username, UsernameError};

/// result type alias using the crate's error type.
pub type Result<T> = std::result::Result<T, Error>;
