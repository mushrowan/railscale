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
mod error;
mod keys;
mod node;
mod oidc;
mod preauth_key;
mod tag;
pub mod test_utils;
mod user;

pub use api_key::{ApiKey, ApiKeySecret};
pub use config::{
    ApiConfig, Config, DatabaseConfig, EmbeddedDerpRuntime, OidcConfig, PkceConfig, PkceMethod,
};
pub use error::Error;
pub use keys::{DiscoKey, MachineKey, NodeKey};
pub use node::{HostInfo, NetInfo, Node, NodeId, NodeView, RegisterMethod};
pub use oidc::{OidcClaims, RegistrationId};
pub use preauth_key::PreAuthKey;
pub use tag::{MAX_TAG_NAME_LEN, MAX_TAGS, Tag, TagError};
pub use user::{User, UserId};

/// result type alias using the crate's error type.
pub type Result<T> = std::result::Result<T, Error>;
