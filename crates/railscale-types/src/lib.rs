//! core types for railscale - a tailscale control server implementation in rust.
//!
//! this crate provides the fundamental data structures used throughout railscale:
//! - [`node`]: represents a tailscale client/device
//! - [`user`]: user/namespace management
//! - [`preauthkey`]: pre-authentication keys for automated registration
//! - [`config`]: application configuration

mod config;
mod error;
mod keys;
mod node;
mod oidc;
mod preauth_key;
mod user;

pub use config::{Config, DatabaseConfig, OidcConfig, PkceConfig, PkceMethod};
pub use error::Error;
pub use keys::{DiscoKey, MachineKey, NodeKey};
pub use node::{HostInfo, NetInfo, Node, NodeId, NodeView, RegisterMethod};
pub use oidc::{OidcClaims, RegistrationId};
pub use preauth_key::PreAuthKey;
pub use user::{User, UserId};

/// result type alias using the crate's error type.
pub type Result<T> = std::result::Result<T, Error>;
