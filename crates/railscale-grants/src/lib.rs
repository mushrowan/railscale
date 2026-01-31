//! grants-based access control for railscale.
//!
//! this crate implements tailscale's grants system for controlling network
//! access and application capabilities. Grants use deny-by-default semantics
//! with union composition (multiple matching grants combine their permissions).

#![warn(missing_docs)]

pub mod capability;
pub mod engine;
pub mod error;
pub mod grant;
pub mod policy;
pub mod posture;
pub mod selector;
pub mod ssh;

pub use capability::{AppCapability, NetworkCapability, Protocol};
pub use engine::{GrantsEngine, UserResolver};
pub use error::{Error, ParseError, Result, ValidationError};
pub use grant::Grant;
pub use policy::Policy;
pub use posture::{PostureAttr, PostureContext, PostureExpr, PostureOp, PostureParseError};
pub use selector::{Autogroup, Selector};
pub use ssh::{SshActionType, SshPolicyRule, build_ssh_users_map};
