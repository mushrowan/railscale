//! grants-based access control for leadscale
//!
//! this crate implements tailscale's grants system for controlling network
//! access and application capabilities. Grants use deny-by-default semantics
//! with union composition (multiple matching grants combine their permissions)

pub mod capability;
pub mod engine;
pub mod error;
pub mod grant;
pub mod policy;
pub mod selector;

pub use capability::{AppCapability, NetworkCapability, Protocol};
pub use engine::GrantsEngine;
pub use error::{Error, ParseError, Result, ValidationError};
pub use grant::Grant;
pub use policy::Policy;
pub use selector::{Autogroup, Selector};
