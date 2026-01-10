//! http handlers for railscale api endpoints.

mod error;
mod key;
mod map;
pub mod oidc;
mod register;

pub use error::{ApiError, OptionExt, ResultExt};
pub use key::key;
pub use map::map;
pub use register::register;
