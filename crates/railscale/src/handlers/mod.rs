//! http handlers for railscale api endpoints.

mod error;
mod map;
pub mod oidc;
mod register;

pub use error::{ApiError, OptionExt, ResultExt};
pub use map::map;
pub use register::register;
