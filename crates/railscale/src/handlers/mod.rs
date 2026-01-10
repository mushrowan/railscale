//! http handlers for railscale api endpoints.

mod error;
mod key;
mod map;
pub mod oidc;
mod register;
mod ts2021;

pub use error::{ApiError, OptionExt, ResultExt};
pub use key::key;
pub use map::map;
pub use register::register;
pub use ts2021::ts2021;
