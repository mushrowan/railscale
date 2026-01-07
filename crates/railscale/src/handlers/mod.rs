//! hTTP handlers for railscale api endpoints

mod error;
mod map;
mod register;

pub use error::{ApiError, OptionExt, ResultExt};
pub use map::map;
pub use register::register;
