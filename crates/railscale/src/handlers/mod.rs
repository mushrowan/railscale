//! http handlers for railscale api endpoints.

mod error;
mod health;
mod key;
mod machine_key_context;
mod map;
pub mod oidc;
mod register;
mod ts2021;
mod version;

pub use error::{ApiError, OptionExt, ResultExt};
pub use health::health;
pub use key::key;
pub use machine_key_context::{MachineKeyContext, OptionalMachineKeyContext};
pub use map::map;
pub use register::{RegisterResponse, register};
pub use ts2021::{ts2021, ts2021_http_upgrade};
pub use version::version;
