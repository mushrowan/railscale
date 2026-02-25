//! http handlers for railscale api endpoints.

mod api_auth;
pub mod api_v1;
mod audit_log;
mod bootstrap_dns;
mod error;
mod health;
mod key;
mod machine_key_context;
mod map;
pub mod oidc;
mod register;
mod set_device_attr;
mod set_dns;
mod templates;
mod tka;
mod ts2021;
mod verify;
mod version;

#[cfg(test)]
pub(crate) mod test_helpers;

pub use api_auth::{ApiAuthError, ApiKeyContext, AuthMethod};

/// validate that the machine key from the Noise session matches the node.
/// prevents a compromised client from spoofing requests for other nodes
pub(crate) fn validate_machine_key(
    machine_key_ctx: &Option<MachineKeyContext>,
    node: &railscale_types::Node,
) -> Result<(), ApiError> {
    if let Some(ctx) = machine_key_ctx {
        if ctx.machine_key().as_bytes() != node.machine_key.as_bytes() {
            return Err(ApiError::unauthorized("machine key does not match node"));
        }
    }
    Ok(())
}
pub use audit_log::audit_log;
pub use bootstrap_dns::bootstrap_dns;
pub use error::{ApiError, JsonBody, OptionExt, ResultExt};
pub use health::health;
pub use key::key;
pub use machine_key_context::{MachineKeyContext, OptionalMachineKeyContext};
pub use map::map;
pub use register::{RegisterResponse, register};
pub use set_device_attr::set_device_attr;
pub use set_dns::set_dns;
pub use tka::{
    tka_bootstrap, tka_disable, tka_init_begin, tka_init_finish, tka_sign, tka_sync_offer,
    tka_sync_send,
};
pub use ts2021::{ts2021, ts2021_http_upgrade};
pub use verify::verify;
pub use version::version;
