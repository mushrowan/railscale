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
    if let Some(ctx) = machine_key_ctx
        && ctx.machine_key().as_bytes() != node.machine_key.as_bytes()
    {
        return Err(ApiError::unauthorized("machine key does not match node"));
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

#[cfg(test)]
mod validate_machine_key_tests {
    use super::*;
    use railscale_types::test_utils::TestNodeBuilder;

    #[test]
    fn matching_machine_key_passes() {
        let node = TestNodeBuilder::new(1).build();
        let ctx = MachineKeyContext(node.machine_key.clone());
        assert!(validate_machine_key(&Some(ctx), &node).is_ok());
    }

    #[test]
    fn mismatched_machine_key_rejects() {
        let node = TestNodeBuilder::new(1).build();
        let wrong_key = MachineKeyContext::from_bytes(vec![99u8; 32]);
        let result = validate_machine_key(&Some(wrong_key), &node);
        assert!(result.is_err());
    }

    #[test]
    fn no_machine_key_context_passes() {
        let node = TestNodeBuilder::new(1).build();
        assert!(validate_machine_key(&None, &node).is_ok());
    }
}
