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

/// node with verified machine key. only constructible via `verify`
pub(crate) struct VerifiedNode(railscale_types::Node);

impl VerifiedNode {
    pub fn verify(
        node: railscale_types::Node,
        machine_key_ctx: &Option<MachineKeyContext>,
    ) -> Result<Self, ApiError> {
        if let Some(ctx) = machine_key_ctx
            && ctx.machine_key().as_bytes() != node.machine_key.as_bytes()
        {
            return Err(ApiError::unauthorized("machine key does not match node"));
        }
        Ok(Self(node))
    }

    pub fn into_inner(self) -> railscale_types::Node {
        self.0
    }
}

impl std::ops::Deref for VerifiedNode {
    type Target = railscale_types::Node;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for VerifiedNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
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
mod verified_node_tests {
    use super::*;
    use railscale_types::test_utils::TestNodeBuilder;

    #[test]
    fn matching_machine_key_passes() {
        let node = TestNodeBuilder::new(1).build();
        let ctx = MachineKeyContext(node.machine_key.clone());
        assert!(VerifiedNode::verify(node, &Some(ctx)).is_ok());
    }

    #[test]
    fn mismatched_machine_key_rejects() {
        let node = TestNodeBuilder::new(1).build();
        let wrong_key = MachineKeyContext::from_bytes(vec![99u8; 32]);
        assert!(VerifiedNode::verify(node, &Some(wrong_key)).is_err());
    }

    #[test]
    fn no_machine_key_context_passes() {
        let node = TestNodeBuilder::new(1).build();
        assert!(VerifiedNode::verify(node, &None).is_ok());
    }

    #[test]
    fn deref_exposes_node_fields() {
        let node = TestNodeBuilder::new(1).build();
        let expected_id = node.id;
        let verified = VerifiedNode::verify(node, &None).unwrap();
        assert_eq!(verified.id, expected_id);
    }

    #[test]
    fn deref_mut_allows_mutation() {
        let node = TestNodeBuilder::new(1).build();
        let mut verified = VerifiedNode::verify(node, &None).unwrap();
        verified.hostname = "mutated".to_string();
        assert_eq!(verified.hostname, "mutated");
    }

    #[test]
    fn into_inner_returns_node() {
        let node = TestNodeBuilder::new(1).build();
        let expected_id = node.id;
        let verified = VerifiedNode::verify(node, &None).unwrap();
        let inner = verified.into_inner();
        assert_eq!(inner.id, expected_id);
    }
}
