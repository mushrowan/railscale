//! shared test helpers for handler tests

use railscale_grants::{Grant, GrantsEngine, NetworkCapability, Policy, Selector};

/// allow-all grants engine for handler tests
pub fn default_grants() -> GrantsEngine {
    let mut policy = Policy::empty();
    policy.grants.push(Grant {
        src: vec![Selector::Wildcard],
        dst: vec![Selector::Wildcard],
        ip: vec![NetworkCapability::Wildcard],
        app: vec![],
        src_posture: vec![],
        via: vec![],
    });
    GrantsEngine::new(policy)
}
