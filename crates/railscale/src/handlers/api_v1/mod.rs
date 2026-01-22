//! headscale-compatible rest api v1 handlers.
//!
//! these endpoints match headscale's api paths for compatibility with
//! existing tools and CLI clients.

mod api_keys;
mod nodes;
mod policy;
mod preauth_keys;
mod users;

pub use api_keys::router as api_keys_router;
pub use nodes::router as nodes_router;
pub use policy::router as policy_router;
pub use preauth_keys::router as preauth_keys_router;
pub use users::router as users_router;

use axum::Router;

use crate::AppState;

/// create the api v1 router with all endpoints.
pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/user", users_router())
        .nest("/node", nodes_router())
        .nest("/preauthkey", preauth_keys_router())
        .nest("/apikey", api_keys_router())
        .nest("/policy", policy_router())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_builds() {
        // just verify the router can be constructed without panicking
        let _router: Router<AppState> = router();
    }
}
