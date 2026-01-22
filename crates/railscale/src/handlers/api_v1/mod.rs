//! headscale-compatible rest api v1 handlers.
//!
//! these endpoints match headscale's api paths for compatibility with
//! existing tools and CLI clients.

mod nodes;
mod users;

pub use nodes::router as nodes_router;
pub use users::router as users_router;

use axum::Router;

use crate::AppState;

/// create the api v1 router with all endpoints.
pub fn router() -> Router<AppState> {
    Router::new()
        .nest("/user", users_router())
        .nest("/node", nodes_router())
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
