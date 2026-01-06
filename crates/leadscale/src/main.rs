//! leadscale - tailscale control server in rust
//!
//! reimplementation of headscale focusing on:
//! - grants-based access control (instead of acls)
//! - modern rust idioms
//! - clean, testable architecture

use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("starting leadscale...");

    // TODO: parse cli arguments
    // TODO: load configuration
    // TODO: initialize state
    // TODO: start http/grpc servers
    // TODO: handle graceful shutdown

    info!("leadscale is not yet implemented. check claude.md for project status.");

    Ok(())
}
