//! railscale - tailscale control server in Rust
//!
//! a reimplementation of headscale focusing on:
//! - Grants-based access control (instead of ACLs)
//! - Modern Rust idioms
//! - Clean, testable architecture

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

    info!("Starting railscale...");

    // TODO: parse cli arguments
    // TODO: load configuration
    // TODO: initialize state
    // TODO: start http/grpc servers
    // TODO: handle graceful shutdown

    info!("railscale is not yet implemented. Check CLAUDE.md for project status.");

    Ok(())
}
