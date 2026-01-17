//! railscale - Tailscale control server in Rust.
//!
//! a reimplementation of headscale focusing on:
//! - Grants-based access control (instead of ACLs)
//! - Modern Rust idioms
//! - Clean, testable architecture

use clap::Parser;
use color_eyre::eyre::Result;
use railscale::cli::{Cli, Command, serve::apply_headscale_env_migration};

#[tokio::main]
async fn main() -> Result<()> {
    // install the ring crypto provider for rustls before any tls operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    color_eyre::install()?;

    // migrate headscale_* env vars to railscale_* for compatibility
    apply_headscale_env_migration();

    let cli = Cli::parse();

    match cli.command {
        Command::Serve(cmd) => cmd.run().await,
        Command::Preauthkeys(cmd) => cmd.run().await,
        Command::Apikeys(cmd) => cmd.run().await,
        Command::Users(cmd) => cmd.run().await,
        Command::Nodes(cmd) => cmd.run().await,
    }
}
