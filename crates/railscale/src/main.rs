//! railscale - Tailscale control server in Rust.
//!
//! a reimplementation of headscale focusing on:
//! - Grants-based access control (instead of ACLs)
//! - Modern Rust idioms
//! - Clean, testable architecture

use clap::Parser;
use color_eyre::eyre::Result;
use railscale::cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    // install the ring crypto provider for rustls before any tls operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    color_eyre::install()?;

    let cli = Cli::parse();

    match cli.command {
        Command::Serve(cmd) => cmd.run().await,
        Command::Preauthkeys(cmd) => cmd.run().await,
        Command::Apikeys(cmd) => cmd.run().await,
        Command::Users(cmd) => cmd.run().await,
        Command::Nodes(cmd) => cmd.run().await,
    }
}
