//! railscale - self-hosted tailscale control server

use clap::Parser;
use color_eyre::eyre::Result;
use railscale::cli::{Cli, Command, serve::apply_headscale_env_migration};

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    color_eyre::install()?;

    apply_headscale_env_migration();

    let cli = Cli::parse();

    match cli.command {
        Command::Serve(cmd) => cmd.run().await,
        Command::Policy(cmd) => cmd.run().await,
        Command::Preauthkeys(cmd) => cmd.run().await,
        Command::Apikeys(cmd) => cmd.run().await,
        Command::Users(cmd) => cmd.run().await,
        Command::Nodes(cmd) => cmd.run().await,
        Command::Lock(cmd) => cmd.run().await,
    }
}
