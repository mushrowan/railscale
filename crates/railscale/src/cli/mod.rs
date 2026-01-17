//! cLI subcommands for railscale
//!
//! the cli is structured like headscale:
//! - `railscale serve` - Run the control server
//! - `railscale preauthkeys create` - Create a preauth key
//! - `railscale preauthkeys list` - List preauth keys
//! - etc

mod preauthkeys;
mod serve;

pub use preauthkeys::PreauthkeysCommand;
pub use serve::ServeCommand;

use clap::{Parser, Subcommand};

/// railscale - self-hosted tailscale control server
#[derive(Parser, Debug)]
#[command(name = "railscale")]
#[command(about = "Self-hosted Tailscale control server", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// top-level commands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// run the control server
    Serve(ServeCommand),

    /// manage preauth keys
    #[command(subcommand)]
    Preauthkeys(PreauthkeysCommand),
}
