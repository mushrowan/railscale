//! cli subcommands for railscale.
//!
//! the cli is structured like headscale:
//! - `railscale apikeys create` - Create an api key
//! - `railscale preauthkeys create` - Create a preauth key
//! - `railscale preauthkeys list` - List preauth keys
//! - `railscale apikeys create` - Create an API key
//! - etc.

mod apikeys;
mod nodes;
mod preauthkeys;
mod serve;
mod users;

pub use apikeys::ApikeysCommand;
pub use nodes::NodesCommand;
pub use preauthkeys::PreauthkeysCommand;
pub use serve::ServeCommand;
pub use users::UsersCommand;

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

    /// manage api keys
    #[command(subcommand)]
    Apikeys(ApikeysCommand),

    /// manage users
    #[command(subcommand)]
    Users(UsersCommand),

    /// manage nodes
    #[command(subcommand)]
    Nodes(NodesCommand),
}
