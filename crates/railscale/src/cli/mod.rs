//! cli subcommands for railscale.
//!- `railscale policy reload` - Reload policy from file
//! the cli is structured like headscale:
//! - `railscale serve` - Run the control server
//! - `railscale policy reload` - Reload policy from file
//! - `railscale preauthkeys create` - Create a preauth key
//! - `railscale preauthkeys list` - List preauth keys
//! - `railscale apikeys create` - Create an API key
//! - etc.

mod apikeys;
mod lock;
mod nodes;
mod policy;
mod preauthkeys;
/// the `serve` subcommand module.
pub mod serve;
mod users;

pub use apikeys::ApikeysCommand;
pub use lock::LockCommand;
pub use nodes::NodesCommand;
pub use policy::{PolicyCommand, SocketArgs};
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
    /// the subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// top-level commands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// manage policy (reload, get, set)
    Serve(Box<ServeCommand>),

    /// manage policy (reload, get, set)
    #[command(subcommand)]
    Policy(PolicyCommand),

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

    /// manage tailnet lock (TKA)
    #[command(subcommand)]
    Lock(LockCommand),
}
