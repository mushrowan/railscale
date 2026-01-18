//! the `policy` subcommand - manage policy via admin socket

use std::path::PathBuf;

use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result};
use railscale_admin::AdminClient;

/// common socket arguments for admin commands
#[derive(Args, Debug, Clone)]
pub struct SocketArgs {
    /// path to admin Unix socket
    #[arg(
        long,
        env = "RAILSCALE_ADMIN_SOCKET",
        default_value = "/run/railscale/admin.sock"
    )]
    pub socket: PathBuf,
}

/// manage policy
#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// reload policy from the configured file
    Reload(ReloadArgs),

    /// get the current policy
    Get(GetArgs),

    /// set policy from a file
    Set(SetArgs),
}

/// reload policy from the configured file
#[derive(Args, Debug)]
pub struct ReloadArgs {
    #[command(flatten)]
    socket: SocketArgs,
}

/// get the current policy
#[derive(Args, Debug)]
pub struct GetArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// output format (json or yaml)
    #[arg(short, long, default_value = "json")]
    output: String,
}

/// set policy from a file
#[derive(Args, Debug)]
pub struct SetArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// path to policy file (json format)
    file: PathBuf,
}

impl PolicyCommand {
    /// run the policy command
    pub async fn run(self) -> Result<()> {
        match self {
            PolicyCommand::Reload(args) => reload_policy(args).await,
            PolicyCommand::Get(args) => get_policy(args).await,
            PolicyCommand::Set(args) => set_policy(args).await,
        }
    }
}

async fn reload_policy(args: ReloadArgs) -> Result<()> {
    let mut client = AdminClient::connect_unix(&args.socket.socket)
        .await
        .with_context(|| {
            format!(
                "failed to connect to admin socket: {:?}",
                args.socket.socket
            )
        })?;

    let response = client
        .reload_policy()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("reload failed: {}", e))?;

    if response.success {
        println!(
            "Policy reloaded successfully ({} grants)",
            response.grants_loaded
        );
    } else {
        println!("Policy reload failed: {}", response.message);
    }

    Ok(())
}

async fn get_policy(args: GetArgs) -> Result<()> {
    let mut client = AdminClient::connect_unix(&args.socket.socket)
        .await
        .with_context(|| {
            format!(
                "failed to connect to admin socket: {:?}",
                args.socket.socket
            )
        })?;

    let response = client
        .get_policy()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("get policy failed: {}", e))?;

    if args.output == "yaml" {
        // convert json to YAML
        let policy: serde_json::Value =
            serde_json::from_str(&response.policy_json).context("failed to parse policy JSON")?;
        let yaml = serde_yaml::to_string(&policy).context("failed to convert to YAML")?;
        println!("{}", yaml);
    } else {
        // pretty-print json
        let policy: serde_json::Value =
            serde_json::from_str(&response.policy_json).context("failed to parse policy JSON")?;
        println!("{}", serde_json::to_string_pretty(&policy)?);
    }

    Ok(())
}

async fn set_policy(args: SetArgs) -> Result<()> {
    let policy_json = std::fs::read_to_string(&args.file)
        .with_context(|| format!("failed to read policy file: {:?}", args.file))?;

    // validate json
    let _: serde_json::Value =
        serde_json::from_str(&policy_json).context("invalid JSON in policy file")?;

    let mut client = AdminClient::connect_unix(&args.socket.socket)
        .await
        .with_context(|| {
            format!(
                "failed to connect to admin socket: {:?}",
                args.socket.socket
            )
        })?;

    let response = client
        .set_policy(policy_json)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("set policy failed: {}", e))?;

    if response.success {
        println!(
            "Policy set successfully ({} grants)",
            response.grants_loaded
        );
    } else {
        println!("Policy set failed: {}", response.message);
    }

    Ok(())
}
