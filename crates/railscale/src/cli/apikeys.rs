//! the `apikeys` subcommand - manage api keys via admin socket

use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result};
use railscale_admin::AdminClient;

use super::SocketArgs;

/// manage api keys
#[derive(Subcommand, Debug)]
pub enum ApikeysCommand {
    /// create a new api key
    Create(CreateArgs),

    /// list all api keys
    List(ListArgs),

    /// delete an api key
    Delete(DeleteArgs),

    /// expire an api key
    Expire(ExpireArgs),
}

/// create a new api key
#[derive(Args, Debug)]
pub struct CreateArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// user id to create the key for
    #[arg(short, long)]
    user: u64,

    /// name/description for the key
    #[arg(short, long)]
    name: String,

    /// key expiration in days (default: 90, 0 = never)
    #[arg(long, default_value_t = 90)]
    expiration_days: i64,
}

/// list api keys
#[derive(Args, Debug)]
pub struct ListArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// filter by user id
    #[arg(short, long)]
    user: Option<u64>,

    /// show expired keys
    #[arg(long, default_value_t = false)]
    show_expired: bool,

    /// output format (table, json)
    #[arg(short, long, default_value = "table")]
    output: String,
}

/// delete an api key
#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// key id to delete
    key_id: u64,
}

/// expire an api key
#[derive(Args, Debug)]
pub struct ExpireArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// key id to expire
    key_id: u64,
}

impl ApikeysCommand {
    /// run the apikeys command
    pub async fn run(self) -> Result<()> {
        match self {
            ApikeysCommand::Create(args) => create_key(args).await,
            ApikeysCommand::List(args) => list_keys(args).await,
            ApikeysCommand::Delete(args) => delete_key(args).await,
            ApikeysCommand::Expire(args) => expire_key(args).await,
        }
    }
}

async fn connect_client(socket: &SocketArgs) -> Result<AdminClient> {
    AdminClient::connect_unix(&socket.socket)
        .await
        .with_context(|| format!("failed to connect to admin socket: {:?}", socket.socket))
}

async fn create_key(args: CreateArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let expiration_days = if args.expiration_days == 0 {
        None
    } else {
        Some(args.expiration_days)
    };

    let key = client
        .create_api_key(args.user, args.name.clone(), expiration_days)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to create API key: {}", e))?;

    println!("Created API key:");
    println!("  ID:         {}", key.id);
    println!("  Key:        {}", key.key);
    println!("  Name:       {}", key.name);
    println!("  User:       {}", key.user_id);
    println!(
        "  Expires:    {}",
        key.expiration.as_deref().unwrap_or("never")
    );
    println!();
    println!("IMPORTANT: Save this key now. It cannot be retrieved later.");

    Ok(())
}

async fn list_keys(args: ListArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let keys = client
        .list_api_keys(args.user, args.show_expired)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list API keys: {}", e))?;

    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&keys)?);
        return Ok(());
    }

    // table output
    if keys.is_empty() {
        println!("No API keys found.");
        return Ok(());
    }

    println!(
        "{:<6} {:<12} {:<20} {:<6} {:<20} LAST USED",
        "ID", "PREFIX", "NAME", "USER", "EXPIRES"
    );
    println!("{}", "-".repeat(90));

    for key in keys {
        let prefix = format!("{}...", key.prefix);

        let expires = key
            .expiration
            .as_ref()
            .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        let last_used = key
            .last_used_at
            .as_ref()
            .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        let name = if key.name.len() > 18 {
            format!("{}...", &key.name[..15])
        } else {
            key.name.clone()
        };

        println!(
            "{:<6} {:<12} {:<20} {:<6} {:<20} {}",
            key.id, prefix, name, key.user_id, expires, last_used
        );
    }

    Ok(())
}

async fn delete_key(args: DeleteArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    client
        .delete_api_key(args.key_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to delete API key: {}", e))?;

    println!("Deleted API key {}", args.key_id);

    Ok(())
}

async fn expire_key(args: ExpireArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    client
        .expire_api_key(args.key_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to expire API key: {}", e))?;

    println!("Expired API key {}", args.key_id);

    Ok(())
}
