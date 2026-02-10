//! the `preauthkeys` subcommand - manage preauth keys via admin socket

use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result};
use railscale_admin::AdminClient;

use super::SocketArgs;

/// manage preauth keys
#[derive(Subcommand, Debug)]
pub enum PreauthkeysCommand {
    /// create a new preauth key
    Create(CreateArgs),

    /// list all preauth keys
    List(ListArgs),

    /// delete a preauth key
    Delete(DeleteArgs),

    /// expire a preauth key
    Expire(ExpireArgs),
}

/// create a new preauth key
#[derive(Args, Debug)]
pub struct CreateArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// user id to create the key for
    #[arg(short, long)]
    user: u64,

    /// make the key reusable (can register multiple nodes)
    #[arg(long, default_value_t = false)]
    reusable: bool,

    /// make registered nodes ephemeral (auto-deleted when inactive)
    #[arg(long, default_value_t = false)]
    ephemeral: bool,

    /// key expiration in days (default: 90)
    #[arg(long, default_value_t = 90)]
    expiration_days: i64,

    /// tags to apply to nodes registered with this key (comma-separated)
    #[arg(long, value_delimiter = ',')]
    tags: Vec<String>,
}

/// list preauth keys
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

/// delete a preauth key
#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// key id to delete
    key_id: u64,
}

/// expire a preauth key
#[derive(Args, Debug)]
pub struct ExpireArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// key id to expire
    key_id: u64,
}

impl PreauthkeysCommand {
    /// run the preauthkeys command
    pub async fn run(self) -> Result<()> {
        match self {
            PreauthkeysCommand::Create(args) => create_key(args).await,
            PreauthkeysCommand::List(args) => list_keys(args).await,
            PreauthkeysCommand::Delete(args) => delete_key(args).await,
            PreauthkeysCommand::Expire(args) => expire_key(args).await,
        }
    }
}

async fn connect_client(socket: &SocketArgs) -> Result<AdminClient> {
    AdminClient::connect_unix(&socket.socket)
        .await
        .with_context(|| format!("failed to connect to admin socket: {:?}", socket.socket))
}

/// normalize tag to have tag: prefix
fn normalize_tag(tag: &str) -> String {
    if tag.starts_with("tag:") {
        tag.to_string()
    } else {
        format!("tag:{}", tag)
    }
}

async fn create_key(args: CreateArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    // normalize tags (ensure they have tag: prefix)
    let tags: Vec<String> = args.tags.iter().map(|t| normalize_tag(t)).collect();

    let key = client
        .create_preauth_key(
            args.user,
            args.reusable,
            args.ephemeral,
            tags,
            Some(args.expiration_days),
        )
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to create preauth key: {}", e))?;

    println!("Created preauth key:");
    println!("  Key:       {}", key.key);
    println!("  User:      {}", key.user_id);
    println!("  Reusable:  {}", key.reusable);
    println!("  Ephemeral: {}", key.ephemeral);
    println!(
        "  Expires:   {}",
        key.expiration.as_deref().unwrap_or("never")
    );
    if !key.tags.is_empty() {
        println!("  Tags:      {}", key.tags.join(", "));
    }

    Ok(())
}

async fn list_keys(args: ListArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let keys = client
        .list_preauth_keys(args.user, args.show_expired)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list preauth keys: {}", e))?;

    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&keys)?);
        return Ok(());
    }

    // table output
    if keys.is_empty() {
        println!("No preauth keys found.");
        return Ok(());
    }

    println!(
        "{:<6} {:<12} {:<6} {:<8} {:<8} {:<20} TAGS",
        "ID", "KEY", "USER", "REUSABLE", "USED", "EXPIRES"
    );
    println!("{}", "-".repeat(80));

    for key in keys {
        let key_preview = if key.key.len() > 10 {
            format!("{}...", &key.key[..10])
        } else {
            key.key.clone()
        };

        let expires = key
            .expiration
            .as_ref()
            .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        let tags = if key.tags.is_empty() {
            "-".to_string()
        } else {
            key.tags.join(", ")
        };

        // use_count > 0 means used
        let used = key.use_count > 0;

        println!(
            "{:<6} {:<12} {:<6} {:<8} {:<8} {:<20} {}",
            key.id,
            key_preview,
            key.user_id,
            if key.reusable { "yes" } else { "no" },
            if used { "yes" } else { "no" },
            expires,
            tags
        );
    }

    Ok(())
}

async fn delete_key(args: DeleteArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    client
        .delete_preauth_key(args.key_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to delete preauth key: {}", e))?;

    println!("Deleted preauth key {}", args.key_id);

    Ok(())
}

async fn expire_key(args: ExpireArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    client
        .expire_preauth_key(args.key_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to expire preauth key: {}", e))?;

    println!("Expired preauth key {}", args.key_id);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_tag_with_prefix() {
        assert_eq!(normalize_tag("tag:web"), "tag:web");
    }

    #[test]
    fn test_normalize_tag_without_prefix() {
        assert_eq!(normalize_tag("web"), "tag:web");
    }
}
