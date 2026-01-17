//! the `apikeys` subcommand - manage api keys

use chrono::{Duration, Utc};
use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result, bail};
use railscale_db::Database;
use railscale_types::{ApiKey, UserId};

use super::preauthkeys::DbArgs;

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
    db: DbArgs,

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
    db: DbArgs,

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
    db: DbArgs,

    /// key id to delete
    key_id: u64,
}

/// expire an api key
#[derive(Args, Debug)]
pub struct ExpireArgs {
    #[command(flatten)]
    db: DbArgs,

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

async fn create_key(args: CreateArgs) -> Result<()> {
    let db = args.db.connect().await?;

    // verify user exists
    let user = db
        .get_user(UserId(args.user))
        .await
        .context("failed to query user")?;

    if user.is_none() {
        bail!("user {} not found", args.user);
    }

    let now = Utc::now();
    let expiration = if args.expiration_days == 0 {
        None
    } else {
        Some(now + Duration::days(args.expiration_days))
    };

    // generate a random key
    let key_string = generate_api_key();

    let mut key = ApiKey::new(0, key_string, args.name, UserId(args.user));
    key.expiration = expiration;

    let created = db
        .create_api_key(&key)
        .await
        .context("failed to create API key")?;

    println!("Created API key:");
    println!("  ID:         {}", created.id);
    println!("  Key:        {}", created.key);
    println!("  Name:       {}", created.name);
    println!("  User:       {}", created.user_id.0);
    println!(
        "  Expires:    {}",
        created
            .expiration
            .map(|e| e.to_rfc3339())
            .unwrap_or_else(|| "never".to_string())
    );
    println!();
    println!("IMPORTANT: Save this key now. It cannot be retrieved later.");

    Ok(())
}

/// generate a random api key string
fn generate_api_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const KEY_LEN: usize = 32;

    let mut rng = rand::rng();
    let random_part: String = (0..KEY_LEN)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    format!("rsapi_{}", random_part)
}

async fn list_keys(args: ListArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let keys = if let Some(user_id) = args.user {
        db.list_api_keys(UserId(user_id))
            .await
            .context("failed to list API keys")?
    } else {
        db.get_all_api_keys()
            .await
            .context("failed to list API keys")?
    };

    // filter expired if needed
    let keys: Vec<_> = if args.show_expired {
        keys
    } else {
        keys.into_iter().filter(|k| k.is_valid()).collect()
    };

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
        "{:<6} {:<12} {:<20} {:<6} {:<20} {}",
        "ID", "PREFIX", "NAME", "USER", "EXPIRES", "LAST USED"
    );
    println!("{}", "-".repeat(90));

    for key in keys {
        let prefix = format!("{}...", key.prefix());

        let expires = key
            .expiration
            .map(|e: chrono::DateTime<chrono::Utc>| e.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        let last_used = key
            .last_used_at
            .map(|e: chrono::DateTime<chrono::Utc>| e.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        let name = if key.name.len() > 18 {
            format!("{}...", &key.name[..15])
        } else {
            key.name.clone()
        };

        println!(
            "{:<6} {:<12} {:<20} {:<6} {:<20} {}",
            key.id, prefix, name, key.user_id.0, expires, last_used
        );
    }

    Ok(())
}

async fn delete_key(args: DeleteArgs) -> Result<()> {
    let db = args.db.connect().await?;

    db.delete_api_key(args.key_id)
        .await
        .context("failed to delete API key")?;

    println!("Deleted API key {}", args.key_id);

    Ok(())
}

async fn expire_key(args: ExpireArgs) -> Result<()> {
    let db = args.db.connect().await?;

    db.expire_api_key(args.key_id)
        .await
        .context("failed to expire API key")?;

    println!("Expired API key {}", args.key_id);

    Ok(())
}
