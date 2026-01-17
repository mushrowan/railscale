//! the `preauthkeys` subcommand - manage preauth keys

use chrono::{Duration, Utc};
use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result, bail};
use railscale_db::{Database, RailscaleDb};
use railscale_types::{Config, PreAuthKey, UserId};

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

/// common database arguments
#[derive(Args, Debug, Clone)]
pub struct DbArgs {
    /// database url (sqlite:// or postgres://)
    #[arg(long, env = "RAILSCALE_DATABASE_URL")]
    database_url: Option<String>,
}

impl DbArgs {
    async fn connect(&self) -> Result<RailscaleDb> {
        let config = self.to_config()?;
        RailscaleDb::new(&config)
            .await
            .context("failed to connect to database")
    }

    fn to_config(&self) -> Result<Config> {
        let database = if let Some(db_url) = &self.database_url {
            if db_url.starts_with("postgres://") {
                railscale_types::DatabaseConfig {
                    db_type: "postgres".to_string(),
                    connection_string: db_url.clone(),
                }
            } else if let Some(path) = db_url.strip_prefix("sqlite://") {
                railscale_types::DatabaseConfig {
                    db_type: "sqlite".to_string(),
                    connection_string: path.to_string(),
                }
            } else {
                bail!("database URL must start with sqlite:// or postgres://");
            }
        } else {
            railscale_types::DatabaseConfig::default()
        };

        Ok(Config {
            database,
            ..Default::default()
        })
    }
}

/// create a new preauth key
#[derive(Args, Debug)]
pub struct CreateArgs {
    #[command(flatten)]
    db: DbArgs,

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

/// delete a preauth key
#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[command(flatten)]
    db: DbArgs,

    /// key id to delete
    key_id: u64,
}

/// expire a preauth key
#[derive(Args, Debug)]
pub struct ExpireArgs {
    #[command(flatten)]
    db: DbArgs,

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

    // normalize tags (ensure they have tag: prefix)
    let tags: Vec<String> = args
        .tags
        .iter()
        .map(|t| {
            if t.starts_with("tag:") {
                t.clone()
            } else {
                format!("tag:{}", t)
            }
        })
        .collect();

    let now = Utc::now();
    let expiration = now + Duration::days(args.expiration_days);

    // generate a random key
    let key_string = generate_preauth_key();

    let mut key = PreAuthKey::new(0, key_string, UserId(args.user));
    key.reusable = args.reusable;
    key.ephemeral = args.ephemeral;
    key.expiration = Some(expiration);
    key.tags = tags;

    let created = db
        .create_preauth_key(&key)
        .await
        .context("failed to create preauth key")?;

    println!("Created preauth key:");
    println!("  Key:       {}", created.key);
    println!("  User:      {}", created.user_id.0);
    println!("  Reusable:  {}", created.reusable);
    println!("  Ephemeral: {}", created.ephemeral);
    println!(
        "  Expires:   {}",
        created
            .expiration
            .map(|e| e.to_rfc3339())
            .unwrap_or_else(|| "never".to_string())
    );
    if !created.tags.is_empty() {
        println!("  Tags:      {}", created.tags.join(", "));
    }

    Ok(())
}

/// generate a random preauth key string
fn generate_preauth_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const KEY_LEN: usize = 48;

    let mut rng = rand::rng();
    (0..KEY_LEN)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

async fn list_keys(args: ListArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let keys = if let Some(user_id) = args.user {
        db.list_preauth_keys(UserId(user_id))
            .await
            .context("failed to list preauth keys")?
    } else {
        db.get_all_preauth_keys()
            .await
            .context("failed to list preauth keys")?
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
        println!("No preauth keys found.");
        return Ok(());
    }

    println!(
        "{:<6} {:<12} {:<6} {:<8} {:<8} {:<20} {}",
        "ID", "KEY", "USER", "REUSABLE", "USED", "EXPIRES", "TAGS"
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
            .map(|e: chrono::DateTime<chrono::Utc>| e.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        let tags = if key.tags.is_empty() {
            "-".to_string()
        } else {
            key.tags.join(", ")
        };

        println!(
            "{:<6} {:<12} {:<6} {:<8} {:<8} {:<20} {}",
            key.id,
            key_preview,
            key.user_id.0,
            if key.reusable { "yes" } else { "no" },
            if key.used { "yes" } else { "no" },
            expires,
            tags
        );
    }

    Ok(())
}

async fn delete_key(args: DeleteArgs) -> Result<()> {
    let db = args.db.connect().await?;

    db.delete_preauth_key(args.key_id)
        .await
        .context("failed to delete preauth key")?;

    println!("Deleted preauth key {}", args.key_id);

    Ok(())
}

async fn expire_key(args: ExpireArgs) -> Result<()> {
    let db = args.db.connect().await?;

    db.expire_preauth_key(args.key_id)
        .await
        .context("failed to expire preauth key")?;

    println!("Expired preauth key {}", args.key_id);

    Ok(())
}
