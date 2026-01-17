//! the `users` subcommand - manage users

use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result, bail};
use railscale_db::Database;
use railscale_types::{User, UserId};

use super::preauthkeys::DbArgs;

/// manage users
#[derive(Subcommand, Debug)]
pub enum UsersCommand {
    /// create a new user
    Create(CreateUserArgs),

    /// list all users
    List(ListUsersArgs),

    /// delete a user
    Delete(DeleteUserArgs),

    /// rename a user
    Rename(RenameUserArgs),
}

/// create a new user
#[derive(Args, Debug)]
pub struct CreateUserArgs {
    #[command(flatten)]
    db: DbArgs,

    /// username
    name: String,

    /// display name (optional)
    #[arg(long)]
    display_name: Option<String>,

    /// email address (optional)
    #[arg(long)]
    email: Option<String>,
}

/// list users
#[derive(Args, Debug)]
pub struct ListUsersArgs {
    #[command(flatten)]
    db: DbArgs,

    /// output format (table, json)
    #[arg(short, long, default_value = "table")]
    output: String,
}

/// delete a user
#[derive(Args, Debug)]
pub struct DeleteUserArgs {
    #[command(flatten)]
    db: DbArgs,

    /// user id to delete
    user_id: u64,

    /// force deletion even if user has nodes
    #[arg(long, default_value_t = false)]
    force: bool,
}

/// rename a user
#[derive(Args, Debug)]
pub struct RenameUserArgs {
    #[command(flatten)]
    db: DbArgs,

    /// user id to rename
    user_id: u64,

    /// new username
    new_name: String,
}

impl UsersCommand {
    /// run the users command
    pub async fn run(self) -> Result<()> {
        match self {
            UsersCommand::Create(args) => create_user(args).await,
            UsersCommand::List(args) => list_users(args).await,
            UsersCommand::Delete(args) => delete_user(args).await,
            UsersCommand::Rename(args) => rename_user(args).await,
        }
    }
}

async fn create_user(args: CreateUserArgs) -> Result<()> {
    let db = args.db.connect().await?;

    // check if user with this name already exists
    if let Some(_existing) = db
        .get_user_by_name(&args.name)
        .await
        .context("failed to check for existing user")?
    {
        bail!("user '{}' already exists", args.name);
    }

    let mut user = User::new(UserId(0), args.name.clone());
    if let Some(display_name) = args.display_name {
        user.display_name = Some(display_name);
    }
    if let Some(email) = args.email {
        user.email = Some(email);
    }

    let created = db
        .create_user(&user)
        .await
        .context("failed to create user")?;

    println!("Created user:");
    println!("  ID:           {}", created.id.0);
    println!("  Name:         {}", created.name);
    if let Some(display_name) = &created.display_name {
        println!("  Display Name: {}", display_name);
    }
    if let Some(email) = &created.email {
        println!("  Email:        {}", email);
    }

    Ok(())
}

async fn list_users(args: ListUsersArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let users = db.list_users().await.context("failed to list users")?;

    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&users)?);
        return Ok(());
    }

    // table output
    if users.is_empty() {
        println!("No users found.");
        return Ok(());
    }

    println!(
        "{:<6} {:<20} {:<25} {:<30}",
        "ID", "NAME", "DISPLAY NAME", "EMAIL"
    );
    println!("{}", "-".repeat(85));

    for user in users {
        println!(
            "{:<6} {:<20} {:<25} {:<30}",
            user.id.0,
            user.name,
            user.display_name.as_deref().unwrap_or("-"),
            user.email.as_deref().unwrap_or("-"),
        );
    }

    Ok(())
}

async fn delete_user(args: DeleteUserArgs) -> Result<()> {
    let db = args.db.connect().await?;

    // check if user exists
    let user = db
        .get_user(UserId(args.user_id))
        .await
        .context("failed to query user")?;

    if user.is_none() {
        bail!("user {} not found", args.user_id);
    }

    // check if user has nodes (unless --force)
    if !args.force {
        let nodes = db
            .list_nodes_for_user(UserId(args.user_id))
            .await
            .context("failed to check for user's nodes")?;

        if !nodes.is_empty() {
            bail!(
                "user {} has {} nodes. Use --force to delete anyway, or delete nodes first.",
                args.user_id,
                nodes.len()
            );
        }
    }

    db.delete_user(UserId(args.user_id))
        .await
        .context("failed to delete user")?;

    println!("Deleted user {}", args.user_id);

    Ok(())
}

async fn rename_user(args: RenameUserArgs) -> Result<()> {
    let db = args.db.connect().await?;

    // check if user exists
    let user = db
        .get_user(UserId(args.user_id))
        .await
        .context("failed to query user")?;

    let Some(mut user) = user else {
        bail!("user {} not found", args.user_id);
    };

    // check if new name is already taken
    if let Some(_existing) = db
        .get_user_by_name(&args.new_name)
        .await
        .context("failed to check for existing user")?
    {
        bail!("user '{}' already exists", args.new_name);
    }

    let old_name = user.name.clone();
    user.name = args.new_name.clone();

    db.update_user(&user)
        .await
        .context("failed to update user")?;

    println!(
        "Renamed user {} from '{}' to '{}'",
        args.user_id, old_name, args.new_name
    );

    Ok(())
}
