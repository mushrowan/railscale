//! the `users` subcommand - manage users via admin socket.

use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result};
use railscale_admin::AdminClient;

use super::SocketArgs;

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
    socket: SocketArgs,

    /// email address (used as username)
    email: String,

    /// display name (optional)
    #[arg(long)]
    display_name: Option<String>,
}

/// list users
#[derive(Args, Debug)]
pub struct ListUsersArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// output format (table, json)
    #[arg(short, long, default_value = "table")]
    output: String,
}

/// delete a user
#[derive(Args, Debug)]
pub struct DeleteUserArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// user id to delete
    user_id: u64,
}

/// rename a user
#[derive(Args, Debug)]
pub struct RenameUserArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// user id to rename
    user_id: u64,

    /// new name
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
    let mut client = AdminClient::connect_unix(&args.socket.socket)
        .await
        .with_context(|| {
            format!(
                "failed to connect to admin socket: {:?}",
                args.socket.socket
            )
        })?;

    let user = client
        .create_user(args.email.clone(), args.display_name.clone())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to create user: {}", e))?;

    println!("Created user:");
    println!("  ID:           {}", user.id);
    println!("  Email:        {}", user.email);
    if !user.display_name.is_empty() {
        println!("  Display Name: {}", user.display_name);
    }

    Ok(())
}

async fn list_users(args: ListUsersArgs) -> Result<()> {
    let mut client = AdminClient::connect_unix(&args.socket.socket)
        .await
        .with_context(|| {
            format!(
                "failed to connect to admin socket: {:?}",
                args.socket.socket
            )
        })?;

    let users = client
        .list_users()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list users: {}", e))?;

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
        "{:<6} {:<30} {:<25} {:<25} {:<20}",
        "ID", "EMAIL", "DISPLAY NAME", "OIDC GROUPS", "CREATED"
    );
    println!("{}", "-".repeat(110));

    for user in users {
        // parse and format created_at
        let created = chrono::DateTime::parse_from_rfc3339(&user.created_at)
            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|_| user.created_at.clone());

        // format oidc groups (truncate if too many)
        let oidc_groups = if user.oidc_groups.is_empty() {
            "-".to_string()
        } else if user.oidc_groups.len() <= 2 {
            user.oidc_groups.join(", ")
        } else {
            format!(
                "{}, +{}",
                user.oidc_groups[..2].join(", "),
                user.oidc_groups.len() - 2
            )
        };

        println!(
            "{:<6} {:<30} {:<25} {:<25} {:<20}",
            user.id,
            user.email,
            if user.display_name.is_empty() {
                "-"
            } else {
                &user.display_name
            },
            oidc_groups,
            created,
        );
    }

    Ok(())
}

async fn delete_user(args: DeleteUserArgs) -> Result<()> {
    let mut client = AdminClient::connect_unix(&args.socket.socket)
        .await
        .with_context(|| {
            format!(
                "failed to connect to admin socket: {:?}",
                args.socket.socket
            )
        })?;

    client
        .delete_user(args.user_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to delete user: {}", e))?;

    println!("Deleted user {}", args.user_id);

    Ok(())
}

async fn rename_user(args: RenameUserArgs) -> Result<()> {
    let mut client = AdminClient::connect_unix(&args.socket.socket)
        .await
        .with_context(|| {
            format!(
                "failed to connect to admin socket: {:?}",
                args.socket.socket
            )
        })?;

    let user = client
        .rename_user(args.user_id, args.new_name.clone())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to rename user: {}", e))?;

    println!("Renamed user {} to '{}'", user.id, args.new_name);

    Ok(())
}
