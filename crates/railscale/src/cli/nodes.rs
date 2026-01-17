//! the `nodes` subcommand - manage nodes

use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result, bail};
use railscale_db::Database;
use railscale_types::{NodeId, UserId};

use super::preauthkeys::DbArgs;

/// manage nodes
#[derive(Subcommand, Debug)]
pub enum NodesCommand {
    /// list all nodes
    List(ListNodesArgs),

    /// show details for a node
    Show(ShowNodeArgs),

    /// delete a node
    Delete(DeleteNodeArgs),

    /// expire a node's registration
    Expire(ExpireNodeArgs),

    /// rename a node
    Rename(RenameNodeArgs),

    /// manage node tags
    #[command(subcommand)]
    Tags(TagsCommand),

    /// manage approved routes
    #[command(subcommand)]
    Routes(RoutesCommand),
}

/// list nodes
#[derive(Args, Debug)]
pub struct ListNodesArgs {
    #[command(flatten)]
    db: DbArgs,

    /// filter by user id
    #[arg(short, long)]
    user: Option<u64>,

    /// show only online nodes
    #[arg(long)]
    online: bool,

    /// output format (table, json)
    #[arg(short, long, default_value = "table")]
    output: String,
}

/// show node details
#[derive(Args, Debug)]
pub struct ShowNodeArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id
    node_id: u64,

    /// output format (table, json)
    #[arg(short, long, default_value = "table")]
    output: String,
}

/// delete a node
#[derive(Args, Debug)]
pub struct DeleteNodeArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id to delete
    node_id: u64,
}

/// expire a node's registration
#[derive(Args, Debug)]
pub struct ExpireNodeArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id to expire
    node_id: u64,
}

/// rename a node
#[derive(Args, Debug)]
pub struct RenameNodeArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id to rename
    node_id: u64,

    /// new name (given_name)
    new_name: String,
}

/// manage node tags
#[derive(Subcommand, Debug)]
pub enum TagsCommand {
    /// add tags to a node
    Add(AddTagsArgs),

    /// remove tags from a node
    Remove(RemoveTagsArgs),

    /// set tags (replaces all existing tags)
    Set(SetTagsArgs),
}

/// add tags to a node
#[derive(Args, Debug)]
pub struct AddTagsArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id
    node_id: u64,

    /// tags to add (comma-separated)
    #[arg(value_delimiter = ',')]
    tags: Vec<String>,
}

/// remove tags from a node
#[derive(Args, Debug)]
pub struct RemoveTagsArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id
    node_id: u64,

    /// tags to remove (comma-separated)
    #[arg(value_delimiter = ',')]
    tags: Vec<String>,
}

/// set tags on a node (replaces all)
#[derive(Args, Debug)]
pub struct SetTagsArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id
    node_id: u64,

    /// tags to set (comma-separated)
    #[arg(value_delimiter = ',')]
    tags: Vec<String>,
}

/// manage approved routes
#[derive(Subcommand, Debug)]
pub enum RoutesCommand {
    /// list approved routes for a node
    List(ListRoutesArgs),

    /// approve routes for a node
    Approve(ApproveRoutesArgs),

    /// unapprove routes for a node
    Unapprove(UnapproveRoutesArgs),
}

/// list routes for a node
#[derive(Args, Debug)]
pub struct ListRoutesArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id
    node_id: u64,
}

/// approve routes for a node
#[derive(Args, Debug)]
pub struct ApproveRoutesArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id
    node_id: u64,

    /// routes to approve (cidr notation, comma-separated)
    #[arg(value_delimiter = ',')]
    routes: Vec<String>,
}

/// unapprove routes for a node
#[derive(Args, Debug)]
pub struct UnapproveRoutesArgs {
    #[command(flatten)]
    db: DbArgs,

    /// node id
    node_id: u64,

    /// routes to unapprove (cidr notation, comma-separated)
    #[arg(value_delimiter = ',')]
    routes: Vec<String>,
}

impl NodesCommand {
    /// run the nodes command
    pub async fn run(self) -> Result<()> {
        match self {
            NodesCommand::List(args) => list_nodes(args).await,
            NodesCommand::Show(args) => show_node(args).await,
            NodesCommand::Delete(args) => delete_node(args).await,
            NodesCommand::Expire(args) => expire_node(args).await,
            NodesCommand::Rename(args) => rename_node(args).await,
            NodesCommand::Tags(cmd) => match cmd {
                TagsCommand::Add(args) => add_tags(args).await,
                TagsCommand::Remove(args) => remove_tags(args).await,
                TagsCommand::Set(args) => set_tags(args).await,
            },
            NodesCommand::Routes(cmd) => match cmd {
                RoutesCommand::List(args) => list_routes(args).await,
                RoutesCommand::Approve(args) => approve_routes(args).await,
                RoutesCommand::Unapprove(args) => unapprove_routes(args).await,
            },
        }
    }
}

async fn list_nodes(args: ListNodesArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let nodes = if let Some(user_id) = args.user {
        db.list_nodes_for_user(UserId(user_id))
            .await
            .context("failed to list nodes")?
    } else {
        db.list_nodes().await.context("failed to list nodes")?
    };

    // filter online if requested
    let nodes: Vec<_> = if args.online {
        nodes
            .into_iter()
            .filter(|n| n.is_online == Some(true))
            .collect()
    } else {
        nodes
    };

    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&nodes)?);
        return Ok(());
    }

    // table output
    if nodes.is_empty() {
        println!("No nodes found.");
        return Ok(());
    }

    println!(
        "{:<6} {:<20} {:<16} {:<8} {:<10} {}",
        "ID", "NAME", "IPv4", "USER", "ONLINE", "TAGS"
    );
    println!("{}", "-".repeat(80));

    for node in nodes {
        let ipv4 = node
            .ipv4
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "-".to_string());

        let user = node
            .user_id
            .map(|u| u.0.to_string())
            .unwrap_or_else(|| "-".to_string());

        let online = match node.is_online {
            Some(true) => "yes",
            Some(false) => "no",
            None => "-",
        };

        let tags = if node.tags.is_empty() {
            "-".to_string()
        } else {
            node.tags.join(", ")
        };

        println!(
            "{:<6} {:<20} {:<16} {:<8} {:<10} {}",
            node.id.0, node.given_name, ipv4, user, online, tags
        );
    }

    Ok(())
}

async fn show_node(args: ShowNodeArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to get node")?;

    let Some(node) = node else {
        bail!("node {} not found", args.node_id);
    };

    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&node)?);
        return Ok(());
    }

    println!("Node Details:");
    println!("  ID:              {}", node.id.0);
    println!("  Hostname:        {}", node.hostname);
    println!("  Given Name:      {}", node.given_name);
    println!(
        "  IPv4:            {}",
        node.ipv4.map(|ip| ip.to_string()).unwrap_or("-".into())
    );
    println!(
        "  IPv6:            {}",
        node.ipv6.map(|ip| ip.to_string()).unwrap_or("-".into())
    );
    println!(
        "  User:            {}",
        node.user_id.map(|u| u.0.to_string()).unwrap_or("-".into())
    );
    println!("  Register Method: {:?}", node.register_method);
    println!(
        "  Online:          {}",
        match node.is_online {
            Some(true) => "yes",
            Some(false) => "no",
            None => "-",
        }
    );
    println!(
        "  Last Seen:       {}",
        node.last_seen.map(|t| t.to_rfc3339()).unwrap_or("-".into())
    );
    println!(
        "  Expiry:          {}",
        node.expiry
            .map(|t| t.to_rfc3339())
            .unwrap_or("never".into())
    );
    println!("  Created:         {}", node.created_at.to_rfc3339());
    println!("  Updated:         {}", node.updated_at.to_rfc3339());

    if !node.tags.is_empty() {
        println!("  Tags:            {}", node.tags.join(", "));
    }

    if !node.approved_routes.is_empty() {
        println!("  Approved Routes:");
        for route in &node.approved_routes {
            println!("    - {}", route);
        }
    }

    if !node.endpoints.is_empty() {
        println!("  Endpoints:");
        for endpoint in &node.endpoints {
            println!("    - {}", endpoint);
        }
    }

    Ok(())
}

async fn delete_node(args: DeleteNodeArgs) -> Result<()> {
    let db = args.db.connect().await?;

    // check if node exists
    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    if node.is_none() {
        bail!("node {} not found", args.node_id);
    }

    db.delete_node(NodeId(args.node_id))
        .await
        .context("failed to delete node")?;

    println!("Deleted node {}", args.node_id);

    Ok(())
}

async fn expire_node(args: ExpireNodeArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    let Some(mut node) = node else {
        bail!("node {} not found", args.node_id);
    };

    node.expiry = Some(chrono::Utc::now());

    db.update_node(&node)
        .await
        .context("failed to update node")?;

    println!("Expired node {}", args.node_id);

    Ok(())
}

async fn rename_node(args: RenameNodeArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    let Some(mut node) = node else {
        bail!("node {} not found", args.node_id);
    };

    let old_name = node.given_name.clone();
    node.given_name = args.new_name.clone();

    db.update_node(&node)
        .await
        .context("failed to update node")?;

    println!(
        "Renamed node {} from '{}' to '{}'",
        args.node_id, old_name, args.new_name
    );

    Ok(())
}

/// normalize tag to have tag: prefix
fn normalize_tag(tag: &str) -> String {
    if tag.starts_with("tag:") {
        tag.to_string()
    } else {
        format!("tag:{}", tag)
    }
}

async fn add_tags(args: AddTagsArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    let Some(mut node) = node else {
        bail!("node {} not found", args.node_id);
    };

    for tag in args.tags {
        let normalized = normalize_tag(&tag);
        if !node.tags.contains(&normalized) {
            node.tags.push(normalized);
        }
    }

    db.update_node(&node)
        .await
        .context("failed to update node")?;

    println!("Tags for node {}: {}", args.node_id, node.tags.join(", "));

    Ok(())
}

async fn remove_tags(args: RemoveTagsArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    let Some(mut node) = node else {
        bail!("node {} not found", args.node_id);
    };

    let tags_to_remove: Vec<String> = args.tags.iter().map(|t| normalize_tag(t)).collect();
    node.tags.retain(|t| !tags_to_remove.contains(t));

    db.update_node(&node)
        .await
        .context("failed to update node")?;

    if node.tags.is_empty() {
        println!("Node {} now has no tags", args.node_id);
    } else {
        println!("Tags for node {}: {}", args.node_id, node.tags.join(", "));
    }

    Ok(())
}

async fn set_tags(args: SetTagsArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    let Some(mut node) = node else {
        bail!("node {} not found", args.node_id);
    };

    node.tags = args.tags.iter().map(|t| normalize_tag(t)).collect();

    db.update_node(&node)
        .await
        .context("failed to update node")?;

    if node.tags.is_empty() {
        println!("Node {} now has no tags", args.node_id);
    } else {
        println!("Tags for node {}: {}", args.node_id, node.tags.join(", "));
    }

    Ok(())
}

async fn list_routes(args: ListRoutesArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    let Some(node) = node else {
        bail!("node {} not found", args.node_id);
    };

    if node.approved_routes.is_empty() {
        println!("Node {} has no approved routes", args.node_id);
    } else {
        println!("Approved routes for node {}:", args.node_id);
        for route in &node.approved_routes {
            println!("  {}", route);
        }
    }

    Ok(())
}

async fn approve_routes(args: ApproveRoutesArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    let Some(mut node) = node else {
        bail!("node {} not found", args.node_id);
    };

    for route in args.routes {
        // parse and validate cidr format
        let parsed: ipnet::IpNet = route
            .parse()
            .map_err(|_| color_eyre::eyre::eyre!("invalid CIDR: {}", route))?;

        if !node.approved_routes.contains(&parsed) {
            node.approved_routes.push(parsed);
        }
    }

    db.update_node(&node)
        .await
        .context("failed to update node")?;

    let routes_str: Vec<String> = node.approved_routes.iter().map(|r| r.to_string()).collect();
    println!(
        "Approved routes for node {}: {}",
        args.node_id,
        routes_str.join(", ")
    );

    Ok(())
}

async fn unapprove_routes(args: UnapproveRoutesArgs) -> Result<()> {
    let db = args.db.connect().await?;

    let node = db
        .get_node(NodeId(args.node_id))
        .await
        .context("failed to query node")?;

    let Some(mut node) = node else {
        bail!("node {} not found", args.node_id);
    };

    // parse the routes to remove
    let routes_to_remove: Vec<ipnet::IpNet> =
        args.routes.iter().filter_map(|r| r.parse().ok()).collect();

    node.approved_routes
        .retain(|r| !routes_to_remove.contains(r));

    db.update_node(&node)
        .await
        .context("failed to update node")?;

    if node.approved_routes.is_empty() {
        println!("Node {} now has no approved routes", args.node_id);
    } else {
        let routes_str: Vec<String> = node.approved_routes.iter().map(|r| r.to_string()).collect();
        println!(
            "Approved routes for node {}: {}",
            args.node_id,
            routes_str.join(", ")
        );
    }

    Ok(())
}
