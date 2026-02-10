//! the `nodes` subcommand - manage nodes via admin socket

use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result};
use railscale_admin::AdminClient;

use super::SocketArgs;

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
    socket: SocketArgs,

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
    socket: SocketArgs,

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
    socket: SocketArgs,

    /// node id to delete
    node_id: u64,
}

/// expire a node's registration
#[derive(Args, Debug)]
pub struct ExpireNodeArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// node id to expire
    node_id: u64,
}

/// rename a node
#[derive(Args, Debug)]
pub struct RenameNodeArgs {
    #[command(flatten)]
    socket: SocketArgs,

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
    socket: SocketArgs,

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
    socket: SocketArgs,

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
    socket: SocketArgs,

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
    socket: SocketArgs,

    /// node id
    node_id: u64,
}

/// approve routes for a node
#[derive(Args, Debug)]
pub struct ApproveRoutesArgs {
    #[command(flatten)]
    socket: SocketArgs,

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
    socket: SocketArgs,

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

async fn connect_client(socket: &SocketArgs) -> Result<AdminClient> {
    AdminClient::connect_unix(&socket.socket)
        .await
        .with_context(|| format!("failed to connect to admin socket: {:?}", socket.socket))
}

async fn list_nodes(args: ListNodesArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let nodes = client
        .list_nodes(args.user, None)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list nodes: {}", e))?;

    // filter online if requested
    let nodes: Vec<_> = if args.online {
        nodes.into_iter().filter(|n| n.online).collect()
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
        "{:<6} {:<20} {:<16} {:<8} {:<10} TAGS",
        "ID", "NAME", "IPv4", "USER", "ONLINE"
    );
    println!("{}", "-".repeat(80));

    for node in nodes {
        let ipv4 = node.ipv4.as_deref().unwrap_or("-");

        let user = node
            .user_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".to_string());

        let online = if node.online { "yes" } else { "no" };

        let tags = if node.tags.is_empty() {
            "-".to_string()
        } else {
            node.tags.join(", ")
        };

        println!(
            "{:<6} {:<20} {:<16} {:<8} {:<10} {}",
            node.id, node.given_name, ipv4, user, online, tags
        );
    }

    Ok(())
}

async fn show_node(args: ShowNodeArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let node = client
        .get_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get node: {}", e))?;

    if args.output == "json" {
        println!("{}", serde_json::to_string_pretty(&node)?);
        return Ok(());
    }

    println!("Node Details:");
    println!("  ID:              {}", node.id);
    println!("  Hostname:        {}", node.hostname);
    println!("  Given Name:      {}", node.given_name);
    println!("  IPv4:            {}", node.ipv4.as_deref().unwrap_or("-"));
    println!("  IPv6:            {}", node.ipv6.as_deref().unwrap_or("-"));
    println!(
        "  User:            {}",
        node.user_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!(
        "  Online:          {}",
        if node.online { "yes" } else { "no" }
    );
    println!(
        "  Last Seen:       {}",
        node.last_seen.as_deref().unwrap_or("-")
    );
    println!(
        "  Expiry:          {}",
        node.expiry.as_deref().unwrap_or("never")
    );
    println!("  Created:         {}", node.created_at);

    if !node.tags.is_empty() {
        println!("  Tags:            {}", node.tags.join(", "));
    }

    if !node.approved_routes.is_empty() {
        println!("  Approved Routes:");
        for route in &node.approved_routes {
            println!("    - {}", route);
        }
    }

    Ok(())
}

async fn delete_node(args: DeleteNodeArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    client
        .delete_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to delete node: {}", e))?;

    println!("Deleted node {}", args.node_id);

    Ok(())
}

async fn expire_node(args: ExpireNodeArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    client
        .expire_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to expire node: {}", e))?;

    println!("Expired node {}", args.node_id);

    Ok(())
}

async fn rename_node(args: RenameNodeArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let node = client
        .rename_node(args.node_id, args.new_name.clone())
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to rename node: {}", e))?;

    println!("Renamed node {} to '{}'", args.node_id, node.given_name);

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
    let mut client = connect_client(&args.socket).await?;

    // merge tags
    let node = client
        .get_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get node: {}", e))?;

    // merge tags
    let mut tags = node.tags;
    for tag in args.tags {
        let normalized = normalize_tag(&tag);
        if !tags.contains(&normalized) {
            tags.push(normalized);
        }
    }

    // set merged tags
    let node = client
        .set_tags(args.node_id, tags)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to set tags: {}", e))?;

    println!("Tags for node {}: {}", args.node_id, node.tags.join(", "));

    Ok(())
}

async fn remove_tags(args: RemoveTagsArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    // remove specified tags
    let node = client
        .get_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get node: {}", e))?;

    // remove specified tags
    let tags_to_remove: Vec<String> = args.tags.iter().map(|t| normalize_tag(t)).collect();
    let tags: Vec<String> = node
        .tags
        .into_iter()
        .filter(|t| !tags_to_remove.contains(t))
        .collect();

    // set filtered tags
    let node = client
        .set_tags(args.node_id, tags)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to set tags: {}", e))?;

    if node.tags.is_empty() {
        println!("Node {} now has no tags", args.node_id);
    } else {
        println!("Tags for node {}: {}", args.node_id, node.tags.join(", "));
    }

    Ok(())
}

async fn set_tags(args: SetTagsArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let tags: Vec<String> = args.tags.iter().map(|t| normalize_tag(t)).collect();

    let node = client
        .set_tags(args.node_id, tags)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to set tags: {}", e))?;

    if node.tags.is_empty() {
        println!("Node {} now has no tags", args.node_id);
    } else {
        println!("Tags for node {}: {}", args.node_id, node.tags.join(", "));
    }

    Ok(())
}

async fn list_routes(args: ListRoutesArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let node = client
        .get_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get node: {}", e))?;

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
    let mut client = connect_client(&args.socket).await?;

    // merge routes (validate cidr format)
    let node = client
        .get_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get node: {}", e))?;

    // set merged routes
    let mut routes = node.approved_routes;
    for route in args.routes {
        // validate cidr format
        let _: ipnet::IpNet = route
            .parse()
            .map_err(|_| color_eyre::eyre::eyre!("invalid CIDR: {}", route))?;

        if !routes.contains(&route) {
            routes.push(route);
        }
    }

    // set merged routes
    let node = client
        .set_approved_routes(args.node_id, routes)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to set routes: {}", e))?;

    println!(
        "Approved routes for node {}: {}",
        args.node_id,
        node.approved_routes.join(", ")
    );

    Ok(())
}

async fn unapprove_routes(args: UnapproveRoutesArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    // get current routes
    let node = client
        .get_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get node: {}", e))?;

    // parse routes to remove (ignore invalid ones)
    let routes_to_remove: Vec<String> = args
        .routes
        .iter()
        .filter(|r| r.parse::<ipnet::IpNet>().is_ok())
        .cloned()
        .collect();

    // filter out removed routes
    let routes: Vec<String> = node
        .approved_routes
        .into_iter()
        .filter(|r| !routes_to_remove.contains(r))
        .collect();

    // set filtered routes
    let node = client
        .set_approved_routes(args.node_id, routes)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to set routes: {}", e))?;

    if node.approved_routes.is_empty() {
        println!("Node {} now has no approved routes", args.node_id);
    } else {
        println!(
            "Approved routes for node {}: {}",
            args.node_id,
            node.approved_routes.join(", ")
        );
    }

    Ok(())
}
