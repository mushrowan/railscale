//! headscale to railscale migration tool
//!
//! reads a headscale sqlite database, config.yaml, and acl.json,
//! then outputs railscale config.toml and policy.json

use std::path::{Path, PathBuf};

use clap::Parser;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;

use railscale_migrate::{config, headscale_acl, nodes, users};

#[derive(Parser)]
#[command(
    name = "railscale-migrate",
    about = "migrate from headscale to railscale"
)]
struct Cli {
    /// path to headscale sqlite database
    #[arg(long)]
    db: PathBuf,

    /// path to headscale config.yaml
    #[arg(long)]
    config: PathBuf,

    /// path to headscale acl.json
    #[arg(long)]
    acl: PathBuf,

    /// output directory for generated files
    #[arg(long, default_value = ".")]
    output: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let acl: headscale_acl::HeadscaleAcl =
        serde_json::from_str(&std::fs::read_to_string(&cli.acl)?)?;
    let hs_config: config::HeadscaleConfig =
        serde_yaml::from_str(&std::fs::read_to_string(&cli.config)?)?;

    // convert policy
    let acl_result = headscale_acl::convert(&acl);
    for w in &acl_result.warnings {
        eprintln!("warning: [{}] {}", w.context, w.message);
    }

    // convert config
    let rs_config = config::convert_config(&hs_config);

    // read and convert users + nodes from sqlite
    let opts = SqliteConnectOptions::new()
        .filename(&cli.db)
        .read_only(true);
    let pool = SqlitePool::connect_with(opts).await?;

    let hs_users: Vec<users::HeadscaleUser> =
        sqlx::query_as("SELECT * FROM users WHERE deleted_at IS NULL")
            .fetch_all(&pool)
            .await?;

    let hs_nodes: Vec<nodes::HeadscaleNode> =
        sqlx::query_as("SELECT * FROM nodes WHERE deleted_at IS NULL")
            .fetch_all(&pool)
            .await?;

    pool.close().await;

    let rs_users: Vec<_> = hs_users.iter().map(users::convert_user).collect();

    let mut rs_nodes = Vec::new();
    let mut node_errors = 0;
    for hs in &hs_nodes {
        match nodes::convert_node(hs) {
            Ok(node) => rs_nodes.push(node),
            Err(e) => {
                eprintln!("warning: node {}: {e}", hs.hostname);
                node_errors += 1;
            }
        }
    }

    // write output
    std::fs::create_dir_all(&cli.output)?;

    write_json(&cli.output.join("policy.json"), &acl_result.policy)?;
    write_file(
        &cli.output.join("config.toml"),
        &toml::to_string_pretty(&rs_config)?,
    )?;
    write_json(&cli.output.join("users.json"), &rs_users)?;
    write_json(&cli.output.join("nodes.json"), &rs_nodes)?;

    // summary
    eprintln!();
    eprintln!("  {} users", rs_users.len());
    eprintln!("  {} nodes ({node_errors} errors)", rs_nodes.len());
    eprintln!("  {} grants", acl_result.policy.grants.len());
    eprintln!("  {} ssh rules", acl_result.policy.ssh.len());
    eprintln!("  {} host aliases", acl_result.policy.hosts.len());

    if !acl_result.policy.hosts.is_empty() {
        eprintln!();
        for (name, ip) in &acl_result.policy.hosts {
            eprintln!("  host:{name} -> {ip}");
        }
    }

    eprintln!();
    eprintln!("next steps:");
    eprintln!("  1. review config.toml (set oidc client_secret, noise key path)");
    eprintln!("  2. review policy.json");
    eprintln!("  3. start railscale, re-register nodes");

    Ok(())
}

fn write_json(
    path: &Path,
    value: &impl serde::Serialize,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(value)?;
    write_file(path, &json)
}

fn write_file(path: &Path, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, content)?;
    eprintln!("wrote {}", path.display());
    Ok(())
}
