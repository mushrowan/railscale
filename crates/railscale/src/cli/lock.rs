//! the `lock` subcommand - manage tailnet lock (TKA) via admin socket

use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Args, Subcommand};
use color_eyre::eyre::{Context, Result, bail};
use railscale_admin::AdminClient;
use railscale_tka::{
    Aum, AumKind, DisablementSecret, Key, KeyKind, NlPrivateKey, NodeKeySignature, TkaKeyId,
};

use super::SocketArgs;

/// manage tailnet lock (TKA)
#[derive(Subcommand, Debug)]
pub enum LockCommand {
    /// initialise tailnet lock
    Init(InitArgs),

    /// show tailnet lock status
    Status(StatusArgs),

    /// sign a node's key
    Sign(SignArgs),

    /// disable tailnet lock
    Disable(DisableArgs),
}

/// initialise tailnet lock
#[derive(Args, Debug)]
pub struct InitArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// skip confirmation prompt
    #[arg(long, short = 'f')]
    force: bool,

    /// write private key to file instead of stdout
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// number of disablement secrets to generate (default: 1)
    #[arg(long, default_value_t = 1)]
    disablement_secrets: usize,
}

/// show tailnet lock status
#[derive(Args, Debug)]
pub struct StatusArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// output format (table, json)
    #[arg(short, long, default_value = "table")]
    output: String,
}

/// sign a node's key
#[derive(Args, Debug)]
pub struct SignArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// node ID to sign
    node_id: u64,

    /// private key (nlpriv:hex format)
    #[arg(long, short = 'k', conflicts_with = "key_file")]
    key: Option<String>,

    /// file containing the private key
    #[arg(long, short = 'K')]
    key_file: Option<PathBuf>,
}

/// disable tailnet lock
#[derive(Args, Debug)]
pub struct DisableArgs {
    #[command(flatten)]
    socket: SocketArgs,

    /// disablement secret (hex format)
    secret: String,
}

impl LockCommand {
    /// run the lock command
    pub async fn run(self) -> Result<()> {
        match self {
            LockCommand::Init(args) => init(args).await,
            LockCommand::Status(args) => status(args).await,
            LockCommand::Sign(args) => sign(args).await,
            LockCommand::Disable(args) => disable(args).await,
        }
    }
}

async fn connect_client(socket: &SocketArgs) -> Result<AdminClient> {
    AdminClient::connect_unix(&socket.socket)
        .await
        .with_context(|| format!("failed to connect to admin socket: {:?}", socket.socket))
}

async fn init(args: InitArgs) -> Result<()> {
    // confirmation prompt unless --force
    if !args.force {
        print!("This will initialise tailnet lock. Continue? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // generate NL keypair
    let nl_private = NlPrivateKey::generate();
    let nl_public = nl_private.public_key();

    // create genesis AUM (AddKey with the new key)
    let key = Key {
        kind: KeyKind::Ed25519,
        votes: 1,
        public: nl_public.as_bytes().to_vec(),
        meta: None,
    };

    let genesis = Aum {
        message_kind: AumKind::AddKey,
        prev_aum_hash: None, // genesis has no parent
        key: Some(key),
        key_id: None,
        state: None,
        votes: None,
        meta: None,
        signatures: vec![],
    };

    let genesis_bytes = genesis
        .to_cbor()
        .map_err(|e| color_eyre::eyre::eyre!("failed to encode genesis AUM: {}", e))?;

    // generate disablement secrets
    let mut disablement_secrets = Vec::new();
    let mut raw_secrets = Vec::new();

    for _ in 0..args.disablement_secrets {
        let secret = DisablementSecret::generate();
        disablement_secrets.push(secret.hash().to_vec());
        // we need to keep the raw secret to show the user
        raw_secrets.push(rand::random::<[u8; 32]>());
    }

    // regenerate with stored raw bytes so we can show them
    disablement_secrets.clear();
    let mut display_secrets = Vec::new();
    for raw in &raw_secrets {
        let secret = DisablementSecret::from(*raw);
        disablement_secrets.push(secret.hash().to_vec());
        display_secrets.push(hex::encode(raw));
    }

    // connect to admin socket
    let mut client = connect_client(&args.socket).await?;

    // get list of nodes to sign
    let nodes = client
        .list_nodes(None, None)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to list nodes: {}", e))?;

    // get TKA key ID from public key
    let tka_key_id = TkaKeyId::from(&nl_public);

    // create signatures for all existing nodes
    let mut signatures = Vec::new();
    for node in &nodes {
        // decode node key from hex
        let node_key_bytes = hex::decode(&node.node_key)
            .map_err(|e| color_eyre::eyre::eyre!("invalid node key hex: {}", e))?;

        // create node key signature
        let sig = NodeKeySignature::sign_direct(&node_key_bytes, &tka_key_id, &nl_private)
            .map_err(|e| color_eyre::eyre::eyre!("failed to sign node key: {}", e))?;

        let sig_bytes = sig
            .to_cbor()
            .map_err(|e| color_eyre::eyre::eyre!("failed to encode signature: {}", e))?;

        signatures.push(railscale_admin::pb::TkaNodeSignature {
            node_id: node.id,
            signature: sig_bytes,
        });
    }

    // call init
    let response = client
        .tka_init(genesis_bytes, disablement_secrets, signatures)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to initialise TKA: {}", e))?;

    if !response.success {
        bail!("TKA initialisation failed: {}", response.message);
    }

    // output the private key
    let private_key_hex = format!("nlpriv:{}", hex::encode(nl_private.to_seed()));

    if let Some(ref output_path) = args.output {
        std::fs::write(output_path, &private_key_hex)
            .with_context(|| format!("failed to write key to {:?}", output_path))?;

        // set restrictive permissions on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(output_path, perms)?;
        }

        println!("Tailnet lock initialised successfully");
        println!("Private key written to: {:?}", output_path);
    } else {
        println!("Tailnet lock initialised successfully");
        println!();
        println!("Private key (save this securely):");
        println!("  {}", private_key_hex);
    }

    println!();
    println!("Nodes signed: {}", response.nodes_signed);

    if !display_secrets.is_empty() {
        println!();
        println!("Disablement secrets (save these securely):");
        for (i, secret) in display_secrets.iter().enumerate() {
            println!("  {}: {}", i + 1, secret);
        }
    }

    Ok(())
}

async fn status(args: StatusArgs) -> Result<()> {
    let mut client = connect_client(&args.socket).await?;

    let status = client
        .tka_get_status()
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get TKA status: {}", e))?;

    if args.output == "json" {
        // manual JSON since protobuf types don't impl Serialize
        let json = serde_json::json!({
            "enabled": status.enabled,
            "head": status.head,
            "keys": status.keys.iter().map(|k| serde_json::json!({
                "key_id": k.key_id,
                "votes": k.votes,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    // table output
    if !status.enabled {
        println!("Tailnet lock: disabled");
        return Ok(());
    }

    println!("Tailnet lock: enabled");
    if let Some(ref head) = status.head {
        println!("Head: {}", head);
    }

    if !status.keys.is_empty() {
        println!();
        println!("Trusted keys:");
        println!("{:<66} VOTES", "KEY ID");
        println!("{}", "-".repeat(72));
        for key in &status.keys {
            println!("{:<66} {}", key.key_id, key.votes);
        }
    }

    Ok(())
}

async fn sign(args: SignArgs) -> Result<()> {
    // load private key
    let key_str = if let Some(ref key) = args.key {
        key.clone()
    } else if let Some(ref key_file) = args.key_file {
        std::fs::read_to_string(key_file)
            .with_context(|| format!("failed to read key file: {:?}", key_file))?
            .trim()
            .to_string()
    } else {
        bail!("must provide --key or --key-file");
    };

    // parse nlpriv:hex format
    let key_hex = key_str
        .strip_prefix("nlpriv:")
        .ok_or_else(|| color_eyre::eyre::eyre!("key must start with 'nlpriv:'"))?;

    let key_bytes =
        hex::decode(key_hex).map_err(|e| color_eyre::eyre::eyre!("invalid key hex: {}", e))?;

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| color_eyre::eyre::eyre!("key must be 32 bytes"))?;

    let nl_private = NlPrivateKey::from_seed(key_array);

    let mut client = connect_client(&args.socket).await?;

    // get node to sign
    let node = client
        .get_node(args.node_id)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to get node: {}", e))?;

    // decode node key from hex
    let node_key_bytes = hex::decode(&node.node_key)
        .map_err(|e| color_eyre::eyre::eyre!("invalid node key hex: {}", e))?;

    // get TKA key ID from public key
    let tka_key_id = TkaKeyId::from(&nl_private.public_key());

    // create signature
    let sig = NodeKeySignature::sign_direct(&node_key_bytes, &tka_key_id, &nl_private)
        .map_err(|e| color_eyre::eyre::eyre!("failed to sign node key: {}", e))?;

    let sig_bytes = sig
        .to_cbor()
        .map_err(|e| color_eyre::eyre::eyre!("failed to encode signature: {}", e))?;

    // submit signature
    let response = client
        .tka_sign_node(args.node_id, sig_bytes)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to sign node: {}", e))?;

    if response.success {
        println!("Node {} signed successfully", args.node_id);
    } else {
        bail!("Failed to sign node: {}", response.message);
    }

    Ok(())
}

async fn disable(args: DisableArgs) -> Result<()> {
    // parse hex secret
    let secret_bytes = hex::decode(&args.secret)
        .map_err(|e| color_eyre::eyre::eyre!("invalid secret hex: {}", e))?;

    if secret_bytes.len() != 32 {
        bail!("disablement secret must be 32 bytes (64 hex chars)");
    }

    let mut client = connect_client(&args.socket).await?;

    let response = client
        .tka_disable(secret_bytes)
        .await
        .map_err(|e| color_eyre::eyre::eyre!("failed to disable TKA: {}", e))?;

    if response.success {
        println!("Tailnet lock disabled");
    } else {
        bail!("Failed to disable TKA: {}", response.message);
    }

    Ok(())
}
