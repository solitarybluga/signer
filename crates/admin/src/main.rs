use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::Deserialize;
use signer_core::unseal::{KekCheckFile, UnsealConfig, UnsealManager};
use signer_share::{HolderKeypair, encrypt_share};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "signer-admin",
    about = "Initialization and share distribution for signer"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an X25519 keypair for one share holder.
    HolderKeygen {
        /// Path for the holder's private key file.
        #[arg(long)]
        out: PathBuf,
    },

    /// Generate a KEK, split it, and export encrypted share envelopes.
    Init {
        /// Directory that also contains kek_check.json.
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,

        /// Number of shares required to unseal.
        #[arg(long, default_value_t = 3)]
        threshold: u8,

        /// Total number of shares to generate.
        #[arg(long, default_value_t = 5)]
        total_shares: u8,

        /// JSON file with [{ "id": "...", "public_key": "<hex>" }, ...].
        #[arg(long)]
        holders: PathBuf,

        /// Overwrite an existing initialization.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Deserialize)]
struct HolderSpec {
    id: String,
    public_key: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::HolderKeygen { out } => holder_keygen(&out),
        Command::Init {
            data_dir,
            threshold,
            total_shares,
            holders,
            force,
        } => init(&data_dir, threshold, total_shares, &holders, force),
    }
}

fn holder_keygen(out: &Path) -> Result<(), Box<dyn Error>> {
    let keypair = HolderKeypair::generate();

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    write_private(out, keypair.secret_bytes())?;

    println!("holder secret: {}", out.display());
    println!("holder public key: {}", hex::encode(keypair.public_bytes()));
    println!("give the public key to the operator and keep the secret file offline");

    Ok(())
}

fn init(
    data_dir: &Path,
    threshold: u8,
    total_shares: u8,
    holders_path: &Path,
    force: bool,
) -> Result<(), Box<dyn Error>> {
    let raw = fs::read_to_string(holders_path)?;
    let holders: Vec<HolderSpec> = serde_json::from_str(&raw)?;

    if holders.len() != total_shares as usize {
        return Err(format!(
            "holders file has {} entries, but total_shares is {}",
            holders.len(),
            total_shares
        )
        .into());
    }

    let mut ids = HashSet::new();
    let mut recipients = Vec::with_capacity(holders.len());
    for holder in &holders {
        if holder.id.is_empty() {
            return Err("holder id cannot be empty".into());
        }
        if !ids.insert(holder.id.clone()) {
            return Err(format!("duplicate holder id: {}", holder.id).into());
        }

        let public_key = hex::decode(&holder.public_key)
            .map_err(|error| format!("invalid public key for {}: {error}", holder.id))?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| format!("public key for {} must be 32 bytes", holder.id))?;
        recipients.push(public_key);
    }

    let check_path = data_dir.join("kek_check.json");
    let shares_dir = data_dir.join("shares");

    if !force && (check_path.exists() || shares_dir.exists()) {
        return Err(format!(
            "{} is already initialized; pass --force to overwrite",
            data_dir.display()
        )
        .into());
    }

    if force {
        if check_path.exists() {
            fs::remove_file(&check_path)?;
        }
        if shares_dir.exists() {
            fs::remove_dir_all(&shares_dir)?;
        }
    }

    let config = UnsealConfig::new(threshold, total_shares);
    let (manager, shares) = UnsealManager::bootstrap(config)?;
    let check_file = KekCheckFile::from_check(&manager.check(), threshold, total_shares);

    fs::create_dir_all(data_dir)?;
    fs::write(&check_path, serde_json::to_vec_pretty(&check_file)?)?;

    fs::create_dir_all(&shares_dir)?;
    println!("wrote KEK check: {}", check_path.display());
    println!("encrypted shares:");

    for ((mut share, holder), public_key) in shares
        .into_iter()
        .zip(holders.iter())
        .zip(recipients.iter())
    {
        let envelope = encrypt_share(public_key, &share)?;
        let path = shares_dir.join(format!("{}.share", holder.id));
        write_private(&path, &envelope)?;
        share.zeroize();

        println!("  {} -> {}", holder.id, path.display());
    }

    println!("distribute each .share file to the matching holder; never commit the data directory");

    Ok(())
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path)?.write_all(data)
}
