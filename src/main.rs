mod grpc;

// The storage layer lands before its callers; remove this allow once the key
// service is wired up.
#[allow(dead_code, unused_imports)]
mod storage;

#[allow(dead_code)]
mod unseal;

use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tonic::transport::Server;

use grpc::SignerGrpc;
use unseal::{KekCheck, UnsealConfig, UnsealManager};

#[derive(Serialize, Deserialize)]
struct CheckFile {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = UnsealConfig {
        threshold: env_u8("SIGNER_UNSEAL_THRESHOLD", 3)?,
        total_shares: env_u8("SIGNER_UNSEAL_TOTAL_SHARES", 5)?,
        session_ttl: time::Duration::minutes(10),
    };

    let data_dir =
        PathBuf::from(std::env::var("SIGNER_DATA_DIR").unwrap_or_else(|_| "data".to_string()));
    std::fs::create_dir_all(&data_dir)?;

    let check_path = data_dir.join("kek_check.json");
    let shares_dir = data_dir.join("shares");

    let manager = if check_path.exists() {
        let raw = std::fs::read(&check_path)?;
        let file: CheckFile = serde_json::from_slice(&raw)?;
        let nonce: [u8; 24] = file.nonce.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid KEK check nonce length",
            )
        })?;
        let check = KekCheck::from_parts(nonce, file.ciphertext)?;
        UnsealManager::from_check(config, check)?
    } else {
        let (manager, shares) = UnsealManager::bootstrap(config)?;
        let check = manager.check();
        let file = CheckFile {
            nonce: check.nonce().to_vec(),
            ciphertext: check.ciphertext().to_vec(),
        };
        std::fs::write(&check_path, serde_json::to_vec_pretty(&file)?)?;

        std::fs::create_dir_all(&shares_dir)?;
        for (index, share) in shares.iter().enumerate() {
            let path = shares_dir.join(format!("share-{:02}.bin", index + 1));
            write_private(&path, share)?;
        }

        eprintln!(
            "generated {} share files in {}; distribute them offline and keep them safe",
            shares.len(),
            shares_dir.display()
        );

        manager
    };

    let addr: SocketAddr = std::env::var("SIGNER_GRPC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string())
        .parse()?;

    eprintln!("signer gRPC listening on {addr}");

    Server::builder()
        .add_service(SignerGrpc::new(Arc::new(manager)).into_server())
        .serve(addr)
        .await?;

    Ok(())
}

fn env_u8(name: &str, default: u8) -> Result<u8, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) => Ok(value.parse()?),
        Err(_) => Ok(default),
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path)?.write_all(data)
}
