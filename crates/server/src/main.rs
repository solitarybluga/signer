mod grpc;

use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tonic::transport::Server;

use grpc::SignerGrpc;
use signer_core::unseal::{KekCheckFile, UnsealConfig, UnsealManager};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let data_dir =
        PathBuf::from(std::env::var("SIGNER_DATA_DIR").unwrap_or_else(|_| "data".to_string()));
    let check_path = data_dir.join("kek_check.json");

    if !check_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "KEK check not found at {}; run `signer-admin init` first",
                check_path.display()
            ),
        )
        .into());
    }

    let raw = std::fs::read(&check_path)?;
    let file: KekCheckFile = serde_json::from_slice(&raw)?;
    let (check, threshold, total_shares) = file.into_parts()?;

    let config = UnsealConfig {
        threshold,
        total_shares,
        session_ttl: session_ttl()?,
    };
    let manager = UnsealManager::from_check(config, check)?;

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

fn session_ttl() -> Result<time::Duration, Box<dyn Error>> {
    let seconds: u64 = match std::env::var("SIGNER_SESSION_TTL_SECS") {
        Ok(value) => value.parse()?,
        Err(_) => 600,
    };

    if seconds == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SIGNER_SESSION_TTL_SECS must be positive",
        )
        .into());
    }

    let seconds = i64::try_from(seconds).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SIGNER_SESSION_TTL_SECS is too large",
        )
    })?;

    Ok(time::Duration::seconds(seconds))
}
