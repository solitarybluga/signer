mod config;
mod grpc;
mod permissions;
mod tls;

use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tonic::service::InterceptorLayer;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

use config::{Config as AppConfig, LogFormat, LoggingConfig};
use grpc::SignerGrpc;
use signer_core::storage::{KeyStore, PostgresStore, SqliteStore};
use signer_core::unseal::{KekCheckFile, UnsealConfig, UnsealManager};

#[derive(Parser)]
#[command(name = "signer", about = "Quorum-unsealing signing service")]
struct Cli {
    /// Path to signer.toml.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = AppConfig::load(cli.config)?;
    init_tracing(&config.logging)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        data_dir = %config.server.data_dir.display(),
        "starting signer"
    );

    if !config.audit.sign_enabled {
        tracing::warn!("Sign audit is disabled by configuration");
    }

    let data_dir = &config.server.data_dir;
    let check_path = data_dir.join("kek_check.json");

    if !check_path.exists() {
        tracing::error!(path = %check_path.display(), "KEK check not found");
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
    let (check, threshold, total_shares, vss, holders) = file.into_parts()?;
    info!(
        threshold,
        total_shares,
        holders = holders.len(),
        "loaded KEK check"
    );

    let unseal_config = UnsealConfig {
        threshold,
        total_shares,
        session_ttl: config.session_ttl()?,
    };
    let manager = UnsealManager::from_check(unseal_config, check, vss, holders)?;

    let is_postgres = config
        .database
        .url
        .as_deref()
        .is_some_and(|url| url.starts_with("postgres://") || url.starts_with("postgresql://"));
    let pool_config = config
        .database
        .pool_config(if is_postgres { 10 } else { 1 })?;

    let store: Arc<dyn KeyStore> = match config.database.url.as_deref() {
        Some(database_url) if is_postgres => {
            Arc::new(PostgresStore::connect_with_pool(database_url, pool_config).await?)
        }
        Some(database_url) => {
            Arc::new(SqliteStore::connect_with_pool(database_url, pool_config).await?)
        }
        None => Arc::new(
            SqliteStore::connect_path_with_pool(data_dir.join("signer.db"), pool_config).await?,
        ),
    };

    info!(
        backend = if is_postgres { "postgres" } else { "sqlite" },
        "initialized key store"
    );

    let addr = config.grpc_addr()?;
    info!(%addr, "signer gRPC listening");

    let signer = SignerGrpc::with_sign_audit(Arc::new(manager), store, config.audit.sign_enabled)
        .with_client_permissions(config.tls.is_some());

    if let Some(tls) = &config.tls {
        let interceptor = tls::ClientCertInterceptor::new(tls);
        info!(
            cert = %tls.cert_path.display(),
            client_ca = %tls.client_ca_path.display(),
            principal_uri_prefix = %tls.principal_uri_prefix,
            holder_uri_prefix = %tls.holder_uri_prefix,
            permission_uri_prefix = %tls.permission_uri_prefix,
            "gRPC mTLS enabled"
        );
        Server::builder()
            .tls_config(tls::server_tls_config(tls)?)?
            .layer(InterceptorLayer::new(interceptor))
            .add_service(signer.into_server())
            .serve(addr)
            .await?;
    } else {
        tracing::warn!(
            "gRPC TLS is disabled; plaintext is only safe on loopback or a trusted network"
        );
        Server::builder()
            .add_service(signer.into_server())
            .serve(addr)
            .await?;
    }

    Ok(())
}

fn init_tracing(config: &LoggingConfig) -> Result<(), config::ConfigError> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.level))
        .map_err(|_| config::ConfigError::Invalid("invalid logging.level"))?;

    match config.format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_file(config.location)
                .with_line_number(config.location)
                .json()
                .init();
        }
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_file(config.location)
                .with_line_number(config.location)
                .init();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_database_path_opens() {
        let dir = std::env::temp_dir().join(format!("signer-db-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let store = SqliteStore::connect_path(dir.join("signer.db"))
            .await
            .unwrap();
        assert!(store.pool().acquire().await.is_ok());

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
