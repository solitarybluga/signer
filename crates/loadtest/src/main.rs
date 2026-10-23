//! Load-test helper: unseal, create test keys, and drive concurrent Sign RPCs.
//!
//! This is a test utility. It intentionally reads test holder identity files
//! and `.share` envelopes from disk; never point it at production identities.

use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use signer_holder::HolderIdentity;
use signer_proto::pb;
use signer_proto::pb::signer_service_client::SignerServiceClient;
use tokio::task::JoinSet;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "signer-loadtest",
    about = "Unseal a test signer deployment and run concurrent Sign requests"
)]
struct Cli {
    /// signer gRPC endpoint, e.g. http://127.0.0.1:50051
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    server: String,

    /// Holder identity and share pair: "holder.key,holder.share".
    /// Repeat for each holder. Empty when using --skip-unseal.
    #[arg(long = "holder", value_name = "KEY,SHARE")]
    holders: Vec<String>,

    /// Skip unsealing; the server must already be unsealed.
    #[arg(long)]
    skip_unseal: bool,

    /// Client CA bundle for mTLS. Must be used with --client-cert and --client-key.
    #[arg(long, value_name = "PATH")]
    ca_cert: Option<PathBuf>,

    /// Client certificate for mTLS.
    #[arg(long, value_name = "PATH")]
    client_cert: Option<PathBuf>,

    /// Client private key for mTLS.
    #[arg(long, value_name = "PATH")]
    client_key: Option<PathBuf>,

    /// TLS server name override (useful when connecting by IP).
    #[arg(long, value_name = "NAME")]
    tls_domain: Option<String>,

    /// Environment variable holding the passphrase for an encrypted client key.
    #[arg(long, default_value = "SIGNER_TLS_KEY_PASSPHRASE")]
    client_key_passphrase_env: String,

    /// Number of Ed25519 keys to create.
    #[arg(long, default_value_t = 1)]
    eddsa: u32,

    /// Number of secp256k1 keys to create.
    #[arg(long, default_value_t = 1)]
    ecdsa: u32,

    /// Concurrent Sign workers.
    #[arg(long, default_value_t = 10)]
    concurrency: usize,

    /// Maximum load duration in seconds.
    #[arg(long, default_value_t = 10)]
    duration_secs: u64,

    /// Optional total request count; duration still applies.
    #[arg(long)]
    requests: Option<u64>,
}

struct HolderPaths {
    identity: PathBuf,
    share: PathBuf,
}

impl HolderPaths {
    fn parse(value: &str) -> Result<Self, &'static str> {
        let (identity, share) = value
            .split_once(',')
            .ok_or("holder must be KEY_PATH,SHARE_PATH")?;
        Ok(Self {
            identity: PathBuf::from(identity),
            share: PathBuf::from(share),
        })
    }
}

struct TlsFiles {
    ca_cert: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
    domain: Option<String>,
}

fn tls_files(cli: &Cli) -> Result<Option<TlsFiles>, Box<dyn Error>> {
    match (&cli.ca_cert, &cli.client_cert, &cli.client_key) {
        (None, None, None) => {
            if cli.tls_domain.is_some() {
                return Err(invalid(
                    "--tls-domain requires --ca-cert, --client-cert and --client-key",
                ));
            }
            Ok(None)
        }
        (Some(ca_cert), Some(client_cert), Some(client_key)) => Ok(Some(TlsFiles {
            ca_cert: ca_cert.clone(),
            client_cert: client_cert.clone(),
            client_key: client_key.clone(),
            domain: cli.tls_domain.clone(),
        })),
        _ => Err(invalid(
            "--ca-cert, --client-cert and --client-key must be provided together",
        )),
    }
}

fn target_url(server: &str, tls_enabled: bool) -> Result<String, Box<dyn Error>> {
    let (scheme, _) = match server.split_once("://") {
        Some(parts) => (Some(parts.0), parts.1),
        None => (None, server),
    };

    match (scheme, tls_enabled) {
        (Some("http"), false) | (Some("https"), true) => Ok(server.to_string()),
        (Some("http"), true) => Err(invalid("mTLS requires an https:// server URL")),
        (Some("https"), false) => Err(invalid(
            "https:// requires --ca-cert, --client-cert and --client-key",
        )),
        (None, true) => Ok(format!("https://{server}")),
        (None, false) => Ok(format!("http://{server}")),
        (Some(_), _) => Err(invalid("server URL must use http:// or https://")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    if cli.concurrency == 0 {
        return Err(invalid("concurrency must be positive"));
    }
    if cli.duration_secs == 0 {
        return Err(invalid("duration_secs must be positive"));
    }
    if cli.requests == Some(0) {
        return Err(invalid("requests must be positive when provided"));
    }
    if cli.eddsa == 0 && cli.ecdsa == 0 {
        return Err(invalid("create at least one Ed25519 or secp256k1 key"));
    }

    let holders = cli
        .holders
        .iter()
        .map(|value| HolderPaths::parse(value).map_err(invalid))
        .collect::<Result<Vec<_>, _>>()?;

    let passphrase = if cli.skip_unseal {
        None
    } else {
        Some(Zeroizing::new(
            std::env::var("SIGNER_LOADTEST_PASSPHRASE")
                .map_err(|_| invalid("set SIGNER_LOADTEST_PASSPHRASE before unsealing"))?,
        ))
    };

    let tls = tls_files(&cli)?;
    let target = target_url(&cli.server, tls.is_some())?;
    let mut endpoint = Endpoint::from_shared(target)?;
    if let Some(tls) = &tls {
        let ca = std::fs::read(&tls.ca_cert)?;
        let cert = std::fs::read(&tls.client_cert)?;
        let key_pem = Zeroizing::new(
            std::fs::read_to_string(&tls.client_key)
                .map_err(|_| invalid("client key must be a PEM file"))?,
        );
        let key_passphrase = optional_passphrase_env(&cli.client_key_passphrase_env)?;
        let key = signer_pki::load_private_key_pem(
            key_pem.as_str(),
            key_passphrase.as_ref().map(|value| value.as_str()),
        )?;
        let mut config = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, key.as_bytes()));
        if let Some(domain) = &tls.domain {
            config = config.domain_name(domain);
        }
        endpoint = endpoint.tls_config(config)?;
    }
    let mut client = SignerServiceClient::new(endpoint.connect().await?);

    if let Some(passphrase) = passphrase {
        if holders.is_empty() {
            return Err(invalid("at least one --holder is required for unsealing"));
        }
        unseal(&mut client, &holders, passphrase.as_str()).await?;
    }

    let keys = create_keys(&mut client, cli.eddsa, cli.ecdsa).await?;
    println!(
        "created {} keys: {} EdDSA, {} ECDSA",
        keys.len(),
        cli.eddsa,
        cli.ecdsa
    );

    let keys = Arc::new(keys);
    let counter = Arc::new(AtomicU64::new(0));
    let load_started = Instant::now();
    let deadline = load_started + Duration::from_secs(cli.duration_secs);
    let mut tasks = JoinSet::new();

    for worker in 0..cli.concurrency {
        let mut client = client.clone();
        let keys = Arc::clone(&keys);
        let counter = Arc::clone(&counter);
        let requests = cli.requests;

        tasks.spawn(async move {
            let mut latencies = Vec::new();
            let mut errors = 0u64;
            let mut sequence = 0u64;

            loop {
                if Instant::now() >= deadline {
                    break;
                }
                if let Some(limit) = requests {
                    let next = counter.fetch_add(1, Ordering::Relaxed);
                    if next >= limit {
                        break;
                    }
                }

                let key_id = keys[(worker + sequence as usize) % keys.len()].clone();
                let started = Instant::now();
                let result = client
                    .sign(pb::SignRequest {
                        key_id,
                        payload: [0x42u8; 32].to_vec(),
                        request_id: format!("lt-{worker}-{sequence}"),
                    })
                    .await;

                match result {
                    Ok(_) => latencies.push(started.elapsed().as_micros()),
                    Err(_) => errors += 1,
                }
                sequence += 1;
            }

            (latencies, errors, sequence)
        });
    }

    let mut latencies = Vec::new();
    let mut errors = 0u64;
    let mut total = 0u64;
    while let Some(result) = tasks.join_next().await {
        let (worker_latencies, worker_errors, worker_total) = result?;
        latencies.extend(worker_latencies);
        errors += worker_errors;
        total += worker_total;
    }

    let actual_elapsed = load_started.elapsed().max(Duration::from_millis(1));
    let qps = total as f64 / actual_elapsed.as_secs_f64();

    latencies.sort_unstable();
    println!(
        "requests={} errors={} qps={:.1} p50={}us p95={}us p99={}us p999={}us",
        total,
        errors,
        qps,
        percentile(&latencies, 50),
        percentile(&latencies, 95),
        percentile(&latencies, 99),
        percentile(&latencies, 999),
    );

    Ok(())
}

async fn unseal(
    client: &mut SignerServiceClient<Channel>,
    holders: &[HolderPaths],
    passphrase: &str,
) -> Result<(), Box<dyn Error>> {
    let start = client
        .start_unseal(pb::StartUnsealRequest {})
        .await?
        .into_inner();

    let threshold = usize::try_from(start.threshold)
        .map_err(|_| invalid("server returned an invalid threshold"))?;
    if holders.len() < threshold {
        return Err(invalid("not enough --holder entries for the threshold"));
    }

    let nonce: [u8; 32] = start
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| invalid("server returned an invalid session nonce"))?;
    let session_public: [u8; 32] = start
        .session_public_key
        .as_slice()
        .try_into()
        .map_err(|_| invalid("server returned an invalid session public key"))?;

    for holder in holders.iter().take(threshold) {
        let identity = HolderIdentity::load_encrypted(&holder.identity, passphrase)?;
        let envelope = std::fs::read(&holder.share)?;
        let share = identity.decrypt_share(&envelope)?;
        if share.len() != 33 || share[0] == 0 {
            return Err(invalid("holder share is invalid"));
        }

        let context = signer_share::submission_context(
            &start.session_id,
            &nonce,
            &session_public,
            identity.holder_id(),
            share[0],
        )?;
        let ciphertext =
            signer_share::encrypt_share_with_context(&session_public, &share, &context)?;
        let signature = identity.sign(&signer_share::submission_signing_input(
            &context,
            &ciphertext,
        ));

        client
            .submit_unseal_share(pb::SubmitUnsealShareRequest {
                session_id: start.session_id.clone(),
                share_holder_id: identity.holder_id().to_string(),
                encrypted_share: ciphertext,
                signature: signature.to_vec(),
                share_index: u32::from(share[0]),
                nonce: nonce.to_vec(),
            })
            .await?;
    }

    let status = client
        .get_unseal_status(pb::GetUnsealStatusRequest {
            session_id: start.session_id,
        })
        .await?
        .into_inner();
    if status.state != pb::UnsealState::Unsealed as i32 {
        return Err(invalid("server did not reach the unsealed state"));
    }

    println!("unsealed with {threshold} holder shares");
    Ok(())
}

async fn create_keys(
    client: &mut SignerServiceClient<Channel>,
    eddsa: u32,
    ecdsa: u32,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut keys = Vec::with_capacity(eddsa as usize + ecdsa as usize);

    for _ in 0..eddsa {
        keys.push(
            create_key(
                client,
                pb::Curve::Edwards25519,
                pb::SignatureAlgorithm::Eddsa,
            )
            .await?,
        );
    }
    for _ in 0..ecdsa {
        keys.push(create_key(client, pb::Curve::Secp256k1, pb::SignatureAlgorithm::Ecdsa).await?);
    }

    Ok(keys)
}

async fn create_key(
    client: &mut SignerServiceClient<Channel>,
    curve: pb::Curve,
    algorithm: pb::SignatureAlgorithm,
) -> Result<String, Box<dyn Error>> {
    let response = client
        .create_key(pb::CreateKeyRequest {
            curve: curve as i32,
            algorithm: algorithm as i32,
            labels: Default::default(),
        })
        .await?
        .into_inner();
    let key = response
        .key
        .ok_or_else(|| invalid("CreateKey returned no key"))?;
    Ok(key.id)
}

fn percentile(sorted: &[u128], p: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (sorted.len() * p / 1000).min(sorted.len() - 1);
    sorted[index]
}

fn optional_passphrase_env(name: &str) -> Result<Option<Zeroizing<String>>, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(Some(Zeroizing::new(value))),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(invalid(
            "client key passphrase environment variable is not valid UTF-8",
        )),
    }
}

fn invalid(message: &'static str) -> Box<dyn Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_holder_pair() {
        let holder = HolderPaths::parse("alice.key,alice.share").unwrap();
        assert_eq!(holder.identity, PathBuf::from("alice.key"));
        assert_eq!(holder.share, PathBuf::from("alice.share"));
        assert!(HolderPaths::parse("alice.key").is_err());
    }

    #[test]
    fn percentiles_are_bounded() {
        let values = [1, 2, 3, 4, 5];
        assert_eq!(percentile(&values, 0), 1);
        assert_eq!(percentile(&values, 999), 5);
        assert_eq!(percentile(&[], 50), 0);
    }

    #[test]
    fn target_url_requires_matching_tls_settings() {
        assert_eq!(
            target_url("127.0.0.1:50051", false).unwrap(),
            "http://127.0.0.1:50051"
        );
        assert_eq!(
            target_url("127.0.0.1:50051", true).unwrap(),
            "https://127.0.0.1:50051"
        );
        assert_eq!(
            target_url("https://signer.test:50051", true).unwrap(),
            "https://signer.test:50051"
        );
        assert!(target_url("http://127.0.0.1:50051", true).is_err());
        assert!(target_url("https://signer.test:50051", false).is_err());
        assert!(target_url("grpc://127.0.0.1:50051", false).is_err());
    }
}
