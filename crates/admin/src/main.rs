use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use signer_core::unseal::{HolderIndex, KekCheckFile, UnsealConfig, UnsealManager};
use signer_holder::{
    HolderEntry, Manifest, PublicBundle, generate_operator_key, operator_fingerprint,
    operator_public, sha256_hex, sign_manifest, write_atomic,
};
use signer_permissions::PermissionSet;
use signer_pki::{
    DEFAULT_CA_DAYS, DEFAULT_CERT_DAYS, GeneratedCsr, generate_client_csr, generate_server_csr,
    sign_client_csr, sign_server_csr,
};
use signer_share::encrypt_share;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

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
    /// Generate an Ed25519 operator signing keypair for share manifests.
    OperatorKeygen {
        /// Path for the operator's private key file.
        #[arg(long)]
        out: PathBuf,

        /// Path for the operator's public key file (hex).
        #[arg(long)]
        pub_out: PathBuf,
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

        /// JSON file with legacy holders or holder public bundles.
        #[arg(long)]
        holders: PathBuf,

        /// Optional Ed25519 operator key used to sign manifest.json.
        #[arg(long)]
        operator_key: Option<PathBuf>,

        /// Overwrite an existing initialization.
        #[arg(long)]
        force: bool,
    },

    /// Create an offline CA with an encrypted PKCS#8 private key.
    TlsCaInit {
        /// Directory for ca.crt and ca.key.enc.
        #[arg(long, default_value = "data/tls")]
        out_dir: PathBuf,

        /// CA common name.
        #[arg(long, default_value = "signer-ca")]
        cn: String,

        /// CA validity in days.
        #[arg(long, default_value_t = DEFAULT_CA_DAYS)]
        days: u32,

        /// Environment variable holding the CA key passphrase.
        #[arg(long, default_value = "SIGNER_CA_PASSPHRASE")]
        passphrase_env: String,

        /// Overwrite existing CA files.
        #[arg(long)]
        force: bool,
    },

    /// Generate an endpoint private key and CSR; the CA never sees the key.
    TlsCsr {
        /// Certificate kind.
        #[arg(long, value_enum)]
        kind: CertificateKind,

        /// Output path for the private key (PEM).
        #[arg(long)]
        out_key: PathBuf,

        /// Output path for the CSR (PEM).
        #[arg(long)]
        out_csr: PathBuf,

        /// Approved audit principal (client only).
        #[arg(long)]
        principal: Option<String>,

        /// Approved holder binding (repeatable; client only).
        #[arg(long = "holder", value_name = "HOLDER_ID")]
        holders: Vec<String>,

        /// Comma-separated approved permissions (client only).
        #[arg(long, default_value = "")]
        permissions: String,

        /// Approved server SAN, for example DNS:localhost or IP:127.0.0.1
        /// (repeatable; server only).
        #[arg(long = "server-san", value_name = "SAN")]
        server_sans: Vec<String>,

        /// Certificate common name; defaults to the principal or first SAN.
        #[arg(long)]
        common_name: Option<String>,

        /// Write an unencrypted key. Required for server keys and for clients
        /// whose TLS stack cannot decrypt PKCS#8.
        #[arg(long)]
        plaintext_key: bool,

        /// Environment variable holding the endpoint key passphrase.
        #[arg(long, default_value = "SIGNER_TLS_KEY_PASSPHRASE")]
        key_passphrase_env: String,

        /// Overwrite existing output files.
        #[arg(long)]
        force: bool,
    },

    /// Sign a CSR with the CA, replacing all requested identity fields.
    TlsSignCsr {
        /// CA certificate path.
        #[arg(long, default_value = "data/tls/ca.crt")]
        ca_cert: PathBuf,

        /// Encrypted CA private key path.
        #[arg(long, default_value = "data/tls/ca.key.enc")]
        ca_key: PathBuf,

        /// CSR path to sign.
        #[arg(long)]
        csr: PathBuf,

        /// Output certificate path (PEM).
        #[arg(long)]
        out: PathBuf,

        /// Certificate kind.
        #[arg(long, value_enum)]
        kind: CertificateKind,

        /// Approved audit principal (client only).
        #[arg(long)]
        principal: Option<String>,

        /// Approved holder binding (repeatable; client only).
        #[arg(long = "holder", value_name = "HOLDER_ID")]
        holders: Vec<String>,

        /// Comma-separated approved permissions (client only).
        #[arg(long, default_value = "")]
        permissions: String,

        /// Approved server SAN, for example DNS:localhost or IP:127.0.0.1
        /// (repeatable; server only).
        #[arg(long = "server-san", value_name = "SAN")]
        server_sans: Vec<String>,

        /// Certificate common name; defaults to the principal or first SAN.
        #[arg(long)]
        common_name: Option<String>,

        /// Certificate validity in days.
        #[arg(long, default_value_t = DEFAULT_CERT_DAYS)]
        days: u32,

        /// Environment variable holding the CA key passphrase.
        #[arg(long, default_value = "SIGNER_CA_PASSPHRASE")]
        passphrase_env: String,

        /// Overwrite an existing certificate.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CertificateKind {
    Client,
    Server,
}

impl CertificateKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HolderSpec {
    /// Legacy: {"id": "...", "public_key": "<x25519 hex>"}
    Legacy { id: String },

    /// Desktop public bundle: holder_id, both public keys, self-signature.
    Bundle {
        holder_id: String,
        x25519_public: String,
        #[serde(default)]
        ed25519_public: Option<String>,
        #[serde(default)]
        self_signature: Option<String>,
        #[serde(default)]
        version: Option<u8>,
    },
}

impl HolderSpec {
    fn into_registered(self) -> Result<RegisteredHolder, Box<dyn Error>> {
        match self {
            HolderSpec::Legacy { id } => Err(format!(
                "holder {id} uses the legacy X25519-only format; secure unseal requires an Ed25519 + X25519 public bundle generated by the desktop client"
            )
            .into()),
            HolderSpec::Bundle {
                holder_id,
                x25519_public,
                ed25519_public,
                self_signature,
                version,
            } => {
                let ed25519_public = ed25519_public.ok_or_else(|| {
                    format!("public bundle for {holder_id} is missing ed25519_public")
                })?;
                let self_signature = self_signature.ok_or_else(|| {
                    format!("public bundle for {holder_id} is missing self_signature")
                })?;

                let bundle = PublicBundle {
                    version: version.unwrap_or(1),
                    holder_id: holder_id.clone(),
                    ed25519_public,
                    x25519_public,
                    self_signature,
                };
                let material = bundle
                    .verify()
                    .map_err(|error| format!("invalid public bundle for {holder_id}: {error}"))?;

                Ok(RegisteredHolder {
                    id: material.holder_id,
                    x25519_public: material.x25519_public,
                    ed25519_public: material.ed25519_public,
                })
            }
        }
    }
}

struct RegisteredHolder {
    id: String,
    x25519_public: [u8; 32],
    ed25519_public: [u8; 32],
}

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::OperatorKeygen { out, pub_out } => operator_keygen(&out, &pub_out),
        Command::Init {
            data_dir,
            threshold,
            total_shares,
            holders,
            operator_key,
            force,
        } => init(
            &data_dir,
            threshold,
            total_shares,
            &holders,
            operator_key.as_deref(),
            force,
        ),
        Command::TlsCaInit {
            out_dir,
            cn,
            days,
            passphrase_env,
            force,
        } => {
            let passphrase = required_passphrase_env(&passphrase_env)?;
            tls_ca_init(&out_dir, &cn, days, passphrase.as_str(), force)
        }
        Command::TlsCsr {
            kind,
            out_key,
            out_csr,
            principal,
            holders,
            permissions,
            server_sans,
            common_name,
            plaintext_key,
            key_passphrase_env,
            force,
        } => {
            let key_passphrase = match kind {
                CertificateKind::Client if !plaintext_key => {
                    optional_passphrase_env(&key_passphrase_env)?
                }
                CertificateKind::Client | CertificateKind::Server => None,
            };
            tls_csr(
                kind,
                &out_key,
                &out_csr,
                principal.as_deref(),
                &holders,
                &permissions,
                &server_sans,
                common_name.as_deref(),
                plaintext_key,
                key_passphrase.as_ref().map(|value| value.as_str()),
                force,
            )
        }
        Command::TlsSignCsr {
            ca_cert,
            ca_key,
            csr,
            out,
            kind,
            principal,
            holders,
            permissions,
            server_sans,
            common_name,
            days,
            passphrase_env,
            force,
        } => {
            let passphrase = required_passphrase_env(&passphrase_env)?;
            tls_sign_csr(
                kind,
                &ca_cert,
                &ca_key,
                &csr,
                &out,
                principal.as_deref(),
                &holders,
                &permissions,
                &server_sans,
                common_name.as_deref(),
                days,
                passphrase.as_str(),
                force,
            )
        }
    }
}

fn required_passphrase_env(name: &str) -> Result<Zeroizing<String>, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(Zeroizing::new(value)),
        Ok(_) => Err(format!("{name} is empty; set a strong passphrase").into()),
        Err(std::env::VarError::NotPresent) => {
            Err(format!("set {name} to the CA key passphrase").into())
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{name} must contain valid UTF-8").into())
        }
    }
}

fn optional_passphrase_env(name: &str) -> Result<Option<Zeroizing<String>>, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(Some(Zeroizing::new(value))),
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{name} must contain valid UTF-8").into())
        }
    }
}

fn operator_keygen(out: &Path, pub_out: &Path) -> Result<(), Box<dyn Error>> {
    let (secret, public) = generate_operator_key()?;
    let secret = Zeroizing::new(secret);

    write_atomic(out, &secret[..], false)?;
    write_atomic(
        pub_out,
        format!("{}\n", hex::encode(public)).as_bytes(),
        false,
    )?;

    println!("operator secret: {}", out.display());
    println!("operator public key: {}", hex::encode(public));
    println!(
        "operator public fingerprint: {}",
        operator_fingerprint(&public)
    );
    println!("keep the secret offline and pin the public key in the desktop client");
    println!("never commit the operator secret");

    Ok(())
}

fn init(
    data_dir: &Path,
    threshold: u8,
    total_shares: u8,
    holders_path: &Path,
    operator_key: Option<&Path>,
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
    let mut public_keys = HashSet::new();
    let mut registered = Vec::with_capacity(holders.len());
    for holder in holders {
        let holder = holder.into_registered()?;
        if !ids.insert(holder.id.clone()) {
            return Err(format!("duplicate holder id: {}", holder.id).into());
        }
        if !public_keys.insert(holder.x25519_public) {
            return Err(format!("duplicate x25519 public key for {}", holder.id).into());
        }
        registered.push(holder);
    }

    let check_path = data_dir.join("kek_check.json");
    let shares_dir = data_dir.join("shares");
    let manifest_path = data_dir.join("manifest.json");
    let signature_path = data_dir.join("manifest.sig");
    let operator_pub_path = data_dir.join("operator.pub");

    if !force
        && (check_path.exists()
            || shares_dir.exists()
            || manifest_path.exists()
            || signature_path.exists()
            || operator_pub_path.exists())
    {
        return Err(format!(
            "{} is already initialized; pass --force to overwrite",
            data_dir.display()
        )
        .into());
    }

    if force {
        for path in [
            &check_path,
            &manifest_path,
            &signature_path,
            &operator_pub_path,
        ] {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        if shares_dir.exists() {
            fs::remove_dir_all(&shares_dir)?;
        }
    }

    let unseal_holders: Vec<HolderIndex> = registered
        .iter()
        .enumerate()
        .map(|(index, holder)| HolderIndex {
            id: holder.id.clone(),
            index: (index + 1) as u8,
            ed25519_public: hex::encode(holder.ed25519_public),
        })
        .collect();

    let config = UnsealConfig::new(threshold, total_shares);
    let (manager, shares, vss) = UnsealManager::bootstrap(config, unseal_holders.clone())?;
    let check_file = KekCheckFile::from_check(
        &manager.check(),
        threshold,
        total_shares,
        vss.clone(),
        unseal_holders,
    );

    fs::create_dir_all(data_dir)?;
    fs::write(&check_path, serde_json::to_vec_pretty(&check_file)?)?;

    fs::create_dir_all(&shares_dir)?;
    println!("wrote KEK check: {}", check_path.display());
    println!("encrypted shares:");

    let ceremony_id = Uuid::new_v4().to_string();
    let mut manifest_holders = Vec::with_capacity(registered.len());

    for (index, (mut share, holder)) in shares.into_iter().zip(registered.iter()).enumerate() {
        let envelope = encrypt_share(&holder.x25519_public, &share)?;
        let path = shares_dir.join(format!("{}.share", holder.id));
        write_private(&path, &envelope)?;

        manifest_holders.push(HolderEntry {
            id: holder.id.clone(),
            index: (index + 1) as u8,
            x25519_public: hex::encode(holder.x25519_public),
            ed25519_public: Some(hex::encode(holder.ed25519_public)),
            envelope_sha256: sha256_hex(&envelope),
        });

        share.zeroize();
        println!("  {} -> {}", holder.id, path.display());
    }

    if let Some(operator_key_path) = operator_key {
        let key_bytes = fs::read(operator_key_path)?;
        let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
            format!(
                "operator key {} must be exactly 32 bytes",
                operator_key_path.display()
            )
        })?;
        let key_bytes = Zeroizing::new(key_bytes);

        let manifest = Manifest {
            version: 2,
            ceremony_id,
            threshold,
            total_shares,
            vss: Some(vss),
            holders: manifest_holders,
        };
        let manifest_bytes = manifest.encode()?;
        let signature = sign_manifest(&manifest_bytes, &key_bytes)?;
        let public = operator_public(&key_bytes);

        write_atomic(&manifest_path, &manifest_bytes, force)?;
        write_atomic(
            &signature_path,
            format!("{}\n", hex::encode(signature)).as_bytes(),
            force,
        )?;
        write_atomic(
            &operator_pub_path,
            format!("{}\n", hex::encode(public)).as_bytes(),
            force,
        )?;

        println!("wrote manifest: {}", manifest_path.display());
        println!("wrote manifest signature: {}", signature_path.display());
        println!("wrote operator public key: {}", operator_pub_path.display());
    } else {
        println!("no --operator-key supplied; manifest was not generated");
    }

    println!("distribute each .share file to the matching holder; never commit the data directory");

    Ok(())
}

fn tls_ca_init(
    out_dir: &Path,
    common_name: &str,
    days: u32,
    passphrase: &str,
    force: bool,
) -> Result<(), Box<dyn Error>> {
    let cert_path = out_dir.join("ca.crt");
    let key_path = out_dir.join("ca.key.enc");

    if !force && (cert_path.exists() || key_path.exists()) {
        return Err(format!(
            "{} already contains CA files; pass --force to overwrite",
            out_dir.display()
        )
        .into());
    }

    let ca = signer_pki::generate_ca(common_name, days, passphrase)?;
    write_cert(&cert_path, &ca.cert_pem, force)?;
    write_atomic(&key_path, ca.key_pem.as_bytes(), force)?;

    println!("created CA certificate: {}", cert_path.display());
    println!("created encrypted CA key: {}", key_path.display());
    println!(
        "CA SHA-256 fingerprint: {}",
        signer_pki::certificate_fingerprint_hex(&ca.cert_pem)?
    );
    println!("keep the CA key offline; never place it on a signer or desktop host");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn tls_csr(
    kind: CertificateKind,
    out_key: &Path,
    out_csr: &Path,
    principal: Option<&str>,
    holders: &[String],
    permissions: &str,
    server_sans: &[String],
    common_name: Option<&str>,
    plaintext_key: bool,
    key_passphrase: Option<&str>,
    force: bool,
) -> Result<(), Box<dyn Error>> {
    if out_key == out_csr {
        return Err("--out-key and --out-csr must be different paths".into());
    }
    if !force && (out_key.exists() || out_csr.exists()) {
        return Err("an output file already exists; pass --force to overwrite".into());
    }

    let generated: GeneratedCsr = match kind {
        CertificateKind::Client => {
            if !server_sans.is_empty() {
                return Err("--server-san is only valid with --kind server".into());
            }
            if plaintext_key && key_passphrase.is_some() {
                return Err("choose either a key passphrase or --plaintext-key, not both".into());
            }
            if !plaintext_key && key_passphrase.is_none() {
                return Err(
                    "client CSRs require a passphrase or an explicit --plaintext-key".into(),
                );
            }
            let principal = principal.ok_or("client CSR requires --principal")?;
            let permissions = PermissionSet::parse_list(permissions)?;
            generate_client_csr(principal, holders, permissions, key_passphrase, common_name)?
        }
        CertificateKind::Server => {
            if principal.is_some() || !holders.is_empty() || !permissions.trim().is_empty() {
                return Err(
                    "--principal, --holder and --permissions are only valid with --kind client"
                        .into(),
                );
            }
            if !plaintext_key || key_passphrase.is_some() {
                return Err(
                    "server CSRs must use --plaintext-key; the signer does not decrypt TLS keys yet"
                        .into(),
                );
            }
            generate_server_csr(server_sans, None, common_name)?
        }
    };

    write_atomic(out_key, generated.key_pem.as_bytes(), force)?;
    write_atomic(out_csr, generated.csr_pem.as_bytes(), force)?;

    println!("wrote {} key: {}", kind.as_str(), out_key.display());
    println!("wrote CSR: {}", out_csr.display());
    if generated.key_encrypted {
        println!("the private key is encrypted; keep the passphrase out of shell history");
    } else {
        println!("WARN: the private key is unencrypted; protect it with filesystem permissions");
    }
    println!("send only the CSR to the CA; the CA must approve identity and permissions");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn tls_sign_csr(
    kind: CertificateKind,
    ca_cert: &Path,
    ca_key: &Path,
    csr: &Path,
    out: &Path,
    principal: Option<&str>,
    holders: &[String],
    permissions: &str,
    server_sans: &[String],
    common_name: Option<&str>,
    days: u32,
    passphrase: &str,
    force: bool,
) -> Result<(), Box<dyn Error>> {
    if out.exists() && !force {
        return Err(format!(
            "{} already exists; pass --force to overwrite",
            out.display()
        )
        .into());
    }

    let ca_cert_pem = fs::read_to_string(ca_cert)?;
    let ca_key_pem = Zeroizing::new(fs::read_to_string(ca_key)?);
    let csr_pem = fs::read_to_string(csr)?;

    let issued = match kind {
        CertificateKind::Client => {
            if !server_sans.is_empty() {
                return Err("--server-san is only valid with --kind server".into());
            }
            let principal = principal.ok_or("client certificate requires --principal")?;
            let permissions = PermissionSet::parse_list(permissions)?;
            sign_client_csr(
                &ca_cert_pem,
                ca_key_pem.as_str(),
                passphrase,
                &csr_pem,
                principal,
                holders,
                permissions,
                common_name,
                days,
            )?
        }
        CertificateKind::Server => {
            if principal.is_some() || !holders.is_empty() || !permissions.trim().is_empty() {
                return Err(
                    "--principal, --holder and --permissions are only valid with --kind client"
                        .into(),
                );
            }
            sign_server_csr(
                &ca_cert_pem,
                ca_key_pem.as_str(),
                passphrase,
                &csr_pem,
                server_sans,
                common_name,
                days,
            )?
        }
    };

    write_cert(out, &issued.cert_pem, force)?;
    println!("wrote {} certificate: {}", kind.as_str(), out.display());
    println!(
        "certificate SHA-256 fingerprint: {}",
        issued.fingerprint_sha256
    );
    println!("CSR-requested SANs were ignored; only approved values were signed");
    Ok(())
}

fn write_cert(path: &Path, pem: &str, force: bool) -> Result<(), Box<dyn Error>> {
    if path.exists() && !force {
        return Err(format!(
            "{} already exists; pass --force to overwrite",
            path.display()
        )
        .into());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use signer_holder::{
        HolderIdentity, decode_operator_public, decode_signature, verify_manifest,
    };
    use signer_permissions::Permission;

    #[test]
    fn init_writes_a_verified_manifest_for_public_bundles() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let holders_path = dir.path().join("holders.json");
        let operator_key_path = dir.path().join("operator.key");

        let alice = HolderIdentity::generate("alice").unwrap();
        let bob = HolderIdentity::generate("bob").unwrap();
        let holders = vec![alice.public_bundle(), bob.public_bundle()];
        fs::write(&holders_path, serde_json::to_vec(&holders).unwrap()).unwrap();

        let (secret, public) = signer_holder::generate_operator_key().unwrap();
        fs::write(&operator_key_path, secret).unwrap();

        init(
            &data_dir,
            1,
            2,
            &holders_path,
            Some(&operator_key_path),
            false,
        )
        .unwrap();

        let manifest_bytes = fs::read(data_dir.join("manifest.json")).unwrap();
        let signature =
            decode_signature(&fs::read_to_string(data_dir.join("manifest.sig")).unwrap()).unwrap();
        let operator_public =
            decode_operator_public(&fs::read_to_string(data_dir.join("operator.pub")).unwrap())
                .unwrap();
        assert_eq!(operator_public, public);

        let manifest = verify_manifest(&manifest_bytes, &signature, &operator_public).unwrap();
        assert_eq!(manifest.holders.len(), 2);
        assert_eq!(manifest.holders[0].id, "alice");
        assert_eq!(
            manifest.holders[0].ed25519_public,
            Some(holders[0].ed25519_public.clone())
        );
        assert!(data_dir.join("shares/alice.share").exists());
        assert!(data_dir.join("shares/bob.share").exists());

        let share_bytes = fs::read(data_dir.join("shares/alice.share")).unwrap();
        let imported = signer_holder::import_share(
            &alice,
            &share_bytes,
            Some(signer_holder::ManifestPackage {
                manifest_bytes: &manifest_bytes,
                signature: &signature,
                operator_public: &operator_public,
            }),
        )
        .unwrap();
        assert_eq!(imported.holder_id, "alice");
        assert_eq!(imported.index, 1);
        assert_eq!(imported.source, signer_holder::VaultSource::Manifest);

        let vault_path = dir.path().join("alice.vault");
        let vault_info = imported.seal(&vault_path, "passphrase-1").unwrap();
        assert_eq!(vault_info.holder_id, "alice");
        let (opened, share) = signer_holder::ShareVault::open(&vault_path, "passphrase-1").unwrap();
        assert_eq!(opened.index, 1);
        assert_eq!(share.as_slice(), imported.share.as_slice());
    }

    #[test]
    fn tls_ca_csr_and_signing_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tls_dir = dir.path().join("tls");
        let key_path = dir.path().join("alice.key");
        let csr_path = dir.path().join("alice.csr");
        let cert_path = dir.path().join("alice.crt");
        let holders = vec!["holder-1".to_string()];

        tls_ca_init(&tls_dir, "test-ca", 30, "ca-passphrase", false).unwrap();
        tls_csr(
            CertificateKind::Client,
            &key_path,
            &csr_path,
            Some("alice"),
            &holders,
            "unseal.start,key.read",
            &[],
            None,
            false,
            Some("key-passphrase"),
            false,
        )
        .unwrap();
        tls_sign_csr(
            CertificateKind::Client,
            &tls_dir.join("ca.crt"),
            &tls_dir.join("ca.key.enc"),
            &csr_path,
            &cert_path,
            Some("alice"),
            &holders,
            "unseal.start,key.read",
            &[],
            None,
            30,
            "ca-passphrase",
            false,
        )
        .unwrap();

        let cert_pem = fs::read_to_string(&cert_path).unwrap();
        let key_pem = fs::read_to_string(&key_path).unwrap();
        let ca_pem = fs::read_to_string(tls_dir.join("ca.crt")).unwrap();
        let info = signer_pki::verify_client_certificate(
            &cert_pem,
            &ca_pem,
            &key_pem,
            Some("key-passphrase"),
        )
        .unwrap();
        assert_eq!(info.principal, "alice");
        assert_eq!(info.holder_ids, holders);
        assert!(info.permissions.contains(Permission::UnsealStart));
        assert!(info.permissions.contains(Permission::KeyRead));
        assert!(!info.permissions.contains(Permission::KeySign));

        let ca_key = fs::read_to_string(tls_dir.join("ca.key.enc")).unwrap();
        assert!(ca_key.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    }
}
