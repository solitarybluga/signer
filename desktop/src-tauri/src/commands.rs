use std::path::Path;

use serde::Serialize;
use tauri::async_runtime::spawn_blocking;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use zeroize::Zeroizing;

use signer_holder::{
    HolderError, HolderIdentity, ManifestPackage, ShareVault, VaultInfo, decode_operator_public,
    decode_signature, import_share, operator_fingerprint,
};
use signer_proto::pb;
use signer_proto::pb::signer_service_client::SignerServiceClient;

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub session_id: String,
    pub nonce_hex: String,
    pub session_public_key_hex: String,
    pub threshold: i32,
    pub shares_collected: i32,
    pub state: String,
    pub expires_at: Option<i64>,
}

impl SessionView {
    fn from_start(response: pb::StartUnsealResponse) -> Self {
        Self {
            session_id: response.session_id,
            nonce_hex: hex::encode(response.nonce),
            session_public_key_hex: hex::encode(response.session_public_key),
            threshold: response.threshold,
            shares_collected: response.shares_collected,
            state: "collecting".to_string(),
            expires_at: response.expires_at.map(|timestamp| timestamp.seconds),
        }
    }

    fn from_status(response: pb::GetUnsealStatusResponse) -> Self {
        Self {
            session_id: response.session_id,
            nonce_hex: hex::encode(response.nonce),
            session_public_key_hex: hex::encode(response.session_public_key),
            threshold: response.threshold,
            shares_collected: response.shares_collected,
            state: state_name(response.state),
            expires_at: response.expires_at.map(|timestamp| timestamp.seconds),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityView {
    pub holder_id: String,
    pub ed25519_public: String,
    pub x25519_public: String,
    pub fingerprint: String,
    pub identity_path: String,
    pub public_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicBundleView {
    pub holder_id: String,
    pub ed25519_public: String,
    pub x25519_public: String,
    pub fingerprint: String,
    pub public_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub vault: VaultInfo,
    pub operator_fingerprint: Option<String>,
}

fn state_name(value: i32) -> String {
    match pb::UnsealState::try_from(value) {
        Ok(pb::UnsealState::Collecting) => "collecting".to_string(),
        Ok(pb::UnsealState::Unsealed) => "unsealed".to_string(),
        Ok(pb::UnsealState::Expired) => "expired".to_string(),
        Ok(pb::UnsealState::Failed) => "failed".to_string(),
        Ok(pb::UnsealState::Unspecified) | Err(_) => "unspecified".to_string(),
    }
}

fn grpc_error(status: tonic::Status) -> String {
    format!("{}: {}", status.code(), status.message())
}

fn holder_error(error: HolderError) -> String {
    match error {
        HolderError::InvalidPassphraseOrCorrupt => "口令错误或文件已损坏".to_string(),
        HolderError::AlreadyExists => "目标文件已存在，请选择其他路径".to_string(),
        HolderError::InvalidHolderId => "Holder ID 无效（1-64 位字母、数字或 . _ -）".to_string(),
        HolderError::InvalidCeremonyId => "ceremony id 无效".to_string(),
        HolderError::EmptyPassphrase => "口令不能为空".to_string(),
        HolderError::InvalidIdentity => "身份文件格式无效".to_string(),
        HolderError::InvalidVault => "vault 文件格式无效".to_string(),
        HolderError::InvalidPublicBundle => "公开信息文件格式无效".to_string(),
        HolderError::InvalidManifest => "manifest 格式无效".to_string(),
        HolderError::InvalidManifestSignature => "manifest 签名验证失败".to_string(),
        HolderError::OperatorFingerprintMismatch => {
            "operator 公钥指纹与带外核对值不一致".to_string()
        }
        HolderError::HolderNotInManifest => "manifest 中没有当前 holder".to_string(),
        HolderError::HolderMismatch => "manifest 中的公钥与当前身份不匹配".to_string(),
        HolderError::EnvelopeHashMismatch => "份额信封哈希与 manifest 不匹配".to_string(),
        HolderError::InvalidShare => "份额格式无效".to_string(),
        HolderError::IndexMismatch => "份额索引与 manifest 不匹配".to_string(),
        HolderError::VssRejected => "份额未通过 VSS 验证".to_string(),
        HolderError::InvalidKdfParams => "文件中的 KDF 参数超出允许范围".to_string(),
        HolderError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            "文件不存在".to_string()
        }
        HolderError::Io(_) | HolderError::Json(_) | HolderError::Share(_) | HolderError::Crypto => {
            "本地文件或密码学操作失败".to_string()
        }
    }
}

async fn blocking<T, F>(task: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    spawn_blocking(task)
        .await
        .map_err(|error| format!("后台任务失败: {error}"))?
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TlsSettings {
    pub ca_cert_path: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    pub domain: Option<String>,
}

impl TlsSettings {
    fn validate(&self) -> Result<(), String> {
        if self.ca_cert_path.trim().is_empty()
            || self.client_cert_path.trim().is_empty()
            || self.client_key_path.trim().is_empty()
        {
            return Err("mTLS 需要同时填写 CA 证书、客户端证书和客户端私钥".to_string());
        }
        if self
            .domain
            .as_deref()
            .is_some_and(|domain| domain.trim().is_empty())
        {
            return Err("TLS domain 不能为空；不需要时请留空".to_string());
        }
        Ok(())
    }
}

fn target_url(server_url: &str, tls_enabled: bool) -> Result<String, String> {
    if tls_enabled {
        if server_url.contains("://") {
            if server_url.starts_with("https://") {
                Ok(server_url.to_string())
            } else {
                Err("启用 mTLS 时 gRPC 地址必须使用 https://".to_string())
            }
        } else {
            Ok(format!("https://{server_url}"))
        }
    } else if server_url.starts_with("https://") {
        Err("https:// 地址需要先配置 mTLS 证书".to_string())
    } else if let Some((scheme, _)) = server_url.split_once("://") {
        if scheme == "http" {
            Ok(server_url.to_string())
        } else {
            Err("gRPC 地址必须使用 http:// 或 https://".to_string())
        }
    } else {
        Ok(format!("http://{server_url}"))
    }
}

async fn connect(
    server_url: &str,
    tls: Option<&TlsSettings>,
) -> Result<SignerServiceClient<Channel>, String> {
    let target = target_url(server_url, tls.is_some())?;
    let mut endpoint =
        Channel::from_shared(target).map_err(|error| format!("invalid server URL: {error}"))?;

    if let Some(tls) = tls {
        tls.validate()?;
        let ca = std::fs::read(&tls.ca_cert_path)
            .map_err(|error| format!("读取 CA 证书失败: {error}"))?;
        let cert = std::fs::read(&tls.client_cert_path)
            .map_err(|error| format!("读取客户端证书失败: {error}"))?;
        let key = Zeroizing::new(
            std::fs::read(&tls.client_key_path)
                .map_err(|error| format!("读取客户端私钥失败: {error}"))?,
        );

        let mut config = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, key.as_slice()));
        if let Some(domain) = &tls.domain {
            config = config.domain_name(domain.trim());
        }
        endpoint = endpoint
            .tls_config(config)
            .map_err(|error| format!("配置 mTLS 失败: {error}"))?;
    }

    let channel = endpoint
        .connect()
        .await
        .map_err(|error| format!("failed to connect to signer: {error}"))?;
    Ok(SignerServiceClient::new(channel))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn start_unseal(
    server_url: String,
    tls: Option<TlsSettings>,
) -> Result<SessionView, String> {
    let mut client = connect(&server_url, tls.as_ref()).await?;
    let response = client
        .start_unseal(pb::StartUnsealRequest {})
        .await
        .map_err(grpc_error)?
        .into_inner();

    Ok(SessionView::from_start(response))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn get_status(
    server_url: String,
    session_id: String,
    tls: Option<TlsSettings>,
) -> Result<SessionView, String> {
    let mut client = connect(&server_url, tls.as_ref()).await?;
    let status = client
        .get_unseal_status(pb::GetUnsealStatusRequest { session_id })
        .await
        .map_err(grpc_error)?
        .into_inner();

    Ok(SessionView::from_status(status))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn seal(server_url: String, tls: Option<TlsSettings>) -> Result<bool, String> {
    let mut client = connect(&server_url, tls.as_ref()).await?;
    let response = client
        .seal(pb::SealRequest {})
        .await
        .map_err(grpc_error)?
        .into_inner();

    Ok(response.sealed)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn holder_create_identity(
    holder_id: String,
    passphrase: String,
    identity_path: String,
    public_path: String,
) -> Result<IdentityView, String> {
    let passphrase = Zeroizing::new(passphrase);

    blocking(move || {
        let identity = HolderIdentity::generate(&holder_id).map_err(holder_error)?;
        let bundle = identity
            .save_encrypted(Path::new(&identity_path), &passphrase)
            .map_err(holder_error)?;
        let public_json = bundle.to_json_pretty().map_err(holder_error)?;
        signer_holder::write_atomic(Path::new(&public_path), public_json.as_bytes(), false)
            .map_err(holder_error)?;
        let fingerprint = bundle.fingerprint().map_err(holder_error)?;

        Ok(IdentityView {
            holder_id: bundle.holder_id,
            ed25519_public: bundle.ed25519_public,
            x25519_public: bundle.x25519_public,
            fingerprint,
            identity_path,
            public_path,
        })
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn holder_export_public(
    identity_path: String,
    passphrase: String,
    public_path: String,
) -> Result<PublicBundleView, String> {
    let passphrase = Zeroizing::new(passphrase);

    blocking(move || {
        let identity = HolderIdentity::load_encrypted(Path::new(&identity_path), &passphrase)
            .map_err(holder_error)?;
        let bundle = identity.public_bundle();
        let public_json = bundle.to_json_pretty().map_err(holder_error)?;
        signer_holder::write_atomic(Path::new(&public_path), public_json.as_bytes(), true)
            .map_err(holder_error)?;
        let fingerprint = bundle.fingerprint().map_err(holder_error)?;

        Ok(PublicBundleView {
            holder_id: bundle.holder_id,
            ed25519_public: bundle.ed25519_public,
            x25519_public: bundle.x25519_public,
            fingerprint,
            public_path,
        })
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
#[allow(clippy::too_many_arguments)]
pub async fn holder_import_share(
    identity_path: String,
    share_path: String,
    vault_path: String,
    passphrase: String,
    manifest_path: Option<String>,
    manifest_sig_path: Option<String>,
    operator_pub_path: Option<String>,
    expected_operator_fingerprint: Option<String>,
) -> Result<ImportResult, String> {
    let package_present =
        manifest_path.is_some() || manifest_sig_path.is_some() || operator_pub_path.is_some();
    let package_complete =
        manifest_path.is_some() && manifest_sig_path.is_some() && operator_pub_path.is_some();
    let expected_operator_fingerprint = expected_operator_fingerprint
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());

    if package_present && !package_complete {
        return Err("manifest、manifest.sig、operator.pub 必须同时提供或同时留空".to_string());
    }
    if !package_present && expected_operator_fingerprint.is_some() {
        return Err("未提供 manifest 时无法核对 operator 指纹".to_string());
    }

    let passphrase = Zeroizing::new(passphrase);

    blocking(move || {
        let identity = HolderIdentity::load_encrypted(Path::new(&identity_path), &passphrase)
            .map_err(holder_error)?;
        let envelope =
            std::fs::read(&share_path).map_err(|error| format!("读取份额文件失败: {error}"))?;

        let imported = if let (Some(manifest_path), Some(sig_path), Some(pub_path)) =
            (manifest_path, manifest_sig_path, operator_pub_path)
        {
            let manifest_bytes = std::fs::read(&manifest_path)
                .map_err(|error| format!("读取 manifest 失败: {error}"))?;
            let signature_text = std::fs::read_to_string(&sig_path)
                .map_err(|error| format!("读取 manifest 签名失败: {error}"))?;
            let public_text = std::fs::read_to_string(&pub_path)
                .map_err(|error| format!("读取 operator 公钥失败: {error}"))?;
            let signature = decode_signature(&signature_text).map_err(holder_error)?;
            let operator_public = decode_operator_public(&public_text).map_err(holder_error)?;

            if let Some(expected) = expected_operator_fingerprint.as_deref() {
                let actual = operator_fingerprint(&operator_public);
                if expected != actual {
                    return Err(holder_error(HolderError::OperatorFingerprintMismatch));
                }
            }

            import_share(
                &identity,
                &envelope,
                Some(ManifestPackage {
                    manifest_bytes: &manifest_bytes,
                    signature: &signature,
                    operator_public: &operator_public,
                }),
            )
            .map_err(holder_error)?
        } else {
            import_share(&identity, &envelope, None).map_err(holder_error)?
        };

        let operator_fingerprint = imported.operator_fingerprint.clone();
        let vault = imported
            .seal(Path::new(&vault_path), &passphrase)
            .map_err(holder_error)?;

        Ok(ImportResult {
            vault,
            operator_fingerprint,
        })
    })
    .await
}

#[tauri::command(rename_all = "snake_case")]
pub fn holder_vault_info(vault_path: String) -> Result<VaultInfo, String> {
    ShareVault::info(Path::new(&vault_path)).map_err(holder_error)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn holder_submit_from_vault(
    server_url: String,
    session_id: String,
    identity_path: String,
    vault_path: String,
    passphrase: String,
    tls: Option<TlsSettings>,
) -> Result<SessionView, String> {
    let mut client = connect(&server_url, tls.as_ref()).await?;

    let status = client
        .get_unseal_status(pb::GetUnsealStatusRequest {
            session_id: session_id.clone(),
        })
        .await
        .map_err(grpc_error)?
        .into_inner();

    let nonce: [u8; 32] = status
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| "服务端返回的会话 nonce 无效".to_string())?;
    let session_public: [u8; 32] = status
        .session_public_key
        .as_slice()
        .try_into()
        .map_err(|_| "服务端返回的会话公钥无效".to_string())?;

    let passphrase = Zeroizing::new(passphrase);
    let submission_session_id = session_id.clone();

    let (holder_id, share_index, ciphertext, signature) = blocking(move || {
        let identity = HolderIdentity::load_encrypted(Path::new(&identity_path), &passphrase)
            .map_err(holder_error)?;
        let (info, share) =
            ShareVault::open(Path::new(&vault_path), &passphrase).map_err(holder_error)?;

        if info.holder_id != identity.holder_id() {
            return Err("vault 与身份文件不属于同一个 holder".to_string());
        }
        if info.index == 0 {
            return Err("vault 中的份额索引无效".to_string());
        }

        let context = signer_share::submission_context(
            &submission_session_id,
            &nonce,
            &session_public,
            &info.holder_id,
            info.index,
        )
        .map_err(|_| "构建提交上下文失败".to_string())?;
        let ciphertext =
            signer_share::encrypt_share_with_context(&session_public, &share, &context)
                .map_err(|_| "加密份额失败".to_string())?;
        let signature = identity.sign(&signer_share::submission_signing_input(
            &context,
            &ciphertext,
        ));

        Ok((info.holder_id, info.index, ciphertext, signature.to_vec()))
    })
    .await?;

    client
        .submit_unseal_share(pb::SubmitUnsealShareRequest {
            session_id: session_id.clone(),
            share_holder_id: holder_id,
            encrypted_share: ciphertext,
            signature,
            share_index: u32::from(share_index),
            nonce: nonce.to_vec(),
        })
        .await
        .map_err(grpc_error)?;

    let status = client
        .get_unseal_status(pb::GetUnsealStatusRequest { session_id })
        .await
        .map_err(grpc_error)?
        .into_inner();

    Ok(SessionView::from_status(status))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(target_url("http://127.0.0.1:50051", true).is_err());
        assert!(target_url("https://signer.test:50051", false).is_err());
        assert!(target_url("grpc://127.0.0.1:50051", false).is_err());
    }

    #[test]
    fn tls_settings_require_all_paths() {
        let mut settings = TlsSettings {
            ca_cert_path: String::new(),
            client_cert_path: "client.crt".to_string(),
            client_key_path: "client.key".to_string(),
            domain: None,
        };
        assert!(settings.validate().is_err());

        settings.ca_cert_path = "ca.crt".to_string();
        assert!(settings.validate().is_ok());

        settings.domain = Some(" ".to_string());
        assert!(settings.validate().is_err());
    }
}
