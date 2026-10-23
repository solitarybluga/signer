//! mTLS server configuration and client-certificate identity extraction.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use tonic::service::Interceptor;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Request, Status};
use x509_parser::prelude::GeneralName;
use zeroize::Zeroizing;

use crate::config::{ConfigError, TlsConfig};
use crate::permissions::PermissionSet;

const MAX_IDENTITY_LEN: usize = 128;

/// Authenticated identity extracted from a client certificate.
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor: String,
    pub holder_ids: Vec<String>,
    pub permissions: PermissionSet,
    pub fingerprint: [u8; 32],
}

/// Reads the server certificate, key and client CA, and builds tonic's TLS config.
///
/// Client authentication is optional at the TLS layer so a missing certificate
/// reaches the interceptor and becomes `UNAUTHENTICATED` instead of a transport
/// error. The interceptor always requires a client certificate.
pub fn server_tls_config(tls: &TlsConfig) -> Result<ServerTlsConfig, ConfigError> {
    let cert = read_pem(&tls.cert_path)?;
    let key = Zeroizing::new(read_pem(&tls.key_path)?);
    let ca = read_pem(&tls.client_ca_path)?;

    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key.as_slice()))
        .client_ca_root(Certificate::from_pem(ca))
        .client_auth_optional(true))
}

fn read_pem(path: &Path) -> Result<Vec<u8>, ConfigError> {
    let bytes = fs::read(path).map_err(|source| ConfigError::TlsFile {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.is_empty() {
        return Err(ConfigError::TlsFileEmpty {
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}

/// Interceptor that authenticates a client certificate and extracts its
/// principal, holder bindings and permission bits into request extensions.
#[derive(Clone)]
pub struct ClientCertInterceptor {
    principal_uri_prefix: String,
    holder_uri_prefix: String,
    permission_uri_prefix: String,
}

impl ClientCertInterceptor {
    pub fn new(tls: &TlsConfig) -> Self {
        Self {
            principal_uri_prefix: tls.principal_uri_prefix.clone(),
            holder_uri_prefix: tls.holder_uri_prefix.clone(),
            permission_uri_prefix: tls.permission_uri_prefix.clone(),
        }
    }
}

impl Interceptor for ClientCertInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let info = request
            .extensions()
            .get::<TlsConnectInfo<TcpConnectInfo>>()
            .ok_or_else(|| Status::unauthenticated("TLS connection info is missing"))?;
        let certs = info
            .peer_certs()
            .ok_or_else(|| Status::unauthenticated("client certificate is missing"))?;
        let leaf = certs
            .first()
            .ok_or_else(|| Status::unauthenticated("client certificate chain is empty"))?;

        let principal = parse_principal(
            leaf.as_ref(),
            &self.principal_uri_prefix,
            &self.holder_uri_prefix,
            &self.permission_uri_prefix,
        )?;
        tracing::debug!(
            actor = %principal.actor,
            fingerprint = %principal.fingerprint_hex(),
            "client certificate authenticated"
        );

        request.extensions_mut().insert(principal);
        Ok(request)
    }
}

fn parse_principal(
    der: &[u8],
    principal_prefix: &str,
    holder_prefix: &str,
    permission_prefix: &str,
) -> Result<Principal, Status> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|_| Status::unauthenticated("invalid client certificate"))?;

    if let Some(basic) = cert
        .basic_constraints()
        .map_err(|_| Status::unauthenticated("invalid client certificate constraints"))?
        && basic.value.ca
    {
        return Err(Status::permission_denied(
            "client certificate must not be a CA certificate",
        ));
    }

    match cert
        .extended_key_usage()
        .map_err(|_| Status::unauthenticated("invalid client certificate key usage"))?
    {
        Some(usage) if usage.value.client_auth => {}
        _ => {
            return Err(Status::permission_denied(
                "client certificate is not valid for client authentication",
            ));
        }
    }

    if let Some(key_usage) = cert
        .key_usage()
        .map_err(|_| Status::unauthenticated("invalid client certificate key usage"))?
        && !key_usage.value.digital_signature()
    {
        return Err(Status::permission_denied(
            "client certificate cannot be used for digital signatures",
        ));
    }

    let san = cert
        .subject_alternative_name()
        .map_err(|_| Status::unauthenticated("invalid client certificate SAN"))?
        .ok_or_else(|| Status::unauthenticated("client certificate has no SAN"))?;

    let mut principals = Vec::new();
    let mut holders = BTreeSet::new();
    let mut permission_values = Vec::new();

    for name in &san.value.general_names {
        let GeneralName::URI(uri) = name else {
            continue;
        };

        if let Some(value) = uri.strip_prefix(principal_prefix) {
            principals.push(value.to_string());
        } else if let Some(value) = uri.strip_prefix(holder_prefix) {
            holders.insert(value.to_string());
        } else if let Some(value) = uri.strip_prefix(permission_prefix) {
            permission_values.push(value.to_string());
        }
    }

    if principals.is_empty() {
        return Err(Status::unauthenticated(
            "client certificate has no principal",
        ));
    }
    if principals.len() > 1 {
        return Err(Status::permission_denied(
            "client certificate has multiple principals",
        ));
    }

    let actor = principals.pop().expect("one principal was checked");
    validate_identity(&actor, "principal")?;

    let mut holder_ids = Vec::with_capacity(holders.len());
    for holder in holders {
        validate_identity(&holder, "holder")?;
        holder_ids.push(holder);
    }

    let permissions = match permission_values.as_slice() {
        [] => PermissionSet::NONE,
        [value] => PermissionSet::parse(value).map_err(|_| {
            Status::permission_denied("client certificate has an invalid permission mask")
        })?,
        _ => {
            return Err(Status::permission_denied(
                "client certificate has multiple permission sets",
            ));
        }
    };

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&Sha256::digest(der));

    Ok(Principal {
        actor,
        holder_ids,
        permissions,
        fingerprint,
    })
}

fn validate_identity(value: &str, kind: &str) -> Result<(), Status> {
    if value.is_empty() || value.len() > MAX_IDENTITY_LEN || value.chars().any(char::is_control) {
        return Err(Status::permission_denied(format!(
            "client certificate {kind} is invalid"
        )));
    }
    Ok(())
}

impl Principal {
    /// Hex SHA-256 of the leaf certificate DER.
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DEFAULT_HOLDER_URI_PREFIX, DEFAULT_PERMISSION_URI_PREFIX, DEFAULT_PRINCIPAL_URI_PREFIX,
        TlsConfig,
    };
    use crate::permissions::Permission;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mtls");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).expect("test fixture exists")
    }

    fn parse(name: &str) -> Result<Principal, Status> {
        parse_principal(
            &fixture(name),
            DEFAULT_PRINCIPAL_URI_PREFIX,
            DEFAULT_HOLDER_URI_PREFIX,
            DEFAULT_PERMISSION_URI_PREFIX,
        )
    }

    #[test]
    fn parses_principal_holder_and_permissions() {
        let principal = parse("client-alice.der").unwrap();
        assert_eq!(principal.actor, "alice");
        assert_eq!(principal.holder_ids, vec!["holder-1".to_string()]);
        assert!(principal.permissions.contains(Permission::UnsealStart));
        assert!(principal.permissions.contains(Permission::UnsealStatus));
        assert!(principal.permissions.contains(Permission::KeyRead));
        assert!(!principal.permissions.contains(Permission::KeySign));
        assert_eq!(principal.fingerprint_hex().len(), 64);
        assert!(principal.fingerprint.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn parses_read_only_and_signer_masks() {
        let bob = parse("client-bob.der").unwrap();
        assert!(bob.permissions.contains(Permission::KeyRead));
        assert!(!bob.permissions.contains(Permission::KeySign));
        assert!(bob.holder_ids.is_empty());

        let carol = parse("client-carol.der").unwrap();
        assert!(carol.permissions.contains(Permission::KeyRead));
        assert!(carol.permissions.contains(Permission::KeySign));
        assert!(!carol.permissions.contains(Permission::UnsealStart));

        let dave = parse("client-dave.der").unwrap();
        assert_eq!(dave.permissions, PermissionSet::NONE);
    }

    #[test]
    fn rejects_reserved_permission_bits() {
        let error = parse("client-eve.der").unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn rejects_server_certificate_as_client_certificate() {
        let error = parse("server.der").unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn rejects_invalid_identity_lengths() {
        assert!(validate_identity("", "principal").is_err());
        assert!(validate_identity("alice", "principal").is_ok());
        assert!(validate_identity(&"a".repeat(MAX_IDENTITY_LEN + 1), "principal").is_err());
        assert!(validate_identity("ali\nce", "principal").is_err());
    }

    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use signer_core::storage::SqliteStore;
    use signer_core::unseal::{HolderIndex, UnsealConfig, UnsealManager};
    use signer_proto::pb;
    use signer_proto::pb::signer_service_client::SignerServiceClient;
    use signer_proto::pb::signer_service_server::SignerServiceServer;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::service::InterceptorLayer;
    use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Server};

    use crate::grpc::SignerGrpc;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(format!("{FIXTURES}/{name}"))
    }

    fn fixture_tls_config() -> TlsConfig {
        TlsConfig {
            cert_path: fixture_path("server.pem"),
            key_path: fixture_path("server.key"),
            client_ca_path: fixture_path("ca.pem"),
            principal_uri_prefix: DEFAULT_PRINCIPAL_URI_PREFIX.to_string(),
            holder_uri_prefix: DEFAULT_HOLDER_URI_PREFIX.to_string(),
            permission_uri_prefix: DEFAULT_PERMISSION_URI_PREFIX.to_string(),
        }
    }

    async fn start_test_server(
        tls: &TlsConfig,
    ) -> (
        std::net::SocketAddr,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let holder_key = SigningKey::from_bytes(&[1u8; 32]);
        let holders = vec![HolderIndex {
            id: "holder-1".to_string(),
            index: 1,
            ed25519_public: hex::encode(holder_key.verifying_key().to_bytes()),
        }];
        let (manager, _, _) = UnsealManager::bootstrap(UnsealConfig::new(1, 1), holders).unwrap();
        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        let signer = SignerGrpc::with_sign_audit(Arc::new(manager), store, true)
            .with_client_permissions(true);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server = Server::builder()
            .tls_config(server_tls_config(tls).unwrap())
            .unwrap()
            .layer(InterceptorLayer::new(ClientCertInterceptor::new(tls)))
            .add_service(SignerServiceServer::new(signer));

        let handle = tokio::spawn(async move {
            let _ = server
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        (addr, shutdown_tx, handle)
    }

    async fn connect(
        addr: std::net::SocketAddr,
        client_identity: Option<(&[u8], &[u8])>,
    ) -> Result<SignerServiceClient<Channel>, String> {
        let ca = fixture("ca.pem");
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .domain_name("127.0.0.1");
        if let Some((cert, key)) = client_identity {
            tls = tls.identity(Identity::from_pem(cert, key));
        }
        let channel = Endpoint::from_shared(format!("https://{addr}"))
            .map_err(|error| error.to_string())?
            .tls_config(tls)
            .map_err(|error| error.to_string())?
            .connect()
            .await
            .map_err(|error| error.to_string())?;
        Ok(SignerServiceClient::new(channel))
    }

    async fn start_unseal_code(
        addr: std::net::SocketAddr,
        client_identity: Option<(&[u8], &[u8])>,
    ) -> Result<(), tonic::Code> {
        let mut client = connect(addr, client_identity)
            .await
            .map_err(|_| tonic::Code::Unavailable)?;
        client
            .start_unseal(pb::StartUnsealRequest {})
            .await
            .map(|_| ())
            .map_err(|status| status.code())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtls_enforces_client_certificates_and_permissions() {
        let tls = fixture_tls_config();
        let (addr, shutdown_tx, handle) = start_test_server(&tls).await;

        let alice_cert = fixture("client-alice.pem");
        let alice_key = fixture("client-alice.key");
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            start_unseal_code(addr, Some((&alice_cert, &alice_key))),
        )
        .await
        .expect("valid client did not finish");
        assert_eq!(result, Ok(()));

        let result = tokio::time::timeout(Duration::from_secs(5), start_unseal_code(addr, None))
            .await
            .expect("missing certificate did not finish");
        assert_eq!(result, Err(tonic::Code::Unauthenticated));

        let bob_cert = fixture("client-bob.pem");
        let bob_key = fixture("client-bob.key");
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            start_unseal_code(addr, Some((&bob_cert, &bob_key))),
        )
        .await
        .expect("read-only client did not finish");
        assert_eq!(result, Err(tonic::Code::PermissionDenied));

        let eve_cert = fixture("client-eve.pem");
        let eve_key = fixture("client-eve.key");
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            start_unseal_code(addr, Some((&eve_cert, &eve_key))),
        )
        .await
        .expect("reserved-bit client did not finish");
        assert_eq!(result, Err(tonic::Code::PermissionDenied));

        let rogue_cert = fixture("client-rogue.pem");
        let rogue_key = fixture("client-rogue.key");
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            start_unseal_code(addr, Some((&rogue_cert, &rogue_key))),
        )
        .await
        .expect("rogue client did not finish");
        assert!(result.is_err());

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
}
