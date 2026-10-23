//! CSR, CA and certificate helpers for signer mTLS.
//!
//! The CA is the authorization root. Signing a CSR never copies the requested
//! SANs or extensions: the caller supplies the approved principal, holder IDs,
//! permission bits and server SANs, and those are written into the certificate.
//! The CSR is only used for its public key, after its self-signature has been
//! verified.

use std::collections::BTreeSet;
use std::net::IpAddr;

use pkcs8::der::pem::{decode_label, decode_vec, encode_string};
use pkcs8::{EncryptedPrivateKeyInfoRef, LineEnding, PrivateKeyInfoRef};
use rand::RngCore;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use sha2::{Digest, Sha256};
use signer_permissions::{
    DEFAULT_HOLDER_URI_PREFIX, DEFAULT_PERMISSION_URI_PREFIX, DEFAULT_PRINCIPAL_URI_PREFIX,
    PermissionSet, holder_uri, is_valid_identity, permission_uri, principal_uri,
};
use time::{Duration, OffsetDateTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::GeneralName;
use x509_parser::time::ASN1Time;
use zeroize::Zeroizing;

/// Default validity for issued endpoint certificates.
pub const DEFAULT_CERT_DAYS: u32 = 825;
/// Default validity for a development CA.
pub const DEFAULT_CA_DAYS: u32 = 3650;

const MAX_CERT_DAYS: u32 = 3650;
const MAX_COMMON_NAME_LEN: usize = 64;
const MAX_SERVER_SANS: usize = 32;
const MAX_DNS_NAME_LEN: usize = 253;

/// CA certificate and encrypted private key, both PEM encoded.
///
/// This type deliberately does not implement `Debug`: the private key must not
/// end up in logs or error messages.
pub struct GeneratedCa {
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
}

/// Endpoint private key and CSR, both PEM encoded.
///
/// This type deliberately does not implement `Debug`.
pub struct GeneratedCsr {
    pub key_pem: Zeroizing<String>,
    pub csr_pem: String,
    pub key_encrypted: bool,
}

/// An issued certificate and its SHA-256 fingerprint.
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub cert_pem: String,
    pub fingerprint_sha256: String,
}

/// Identity fields extracted from a client certificate.
#[derive(Debug, Clone)]
pub struct ClientCertificateInfo {
    pub fingerprint_sha256: String,
    pub principal: String,
    pub holder_ids: Vec<String>,
    pub permissions: PermissionSet,
    pub not_after_unix: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("invalid PEM document")]
    InvalidPem,
    #[error("unsupported private key PEM label")]
    UnsupportedKeyLabel,
    #[error("private key passphrase is required")]
    KeyPassphraseRequired,
    #[error("private key passphrase is incorrect or the key is corrupt")]
    KeyDecryptFailed,
    #[error("invalid private key")]
    InvalidPrivateKey,
    #[error("CA private key must be encrypted with a passphrase")]
    CaKeyMustBeEncrypted,
    #[error("CA private key passphrase is incorrect or the key is corrupt")]
    CaKeyDecryptFailed,
    #[error("CA certificate is not a CA")]
    CaNotCa,
    #[error("CA certificate is not valid for certificate signing")]
    CaNotAuthorized,
    #[error("CA certificate is outside its validity period")]
    CaExpired,
    #[error("CA certificate and private key do not match")]
    CaKeyMismatch,
    #[error("invalid certificate signing request")]
    InvalidCsr,
    #[error("invalid common name")]
    InvalidCommonName,
    #[error("invalid principal")]
    InvalidPrincipal,
    #[error("invalid holder id: {0}")]
    InvalidHolder(String),
    #[error("invalid server SAN: {0}")]
    InvalidServerSan(String),
    #[error("at least one server SAN is required")]
    MissingServerSan,
    #[error("too many server SANs")]
    TooManyServerSans,
    #[error("invalid certificate validity")]
    InvalidValidity,
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("certificate and private key do not match")]
    KeyMismatch,
    #[error("certificate is not valid for client authentication")]
    NotClientCertificate,
    #[error("certificate has no principal")]
    NoPrincipal,
    #[error("certificate has multiple principals")]
    MultiplePrincipals,
    #[error("certificate has multiple permission sets")]
    MultiplePermissionSets,
    #[error("certificate permission mask is invalid")]
    InvalidPermissions,
    #[error("certificate is not yet valid")]
    CertificateNotYetValid,
    #[error("certificate has expired")]
    CertificateExpired,
    #[error("certificate was not issued by the supplied CA")]
    CertificateIssuerMismatch,
    #[error("certificate signature verification failed")]
    CertificateSignatureInvalid,
    #[error("cryptographic operation failed")]
    Crypto,
}

/// Generate a self-signed CA with an encrypted PKCS#8 private key.
pub fn generate_ca(
    common_name: &str,
    days: u32,
    passphrase: &str,
) -> Result<GeneratedCa, PkiError> {
    validate_common_name(common_name)?;
    if passphrase.is_empty() {
        return Err(PkiError::KeyPassphraseRequired);
    }

    let key = KeyPair::generate().map_err(|_| PkiError::Crypto)?;
    let (not_before, not_after) = validity(days)?;

    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.serial_number = Some(random_serial());
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.subject_alt_names.clear();
    params.use_authority_key_identifier_extension = false;

    let cert = params.self_signed(&key).map_err(|_| PkiError::Crypto)?;
    let key_pem = encrypt_key(&key, passphrase)?;
    Ok(GeneratedCa {
        cert_pem: cert.pem(),
        key_pem,
    })
}

/// Generate a client key and CSR.
///
/// The CSR requests the same SANs that the CA is expected to approve, but the
/// CA must ignore them and use its own approved values. When
/// `key_passphrase` is `Some`, the private key is encrypted with PKCS#8
/// PBES2; `None` writes an unencrypted PKCS#8 key.
pub fn generate_client_csr(
    principal: &str,
    holder_ids: &[String],
    permissions: PermissionSet,
    key_passphrase: Option<&str>,
    common_name: Option<&str>,
) -> Result<GeneratedCsr, PkiError> {
    let sans = client_sans(principal, holder_ids, permissions)?;
    let default_cn = default_client_common_name(principal);
    let common_name = common_name.unwrap_or(&default_cn);
    generate_csr(LeafKind::Client, common_name, sans, key_passphrase)
}

/// Generate a server key and CSR.
pub fn generate_server_csr(
    server_sans: &[String],
    key_passphrase: Option<&str>,
    common_name: Option<&str>,
) -> Result<GeneratedCsr, PkiError> {
    let sans = parse_server_sans(server_sans)?;
    let default_cn = default_server_common_name(&sans);
    let common_name = common_name.unwrap_or(&default_cn);
    generate_csr(LeafKind::Server, common_name, sans, key_passphrase)
}

/// Sign a client CSR with approved identity fields.
///
/// The CSR's requested SANs, key usages, validity and extensions are ignored.
/// Only its public key and verified self-signature are used.
#[allow(clippy::too_many_arguments)]
pub fn sign_client_csr(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    ca_passphrase: &str,
    csr_pem: &str,
    principal: &str,
    holder_ids: &[String],
    permissions: PermissionSet,
    common_name: Option<&str>,
    days: u32,
) -> Result<IssuedCertificate, PkiError> {
    let sans = client_sans(principal, holder_ids, permissions)?;
    let default_cn = default_client_common_name(principal);
    let common_name = common_name.unwrap_or(&default_cn);
    let params = leaf_params(LeafKind::Client, common_name, sans, days)?;
    sign_csr(ca_cert_pem, ca_key_pem, ca_passphrase, csr_pem, params)
}

/// Sign a server CSR with approved SANs.
#[allow(clippy::too_many_arguments)]
pub fn sign_server_csr(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    ca_passphrase: &str,
    csr_pem: &str,
    server_sans: &[String],
    common_name: Option<&str>,
    days: u32,
) -> Result<IssuedCertificate, PkiError> {
    let sans = parse_server_sans(server_sans)?;
    let default_cn = default_server_common_name(&sans);
    let common_name = common_name.unwrap_or(&default_cn);
    let params = leaf_params(LeafKind::Server, common_name, sans, days)?;
    sign_csr(ca_cert_pem, ca_key_pem, ca_passphrase, csr_pem, params)
}

/// Load a PEM private key, decrypting PKCS#8 PBES2 when necessary.
///
/// Returns an unencrypted `PRIVATE KEY` PEM wrapped in [`Zeroizing`].
pub fn load_private_key_pem(
    key_pem: &str,
    passphrase: Option<&str>,
) -> Result<Zeroizing<String>, PkiError> {
    let (label, der) = decode_vec(key_pem.as_bytes()).map_err(|_| PkiError::InvalidPem)?;
    let der = Zeroizing::new(der);

    match label {
        "PRIVATE KEY" => Ok(Zeroizing::new(key_pem.to_string())),
        "ENCRYPTED PRIVATE KEY" => {
            let passphrase = passphrase
                .filter(|value| !value.is_empty())
                .ok_or(PkiError::KeyPassphraseRequired)?;
            let encrypted = EncryptedPrivateKeyInfoRef::try_from(der.as_slice())
                .map_err(|_| PkiError::InvalidPrivateKey)?;
            let plaintext = encrypted
                .decrypt(passphrase)
                .map_err(|_| PkiError::KeyDecryptFailed)?;
            let pem = encode_string("PRIVATE KEY", LineEnding::LF, plaintext.as_bytes())
                .map_err(|_| PkiError::Crypto)?;
            Ok(Zeroizing::new(pem))
        }
        _ => Err(PkiError::UnsupportedKeyLabel),
    }
}

/// Returns whether the PEM document is an encrypted PKCS#8 private key.
pub fn is_encrypted_private_key_pem(key_pem: &str) -> bool {
    decode_label(key_pem.as_bytes()).is_ok_and(|label| label == "ENCRYPTED PRIVATE KEY")
}

/// Verify that a certificate and a private key belong together.
pub fn certificate_matches_key(
    cert_pem: &str,
    key_pem: &str,
    key_passphrase: Option<&str>,
) -> Result<(), PkiError> {
    let cert_der = decode_cert_pem(cert_pem)?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&cert_der).map_err(|_| PkiError::InvalidCertificate)?;
    let key_pem = load_private_key_pem(key_pem, key_passphrase)?;
    let key = KeyPair::from_pem(&key_pem).map_err(|_| PkiError::InvalidPrivateKey)?;
    let public_pem = key.public_key_pem();
    let (label, spki) = decode_vec(public_pem.as_bytes()).map_err(|_| PkiError::Crypto)?;
    if label == "PUBLIC KEY" && spki.as_slice() == cert.public_key().raw {
        Ok(())
    } else {
        Err(PkiError::KeyMismatch)
    }
}

/// Parse the identity fields of a client certificate without chaining it to a CA.
pub fn inspect_client_certificate(cert_pem: &str) -> Result<ClientCertificateInfo, PkiError> {
    let cert_der = decode_cert_pem(cert_pem)?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&cert_der).map_err(|_| PkiError::InvalidCertificate)?;
    inspect_client(&cert, &cert_der)
}

/// Verify a client certificate, its CA signature and its private key.
///
/// This checks the leaf EKU, validity, issuer name, CA basic constraints and
/// key usage, the certificate signature and that the private key matches.
pub fn verify_client_certificate(
    cert_pem: &str,
    ca_cert_pem: &str,
    key_pem: &str,
    key_passphrase: Option<&str>,
) -> Result<ClientCertificateInfo, PkiError> {
    let cert_der = decode_cert_pem(cert_pem)?;
    let (_, cert) =
        x509_parser::parse_x509_certificate(&cert_der).map_err(|_| PkiError::InvalidCertificate)?;
    let info = inspect_client(&cert, &cert_der)?;

    let ca_der = decode_cert_pem(ca_cert_pem)?;
    let (_, ca) =
        x509_parser::parse_x509_certificate(&ca_der).map_err(|_| PkiError::InvalidCertificate)?;
    validate_ca(&ca)?;

    let now = ASN1Time::now();
    if !cert.validity().is_valid_at(now) {
        return Err(
            if cert.validity().not_before.timestamp() > now.timestamp() {
                PkiError::CertificateNotYetValid
            } else {
                PkiError::CertificateExpired
            },
        );
    }
    if cert.issuer().as_raw() != ca.subject().as_raw() {
        return Err(PkiError::CertificateIssuerMismatch);
    }
    cert.verify_signature(Some(ca.public_key()))
        .map_err(|_| PkiError::CertificateSignatureInvalid)?;

    certificate_matches_key(cert_pem, key_pem, key_passphrase)?;
    Ok(info)
}

/// SHA-256 fingerprint of the certificate DER, lowercase hex.
pub fn certificate_fingerprint_hex(cert_pem: &str) -> Result<String, PkiError> {
    let der = decode_cert_pem(cert_pem)?;
    Ok(hex::encode(Sha256::digest(&der)))
}

#[derive(Clone, Copy)]
enum LeafKind {
    Client,
    Server,
}

fn generate_csr(
    kind: LeafKind,
    common_name: &str,
    sans: Vec<SanType>,
    key_passphrase: Option<&str>,
) -> Result<GeneratedCsr, PkiError> {
    let key = KeyPair::generate().map_err(|_| PkiError::Crypto)?;
    let mut params = leaf_params(kind, common_name, sans, DEFAULT_CERT_DAYS)?;
    // rcgen rejects CSRs that request an authority key identifier extension;
    // the CA adds it when signing.
    params.use_authority_key_identifier_extension = false;
    let csr_pem = params
        .serialize_request(&key)
        .map_err(|_| PkiError::Crypto)?
        .pem()
        .map_err(|_| PkiError::Crypto)?;

    let (key_pem, key_encrypted) = match key_passphrase {
        Some("") => return Err(PkiError::KeyPassphraseRequired),
        Some(passphrase) => (encrypt_key(&key, passphrase)?, true),
        None => (Zeroizing::new(key.serialize_pem()), false),
    };

    Ok(GeneratedCsr {
        key_pem,
        csr_pem,
        key_encrypted,
    })
}

fn leaf_params(
    kind: LeafKind,
    common_name: &str,
    sans: Vec<SanType>,
    days: u32,
) -> Result<CertificateParams, PkiError> {
    validate_common_name(common_name)?;
    let (not_before, not_after) = validity(days)?;

    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.subject_alt_names = sans;
    params.is_ca = IsCa::ExplicitNoCa;
    params.name_constraints = None;
    params.crl_distribution_points.clear();
    params.custom_extensions.clear();
    params.use_authority_key_identifier_extension = true;

    match kind {
        LeafKind::Client => {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
        LeafKind::Server => {
            params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }
    }

    Ok(params)
}

fn sign_csr(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    ca_passphrase: &str,
    csr_pem: &str,
    mut params: CertificateParams,
) -> Result<IssuedCertificate, PkiError> {
    let ca_der = decode_cert_pem(ca_cert_pem)?;
    let (_, ca) =
        x509_parser::parse_x509_certificate(&ca_der).map_err(|_| PkiError::InvalidCertificate)?;
    validate_ca(&ca)?;

    let ca_key = load_ca_key_pair(ca_key_pem, ca_passphrase)?;
    if !ca_key_matches(&ca, &ca_key) {
        return Err(PkiError::CaKeyMismatch);
    }

    // `from_pem` verifies the CSR self-signature. The requested fields in
    // `csr.params` are intentionally discarded; only the public key is used.
    let csr =
        CertificateSigningRequestParams::from_pem(csr_pem).map_err(|_| PkiError::InvalidCsr)?;

    params.serial_number = Some(random_serial());
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, ca_key).map_err(|_| PkiError::Crypto)?;
    let cert = params
        .signed_by(&csr.public_key, &issuer)
        .map_err(|_| PkiError::Crypto)?;

    let cert_der = cert.der();
    let (_, issued) =
        x509_parser::parse_x509_certificate(cert_der.as_ref()).map_err(|_| PkiError::Crypto)?;
    issued
        .verify_signature(Some(ca.public_key()))
        .map_err(|_| PkiError::CertificateSignatureInvalid)?;

    Ok(IssuedCertificate {
        cert_pem: cert.pem(),
        fingerprint_sha256: hex::encode(Sha256::digest(cert_der.as_ref())),
    })
}

fn load_ca_key_pair(ca_key_pem: &str, passphrase: &str) -> Result<KeyPair, PkiError> {
    if !is_encrypted_private_key_pem(ca_key_pem) {
        return Err(PkiError::CaKeyMustBeEncrypted);
    }
    if passphrase.is_empty() {
        return Err(PkiError::CaKeyDecryptFailed);
    }
    let plaintext = load_private_key_pem(ca_key_pem, Some(passphrase))
        .map_err(|_| PkiError::CaKeyDecryptFailed)?;
    KeyPair::from_pem(&plaintext).map_err(|_| PkiError::CaKeyDecryptFailed)
}

fn ca_key_matches(ca: &X509Certificate<'_>, key: &KeyPair) -> bool {
    let public_pem = key.public_key_pem();
    let Ok((label, spki)) = decode_vec(public_pem.as_bytes()) else {
        return false;
    };
    label == "PUBLIC KEY" && spki.as_slice() == ca.public_key().raw
}

fn validate_ca(ca: &X509Certificate<'_>) -> Result<(), PkiError> {
    let basic = ca
        .basic_constraints()
        .map_err(|_| PkiError::InvalidCertificate)?
        .ok_or(PkiError::CaNotCa)?;
    if !basic.value.ca {
        return Err(PkiError::CaNotCa);
    }

    match ca.key_usage().map_err(|_| PkiError::InvalidCertificate)? {
        Some(usage) if usage.value.key_cert_sign() => {}
        _ => return Err(PkiError::CaNotAuthorized),
    }

    if !ca.validity().is_valid_at(ASN1Time::now()) {
        return Err(PkiError::CaExpired);
    }
    Ok(())
}

fn inspect_client(
    cert: &X509Certificate<'_>,
    cert_der: &[u8],
) -> Result<ClientCertificateInfo, PkiError> {
    if let Some(basic) = cert
        .basic_constraints()
        .map_err(|_| PkiError::InvalidCertificate)?
        && basic.value.ca
    {
        return Err(PkiError::InvalidCertificate);
    }

    match cert
        .extended_key_usage()
        .map_err(|_| PkiError::InvalidCertificate)?
    {
        Some(usage) if usage.value.client_auth => {}
        _ => return Err(PkiError::NotClientCertificate),
    }

    if let Some(usage) = cert.key_usage().map_err(|_| PkiError::InvalidCertificate)?
        && !usage.value.digital_signature()
    {
        return Err(PkiError::NotClientCertificate);
    }

    let san = cert
        .subject_alternative_name()
        .map_err(|_| PkiError::InvalidCertificate)?
        .ok_or(PkiError::NoPrincipal)?;

    let mut principals = Vec::new();
    let mut holders = BTreeSet::new();
    let mut permission_values = Vec::new();

    for name in &san.value.general_names {
        let GeneralName::URI(uri) = name else {
            continue;
        };
        if let Some(value) = uri.strip_prefix(DEFAULT_PRINCIPAL_URI_PREFIX) {
            principals.push(value.to_string());
        } else if let Some(value) = uri.strip_prefix(DEFAULT_HOLDER_URI_PREFIX) {
            holders.insert(value.to_string());
        } else if let Some(value) = uri.strip_prefix(DEFAULT_PERMISSION_URI_PREFIX) {
            permission_values.push(value.to_string());
        }
    }

    if principals.is_empty() {
        return Err(PkiError::NoPrincipal);
    }
    if principals.len() > 1 {
        return Err(PkiError::MultiplePrincipals);
    }
    let principal = principals.pop().expect("one principal was checked");
    if !is_valid_identity(&principal) {
        return Err(PkiError::InvalidPrincipal);
    }

    let mut holder_ids = Vec::with_capacity(holders.len());
    for holder in holders {
        if !is_valid_identity(&holder) {
            return Err(PkiError::InvalidHolder(holder));
        }
        holder_ids.push(holder);
    }

    let permissions = match permission_values.as_slice() {
        [] => PermissionSet::NONE,
        [value] => PermissionSet::parse(value).map_err(|_| PkiError::InvalidPermissions)?,
        _ => return Err(PkiError::MultiplePermissionSets),
    };

    Ok(ClientCertificateInfo {
        fingerprint_sha256: hex::encode(Sha256::digest(cert_der)),
        principal,
        holder_ids,
        permissions,
        not_after_unix: cert.validity().not_after.timestamp(),
    })
}

fn client_sans(
    principal: &str,
    holder_ids: &[String],
    permissions: PermissionSet,
) -> Result<Vec<SanType>, PkiError> {
    if !is_valid_identity(principal) || !principal.is_ascii() {
        return Err(PkiError::InvalidPrincipal);
    }

    let mut sans = Vec::with_capacity(holder_ids.len() + 2);
    sans.push(uri_san(
        principal_uri(principal),
        PkiError::InvalidPrincipal,
    )?);

    let mut holders = BTreeSet::new();
    for holder in holder_ids {
        if !is_valid_identity(holder) || !holder.is_ascii() {
            return Err(PkiError::InvalidHolder(holder.clone()));
        }
        holders.insert(holder.as_str());
    }
    for holder in holders {
        sans.push(uri_san(
            holder_uri(holder),
            PkiError::InvalidHolder(holder.to_string()),
        )?);
    }

    sans.push(uri_san(
        permission_uri(permissions),
        PkiError::InvalidPermissions,
    )?);
    Ok(sans)
}

fn uri_san(value: String, invalid: PkiError) -> Result<SanType, PkiError> {
    Ia5String::try_from(value)
        .map(SanType::URI)
        .map_err(|_| invalid)
}

fn parse_server_sans(values: &[String]) -> Result<Vec<SanType>, PkiError> {
    if values.is_empty() {
        return Err(PkiError::MissingServerSan);
    }
    if values.len() > MAX_SERVER_SANS {
        return Err(PkiError::TooManyServerSans);
    }

    let mut seen = BTreeSet::new();
    let mut sans = Vec::with_capacity(values.len());
    for value in values {
        let (san, display) = parse_server_san(value)?;
        if seen.insert(display) {
            sans.push(san);
        }
    }
    Ok(sans)
}

fn parse_server_san(value: &str) -> Result<(SanType, String), PkiError> {
    let value = value.trim();
    if value.is_empty() || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(PkiError::InvalidServerSan(value.to_string()));
    }

    let lower = value.to_ascii_lowercase();
    let (is_ip, raw) = if lower.starts_with("ip:") {
        (true, &value[3..])
    } else if lower.starts_with("dns:") {
        (false, &value[4..])
    } else {
        (value.parse::<IpAddr>().is_ok(), value)
    };

    if raw.is_empty() {
        return Err(PkiError::InvalidServerSan(value.to_string()));
    }

    if is_ip {
        let ip = raw
            .parse::<IpAddr>()
            .map_err(|_| PkiError::InvalidServerSan(value.to_string()))?;
        Ok((SanType::IpAddress(ip), ip.to_string()))
    } else {
        if raw.len() > MAX_DNS_NAME_LEN {
            return Err(PkiError::InvalidServerSan(value.to_string()));
        }
        let dns =
            Ia5String::try_from(raw).map_err(|_| PkiError::InvalidServerSan(value.to_string()))?;
        Ok((SanType::DnsName(dns), raw.to_string()))
    }
}

fn default_client_common_name(principal: &str) -> String {
    if principal.len() <= MAX_COMMON_NAME_LEN {
        principal.to_string()
    } else {
        "signer-client".to_string()
    }
}

fn default_server_common_name(sans: &[SanType]) -> String {
    let candidate = match &sans[0] {
        SanType::DnsName(value) => value.as_str().to_string(),
        SanType::IpAddress(ip) => ip.to_string(),
        _ => "signer-server".to_string(),
    };
    if candidate.len() <= MAX_COMMON_NAME_LEN {
        candidate
    } else {
        "signer-server".to_string()
    }
}

fn validate_common_name(value: &str) -> Result<(), PkiError> {
    if value.is_empty() || value.len() > MAX_COMMON_NAME_LEN || value.chars().any(char::is_control)
    {
        return Err(PkiError::InvalidCommonName);
    }
    Ok(())
}

fn validity(days: u32) -> Result<(OffsetDateTime, OffsetDateTime), PkiError> {
    if days == 0 || days > MAX_CERT_DAYS {
        return Err(PkiError::InvalidValidity);
    }
    let now = OffsetDateTime::now_utc();
    Ok((
        now - Duration::minutes(5),
        now + Duration::days(i64::from(days)),
    ))
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[0] = (bytes[0] & 0x7f) | 0x01;
    SerialNumber::from_slice(&bytes)
}

fn encrypt_key(key: &KeyPair, passphrase: &str) -> Result<Zeroizing<String>, PkiError> {
    let info = PrivateKeyInfoRef::try_from(key.serialized_der())
        .map_err(|_| PkiError::InvalidPrivateKey)?;
    let encrypted = info.encrypt(passphrase).map_err(|_| PkiError::Crypto)?;
    encrypted
        .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
        .map_err(|_| PkiError::Crypto)
}

fn decode_cert_pem(cert_pem: &str) -> Result<Vec<u8>, PkiError> {
    let (label, der) = decode_vec(cert_pem.as_bytes()).map_err(|_| PkiError::InvalidCertificate)?;
    if label != "CERTIFICATE" {
        return Err(PkiError::InvalidCertificate);
    }
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::KeyPair;
    use signer_permissions::Permission;

    fn parse_der(pem: &str) -> Vec<u8> {
        decode_vec(pem.as_bytes()).expect("valid PEM").1
    }

    fn make_ca() -> GeneratedCa {
        generate_ca("test-ca", 30, "ca-passphrase").expect("CA generation")
    }

    #[test]
    fn ca_key_is_encrypted_and_requires_the_passphrase() {
        let ca = make_ca();
        assert!(is_encrypted_private_key_pem(&ca.key_pem));
        assert!(matches!(
            load_private_key_pem(&ca.key_pem, None),
            Err(PkiError::KeyPassphraseRequired)
        ));
        assert!(matches!(
            load_private_key_pem(&ca.key_pem, Some("wrong")),
            Err(PkiError::KeyDecryptFailed)
        ));
        let plaintext =
            load_private_key_pem(&ca.key_pem, Some("ca-passphrase")).expect("correct passphrase");
        assert!(plaintext.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn client_csr_roundtrip_extracts_approved_identity() {
        let ca = make_ca();
        let permissions =
            PermissionSet::parse_list("unseal.start,key.read,key.sign").expect("permissions");
        let csr = generate_client_csr(
            "alice",
            &["holder-1".to_string()],
            permissions,
            Some("key-passphrase"),
            None,
        )
        .expect("client CSR");
        assert!(is_encrypted_private_key_pem(&csr.key_pem));

        let issued = sign_client_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &csr.csr_pem,
            "alice",
            &["holder-1".to_string()],
            permissions,
            None,
            30,
        )
        .expect("signed certificate");

        let info = verify_client_certificate(
            &issued.cert_pem,
            &ca.cert_pem,
            &csr.key_pem,
            Some("key-passphrase"),
        )
        .expect("verified certificate");
        assert_eq!(info.principal, "alice");
        assert_eq!(info.holder_ids, vec!["holder-1".to_string()]);
        assert_eq!(info.permissions, permissions);
        assert_eq!(info.fingerprint_sha256, issued.fingerprint_sha256);
        assert!(info.not_after_unix > OffsetDateTime::now_utc().unix_timestamp());

        assert!(matches!(
            verify_client_certificate(&issued.cert_pem, &ca.cert_pem, &csr.key_pem, Some("wrong"),),
            Err(PkiError::KeyDecryptFailed)
        ));
    }

    #[test]
    fn signing_overrides_csr_requested_sans() {
        let ca = make_ca();
        let requested = PermissionSet::parse_list("unseal.seal,key.sign").expect("permissions");
        let csr = generate_client_csr(
            "alice",
            &["holder-1".to_string()],
            requested,
            Some("key-passphrase"),
            None,
        )
        .expect("client CSR");

        let approved = PermissionSet::parse_list("key.read").expect("permissions");
        let issued = sign_client_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &csr.csr_pem,
            "bob",
            &["holder-2".to_string()],
            approved,
            None,
            30,
        )
        .expect("signed certificate");

        let info = verify_client_certificate(
            &issued.cert_pem,
            &ca.cert_pem,
            &csr.key_pem,
            Some("key-passphrase"),
        )
        .expect("verified certificate");
        assert_eq!(info.principal, "bob");
        assert_eq!(info.holder_ids, vec!["holder-2".to_string()]);
        assert_eq!(info.permissions, approved);
        assert!(!info.permissions.contains(Permission::UnsealSeal));
        assert!(!info.permissions.contains(Permission::KeySign));
    }

    #[test]
    fn signing_ignores_malicious_csr_sans() {
        let ca = make_ca();
        let key = KeyPair::generate().expect("CSR key");
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "mallory");
        params.subject_alt_names = vec![
            SanType::URI(
                Ia5String::try_from("signer://principal/mallory".to_string()).expect("URI"),
            ),
            SanType::URI(
                Ia5String::try_from("signer://permissions/0x400".to_string()).expect("URI"),
            ),
        ];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let csr_pem = params
            .serialize_request(&key)
            .expect("CSR")
            .pem()
            .expect("CSR PEM");
        let key_pem = key.serialize_pem();

        let approved = PermissionSet::parse_list("key.read").expect("permissions");
        let issued = sign_client_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &csr_pem,
            "alice",
            &[],
            approved,
            None,
            30,
        )
        .expect("signed certificate");
        let info = verify_client_certificate(&issued.cert_pem, &ca.cert_pem, &key_pem, None)
            .expect("verified certificate");
        assert_eq!(info.principal, "alice");
        assert_eq!(info.permissions, approved);
        assert!(info.holder_ids.is_empty());
    }

    #[test]
    fn tampered_csr_is_rejected() {
        let ca = make_ca();
        let csr = generate_client_csr(
            "alice",
            &["holder-1".to_string()],
            PermissionSet::NONE,
            Some("key-passphrase"),
            None,
        )
        .expect("client CSR");
        let mut der = parse_der(&csr.csr_pem);
        let last = der.len() - 1;
        der[last] ^= 0xff;
        let tampered =
            encode_string("CERTIFICATE REQUEST", LineEnding::LF, &der).expect("PEM encoding");

        let result = sign_client_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &tampered,
            "alice",
            &["holder-1".to_string()],
            PermissionSet::NONE,
            None,
            30,
        );
        assert!(matches!(result, Err(PkiError::InvalidCsr)));
    }

    #[test]
    fn rejects_non_ca_certificate_and_wrong_ca_key() {
        let ca = make_ca();
        let csr = generate_client_csr(
            "alice",
            &["holder-1".to_string()],
            PermissionSet::NONE,
            Some("key-passphrase"),
            None,
        )
        .expect("client CSR");
        let leaf = sign_client_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &csr.csr_pem,
            "alice",
            &["holder-1".to_string()],
            PermissionSet::NONE,
            None,
            30,
        )
        .expect("leaf certificate");

        let result = sign_client_csr(
            &leaf.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &csr.csr_pem,
            "alice",
            &["holder-1".to_string()],
            PermissionSet::NONE,
            None,
            30,
        );
        assert!(matches!(result, Err(PkiError::CaNotCa)));

        let other_ca = make_ca();
        let result = sign_client_csr(
            &ca.cert_pem,
            &other_ca.key_pem,
            "ca-passphrase",
            &csr.csr_pem,
            "alice",
            &["holder-1".to_string()],
            PermissionSet::NONE,
            None,
            30,
        );
        assert!(matches!(result, Err(PkiError::CaKeyMismatch)));
    }

    #[test]
    fn rejects_plaintext_ca_key_and_wrong_passphrase() {
        let ca = make_ca();
        let server =
            generate_server_csr(&["DNS:localhost".to_string()], None, None).expect("server CSR");
        let result = sign_server_csr(
            &ca.cert_pem,
            &server.key_pem,
            "ca-passphrase",
            &server.csr_pem,
            &["DNS:localhost".to_string()],
            None,
            30,
        );
        assert!(matches!(result, Err(PkiError::CaKeyMustBeEncrypted)));

        let result = sign_server_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "wrong",
            &server.csr_pem,
            &["DNS:localhost".to_string()],
            None,
            30,
        );
        assert!(matches!(result, Err(PkiError::CaKeyDecryptFailed)));
    }

    #[test]
    fn server_csr_roundtrip_has_server_sans_and_eku() {
        let ca = make_ca();
        let sans = vec!["DNS:localhost".to_string(), "IP:127.0.0.1".to_string()];
        let csr = generate_server_csr(&sans, None, None).expect("server CSR");
        assert!(!csr.key_encrypted);

        let issued = sign_server_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &csr.csr_pem,
            &sans,
            None,
            30,
        )
        .expect("signed server certificate");

        certificate_matches_key(&issued.cert_pem, &csr.key_pem, None)
            .expect("key matches certificate");

        let der = parse_der(&issued.cert_pem);
        let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert!(
            cert.extended_key_usage()
                .unwrap()
                .expect("EKU")
                .value
                .server_auth
        );
        assert!(!cert.basic_constraints().unwrap().unwrap().value.ca);

        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert!(
            san.value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::DNSName(value) if *value == "localhost"))
        );
        assert!(
            san.value
                .general_names
                .iter()
                .any(|name| matches!(name, GeneralName::IPAddress(_)))
        );
    }

    #[test]
    fn verification_rejects_a_different_ca() {
        let ca = make_ca();
        let other_ca = make_ca();
        let csr = generate_client_csr(
            "alice",
            &[],
            PermissionSet::NONE,
            Some("key-passphrase"),
            None,
        )
        .expect("client CSR");
        let issued = sign_client_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &csr.csr_pem,
            "alice",
            &[],
            PermissionSet::NONE,
            None,
            30,
        )
        .expect("certificate");

        let error = verify_client_certificate(
            &issued.cert_pem,
            &other_ca.cert_pem,
            &csr.key_pem,
            Some("key-passphrase"),
        )
        .expect_err("certificate must not verify under another CA");
        assert!(matches!(
            error,
            PkiError::CertificateIssuerMismatch | PkiError::CertificateSignatureInvalid
        ));
    }

    #[test]
    fn certificate_and_key_must_match() {
        let ca = make_ca();
        let first = generate_client_csr(
            "alice",
            &[],
            PermissionSet::NONE,
            Some("key-passphrase"),
            None,
        )
        .expect("first CSR");
        let second = generate_client_csr(
            "alice",
            &[],
            PermissionSet::NONE,
            Some("key-passphrase"),
            None,
        )
        .expect("second CSR");
        let issued = sign_client_csr(
            &ca.cert_pem,
            &ca.key_pem,
            "ca-passphrase",
            &first.csr_pem,
            "alice",
            &[],
            PermissionSet::NONE,
            None,
            30,
        )
        .expect("certificate");

        certificate_matches_key(&issued.cert_pem, &first.key_pem, Some("key-passphrase"))
            .expect("matching key");
        assert!(matches!(
            certificate_matches_key(&issued.cert_pem, &second.key_pem, Some("key-passphrase")),
            Err(PkiError::KeyMismatch)
        ));
    }

    #[test]
    fn rejects_invalid_identities_and_server_sans() {
        assert!(matches!(
            generate_client_csr("", &[], PermissionSet::NONE, None, None),
            Err(PkiError::InvalidPrincipal)
        ));
        assert!(matches!(
            generate_client_csr("ali\nce", &[], PermissionSet::NONE, None, None),
            Err(PkiError::InvalidPrincipal)
        ));
        assert!(matches!(
            generate_client_csr(
                "alice",
                &["holder\n1".to_string()],
                PermissionSet::NONE,
                None,
                None
            ),
            Err(PkiError::InvalidHolder(_))
        ));
        assert!(matches!(
            generate_server_csr(&[], None, None),
            Err(PkiError::MissingServerSan)
        ));
        assert!(matches!(
            generate_server_csr(&["DNS:bad host".to_string()], None, None),
            Err(PkiError::InvalidServerSan(_))
        ));
        assert!(matches!(
            generate_server_csr(&["IP:not-an-ip".to_string()], None, None),
            Err(PkiError::InvalidServerSan(_))
        ));
    }

    #[test]
    fn key_pair_helper_still_parses_generated_keys() {
        // Guards against accidentally writing a key format that rcgen cannot read.
        let csr =
            generate_client_csr("alice", &[], PermissionSet::NONE, None, None).expect("client CSR");
        KeyPair::from_pem(&csr.key_pem).expect("rcgen can parse the generated key");
    }
}
