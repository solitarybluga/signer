use std::collections::BTreeMap;
use std::sync::Arc;

use prost_types::Timestamp;
use time::OffsetDateTime;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use signer_core::keystore::{Keystore, KeystoreError};
use signer_core::storage::{
    Curve as StorageCurve, KeyMetadata, KeyState as StorageKeyState, KeyStore, Page,
    SignatureAlgorithm as StorageAlgorithm,
};
use signer_core::unseal::{SessionState, ShareSubmission, UnsealError, UnsealManager};
use signer_proto::pb;

use crate::permissions::Permission;
use crate::tls::Principal;

use pb::{
    CreateKeyRequest, CreateKeyResponse, GetPublicKeyRequest, GetPublicKeyResponse,
    GetUnsealStatusRequest, GetUnsealStatusResponse, ImportKeyRequest, ImportKeyResponse,
    ListKeysRequest, ListKeysResponse, SealRequest, SealResponse, SignRequest, SignResponse,
    StartUnsealRequest, StartUnsealResponse, SubmitUnsealShareRequest, SubmitUnsealShareResponse,
    signer_service_server::{SignerService, SignerServiceServer},
};

const GRPC_ACTOR: &str = "grpc";

/// gRPC adapter around the unseal manager.
#[derive(Clone)]
pub struct SignerGrpc {
    unseal: Arc<UnsealManager>,
    keystore: Arc<Keystore>,
    require_permissions: bool,
}

impl SignerGrpc {
    pub fn with_sign_audit(
        unseal: Arc<UnsealManager>,
        store: Arc<dyn KeyStore>,
        sign_audit: bool,
    ) -> Self {
        let keystore = Arc::new(Keystore::new(store, unseal.clone()).with_sign_audit(sign_audit));
        Self {
            unseal,
            keystore,
            require_permissions: false,
        }
    }

    /// Require a client-certificate principal and per-RPC permission bits.
    /// Enabled by `main` whenever `[tls]` is configured; direct in-process tests
    /// keep the permissive default.
    pub fn with_client_permissions(mut self, enabled: bool) -> Self {
        self.require_permissions = enabled;
        self
    }

    pub fn into_server(self) -> SignerServiceServer<Self> {
        SignerServiceServer::new(self)
    }

    fn principal<T>(&self, request: &Request<T>) -> Result<Option<Principal>, Status> {
        if !self.require_permissions {
            return Ok(None);
        }
        request
            .extensions()
            .get::<Principal>()
            .cloned()
            .map(Some)
            .ok_or_else(|| Status::unauthenticated("client identity is missing"))
    }

    fn authorize<T>(
        &self,
        request: &Request<T>,
        permission: Permission,
    ) -> Result<Option<Principal>, Status> {
        let principal = self.principal(request)?;
        if let Some(principal) = &principal
            && !principal.permissions.contains(permission)
        {
            debug!(
                permission = permission.as_str(),
                actor = %principal.actor,
                "authorization denied"
            );
            return Err(Status::permission_denied("permission denied"));
        }
        Ok(principal)
    }

    fn actor(principal: Option<&Principal>) -> &str {
        principal
            .map(|principal| principal.actor.as_str())
            .unwrap_or(GRPC_ACTOR)
    }
}

#[async_trait::async_trait]
impl SignerService for SignerGrpc {
    async fn create_key(
        &self,
        request: Request<CreateKeyRequest>,
    ) -> Result<Response<CreateKeyResponse>, Status> {
        let principal = self.authorize(&request, Permission::KeyCreate)?;
        let actor = Self::actor(principal.as_ref()).to_string();
        let request = request.into_inner();
        let curve = parse_curve(request.curve)?;
        let algorithm = parse_algorithm(request.algorithm)?;
        let labels: BTreeMap<String, String> = request.labels.into_iter().collect();
        info!(
            curve = curve.as_str(),
            algorithm = algorithm.as_str(),
            "CreateKey requested"
        );

        let key = self
            .keystore
            .create_key(curve, algorithm, labels, &actor)
            .await
            .map_err(|error| {
                warn!("CreateKey failed");
                map_keystore_error(error)
            })?;

        info!(key_id = %key.id, "key created");
        Ok(Response::new(CreateKeyResponse {
            key: Some(key_to_proto(&key)),
        }))
    }

    async fn import_key(
        &self,
        request: Request<ImportKeyRequest>,
    ) -> Result<Response<ImportKeyResponse>, Status> {
        let _principal = self.authorize(&request, Permission::KeyImport)?;
        Err(Status::unimplemented("ImportKey is not implemented yet"))
    }

    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        let _principal = self.authorize(&request, Permission::KeyRead)?;
        let request = request.into_inner();
        let key_id = parse_key_id(&request.key_id)?;
        debug!(key_id = %key_id, "GetPublicKey requested");
        let key = self
            .keystore
            .get_public_key(key_id)
            .await
            .map_err(|error| {
                warn!(key_id = %key_id, "GetPublicKey failed");
                map_keystore_error(error)
            })?;

        Ok(Response::new(GetPublicKeyResponse {
            key_id: key.id.to_string(),
            curve: curve_to_proto(key.curve) as i32,
            algorithm: algorithm_to_proto(key.algorithm) as i32,
            public_key: key.public_key,
        }))
    }

    async fn list_keys(
        &self,
        request: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        let _principal = self.authorize(&request, Permission::KeyRead)?;
        let request = request.into_inner();
        let limit = match request.page_size {
            0 => 50,
            value if (1..=200).contains(&value) => value as u32,
            _ => {
                return Err(Status::invalid_argument(
                    "page_size must be between 1 and 200",
                ));
            }
        };
        let offset = if request.page_token.is_empty() {
            0
        } else {
            request
                .page_token
                .parse::<u32>()
                .map_err(|_| Status::invalid_argument("page_token must be a decimal offset"))?
        };
        debug!(limit, offset, "ListKeys requested");

        let keys = self
            .keystore
            .list_keys(Page { limit, offset })
            .await
            .map_err(|error| {
                warn!("ListKeys failed");
                map_keystore_error(error)
            })?;
        debug!(count = keys.len(), "ListKeys completed");
        let next_page_token = if keys.len() == limit as usize {
            offset.saturating_add(limit).to_string()
        } else {
            String::new()
        };

        Ok(Response::new(ListKeysResponse {
            keys: keys.iter().map(key_to_proto).collect(),
            next_page_token,
        }))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let principal = self.authorize(&request, Permission::KeySign)?;
        let actor = Self::actor(principal.as_ref()).to_string();
        let request = request.into_inner();
        let key_id = parse_key_id(&request.key_id)?;
        info!(
            key_id = %key_id,
            has_request_id = !request.request_id.is_empty(),
            "Sign requested"
        );
        let signature = self
            .keystore
            .sign(key_id, &request.payload, &actor, Some(&request.request_id))
            .await
            .map_err(|error| {
                warn!(key_id = %key_id, "Sign failed");
                map_keystore_error(error)
            })?;
        info!(key_id = %key_id, "signature produced");

        Ok(Response::new(SignResponse {
            key_id: key_id.to_string(),
            signature,
            request_id: request.request_id,
        }))
    }

    async fn start_unseal(
        &self,
        request: Request<StartUnsealRequest>,
    ) -> Result<Response<StartUnsealResponse>, Status> {
        let _principal = self.authorize(&request, Permission::UnsealStart)?;
        let session = self.unseal.start_session().map_err(map_unseal_error)?;
        info!(
            session_id = %session.id,
            threshold = session.threshold,
            "unseal session started"
        );

        Ok(Response::new(StartUnsealResponse {
            session_id: session.id.to_string(),
            nonce: session.nonce.to_vec(),
            session_public_key: session.session_public_key.to_vec(),
            threshold: i32::from(session.threshold),
            shares_collected: i32::try_from(session.shares_collected).unwrap_or(i32::MAX),
            expires_at: timestamp(session.expires_at),
        }))
    }

    async fn submit_unseal_share(
        &self,
        request: Request<SubmitUnsealShareRequest>,
    ) -> Result<Response<SubmitUnsealShareResponse>, Status> {
        let principal = self.authorize(&request, Permission::UnsealSubmit)?;
        let request = request.into_inner();

        if request.share_holder_id.is_empty() {
            return Err(Status::invalid_argument("share_holder_id is required"));
        }
        if let Some(principal) = &principal
            && !principal
                .holder_ids
                .iter()
                .any(|id| id == &request.share_holder_id)
        {
            return Err(Status::permission_denied(
                "holder is not bound to this certificate",
            ));
        }
        if request.encrypted_share.is_empty() {
            return Err(Status::invalid_argument("encrypted_share is required"));
        }
        if request.signature.len() != 64 {
            return Err(Status::invalid_argument(
                "signature must be a 64-byte Ed25519 signature",
            ));
        }
        if request.nonce.len() != 32 {
            return Err(Status::invalid_argument("nonce must be 32 bytes"));
        }
        if request.share_index == 0 {
            return Err(Status::invalid_argument("share_index is required"));
        }
        let share_index = u8::try_from(request.share_index)
            .map_err(|_| Status::invalid_argument("share_index must be between 1 and 255"))?;

        let session_id = parse_session_id(&request.session_id)?;
        debug!(
            session_id = %session_id,
            holder_id = %request.share_holder_id,
            share_index,
            "share submission"
        );
        self.unseal
            .submit_share(
                session_id,
                ShareSubmission {
                    holder_id: &request.share_holder_id,
                    share_index: Some(share_index),
                    nonce: &request.nonce,
                    ciphertext: &request.encrypted_share,
                    signature: &request.signature,
                },
            )
            .map_err(|error| {
                warn!(
                    session_id = %session_id,
                    holder_id = %request.share_holder_id,
                    "share submission failed"
                );
                map_unseal_error(error)
            })?;

        let status = self.unseal.status(session_id).map_err(map_unseal_error)?;
        info!(
            session_id = %status.id,
            state = status.state.as_str(),
            shares_collected = status.shares_collected,
            threshold = status.threshold,
            "share accepted"
        );

        Ok(Response::new(SubmitUnsealShareResponse {
            shares_collected: i32::try_from(status.shares_collected).unwrap_or(i32::MAX),
            threshold: i32::from(status.threshold),
            state: state_to_proto(status.state),
        }))
    }

    async fn get_unseal_status(
        &self,
        request: Request<GetUnsealStatusRequest>,
    ) -> Result<Response<GetUnsealStatusResponse>, Status> {
        let _principal = self.authorize(&request, Permission::UnsealStatus)?;
        let session_id = parse_session_id(&request.into_inner().session_id)?;
        debug!(session_id = %session_id, "GetUnsealStatus requested");
        let status = self.unseal.status(session_id).map_err(map_unseal_error)?;

        Ok(Response::new(GetUnsealStatusResponse {
            session_id: status.id.to_string(),
            threshold: i32::from(status.threshold),
            shares_collected: i32::try_from(status.shares_collected).unwrap_or(i32::MAX),
            state: state_to_proto(status.state),
            expires_at: timestamp(status.expires_at),
            nonce: status.nonce.to_vec(),
            session_public_key: status.session_public_key.to_vec(),
        }))
    }

    async fn seal(&self, request: Request<SealRequest>) -> Result<Response<SealResponse>, Status> {
        let _principal = self.authorize(&request, Permission::UnsealSeal)?;
        self.unseal.seal();
        info!("service sealed; KEK and unseal sessions cleared");
        Ok(Response::new(SealResponse { sealed: true }))
    }
}

fn parse_session_id(value: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(value).map_err(|_| Status::invalid_argument("session_id must be a UUID"))
}

fn parse_key_id(value: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(value).map_err(|_| Status::invalid_argument("key_id must be a UUID"))
}

fn parse_curve(value: i32) -> Result<StorageCurve, Status> {
    match pb::Curve::try_from(value) {
        Ok(pb::Curve::Secp256k1) => Ok(StorageCurve::Secp256k1),
        Ok(pb::Curve::Edwards25519) => Ok(StorageCurve::Edwards25519),
        _ => Err(Status::invalid_argument(
            "curve must be CURVE_SECP256K1 or CURVE_EDWARDS25519",
        )),
    }
}

fn parse_algorithm(value: i32) -> Result<StorageAlgorithm, Status> {
    match pb::SignatureAlgorithm::try_from(value) {
        Ok(pb::SignatureAlgorithm::Ecdsa) => Ok(StorageAlgorithm::Ecdsa),
        Ok(pb::SignatureAlgorithm::Eddsa) => Ok(StorageAlgorithm::EdDsa),
        _ => Err(Status::invalid_argument(
            "algorithm must be SIGNATURE_ALGORITHM_ECDSA or SIGNATURE_ALGORITHM_EDDSA",
        )),
    }
}

fn curve_to_proto(curve: StorageCurve) -> pb::Curve {
    match curve {
        StorageCurve::Secp256k1 => pb::Curve::Secp256k1,
        StorageCurve::Edwards25519 => pb::Curve::Edwards25519,
    }
}

fn algorithm_to_proto(algorithm: StorageAlgorithm) -> pb::SignatureAlgorithm {
    match algorithm {
        StorageAlgorithm::Ecdsa => pb::SignatureAlgorithm::Ecdsa,
        StorageAlgorithm::EdDsa => pb::SignatureAlgorithm::Eddsa,
    }
}

fn key_state_to_proto(state: StorageKeyState) -> i32 {
    match state {
        StorageKeyState::Created => pb::KeyState::Created as i32,
        StorageKeyState::Active => pb::KeyState::Active as i32,
        StorageKeyState::Rotating => pb::KeyState::Rotating as i32,
        StorageKeyState::Destroyed => pb::KeyState::Destroyed as i32,
    }
}

fn key_to_proto(key: &KeyMetadata) -> pb::Key {
    pb::Key {
        id: key.id.to_string(),
        curve: curve_to_proto(key.curve) as i32,
        algorithm: algorithm_to_proto(key.algorithm) as i32,
        public_key: key.public_key.clone(),
        state: key_state_to_proto(key.state),
        created_at: timestamp(key.created_at),
    }
}

fn map_keystore_error(error: KeystoreError) -> Status {
    match error {
        KeystoreError::Sealed => Status::failed_precondition("service is sealed"),
        KeystoreError::NotFound => Status::not_found("key not found"),
        KeystoreError::Conflict => Status::already_exists("key already exists"),
        KeystoreError::KeyNotActive => Status::failed_precondition("key is not active"),
        KeystoreError::InvalidAlgorithmPair => {
            Status::invalid_argument("unsupported curve/algorithm pair")
        }
        KeystoreError::InvalidPayload => {
            Status::invalid_argument("ECDSA payload must be a 32-byte digest")
        }
        KeystoreError::InvalidMaterial | KeystoreError::Corrupt => {
            Status::internal("stored key is corrupt")
        }
        KeystoreError::Storage(_) | KeystoreError::Audit(_) | KeystoreError::Internal => {
            Status::internal("key storage operation failed")
        }
    }
}

fn timestamp(value: OffsetDateTime) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: value.unix_timestamp(),
        nanos: value.nanosecond() as i32,
    })
}

fn state_to_proto(state: SessionState) -> i32 {
    match state {
        SessionState::Collecting => pb::UnsealState::Collecting as i32,
        SessionState::Unsealed => pb::UnsealState::Unsealed as i32,
        SessionState::Expired => pb::UnsealState::Expired as i32,
        SessionState::Failed => pb::UnsealState::Failed as i32,
    }
}

fn map_unseal_error(error: UnsealError) -> Status {
    match error {
        UnsealError::InvalidConfig(message) => Status::failed_precondition(message),
        UnsealError::AlreadyUnsealed => Status::failed_precondition("service is already unsealed"),
        UnsealError::Sealed => Status::failed_precondition("service is sealed"),
        UnsealError::SessionNotFound => Status::not_found("unseal session not found"),
        UnsealError::SessionExpired => Status::failed_precondition("unseal session expired"),
        UnsealError::SessionClosed => {
            Status::failed_precondition("unseal session is no longer collecting")
        }
        UnsealError::UnknownHolder(holder) => {
            Status::permission_denied(format!("share holder is not registered: {holder}"))
        }
        UnsealError::DuplicateHolder(holder) => {
            Status::already_exists(format!("duplicate share holder: {holder}"))
        }
        UnsealError::DuplicateIndex(index) => {
            Status::already_exists(format!("duplicate share index: {index}"))
        }
        UnsealError::IndexMismatch => {
            Status::invalid_argument("share index does not match the holder registration")
        }
        UnsealError::InvalidNonce => Status::invalid_argument("unseal session nonce is invalid"),
        UnsealError::InvalidSignature => {
            Status::permission_denied("share holder signature is invalid")
        }
        UnsealError::InvalidShare(message) => {
            Status::invalid_argument(format!("invalid share: {message}"))
        }
        UnsealError::VssRejected(message) => {
            Status::invalid_argument(format!("share failed VSS verification: {message}"))
        }
        UnsealError::RecoveryFailed(message) => {
            Status::invalid_argument(format!("failed to recover the KEK: {message}"))
        }
        UnsealError::InvalidKek => Status::invalid_argument("recovered KEK failed verification"),
        UnsealError::Internal(message) => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{
        KEY_CREATE, KEY_IMPORT, KEY_READ, KEY_SIGN, PermissionSet, UNSEAL_SEAL, UNSEAL_START,
        UNSEAL_STATUS, UNSEAL_SUBMIT,
    };
    use crate::tls::Principal;
    use ed25519_dalek::{
        Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey,
    };
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
    use rand::RngCore;
    use rand::rngs::OsRng;
    use signer_core::storage::SqliteStore;
    use signer_core::unseal::{HolderIndex, UnsealConfig, UnsealManager};
    use signer_share::{encrypt_share_with_context, submission_context, submission_signing_input};
    use zeroize::Zeroizing;

    struct TestHolder {
        id: String,
        index: u8,
        signing_key: SigningKey,
    }

    impl TestHolder {
        fn new(index: u8) -> Self {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            Self {
                id: format!("holder-{index}"),
                index,
                signing_key: SigningKey::from_bytes(&seed),
            }
        }
    }

    async fn setup() -> (SignerGrpc, Vec<Zeroizing<Vec<u8>>>, Vec<TestHolder>) {
        let (service, shares, holders, _) = setup_with_store().await;
        (service, shares, holders)
    }

    async fn setup_with_store() -> (
        SignerGrpc,
        Vec<Zeroizing<Vec<u8>>>,
        Vec<TestHolder>,
        Arc<SqliteStore>,
    ) {
        let test_holders: Vec<TestHolder> = (1..=3).map(TestHolder::new).collect();
        let holders: Vec<HolderIndex> = test_holders
            .iter()
            .map(|holder| HolderIndex {
                id: holder.id.clone(),
                index: holder.index,
                ed25519_public: hex::encode(holder.signing_key.verifying_key().to_bytes()),
            })
            .collect();
        let (manager, shares, _) =
            UnsealManager::bootstrap(UnsealConfig::new(2, 3), holders).unwrap();
        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        (
            SignerGrpc::with_sign_audit(Arc::new(manager), store.clone(), true),
            shares,
            test_holders,
            store,
        )
    }

    fn test_principal(actor: &str, mask: u64, holders: &[&str]) -> Principal {
        Principal {
            actor: actor.to_string(),
            holder_ids: holders.iter().map(|holder| holder.to_string()).collect(),
            permissions: PermissionSet::from_known_mask(mask).unwrap(),
            fingerprint: [7u8; 32],
        }
    }

    fn with_principal<T>(message: T, principal: Principal) -> Request<T> {
        let mut request = Request::new(message);
        request.extensions_mut().insert(principal);
        request
    }

    fn submission_request(
        start: &StartUnsealResponse,
        holder: &TestHolder,
        share: &[u8],
    ) -> SubmitUnsealShareRequest {
        let nonce: [u8; 32] = start.nonce.as_slice().try_into().unwrap();
        let session_public: [u8; 32] = start.session_public_key.as_slice().try_into().unwrap();
        let context = submission_context(
            &start.session_id,
            &nonce,
            &session_public,
            &holder.id,
            holder.index,
        )
        .unwrap();
        let ciphertext = encrypt_share_with_context(&session_public, share, &context).unwrap();
        let signature = holder
            .signing_key
            .sign(&submission_signing_input(&context, &ciphertext))
            .to_bytes()
            .to_vec();

        SubmitUnsealShareRequest {
            session_id: start.session_id.clone(),
            share_holder_id: holder.id.clone(),
            encrypted_share: ciphertext,
            signature,
            share_index: u32::from(holder.index),
            nonce: start.nonce.clone(),
        }
    }

    #[tokio::test]
    async fn unseal_rpcs_work_end_to_end() {
        let (service, shares, holders) = setup().await;

        let start = service
            .start_unseal(Request::new(StartUnsealRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(start.threshold, 2);
        assert_eq!(start.nonce.len(), 32);
        assert_eq!(start.session_public_key.len(), 32);

        let response = service
            .submit_unseal_share(Request::new(submission_request(
                &start,
                &holders[0],
                &shares[0],
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.state, pb::UnsealState::Collecting as i32);
        assert_eq!(response.shares_collected, 1);

        let response = service
            .submit_unseal_share(Request::new(submission_request(
                &start,
                &holders[1],
                &shares[1],
            )))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.state, pb::UnsealState::Unsealed as i32);

        let status = service
            .get_unseal_status(Request::new(GetUnsealStatusRequest {
                session_id: start.session_id,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.state, pb::UnsealState::Unsealed as i32);
        assert_eq!(status.shares_collected, 2);
        assert_eq!(status.nonce, start.nonce);
        assert_eq!(status.session_public_key, start.session_public_key);

        let sealed = service
            .seal(Request::new(SealRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(sealed.sealed);
    }

    #[tokio::test]
    async fn plaintext_shares_are_rejected() {
        let (service, shares, holders) = setup().await;
        let start = service
            .start_unseal(Request::new(StartUnsealRequest {}))
            .await
            .unwrap()
            .into_inner();

        let nonce: [u8; 32] = start.nonce.as_slice().try_into().unwrap();
        let session_public: [u8; 32] = start.session_public_key.as_slice().try_into().unwrap();
        let context = submission_context(
            &start.session_id,
            &nonce,
            &session_public,
            &holders[0].id,
            holders[0].index,
        )
        .unwrap();
        let plaintext = shares[0].to_vec();
        let signature = holders[0]
            .signing_key
            .sign(&submission_signing_input(&context, &plaintext))
            .to_bytes()
            .to_vec();

        let error = service
            .submit_unseal_share(Request::new(SubmitUnsealShareRequest {
                session_id: start.session_id,
                share_holder_id: holders[0].id.clone(),
                encrypted_share: plaintext,
                signature,
                share_index: u32::from(holders[0].index),
                nonce: start.nonce,
            }))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn nonce_and_signature_are_enforced() {
        let (service, shares, holders) = setup().await;
        let start = service
            .start_unseal(Request::new(StartUnsealRequest {}))
            .await
            .unwrap()
            .into_inner();

        let mut request = submission_request(&start, &holders[0], &shares[0]);
        request.nonce = vec![0u8; 32];
        let error = service
            .submit_unseal_share(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);

        let mut request = submission_request(&start, &holders[0], &shares[0]);
        request.signature[0] ^= 1;
        let error = service
            .submit_unseal_share(Request::new(request))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn ed25519_key_lifecycle_end_to_end() {
        let (service, shares, holders) = setup().await;
        let create_request = || CreateKeyRequest {
            curve: pb::Curve::Edwards25519 as i32,
            algorithm: pb::SignatureAlgorithm::Eddsa as i32,
            labels: Default::default(),
        };

        let error = service
            .create_key(Request::new(create_request()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let start = service
            .start_unseal(Request::new(StartUnsealRequest {}))
            .await
            .unwrap()
            .into_inner();
        for index in 0..2 {
            service
                .submit_unseal_share(Request::new(submission_request(
                    &start,
                    &holders[index],
                    &shares[index],
                )))
                .await
                .unwrap();
        }

        let created = service
            .create_key(Request::new(create_request()))
            .await
            .unwrap()
            .into_inner();
        let key = created.key.expect("create_key returns a key");
        assert_eq!(key.state, pb::KeyState::Active as i32);
        assert_eq!(key.public_key.len(), 32);

        let payload = b"hello signer".to_vec();
        let signed = service
            .sign(Request::new(SignRequest {
                key_id: key.id.clone(),
                payload: payload.clone(),
                request_id: "req-1".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(signed.key_id, key.id);
        assert_eq!(signed.request_id, "req-1");

        let public_key: [u8; 32] = key.public_key.as_slice().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&public_key).unwrap();
        let signature = Ed25519Signature::from_slice(&signed.signature).unwrap();
        verifying_key.verify(&payload, &signature).unwrap();

        let fetched = service
            .get_public_key(Request::new(GetPublicKeyRequest {
                key_id: key.id.clone(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(fetched.public_key, key.public_key);

        let listed = service
            .list_keys(Request::new(ListKeysRequest {
                page_size: 10,
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.keys.len(), 1);
        assert_eq!(listed.keys[0].id, key.id);
        assert!(listed.next_page_token.is_empty());

        service.seal(Request::new(SealRequest {})).await.unwrap();
        let error = service
            .sign(Request::new(SignRequest {
                key_id: key.id,
                payload,
                request_id: "req-2".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn secp256k1_key_lifecycle_end_to_end() {
        let (service, shares, holders) = setup().await;

        let start = service
            .start_unseal(Request::new(StartUnsealRequest {}))
            .await
            .unwrap()
            .into_inner();
        for index in 0..2 {
            service
                .submit_unseal_share(Request::new(submission_request(
                    &start,
                    &holders[index],
                    &shares[index],
                )))
                .await
                .unwrap();
        }

        let created = service
            .create_key(Request::new(CreateKeyRequest {
                curve: pb::Curve::Secp256k1 as i32,
                algorithm: pb::SignatureAlgorithm::Ecdsa as i32,
                labels: Default::default(),
            }))
            .await
            .unwrap()
            .into_inner();
        let key = created.key.expect("create_key returns a key");
        assert_eq!(key.state, pb::KeyState::Active as i32);
        assert_eq!(key.public_key.len(), 33);

        let digest = [7u8; 32];
        let signed = service
            .sign(Request::new(SignRequest {
                key_id: key.id.clone(),
                payload: digest.to_vec(),
                request_id: "req-ecdsa".to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(signed.signature.len(), 65);

        let signature = EcdsaSignature::from_slice(&signed.signature[..64]).unwrap();
        assert!(signature.normalize_s().is_none());
        let verifying_key = EcdsaVerifyingKey::from_sec1_bytes(&key.public_key).unwrap();
        verifying_key.verify_prehash(&digest, &signature).unwrap();

        let recovery = RecoveryId::from_byte(signed.signature[64] - 27).unwrap();
        let recovered =
            EcdsaVerifyingKey::recover_from_prehash(&digest, &signature, recovery).unwrap();
        assert_eq!(recovered, verifying_key);

        let error = service
            .sign(Request::new(SignRequest {
                key_id: key.id,
                payload: vec![1u8; 31],
                request_id: "req-bad-digest".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn unwired_rpcs_report_unimplemented() {
        let (service, _, _) = setup().await;

        let error = service
            .import_key(Request::new(ImportKeyRequest::default()))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn invalid_session_id_is_rejected() {
        let (service, _, _) = setup().await;

        let error = service
            .get_unseal_status(Request::new(GetUnsealStatusRequest {
                session_id: "not-a-uuid".to_string(),
            }))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn permissions_are_required_for_every_rpc() {
        let (service, _, _) = setup().await;
        let service = service.with_client_permissions(true);
        let none = test_principal("none", 0, &[]);

        let error = service
            .start_unseal(with_principal(StartUnsealRequest {}, none.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let error = service
            .submit_unseal_share(with_principal(
                SubmitUnsealShareRequest::default(),
                none.clone(),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let error = service
            .get_unseal_status(with_principal(
                GetUnsealStatusRequest::default(),
                none.clone(),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let error = service
            .seal(with_principal(SealRequest {}, none.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let error = service
            .create_key(with_principal(CreateKeyRequest::default(), none.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let error = service
            .import_key(with_principal(ImportKeyRequest::default(), none.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let error = service
            .get_public_key(with_principal(GetPublicKeyRequest::default(), none.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let error = service
            .list_keys(with_principal(ListKeysRequest::default(), none.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let error = service
            .sign(with_principal(SignRequest::default(), none))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn permission_bits_are_independent_and_holder_bound() {
        let (service, _, _) = setup().await;
        let service = service.with_client_permissions(true);

        let starter = test_principal("starter", UNSEAL_START | UNSEAL_STATUS, &[]);
        service
            .start_unseal(with_principal(StartUnsealRequest {}, starter.clone()))
            .await
            .unwrap();
        let error = service
            .create_key(with_principal(CreateKeyRequest::default(), starter.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        let error = service
            .get_unseal_status(with_principal(
                GetUnsealStatusRequest {
                    session_id: "not-a-uuid".to_string(),
                },
                starter,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);

        let reader = test_principal("reader", KEY_READ, &[]);
        service
            .list_keys(with_principal(ListKeysRequest::default(), reader.clone()))
            .await
            .unwrap();
        let error = service
            .sign(with_principal(SignRequest::default(), reader))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let signer = test_principal("signer", KEY_SIGN, &[]);
        let error = service
            .sign(with_principal(
                SignRequest {
                    key_id: Uuid::new_v4().to_string(),
                    payload: vec![1; 32],
                    request_id: String::new(),
                },
                signer,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);

        let creator = test_principal("creator", KEY_CREATE, &[]);
        let error = service
            .create_key(with_principal(
                CreateKeyRequest {
                    curve: pb::Curve::Edwards25519 as i32,
                    algorithm: pb::SignatureAlgorithm::Eddsa as i32,
                    labels: Default::default(),
                },
                creator,
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);

        let importer = test_principal("importer", KEY_IMPORT, &[]);
        let error = service
            .import_key(with_principal(ImportKeyRequest::default(), importer))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unimplemented);

        let submitter = test_principal("submitter", UNSEAL_SUBMIT, &["holder-1"]);
        let request = SubmitUnsealShareRequest {
            session_id: "not-a-uuid".to_string(),
            share_holder_id: "holder-2".to_string(),
            encrypted_share: vec![1],
            signature: vec![0; 64],
            share_index: 1,
            nonce: vec![0; 32],
        };
        let error = service
            .submit_unseal_share(with_principal(request, submitter.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);

        let request = SubmitUnsealShareRequest {
            session_id: "not-a-uuid".to_string(),
            share_holder_id: "holder-1".to_string(),
            encrypted_share: vec![1],
            signature: vec![0; 64],
            share_index: 1,
            nonce: vec![0; 32],
        };
        let error = service
            .submit_unseal_share(with_principal(request, submitter))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);

        let sealer = test_principal("sealer", UNSEAL_SEAL, &[]);
        service
            .seal(with_principal(SealRequest {}, sealer))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn missing_principal_is_unauthenticated() {
        let (service, _, _) = setup().await;
        let service = service.with_client_permissions(true);

        let error = service
            .start_unseal(Request::new(StartUnsealRequest {}))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn audit_uses_certificate_principal_actor() {
        let (service, shares, holders, store) = setup_with_store().await;
        let service = service.with_client_permissions(true);

        let starter = test_principal("unseal-operator", UNSEAL_START | UNSEAL_STATUS, &[]);
        let start = service
            .start_unseal(with_principal(StartUnsealRequest {}, starter))
            .await
            .unwrap()
            .into_inner();

        for index in 0..2 {
            let holder = &holders[index];
            let request = submission_request(&start, holder, &shares[index]);
            let holder_id = holder.id.as_str();
            let principal = test_principal(holder_id, UNSEAL_SUBMIT, &[holder_id]);
            service
                .submit_unseal_share(with_principal(request, principal))
                .await
                .unwrap();
        }

        let creator = test_principal("alice-creator", KEY_CREATE, &[]);
        let created = service
            .create_key(with_principal(
                CreateKeyRequest {
                    curve: pb::Curve::Edwards25519 as i32,
                    algorithm: pb::SignatureAlgorithm::Eddsa as i32,
                    labels: Default::default(),
                },
                creator,
            ))
            .await
            .unwrap()
            .into_inner();
        let key = created.key.expect("CreateKey returns a key");

        let signer = test_principal("alice-signer", KEY_SIGN, &[]);
        service
            .sign(with_principal(
                SignRequest {
                    key_id: key.id,
                    payload: b"payload".to_vec(),
                    request_id: "req-audit".to_string(),
                },
                signer,
            ))
            .await
            .unwrap();

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT actor, action FROM audit_log ORDER BY id")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert!(
            rows.iter()
                .any(|(actor, action)| actor == "alice-creator" && action == "CreateKey")
        );
        assert!(
            rows.iter()
                .any(|(actor, action)| actor == "alice-signer" && action == "Sign")
        );
    }
}
