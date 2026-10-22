use std::sync::Arc;

use prost_types::Timestamp;
use time::OffsetDateTime;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use signer_core::unseal::{SessionState, ShareSubmission, UnsealError, UnsealManager};
use signer_proto::pb;

use pb::{
    CreateKeyRequest, CreateKeyResponse, GetPublicKeyRequest, GetPublicKeyResponse,
    GetUnsealStatusRequest, GetUnsealStatusResponse, ImportKeyRequest, ImportKeyResponse,
    ListKeysRequest, ListKeysResponse, SealRequest, SealResponse, SignRequest, SignResponse,
    StartUnsealRequest, StartUnsealResponse, SubmitUnsealShareRequest, SubmitUnsealShareResponse,
    signer_service_server::{SignerService, SignerServiceServer},
};

/// gRPC adapter around the unseal manager.
#[derive(Clone)]
pub struct SignerGrpc {
    unseal: Arc<UnsealManager>,
}

impl SignerGrpc {
    pub fn new(unseal: Arc<UnsealManager>) -> Self {
        Self { unseal }
    }

    pub fn into_server(self) -> SignerServiceServer<Self> {
        SignerServiceServer::new(self)
    }
}

#[async_trait::async_trait]
impl SignerService for SignerGrpc {
    async fn create_key(
        &self,
        _request: Request<CreateKeyRequest>,
    ) -> Result<Response<CreateKeyResponse>, Status> {
        Err(Status::unimplemented("CreateKey is not wired yet"))
    }

    async fn import_key(
        &self,
        _request: Request<ImportKeyRequest>,
    ) -> Result<Response<ImportKeyResponse>, Status> {
        Err(Status::unimplemented("ImportKey is not wired yet"))
    }

    async fn get_public_key(
        &self,
        _request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        Err(Status::unimplemented("GetPublicKey is not wired yet"))
    }

    async fn list_keys(
        &self,
        _request: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        Err(Status::unimplemented("ListKeys is not wired yet"))
    }

    async fn sign(&self, _request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        Err(Status::unimplemented("Sign is not wired yet"))
    }

    async fn start_unseal(
        &self,
        _request: Request<StartUnsealRequest>,
    ) -> Result<Response<StartUnsealResponse>, Status> {
        let session = self.unseal.start_session().map_err(map_unseal_error)?;

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
        let request = request.into_inner();

        if request.share_holder_id.is_empty() {
            return Err(Status::invalid_argument("share_holder_id is required"));
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
            .map_err(map_unseal_error)?;

        let status = self.unseal.status(session_id).map_err(map_unseal_error)?;

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
        let session_id = parse_session_id(&request.into_inner().session_id)?;
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

    async fn seal(&self, _request: Request<SealRequest>) -> Result<Response<SealResponse>, Status> {
        self.unseal.seal();
        Ok(Response::new(SealResponse { sealed: true }))
    }
}

fn parse_session_id(value: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(value).map_err(|_| Status::invalid_argument("session_id must be a UUID"))
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
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngCore;
    use rand::rngs::OsRng;
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

    fn setup() -> (SignerGrpc, Vec<Zeroizing<Vec<u8>>>, Vec<TestHolder>) {
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
        (SignerGrpc::new(Arc::new(manager)), shares, test_holders)
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
        let (service, shares, holders) = setup();

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
        let (service, shares, holders) = setup();
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
        let (service, shares, holders) = setup();
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
    async fn unwired_rpcs_report_unimplemented() {
        let (service, _, _) = setup();

        let error = service
            .create_key(Request::new(CreateKeyRequest::default()))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn invalid_session_id_is_rejected() {
        let (service, _, _) = setup();

        let error = service
            .get_unseal_status(Request::new(GetUnsealStatusRequest {
                session_id: "not-a-uuid".to_string(),
            }))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}
