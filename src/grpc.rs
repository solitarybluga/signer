use std::sync::Arc;

use prost_types::Timestamp;
use time::OffsetDateTime;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::unseal::{SessionState, UnsealError, UnsealManager};

pub mod pb {
    tonic::include_proto!("signer.v1");
}

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
            // Share envelope encryption is not wired yet.
            session_public_key: Vec::new(),
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

        if !request.signature.is_empty() {
            return Err(Status::unimplemented(
                "share holder signatures are not wired yet",
            ));
        }
        if request.share_holder_id.is_empty() {
            return Err(Status::invalid_argument("share_holder_id is required"));
        }
        if request.share.is_empty() {
            return Err(Status::invalid_argument("share is required"));
        }

        let session_id = parse_session_id(&request.session_id)?;
        self.unseal
            .submit_share(session_id, &request.share_holder_id, &request.share)
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
        UnsealError::DuplicateHolder(holder) => {
            Status::already_exists(format!("duplicate share holder: {holder}"))
        }
        UnsealError::InvalidShare(message) => {
            Status::invalid_argument(format!("invalid share: {message}"))
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
    use crate::unseal::{UnsealConfig, UnsealManager};

    #[tokio::test]
    async fn unseal_rpcs_work_end_to_end() {
        let (manager, shares) = UnsealManager::bootstrap(UnsealConfig::new(2, 3)).unwrap();
        let service = SignerGrpc::new(Arc::new(manager));

        let start = service
            .start_unseal(Request::new(StartUnsealRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(start.threshold, 2);
        assert_eq!(start.nonce.len(), 32);

        let response = service
            .submit_unseal_share(Request::new(SubmitUnsealShareRequest {
                session_id: start.session_id.clone(),
                share_holder_id: "holder-1".to_string(),
                share: shares[0].clone(),
                signature: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.state, pb::UnsealState::Collecting as i32);
        assert_eq!(response.shares_collected, 1);

        let response = service
            .submit_unseal_share(Request::new(SubmitUnsealShareRequest {
                session_id: start.session_id.clone(),
                share_holder_id: "holder-2".to_string(),
                share: shares[1].clone(),
                signature: Vec::new(),
            }))
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

        let sealed = service
            .seal(Request::new(SealRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(sealed.sealed);
    }

    #[tokio::test]
    async fn unwired_rpcs_report_unimplemented() {
        let (manager, _) = UnsealManager::bootstrap(UnsealConfig::new(2, 3)).unwrap();
        let service = SignerGrpc::new(Arc::new(manager));

        let error = service
            .create_key(Request::new(CreateKeyRequest::default()))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn invalid_session_id_is_rejected() {
        let (manager, _) = UnsealManager::bootstrap(UnsealConfig::new(2, 3)).unwrap();
        let service = SignerGrpc::new(Arc::new(manager));

        let error = service
            .get_unseal_status(Request::new(GetUnsealStatusRequest {
                session_id: "not-a-uuid".to_string(),
            }))
            .await
            .unwrap_err();

        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
}
