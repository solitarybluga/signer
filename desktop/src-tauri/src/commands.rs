use serde::Serialize;
use tonic::transport::Channel;
use zeroize::Zeroizing;

use signer_proto::pb;
use signer_proto::pb::signer_service_client::SignerServiceClient;

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub session_id: String,
    pub nonce_hex: String,
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
            threshold: response.threshold,
            shares_collected: response.shares_collected,
            state: "collecting".to_string(),
            expires_at: response.expires_at.map(|timestamp| timestamp.seconds),
        }
    }

    fn from_status(response: pb::GetUnsealStatusResponse) -> Self {
        Self {
            session_id: response.session_id,
            nonce_hex: String::new(),
            threshold: response.threshold,
            shares_collected: response.shares_collected,
            state: state_name(response.state),
            expires_at: response.expires_at.map(|timestamp| timestamp.seconds),
        }
    }
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

async fn connect(server_url: &str) -> Result<SignerServiceClient<Channel>, String> {
    let target = if server_url.contains("://") {
        server_url.to_string()
    } else {
        format!("http://{server_url}")
    };

    SignerServiceClient::connect(target)
        .await
        .map_err(|error| format!("failed to connect to signer: {error}"))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn start_unseal(server_url: String) -> Result<SessionView, String> {
    let mut client = connect(&server_url).await?;
    let response = client
        .start_unseal(pb::StartUnsealRequest {})
        .await
        .map_err(grpc_error)?
        .into_inner();

    Ok(SessionView::from_start(response))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn submit_share(
    server_url: String,
    session_id: String,
    holder_id: String,
    share_envelope: Vec<u8>,
    holder_secret: Vec<u8>,
) -> Result<SessionView, String> {
    let holder_secret = Zeroizing::new(holder_secret);
    let secret: [u8; 32] = holder_secret
        .as_slice()
        .try_into()
        .map_err(|_| "holder secret must be 32 bytes".to_string())?;
    let secret = Zeroizing::new(secret);

    let share = signer_share::decrypt_share(&secret, &share_envelope)
        .map_err(|error| format!("failed to decrypt share: {error}"))?;

    let mut client = connect(&server_url).await?;

    client
        .submit_unseal_share(pb::SubmitUnsealShareRequest {
            session_id: session_id.clone(),
            share_holder_id: holder_id,
            share: share.to_vec(),
            signature: Vec::new(),
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

#[tauri::command(rename_all = "snake_case")]
pub async fn get_status(server_url: String, session_id: String) -> Result<SessionView, String> {
    let mut client = connect(&server_url).await?;
    let status = client
        .get_unseal_status(pb::GetUnsealStatusRequest { session_id })
        .await
        .map_err(grpc_error)?
        .into_inner();

    Ok(SessionView::from_status(status))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn seal(server_url: String) -> Result<bool, String> {
    let mut client = connect(&server_url).await?;
    let response = client
        .seal(pb::SealRequest {})
        .await
        .map_err(grpc_error)?
        .into_inner();

    Ok(response.sealed)
}
