
use cosmrs::{ tx::{self, Fee, SignDoc, SignerInfo}, Coin};
use cosmos_sdk_proto::cosmos::{
    base::{self, tendermint::v1beta1::GetLatestBlockRequest}, tx::v1beta1::{service_client::ServiceClient as TxServiceClient, BroadcastMode, BroadcastTxRequest}
};
use cosmos_sdk_proto::cosmos::base::tendermint::v1beta1::service_client::ServiceClient as TendermintServiceClient;
use reqwest::Error;
use tonic::{Response, Status};
use cosmos_sdk_proto::side::btcbridge::{query_client::QueryClient as BtcQueryClient, QueryChainTipRequest, QueryChainTipResponse, QueryWithdrawRequestsRequest, QueryWithdrawRequestsResponse};
use crate::app::signer::Shuttler;

use prost_types::Any;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Pagination {
    pub limit: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningRequest {
    pub address: String,
    pub psbt: String,
    pub status: String,
    pub sequence: u32,
    pub vault_address: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SigningRequestsResponse {
    requests: Vec<SigningRequest>,
    pagination: Option<Pagination>,
}

impl SigningRequestsResponse {
    pub fn requests(&self) -> &Vec<SigningRequest> {
        &self.requests
    }

    pub fn pagination(&self) -> Option<&Pagination> {
        self.pagination.as_ref()
    }
}

pub async fn get_bitcoin_tip_on_side(host: &str ) -> Result<Response<QueryChainTipResponse>, Status> {
    let mut btc_client = BtcQueryClient::connect(host.to_string()).await.unwrap();
    btc_client.query_chain_tip(QueryChainTipRequest {}).await
}

pub async fn get_signing_requests(host: &str ) -> Result<Response<QueryWithdrawRequestsResponse>, Status> {
    let mut btc_client = BtcQueryClient::connect(host.to_string()).await.unwrap();
    btc_client.query_withdraw_requests(QueryWithdrawRequestsRequest {
        pagination: None,
        status: 0i32
    }).await
}

pub async fn get_signing_request_by_txid(host: &str, _txid: String) -> Result<Response<QueryWithdrawRequestsResponse>, Status> {
    let mut btc_client = BtcQueryClient::connect(host.to_string()).await.unwrap();
    btc_client.query_withdraw_requests(QueryWithdrawRequestsRequest {
        pagination: None,
        status: 0
    }).await
}

pub async fn mock_signing_requests() -> Result<SigningRequestsResponse, Error> {
    Ok(SigningRequestsResponse {
        requests: vec![
            SigningRequest {
                address: "bc1q5wgdhplnzn075eq7xep4zes7lnk5jy2ke0scsm".to_string(),
                psbt: "cHNidP8BAIkCAAAAARuMLk06K1ufndtymk3RaWdbLy21UYs9vUs8D6o8HjtNAAAAAAAAAAAAAkCcAAAAAAAAIlEglUAPVXmsEIekhIthcGwg/vRxs93mpUYfH3vFVlGNjiEoIwAAAAAAACJRIJVAD1V5rBCHpISLYXBsIP70cbPd5qVGHx97xVZRjY4hAAAAAAABAStQwwAAAAAAACJRIJVAD1V5rBCHpISLYXBsIP70cbPd5qVGHx97xVZRjY4hAQMEAAAAAAAAAA==".to_string(),
                status: "pending".to_string(),
                sequence: 1,
                vault_address: "bc1q5wgdhplnzn075eq7xep4zes7lnk5jy2ke0scsm".to_string(),
            }],
        pagination: None,
    })
}

pub async fn send_cosmos_transaction(shuttler: &Shuttler, msg : Any) {
    let conf = shuttler.config();

    if conf.side_chain.grpc.is_empty() {
        tracing::error!("GRPC URL is empty, skip sending");
        return;
    }

    // Generate sender private key.
    // In real world usage, this account would need to be funded before use.
    let sender_private_key = shuttler.relayer_key();
    // let sender_account_id = shuttler.relayer_address();

    ///////////////////////////
    // Building transactions //
    ///////////////////////////

    let base_account = shuttler.get_relayer_account().await;
    

    let mut base_client = TendermintServiceClient::connect(conf.side_chain.grpc.to_string()).await.unwrap();
    let resp_b = base_client.get_latest_block(GetLatestBlockRequest {
    }).await.unwrap();
    
    let chain_id = resp_b.into_inner().block.unwrap().header.unwrap().chain_id.parse().unwrap();
    let account_number = base_account.account_number;
    let sequence_number = base_account.sequence;
    let gas = conf.side_chain.gas;
    let timeout_height = 0u16;
    let memo = "tss_signer";

    let fees = Coin {
        amount: 2_000u128,
        denom: "uside".parse().unwrap(),
    };

    // Create transaction body from the MsgSend, memo, and timeout height.
    let tx_body = tx::Body::new(vec![msg], memo, timeout_height);

    // Create signer info from public key and sequence number.
    // This uses a standard "direct" signature from a single signer.
    let signer_info = SignerInfo::single_direct(Some(sender_private_key.public_key()), sequence_number);

    // Compute auth info from signer info by associating a fee.
    let auth_info = signer_info.auth_info(Fee::from_amount_and_gas(fees, gas as u64));

    //////////////////////////
    // Signing transactions //
    //////////////////////////

    // The "sign doc" contains a message to be signed.
    let sign_doc = SignDoc::new(&tx_body, &auth_info, &chain_id, account_number).unwrap();

    // Sign the "sign doc" with the sender's private key, producing a signed raw transaction.
    let tx_signed = sign_doc.sign(&sender_private_key).unwrap();

    // Serialize the raw transaction as bytes (i.e. `Vec<u8>`).
    let tx_bytes = tx_signed.to_bytes().unwrap();

    let mut tx_client = TxServiceClient::connect(conf.side_chain.grpc.to_string()).await.unwrap();
    match tx_client.broadcast_tx(BroadcastTxRequest {
        tx_bytes,
        mode: BroadcastMode::Sync.into(),    
    }).await {
        Ok(resp) => {
            tracing::info!("Transaction sent: {:?}", resp.into_inner());
        },
        Err(error) => {
            tracing::error!("Failed to send transaction: {:?}", error);
        }    
    };
    
   // post::<>(url.as_str(), tx).await
}