use std::{sync::mpsc::SendError, time::Duration};

use bitcoin::{consensus::encode, Address, BlockHash, OutPoint, Transaction};
use bitcoincore_rpc::RpcApi;
use futures::join;
use prost_types::Any;
use tokio::{sync::Mutex, time::sleep};
use tracing::{debug, error, info};

use crate::{
    app::{config::{get_database_with_name, Config}, relayer::Relayer},
    helper::{
        bitcoin::{self as bitcoin_utils}, client_side, encoding::to_base64, 
    },
};

use cosmos_sdk_proto::side::btcbridge::{BlockHeader, MsgSubmitBlockHeaders, MsgSubmitDepositTransaction, MsgSubmitWithdrawTransaction, QueryParamsRequest};
use lazy_static::lazy_static;

#[derive(Debug)]
struct Lock {
    loading: bool,
}

const DB_KEY_BITCOIN_TIP: &str = "bitcoin_tip";
const DB_KEY_VAULTS: &str = "bitcoin_vaults";
const DB_KEY_VAULTS_LAST_UPDATE: &str = "bitcoin_vaults_last_update";

lazy_static! {
    static ref LOADING: Mutex<Lock> = Mutex::new(Lock { loading: false });
    static ref DB: sled::Db = {
        let path = get_database_with_name("relayer");
        sled::open(path).unwrap()
    };
}

/// Start relayer tasks
/// 1. Sync BTC blocks
/// 2. Scan vault txs
/// Only the coordinator will run the tasks, the coordinator is selected randomly from the active validator set
pub async fn start_relayer_tasks(relayer: &Relayer) {
    
    join!(
        sync_btc_blocks(relayer),
        scan_vault_txs_loop(relayer),
    );
}

pub async fn sync_btc_blocks(relayer: &Relayer) {

    loop {
        let tip_on_bitcoin = match relayer.bitcoin_client.get_block_count() {
            Ok(height) => height - 1,
            Err(e) => {
                error!(error=%e);
                return;
            }
        };

        let mut tip_on_side =
            match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
                Ok(res) => res.get_ref().height,
                Err(e) => {
                    error!(error=%e);
                    return;
                }
            };

        if tip_on_bitcoin == tip_on_side {
            debug!("No new blocks to sync, sleep for 60 seconds...");
            sleep(Duration::from_secs(60)).await;
            continue;
        }

        let mut lock = LOADING.lock().await;
        if lock.loading {
            info!("a previous task is running, skip!");
            return;
        }
        lock.loading = true;

        let mut block_headers: Vec<BlockHeader> = vec![];

        let batch = if tip_on_side + 10 > tip_on_bitcoin {
            tip_on_bitcoin
        } else {
            tip_on_side + 10
        };

        debug!("Syncing blocks from {} to {}", tip_on_side, batch);

        while tip_on_side < batch {
            tip_on_side = tip_on_side + 1;
            let hash = match relayer.bitcoin_client.get_block_hash(tip_on_side) {
                Ok(hash) => hash,
                Err(e) => {
                    error!(error=%e);
                    return;
                }
            };

            let header = match relayer.bitcoin_client.get_block_header(&hash) {
                Ok(b) => b,
                Err(e) => {
                    error!(error=%e);
                    return;
                }
            };

            block_headers.push(BlockHeader {
                version: header.version.to_consensus() as u64,
                hash: header.block_hash().to_string(),
                height: tip_on_side,
                previous_block_hash: header.prev_blockhash.to_string(),
                merkle_root: header.merkle_root.to_string(),
                nonce: header.nonce as u64,
                bits: format!("{:x}", header.bits.to_consensus()),
                time: header.time as u64,
                ntx: 0u64,
            });

            match send_block_headers(relayer, &block_headers) {
                Ok(_) => {
                    debug!("Block headers sent to sending pool, {:?}", block_headers.iter().map(|b| b.height).collect::<Vec<_>>());
                }
                Err(e) => {
                    error!("Failed to send block headers: {:?}", e);
                }
            }

        }

        lock.loading = false;
    }
}

pub fn send_block_headers(
    relayer: &Relayer,
    block_headers: &Vec<BlockHeader>,
) -> Result<(), SendError<Any>>  {
    let submit_block_msg = MsgSubmitBlockHeaders {
        sender: relayer.config().relayer_bitcoin_address().to_string(),
        block_headers: block_headers.clone(),
    };

    info!("Submitting block headers: {:?}", submit_block_msg);
    let any_msg = Any::from_msg(&submit_block_msg).unwrap();
    relayer.sender.send(any_msg)
    // send_cosmos_transaction(relayer.config(), any_msg).await
}

pub async fn scan_vault_txs_loop(relayer: &Relayer) {
    let mut height = get_last_scanned_height(relayer.config()) + 1;

    debug!("Start to scan vault txs from height: {}", height);

    loop {
        let side_tip =
            match client_side::get_bitcoin_tip_on_side(&relayer.config().side_chain.grpc).await {
                Ok(res) => res.get_ref().height,
                Err(e) => {
                    error!("Failed to get tip from side chain: {}", e);
                    continue;
                }
            };
        if height > side_tip - 1 {
            sleep(Duration::from_secs(60)).await;
            continue;
        }

        debug!("Scanning height: {:?}, side tip: {:?}", height, side_tip);

        scan_vault_txs(relayer, height).await;
        save_last_scanned_height(height);
        height += 1;
    }
}

pub async fn scan_vault_txs(relayer: &Relayer, height: u64) {
    let block_hash = match relayer.bitcoin_client.get_block_hash(height) {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to get block hash: {:?}, err: {:?}", height, e);
            return;
        }
    };

    let block = match relayer.bitcoin_client.get_block(&block_hash) {
        Ok(block) => block,
        Err(e) => {
            error!("Failed to get block: {}, err: {}", height, e);
            return;
        }
    };

    let vaults = get_cached_vaults(relayer.config().side_chain.grpc.clone()).await;

    for (i, tx) in block.txdata.iter().enumerate() {
        debug!(
            "Checking tx {:?}, height: {:?}, index: {:?}",
            tx.compute_txid(),
            height,
            i
        );

        if bitcoin_utils::may_be_withdraw_tx(&tx) {
            let prev_txid = tx.input[0].previous_output.txid;
            let prev_vout=tx.input[0].previous_output.vout;

            let address = match relayer
                .bitcoin_client
                .get_raw_transaction (&prev_txid, None)
            {
                Ok(prev_tx) => {
                    if prev_tx.output.len() <= prev_vout as usize {
                        error!("Invalid previous tx");
                        continue;
                    }

                    match Address::from_script(prev_tx.output[prev_vout as usize].script_pubkey.as_script(), relayer.config().bitcoin.network) {
                        Ok(addr) => Some(addr),
                        Err(e) => {
                            error!("Failed to parse public key script: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to get the previous tx: {:?}, err: {:?}",
                        prev_txid, e
                    );

                    None
                }
            };

            if address.is_some() {
                let address = address.unwrap().to_string();
                if vaults.contains(&address) {
                    debug!("Withdrawal tx found... {:?}", &tx);

                    let proof = bitcoin_utils::compute_tx_proof(
                        block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
                        i,
                    );

                    match send_withdraw_tx(relayer, &block_hash, &tx, proof) {
                        Ok(()) => {
                            info!("Added withdraw tx to sending pool" );
                        }
                        Err(e) => {
                            error!("Failed to add withdrawal tx to the pool: {:?}", e);
                        }
                    }

                    continue;
                }
            }
        }

        if bitcoin_utils::is_deposit_tx(tx, relayer.config().bitcoin.network, &vaults) {
            debug!("Deposit tx found... {:?}", &tx);

            if bitcoin_utils::is_runes_deposit(tx) {
                if !relayer.config().relay_runes {
                    debug!("Skip the tx due to runes relaying not enabled");
                    continue;
                }

                let edict = match bitcoin_utils::parse_runes(tx) {
                    Some(edict) => edict,
                    None => {
                        debug!("Failed to parse runes deposit tx {}", tx.compute_txid());
                        continue;
                    }
                };

                // get the rune by id
                let rune =match relayer.ordinals_client.get_rune(edict.id).await {
                    Ok(rune) => rune.entry.spaced_rune,
                    Err(e) => {
                        error!("Failed to get rune {}: {}", edict.id, e);
                        continue;
                    }
                };

                // get the runes output
                let output = match relayer.ordinals_client.get_output(OutPoint::new(tx.compute_txid(), edict.output)).await {
                    Ok(output) => output,
                    Err(e) => {
                        error!("Failed to get output {}:{} from ord: {}", tx.compute_txid(), edict.output, e);
                        continue;
                    }
                };

                // validate if the runes deposit is valid
                if !bitcoin_utils::validate_runes(&edict, &rune, &output) {
                    debug!("Failed to validate runes deposit tx {}", tx.compute_txid());
                    continue;
                }
            }

            let proof = bitcoin_utils::compute_tx_proof(
                block.txdata.iter().map(|tx| tx.compute_txid()).collect(),
                i,
            );

            let prev_txid = tx.input[0].previous_output.txid;
            let prev_tx = match relayer
                .bitcoin_client
                .get_raw_transaction(&prev_txid, None)
            {
                Ok(prev_tx) => prev_tx,
                Err(e) => {
                    error!(
                        "Failed to get the previous tx: {:?}, err: {:?}",
                        prev_txid, e
                    );

                    continue;
                }
            };

            match send_deposit_tx(relayer, &block_hash, &prev_tx, &tx, proof).await {
                Ok(_) => {
                    debug!("added tx into sending pool: {:?}", tx);
                }
                Err(e) => {
                    error!("Failed to submit deposit tx: {:?}", e);
                }
            }
        }
    }
}

pub fn send_withdraw_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<(), SendError<Any>> {
    let msg = MsgSubmitWithdrawTransaction {
        sender: relayer.config().relayer_bitcoin_address().to_string(),
        blockhash: block_hash.to_string(),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting withdrawal tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    relayer.sender.send(any_msg)
    //send_cosmos_transaction(relayer.config(), any_msg).await
}

pub async fn send_deposit_tx(
    relayer: &Relayer,
    block_hash: &BlockHash,
    prev_tx: &Transaction,
    tx: &Transaction,
    proof: Vec<String>,
) -> Result<(), SendError<Any>> {
    let msg = MsgSubmitDepositTransaction {
        sender: relayer.config().relayer_bitcoin_address(),
        blockhash: block_hash.to_string(),
        prev_tx_bytes: to_base64(encode::serialize(prev_tx).as_slice()),
        tx_bytes: to_base64(encode::serialize(tx).as_slice()),
        proof,
    };

    info!("Submitting deposit tx: {:?}", msg);

    let any_msg = Any::from_msg(&msg).unwrap();
    relayer.sender.send(any_msg)
    //send_cosmos_transaction(&relayer.config(), any_msg).await
}

pub(crate) fn get_last_scanned_height(config: &Config) -> u64 {
    match DB.get(DB_KEY_BITCOIN_TIP) {
        Ok(Some(tip)) => {
            serde_json::from_slice(&tip).unwrap_or(config.last_scanned_height)
        }
        _ => {
            config.last_scanned_height
        }
    }
}

fn save_last_scanned_height(height: u64) {
    let _ = DB.insert(DB_KEY_BITCOIN_TIP, serde_json::to_vec(&height).unwrap());
}

async fn get_cached_vaults(grpc: String) -> Vec<String> {
    if let Ok(Some(last_update)) = DB.get(DB_KEY_VAULTS_LAST_UPDATE) {
        let last_update: u64 = serde_json::from_slice(&last_update).unwrap_or(0);
        let now = chrono::Utc::now().timestamp() as u64;
        if now - last_update < 60 * 60 * 24 { // 24 hours
            if let Ok(Some(vaults)) =  DB.get(DB_KEY_VAULTS) {
                return serde_json::from_slice(&vaults).unwrap_or(vec![])
            };
        }
    }
    let mut client = cosmos_sdk_proto::side::btcbridge::query_client::QueryClient::connect(grpc).await.unwrap();
    let x = client.query_params(QueryParamsRequest{}).await.unwrap().into_inner();
    match x.params {
        Some(params) => {
            let vaults = params.vaults.iter().map(|v| v.address.clone()).collect::<Vec<_>>();
            let _ = DB.insert(DB_KEY_VAULTS, serde_json::to_vec(&vaults).unwrap());
            let _ = DB.insert(DB_KEY_VAULTS_LAST_UPDATE, serde_json::to_vec(&chrono::Utc::now().timestamp()).unwrap());
            vaults
        }
        None => vec![]
    }
}
