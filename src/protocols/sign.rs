use std::{collections::BTreeMap, sync::Mutex};

use bitcoin::{ sighash::{self, SighashCache}, Address, Psbt, TapSighashType, Witness};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::RpcApi;
use cosmos_sdk_proto::side::btcbridge::{BitcoinWithdrawRequest, MsgSubmitWithdrawSignatures};
use cosmrs::Any;

use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use frost::{Identifier, round1, round2}; 
use frost_secp256k1_tr::{self as frost, round1::SigningNonces};
use crate::{app::{config::{self, get_database_with_name}, signer::Signer}, helper::{client_side::send_cosmos_transaction, encoding::{self, from_base64}, gossip::publish_sign_package, now}};

use super::{dkg::list_tasks, Round, TSSBehaviour};
use lazy_static::lazy_static;

lazy_static! {
    // static ref DB: sled::Db = {
    //     let path = get_database_with_name("sign-variables");
    //     sled::open(path).unwrap()
    // };
    static ref DB_TASK: Mutex<sled::Db> = {
        let path = get_database_with_name("sign-task");
        Mutex::new(sled::open(path).unwrap())
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
    pub task_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignResponse {
    task_id: String,
    commitments: Vec<BTreeMap<Identifier, round1::SigningCommitments>>,
    // <sender, <receiver, package>>
    signatures_shares: Vec<BTreeMap<Identifier, round2::SignatureShare>>,
    nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignTask {
    pub id: String,
    pub psbt: String,
    pub round: Round,
    pub sessions: Vec<SignSession>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignSession {
    pub task_id: String,
    pub index: usize,
    pub sig_hash: Vec<u8>,
    pub address: String,
    /// NOTE: Should not share this with other parties
    pub nonces: SigningNonces,
    pub commitments: BTreeMap<Identifier, round1::SigningCommitments>,
    pub signatures: BTreeMap<Identifier, round2::SignatureShare>,
}

pub fn generate_nonce_and_commitments(request: BitcoinWithdrawRequest, signer: &Signer) {
    let task_db = DB_TASK.lock().unwrap();
    match task_db.contains_key(request.txid.as_bytes()) {
        Ok(false) => {
            info!("Fetched a new signing task: {:?}", request);
        }
        _ => {
            debug!("Task already exists: {:?}", request.txid);
            return;
        }
    }

    let psbt_bytes = from_base64(&request.psbt).unwrap();
    let group_task_id = request.txid.clone();

    let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return;
        }
    };

    let len = psbt.inputs.len();
    debug!("(signing round 0) prepare for signing: {:?} sessions of {:?}", len, request.txid );
    let mut sessions = Vec::new();
    let preouts = psbt.inputs.iter()
        .filter(|i| i.witness_utxo.is_some())
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect::<Vec<_>>();
    for i in 0..len {

        let input = &psbt.inputs[i];
        if input.witness_utxo.is_none() {
            continue;
        }

        let prev_utxo = match psbt.inputs[i].witness_utxo.clone() {
            Some(utxo) => utxo,
            None => {
                error!("Failed to get witness_utxo");
                return;
            }
        };

        info!("prev_tx: {:?}", prev_utxo.script_pubkey);
        let script = input.witness_utxo.clone().unwrap().script_pubkey;
        let address: Address = Address::from_script(&script, signer.config().bitcoin.network).unwrap();

        // get the message to sign
        let hash_ty = input
            .sighash_type
            .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
            .unwrap_or(bitcoin::TapSighashType::Default);
        let hash = match SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
            i,
            &sighash::Prevouts::All(&preouts),
            hash_ty,
        ) {
            Ok(hash) => hash,
            Err(e) => {
                error!("failed to compute sighash: {}", e);
                return;
            }
        };

        let sign_key = match config::get_keypair_from_db(&address.to_string()) {
            Some(key) => {
                debug!("loaded key for address: {:?}", address);
                key.priv_key
            }
            None => {
                error!("Failed to get signing key for address: {}", address);
                continue;
            }
        };

        let mut rng = thread_rng();
        let (nonce, commitments) = frost::round1::commit(sign_key.signing_share(), &mut rng);

        let mut commitments_map = BTreeMap::new();
        commitments_map.insert(signer.identifier().clone(), commitments.clone());
        let trasaction = SignSession {
            task_id: group_task_id.clone(),
            index: i,
            sig_hash: hash.to_raw_hash().to_byte_array().to_vec(),
            address: address.to_string(),
            nonces: nonce,
            commitments: commitments_map,
            signatures: BTreeMap::new(),
        };

        sessions.push(trasaction);
 
    }

    let task = SignTask {
        id: group_task_id.clone(),
        psbt: request.psbt.clone(),
        round: Round::Round1,
        sessions,
    };

    save_sign_task(&task);

}

pub fn prepare_response_for_request(task_id: String) -> Option<SignResponse> {
    let task = match get_sign_task(&task_id) {
        Some(task) => task,
        None => return None,
    };
    Some(SignResponse {
        task_id: task.id.clone(),
        commitments: task.sessions.iter().map(|session| session.commitments.clone()).collect::<Vec<_>>(),
        signatures_shares: task.sessions.iter().map(|session| session.signatures.clone()).collect::<Vec<_>>(),
        nonce: now(),
    })
}

pub fn received_sign_response(response: SignResponse) {

    let task_id = response.task_id.clone();

    let mut task = match get_sign_task(&task_id) {
        Some(task) => task,
        None => {
            debug!("task does not exist: {}", task_id);
            return;
        }
    };
    task.sessions.iter_mut().enumerate().for_each(|(i, session)| {
        let packet = response.commitments.get(i).unwrap();
        session.commitments.extend(packet); // merge received commitments
    });

    task.sessions.iter_mut().enumerate().for_each(|(i, session)| {
        let packet = response.signatures_shares.get(i).unwrap();
        session.signatures.extend(packet); // merge received signatures
    });

    debug!("Received response for task: {:?} {:?} {:?}", task_id, 
        task.sessions.iter().map(|s| s.commitments.clone()).collect::<Vec<_>>(),
        task.sessions.iter().map(|s| s.signatures.clone()).collect::<Vec<_>>(),
    );

    save_sign_task(&task);

}

pub fn generate_signature_shares(task: &mut SignTask, identifier: Identifier) {

    if task.round == Round::Closed {
        return;
    }

    task.sessions.iter_mut().enumerate().for_each(|(i, session)| {
        // filter packets from unknown parties
        match config::get_keypair_from_db(&session.address) {
            Some(keypair) => {

                if session.commitments.len() < *keypair.priv_key.min_signers() as usize {
                    error!("skip task, not enough commitments for task: {:?} {}", task.id, i);
                    return;
                }

                if session.signatures.contains_key(&identifier) {
                    debug!("skip task, already signed for task: {:?} {}", task.id, i);
                    return;
                }

                // when number of receved commitments is larger than min_signers
                // the following code will be executed or re-executed
                let signing_package = frost::SigningPackage::new(
                    session.commitments.clone(), 
                    frost::SigningTarget::new(
                        &session.sig_hash, 
                        frost::SigningParameters{
                            tapscript_merkle_root: match keypair.tweak {
                                Some(tweak) => Some(tweak.to_vec()),
                                None => None,
                            },
                        }
                    ));

                let signature_shares =
                    match frost::round2::sign(&signing_package, &session.nonces, &keypair.priv_key) {
                        Ok(shares) => shares,
                        Err(e) => {
                            error!("Error: {:?}", e);
                            return;
                        }
                    };
                session.signatures.insert(identifier, signature_shares);
            }
            None => {
                error!("skip task, not found keypair for task: {:?}", task.id);
            }
        };
    });

    save_sign_task(task)

}

pub fn aggregate_signature_shares(task: &mut SignTask) -> Option<Psbt> {

    if task.round == Round::Closed {
        return None;
    }
    
    let psbt_bytes = from_base64(&task.psbt).unwrap();
    let mut psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
        Ok(psbt) => psbt,
        Err(e) => {
            error!("Failed to deserialize PSBT: {}", e);
            return None;
        }
    };

    // task.sessions.iter().enumerate().for_each(|(index, session)| {
    for (index, session) in task.sessions.iter().enumerate() {

        if session.commitments.len() != session.signatures.len() {
            return None;
        }
        let keypair = match config::get_keypair_from_db(&session.address) {
            Some(keypair) => keypair,
            None => {
                error!("Failed to get keypair for address: {}", session.address);
                return None;
            }
        };
        if session.signatures.len() < *keypair.priv_key.min_signers() as usize {
            return None;
        }
        let sig_target = frost::SigningTarget::new(
            &session.sig_hash,
            frost::SigningParameters {
                tapscript_merkle_root:  match keypair.tweak {
                        Some(tweak) => Some(tweak.to_vec()),
                        None => None,
                    },
                }
        );
        let signing_package = frost::SigningPackage::new(
            session.commitments.clone(),
            sig_target
        );

        match frost::aggregate(&signing_package, &session.signatures, &keypair.pub_key) {
            Ok(signature) => {
                // println!("public key: {:?}", pub)
                // let sighash = &hex::decode(sig_shares_message.message).unwrap();
                let is_signature_valid = keypair.pub_key
                    .verifying_key()
                    .verify(signing_package.sig_target().clone(), &signature)
                    .is_ok();
                info!(
                    "Signature: {:?} verified: {:?}",
                    signature, is_signature_valid
                );

                if !is_signature_valid {
                    error!("Signature is invalid");
                    return None;
                }

                let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature.serialize()).unwrap();

                psbt.inputs[index].tap_key_sig = Option::Some(bitcoin::taproot::Signature {
                    signature: sig,
                    sighash_type: TapSighashType::Default,
                });

                let witness = Witness::p2tr_key_spend(&psbt.inputs[index].tap_key_sig.unwrap());
                psbt.inputs[index].final_script_witness = Some(witness);
                psbt.inputs[index].partial_sigs = BTreeMap::new();
                psbt.inputs[index].sighash_type = None;
            }
            Err(e) => {
                error!("Signature aggregation error: {:?}", e);
            }
        };
    };

    let is_complete = psbt.inputs.iter().all(|input| {
        input.final_script_witness.is_some()
    });
    debug!("Is {} complete: {:?}", task.id, is_complete);

    if is_complete {
        task.round = Round::Closed;
        save_sign_task(task);
        return Some(psbt.to_owned())
    }

    save_sign_task(task);
    None
}

pub async fn submit_signatures(psbt: Psbt, signer: &Signer) {

    // broadcast to bitcoin network
    let signed_tx = psbt.clone().extract_tx().expect("failed to extract signed tx");
    match signer.bitcoin_client.send_raw_transaction(&signed_tx) {
        Ok(txid) => {
            info!("Tx broadcasted: {}", txid);
        }
        Err(err) => {
            error! ("Failed to broadcast tx: {:?}, err: {:?}", signed_tx.compute_txid(), err);
            return;
        }
    }

    let psbt_bytes = psbt.serialize();
    let psbt_base64 = encoding::to_base64(&psbt_bytes);
    info!("Signed PSBT: {:?}", psbt_base64);

    // submit signed psbt to side chain
    let msg = MsgSubmitWithdrawSignatures {
        sender: signer.config().relayer_bitcoin_address(),
        txid: signed_tx.compute_txid().to_string(),
        psbt: psbt_base64,
    };

    let any = Any::from_msg(&msg).unwrap();
    match send_cosmos_transaction(signer.config(), any).await {
        Ok(resp) => {
            let tx_response = resp.into_inner().tx_response.unwrap();
            if tx_response.code != 0 {
                error!("Failed to submit signatures: {:?}", tx_response);
                return
            }
            info!("Submitted signatures: {:?}", tx_response);
        },
        Err(e) => {
            error!("Failed to submit signatures: {:?}", e);
            return
        },
    };
    // send message to the network
}

pub async fn collect_tss_packages(swarm: &mut libp2p::Swarm<TSSBehaviour>, signer: &Signer) {

    for mut task in list_sign_tasks() {

        debug!("Collected task: {:?}", task);
        // try to generate signature shares if shares is enough
        generate_signature_shares(&mut task, signer.identifier().clone());
        if let Some(psbt) = aggregate_signature_shares(&mut task) {
            submit_signatures(psbt, signer).await;
        }

        if task.round == Round::Closed {
            continue;
        }

        // publish its packages to other peers
        publish_sign_package(swarm, &task);

        // request packages from other connected peers
        // peers.iter().for_each(|p| {
        //     let request = SignRequest {
        //         task_id: task.id.clone()
        //     };
        //     debug!("Sent Signer Request to {p}: {:?}", &request);
        //     swarm.behaviour_mut().signer.send_request(p, request);
        // })
    };
}

// pub fn tss_event_handler(behave: &mut TSSBehaviour, peer: &PeerId, message: request_response::Message<SignRequest, SignResponse>) {
//     // handle dkg events
//     debug!("Received TSS response from {peer}: {:?}", &message);
//     match message {
//         request_response::Message::Request { request_id, request, channel } => {
//             debug!("Received TSS Request from {peer}: {request_id}");
//             if let Some(response) = prepare_response_for_request(request.task_id) {
//                 match behave.signer.send_response(channel, response) {
//                     Ok(_) => {
//                         debug!("Sent TSS Response to {peer}: {request_id}");
//                     }
//                     Err(e) => {
//                         error!("Failed to send TSS Response to {peer}: {request_id} - {:?}", e);
//                     }
//                 };
//             }
//         }

//         request_response::Message::Response { request_id, response } => {
//             debug!("Received TSS Response from {peer}: {request_id}");
//             received_response(response);
//         }
//     }
// }
pub fn list_sign_tasks() -> Vec<SignTask> {
    let mut tasks = vec![];

    let task_db = DB_TASK.lock().unwrap();
    debug!("loading in-process sign tasks from database, total: {:?}", task_db.len());
    for task in task_db.iter() {
        let (_, task) = task.unwrap();
        tasks.push(serde_json::from_slice(&task).unwrap());
    }
    tasks
}

fn get_sign_task(id: &str) -> Option<SignTask> {
    let task_db = DB_TASK.lock().unwrap();
    match task_db.get(id) {
        Ok(Some(task)) => {
            let task: SignTask = serde_json::from_slice(&task).unwrap();
            Some(task)
        },
        _ => None,
    }
}

fn save_sign_task(task: &SignTask) {
    let value = serde_json::to_vec(&task).unwrap();
    let task_db = DB_TASK.lock().unwrap();
    task_db.insert(task.id.as_bytes(), value).unwrap();
}

pub fn delete_tasks() {
    let task_db = DB_TASK.lock().unwrap();
    task_db.clear().unwrap();
    task_db.flush().unwrap();
}

pub fn remove_task(task_id: &str) {

    let task_db = DB_TASK.lock().unwrap();
    match task_db.remove(task_id) {
        Ok(_) => {
            info!("Removed task from database: {}", task_id);
        },
        _ => {
            error!("Failed to remove task from database: {}", task_id);
        }
    };
}