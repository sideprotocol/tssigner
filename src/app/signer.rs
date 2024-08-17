
use std::{collections::BTreeMap, fs, str::FromStr, sync::Mutex};

use bip39::Mnemonic;
use bitcoin::{key::{TapTweak as _, UntweakedPublicKey}, secp256k1, sighash::{self, SighashCache}, Address, TapNodeHash, Psbt, PublicKey, TxOut, Witness};
use bitcoin_hashes::Hash;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use cosmrs::{crypto::secp256k1::SigningKey, AccountId, Any};
use frost_core::{keys::{PublicKeyPackage, KeyPackage}, Field};
use futures::executor::block_on;
use libp2p::gossipsub::Message;
use cosmos_sdk_proto::{cosmos::auth::v1beta1::{query_client::QueryClient as AuthQueryClient, BaseAccount, QueryAccountRequest}, side::btcbridge::{MsgCompleteDkg, MsgSubmitWithdrawSignatures}};
use crate::{app::config::{self, Config, PrivValidatorKey}, helper::{client_side::send_cosmos_transaction, messages::now, bitcoin::{get_group_address, get_group_address_by_tweak}}};
use crate::helper::{
    cipher::{decrypt, encrypt}, encoding::{self, from_base64}, messages::{DKGRoundMessage, SignMessage, SigningBehaviour, SigningSteps, Task}, store
};
use frost::Identifier; 
use frost_secp256k1_tr::{self as frost, Secp256K1Sha256};

use ::bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;

use tracing::{debug, error, info};
use rand::thread_rng;
use ed25519_compact::{x25519, SecretKey};

use lazy_static::lazy_static;

lazy_static! {
    static ref BASE_ACCOUNT: Mutex<Option<BaseAccount>> = {
        Mutex::new(None)
    };
}

pub struct Shuttler {
    config: Config,
    identity_key: SecretKey,
    identifier: Identifier,
    validator_address: Vec<u8>,
    relayer_key: SigningKey,
    relayer_address: AccountId,

    pub bitcoin_client: Client,
}

impl Shuttler {
    pub fn new(conf: Config) -> Self {

        // load private key from priv_validator_key_path
        let text: String = fs::read_to_string(&conf.priv_validator_key_path).expect("failed to load priv_validator_key.json");
        let validator_key: PrivValidatorKey = serde_json::from_str::<PrivValidatorKey>(text.as_str()).expect("unable to parse priv_validator_key.json");

        let b = encoding::from_base64(&validator_key.priv_key.value).unwrap();
        
        let local_key = SecretKey::from_slice(b.as_slice()).expect("invalid secret key");
        let id = frost::Secp256K1ScalarField::deserialize(&local_key.public_key().as_slice().try_into().unwrap()).unwrap();
        let identifier = frost_core::Identifier::new(id).unwrap(); 

        info!("Threshold Signature Identifier: {:?}", identifier);

        let bitcoin_client = Client::new(
            &conf.bitcoin.rpc, 
            Auth::UserPass(conf.bitcoin.user.clone(), conf.bitcoin.password.clone()))
            .expect("Could not initial bitcoin RPC client");

        let hdpath = cosmrs::bip32::DerivationPath::from_str("m/44'/118'/0'/0/0").unwrap();
        let mnemonic = Mnemonic::parse(conf.mnemonic.as_str()).unwrap();

        let relayer_key = SigningKey::derive_from_path(mnemonic.to_seed(""), &hdpath).unwrap();
        let relayer_address =relayer_key.public_key().account_id(&conf.side_chain.address_prefix).expect("failed to derive relayer address");

        info!("Relayer Address: {:?}", relayer_address.to_string());

        Self {
            identity_key: local_key,
            identifier,
            validator_address: hex::decode(validator_key.address).unwrap(),
            bitcoin_client,
            relayer_key, 
            relayer_address,
            config: conf,
        }
    }

    pub fn dkg_init(&mut self, behave: &mut SigningBehaviour, task: &Task) {

        if store::has_dkg_preceeded(&task.id) {
            return
        }

        store::save_task(&task.id, task);

        let mut rng = thread_rng();
        let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
            self.identifier.clone(),
            task.max_signers,
            task.min_signers,
            &mut rng,
        )
        .expect("error in DKG round 1");
        debug!(
            "round1_secret_package: {:?}, {:?}",
            &round1_secret_package, &round1_package
        );
        

        store::set_dkg_round1_secret_packet(&task.id, round1_secret_package.clone());

        let round1_message = DKGRoundMessage {
            task_id: task.id.clone(),
            from_party_id: self.identifier,
            to_party_id: None,
            packet: &round1_package,
        };

        let new_msg = serde_json::to_string(&round1_message).expect("msg not serialized");
        match behave
            .gossipsub
            .publish(SigningSteps::DkgRound1.topic(), new_msg.as_bytes())
        {
            Ok(_) => {
                info!("Published dkg round1 message to gossip: {:?}", new_msg);
            }
            Err(e) => {
                error!("Failed to publish dkg round1 message to gossip: {:?}", e);
            }
        }
    }

    pub fn dkg_round1(&mut self, msg: &Message) {
        let round1_package: DKGRoundMessage<frost::keys::dkg::round1::Package> =
            serde_json::from_slice(&msg.data).expect("msg not deserialized");
        debug!("round1_package: {:?}", round1_package);

        store::set_dkg_round1_packets(
            &round1_package.task_id,
            round1_package.from_party_id,
            round1_package.packet.clone(),
        );

    }

    pub fn dkg_round2(&mut self, msg: &Message) {
        let round2_package: DKGRoundMessage<Vec<u8>> =
            serde_json::from_slice(&msg.data).expect("msg not deserialized");
        debug!("round2_package: {:?}", String::from_utf8_lossy(&msg.data));

        if let Some(to) = round2_package.to_party_id {
            if to != self.identifier {
                return;
            }
        }

        let bz = round2_package.from_party_id.serialize();
        let source = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();

        let share_key = source.dh(&x25519::SecretKey::from_ed25519(&self.identity_key).unwrap()).unwrap();

        let packet = decrypt(round2_package.packet.as_slice(), share_key.as_slice().try_into().unwrap());
        let received_round2_package =
            frost::keys::dkg::round2::Package::deserialize(&packet).unwrap();

        store::set_dkg_round2_packets(
            &round2_package.task_id,
            round2_package.from_party_id.clone(),
            received_round2_package,
        );

        if let Some(received_round2_packages) =
            store::get_dkg_round2_packets(&round2_package.task_id)
        {
            let task = match store::get_task(&round2_package.task_id) {
                Some(task) => task,
                None => {
                    error!("Failed to get dkg task: {}", round2_package.task_id);
                    return;
                }
            };
            if received_round2_packages.len() as u16 == task.max_signers - 1 {
                let round2_secret_package =
                    store::get_dkg_round2_secret_packet(&round2_package.task_id);
                match round2_secret_package {
                    Some(secret_package) => {
                        let received_round1_packages =
                            match store::get_dkg_round1_packets(round2_package.task_id.as_str()) {
                                Some(packages) => packages,
                                None => {
                                    error!("round1_secret_package not found");
                                    return;
                                }
                            };

                        let (key, pubkey) = frost::keys::dkg::part3(
                            &secret_package,
                            &received_round1_packages,
                            &received_round2_packages,
                        )
                        .expect("msg not deserialized");

                        // clean caches
                        // store::clear_dkg_variables(&round2_package.task_id);

                        let address = get_group_address(pubkey.verifying_key(), self.config.bitcoin.network);
                        info!(
                            "DKG Completed: {:?}, {:?}",
                            address.to_string(),
                            &pubkey,
                        );

                        let privkey_bytes = key.serialize().expect("key not serialized");
                        let pubkey_bytes = pubkey.serialize().expect("pubkey not serialized");
                        
                        config::add_sign_key(&address.to_string(), key.clone());
                        config::add_pub_key(&address.to_string(), pubkey.clone());

                        self.config
                            .keys
                            .insert(address.to_string(), encoding::to_base64(&privkey_bytes));
                        self.config
                            .pubkeys
                            .insert(address.to_string(), encoding::to_base64(&pubkey_bytes));
                        self.config.save().expect("Failed to save generated keys");

                        let address_with_tweak = self.add_address_with_tweak(pubkey, key, self.config.get_default_tweak());

                         // submit the vault address to sidechain
                         let mut cosm_msg = MsgCompleteDkg {
                            id: round2_package.task_id.parse().unwrap(),
                            sender: self.relayer_address.to_string(),
                            vaults: vec![address.to_string(), address_with_tweak.to_string()],
                            consensus_address: hex::encode_upper(&self.validator_address),
                            signature: "".to_string(),
                        };

                        cosm_msg.signature = self.get_complete_dkg_signature(cosm_msg.id, &cosm_msg.vaults);

                        let any = Any::from_msg(&cosm_msg).unwrap();
                        match block_on(send_cosmos_transaction(self, any)) {
                            Ok(resp) => {
                                let tx_response = resp.into_inner().tx_response.unwrap();
                                if tx_response.code != 0 {
                                    error!("Failed to send dkg vault: {:?}", tx_response);
                                    return
                                }
                                info!("Sent dkg vault: {:?}", tx_response);
                            },
                            Err(e) => {
                                error!("Failed to send dkg vault: {:?}", e);
                                return
                            },
                        };

                    }
                    None => {
                        error!("round2_secret_package not found");
                    }
                }
            }
        }
    }

    pub fn sign_init(&mut self, behave: &mut SigningBehaviour, task: &Task) {

        let psbt_bytes = from_base64(task.message.as_str()).unwrap();
        let group_task_id = bitcoin_hashes::sha256::Hash::hash(&psbt_bytes).to_string();

        let psbt = match Psbt::deserialize(psbt_bytes.as_slice()) {
            Ok(psbt) => psbt,
            Err(e) => {
                error!("Failed to deserialize PSBT: {}", e);
                return;
            }
        };

        // let txid = &psbt.unsigned_tx.compute_txid();
        // check if txid exists on sidechain.
        // if not, return

        store::set_signing_task(&group_task_id, psbt.clone());

        let len = psbt.inputs.len();
        debug!("(signing round 0) prepare for signing: {:?} tasks", len);
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
            let address: Address = Address::from_script(&script, self.config.bitcoin.network).unwrap();

            // get the message to sign
            let hash_ty = input
                .sighash_type
                .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                .unwrap_or(bitcoin::TapSighashType::Default);
            let hash = match SighashCache::new(&psbt.unsigned_tx).taproot_key_spend_signature_hash(
                i,
                &sighash::Prevouts::All(&[TxOut {
                    value: prev_utxo.value,
                    script_pubkey: script,
                }]),
                hash_ty,
            ) {
                Ok(hash) => hash,
                Err(e) => {
                    error!("failed to compute sighash: {}", e);
                    return;
                }
            };

            let sign_key = match config::get_sign_key(address.to_string().as_str()) {
                Some(key) => {
                    debug!("loaded key: {:?}", key);
                    key
                }
                None => {
                    error!("Failed to get signing key for address: {}", address);
                    continue;
                }
            };

            let mut rng = thread_rng();
            let (nonce, commitments) = frost::round1::commit(sign_key.signing_share(), &mut rng);

            let sub_task_id = format!("{}-{}", group_task_id, i);

            debug!("(signing round 0) save nonces for {:?} ", &sub_task_id);
            
            let variables = store::TaskVariables {
                signing_nonces: nonce,
                address: address.to_string(),
                // pubkey, 
                sighash: hash.to_raw_hash().to_byte_array().to_vec(),
                group_task_id: group_task_id.clone(),
                step: SigningSteps::SignInit,
            };
            store::set_signing_task_variables(&sub_task_id, variables);
            // store::set_sign_nonces(&sub_task_id, nonce);
            store::set_signing_commitments(&sub_task_id, self.identifier, commitments);

            let sign_message = SignMessage {
                task_id: sub_task_id,
                party_id: self.identifier,
                address: address.to_string(),
                // message: hex::encode(hash.to_raw_hash()),
                packet: commitments,
                timestamp : 0,
            };

            let new_msg = serde_json::to_string(&sign_message).expect("msg not serialized");
            match behave.gossipsub.publish(SigningSteps::SignRound1.topic(), new_msg.as_bytes()) {
                Ok(_) => {
                    debug!("Published commitments to gossip: {:?}", new_msg);
                }
                Err(e) => {
                    error!("Failed to publish message to gossip: {:?}", e);
                }
            };
        }
    }

    pub fn sign_round1(&mut self, msg: &Message) {

        let sign_message: SignMessage<frost::round1::SigningCommitments> =
            serde_json::from_slice(&msg.data).expect("error in sign_round1");

        // filter packets from unknown parties
        match config::get_pub_key(sign_message.address.as_str()) {
            Some(pubkey) => {

                // check if the pubkey is in the list of signers
                if pubkey.verifying_shares().contains_key(&sign_message.party_id) {
                    store::set_signing_commitments(
                        &sign_message.task_id,
                        sign_message.party_id,
                        sign_message.packet.clone(),
                    );

                    let signing_variables = match store::get_signing_task_variables(&sign_message.task_id) {
                        Some(variables) => variables,
                        None => {
                            error!("Failed to get signing variables for task: {}", &sign_message.task_id);
                            // store::clear_signing_variables(task_id);
                            return;
                        }        
                    };

                    let commitments = store::get_signing_commitments(&sign_message.task_id).unwrap();
                    debug!("(signing round 1) received commitments: {:?}, {}", &sign_message, commitments.len());

                    let key_package = match config::get_sign_key(&signing_variables.address) {
                        Some(pk) => pk,
                        None => {
                            error!("not found signing key for {}", &signing_variables.address);
                            return;
                        }
                    };

                    if commitments.len() < key_package.min_signers().clone() as usize {
                        info!("skip task, not enough commitments");
                        return;
                    }

                    // when number of receved commitments is larger than min_signers
                    // the following code will be executed or re-executed
                    let signing_package = frost::SigningPackage::new(
                        commitments.clone(), 
                        frost::SigningTarget::new(
                            &signing_variables.sighash, 
                            frost::SigningParameters{
                                tapscript_merkle_root: config::get_tweak(&sign_message.address)
                            }
                        ));
        
                    store::set_sign_package(&sign_message.task_id, signing_package.clone());
        
                    // if store::has_sign_shares(&sign_message.task_id) {
                    //     info!("skip task, already signed");
                    //     return;
                    // }
        
                    let signature_shares =
                        match frost::round2::sign(&signing_package, &signing_variables.signing_nonces, &key_package) {
                            Ok(shares) => shares,
                            Err(e) => {
                                error!("Error: {:?}", e);
                                return;
                            }
                        };
        
                    store::set_sign_shares(
                        sign_message.task_id.as_str(),
                        key_package.identifier().clone(), 
                        signature_shares,
                    );
                }
            }
            None => {
                error!("skip task, no pubkey found for task: {:?}", sign_message.task_id);
            }
        };

    }

    pub async fn sign_round2(&mut self, msg: &Message) {
        let sig_shares_message: SignMessage<frost::round2::SignatureShare> =
            serde_json::from_slice(&msg.data).expect("msg not deserialized");

        let signing_package = match store::get_sign_package(&sig_shares_message.task_id) {
            Some(package) => package,
            None => {
                error!("(signing round 2) Failed to get signing package for task: {}", sig_shares_message.task_id);
                return;
            }
        };

        if signing_package.signing_commitments().contains_key(&sig_shares_message.party_id) {
            debug!("(Signing Round 2) found commitment for: {:?}", sig_shares_message.party_id);
            store::set_sign_shares(
                &sig_shares_message.task_id,
                sig_shares_message.party_id,
                sig_shares_message.packet.clone(),
            );
        } else {
            error!("(Signing Round 2) commitment not found for: {:?}", sig_shares_message.party_id);
            return;
        }

        let signature_shares = match store::get_sign_shares(&sig_shares_message.task_id) {
            Some(shares) => shares,
            None => {
                error!(
                    "Failed to get shares for task: {}",
                    sig_shares_message.task_id
                );
                return;
            }
        };

        debug!("(signing round 2) received shares: {:?} {:?}", signature_shares.len(), &sig_shares_message);

        if signature_shares.len() == signing_package.signing_commitments().len()  {

            debug!("commentments keys: {:?}", signing_package.signing_commitments().keys());
            debug!("signature shares: {:?}", signature_shares.keys());

            let signing_variables = store::get_signing_task_variables(sig_shares_message.task_id.as_str()).unwrap();

            let pubkeys = match config::get_pub_key(&signing_variables.address) {
                Some(pk) => pk,
                None => {
                    error!("not found pubkey for : {:?}", &signing_variables.address);
                    return;
                }
            };

            match frost::aggregate(&signing_package, &signature_shares, &pubkeys) {
                Ok(signature) => {
                    // println!("public key: {:?}", pub)
                    // let sighash = &hex::decode(sig_shares_message.message).unwrap();
                    let is_signature_valid = pubkeys
                        .verifying_key()
                        .verify(signing_package.sig_target().clone(), &signature)
                        .is_ok();
                    info!(
                        "Signature: {:?} verified: {:?}",
                        signature, is_signature_valid
                    );
                  
                    match store::get_signing_task(&signing_variables.group_task_id) {
                        Some(psbt) => {
                            let mut psbt = psbt.clone();

                            let pubkey = PublicKey::from_slice(&pubkeys.verifying_key().serialize()).unwrap();
                            debug!("pubkey: {:?}", pubkey.to_bytes());

                            let sig_bytes = signature.serialize();
                            debug!("signature: {:?}, {}", sig_bytes, sig_bytes.len());

                            let secp = secp256k1::Secp256k1::new();
                            let utpk = UntweakedPublicKey::from(pubkey.inner);

                            let merkle_root = match signing_package.sig_target().sig_params().tapscript_merkle_root.clone() {
                                Some(root) => {
                                    if root.len() == 0 {
                                        None
                                    } else {
                                        Some(TapNodeHash::from_slice(&root).unwrap())
                                    }
                                }
                                None => None
                            };

                            let (tpk, _) = utpk.tap_tweak(&secp, merkle_root);
                            // let addr = Address::p2tr(&secp, tpk., None, Network::Bitcoin);
                            // let sig_b = group_signature.serialize();
                            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap();
                            let msg = bitcoin::secp256k1::Message::from_digest_slice(&signing_variables.sighash).unwrap();
                            match secp.verify_schnorr(&sig, &msg, &tpk.to_inner()) {
                                Ok(_) => info!("Signature is valid"),
                                Err(e) => error!("Signature is invalid: {}", e),
                            }

                            // add sig to psbt
                            let hash_ty = bitcoin::sighash::TapSighashType::Default;
                            // let sighash_type =  bitcoin::psbt::PsbtSighashType::from(hash_ty);
                            let sig = SchnorrSignature::from_slice(&sig_bytes).unwrap();
                            let index = extract_index_from_task_id(sig_shares_message.task_id.as_str());
                            // psbt.inputs[index].sighash_type = Option::Some(sighash_type);
                            psbt.inputs[index].tap_key_sig = Option::Some(bitcoin::taproot::Signature {
                                signature: sig,
                                sighash_type: hash_ty,
                            });

                            let witness = Witness::p2tr_key_spend(&psbt.inputs[index].tap_key_sig.unwrap());
                            psbt.inputs[index].final_script_witness = Some(witness);
                            psbt.inputs[index].partial_sigs = BTreeMap::new();
                            psbt.inputs[index].sighash_type = None;

                            let is_complete = psbt.inputs.iter().all(|input| {
                                input.final_script_witness.is_some()
                            });
                            debug!("is_complete: {:?}", is_complete);

                            if is_complete {

                                let psbt_bytes = psbt.serialize();
                                let psbt_base64 = encoding::to_base64(&psbt_bytes);
                                info!("Signed PSBT: {:?}", psbt_base64);

                                // broadcast to bitcoin network
                                let signed_tx = psbt.extract_tx().expect("failed to extract signed tx");
                                match self.bitcoin_client.send_raw_transaction(&signed_tx) {
                                    Ok(txid) => {
                                        info!("Tx broadcasted: {}", txid);
                                    }
                                    Err(err) => {
                                        error! ("Failed to broadcast tx: {:?}, err: {:?}", signed_tx.compute_txid(), err);
                                        return;
                                    }
                                }

                                // submit signed psbt to side chain
                                let msg = MsgSubmitWithdrawSignatures {
                                    sender: self.config().signer_address(),
                                    txid: signed_tx.compute_txid().to_string(),
                                    psbt: psbt_base64,
                                };

                                let any = Any::from_msg(&msg).unwrap();
                                match send_cosmos_transaction(self, any).await {
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
                            } else {
                                info!("PSBT is incomplete");
                            }

                        }
                        None => {
                            error!("Failed to get group task: {}", &signing_variables.group_task_id);
                        }                    
                    };
                }
                Err(e) => {
                    error!("Signature aggregation error: {:?}", e);
                }
            };
            // store::clear_signing_variables(sig_shares_message.task_id.as_str());
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn identifier(&self) -> &Identifier {
        &self.identifier
    }

    pub fn relayer_key(&self) -> &SigningKey {
        &self.relayer_key
    }

    pub fn relayer_address(&self) -> &AccountId {
        &self.relayer_address
    }

    pub fn validator_address(&self) -> &[u8] {
        &self.validator_address
    }

    pub async fn get_relayer_account(&self) -> BaseAccount {

        let cache = BASE_ACCOUNT.lock().unwrap().clone().map(|account| account);
        match cache {
            Some(account) => {
                let mut new_account = account.clone();
                new_account.sequence += 1;
                BASE_ACCOUNT.lock().unwrap().replace(new_account.clone());
                return new_account;
            }
            None => {
                let mut client = AuthQueryClient::connect(self.config.side_chain.grpc.clone()).await.unwrap();
                let request = QueryAccountRequest {
                    address: self.relayer_address.to_string(),
                };
        
                match client.account(request).await {
                    Ok(response) => {
        
                        let base_account: BaseAccount = response.into_inner().account.unwrap().to_msg().unwrap();
                        BASE_ACCOUNT.lock().unwrap().replace(base_account.clone());
                        base_account
                    }
                    Err(_) => {
                        panic!("Failed to get relayer account");
                    }
                }
            }
        }
    }

    pub fn add_address_with_tweak(&mut self, pubkey: PublicKeyPackage<Secp256K1Sha256>, key: KeyPackage<Secp256K1Sha256>, tweak: Vec<u8>) -> Address {
        let address_with_tweak = get_group_address_by_tweak(&pubkey.verifying_key(), tweak.clone(), self.config.bitcoin.network);

        let privkey_bytes = key.serialize().expect("key not serialized");
        let pubkey_bytes = pubkey.serialize().expect("pubkey not serialized");

        config::add_sign_key(&address_with_tweak.to_string(),key);
        config::add_pub_key(&address_with_tweak.to_string(), pubkey);
        config::add_tweak(&address_with_tweak.to_string(), tweak.clone());

        self.config.keys.insert(address_with_tweak.to_string(), encoding::to_base64(&privkey_bytes));
        self.config.pubkeys.insert(address_with_tweak.to_string(), encoding::to_base64(&pubkey_bytes));
        self.config.tweaks.insert(address_with_tweak.to_string(), String::from_utf8(tweak).expect("invalid tweak"));
        self.config.save().expect("Failed to save generated keys");

        address_with_tweak
    }

    pub fn get_complete_dkg_signature(&self, id: u64, vaults: &[String]) -> String {
        let mut sig_msg = id.to_be_bytes().to_vec();

        for v in vaults {
            sig_msg.extend(v.as_bytes())
        }

        sig_msg = hex::decode(sha256::digest(sig_msg)).unwrap();

        hex::encode(self.identity_key.sign(sig_msg, None))
    }
}

fn extract_index_from_task_id(task_id: &str) -> usize {
    let parts: Vec<&str> = task_id.split("-").collect();
    let index = parts[1].parse::<usize>().unwrap();
    index
}

pub fn broadcast_dkg_commitments(
    behave: &mut SigningBehaviour,
    signer: &mut Shuttler,
) {

    let pending_packages = store::get_all_dkg_round1_packets();
    pending_packages.iter().for_each(|(task_id, received_round1_packages)| {

        let task = match store::get_task(task_id) {
            Some(task) => task,
            None => {
                error!("Failed to get dkg task: {}", task_id);
                return;
            }
        };

        // check if the task has recevied enough packets
        if task.max_signers - 1 != received_round1_packages.len() as u16 {
            return;
        }

        let secret_package = match store::get_dkg_round1_secret_packet(task_id) {
            Some(secret) => secret,
            None => {
                error!("round1_secret_package not found");
                return;
            }
        };

        let (round2_secret_package, round2_packages) =
            frost::keys::dkg::part2(secret_package, &received_round1_packages)
                .expect("error in DKG round 2");
        debug!(
            "round2_secret_package: {:?}, {:?}",
            &round2_secret_package, &round2_packages
        );

        store::set_dkg_round2_secret_packet(
            &task_id,
            round2_secret_package.clone(),
        );

        for (receiver_identifier, round2_package) in round2_packages {
            let bz = receiver_identifier.serialize();
            let target = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();

            let share_key = target.dh(&x25519::SecretKey::from_ed25519(&signer.identity_key).unwrap()).unwrap();

            let byte = round2_package.serialize().unwrap();
            let packet = encrypt(byte.as_slice(), share_key.as_slice().try_into().unwrap());

            let round2_message = DKGRoundMessage {
                task_id: task_id.clone(),
                // min_signers: round1_package.min_signers,
                // max_signers: round1_package.max_signers,
                from_party_id: signer.identifier.clone(),
                to_party_id: Some(receiver_identifier.clone()),
                packet,
            };

            let new_msg =
                serde_json::to_string(&round2_message).expect("msg not serialized");
            match behave
                .gossipsub
                .publish(SigningSteps::DkgRound2.topic(), new_msg.as_bytes()) {
                    Ok(_) => {
                        info!("Published round2 to gossip: {:?}", new_msg);
                    },
                    Err(e) => {
                        info!("Failed to publish message to gossip: {:?}", e);
                    },
                };
        }
    });
}

pub fn broadcast_signing_commitments( 
    behave: &mut SigningBehaviour,
    signer: &mut Shuttler,
) {

    let pending_commitments = store::get_all_signing_commitments();

    pending_commitments.iter().for_each(|(task_id, commitments)| {
        let mut signing_variables = match store::get_signing_task_variables(task_id) {
            Some(variables) => variables,
            None => {
                error!("Failed to get signing variables for task: {}", task_id);
                // store::clear_signing_variables(task_id);
                return;
            }        
        };

        let sign_key = match config::get_sign_key(&signing_variables.address) {
            Some(pk) => pk,
            None => {
                error!("not found signing key for {}", &signing_variables.address);
                return;
            }
        };

        if signing_variables.step == SigningSteps::SignInit && commitments.len() as u16 >= *sign_key.min_signers() {
            debug!("(signing round 1) collected enough commitment {:?} for tasks {:?}", commitments.len(), task_id);

            // update step
            signing_variables.step = SigningSteps::SignRound1;
            store::set_signing_task_variables(task_id, signing_variables.clone());

            let signature_shares = match store::get_sign_shares(&task_id) {
                Some(shares) => shares,
                None => {
                    error!(
                        "Failed to get shares for task: {}",
                        task_id
                    );
                    return;
                }
            };

            let my_share = match signature_shares.get(&signer.identifier) {
                Some(share) => share,
                None => {
                    error!("Failed to get my share for task: {}", task_id);
                    return;
                }
            };

            let addr = &signing_variables.address.clone();
            let sig_shares_message = SignMessage {
                task_id: task_id.clone(),
                party_id: signer.identifier,
                address: addr.to_string(),
                packet: my_share,
                timestamp: now(),
            };

            let new_msg = serde_json::to_string(&sig_shares_message).unwrap();
            match behave.gossipsub.publish(SigningSteps::SignRound2.topic(), new_msg.as_bytes()) {
                Ok(_) => {
                    info!("Published signature share to gossip: {:?}", new_msg);
                }
                Err(e) => {
                    error!("Failed to publish message to gossip: {:?}", e);
                }
            };
        }
    });

}