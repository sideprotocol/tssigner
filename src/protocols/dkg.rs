

use core::fmt;
use std::{collections::BTreeMap, fmt::Debug};
use cosmos_sdk_proto::side::btcbridge::DkgRequest;
use ed25519_compact::{x25519, SecretKey};
use rand::thread_rng;
use tracing::{debug, error, info};
use serde::{Deserialize, Serialize};


use frost_secp256k1_tr::{self as frost};
use frost::{keys, Identifier, Secp256K1Sha256};

use frost_core::keys::dkg::round1::Package;
use super::{Round, TSSBehaviour};
use crate::{app::{config:: get_database_with_name, signer::Signer}, helper::{gossip::publish_dkg_packages, now, mem_store}};
use crate::helper::cipher::{decrypt, encrypt};


use lazy_static::lazy_static;

lazy_static! {
    static ref DB: sled::Db = {
        let path = get_database_with_name("dkg-variables");
        sled::open(path).unwrap()
    };
    static ref DB_TASK: sled::Db = {
        let path = get_database_with_name("dkg-task");
        sled::open(path).unwrap()
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGTask {
    pub id: String,
    pub participants: Vec<String>,
    pub threshold: u16,
    pub round: Round,
    pub timestamp: i64,
    pub address_num: u16,
    pub dkg_vaults: Vec<String>,
    pub submitted: bool,
}

impl DKGTask {
    pub fn from_request(request: &DkgRequest) -> Self {
        Self {
            id: format!("dkg-{}", request.id),
            participants: request.participants.iter().map(|p| {
                p.consensus_address.clone()
            }).collect(), 
            threshold: request.threshold as u16,
            round: Round::Round1,
            timestamp: match request.expiration {
                Some(expiration) => expiration.seconds,
                None => 0,
            },
            address_num: request.vault_types.len() as u16,
            dkg_vaults: vec![],
            submitted: false,
        }
    }
    
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKGRequest {
    pub task_id: String,
    pub round: Round,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct  DKGResponse {
    pub task_id: String,
    pub round1_packages: BTreeMap<Identifier, keys::dkg::round1::Package>,
    // <sender, <receiver, package>>
    pub round2_packages: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>,
    pub nonce: u64,
}

pub fn has_task_preceeded(task_id: &str) -> bool {
    match DB_TASK.get(task_id) {
        Ok(Some(_)) => true,
        _ => false,
    }
}

pub fn generate_round1_package(identifier: Identifier, task: &DKGTask) {

    if has_task_preceeded(task.id.to_string().as_str()) {
        debug!("DKG has already preceeded: {}", task.id);
        return;
    };

    let mut rng = thread_rng();
    if let Ok((secret_packet, round1_package)) = frost::keys::dkg::part1(
        identifier,
        task.participants.len() as u16,
        task.threshold as u16,
        &mut rng,
    ) {
        debug!(
            "round1_secret_package: {:?}, {:?}",
            task.id, &round1_package
        );
        mem_store::set_dkg_round1_secret_packet(task.id.to_string().as_str(), secret_packet);

        let mut round1_packages = BTreeMap::new();
        round1_packages.insert(identifier, round1_package);

        let value = serde_json::to_vec(&round1_packages).unwrap();
        match DB.insert(format!("dkg-{}-round1", task.id), value) {
            Ok(_) => {
                info!("DKG round 1 completed: {}", task.id);
            }
            Err(e) => {
                error!("error in DKG round 1: {:?}", e);
            }
        }
     } else {
        error!("error in DKG round 1: {:?}", task.id);
     }
}

pub fn generate_round2_packages(identifier: &Identifier, enc_key: &SecretKey, task: &mut DKGTask, round1_packages: BTreeMap<Identifier, Package<Secp256K1Sha256>>) -> Result<(), DKGError> {

    let task_id = task.id.clone();

    let secret_package = match mem_store::get_dkg_round1_secret_packet(&task_id) {
        Some(secret_packet) => secret_packet,
        None => {
            return Err(DKGError(format!("No secret packet found for DKG: {}", task_id)));
        }
    };

    if task.participants.len() as u16 != round1_packages.len() as u16 {
        return Err(DKGError(format!("Have not received enough packages: {}", task_id)));
    }

    info!("Generating round2 packages: {task_id}, {:?}", &round1_packages);

    let mut cloned = round1_packages.clone();
    cloned.remove(identifier);

    match frost::keys::dkg::part2(secret_package, &cloned) {
        Ok((round2_secret_package, round2_packages)) => {
            mem_store::set_dkg_round2_secret_packet(&task_id, round2_secret_package);

            // convert it to <receiver, Vec<u8>>, then only the receiver can decrypt it.
            let mut output_packages = BTreeMap::new();
            for (receiver_identifier, round2_package) in round2_packages {
                let bz = receiver_identifier.serialize();
                let target = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
    
                let share_key = target.dh(&x25519::SecretKey::from_ed25519(enc_key).unwrap()).unwrap();
    
                let byte = round2_package.serialize().unwrap();
                let packet = encrypt(byte.as_slice(), share_key.as_slice().try_into().unwrap());
    
                output_packages.insert(receiver_identifier, packet);
            };

            // convert it to <sender, <receiver, Vec<u8>>
            let mut merged = BTreeMap::new();
            merged.insert(identifier, output_packages);

            let value = serde_json::to_vec(&merged).unwrap();

            match DB.insert(format!("dkg-{}-round2", &task_id), value) {
                Ok(_) => {
                    info!("DKG round 2 completed: {task_id}");
                }
                Err(e) => {
                    return Err(DKGError(e.to_string()));
                }
            };
        }
        Err(e) => {
            return Err(DKGError(e.to_string()));
        }
    };
    Ok(())
}

pub fn collect_dkg_packages(swarm: &mut libp2p::Swarm<TSSBehaviour>) {
    let tasks = list_tasks();
    for t in tasks.iter() {
        if t.timestamp as u64 >= now() {
            // publish its packages to other peers
            publish_dkg_packages(swarm, &t);
        } else {
            // remove the task
            remove_task(t.id.as_str());
        }
    }
}

pub fn prepare_response_for_task(task_id: String) -> DKGResponse {
    let round1_packages = match DB.get(format!("dkg-{}-round1", task_id)) {
        Ok(Some(packets)) => {
            match serde_json::from_slice(&packets) {
                Ok(packets) => packets,
                Err(e) => {
                    error!("Failed to deserialize DKG Round 1 packets: {:?}", e);
                    BTreeMap::new()
                }
            }
        },
        _ => {
            debug!("No DKG Round 1 packets found: {task_id}");
            BTreeMap::new()
        },
    };
    let round2_packages = match DB.get(format!("dkg-{}-round2", task_id)) {
        Ok(Some(packets)) => {
            match serde_json::from_slice(&packets) {
                Ok(packets) => packets,
                Err(e) => {
                    error!("Failed to deserialize DKG Round 2 packets: {:?}", e);
                    BTreeMap::new()
                }
            }
        },
        _ => {
            debug!("No DKG Round 2 packets found: {task_id}");
            BTreeMap::new()
        },
    };
    DKGResponse{ task_id, round1_packages, round2_packages, nonce: now() }
}

pub fn received_dkg_response(response: DKGResponse, signer: &Signer) {
    let task_id = response.task_id.clone();
    let mut task = match get_task(&task_id) {
        Some(task) => task,
        None => {
            error!("No task found for DKG: {}", task_id);
            return;
        }
    };

    if task.round == Round::Round1 {
        received_round1_packages(&mut task, response.round1_packages, signer.identifier(), &signer.identity_key)
    } else if task.round == Round::Round2 {
        received_round2_packages(&mut task, response.round2_packages, signer)
    } else {
        debug!("DKG has already completed on my side: {}", task_id);
    }
}
// pub fn prepare_round1_package_for_request(task_id: String) -> DKGResponse {

//     // behave.dkg.send_response(channel, DKGResponse::Round1 { task_id, packets: BTreeMap::new() });
//     let packets = match DB.get(format!("dkg-{}-round1", task_id)) {
//         Ok(Some(packets)) => {
//             match serde_json::from_slice(&packets) {
//                 Ok(packets) => packets,
//                 Err(e) => {
//                     error!("Failed to deserialize DKG Round 1 packets: {:?}", e);
//                     BTreeMap::new()
//                 }
//             }
//         },
//         _ => {
//             debug!("No DKG Round 1 packets found: {task_id}");
//             BTreeMap::new()
//         },
//     };
//     DKGResponse::Round1 { task_id, packets, nonce: now() }
// }

// pub fn prepare_round2_package_for_request(task_id: String) -> DKGResponse {
//     // behave.dkg.send_response(channel, DKGResponse::Round2 { task_id, packets: BTreeMap::new() });
//     let packets = match DB.get(format!("dkg-{}-round2", task_id)) {
//         Ok(Some(packets)) => {
//             match serde_json::from_slice(&packets) {
//                 Ok(packets) => packets,
//                 Err(e) => {
//                     error!("Failed to deserialize DKG Round 2 packets: {:?}", e);
//                     BTreeMap::new()
//                 }
//             }
//         },
//         _ => {
//             debug!("No DKG Round 2 packets found: {task_id}");
//             BTreeMap::new()
//         },
//     };
//     DKGResponse::Round2 { task_id, packets, nonce: now() }
// }

pub fn received_round1_packages(task: &mut DKGTask, packets: BTreeMap<Identifier, keys::dkg::round1::Package>, identifier: &Identifier, enc_key: &SecretKey) {
    // let mut task = match get_task(&task_id) {
    //     Some(task) => task,
    //     None => {
    //         error!("No task found for DKG: {}", task_id);
    //         return;
    //     }
    // };
    // store round 1 packets
    let mut local = match DB.get(format!("dkg-{}-round1", task.id)) {
        Ok(Some(local)) => {
            match serde_json::from_slice(&local) {
                Ok(local) => local,
                Err(e) => {
                    error!("Failed to deserialize local DKG Round 1 packets: {:?}", e);
                    BTreeMap::new()
                }
            }
        },
        _ => {
            debug!("No local DKG Round 1 packets found: {}", task.id);
            BTreeMap::new()
        },
    };

    // merge packets with local
    local.extend(packets);

    match DB.insert(format!("dkg-{}-round1", task.id), serde_json::to_vec(&local).unwrap()) {
        Ok(_) => {
            debug!("Stored DKG Round 1 packets: {}: {} packages", task.id, local.len());
        }
        Err(e) => {
            error!("Failed to store DKG Round 1 packets: {} - {:?}", task.id, e);
        }
    }

    if task.participants.len() == local.len() {
        info!("Received round1 packets from all participants: {}", task.id);

        match generate_round2_packages(identifier, enc_key, task, local) {
            Ok(_) => {
                task.round = Round::Round2;
                save_task(&task);
            }
            Err(e) => {
                task.round = Round::Closed;
                save_task(&task);
                error!("Failed to generate round2 packages: {} - {:?}", task.id, e);
            }
        }
        return;
    }
}

pub fn received_round2_packages(task: &mut DKGTask, packets: BTreeMap<Identifier, BTreeMap<Identifier, Vec<u8>>>, signer: &Signer) {
    // let mut task = match get_task(&task_id) {
    //     Some(task) => task,
    //     None => {
    //         error!("No task found for DKG: {}", task_id);
    //         return;
    //     }
    // };

    if task.round == Round::Closed {
        debug!("DKG is already closed: {}", task.id);
        return;
    }

    // store round 1 packets
    let mut local = match DB.get(format!("dkg-{}-round2", task.id)) {
        Ok(Some(local)) => {
            match serde_json::from_slice(&local) {
                Ok(local) => local,
                Err(e) => {
                    error!("Failed to deserialize local DKG Round 1 packets: {:?}", e);
                    BTreeMap::new()
                }
            }
        },
        _ => {
            debug!("Not found local DKG Round 2 packets: {}", task.id);
            BTreeMap::new()
        },
    };

    local.extend(packets);

    // store round 2 packets
    match DB.insert(format!("dkg-{}-round2", task.id), serde_json::to_vec(&local).unwrap()) {
        Ok(_) => {
            debug!("Stored DKG Round 2 packets: {}:  {} packages", task.id, local.len());
        }
        Err(e) => {
            error!("Failed to store DKG Round 2 packets: {} - {:?}", task.id, e);
        }
    }

    if task.participants.len() == local.len() {
        info!("Received round2 packets from all participants: {}", task.id);

        let mut round2_packages = BTreeMap::new();
        local.iter().for_each(|(sender, packages)| {
            packages.iter().for_each(|(receiver, packet)| {
                if receiver == signer.identifier() {
                    let packet = packet.clone();
                    
                    let bz = sender.serialize();
                    let source = x25519::PublicKey::from_ed25519(&ed25519_compact::PublicKey::from_slice(bz.as_slice()).unwrap()).unwrap();
                    let share_key = source.dh(&x25519::SecretKey::from_ed25519(&signer.identity_key).unwrap()).unwrap();

                    let packet = decrypt(packet.as_slice(), share_key.as_slice().try_into().unwrap());
                    let received_round2_package = frost::keys::dkg::round2::Package::deserialize(&packet).unwrap();
                    debug!("Received round2 package: {:?}", received_round2_package);
                    round2_packages.insert(sender.clone(), received_round2_package);
                }
            })
        });

        info!("Received round2 packages from all participants: {}, {:?}", task.id, round2_packages);

        // compute the threshold key
        let round2_secret_package = match mem_store::get_dkg_round2_secret_packet(&task.id) {
            Some(secret_package) => secret_package,
            None => {
                error!("No secret packet found for DKG: {}", task.id);
                return;
            }
        };

        let mut round1_packages = match DB.get(format!("dkg-{}-round1", task.id)) {
            Ok(Some(packets)) => {
                match serde_json::from_slice(&packets) {
                    Ok(packets) => packets,
                    Err(e) => {
                        error!("Failed to deserialize DKG Round 1 packets: {:?}", e);
                        BTreeMap::new()
                    }
                }
            },
            _ => {
                debug!("No DKG Round 1 packets found: {}", task.id);
                BTreeMap::new()
            },
        };

        // let mut round1_packages_cloned = round1_packages.clone();
        // remove self
        // frost does not need its own package to compute the threshold key
        round1_packages.remove(signer.identifier()); 

        let (key, pubkey) = match frost::keys::dkg::part3(
            &round2_secret_package,
            &round1_packages,
            &round2_packages,
        ) {
            Ok((key, pubkey)) => (key, pubkey),
            Err(e) => {
                error!("Failed to compute threshold key: {:?}", e);
                return;
            }
        };

        // generate vault addresses and save its key share
        let address_with_tweak = signer.generate_vault_addresses(pubkey, key, task.address_num);

        task.round = Round::Closed;
        task.dkg_vaults = address_with_tweak;
        save_task(&task);
        
    }
}

// pub fn dkg_event_handler(signer: &Signer, behave: &mut TSSBehaviour, peer: &PeerId, message: Message<DKGRequest, DKGResponse>) {
//     // handle dkg events
//     debug!("Reqeust-Response Received DKG response from {peer}: {:?}", &message);
//     match message {
//         request_response::Message::Request { request_id, request, channel } => {
//             debug!("Received DKG Request from {peer}: {request_id}");
//             let response = match request { DKGRequest { task_id, round } => {
//                     match round {
//                         Round::Round1 => {
//                             // send round 1 packets to requester
//                             debug!("Received DKG Round 1 Request from {peer}, {request_id}");
//                             prepare_round1_package_for_request(task_id)
//                         }
//                         Round::Round2 => {
//                             // send round 2 packets to requester
//                             debug!("Received DKG Round 2 Request from {peer}: {request_id}");
//                             prepare_round2_package_for_request(task_id)
//                         }
//                         // skip other rounds
//                         _ => {return;},
//                     }
//                 }
//             };
//             match behave.dkg.send_response(channel, response) {
//                 Ok(_) => {
//                     debug!("Sent DKG Response to {peer}: {request_id}");
//                 }
//                 Err(e) => {
//                     error!("Failed to send DKG Response to {peer}: {request_id} - {:?}", e);
//                 }
//             };
//         }

//         request_response::Message::Response { request_id, response } => {
//             debug!("Received DKG Response from {peer}: {request_id}");
//             match response {
//                 // collect round 1 packets
//                 DKGResponse::Round1 { task_id, packets, nonce: _ } => {
//                     received_round1_packages(task_id, packets, signer.identifier(), &signer.identity_key);
//                 }
//                 // collect round 2 packets
//                 DKGResponse::Round2 { task_id, packets, nonce: _ } => {
//                     received_round2_packages(task_id, packets, signer);
//                 }
//             }

//         }
//     }
// }

#[derive(Debug, Clone)]
pub struct DKGError(String);

impl fmt::Display for DKGError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Use `self.number` to refer to each positional data point.
        write!(f, "dkg error: {}", self.0 )
    }
}


pub fn save_task(task: &DKGTask) {
    let se =  &serde_json::to_string(task).unwrap();
    DB_TASK.insert(task.id.as_str(), se.as_bytes()).expect("Failed to save task to database");
 }
 
 pub fn get_task(task_id: &str) -> Option<DKGTask> {
     match DB_TASK.get(task_id) {
         Ok(Some(task)) => {
             Some(serde_json::from_slice(&task).unwrap())
         },
         _ => {
             None
         }
     }
 }

 pub fn remove_task(task_id: &str) {
    match DB_TASK.remove(task_id) {
        Ok(_) => {
            info!("Removed task from database: {}", task_id);
        },
        _ => {
            error!("Failed to remove task from database: {}", task_id);
        }
    };

}
 
 pub fn list_tasks() -> Vec<DKGTask> {
     let mut tasks = vec![];
     debug!("loading in-process dkg tasks from database, total: {:?}", DB_TASK.len());
     for task in DB_TASK.iter() {
         let (_, task) = task.unwrap();
         tasks.push(serde_json::from_slice(&task).unwrap());
     }
     tasks
 }
 
 pub fn delete_tasks() {
     DB_TASK.clear().unwrap();
     DB_TASK.flush().unwrap();
     DB.clear().unwrap();
     DB.flush().unwrap();
 }
