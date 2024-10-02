
use std::{sync::{Arc, Mutex}, time::Duration};

use cosmos_sdk_proto::side::btcbridge::{query_client::QueryClient as BtcQueryClient, DkgRequestStatus, MsgCompleteDkg, QueryDkgRequestsRequest};
use cosmrs::Any;
use libp2p:: Swarm;
use tracing::{debug, error, info};
use tokio::time::sleep;

use crate::{app::signer::Signer, helper::client_side::{get_signing_requests, send_cosmos_transaction}, protocols::{dkg::{self, collect_dkg_packages, generate_round1_package, list_tasks, save_task, DKGTask}, sign::{self, collect_tss_packages, generate_nonce_and_commitments, list_sign_tasks}, Round, TSSBehaviour}};

async fn fetch_signing_requests(
    _behave: &mut TSSBehaviour,
    shuttler: &Signer,
) {
    let host = shuttler.config().side_chain.grpc.as_str();

    match get_signing_requests(&host).await {
        Ok(response) => {
            let requests = response.into_inner().requests;
            let tasks_in_process = requests.iter().map(|r| r.txid.clone() ).collect::<Vec<_>>();
            debug!("Fetched signing requests: {:?}", tasks_in_process);
            list_sign_tasks().iter().for_each(|task| {
                if !tasks_in_process.contains(&task.id) {
                    debug!("Removing expired signing task: {:?}", task.id);
                    sign::remove_task(&task.id);
                }
            });
            // mock for testing
            // if requests.len() == 0 {
                // requests.push(SigningRequest {
                //     address: "tb1pr8auk03a54w547e3q7w4xqu0wj57skgp3l8sfeus0skhdhltrq5qxtur6k".to_string(),
                //     psbt: "cHNidP8BAI8CAAAAA+67aDQ4JUktcSgEunL5O7FG5T2plGO95wYDt2aIajrAAQAAAAD/////7rtoNDglSS1xKAS6cvk7sUblPamUY73nBgO3ZohqOsABAAAAAP/////uu2g0OCVJLXEoBLpy+TuxRuU9qZRjvecGA7dmiGo6wAEAAAAA/////wEAAAAAAAAAAAFqAAAAAAABASsQJwAAAAAAACJRIBn7yz49pV1K+zEHnVMDj3Sp6FkBj88E55B8LXbf6xgoAAEBKxAnAAAAAAAAIlEgGfvLPj2lXUr7MQedUwOPdKnoWQGPzwTnkHwtdt/rGCgAAQErECcAAAAAAAAiUSAZ+8s+PaVdSvsxB51TA490qehZAY/PBOeQfC123+sYKAAA".to_string(),
                //     status: 1,
                //     sequence: 0,
                //     txid: "123455".to_string(),
                // });
            // }
            for request in requests {
                generate_nonce_and_commitments(request, shuttler);
            }
        }
        Err(e) => {
            error!("Failed to fetch signing requests: {:?}", e);
            return;
        }
    };
}

async fn fetch_dkg_requests(shuttler: &Signer) {
    let host = shuttler.config().side_chain.grpc.clone();
    let mut client = match BtcQueryClient::connect(host.to_owned()).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create btcbridge query client: {host} {}", e);
            return;
        }
    };
    if let Ok(requests_response) = client
        .query_dkg_requests(QueryDkgRequestsRequest {
            status: DkgRequestStatus::Pending as i32,
        })
        .await
    {

        let requests = requests_response.into_inner().requests;
        let tasks_in_process = requests.iter().map(|r| format!("dkg-{}", r.id)).collect::<Vec<_>>();
        debug!("Fetched DKG requests: {:?}", tasks_in_process);
        list_tasks().iter().for_each(|task| {
            if !tasks_in_process.contains(&task.id) {
                debug!("Removing expired task: {:?}", task.id);
                dkg::remove_task(&task.id);
            }
        });
        for request in requests {
            if request
                .participants
                .iter()
                .find(|p| p.consensus_address == shuttler.validator_address())
                .is_some()
            {
                // create a dkg task
                let task = DKGTask::from_request(&request);
                if dkg::has_task_preceeded(task.id.as_str()) {
                    continue;
                };
                generate_round1_package(shuttler.identifier().clone(), &task);
                debug!("generated round1 packages: {:?} {:?}", &task.id, request);
                dkg::save_task(&task);
            }
        }
    };
}


pub async fn start_tss_tasks(
    // peers: Vec<&PeerId>,
    // behave: &mut TSSBehaviour,
    shared_swarm: Arc<tokio::sync::Mutex<Swarm<TSSBehaviour>>>, 
    shuttler: &Signer,
) {
    loop {
        let mut swarm = shared_swarm.lock().await;

        if shuttler.config().get_validator_key().is_none() {
            continue;
        }

        if swarm.connected_peers().count() == 0 {
            continue;
        }

        debug!("Connected peers: {:?}", swarm.connected_peers().collect::<Vec<_>>());

        // ===========================
        // all participants tasks:
        // ===========================

        // 1. fetch dkg requests
        fetch_dkg_requests(shuttler).await;
        // 2. collect dkg packages
        collect_dkg_packages(&mut swarm);
        // 3. fetch signing requests
        fetch_signing_requests(swarm.behaviour_mut(), shuttler).await;
        // 4. collect signing requests tss packages
        collect_tss_packages(&mut swarm, shuttler).await;
        // 5. submit dkg address
        submit_dkg_address(shuttler).await;

        sleep(Duration::from_secs(6)).await;
    }
}

async fn submit_dkg_address(signer: &Signer) {
    for task in list_tasks().iter_mut() {
        if task.round != Round::Closed {
            continue;
        }
        let task_id = task.id.replace("dkg-", "").parse().unwrap();
        // submit the vault address to sidechain
        let cosm_msg = MsgCompleteDkg {
            id: task_id,
            sender: signer.config().relayer_bitcoin_address(),
            vaults: task.dkg_vaults.clone(),
            consensus_address: signer.validator_address(),
            signature: signer.get_complete_dkg_signature(task_id, &task.dkg_vaults),
        };

        let any = Any::from_msg(&cosm_msg).unwrap();
        match send_cosmos_transaction(signer.config(), any).await {
            Ok(resp) => {
                let tx_response = resp.into_inner().tx_response.unwrap();
                if tx_response.code != 0 {
                    error!("Failed to send dkg vault: {:?}", tx_response);
                    task.submitted = true;
                    save_task(task);
                    continue
                }
                info!("Sent dkg vault: {:?}", tx_response);
            },
            Err(e) => {
                error!("Failed to send dkg vault: {:?}", e);
            },
        };
    };
    
}
