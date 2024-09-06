

use prost_types::Any;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use tracing::{error, info};
use crate::{app::{config::Config, relayer, signer}, helper::client_side::send_cosmos_transaction};


pub async fn execute(home: &str, relayer: bool, signer: bool) {
    
    let conf = Config::from_file(home).unwrap();

    let filter = EnvFilter::new("info").add_directive(format!("shuttler={}", conf.log_level).parse().unwrap());
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter) // Enable log filtering through environment variable
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let (sender, receiver) = std::sync::mpsc::sync_channel::<Any>(10);
    
    if relayer && !signer {
        let conf2 = conf.clone();
        tokio::spawn(async move { signer::run_signer_daemon(conf2, sender).await });
    } else if signer && !relayer {
        let conf2 = conf.clone();
        tokio::spawn(async move { relayer::run_relayer_daemon(conf2, sender).await });
    } else {
        let conf2 = conf.clone();
        let conf3 = conf.clone();
        let sender2 = sender.clone();
        tokio::spawn(async move { signer::run_signer_daemon(conf3, sender).await });
        tokio::spawn(async move { relayer::run_relayer_daemon(conf2, sender2).await });
    }

    loop {
        match receiver.recv() {
            Ok(msg) => {
                match send_cosmos_transaction(&conf, msg).await {
                    Ok(resp) => {
                        let tx_response = resp.into_inner().tx_response.unwrap();
                        if tx_response.code != 0 {
                            panic!("Failed to submit transaction to Side chain: {:?}", tx_response);
                            // return
                        }
                        info!("Sent transaction to Side chain: {:?}", tx_response);
                    },
                    Err(e) => {
                        panic!("Failed to send transaction to side chain: {:?}", e);
                        // return
                    },
                };
            }
            Err(e) => panic!("Failed to receive message from channel: {}", e),
        }
    }

}