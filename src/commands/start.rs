use bitcoincore_zmq::subscribe_async;
use futures::StreamExt;
use libp2p::gossipsub::Message;

use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, mdns, noise, tcp, yamux};
use tokio::io::AsyncReadExt as _;
use tokio::time::Instant;

use crate::app::{config::Config, signer::Shuttler};
use crate::helper::messages::{ now, SigningBehaviour, SigningBehaviourEvent, SigningSteps, Task};
use crate::helper::ticker::tasks_fetcher;
use std::error::Error;
use std::time::Duration;
use tokio::{io,  select};

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, error};

use super::Cli;

pub async fn execute(cli: &Cli) {

    // Generate a random peer ID
    let kb = Keypair::generate_ed25519();
    let local_peer_id = kb.public().to_peer_id();

    info!("Local peer id: {:?}", local_peer_id);

    let mut swarm: libp2p::Swarm<SigningBehaviour> = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("Network setup failed")
        .with_quic()
        .with_behaviour(|key| {
            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &gossipsub::Message| {
                // let mut s = DefaultHasher::new();
                // message.data.hash(&mut s);
                // gossipsub::MessageId::from(s.finish().to_string())
                // hash_msg(String::from_utf8(message.data)?.to_string())
                gossipsub::MessageId::from(String::from_utf8_lossy(&message.data).to_string())
            };

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
                .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            Ok(SigningBehaviour { gossipsub, mdns })
        })
        .expect("swarm behaviour config failed")
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // start libp2p swarm
    // subscribes to topics
    subscribes(swarm.behaviour_mut());
    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().expect("address parser error")).expect("failed to listen on all interfaces");
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().expect("Address parse error")).expect("failed to listen on all interfaces");

    let conf = Config::from_file(&cli.home).unwrap();
    let mut shuttler = Shuttler::new(conf.clone());

    // start the command server
    // listen for local incoming commands
    let listener = match TcpListener::bind(&conf.mock_server).await {
        Ok(listener) => {
            info!("Listening on: {:?}", listener.local_addr().unwrap());
            listener
        }
        Err(e) => {
            error!("Failed to bind: {:?}", e);
            return;
        }
    };

    let mut stream = subscribe_async(&["tcp://149.28.156.79:38332"]).unwrap();

    
    // this is to ensure that each node fetches tasks at the same time    
    let d = 6 as u64;
    let start = Instant::now() + (Duration::from_secs(d) - Duration::from_secs(now() % d));
    let mut interval = tokio::time::interval_at(start, Duration::from_secs(d));

    loop {
        select! {
            swarm_event = swarm.select_next_some() => match swarm_event {
                SwarmEvent::Behaviour(evt) => {
                    event_handler(evt, swarm.behaviour_mut(), &mut shuttler).await;
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Local node is listening on {address}");
                },
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    info!("Connected to {peer_id}");
                },
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    info!("Connection {peer_id} closed.{:?}", cause);
                },
                _ => {
                    // debug!("Swarm event: {:?}", swarm_event);
                },
            },

            zmq_msg = stream.next() => match zmq_msg {
                Some(block) => {
                    info!("block: {:?}", block)
                },
                None => {}
            },

            _ = interval.tick() => {
                tasks_fetcher(cli, swarm.behaviour_mut(), &mut shuttler).await;
            },

            socket = listener.accept() => match socket {
                Ok((mut tcpstream, _)) => {
                    debug!("Accepted connection from: {:?}", tcpstream.peer_addr().unwrap());
                    command_handler(&mut tcpstream, swarm.behaviour_mut(), &mut shuttler).await;
                }
                Err(e) => {
                    error!("Failed to accept connection: {:?}", e);
                }
            }
        }
    }
}



// handle events from the swarm
async fn event_handler(event: SigningBehaviourEvent, behave: &mut SigningBehaviour, shuttler: &mut Shuttler) {
    match event {
        SigningBehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
            for (peer_id, _multiaddr) in list {
                info!("mDNS discovered a new peer: {peer_id}");
                behave.gossipsub.add_explicit_peer(&peer_id); 
            }
        }
        SigningBehaviourEvent::Mdns(mdns::Event::Expired(list)) => {
            for (peer_id, _multiaddr) in list {
                info!("mDNS discover peer has expired: {peer_id}");
                behave.gossipsub.remove_explicit_peer(&peer_id);
            }
        }
        SigningBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source: _peer_id,
            message_id: _id,
            message,
        }) => {
            // debug!("Received: {:?}", String::from_utf8_lossy(&message.data));
            topic_handler(&message, behave, shuttler).await.expect("topic processing failed");
        }
        _ => {}
    }
}

pub async fn command_handler(steam: &mut TcpStream, behave: &mut SigningBehaviour, shuttler: &mut Shuttler) {

    debug!("Accepted connection from: {:?}", steam.peer_addr().unwrap());
    let mut buf = [0; 1024];
    let result = steam.read(&mut buf).await;

    match result {
        Ok(0) => {
            // Connection closed
            error!("Connection closed");
            return;
        }
        Ok(n) => {
            // Print the received message
            let message = String::from_utf8_lossy(&buf[..n]);
            let task = serde_json::from_str::<crate::helper::messages::Task>(&message).unwrap();

            // process the task on local node first
            match task.step {
                SigningSteps::DkgInit => shuttler.dkg_init(behave, &task),
                SigningSteps::SignInit => shuttler.sign_init(behave, &task),
                _ => {}
            }

            // publish the message to gossip to enable other nodes to process
            match behave.gossipsub.publish(task.step.topic(), &buf[..n]) {
                Ok(_) => {
                    info!("Published message to gossip: {:?}", message);
                }
                Err(e) => {
                    error!("Failed to publish message to gossip: {:?}", e);
                }
            } 
        }
        Err(e) => {
            error!("Failed to read from socket: {}", e);
        }
    }
}

fn subscribes(behave: &mut SigningBehaviour) {

    let topics = vec![
        SigningSteps::DkgInit,
        SigningSteps::DkgRound1,
        SigningSteps::DkgRound2,
        SigningSteps::SignInit,
        SigningSteps::SignRound1,
        SigningSteps::SignRound2,
    ];
    
    for topic in topics {
        behave.gossipsub.subscribe(&topic.topic()).expect("Failed to subscribe to topic");
    }
}

async fn topic_handler(message: &Message, behave: &mut SigningBehaviour, shuttler: &mut Shuttler) -> Result<(), Box<dyn Error>> {
    let topic = message.topic.clone();
    if topic == SigningSteps::SignInit.topic().into() {
        let json = String::from_utf8_lossy(&message.data);
        let task: Task = serde_json::from_str(&json).expect("msg not deserialized");
        shuttler.sign_init(behave, &task);
    } else if topic == SigningSteps::SignRound1.topic().into() {
        shuttler.sign_round1(message);
    } else if topic == SigningSteps::SignRound2.topic().into() {
        shuttler.sign_round2(message).await;
    } else if topic == SigningSteps::DkgInit.topic().into() {
        let json = String::from_utf8_lossy(&message.data);
        let task: Task = serde_json::from_str(&json).expect("msg not deserialized");
        shuttler.dkg_init(behave, &task);
    } else if topic == SigningSteps::DkgRound1.topic().into() {
        shuttler.dkg_round1(behave, message);
    } else if topic == SigningSteps::DkgRound2.topic().into() {
        shuttler.dkg_round2(message);
    }
    Ok(())
}
