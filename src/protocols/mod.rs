
use libp2p::{floodsub, kad::store::MemoryStore, mdns, swarm::NetworkBehaviour};
use serde::{Deserialize, Serialize};

pub mod dkg;
pub mod sign;

#[derive(NetworkBehaviour)]
pub struct TSSBehaviour {
    pub kad: libp2p::kad::Behaviour<MemoryStore>,
    pub identify: libp2p::identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub gossip: floodsub::Floodsub,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Round {
    Round1,
    Round2,
    Aggregate,
    Closed,
}

