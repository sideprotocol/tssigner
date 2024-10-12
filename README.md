# Shuttler

Shuttler is a TSS network client

The *`TSS`*(**Threshold Signature Scheme**) network is a key building block intended to perform Bitcoin signing in the distributed manner to facilitate the Bitcoin bridge on the [Side Chain](https://github.com/sideprotocol/side)

The TSS signature network consists of twenty-one nodes which are a subset of the Side validators of well-known reputation.

TSS nodes are mainly responsible for several tasks: *`DKG`*(**Distributed Key Generation**), `Signing` and `Relaying`.

## DKG

The DKG procedure is as follows:

1. Initiate: The DKG initiation is proposed as a governance proposal on the Side chain. The proposal contains the DKG participant set and required  threshold for later signing.

2. Vote: Community members and validators can vote for the proposal.

3. Create: The DKG request is formally created on the Side chain when the proposal passed.

4. Complete: TSS nodes will coordinate to complete the DKG request. All participants listed in the proposal must be connected to the TSS network in the phase.

5. Re-DKG: This happen when some nodes want to quit the TSS network according to their operation demands. New signing keys will be generated by the steps above and all assets held by the previous keys will be transferred to the newly generated ones.

## Signing

Signing is the regular task for TSS nodes.

1. Signing requests are fetched from the Side chain by the TSS node periodically.

2. Sign the requests and broadcast the related messages when signing requests are received.

## Relaying

As the security guard, TSS nodes can contribute to the security of the bitcoin bridge by relaying the bitcoin block headers.

At the same time, the bridge related transactions including deposit and withdrawal can be relayed to the Side chain by TSS nodes as well.

## Get started

### Build from source

1. Install *Rust*

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. Clone and build

```
git clone https://github.com/sideprotocol/shuttler.git
cd shuttler
cargo build --release
```

The binary can be placed into the bin directory of Cargo for convenience.

```
cp target/release/shuttler ~/.cargo/bin
```

### Configure

1. Initialize

```
shuttler --home ~/.shuttler init --network testnet
```

The *home* directory can be replaced by your choice.

You can specify the port by `--port`. The default port is `5158`.

2. Set the bootstrapping nodes

```
bootstrap_nodes = ["<peer address>",...,"<peer address>"]
```

The bootstrapping nodes are used to help connect to the TSS network when started.

The format of the peer address is like this:

```
/ip4/<IP>/tcp/<PORT>/p2p/<PEER ID>
```

The `local peer id` can be retrieved as the following command:

```
shuttler --home <home> id
```

You can share your node address if possible. And the public nodes published by the TSS network members can be used as well.

3. Set the validator key

```
priv_validator_key_path = "<validator key path>"
```

The validator key is required to participate the DKG.
The item should be set to the correct location which is commonly the *.side/config/priv_validator_key.json* in the home directory.

4. Set the Side gRPC

```
[side_chain]
grpc = "<gprc address>"
```

If you run own Side node on the same server, the item can be set to `http://localhost:9090`. The value can be configured by the actual deployment or set to the public Side node which provides the gRPC server.

5. Set the Bitcoin RPC

```
[bitcoin]
network = "<network name>"
rpc = "<rpc endpoint>"
user = "<rpc username>"
password = "<rpc password>"
```

For signers and relayers, the bitcoin node rpc is required to send the signed transactions or sync the bitcoin block headers and the bridge related transactions to the Side chain.

In the Side testnet phase 3, the corresponding bitcoin network is `testnet3`. For testnet3, the network name is `testnet` and defaut port is `18332`.

The TSS node operator can deploy own bitcoin node or use the third-party server provider by demand.

The public bitcoin node information provided by Side Labs is as follows:

```
network = "testnet"
rpc = "http://192.248.150.102:18332"
user = "side"
password = "12345678"
```

**_Note_**: The `--txindex` is required to be set when starting the Bitcoin node as following:

```
bitcoind -txindex -rpcuser=<user> --rpcpassword=<password>
```

### Fund the relayer address

The relayer(Side transaction sender) address can be viewed by the following command:

```
shuttler --home <home> address
```

**Note**: Before starting the TSS node, the sender address needs to be funded for sending the transactions to the Side chain.

### Start

The TSS node can be started by the different modes or roles: *`signer`* and *`relayer`*.

1. Start as signer

```
shuttler --home <home> start --signer
```

2. Start as relayer

```
shuttler --home <home> start --relayer
```

3. Start as both signer and relayer

```
shuttler --home <home> start --signer --relayer
```

or start by default

```
shuttler --home <home> start
```

### Hardware Specifications

#### Running only the TSS node

1. Minimum Requirements

   - CPU: 4 cores

   - RAM: 8 GB

   - Storage: 100 GB

   - Network: 1 Gbps

2. Recommended Specifications

   - CPU: 8 cores

   - RAM: 16 GB

   - Storage: 500 GB

   - Network: 1 Gbps

#### Running only the Bitcoin Testnet3 full node

1. Minimum Requirements

   - CPU: 4 cores

   - RAM: 8 GB

   - Storage: 200 GB

   - Network: 1 Gbps

2. Recommended Specifications

   - CPU: 8 cores

   - RAM: 16 GB

   - Storage: 500 GB

   - Network: 1 Gbps

#### Running both the TSS node and Bitcoin Testnet3 full node

1. Minimum Requirements

   - CPU: 4 cores

   - RAM: 8 GB

   - Storage: 200 GB

   - Network: 1 Gbps

2. Recommended Specifications

   - CPU: 8 cores

   - RAM: 16 GB

   - Storage: 500 GB

   - Network: 1 Gbps

**Note**: To ensure service quality, we strongly recommend not running the Side Chain validator node on any of the machines listed above.
