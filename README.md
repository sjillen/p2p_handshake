# P2P Handshake


## Overview
This project is an implementation of of a Peer to Peer handshake with an ethereum node.
Ethereum nodes use the RLPx protocol as documented here: https://github.com/ethereum/devp2p/blob/master/rlpx.md.
This project can perform the handshake with any Ethereum node client (Geth, Reth, Ethermind,...).

As of now, only the initial RLPx handshake is performed before dropping the connection. The ethereum handshake has not been implemented yet.

## How to install

This project is written in Rust(^1.79) and uses cargo to manage its dependencies.
Check [here](https://www.rust-lang.org/tools/install) for instructions how on to install rust and cargo.

## How to run:

### Running the peer
In order to run the app, you will need an ethereum enode address.
One option is to run a go-ethereum (Geth) node locally.
You can install geth from here: https://geth.ethereum.org/docs/getting-started/installing-geth.
Once it's done, start the node with the following command:
```bash
geth --no-discover 
```
*Note: we use the `--no-discover` flag to avoid the noise in the logs.*

Then you should see the node's enode address in the logs as it boots up.

It should look like this:
`<node-id>@<host>:<port>`.


You can also find the enode by opening the geth console in another instance of your CLI:
```bash
geth attach
```
Once in the geth console, run:
```
admin.nodeInfo
```
Another option is to use any publicly available ethereum node online with its TCP ports open (eg. https://ethernodes.org/nodes).

Once you get the enode, copy and paste the value in the `.env file` (You will need to create it by making a copy of `.env.example`).
```
ENODE = <node-id>@<node-ip>:<node-port>
```
*Note: if your node is running locally, replace the ip by `127.0.0.1`.*

### Running the app

Once you have the enode of a running Ethereum node, you can start the app:
```bash
cargo run <your-enode>

# or without argument to fallback to the ENODE value from the .env
cargo run
```
If successful, you should see the following logs, indicating that the Mac has been validated and the node has sent its specs with the hello message:
```bash
[2024-07-28T14:34:34Z INFO  p2p_handshake::stream::p2p_stream] MAC valid, initial handshake completed.
[2024-07-28T14:34:34Z INFO  p2p_handshake::stream::rlpx_codec] Peer Specs: Hello { protocol_version: 5, client_version: "Geth/v1.14.7-stable/darwin-arm64/go1.22.5", capabilities: [Capability { name: "eth", version: 68 }, Capability { name: "snap", version: 1 }], port: 0, id: PublicKey(197e8a6cf3646296dbeac011a9669484c528684bdc45670523d4157507f39cd38922a319a612dc032c536eeba70cd9920cfe5518c38e54045a09a5b5d6b0d95a) }
[2024-07-28T14:34:34Z INFO  p2p_handshake::app] Disconnected from peer
```