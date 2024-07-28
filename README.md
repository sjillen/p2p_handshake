#P2P Handshake


## Overview
This project is an implementation of of a Peer to Peer handshake with an ethereum node.
Ethereum node use the RLPx protocol as documented here: https://github.com/ethereum/devp2p/blob/master/rlpx.md.
This project can perform the handshake with any Ethereum node client (Geth, Reth, Ethermind,...).

## How to install

This project is written in Rust(^1.79) and uses cargo to manages dependencies.
Check [here](https://www.rust-lang.org/tools/install) for instructions how on to install rust and cargo.

## How to run:

### Running the peer
In order to run the app, you will need an ethereum enode address.
One option is to run a go-ethereum (Geth) node locally.
You can install geth from here: https://geth.ethereum.org/docs/getting-started/installing-geth
Once it's done, you run the node with the following command:
```bash
geth --no-discover 
```
*Note: we use the `--no-discover` flag to avoid the noise in the logs*
Then you will see the node's enode address in the logs as it boots up.

It will look like this:
`<node-id>@<host>:<port>`


You can also find the enode by opening the geth console in another instance of your CLI:
```bash
geth attach
```
then, in the geth console, run:
```
admin.nodeInfo
```
Another option is to use any publicly available ethereum node online with its TCP ports open (eg. https://ethernodes.org/nodes)

Once you get the enode, copy and paste the value in the `.env file'
```
ENODE = <your-enode-value>
```
*Note: if your node is running locally, replace the ip by `127.0.0.1`*

### Running the app

Once you have the enode of a running Ethereum node, you can start the app:
```bash
cargo run <your-enode>

# or without argument to fallback to the ENODE value from the .env
cargo run
```

