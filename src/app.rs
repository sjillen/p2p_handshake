use crate::{
    error::{Error, Result},
    messages::P2PMessage,
    rlpx_auth::Ecies,
    stream::{Handshake, P2PStream, RlpxCodec},
    utils::parse_enode,
};
use futures::{SinkExt, StreamExt};
use log::{error, info, warn};
use secp256k1::{PublicKey, SecretKey};
use std::env;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

pub async fn handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let ecies = Ecies::new(private_key, node_public_key);
    let handshake = Handshake::new(ecies, P2PStream::new_unauthed());
    let mut framed = Framed::new(stream, RlpxCodec::new(handshake));

    framed.send(P2PMessage::Auth).await?;

    while let Some(message) = framed.next().await {
        match message {
            Ok(frame) => match frame {
                P2PMessage::Hello => {
                    // received Hello message, p2p handshake is complete
                    break;
                }
                P2PMessage::Disconnect(reason) => {
                    info!("Disconnect message received from peer: {:?}", reason);
                    break;
                }
                _ => {
                    // other possible messages before handshake are auth and ack
                    // we just keep going until we get a Hello or Disconnect
                }
            },
            Err(e) => {
                error!("Error receiving message: {e}");
                break;
            }
        }
    }

    info!("Disconnected from peer");

    Ok(())
}

pub fn get_node_info() -> Result<(PublicKey, String)> {
    let enode = find_enode()?;
    parse_enode(enode)
}

fn find_enode() -> Result<String, Error> {
    let mut args = env::args();
    let _inner = args.next();

    let enode = args.next();
    if !enode.is_none() {
        return Ok(enode.unwrap());
    }
    warn!("No ENODE argument found, trying to read from environment...");
    dotenvy::var("ENODE")
        .map_err(|_| Error::InvalidInput("No ENODE found in environment".to_string()))
}
