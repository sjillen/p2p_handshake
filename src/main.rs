use futures::{SinkExt, StreamExt};
use log::{error, info, warn};
use p2p_handshake::{
    error::{Error, Result},
    handshake::Handshake,
    messages::P2PMessage,
    rlpx_auth::Ecies,
    rlpx_codec::RlpxCodec,
};
use secp256k1::{PublicKey, SecretKey};
use std::env;
use std::process;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<(), Error> {
    dotenvy::dotenv().ok();
    env_logger::init();
    let enode = find_enode()?;

    let (node_public_key, node_address) = parse_enode(enode)?;
    let mut stream = TcpStream::connect(&node_address).await?;
    perform_handshake(&mut stream, node_public_key).await?;

    Ok(())
}

async fn perform_handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let ecies = Ecies::new(private_key, node_public_key);
    let handshake = Handshake::new(ecies);
    let mut framed = Framed::new(stream, RlpxCodec::new(handshake));

    framed.send(P2PMessage::Auth).await?;

    while let Some(message) = framed.next().await {
        match message {
            Ok(frame) => match frame {
                P2PMessage::Auth => {
                    info!("Auth message received from peer");
                }
                P2PMessage::AuthAck => {
                    info!("AuthAck message received from peer");
                }
                P2PMessage::Hello => {
                    // framed
                    //     .send(P2PMessage::Disconnect(Reason::DisconnectRequested))
                    //     .await?;
                }
                P2PMessage::Disconnect(reason) => {
                    info!("Disconnect message received from peer: {:?}", reason);
                    process::exit(0);
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

fn parse_enode(enode: String) -> Result<(PublicKey, String)> {
    let enode_parts: Vec<&str> = enode.split('@').collect();
    if enode_parts.len() != 2 {
        return Err(Error::InvalidInput("Invalid enode ID".to_string()));
    }

    let id_decoded = hex::decode(enode_parts[0])
        .map_err(|_| Error::InvalidInput("Invalid node ID".to_string()))?;
    let public_key = public_key_from_slice(&id_decoded)?;

    let addr = enode_parts[1];

    Ok((public_key, addr.to_string()))
}

fn public_key_from_slice(data: &[u8]) -> Result<PublicKey> {
    const PUBLIC_KEY_LENGTH: usize = 64;
    const PUBLIC_KEY_WITH_PREFIX_LENGTH: usize = 65;
    if data.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidInput("Invalid public key length".to_string()));
    }

    let mut s = [4_u8; PUBLIC_KEY_WITH_PREFIX_LENGTH];
    s[1..].copy_from_slice(data);

    PublicKey::from_slice(&s).map_err(|e| Error::InvalidPublicKey(e.to_string()))
}
