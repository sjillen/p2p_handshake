use futures::{SinkExt, StreamExt};
use log::{error, info};
use p2p_handshake::{
    error::{Error, Result},
    handshake::Handshake,
    messages::{P2PMessage, Reason},
    rlpx_auth::Ecies,
    rlpx_codec::RlpxCodec,
};
use secp256k1::{PublicKey, SecretKey};
use std::env;
use std::process;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() {
    env_logger::init();

    match parse_input() {
        Ok((node_public_key, node_address)) => {
            info!("Target address: {node_address}");
            match TcpStream::connect(&node_address).await {
                Ok(mut stream) => {
                    info!("Connected to target address");
                    if let Err(e) = perform_handshake(&mut stream, node_public_key).await {
                        error!("Handshake error: {e}");
                    }
                }
                Err(e) => error!("Failed to connect to the given Ethereum node: {e}"),
            }
        }
        Err(e) => error!("Error parsing input: {e}"),
    }
}

async fn perform_handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let ecies = Ecies::new(private_key, node_public_key);
    let handshake = Handshake::new(ecies);
    let mut framed = Framed::new(stream, RlpxCodec::new(handshake));

    framed.send(P2PMessage::Auth).await?;
    info!("Auth message sent to peer");

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
                    framed
                        .send(P2PMessage::Disconnect(Reason::DisconnectRequested))
                        .await?;
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

fn parse_input() -> Result<(PublicKey, String)> {
    let mut args = env::args();
    let _inner = args.next();
    let id = args
        .next()
        .ok_or_else(|| Error::InvalidInput("Missing node ID".to_string()))?;
    let id_decoded =
        hex::decode(id).map_err(|_| Error::InvalidInput("Invalid node ID".to_string()))?;
    let public_key = public_key_from_slice(&id_decoded)?;

    let ip_addr = args
        .next()
        .ok_or_else(|| Error::InvalidInput("Missing IP address".to_string()))?;
    let port = args
        .next()
        .ok_or_else(|| Error::InvalidInput("Missing port".to_string()))?;

    let addr = format!("{}:{}", ip_addr, port);
    Ok((public_key, addr))
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