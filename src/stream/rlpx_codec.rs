use bytes::{Buf, BytesMut};
use log::{error, info};
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    error::{Error, Result},
    messages::{Disconnect, Hello, P2PMessage, P2PMessageID},
    stream::Handshake,
};

enum State {
    Auth,
    AuthAck,
    Frame,
}

// RlpxCodec is a struct that handles encoding and decoding of RLPx messages.
pub struct RlpxCodec {
    handshake: Handshake,
    state: State,
}

impl RlpxCodec {
    pub fn new(handshake: Handshake) -> Self {
        Self {
            handshake,
            state: State::Auth,
        }
    }

    fn decode_frame(frame: Vec<u8>) -> Result<P2PMessage> {
        let message_id = rlp::decode::<P2PMessageID>(&[frame[0]]).expect("Unsupported Message ID");
        match message_id {
            P2PMessageID::Hello => {
                let hello = rlp::decode::<Hello>(&frame[1..])?;
                info!("Peer Specs: {:?}", hello);
                Ok(P2PMessage::Hello)
            }
            P2PMessageID::Disconnect => {
                let disc = rlp::decode::<Disconnect>(&frame[1..])?;
                info!("Disconnect message from peer:\n{:?}", disc);
                Ok(P2PMessage::Disconnect(disc.reason))
            }
        }
    }
}

impl Encoder<P2PMessage> for RlpxCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: P2PMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            P2PMessage::Auth => {
                self.state = State::AuthAck;
                let auth = self.handshake.auth();
                dst.extend_from_slice(&auth);
            }
            P2PMessage::AuthAck => {
                // We are not sending AuthAck messages
            }
            P2PMessage::Hello => {
                let hello = self.handshake.hello_msg();
                dst.extend_from_slice(&hello);
            }
            P2PMessage::Disconnect(reason) => {
                let disc = self.handshake.disconnect_msg(reason);
                dst.extend_from_slice(&disc);
            }
        }

        Ok(())
    }
}

impl Decoder for RlpxCodec {
    type Item = P2PMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            State::Auth => {
                self.state = State::AuthAck;
                Ok(None)
            }
            State::AuthAck => {
                if src.len() < 2 {
                    return Ok(None);
                }

                let payload = u16::from_be_bytes([src[0], src[1]]) as usize;
                let total_size = payload + 2;

                if src.len() < total_size {
                    return Ok(None);
                }

                let mut buf = src.split_to(total_size);
                let auth_ack = self.handshake.decrypt(&mut buf)?;
                self.handshake.authenticate_stream(auth_ack)?;

                self.state = State::Frame;
                Ok(Some(P2PMessage::AuthAck))
            }
            State::Frame => {
                if src.is_empty() {
                    return Ok(None);
                }

                match self.handshake.p2p_stream.read_frame(&mut src[..]) {
                    Ok((frame, size_used)) => {
                        src.advance(size_used);
                        Self::decode_frame(frame).map(Some)
                    }
                    Err(e) => {
                        error!("Failed to read frame: {:?}", e);
                        Ok(None)
                    }
                }
            }
        }
    }
}
