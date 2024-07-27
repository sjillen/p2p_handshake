use rlp::Decodable;

use super::Reason;

/// Message IDs for `p2p` subprotocol messages.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum P2PMessageID {
    /// Message ID for the Hello message.
    Hello = 0x00,
    /// Message ID for the Disconnect message.
    Disconnect = 0x01,
}

impl Decodable for P2PMessageID {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        match rlp.as_val::<u8>() {
            Ok(0x00) => Ok(P2PMessageID::Hello),
            Ok(0x01) => Ok(P2PMessageID::Disconnect),
            _ => Err(rlp::DecoderError::Custom("Invalid reason value")),
        }
    }
}

#[derive(Debug)]
pub enum P2PMessage {
    Auth,
    AuthAck,
    Hello,
    Disconnect(Reason),
}
