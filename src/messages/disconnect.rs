use rlp::{Decodable, Encodable};

#[derive(Debug)]
pub struct Disconnect {
    pub reason: Reason,
}

impl Encodable for Disconnect {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(1);
        s.append(&self.reason);
    }
}

impl Decodable for Disconnect {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            reason: rlp.val_at(0)?,
        })
    }
}

#[derive(Debug)]
pub enum Reason {
    DisconnectRequested,
}

impl Encodable for Reason {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        match self {
            Reason::DisconnectRequested => s.append(&0u8),
        };
    }
}

impl Decodable for Reason {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        match rlp.as_val::<u8>() {
            Ok(0) => Ok(Reason::DisconnectRequested),
            _ => Err(rlp::DecoderError::Custom("Invalid reason value")),
        }
    }
}
