use crate::{
    error::Result,
    messages::{Disconnect, Hello, Reason},
    rlpx_auth::Ecies,
    stream::P2PStream,
};

use bytes::{Bytes, BytesMut};
use rlp::{Rlp, RlpStream};
use secp256k1::SECP256K1;

const PROTOCOL_VERSION: usize = 5;

pub struct Handshake {
    pub ecies: Ecies,
    pub p2p_stream: P2PStream,
}

impl Handshake {
    pub fn new(ecies: Ecies, p2p_stream: P2PStream) -> Self {
        Handshake { ecies, p2p_stream }
    }

    pub fn auth(&mut self) -> BytesMut {
        let signature = self.signature();

        let full_pub_key = self.ecies.public_key.serialize_uncompressed();
        let public_key = &full_pub_key[1..];

        let mut stream = RlpStream::new_list(4);
        stream.append(&&signature[..]);
        stream.append(&public_key);
        stream.append(&self.ecies.nonce.as_bytes());
        stream.append(&PROTOCOL_VERSION);

        let auth_body = stream.out();

        let mut buf = BytesMut::default();
        self.encrypt(auth_body, &mut buf)
            .expect("Failed to encrypt auth message");

        self.ecies.init_msg = Some(Bytes::copy_from_slice(&buf[..]));

        buf
    }

    fn signature(&self) -> [u8; 65] {
        let msg = self.ecies.shared_key ^ self.ecies.nonce;

        let (rec_id, sig) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(msg.as_bytes()).unwrap(),
                &self.ecies.ephemeral_private_key,
            )
            .serialize_compact();

        let mut signature: [u8; 65] = [0; 65];
        signature[..64].copy_from_slice(&sig);
        signature[64] = rec_id.to_i32() as u8;

        signature
    }

    pub fn encrypt(&self, data_in: BytesMut, data_out: &mut BytesMut) -> Result<usize> {
        self.ecies.encrypt(data_in, data_out)
    }

    pub fn decrypt<'a>(&mut self, data_in: &'a mut [u8]) -> Result<&'a mut [u8]> {
        self.ecies.decrypt(data_in)
    }

    pub fn authenticate_stream(&mut self, ack_body: &[u8]) -> Result<()> {
        let rlp = Rlp::new(ack_body);
        self.p2p_stream.authenticate(rlp, &self.ecies)
    }

    pub fn hello_msg(&mut self) -> BytesMut {
        let msg = Hello {
            protocol_version: PROTOCOL_VERSION,
            client_version: "hello".to_string(),
            capabilities: vec![],
            port: 0,
            id: self.ecies.public_key,
        };

        let mut encoded_hello = BytesMut::default();
        encoded_hello.extend_from_slice(&rlp::encode(&0_u8));
        encoded_hello.extend_from_slice(&rlp::encode(&msg));

        self.p2p_stream.write_frame(&encoded_hello)
    }

    pub fn disconnect_msg(&mut self, reason: Reason) -> BytesMut {
        let msg = Disconnect { reason };

        let mut encoded_disc = BytesMut::default();
        encoded_disc.extend_from_slice(&rlp::encode(&1_u8));
        encoded_disc.extend_from_slice(&rlp::encode(&msg));

        self.p2p_stream.write_frame(&encoded_disc)
    }
}
