use crate::{
    error::{Error, Result},
    messages::{Disconnect, Hello, Reason},
    rlpx_auth::{Ecies, Secrets},
};

use aes::cipher::StreamCipher;
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use ethereum_types::{H128, H256};
use rlp::{Rlp, RlpStream};
use secp256k1::{PublicKey, SECP256K1};

const PROTOCOL_VERSION: usize = 5;
const ZERO_HEADER: &[u8; 3] = &[194, 128, 128]; // Hex{0xC2, 0x80, 0x80} -> u8 &[194, 128, 128]

pub struct Handshake {
    pub ecies: Ecies,
    pub secrets: Option<Secrets>,
}

impl Handshake {
    pub fn new(ecies: Ecies) -> Self {
        Handshake {
            ecies,
            secrets: None,
        }
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

    pub fn derive_secrets(&mut self, ack_body: &[u8]) -> Result<()> {
        let rlp = Rlp::new(ack_body);

        let recipient_ephemeral_public_key_raw: Vec<_> = rlp.val_at(0)?;

        let mut buf = [4_u8; 65];
        buf[1..].copy_from_slice(&recipient_ephemeral_public_key_raw);
        let recipient_ephemeral_public_key =
            PublicKey::from_slice(&buf).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;

        // recipient nonce
        let recipient_nonce_raw: Vec<_> = rlp.val_at(1)?;
        let recipient_nonce = H256::from_slice(&recipient_nonce_raw);

        self.secrets = Some(Secrets::compute(
            recipient_nonce,
            recipient_ephemeral_public_key,
            &self.ecies,
        ));

        Ok(())
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

        self.write_frame(&encoded_hello)
    }

    pub fn disconnect_msg(&mut self, reason: Reason) -> BytesMut {
        let msg = Disconnect { reason };

        let mut encoded_disc = BytesMut::default();
        encoded_disc.extend_from_slice(&rlp::encode(&1_u8));
        encoded_disc.extend_from_slice(&rlp::encode(&msg));

        self.write_frame(&encoded_disc)
    }

    fn write_frame(&mut self, data: &[u8]) -> BytesMut {
        let mut buf = [0; 8];
        let n_bytes = 3; // 3 * 8 = 24;
        BigEndian::write_uint(&mut buf, data.len() as u64, n_bytes);

        let mut header_buf = [0_u8; 16];
        header_buf[..3].copy_from_slice(&buf[..3]);
        header_buf[3..6].copy_from_slice(ZERO_HEADER);

        let secrets = self.secrets.as_mut().unwrap();
        secrets.egress_aes.apply_keystream(&mut header_buf);
        secrets.egress_mac.compute_header(&header_buf);

        let mac = secrets.egress_mac.digest();

        let mut out = BytesMut::default();
        out.reserve(32);
        out.extend_from_slice(&header_buf);
        out.extend_from_slice(mac.as_bytes());

        let mut len = data.len();
        // round to nearest multiple of 16
        if len % 16 > 0 {
            len = (len / 16 + 1) * 16;
        }

        let old_len = out.len();
        out.resize(old_len + len, 0);

        let encrypted = &mut out[old_len..old_len + len];
        encrypted[..data.len()].copy_from_slice(data);

        secrets.egress_aes.apply_keystream(encrypted);
        secrets.egress_mac.compute_frame(encrypted);
        let mac = secrets.egress_mac.digest();

        out.extend_from_slice(mac.as_bytes());

        out
    }

    pub fn read_frame(&mut self, buf: &mut [u8]) -> Result<(Vec<u8>, usize), Error> {
        if buf.len() < 32 {
            return Err(Error::InvalidInput("Too short".to_string()));
        }

        let (header_bytes, frame) = buf.split_at_mut(32);
        let (header, mac) = header_bytes.split_at_mut(16);
        let mac = H128::from_slice(mac);

        let secrets = self.secrets.as_mut().unwrap();

        secrets.ingress_mac.compute_header(header);
        if mac != secrets.ingress_mac.digest() {
            return Err(Error::InvalidMac(mac));
        }

        secrets.ingress_aes.apply_keystream(header);

        let mut frame_size = BigEndian::read_uint(header, 3) + 16;
        let padding = frame_size % 16;
        if padding > 0 {
            frame_size += 16 - padding;
        }

        let (frame, _) = frame.split_at_mut(frame_size as usize);
        let (frame_data, frame_mac) = frame.split_at_mut(frame.len() - 16);
        let frame_mac = H128::from_slice(frame_mac);

        secrets.ingress_mac.compute_frame(frame_data);

        if frame_mac != secrets.ingress_mac.digest() {
            return Err(Error::InvalidMac(frame_mac));
        }

        secrets.ingress_aes.apply_keystream(frame_data);

        let total_bytes_used = 32 + frame_size as usize;

        Ok((frame_data.to_owned(), total_bytes_used))
    }
}
