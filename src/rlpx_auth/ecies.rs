use aes::cipher::{KeyIvInit, StreamCipher};
use bytes::{Bytes, BytesMut};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

use crate::{
    error::{Error, Result},
    messages::RlpxMessage,
    rlpx_auth::Aes128Ctr64BE,
};

#[derive(Debug)]
pub struct Ecies {
    pub ephemeral_private_key: SecretKey,
    pub public_key: PublicKey,
    pub shared_key: H256,
    pub nonce: H256,
    pub init_msg: Option<Bytes>,
    pub remote_init_msg: Option<Bytes>,
    private_key: SecretKey,
    remote_public_key: PublicKey,
}

impl Ecies {
    pub fn new(private_key: SecretKey, remote_public_key: PublicKey) -> Self {
        let ephemeral_private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        let shared_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(&remote_public_key, &private_key)[..32],
        );

        Self {
            private_key,
            ephemeral_private_key,
            public_key,
            remote_public_key,
            shared_key,
            nonce: H256::random(),
            init_msg: None,
            remote_init_msg: None,
        }
    }

    pub fn decrypt<'a>(&mut self, data_in: &'a mut [u8]) -> Result<&'a mut [u8]> {
        let payload_size = u16::from_be_bytes([data_in[0], data_in[1]]);
        self.remote_init_msg = Some(Bytes::copy_from_slice(
            &data_in[..payload_size as usize + 2],
        ));

        let rlpx_message = RlpxMessage::parse(data_in)?;

        let (enc_key, mac_key) = derive_sym_keys(rlpx_message.public_key, self.private_key);
        rlpx_message.check_tag_for_integrity(mac_key)?;

        let encrypted_key = H128::from_slice(enc_key.as_bytes());
        let mut decryptor = Aes128Ctr64BE::new(
            encrypted_key.as_ref().into(),
            rlpx_message.iv.as_ref().into(),
        );
        decryptor.apply_keystream(rlpx_message.encrypted_data);

        Ok(rlpx_message.encrypted_data)
    }

    pub fn encrypt(&self, data_in: BytesMut, data_out: &mut BytesMut) -> Result<usize> {
        let ephemeral_secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let iv = H128::random();
        let (enc_key, mac_key) = derive_sym_keys(self.remote_public_key, ephemeral_secret_key);

        let total_size = u16::try_from(
            secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 + data_in.len() + 32,
        )
        .map_err(|_| Error::InvalidInput("Data size overflow".to_string()))?;

        let encrypted_data = self.encrypt_data(data_in, &iv, &enc_key);
        let tag = hmac_sha256(
            mac_key.as_ref(),
            &[&iv.as_bytes(), &encrypted_data],
            &total_size.to_be_bytes(),
        );

        data_out.extend_from_slice(&total_size.to_be_bytes());
        data_out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, &ephemeral_secret_key).serialize_uncompressed(),
        );
        data_out.extend_from_slice(iv.as_bytes());
        data_out.extend_from_slice(&encrypted_data);
        data_out.extend_from_slice(tag.as_bytes());

        Ok(data_out.len())
    }

    fn encrypt_data(&self, mut data: BytesMut, iv: &H128, encryption_key: &H128) -> BytesMut {
        let mut encryptor = Aes128Ctr64BE::new(encryption_key.as_ref().into(), iv.as_ref().into());
        encryptor.apply_keystream(&mut data);
        data
    }
}

fn derive_sym_keys(public_key: PublicKey, secret_key: SecretKey) -> (H128, H256) {
    // perform ECDH to get the shared secret, using the remote public key from the message and
    // the given secret key
    let shared_key = ecdh(&public_key, &secret_key);

    let mut key = [0_u8; 32];
    kdf(shared_key, &[], &mut key);

    let enc_key = H128::from_slice(&key[..16]);
    let mac_key = H256::from(Sha256::digest(&key[16..32]).as_ref());

    (enc_key, mac_key)
}

pub fn ecdh(public_key: &PublicKey, private_key: &SecretKey) -> H256 {
    let shared_key_bytes = secp256k1::ecdh::shared_secret_point(public_key, private_key);
    H256::from_slice(&shared_key_bytes[..32])
}

fn kdf(secret: H256, other_info: &[u8], dest: &mut [u8]) {
    concat_kdf::derive_key_into::<Sha256>(secret.as_bytes(), other_info, dest).unwrap();
}

pub fn hmac_sha256(mac_key: &[u8], input: &[&[u8]], auth_data: &[u8]) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_data);
    H256::from_slice(&hmac.finalize().into_bytes())
}