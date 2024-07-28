use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

pub fn derive_sym_keys(public_key: PublicKey, secret_key: SecretKey) -> (H128, H256) {
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
