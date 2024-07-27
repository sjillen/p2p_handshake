use aes::cipher::KeyIvInit;
use ethereum_types::{H128, H256};
use secp256k1::PublicKey;
use sha2::Digest;
use sha3::Keccak256;

use crate::rlpx_auth::{ecdh, mac::Mac, Aes256Ctr64BE, Ecies};

pub struct Secrets {
    pub aes_secret: H256,
    pub mac_secret: H256,
    pub shared_secret: H256,
    pub ingress_mac: Mac,
    pub egress_mac: Mac,
    pub ingress_aes: Aes256Ctr64BE,
    pub egress_aes: Aes256Ctr64BE,
}

impl Secrets {
    pub fn compute(
        recipient_nonce: H256,
        recipient_ephemeral_public_key: PublicKey,
        ecies: &Ecies,
    ) -> Self {
        let (aes_secret, mac_secret, shared_secret) =
            hash_rlpx_secrets(recipient_nonce, recipient_ephemeral_public_key, ecies);

        // egress-mac
        let mut egress_mac = Mac::new(mac_secret);
        egress_mac.update((mac_secret ^ recipient_nonce).as_bytes());
        egress_mac.update(ecies.init_msg.as_ref().unwrap());

        // ingress-mac
        let mut ingress_mac = Mac::new(mac_secret);
        ingress_mac.update((mac_secret ^ ecies.nonce).as_bytes());
        ingress_mac.update(ecies.remote_init_msg.as_ref().unwrap());

        let iv = H128::default();

        Secrets {
            aes_secret,
            mac_secret,
            shared_secret,
            egress_mac,
            ingress_mac,
            ingress_aes: Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into()),
            egress_aes: Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into()),
        }
    }
}

fn hash_rlpx_secrets(
    nonce: H256,
    ephemeral_public_key: PublicKey,
    ecies: &Ecies,
) -> (H256, H256, H256) {
    let ephemeral_key = ecdh(&ephemeral_public_key, &ecies.ephemeral_private_key);

    let keccak_nonce = hash_256(&[nonce.as_ref(), ecies.nonce.as_ref()]);
    let shared_secret = hash_256(&[ephemeral_key.as_ref(), keccak_nonce.as_ref()]);
    let aes_secret = hash_256(&[ephemeral_key.as_ref(), shared_secret.as_ref()]);
    let mac_secret = hash_256(&[ephemeral_key.as_ref(), aes_secret.as_ref()]);

    (aes_secret, mac_secret, shared_secret)
}

fn hash_256(inputs: &[&[u8]]) -> H256 {
    let mut hasher = Keccak256::new();

    for input in inputs {
        hasher.update(input)
    }

    H256::from(hasher.finalize().as_ref())
}
