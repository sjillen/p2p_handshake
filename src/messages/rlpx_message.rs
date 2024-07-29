use ethereum_types::{H128, H256};
use secp256k1::PublicKey;

use crate::{error::Error, utils::hmac_sha256};

pub struct RlpxMessage<'a> {
    /// The auth data, used when checking the `tag` with HMAC-SHA256.
    pub auth_data: [u8; 2],
    /// The remote secp256k1 public key
    pub public_key: PublicKey,
    /// The IV, for use in AES during decryption, in the tag check
    pub iv: H128,
    /// The encrypted data
    pub encrypted_data: &'a mut [u8],
    /// The message tag
    pub tag: H256,
}

impl<'a> RlpxMessage<'a> {
    pub fn parse(data: &mut [u8]) -> Result<RlpxMessage<'_>, Error> {
        if data.len() < 2 {
            return Err(Error::InvalidInput("Input data too short".to_string()));
        }

        let payload_size = u16::from_be_bytes([data[0], data[1]]);
        if data.len() < payload_size as usize + 2 {
            return Err(Error::InvalidInput("Input data too short".to_string()));
        }

        let (_size, rest) = data.split_at_mut(2);

        if rest.len() < 65 {
            return Err(Error::InvalidInput("Input data too short".to_string()));
        }

        let (pub_data, rest) =
            rest.split_at_mut(secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE);
        let remote_ephemeral_pub_key =
            PublicKey::from_slice(pub_data).map_err(|e| Error::Secp256k1(e.to_string()))?;

        let (iv, rest) = rest.split_at_mut(16);
        let (encrypted_data, tag) = rest.split_at_mut(
            payload_size as usize - (secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 + 32),
        );
        let tag = H256::from_slice(&tag[..32]);

        let iv = H128::from_slice(iv);

        Ok(RlpxMessage {
            auth_data: payload_size.to_be_bytes(),
            public_key: remote_ephemeral_pub_key,
            iv,
            encrypted_data,
            tag,
        })
    }

    pub fn check_tag_for_integrity(&self, mac_key: H256) -> Result<(), Error> {
        let remote_tag = hmac_sha256(
            mac_key.as_ref(),
            &[self.iv.as_bytes(), self.encrypted_data],
            &self.auth_data,
        );

        if self.tag != remote_tag {
            return Err(Error::InvalidTag(remote_tag));
        }

        Ok(())
    }
}
