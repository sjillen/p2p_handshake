use secp256k1::PublicKey;

use crate::error::{Error, Result};

pub fn parse_enode(enode: String) -> Result<(PublicKey, String)> {
    let enode_parts: Vec<&str> = enode.split('@').collect();
    if enode_parts.len() != 2 {
        return Err(Error::InvalidInput("Invalid enode ID".to_string()));
    }

    let id_decoded = hex::decode(enode_parts[0])
        .map_err(|_| Error::InvalidInput("Invalid node ID".to_string()))?;
    let public_key = public_key_from_slice(&id_decoded)?;

    let addr = enode_parts[1];

    Ok((public_key, addr.to_string()))
}

pub fn public_key_from_slice(data: &[u8]) -> Result<PublicKey> {
    const PUBLIC_KEY_LENGTH: usize = 64;
    const PUBLIC_KEY_WITH_PREFIX_LENGTH: usize = 65;
    if data.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidInput("Invalid public key length".to_string()));
    }

    let mut s = [4_u8; PUBLIC_KEY_WITH_PREFIX_LENGTH];
    s[1..].copy_from_slice(data);

    PublicKey::from_slice(&s).map_err(|e| Error::InvalidPublicKey(e.to_string()))
}
