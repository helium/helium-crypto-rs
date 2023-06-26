mod keyblob;
mod rsa_key;

use crate::{public_key, rsa, KeyTag, KeyType, Network, Result, Sign};
use ::rsa::RsaPublicKey;
use std::fmt;

extern crate num_bigint_dig as num_bigint;
use num_bigint::BigUint;

use crate::nova_tz::rsa_key::RsaKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("`{0}` returned error: {1}")]
    TZError(&'static str, u32),

    #[error("bad key path: {0}")]
    BadKeyPath(String),

    #[error("KeyBlob error")]
    KeyBlobError(#[from] keyblob::Error),

    #[error("qseecom error: {0}")]
    QseecomError(String),
}

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    pub path: String,
    key: RsaKey,
}

impl PartialEq for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network && self.public_key == other.public_key
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        f.debug_struct("Keypair")
            .field("path", &self.path)
            .field("public", &self.public_key)
            .finish()
    }
}

impl Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.key.sign(msg)
    }
}

impl Keypair {
    pub fn from_key_path(network: Network, key_path: &str) -> Result<Keypair> {
        let key = RsaKey::new(key_path)?;
        let (modulus, public_exp) = key.public_key()?;
        let public_key = RsaPublicKey::new(
            BigUint::from_bytes_be(modulus.as_slice()),
            BigUint::from_bytes_be(public_exp.as_slice()),
        )?;

        Ok(Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, rsa::PublicKey(public_key)),
            path: key_path.to_string(),
            key: RsaKey::new(key_path)?,
        })
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: KeyType::Rsa,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Verify;
    use hex_literal::hex;

    #[test]
    fn verify() {
        // Test a msg signed and verified with a keypair generated with qseecom crypto
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "1trSusex3KsU6oyDmozsPFLC13G9DQ6A6ksZfLWY1A4zYPn5qP8cBD6CgTjZrAQQ1Tg3wTYyZx5mqrrGeaCf6UWNs6nH5MfAkeRYSKpEUcfMu1ZM5Jtj3BrMDFJFSyVgXtNSPtarSj61iFmCwSsNke87QUKGd5RcgFiE5VH3uCTNEkNmqwDrhkfkWieTQ2BRTSbhbPwmS4dKzNVUTjb7z5o7rU4AY67PrZqZPiV6MrS4vHshbLfBb8tKnFtYNwAUNnK2MK7heUMKhN6TZiCpEQE4zZrvgyAJpZd3XkbuQJDVAF18bc7QeAT4aeMKsbfdx6XYREamJyAnoHffqdokLu4stM7h8LPSNA8cT2VKrFxYuS";
        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        const SIG: &[u8] =
            &hex!("460adb3380bd8856c47176c3235f020c85b2067a7180fe40f3936ad572941d5340267577ad314443c64c3dee997aa1c0488fb2fd9b76d018e59a8b38dfe321cf6030fe65faa0bf9ab59565fb78baa37d1a85c33745c9852845791f75545904720d2e240bc6dbff12332d6dd4a411fb4b58f67653514eaf4219f0a37c6961b38f9351abb235f5b953f94ea2db225ecdd7b73e4bf4323034a91ef8c9f617eca338a69e70da3d0cf3bebf408c837a8c60924202f510e633ed36b156215cf21553edffb3fcd845f1884fce971b60c4d12096eea8513dfbf3c7a3027502b66492504c89f0ca72b5fcaff38cd5455286cf9b88827aec15943e03d69e21bbfa10671397");
        assert!(public_key.verify(MSG, SIG).is_ok());
    }

    #[test]
    fn b58_roundtrip() {
        // Test a public key generated with qseecom crypto
        const B58: &str = "1trSusex3KsU6oyDmozsPFLC13G9DQ6A6ksZfLWY1A4zYPn5qP8cBD6CgTjZrAQQ1Tg3wTYyZx5mqrrGeaCf6UWNs6nH5MfAkeRYSKpEUcfMu1ZM5Jtj3BrMDFJFSyVgXtNSPtarSj61iFmCwSsNke87QUKGd5RcgFiE5VH3uCTNEkNmqwDrhkfkWieTQ2BRTSbhbPwmS4dKzNVUTjb7z5o7rU4AY67PrZqZPiV6MrS4vHshbLfBb8tKnFtYNwAUNnK2MK7heUMKhN6TZiCpEQE4zZrvgyAJpZd3XkbuQJDVAF18bc7QeAT4aeMKsbfdx6XYREamJyAnoHffqdokLu4stM7h8LPSNA8cT2VKrFxYuS";
        let decoded: crate::PublicKey = B58.parse().expect("b58 public key");
        assert_eq!(B58, decoded.to_string());
    }
}
