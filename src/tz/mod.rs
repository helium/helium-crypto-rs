mod keyblob;

use crate::{public_key, rsa, rsa::Signature, KeyTag, KeyType, Network, Result, Sign};
use ::rsa::RsaPublicKey;
use std::{convert::TryFrom, fmt, fs};

extern crate num_bigint_dig as num_bigint;
use num_bigint::BigUint;

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
        fs::write(
            "/sys/rsa_sec_key/rsa_key_blob",
            &fs::read(&self.path).unwrap(),
        )
        .map_err(|e| Error::QseecomError(e.to_string()))?;
        fs::write("/sys/rsa_sec_key/rsa_sign", msg)
            .map_err(|e| Error::QseecomError(e.to_string()))?;
        let signed = fs::read("/sys/rsa_sec_key/rsa_sign")
            .map_err(|e| Error::QseecomError(e.to_string()))?;
        Ok(signed)
    }
}

impl Keypair {
    pub fn from_key_path(network: Network, key_path: &str) -> Result<Keypair> {
        let (modulus, public_exp) = Self::public_key(key_path)?;
        let public_key = RsaPublicKey::new(
            BigUint::from_bytes_be(modulus.as_slice()),
            BigUint::from_bytes_be(public_exp.as_slice()),
        )?;

        Ok(Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, rsa::PublicKey(public_key)),
            path: key_path.to_string(),
        })
    }

    fn public_key(key_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let ket_blob = fs::read(key_path).map_err(|_| Error::BadKeyPath(key_path.to_string()))?;
        let key_blob =
            keyblob::KeyBlob::try_from(ket_blob.as_ref()).map_err(|e| Error::KeyBlobError(e))?;
        Ok((key_blob.modulus, key_blob.public_exponent))
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: KeyType::Rsa,
        }
    }
}
