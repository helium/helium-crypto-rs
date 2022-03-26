use std::{
    convert::{TryFrom, TryInto},
    sync::Once,
};

use p256::{ecdsa};
use sha2::{Digest, Sha256};

use crate::{keypair, KeyTag, Network, public_key, Result, KeyType as CrateKeyType, error};

use helium_tpm::{sign, ecdh, tpm_init, tpm_deinit, public_key, Error};
use p256::elliptic_curve::sec1::FromEncodedPoint;

use crate::{
    ecc_compact, ecc_compact::Signature,
};


static INIT: Once = Once::new();

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    pub path: String,
}

impl PartialEq<Self> for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key && self.path == other.path
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("path", &self.path)
            .field("public", &self.public_key)
            .finish()
    }
}

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_vec())
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        helium_tpm::tpm_deinit();
    }
}

pub fn init() -> Result {
    if INIT.is_completed() {
        return Ok(());
    }

    helium_tpm::tpm_init()?;

    Ok(())
}

impl Keypair {
    pub fn from_key_path(network: Network, key_path: String) -> Result<Keypair> {
        let bytes: Vec<u8> = Self::public_key(&key_path)?;
        let mut key_bytes = vec![4u8];
        key_bytes.extend_from_slice(bytes.as_slice());
        let public_key = ecc_compact::PublicKey::try_from(key_bytes.as_ref())?;
        Ok(Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, public_key),
            path: key_path
        })
    }

    fn public_key(key_path: &String) -> Result<Vec<u8>> {
        let res = helium_tpm::public_key(key_path)?;
        return Ok(res);
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: CrateKeyType::EccCompact,
        }
    }

    pub fn ecdh<'a, C>(&self, public_key: C) -> Result<ecc_compact::SharedSecret>
        where
            C: TryInto<&'a ecc_compact::PublicKey, Error = error::Error>,
    {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let key = public_key.try_into()?;
        let point = key.0.to_encoded_point(false);
        let path = &self.path;

        let mut shared_secret_bytes = vec![4u8];
        shared_secret_bytes.extend_from_slice(helium_tpm::ecdh(point, path)?.as_slice());

        let encoded_point = p256::EncodedPoint::from_bytes(shared_secret_bytes.as_slice()).map_err(p256::elliptic_curve::Error::from)?;
        let affine_point = p256::AffinePoint::from_encoded_point(&encoded_point).unwrap();
        Ok(ecc_compact::SharedSecret(p256::ecdh::SharedSecret::from(&affine_point)))
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let digest = Sha256::digest(msg).to_vec();
        let sign_slice = helium_tpm::sign(&self.path, digest).map_err(|e| signature::Error::from_source(e))?;

        let signature = ecdsa::Signature::from_der(&sign_slice[..])?;
        Ok(Signature(signature))
    }
}