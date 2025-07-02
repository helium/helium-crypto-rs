mod esys_wrapper;

use crate::{
    ecc_compact, ecc_compact::Signature, error, keypair, public_key, KeyTag,
    KeyType as CrateKeyType, Network, Result,
};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use std::convert::{TryFrom, TryInto};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("esys wrapper error: {0}")]
    TPMEsapiError(String),

    #[error("bad key path {0}")]
    BadKeyPath(String),

    #[error("bad key handle {0}")]
    BadKeyHandle(u32),

    #[error("bad key type")]
    BadKeyType(),

    #[error("unexpected error: {0}")]
    Other(String),
}

impl From<tss_esapi::Error> for Error {
    fn from(v: tss_esapi::Error) -> Self {
        Self::TPMEsapiError(v.to_string())
    }
}

#[derive(PartialEq)]
pub struct KeypairHandle {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    pub handle: u32,
}

impl std::fmt::Debug for KeypairHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("handle", &self.handle)
            .field("public", &self.public_key)
            .finish()
    }
}

impl keypair::Sign for KeypairHandle {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_vec())
    }
}

impl KeypairHandle {
    pub fn from_key_handle(network: Network, key_handle: u32) -> Result<KeypairHandle> {
        let key_bytes = {
            let mut key_bytes: Vec<u8> = Self::public_key(key_handle)?;
            key_bytes.push(4);
            key_bytes.rotate_right(1);
            key_bytes
        };
        let public_key = ecc_compact::PublicKey::try_from(key_bytes.as_ref())?;
        Ok(KeypairHandle {
            network,
            public_key: public_key::PublicKey::for_network(network, public_key),
            handle: key_handle,
        })
    }

    fn public_key(key_handle: u32) -> Result<Vec<u8>> {
        let res = esys_wrapper::public_key(key_handle)?;
        Ok(res)
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
        let x = point.x().unwrap().as_slice();
        let y = point.y().unwrap().as_slice();
        let key_handle = self.handle;

        let mut shared_secret_bytes = vec![4u8];
        shared_secret_bytes.extend_from_slice(esys_wrapper::ecdh(x, y, key_handle)?.as_slice());

        let encoded_point = p256::EncodedPoint::from_bytes(shared_secret_bytes.as_slice())
            .map_err(p256::elliptic_curve::Error::from)?;
        let affine_point = p256::AffinePoint::from_encoded_point(&encoded_point).unwrap();

        Ok(ecc_compact::SharedSecret(p256::ecdh::SharedSecret::from(
            p256::elliptic_curve::point::AffineCoordinates::x(&affine_point),
        )))
    }
}

impl signature::Signer<Signature> for KeypairHandle {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let signature =
            esys_wrapper::sign(self.handle, msg).map_err(signature::Error::from_source)?;
        Ok(Signature(signature))
    }
}
