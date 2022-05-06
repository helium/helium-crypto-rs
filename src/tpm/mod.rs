mod tpm_wrapper;

use p256::ecdsa;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};
use std::sync::{
    atomic::{AtomicI32, Ordering::SeqCst},
    Once,
};
use thiserror::Error;

use crate::{
    ecc_compact, ecc_compact::Signature, error, keypair, public_key, KeyTag,
    KeyType as CrateKeyType, Network, Result,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("function {0} returned error code {1}")]
    TPMError(&'static str, u32),

    #[error("wrong key path")]
    WrongKeyPath,
}

impl Error {
    pub fn tpm_error(func: &'static str, code: u32) -> crate::Error {
        Self::TPMError(func, code).into()
    }

    pub fn wrong_key_path() -> crate::Error {
        Self::WrongKeyPath.into()
    }
}

static INIT: Once = Once::new();
static COUNTER: AtomicI32 = AtomicI32::new(0);

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
        if COUNTER.fetch_sub(1, SeqCst) == 1 {
            tpm_wrapper::tpm_deinit();
        }
    }
}

pub fn init() -> Result {
    if INIT.is_completed() {
        COUNTER.fetch_add(1, SeqCst);
        return Ok(());
    }

    let mut res: Result = Ok(());
    INIT.call_once(|| {
        res = tpm_wrapper::tpm_init();
    });

    COUNTER.fetch_add(1, SeqCst);
    res
}

impl Keypair {
    pub fn from_key_path(network: Network, key_path: &str) -> Result<Keypair> {
        let bytes: Vec<u8> = Self::public_key(key_path)?;
        let mut key_bytes = vec![4u8];
        key_bytes.extend_from_slice(bytes.as_slice());
        let public_key = ecc_compact::PublicKey::try_from(key_bytes.as_ref())?;
        Ok(Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, public_key),
            path: key_path.to_string(),
        })
    }

    fn public_key(key_path: &str) -> Result<Vec<u8>> {
        let res = tpm_wrapper::public_key(key_path)?;
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
        let path = &self.path;

        let mut shared_secret_bytes = vec![4u8];
        shared_secret_bytes.extend_from_slice(tpm_wrapper::ecdh(x, y, path)?.as_slice());

        let encoded_point = p256::EncodedPoint::from_bytes(shared_secret_bytes.as_slice())
            .map_err(p256::elliptic_curve::Error::from)?;
        let affine_point = p256::AffinePoint::from_encoded_point(&encoded_point).unwrap();
        Ok(ecc_compact::SharedSecret(p256::ecdh::SharedSecret::from(
            &affine_point,
        )))
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let digest = Sha256::digest(msg).to_vec();
        let sign_slice =
            tpm_wrapper::sign(&self.path, digest).map_err(signature::Error::from_source)?;

        let signature = ecdsa::Signature::from_der(&sign_slice[..])?;
        Ok(Signature(signature))
    }
}
