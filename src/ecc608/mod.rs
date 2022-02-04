use crate::{
    ecc_compact::{self, Signature},
    keypair, public_key, Error, KeyTag, KeyType as CrateKeyType, Network, Result,
};
pub use ecc608_linux::{
    address, key_config, slot_config, Ecc, KeyConfig, KeyType, SlotConfig, Zone, MAX_SLOT,
};

use p256::{ecdsa, elliptic_curve};
use std::{
    convert::{TryFrom, TryInto},
    sync::{Mutex, Once},
};

static INIT: Once = Once::new();
static mut ECC: Option<Mutex<Ecc>> = None;

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    slot: u8,
}

impl PartialEq for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network && self.public_key == other.public_key
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("tag", &self.key_tag())
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

pub fn init(path: &str, address: u16) -> Result {
    if INIT.is_completed() {
        return Ok(());
    }
    let ecc = ecc608_linux::Ecc::from_path(path, address)?;
    unsafe {
        INIT.call_once(|| ECC = Some(Mutex::new(ecc)));
    }
    Ok(())
}

fn ecc<'a>() -> &'a Mutex<Ecc> {
    unsafe { ECC.as_ref().unwrap() }
}

impl Keypair {
    /// Constructs a keypair from the given slot. The returned keypair will use
    /// the private key in the given slot to sign data.
    ///
    /// NOTE: The init function _must have been called once, before using this
    /// function.
    pub fn from_slot(network: Network, slot: u8) -> Result<Keypair> {
        with_ecc(|ecc| Self::from_ecc_slot(ecc, network, slot))
    }

    /// Constructs a keypair from the given slot using the given ECC. The
    /// returned keypair will use the private key in the given slot to sign
    /// data.
    ///
    /// The normal use case is to call this function within the `with_ecc`
    /// callback to use a locked global instance of the ECC.
    pub fn from_ecc_slot(ecc: &mut Ecc, network: Network, slot: u8) -> Result<Keypair> {
        let bytes = ecc.genkey(KeyType::Public, slot)?;
        // Start with the "decompressed" sec1 tag since the ecc does not include it.
        let mut key_bytes = vec![4u8];
        // Add the keybytes from the slot.
        key_bytes.extend_from_slice(bytes.as_ref());
        let public_key = ecc_compact::PublicKey::try_from(key_bytes.as_ref())?;
        Ok(Keypair {
            slot,
            network,
            public_key: public_key::PublicKey::for_network(network, public_key),
        })
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: CrateKeyType::EccCompact,
        }
    }

    pub fn ecdh<'a, C>(&self, public_key: C) -> Result<ecc_compact::SharedSecret>
    where
        C: TryInto<&'a ecc_compact::PublicKey, Error = Error>,
    {
        use elliptic_curve::sec1::ToEncodedPoint;
        let key = public_key.try_into()?;
        let point = key.0.to_encoded_point(false);
        let shared_secret_bytes =
            with_ecc(|ecc| ecc.ecdh(self.slot, point.x().unwrap(), point.y().unwrap()))?;
        Ok(ecc_compact::SharedSecret(p256::ecdh::SharedSecret::from(
            *p256::FieldBytes::from_slice(&shared_secret_bytes),
        )))
    }
}

/// Locks the global ECC and runs the given function, passing in the ECC. The
/// lock on the ecc is dropped as soon as this function returns.
pub fn with_ecc<F, R>(f: F) -> R
where
    F: FnOnce(&mut Ecc) -> R,
{
    let mut ecc = ecc().lock().unwrap();
    f(&mut ecc)
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let sign_result = with_ecc(|ecc| ecc.sign(self.slot, msg));
        match sign_result {
            Ok(bytes) => {
                let signature = ecdsa::Signature::try_from(&bytes[..])?;
                Ok(Signature(signature))
            }
            Err(err) => Err(signature::Error::from_source(err)),
        }
    }
}
