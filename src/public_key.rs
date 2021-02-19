//! Public keys are the public part of a keypair. While keypairs define specific
//! implementations, the pulic key implementation needs to support all of them
//! since a client will need to be able to parse and use a public key from any
//! keypair.
use crate::{ecc_compact, ed25519, error, IntoBytes, KeyTag, KeyType, Network};
use std::convert::TryFrom;

///Verify a given message against a given signature slice. Public keys are
///expected to implemt this trait to verify signed messages.
pub trait Verify {
    /// Verify the given message against the givem signature. An error is
    /// returned if the signature can not be parsed or verified for the
    /// implementor
    fn verify(&self, msg: &[u8], signature: &[u8]) -> error::Result;
}

/// The public key byte length is 32 for all key types with an extra type byte
/// prefixed.
pub const PUBLIC_KEY_LENGTH: usize = 33;

/// A public key representing any of the supported public key types on a given
/// network.
///
/// Public keys can convert to and from their binary and base58 representation
#[derive(Debug, PartialEq, Clone)]
pub struct PublicKey {
    /// The network this public key is valid for
    pub network: Network,
    inner: PublicKeyRepr,
}

/// Holds the actual representation of all supported public key types.
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum PublicKeyRepr {
    EccCompact(ecc_compact::PublicKey),
    Ed25519(ed25519::PublicKey),
}

impl Eq for PublicKey {}

impl From<&PublicKey> for Vec<u8> {
    fn from(v: &PublicKey) -> Self {
        let mut result = vec![0u8; PUBLIC_KEY_LENGTH];
        v.bytes_into(&mut result);
        result
    }
}

impl From<PublicKey> for Vec<u8> {
    fn from(v: PublicKey) -> Self {
        Self::from(&v)
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = error::Error;
    fn try_from(v: Vec<u8>) -> error::Result<Self> {
        Self::try_from(&v[..])
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = error::Error;
    fn try_from(bytes: &[u8]) -> error::Result<Self> {
        Ok(Self {
            network: Network::try_from(bytes[0])?,
            inner: PublicKeyRepr::try_from(bytes)?,
        })
    }
}

impl TryFrom<&[u8]> for PublicKeyRepr {
    type Error = error::Error;
    fn try_from(bytes: &[u8]) -> error::Result<Self> {
        match KeyType::try_from(bytes[0])? {
            KeyType::EccCompact => Ok(Self::EccCompact(ecc_compact::PublicKey::try_from(bytes)?)),
            KeyType::Ed25519 => Ok(Self::Ed25519(ed25519::PublicKey::try_from(bytes)?)),
        }
    }
}

impl IntoBytes for PublicKey {
    fn bytes_into(&self, output: &mut [u8]) {
        output[0] = u8::from(self.tag());
        self.inner.bytes_into(&mut output[1..]);
    }
}

impl IntoBytes for PublicKeyRepr {
    fn bytes_into(&self, output: &mut [u8]) {
        match self {
            Self::EccCompact(key) => key.bytes_into(output),
            Self::Ed25519(key) => key.bytes_into(output),
        }
    }
}

impl From<ecc_compact::PublicKey> for PublicKeyRepr {
    fn from(v: ecc_compact::PublicKey) -> Self {
        Self::EccCompact(v)
    }
}

impl From<ed25519::PublicKey> for PublicKeyRepr {
    fn from(v: ed25519::PublicKey) -> Self {
        Self::Ed25519(v)
    }
}

impl Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> error::Result {
        self.inner.verify(msg, signature)
    }
}

impl Verify for PublicKeyRepr {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> error::Result {
        match self {
            Self::Ed25519(key) => key.verify(msg, signature),
            Self::EccCompact(key) => key.verify(msg, signature),
        }
    }
}

impl std::str::FromStr for PublicKey {
    type Err = error::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let data = bs58::decode(s).with_check(Some(0)).into_vec()?;
        Self::try_from(&data[1..])
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let mut data = [0u8; PUBLIC_KEY_LENGTH + 1];
        self.bytes_into(&mut data[1..]);
        let encoded = bs58::encode(data.as_ref()).with_check().into_string();
        f.write_str(&encoded)
    }
}

impl PublicKey {
    pub(crate) fn for_network<C: Into<PublicKeyRepr>>(network: Network, public_key: C) -> Self {
        Self {
            network,
            inner: public_key.into(),
        }
    }

    /// Construct a public key from its binary form
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> error::Result<Self> {
        Self::try_from(bytes.as_ref())
    }

    /// Convert a public key to it's binary form
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        let mut result = [0u8; PUBLIC_KEY_LENGTH];
        self.bytes_into(&mut result);
        result
    }

    /// Convert a public to a Vec of it's binary form. A convenience function
    /// equivalent to calling `public_key.to_bytes().to_vec()`
    pub fn to_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    /// Get the tag for this key
    pub fn tag(&self) -> KeyTag {
        let key_type = match self.inner {
            PublicKeyRepr::EccCompact(..) => KeyType::EccCompact,
            PublicKeyRepr::Ed25519(..) => KeyType::Ed25519,
        };
        KeyTag {
            network: self.network,
            key_type,
        }
    }
}
