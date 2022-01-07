//! Public keys are the public part of a keypair. While keypairs define specific
//! implementations, the pulic key implementation needs to support all of them
//! since a client will need to be able to parse and use a public key from any
//! keypair.
use crate::*;
use std::{convert::TryFrom, hash::Hash};

///Verify a given message against a given signature slice. Public keys are
///expected to implemt this trait to verify signed messages.
pub trait Verify {
    /// Verify the given message against the givem signature. An error is
    /// returned if the signature can not be parsed or verified for the
    /// implementor
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result;
}

/// The public key byte length is the underlying public key length all key types
/// with an extra type byte prefixed.
pub trait PublicKeySize {
    fn public_key_size(&self) -> usize;
}

/// A public key representing any of the supported public key types on a given
/// network.
///
/// Public keys can convert to and from their binary and base58 representation
#[derive(Clone, PartialEq, Hash)]
pub struct PublicKey {
    /// The network this public key is valid for
    pub network: Network,
    inner: PublicKeyRepr,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r#type = match self.inner {
            PublicKeyRepr::Ed25519(_) => "ed25519",
            PublicKeyRepr::EccCompact(_) => "ecc_compact",
        };
        let output = format!(
            "PublicKey {{ \
        network: {:?}, type: {}, base58: {} }}",
            &self.network,
            &r#type,
            &self.to_string()
        );
        f.write_str(&output)
    }
}

/// Holds the actual representation of all supported public key types.
#[derive(Debug, Clone, PartialEq, Hash)]
pub(crate) enum PublicKeyRepr {
    EccCompact(ecc_compact::PublicKey),
    Ed25519(ed25519::PublicKey),
}

impl Eq for PublicKey {}

impl PublicKeySize for PublicKeyRepr {
    fn public_key_size(&self) -> usize {
        match self {
            Self::EccCompact(key) => key.public_key_size(),
            Self::Ed25519(key) => key.public_key_size(),
        }
    }
}

impl PublicKeySize for PublicKey {
    fn public_key_size(&self) -> usize {
        self.inner.public_key_size()
    }
}

impl From<&PublicKey> for Vec<u8> {
    fn from(v: &PublicKey) -> Self {
        v.to_vec()
    }
}

impl From<PublicKey> for Vec<u8> {
    fn from(v: PublicKey) -> Self {
        Self::from(&v)
    }
}

impl TryFrom<Vec<u8>> for PublicKey {
    type Error = Error;
    fn try_from(v: Vec<u8>) -> Result<Self> {
        Self::try_from(&v[..])
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::missing_keytype());
        }
        Ok(Self {
            network: Network::try_from(bytes[0])?,
            inner: PublicKeyRepr::try_from(bytes)?,
        })
    }
}

impl TryFrom<&[u8]> for PublicKeyRepr {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::missing_keytype());
        }
        match KeyType::try_from(bytes[0])? {
            KeyType::EccCompact => Ok(Self::EccCompact(ecc_compact::PublicKey::try_from(bytes)?)),
            KeyType::Ed25519 => Ok(Self::Ed25519(ed25519::PublicKey::try_from(bytes)?)),
        }
    }
}

impl IntoBytes for PublicKey {
    fn bytes_into(&self, output: &mut [u8]) {
        output[0] = u8::from(self.key_tag());
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

impl From<ed25519::PublicKey> for PublicKeyRepr {
    fn from(v: ed25519::PublicKey) -> Self {
        Self::Ed25519(v)
    }
}

impl From<ecc_compact::PublicKey> for PublicKeyRepr {
    fn from(v: ecc_compact::PublicKey) -> Self {
        Self::EccCompact(v)
    }
}

impl Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        self.inner.verify(msg, signature)
    }
}

impl Verify for PublicKeyRepr {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        match self {
            Self::Ed25519(key) => key.verify(msg, signature),
            Self::EccCompact(key) => key.verify(msg, signature),
        }
    }
}

impl From<ecc_compact::PublicKey> for PublicKey {
    fn from(v: ecc_compact::PublicKey) -> Self {
        Self::for_network(Network::MainNet, v)
    }
}

impl<'a> TryFrom<&'a PublicKey> for &'a ecc_compact::PublicKey {
    type Error = Error;
    fn try_from(v: &'a PublicKey) -> Result<Self> {
        match &v.inner {
            PublicKeyRepr::EccCompact(public_key) => Ok(public_key),
            _ => Err(Error::invalid_curve()),
        }
    }
}

impl From<ed25519::PublicKey> for PublicKey {
    fn from(v: ed25519::PublicKey) -> Self {
        Self::for_network(Network::MainNet, v)
    }
}

impl<'a> TryFrom<&'a PublicKey> for &'a ed25519::PublicKey {
    type Error = Error;
    fn try_from(v: &'a PublicKey) -> Result<Self> {
        match &v.inner {
            PublicKeyRepr::Ed25519(public_key) => Ok(public_key),
            _ => Err(Error::invalid_curve()),
        }
    }
}

impl std::str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let data = bs58::decode(s).with_check(Some(0)).into_vec()?;
        Self::try_from(&data[1..])
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let mut data = vec![0u8; self.public_key_size() + 1];
        self.bytes_into(&mut data[1..]);
        let encoded = bs58::encode(&data).with_check().into_string();
        f.write_str(&encoded)
    }
}

use serde::de::{self, Deserialize, Deserializer, Visitor};

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl<'de> Visitor<'de> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("base58 public key")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<PublicKey, E>
            where
                E: de::Error,
            {
                let key = PublicKey::from_str(value)
                    .map_err(|_| de::Error::custom("invalid public key"))?;
                Ok(key)
            }
        }

        deserializer.deserialize_str(PublicKeyVisitor)
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
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Self::try_from(bytes.as_ref())
    }

    /// Convert a public to a Vec of it's binary form.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = vec![0u8; self.public_key_size()];
        self.bytes_into(&mut result);
        result
    }

    /// Get the type for this key
    pub fn key_type(&self) -> KeyType {
        match self.inner {
            PublicKeyRepr::EccCompact(..) => KeyType::EccCompact,
            PublicKeyRepr::Ed25519(..) => KeyType::Ed25519,
        }
    }

    /// Get the tag for this key
    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: self.key_type(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_roundtrip() {
        // This is a valid b58 encoded compact key
        const B58: &str = "11263KvqW3GZPAvag5sQYtBJSjb25azSTSwoi5Tza9kboaLRxcsv";
        let public_key: PublicKey = B58.parse().expect("public key");
        assert_eq!(
            public_key.key_tag(),
            KeyTag {
                network: Network::MainNet,
                key_type: KeyType::EccCompact
            }
        );
        assert_eq!(public_key.to_string(), B58.to_string())
    }

    use hex_literal::hex;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    const DEFAULT_BYTES: [u8; 33] =
        hex!("008f23e96ab6bbff48c8923cac831dc97111bcf33dba9f5a8539c00f9d93551af1");

    // move the key so as to consume it and avoid accidentally hashing the same thing twice in tests
    fn pubkey_hash(pubkey: PublicKey) -> u64 {
        let mut hasher = DefaultHasher::new();
        pubkey.hash(&mut hasher);
        hasher.finish()
    }

    fn parse_pubkey(bytes: &[u8; 33]) -> PublicKey {
        PublicKey::from_bytes(&bytes).expect("failed to parse bytes as publickey")
    }

    #[test]
    fn hash_match() {
        let bytes = DEFAULT_BYTES;
        let public_key_one = parse_pubkey(&bytes);
        let public_key_two = parse_pubkey(&bytes);

        let hash_one = pubkey_hash(public_key_one);
        let hash_two = pubkey_hash(public_key_two);
        // hashing same input twice should always match
        assert_eq!(hash_one, hash_two);
    }

    #[test]
    fn hash_diff_network() {
        let bytes_mainnet = DEFAULT_BYTES;

        let mut bytes_testnet = DEFAULT_BYTES;
        bytes_testnet[0] = 0x10;

        let public_key_mainnet = parse_pubkey(&bytes_mainnet);
        let public_key_testnet = parse_pubkey(&bytes_testnet);
        // we verify the different networks
        assert_eq!(public_key_mainnet.network, Network::MainNet);
        assert_eq!(public_key_testnet.network, Network::TestNet);

        let hash_mainnet = pubkey_hash(public_key_mainnet);
        let hash_testnet = pubkey_hash(public_key_testnet);
        // we confirm no collision
        assert_ne!(hash_mainnet, hash_testnet);
    }

    #[test]
    fn hash_diff_keytype() {
        let bytes_ecccompact = DEFAULT_BYTES;
        let mut bytes_ed25519 = DEFAULT_BYTES;
        bytes_ed25519[0] = 0x01;

        let public_key_ecccompact = parse_pubkey(&bytes_ecccompact);
        let public_key_ed25519 = parse_pubkey(&bytes_ed25519);
        // we verify the different keytypes
        assert_eq!(public_key_ecccompact.key_type(), KeyType::EccCompact);
        assert_eq!(public_key_ed25519.key_type(), KeyType::Ed25519);

        let hash_ecccompact = pubkey_hash(public_key_ecccompact);
        let hash_ed25519 = pubkey_hash(public_key_ed25519);
        // we verify no collision
        assert_ne!(hash_ecccompact, hash_ed25519);
    }

    #[test]
    fn hash_one_byte_diff() {
        let bytes_one = DEFAULT_BYTES;
        let mut bytes_two = DEFAULT_BYTES;
        bytes_two[8] = 0xAB;

        let public_key_one = parse_pubkey(&bytes_one);
        let public_key_two = parse_pubkey(&bytes_two);

        let hash_one = pubkey_hash(public_key_one);
        let hash_two = pubkey_hash(public_key_two);
        assert_ne!(hash_one, hash_two);
    }

    #[test]
    fn custom_debug() {
        let public_key = PublicKey::from_bytes(DEFAULT_BYTES).unwrap();

        let debug = format!("{:?}", public_key);
        assert_eq!(
            debug,
            "PublicKey { \
                        network: MainNet, type: ecc_compact, \
                        base58: 11263KvqW3GZPAvag5sQYtBJSjb25azSTSwoi5Tza9kboaLRxcsv \
                    }"
        );
    }
}
