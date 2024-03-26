//! Public keys are the public part of a keypair. While keypairs define specific
//! implementations, the pulic key implementation needs to support all of them
//! since a client will need to be able to parse and use a public key from any
//! keypair.
use crate::*;

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
    const PUBLIC_KEY_SIZE: usize;
}

/// A public key representing any of the supported public key types on a given
/// network.
///
/// Public keys can convert to and from their binary and base58 representation
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    /// The network this public key is valid for
    pub network: Network,
    pub(crate) inner: PublicKeyRepr,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("network", &self.network)
            .field("type", &self.key_type())
            .field("address", &self.to_string())
            .finish()
    }
}

/// Holds the actual representation of all supported public key types.
#[derive(Clone, PartialEq, Hash, PartialOrd, Ord)]
pub(crate) enum PublicKeyRepr {
    EccCompact(ecc_compact::PublicKey),
    Ed25519(ed25519::PublicKey),
    #[cfg(feature = "multisig")]
    MultiSig(multisig::PublicKey),
    Secp256k1(secp256k1::PublicKey),
    #[cfg(feature = "rsa")]
    Rsa(rsa::PublicKey),
}

impl Eq for PublicKeyRepr {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let network_cmp = self.network.cmp(&other.network);
        if network_cmp == std::cmp::Ordering::Equal {
            self.inner.cmp(&other.inner)
        } else {
            network_cmp
        }
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
            #[cfg(feature = "multisig")]
            KeyType::MultiSig => Ok(Self::MultiSig(multisig::PublicKey::try_from(bytes)?)),
            KeyType::Secp256k1 => Ok(Self::Secp256k1(secp256k1::PublicKey::try_from(bytes)?)),
            #[cfg(feature = "rsa")]
            KeyType::Rsa => Ok(Self::Rsa(rsa::PublicKey::try_from(bytes)?)),
        }
    }
}

impl WriteTo for PublicKey {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        output.write_all(&[u8::from(self.key_tag())])?;
        self.inner.write_to(output)
    }
}

impl ReadFrom for PublicKey {
    fn read_from<R: std::io::Read>(input: &mut R) -> Result<Self> {
        let key_tag = KeyTag::read_from(input)?;
        let inner = match key_tag.key_type {
            KeyType::EccCompact => {
                PublicKeyRepr::EccCompact(ecc_compact::PublicKey::read_from(input)?)
            }
            KeyType::Ed25519 => PublicKeyRepr::Ed25519(ed25519::PublicKey::read_from(input)?),
            #[cfg(feature = "multisig")]
            KeyType::MultiSig => PublicKeyRepr::MultiSig(multisig::PublicKey::read_from(input)?),
            KeyType::Secp256k1 => PublicKeyRepr::Secp256k1(secp256k1::PublicKey::read_from(input)?),
            #[cfg(feature = "rsa")]
            KeyType::Rsa => PublicKeyRepr::Rsa(rsa::PublicKey::read_from(input)?),
        };
        Ok(Self {
            network: key_tag.network,
            inner,
        })
    }
}

impl WriteTo for PublicKeyRepr {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        match self {
            Self::EccCompact(key) => key.write_to(output),
            Self::Ed25519(key) => key.write_to(output),
            #[cfg(feature = "multisig")]
            Self::MultiSig(key) => key.write_to(output),
            Self::Secp256k1(key) => key.write_to(output),
            #[cfg(feature = "rsa")]
            Self::Rsa(key) => key.write_to(output),
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

#[cfg(feature = "multisig")]
impl From<multisig::PublicKey> for PublicKeyRepr {
    fn from(v: multisig::PublicKey) -> Self {
        Self::MultiSig(v)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::PublicKey> for PublicKeyRepr {
    fn from(v: rsa::PublicKey) -> Self {
        Self::Rsa(v)
    }
}

#[cfg(feature = "sqlx-postgres")]
mod sqlx_postgres {
    use super::*;
    use sqlx::{
        decode::Decode,
        encode::{Encode, IsNull},
        error::BoxDynError,
        postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef, Postgres},
        types::Type,
    };

    impl Type<Postgres> for PublicKey {
        fn type_info() -> PgTypeInfo {
            PgTypeInfo::with_name("text")
        }
    }

    impl Encode<'_, Postgres> for PublicKey {
        fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> IsNull {
            let address = self.to_string();
            Encode::<Postgres>::encode(&address, buf)
        }

        fn size_hint(&self) -> usize {
            25
        }
    }

    impl<'r> Decode<'r, Postgres> for PublicKey {
        fn decode(value: PgValueRef<'r>) -> std::result::Result<Self, BoxDynError> {
            let value = <&str as Decode<Postgres>>::decode(value)?;
            let key = Self::from_str(value)?;
            Ok(key)
        }
    }
}

impl From<secp256k1::PublicKey> for PublicKeyRepr {
    fn from(v: secp256k1::PublicKey) -> Self {
        Self::Secp256k1(v)
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
            Self::Secp256k1(key) => key.verify(msg, signature),
            Self::Ed25519(key) => key.verify(msg, signature),
            Self::EccCompact(key) => key.verify(msg, signature),
            #[cfg(feature = "multisig")]
            Self::MultiSig(key) => key.verify(msg, signature),
            #[cfg(feature = "rsa")]
            Self::Rsa(key) => key.verify(msg, signature),
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

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(v: secp256k1::PublicKey) -> Self {
        Self::for_network(Network::MainNet, v)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::PublicKey> for PublicKey {
    fn from(v: rsa::PublicKey) -> Self {
        Self::for_network(Network::MainNet, v)
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
        // allocate one extra byte for the base58 version
        let mut data = vec![0u8; self.public_key_size() + 1];
        // unwrap ok sicne the allocated data can be assumed to be big enough
        self.write_to(&mut std::io::Cursor::new(&mut data[1..]))
            .unwrap();
        let encoded = bs58::encode(&data).with_check().into_string();
        f.write_str(&encoded)
    }
}

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

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

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                let key = Self::Value::from_str(value)
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

    /// Convert a public key to it's binary form.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = vec![0u8; self.public_key_size()];
        // Unwrap ok here since we've allocated enough space for the output
        self.write_to(&mut std::io::Cursor::new(&mut result))
            .unwrap();
        result
    }

    /// Get the type for this key
    pub fn key_type(&self) -> KeyType {
        match self.inner {
            PublicKeyRepr::EccCompact(..) => KeyType::EccCompact,
            PublicKeyRepr::Ed25519(..) => KeyType::Ed25519,
            #[cfg(feature = "multisig")]
            PublicKeyRepr::MultiSig(..) => KeyType::MultiSig,
            PublicKeyRepr::Secp256k1(..) => KeyType::Secp256k1,
            #[cfg(feature = "rsa")]
            PublicKeyRepr::Rsa(..) => KeyType::Rsa,
        }
    }

    /// Get the tag for this key
    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: self.key_type(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match &self.inner {
            PublicKeyRepr::EccCompact(..) => ecc_compact::PublicKey::PUBLIC_KEY_SIZE,
            PublicKeyRepr::Ed25519(..) => ed25519::PublicKey::PUBLIC_KEY_SIZE,
            #[cfg(feature = "multisig")]
            PublicKeyRepr::MultiSig(..) => multisig::PublicKey::PUBLIC_KEY_SIZE,
            PublicKeyRepr::Secp256k1(..) => secp256k1::PUBLIC_KEY_LENGTH,
            #[cfg(feature = "rsa")]
            PublicKeyRepr::Rsa(public_key) => public_key.public_key_size(),
        }
    }
}

#[cfg(feature = "solana")]
impl TryFrom<PublicKey> for solana_sdk::pubkey::Pubkey {
    type Error = error::Error;

    fn try_from(public_key: PublicKey) -> std::result::Result<Self, Self::Error> {
        if let PublicKeyRepr::Ed25519(key) = public_key.inner {
            Ok(solana_sdk::pubkey::Pubkey::new_from_array(*key.0))
        } else {
            Err(error::DecodeError::Unsupported(
                "only Helium Ed25519 keys may be converted to a Solana key",
            )
            .into())
        }
    }
}

#[cfg(feature = "solana")]
impl From<solana_sdk::pubkey::Pubkey> for PublicKey {
    fn from(v: solana_sdk::pubkey::Pubkey) -> Self {
        let repr = PublicKeyRepr::Ed25519(ed25519::PublicKey(ed25519_compact::PublicKey::new(
            v.to_bytes(),
        )));
        Self::for_network(Network::MainNet, repr)
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
        PublicKey::from_bytes(bytes).expect("failed to parse bytes as publickey")
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
    fn serde() {
        let orig_pub_key = parse_pubkey(&DEFAULT_BYTES);
        let serialized = serde_json::to_string(&orig_pub_key).unwrap();
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(orig_pub_key, deserialized);
    }

    #[test]
    fn k256p1_roundtrip() {
        // This is a valid b58 encoded secp256k1 key
        const B58: &str = "1SpLY6fic4fGthLGjeAUdLVNVYk1gJGrWTGhsukm2dnELaSEQmhL";
        let public_key: PublicKey = B58.parse().expect("public key");
        assert_eq!(
            public_key.key_tag(),
            KeyTag {
                network: Network::MainNet,
                key_type: KeyType::Secp256k1,
            }
        );
        assert_eq!(public_key.to_string(), B58.to_string())
    }

    #[cfg(feature = "solana")]
    #[test]
    fn solana_roundtrip() {
        const B58: &str = "14tCTJDdrecpCN29entF8btzNAoDP6qEAn8CxUiT9SdVwiyXji8";
        let helium_pubkey: PublicKey = B58.parse().expect("helium public key");
        let solana_pubkey =
            solana_sdk::pubkey::Pubkey::try_from(helium_pubkey.clone()).expect("solana pubkey");

        assert_eq!(helium_pubkey, PublicKey::from(solana_pubkey))
    }
}
