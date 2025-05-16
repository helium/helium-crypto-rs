use crate::{Error, KeyTag, PublicKey, Result};
use std::{convert::TryFrom, fmt, str::FromStr};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKeyBinary(Vec<u8>);

impl fmt::Debug for PublicKeyBinary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_tag = KeyTag::try_from(self.0[0]).map_err(|_| fmt::Error)?;
        f.debug_struct("PublicKeyBinary")
            .field("network", &key_tag.network)
            .field("type", &key_tag.key_type)
            .field("address", &self.to_string())
            .finish()
    }
}

impl From<PublicKey> for PublicKeyBinary {
    fn from(value: PublicKey) -> Self {
        Self(value.to_vec())
    }
}

impl From<&[u8]> for PublicKeyBinary {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<Vec<u8>> for PublicKeyBinary {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<PublicKeyBinary> for Vec<u8> {
    fn from(value: PublicKeyBinary) -> Self {
        value.0
    }
}

impl TryFrom<PublicKeyBinary> for PublicKey {
    type Error = Error;
    fn try_from(value: PublicKeyBinary) -> Result<Self> {
        Self::try_from(value.0)
    }
}

impl AsRef<[u8]> for PublicKeyBinary {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::str::FromStr for PublicKeyBinary {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut data = bs58::decode(s).with_check(Some(0)).into_vec()?;
        Ok(Self(data.split_off(1)))
    }
}

impl std::fmt::Display for PublicKeyBinary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        // allocate one extra byte for the base58 version
        let mut data = vec![0u8; self.0.len() + 1];
        data[1..].copy_from_slice(&self.0);
        let encoded = bs58::encode(&data).with_check().into_string();
        f.write_str(&encoded)
    }
}

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

impl Serialize for PublicKeyBinary {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PublicKeyBinary {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PublicKeyVisitor;

        impl Visitor<'_> for PublicKeyVisitor {
            type Value = PublicKeyBinary;

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

#[cfg(feature = "sqlx-postgres")]
mod sqlx_postgres {
    use super::*;
    use sqlx::{
        decode::Decode,
        encode::{Encode, IsNull},
        error::BoxDynError,
        postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueRef, Postgres},
        types::Type,
    };

    impl Type<Postgres> for PublicKeyBinary {
        fn type_info() -> PgTypeInfo {
            PgTypeInfo::with_name("text")
        }
    }

    impl PgHasArrayType for PublicKeyBinary {
        fn array_type_info() -> PgTypeInfo {
            PgTypeInfo::with_name("_text")
        }
    }

    impl Encode<'_, Postgres> for PublicKeyBinary {
        fn encode_by_ref(
            &self,
            buf: &mut PgArgumentBuffer,
        ) -> std::result::Result<IsNull, BoxDynError> {
            let address = self.to_string();
            Encode::<Postgres>::encode(&address, buf)
        }

        fn size_hint(&self) -> usize {
            25
        }
    }

    impl<'r> Decode<'r, Postgres> for PublicKeyBinary {
        fn decode(value: PgValueRef<'r>) -> std::result::Result<Self, BoxDynError> {
            let value = <&str as Decode<Postgres>>::decode(value)?;
            let key = Self::from_str(value)?;
            Ok(key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicKey;

    #[test]
    fn public_key_roundtrip() {
        // This is a valid b58 encoded compact key
        const B58: &str = "11263KvqW3GZPAvag5sQYtBJSjb25azSTSwoi5Tza9kboaLRxcsv";
        let pubkey_bin: PublicKeyBinary = B58.parse().expect("public key");
        let pubkey: PublicKey = B58.parse().expect("public key");
        assert_eq!(pubkey_bin.to_string(), B58.to_string());
        assert_eq!(pubkey_bin, PublicKeyBinary::from(pubkey_bin.as_ref()));
        assert_eq!(pubkey_bin, PublicKeyBinary::from(pubkey.clone()));
        assert_eq!(
            pubkey_bin,
            PublicKeyBinary::from(<PublicKeyBinary as Into<Vec<u8>>>::into(pubkey_bin.clone()))
        );
        assert_eq!(pubkey.to_string(), pubkey_bin.to_string());
        assert_eq!(pubkey, PublicKey::try_from(pubkey_bin).expect("public key"));
    }

    use hex_literal::hex;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    const DEFAULT_BYTES: [u8; 33] =
        hex!("008f23e96ab6bbff48c8923cac831dc97111bcf33dba9f5a8539c00f9d93551af1");

    fn parse_pubkey(bytes: &[u8; 33]) -> PublicKeyBinary {
        PublicKeyBinary::from(bytes.to_vec())
    }

    // move the key so as to consume it and avoid accidentally hashing the same thing twice in tests
    fn pubkey_hash(pubkey: PublicKeyBinary) -> u64 {
        let mut hasher = DefaultHasher::new();
        pubkey.hash(&mut hasher);
        hasher.finish()
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
    fn serde() {
        let orig_pub_key = parse_pubkey(&DEFAULT_BYTES);
        let serialized = serde_json::to_string(&orig_pub_key).unwrap();
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(orig_pub_key, deserialized);
    }
}
