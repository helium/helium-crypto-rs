use crate::{error, FromBytes, IntoBytes, KEYTYPE_ECC_COMPACT, KEYTYPE_ED25519};

///Verify a given message against a given signature slice. Public keys are
///expected to implemt this trait to verify signed messages.
pub trait Verify {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> error::Result;
}

/// The public key byte length is 32 for all key types with an extra type byte
/// prefixed.
pub const PUBLIC_KEY_LENGTH: usize = 33;

/// A public key representing any of the supported public key types.
#[derive(Debug, PartialEq)]
pub enum PublicKey {
    EccCompact(crate::ecc_compact::PublicKey),
    Ed25519(crate::ed25519::PublicKey),
}

impl Eq for PublicKey {}

impl FromBytes for PublicKey {
    fn from_bytes(bytes: &[u8]) -> error::Result<Self> {
        match bytes[0] {
            KEYTYPE_ECC_COMPACT => Ok(Self::EccCompact(crate::ecc_compact::PublicKey::from_bytes(
                &bytes[1..],
            )?)),
            KEYTYPE_ED25519 => Ok(Self::Ed25519(crate::ed25519::PublicKey::from_bytes(
                &bytes[1..],
            )?)),
            invalid => Err(error::invalid_keytype(invalid)),
        }
    }
}

impl Verify for PublicKey {
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
        Self::from_bytes(&data[1..])
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        let mut data = [0u8; PUBLIC_KEY_LENGTH + 1];
        match self {
            Self::Ed25519(key) => {
                data[1] = KEYTYPE_ED25519;
                key.bytes_into(&mut data[2..]);
            }
            Self::EccCompact(key) => {
                data[1] = KEYTYPE_ECC_COMPACT;
                key.bytes_into(&mut data[2..]);
            }
        }
        let encoded = bs58::encode(data.as_ref()).with_check().into_string();
        f.write_str(&encoded)
    }
}
