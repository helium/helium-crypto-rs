//! Crypto primitives used by various [Helium][HELIUM] blockchain and wallet services.
//!
//! The library exposes both [Elliptic Curve (ECC)][ECC] NIST P-256 (secp256r1),
//! and ED25519 keypairs based on the excellent work done by the
//! [RustCrypto][RUSTCRYPTO] and [Dalek cryptography][DALEK] projects.
//!
//! ECC keypairs keys implement the strategy described in a [Victor Miller
//! paper][JIVSOV] which compresses keys to just their X-coordinate.
//!
//! The intended implemenation strategy in this crate allows for keypair
//! implementations where the private key is based external to the software,
//! such as an ECC608 chip or an HSM.
//!
//! [RUSTCRYPTO]: https://github.com/RustCrypto
//!
//! [DALEK]: https://github.com/dalek-cryptography
//!
//! [ECC]: http://oid-info.com/get/1.2.840.10045.3.1.7
//!
//! [JIVSOV]: https://tools.ietf.org/html/draft-jivsov-ecc-compact-05
//!
//! [HELIUM]: https://helium.com

pub mod ecc_compact;
pub mod ed25519;

#[cfg(feature = "ecc608")]
pub mod ecc608;

pub mod error;
pub mod public_key;

mod keypair;
pub use error::{Error, Result};
pub use keypair::{Keypair, Sign};
pub use public_key::{PublicKey, PublicKeySize, Verify};
use std::{
    convert::{From, TryFrom, TryInto},
    fmt,
    hash::Hash,
    str::FromStr,
};

/// Keys are generated for a given network. Supported networks are mainnet and
/// testnet. The default network is mainnet.
#[derive(Debug, PartialEq, Clone, Hash)]
pub enum Network {
    MainNet,
    TestNet,
}

impl Copy for Network {}

impl Default for Network {
    fn default() -> Self {
        Self::MainNet
    }
}

/// Key types are the supported types of keys for either public or private keys.
/// The default key type is ed25519.
#[derive(Debug, PartialEq, Clone)]
pub enum KeyType {
    Ed25519,
    EccCompact,
}

impl Copy for KeyType {}

impl Default for KeyType {
    fn default() -> Self {
        Self::Ed25519
    }
}

/// A keytag is the byte prefix tag for both public and private keys in their
/// binary form. A tag encodes both the network and the type of key.
#[derive(Debug, Default, PartialEq, Clone)]
pub struct KeyTag {
    pub network: Network,
    pub key_type: KeyType,
}

impl Copy for KeyTag {}

impl TryFrom<u8> for KeyTag {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        Ok(KeyTag {
            network: v.try_into()?,
            key_type: v.try_into()?,
        })
    }
}

impl From<KeyTag> for u8 {
    fn from(v: KeyTag) -> Self {
        u8::from(v.network) | u8::from(v.key_type)
    }
}

impl TryFrom<u8> for Network {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v & 0xF0 {
            NETTYPE_MAIN => Ok(Self::MainNet),
            NETTYPE_TEST => Ok(Self::TestNet),
            _ => Err(Error::invalid_keytype(v)),
        }
    }
}

impl FromStr for Network {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            NETTYPE_MAIN_STR => Ok(Self::MainNet),
            NETTYPE_TEST_STR => Ok(Self::TestNet),
            _ => Err(Error::invalid_keytype_str(s)),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        f.write_str(match self {
            Self::MainNet => NETTYPE_MAIN_STR,
            Self::TestNet => NETTYPE_TEST_STR,
        })
    }
}

impl From<Network> for u8 {
    fn from(v: Network) -> Self {
        match v {
            Network::MainNet => NETTYPE_MAIN,
            Network::TestNet => NETTYPE_TEST,
        }
    }
}

impl FromStr for KeyType {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            KEYTYPE_ED25519_STR => Ok(Self::Ed25519),
            KEYTYPE_ECC_COMPACT_STR => Ok(Self::EccCompact),
            _ => Err(Error::invalid_keytype_str(s)),
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        f.write_str(match self {
            Self::Ed25519 => KEYTYPE_ED25519_STR,
            Self::EccCompact => KEYTYPE_ECC_COMPACT_STR,
        })
    }
}

impl TryFrom<u8> for KeyType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v & 0xF {
            KEYTYPE_ED25519 => Ok(Self::Ed25519),
            KEYTYPE_ECC_COMPACT => Ok(Self::EccCompact),
            _ => Err(Error::invalid_keytype(v)),
        }
    }
}

impl From<KeyType> for u8 {
    fn from(v: KeyType) -> Self {
        match v {
            KeyType::EccCompact => KEYTYPE_ECC_COMPACT,
            KeyType::Ed25519 => KEYTYPE_ED25519,
        }
    }
}

/// The type tag for encoded ed25519 keys.
pub const KEYTYPE_ED25519: u8 = 0x01;
// The type tag for encoded ecc_compact keys
pub const KEYTYPE_ECC_COMPACT: u8 = 0x00;
/// The string representation of the ed25519 key type
pub const KEYTYPE_ED25519_STR: &str = "ed25519";
/// The string representation of the ecc_compact key type
pub const KEYTYPE_ECC_COMPACT_STR: &str = "ecc_compact";

// The type tag for mainnet keys.
pub const NETTYPE_MAIN: u8 = 0x00;
// The type tag for testnet keys.
pub const NETTYPE_TEST: u8 = 0x10;
/// The string representation of the mainnet network type
pub const NETTYPE_MAIN_STR: &str = "mainnet";
/// The string representation of the testnet network type
pub const NETTYPE_TEST_STR: &str = "testnet";

/// Convert the implementor into its binary form by writing to the given output
/// slice. The output slice is assumed to be of the right minimum size and
/// implementors are expected to panic otherwise.
pub(crate) trait IntoBytes {
    fn bytes_into(&self, output: &mut [u8]);
}
