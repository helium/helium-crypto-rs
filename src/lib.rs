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
mod error;
mod keypair;

pub use error::Error;
pub mod ecc_compact;
pub mod ed25519;
pub mod public_key;

pub use keypair::Sign;
pub use public_key::{PublicKey, Verify};

/// The type tag for encoded ed25519 keys
pub const KEYTYPE_ED25519: u8 = 1;
// The type rag for encoded ecc_compact keys
pub const KEYTYPE_ECC_COMPACT: u8 = 0;

/// Convert the implementor into its binary form by writing to the given output
/// slice. The output slice is assumed to be of the right minimum size and
/// implementors are expected to panic otherwise.
pub trait IntoBytes {
    fn bytes_into(&self, output: &mut [u8]);
}

/// Create an instance of the implementor from a given byte slice.
pub trait FromBytes {
    fn from_bytes(input: &[u8]) -> error::Result<Self>
    where
        Self: std::marker::Sized;
}
