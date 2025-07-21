use crate::*;
use std::ops::Deref;

/// Defines a trait for signing messages. Rather than the signature::Signer
/// trait which deals with exact signature sizes, this trait allows for variable
/// sized signatures, since the ECDSA signature is DER encoded.
pub trait Sign {
    /// Sign the given message
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

/// Represents a cryptographic keypair for any supported key type.
///
/// This enum acts as a type-erased wrapper for all supported keypair types (e.g., Ed25519, Secp256k1, ECC Compact, etc.),
/// allowing generic handling of key generation, signing, and public key extraction.
#[derive(PartialEq, Debug)]
pub enum Keypair {
    Secp256k1(secp256k1::Keypair),
    Ed25519(ed25519::Keypair),
    EccCompact(ecc_compact::Keypair),
    #[cfg(feature = "ecc608")]
    Ecc608(ecc608::Keypair),
    #[cfg(feature = "tpm")]
    TPMHandle(tpm::KeypairHandle),
    #[cfg(feature = "rsa")]
    Rsa(Box<rsa::Keypair>),
    #[cfg(feature = "nova-tz")]
    TrustZone(nova_tz::Keypair),
}

pub struct SharedSecret(ecc_compact::SharedSecret);

impl Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Secp256k1(keypair) => keypair.sign(msg),
            Self::Ed25519(keypair) => keypair.sign(msg),
            Self::EccCompact(keypair) => keypair.sign(msg),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => keypair.sign(msg),
            #[cfg(feature = "tpm")]
            Self::TPMHandle(keypair) => keypair.sign(msg),
            #[cfg(feature = "rsa")]
            Self::Rsa(keypair) => keypair.sign(msg),
            #[cfg(feature = "nova-tz")]
            Self::TrustZone(keypair) => keypair.sign(msg),
        }
    }
}

impl Keypair {
    /// Generates a new keypair for the specified key type and network using the provided CSPRNG.
    ///
    /// # Arguments
    /// * `key_tag` - The key tag specifying the network and key type.
    /// * `csprng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    /// A new `Keypair` instance for the requested type and network.
    ///
    /// # Panics
    /// Panics if the key type is not supported or if key generation fails.
    pub fn generate<R>(key_tag: KeyTag, csprng: &mut R) -> Keypair
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        match key_tag.key_type {
            KeyType::EccCompact => {
                Self::EccCompact(ecc_compact::Keypair::generate(key_tag.network, csprng))
            }
            KeyType::Ed25519 => Self::Ed25519(ed25519::Keypair::generate(key_tag.network, csprng)),
            #[cfg(feature = "multisig")]
            KeyType::MultiSig => panic!("not supported"),
            KeyType::Secp256k1 => {
                Self::Secp256k1(secp256k1::Keypair::generate(key_tag.network, csprng))
            }
            #[cfg(feature = "rsa")]
            KeyType::Rsa => Self::Rsa(Box::new(rsa::Keypair::generate(key_tag.network, csprng))),
        }
    }

    /// Generates a new keypair from the provided entropy for the specified key type and network.
    ///
    /// # Arguments
    /// * `key_tag` - The key tag specifying the network and key type.
    /// * `entropy` - A byte slice containing sufficient entropy for key generation.
    ///
    /// # Returns
    /// A new `Keypair` instance if the entropy is valid for the requested type and network.
    ///
    /// # Errors
    /// Returns an error if the entropy is invalid or the key type is not supported.
    pub fn generate_from_entropy(key_tag: KeyTag, entropy: &[u8]) -> Result<Keypair> {
        match key_tag.key_type {
            KeyType::EccCompact => Ok(Self::EccCompact(
                ecc_compact::Keypair::generate_from_entropy(key_tag.network, entropy)?,
            )),
            KeyType::Ed25519 => Ok(Self::Ed25519(ed25519::Keypair::generate_from_entropy(
                key_tag.network,
                entropy,
            )?)),
            #[cfg(feature = "multisig")]
            KeyType::MultiSig => panic!("not supported"),
            KeyType::Secp256k1 => Ok(Self::Secp256k1(secp256k1::Keypair::generate_from_entropy(
                key_tag.network,
                entropy,
            )?)),
            #[cfg(feature = "rsa")]
            KeyType::Rsa => Ok(Self::Rsa(Box::new(rsa::Keypair::generate_from_entropy(
                key_tag.network,
                entropy,
            )?))),
        }
    }

    /// Returns the key tag for this keypair, encoding the network and key type.
    ///
    /// The key tag is used to identify the network and cryptographic algorithm associated with this keypair.
    pub fn key_tag(&self) -> KeyTag {
        match self {
            Self::Secp256k1(keypair) => keypair.key_tag(),
            Self::Ed25519(keypair) => keypair.key_tag(),
            Self::EccCompact(keypair) => keypair.key_tag(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => keypair.key_tag(),
            #[cfg(feature = "tpm")]
            Self::TPMHandle(keypair) => keypair.key_tag(),
            #[cfg(feature = "rsa")]
            Self::Rsa(keypair) => keypair.key_tag(),
            #[cfg(feature = "nova-tz")]
            Self::TrustZone(keypair) => keypair.key_tag(),
        }
    }

    /// Returns a reference to the public key associated with this keypair.
    ///
    /// The returned public key can be used for signature verification or key exchange.
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::Secp256k1(keypair) => &keypair.public_key,
            Self::Ed25519(keypair) => &keypair.public_key,
            Self::EccCompact(keypair) => &keypair.public_key,
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => &keypair.public_key,
            #[cfg(feature = "tpm")]
            Self::TPMHandle(keypair) => &keypair.public_key,
            #[cfg(feature = "rsa")]
            Self::Rsa(keypair) => &keypair.public_key,
            #[cfg(feature = "nova-tz")]
            Self::TrustZone(keypair) => &keypair.public_key,
        }
    }

    /// Performs an Elliptic Curve Diffie-Hellman (ECDH) key exchange with the given public key.
    ///
    /// # Arguments
    /// * `public_key` - The peer's public key.
    ///
    /// # Returns
    /// A shared secret if ECDH is supported for this key type.
    ///
    /// # Errors
    /// Returns an error if ECDH is not supported for this key type or if the operation fails.
    pub fn ecdh(&self, public_key: &PublicKey) -> Result<SharedSecret> {
        match self {
            Self::EccCompact(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            #[cfg(feature = "tpm")]
            Self::TPMHandle(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            _ => Err(Error::invalid_curve()),
        }
    }

    /// Serializes the keypair to its binary representation.
    ///
    /// # Returns
    /// A vector of bytes containing the serialized keypair, including the key tag and secret key material.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Secp256k1(keypair) => keypair.to_vec(),
            Self::Ed25519(keypair) => keypair.to_vec(),
            Self::EccCompact(keypair) => keypair.to_vec(),
            #[cfg(feature = "rsa")]
            Self::Rsa(keypair) => keypair.to_vec(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(_) => panic!("not supported"),
            #[cfg(feature = "tpm")]
            Self::TPMHandle(_) => panic!("not supported"),
            #[cfg(feature = "nova-tz")]
            Self::TrustZone(_) => panic!("not supported"),
        }
    }

    /// Serializes the secret key material to its binary representation.
    ///
    /// # Returns
    /// A vector of bytes containing the secret key material only (excluding the key tag).
    ///
    /// # Security
    /// Handle this output with care, as it contains sensitive private key material.
    pub fn secret_to_vec(&self) -> Vec<u8> {
        match self {
            Self::Secp256k1(keypair) => keypair.secret_to_vec(),
            Self::Ed25519(keypair) => keypair.secret_to_vec(),
            Self::EccCompact(keypair) => keypair.secret_to_vec(),
            #[cfg(feature = "rsa")]
            Self::Rsa(keypair) => keypair.secret_to_vec(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(_) => panic!("not supported"),
            #[cfg(feature = "tpm")]
            Self::TPMHandle(_) => panic!("not supported"),
            #[cfg(feature = "nova-tz")]
            Self::TrustZone(_) => panic!("not supported"),
        }
    }
}

impl From<secp256k1::Keypair> for Keypair {
    fn from(keypair: secp256k1::Keypair) -> Self {
        Self::Secp256k1(keypair)
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::Keypair> for Keypair {
    fn from(keypair: rsa::Keypair) -> Self {
        Self::Rsa(Box::new(keypair))
    }
}

#[cfg(feature = "nova-tz")]
impl From<nova_tz::Keypair> for Keypair {
    fn from(keypair: nova_tz::Keypair) -> Self {
        Self::TrustZone(keypair)
    }
}

impl From<ed25519::Keypair> for Keypair {
    fn from(keypair: ed25519::Keypair) -> Self {
        Self::Ed25519(keypair)
    }
}

impl From<ecc_compact::Keypair> for Keypair {
    fn from(keypair: ecc_compact::Keypair) -> Self {
        Self::EccCompact(keypair)
    }
}

#[cfg(feature = "ecc608")]
impl From<ecc608::Keypair> for Keypair {
    fn from(keypair: ecc608::Keypair) -> Self {
        Self::Ecc608(keypair)
    }
}

#[cfg(feature = "tpm")]
impl From<tpm::KeypairHandle> for Keypair {
    fn from(keypair: tpm::KeypairHandle) -> Self {
        Self::TPMHandle(keypair)
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        match KeyType::try_from(input[0])? {
            KeyType::Secp256k1 => Ok(secp256k1::Keypair::try_from(input)?.into()),
            KeyType::Ed25519 => Ok(ed25519::Keypair::try_from(input)?.into()),
            KeyType::EccCompact => Ok(ecc_compact::Keypair::try_from(input)?.into()),
            #[cfg(feature = "rsa")]
            KeyType::Rsa => Ok(rsa::Keypair::try_from(input)?.into()),
            #[cfg(feature = "multisig")]
            KeyType::MultiSig => Err(Error::invalid_keytype(input[0])),
        }
    }
}

impl Deref for SharedSecret {
    type Target = ecc_compact::SharedSecret;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    #[cfg(feature = "nova-tz")]
    use {
        std::fs,
        std::io::{Read, Write},
        tempfile,
    };

    fn bytes_roundtrip(key_tag: KeyTag) {
        let keypair = Keypair::generate(key_tag, &mut OsRng);
        let bytes = keypair.to_vec();
        assert_eq!(
            keypair,
            super::Keypair::try_from(&bytes[..]).expect("keypair")
        );
        assert_eq!(keypair.key_tag(), key_tag);
    }

    fn sign_test_tag(key_tag: KeyTag) {
        let keypair = Keypair::generate(key_tag, &mut OsRng);
        sign_test_keypair(&keypair);
    }

    fn sign_test_keypair(key_pair: &Keypair) {
        let signature = key_pair.sign(b"hello world").expect("signature");
        key_pair
            .public_key()
            .verify(b"hello world", &signature)
            .expect("roundtrip signatures should always verify");
    }

    fn ecdh_test_tag(key_tag: KeyTag) {
        let keypair = Keypair::generate(key_tag, &mut OsRng);
        ecdh_test_keypair(&keypair);
    }

    fn ecdh_test_keypair(key_pair: &Keypair) {
        let other = Keypair::generate(key_pair.key_tag(), &mut OsRng);
        let keypair_shared = key_pair
            .ecdh(other.public_key())
            .expect("keypair shared secret");
        let other_shared = other
            .ecdh(key_pair.public_key())
            .expect("other shared secret");

        assert_eq!(
            keypair_shared.raw_secret_bytes(),
            other_shared.raw_secret_bytes()
        );
    }

    fn seed_roundtrip(key_tag: KeyTag) {
        // Assert that initial entropy is the same as secret_to_vec() returns
        const ENTROPY: [u8; 32] = [
            248, 55, 78, 168, 99, 123, 22, 203, 36, 250, 136, 86, 110, 119, 198, 170, 248, 55, 78,
            168, 99, 123, 22, 203, 36, 250, 136, 86, 110, 119, 198, 170,
        ];
        let keypair = Keypair::generate_from_entropy(key_tag, &ENTROPY).expect("keypair");
        assert_eq!(ENTROPY.to_vec(), keypair.secret_to_vec());
    }

    #[test]
    fn bytes_roundtrip_secp256k1() {
        bytes_roundtrip(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::Secp256k1,
        });
        bytes_roundtrip(KeyTag {
            network: Network::TestNet,
            key_type: KeyType::Secp256k1,
        });
    }

    #[test]
    fn bytes_roundtrip_ed25519() {
        bytes_roundtrip(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::Ed25519,
        });
        bytes_roundtrip(KeyTag {
            network: Network::TestNet,
            key_type: KeyType::Ed25519,
        })
    }

    #[test]
    fn bytes_roundtrip_ecc_compact() {
        bytes_roundtrip(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        });
        bytes_roundtrip(KeyTag {
            network: Network::TestNet,
            key_type: KeyType::EccCompact,
        });
    }

    #[test]
    fn seed_roundtrip_ecc_secp256k1() {
        seed_roundtrip(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::Secp256k1,
        });
    }

    #[test]
    fn seed_roundtrip_ed25519() {
        seed_roundtrip(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::Ed25519,
        });
    }

    #[test]
    fn seed_roundtrip_ecc_compact() {
        seed_roundtrip(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        });
    }

    #[test]
    fn sign_ed25519() {
        sign_test_tag(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::Ed25519,
        });
    }

    #[test]
    fn sign_ecc_compact() {
        sign_test_tag(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        });
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn sign_tpm_handle() {
        let keypair = tpm::KeypairHandle::from_key_handle(Network::MainNet, 0x81000031).unwrap();

        sign_test_keypair(&Keypair::TPMHandle(keypair));
    }

    #[cfg(feature = "nova-tz")]
    #[test]
    fn sign_tz() {
        let mut tmpfile = tempfile::tempfile().unwrap();
        tmpfile
            .write_all(
                fs::read("/sys/rsa_sec_key/rsa_generate")
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        let mut key_blob_data: Vec<u8> = vec![];
        tmpfile.read_to_end(&mut key_blob_data).unwrap();

        let keypair =
            nova_tz::Keypair::from_key_blob(Network::MainNet, key_blob_data.as_slice()).unwrap();

        sign_test_keypair(&Keypair::TrustZone(keypair));
    }

    #[test]
    fn ecdh_ecc_compact() {
        ecdh_test_tag(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        });
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn ecdh_tpm_handle() {
        let keypair = tpm::KeypairHandle::from_key_handle(Network::MainNet, 0x81000031).unwrap();

        ecdh_test_keypair(&Keypair::TPMHandle(keypair));
    }
}
