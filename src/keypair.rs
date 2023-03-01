use crate::*;
use std::ops::Deref;

/// Defines a trait for signing messages. Rather than the signature::Signer
/// trait which deals with exact signature sizes, this trait allows for variable
/// sized signatures, since the ECDSA signature is DER encoded.
pub trait Sign {
    /// Sign the given message
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

#[derive(PartialEq, Debug)]
pub enum Keypair {
    Secp256k1(secp256k1::Keypair),
    Ed25519(ed25519::Keypair),
    EccCompact(ecc_compact::Keypair),
    #[cfg(feature = "ecc608")]
    Ecc608(ecc608::Keypair),
    #[cfg(feature = "tpm")]
    TPM(tpm::Keypair),
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
            Self::TPM(keypair) => keypair.sign(msg),
        }
    }
}

impl Keypair {
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
        }
    }

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
        }
    }

    pub fn key_tag(&self) -> KeyTag {
        match self {
            Self::Secp256k1(keypair) => keypair.key_tag(),
            Self::Ed25519(keypair) => keypair.key_tag(),
            Self::EccCompact(keypair) => keypair.key_tag(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => keypair.key_tag(),
            #[cfg(feature = "tpm")]
            Self::TPM(keypair) => keypair.key_tag(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::Secp256k1(keypair) => &keypair.public_key,
            Self::Ed25519(keypair) => &keypair.public_key,
            Self::EccCompact(keypair) => &keypair.public_key,
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => &keypair.public_key,
            #[cfg(feature = "tpm")]
            Self::TPM(keypair) => &keypair.public_key,
        }
    }

    pub fn ecdh(&self, public_key: &PublicKey) -> Result<SharedSecret> {
        match self {
            Self::EccCompact(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            #[cfg(feature = "tpm")]
            Self::TPM(keypair) => Ok(SharedSecret(keypair.ecdh(public_key)?)),
            _ => Err(Error::invalid_curve()),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Secp256k1(keypair) => keypair.to_vec(),
            Self::Ed25519(keypair) => keypair.to_vec(),
            Self::EccCompact(keypair) => keypair.to_vec(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(_) => panic!("not supported"),
            #[cfg(feature = "tpm")]
            Self::TPM(_) => panic!("not supported"),
        }
    }

    pub fn secret_to_vec(&self) -> Vec<u8> {
        match self {
            Self::Secp256k1(keypair) => keypair.secret_to_vec(),
            Self::Ed25519(keypair) => keypair.secret_to_vec(),
            Self::EccCompact(keypair) => keypair.secret_to_vec(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(_) => panic!("not supported"),
            #[cfg(feature = "tpm")]
            Self::TPM(_) => panic!("not supported"),
        }
    }
}

impl From<secp256k1::Keypair> for Keypair {
    fn from(keypair: secp256k1::Keypair) -> Self {
        Self::Secp256k1(keypair)
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
impl From<tpm::Keypair> for Keypair {
    fn from(keypair: tpm::Keypair) -> Self {
        Self::TPM(keypair)
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        match KeyType::try_from(input[0])? {
            KeyType::Secp256k1 => Ok(secp256k1::Keypair::try_from(input)?.into()),
            KeyType::Ed25519 => Ok(ed25519::Keypair::try_from(input)?.into()),
            KeyType::EccCompact => Ok(ecc_compact::Keypair::try_from(input)?.into()),
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
        assert!(key_pair
            .public_key()
            .verify(b"hello world", &signature)
            .is_ok())
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
    fn sign_tpm() {
        let keypair = tpm::Keypair::from_key_path(Network::MainNet, "HS/SRK/MinerKey").unwrap();

        sign_test_keypair(&Keypair::TPM(keypair));
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
    fn ecdh_tpm() {
        let keypair = tpm::Keypair::from_key_path(Network::MainNet, "HS/SRK/MinerKey").unwrap();

        ecdh_test_keypair(&Keypair::TPM(keypair));
    }
}
