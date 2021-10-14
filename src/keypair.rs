use crate::*;

/// Defines a trait for signing messages. Rather than the signature::Signer
/// trait which deals with exact signature sizes, this trait allows for variable
/// sized signatures, since the ECDSA signature is DER encoded.
pub trait Sign {
    /// Sign the given message
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

#[derive(PartialEq, Debug)]
pub enum Keypair {
    Ed25519(ed25519::Keypair),
    EccCompact(ecc_compact::Keypair),
    #[cfg(feature = "ecc608")]
    Ecc608(ecc608::Keypair),
}

impl Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(keypair) => keypair.sign(msg),
            Self::EccCompact(keypair) => keypair.sign(msg),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => keypair.sign(msg),
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
        }
    }

    pub fn key_tag(&self) -> KeyTag {
        match self {
            Self::Ed25519(keypair) => keypair.key_tag(),
            Self::EccCompact(keypair) => keypair.key_tag(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => keypair.key_tag(),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::Ed25519(keypair) => &keypair.public_key,
            Self::EccCompact(keypair) => &keypair.public_key,
            #[cfg(feature = "ecc608")]
            Self::Ecc608(keypair) => &keypair.public_key,
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(keypair) => keypair.to_vec(),
            Self::EccCompact(keypair) => keypair.to_vec(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(_) => panic!("not supported"),
        }
    }

    pub fn secret_to_vec(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(keypair) => keypair.secret_to_vec(),
            Self::EccCompact(keypair) => keypair.secret_to_vec(),
            #[cfg(feature = "ecc608")]
            Self::Ecc608(_) => panic!("not supported"),
        }
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

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        match KeyType::try_from(input[0])? {
            KeyType::Ed25519 => Ok(ed25519::Keypair::try_from(input)?.into()),
            KeyType::EccCompact => Ok(ecc_compact::Keypair::try_from(input)?.into()),
        }
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

    fn sign_test(key_tag: KeyTag) {
        let keypair = Keypair::generate(key_tag, &mut OsRng);
        let signature = keypair.sign(b"hello world").expect("signature");
        assert!(keypair
            .public_key()
            .verify(b"hello world", &signature)
            .is_ok())
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
    fn sign_ed25519() {
        sign_test(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::Ed25519,
        });
    }

    #[test]
    fn sign_ecc_compact() {
        sign_test(KeyTag {
            network: Network::MainNet,
            key_type: KeyType::EccCompact,
        });
    }
}
