use crate::*;
use p256::{
    ecdsa,
    elliptic_curve::{sec1::ToCompactEncodedPoint, weierstrass::DecompactPoint},
    FieldBytes,
};
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Clone)]
pub struct PublicKey(pub(crate) p256::PublicKey);

#[derive(Debug, PartialEq, Clone)]
pub struct Signature(pub(crate) ecdsa::Signature);

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    secret: p256::ecdsa::SigningKey,
}

pub const KEYPAIR_LENGTH: usize = 33;
pub const PUBLIC_KEY_LENGTH: usize = 33;

pub trait IsCompactable {
    fn is_compactable(&self) -> bool;
}

impl IsCompactable for p256::PublicKey {
    fn is_compactable(&self) -> bool {
        self.as_affine().to_compact_encoded_point().is_some()
    }
}

impl PartialEq for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network && self.public_key == other.public_key
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("tag", &self.key_tag())
            .field("public", &self.public_key)
            .finish()
    }
}

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_vec())
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;
    fn try_from(input: &[u8]) -> Result<Self> {
        let network = Network::try_from(input[0])?;
        let secret = p256::SecretKey::from_bytes(&input[1..])?;
        let public_key =
            public_key::PublicKey::for_network(network, PublicKey(secret.public_key()));
        Ok(Keypair {
            network,
            public_key,
            secret: p256::ecdsa::SigningKey::from(secret),
        })
    }
}

impl IntoBytes for Keypair {
    fn bytes_into(&self, output: &mut [u8]) {
        output[0] = u8::from(self.key_tag());
        output[1..].copy_from_slice(&self.secret.to_bytes());
    }
}

impl Keypair {
    pub fn generate<R>(network: Network, csprng: &mut R) -> Keypair
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let mut secret = p256::SecretKey::random(&mut *csprng);
        let mut public_key = secret.public_key();
        while !public_key.is_compactable() {
            secret = p256::SecretKey::random(&mut *csprng);
            public_key = secret.public_key();
        }
        Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, PublicKey(public_key)),
            secret: p256::ecdsa::SigningKey::from(secret),
        }
    }

    pub fn generate_from_entropy(network: Network, entropy: &[u8]) -> Result<Keypair> {
        let secret = p256::SecretKey::from_bytes(entropy)?;
        let public_key = secret.public_key();
        if !public_key.is_compactable() {
            return Err(Error::not_compact());
        }
        Ok(Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, PublicKey(public_key)),
            secret: p256::ecdsa::SigningKey::from(secret),
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = vec![0u8; KEYPAIR_LENGTH];
        self.bytes_into(&mut result);
        result
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: KeyType::EccCompact,
        }
    }

    pub fn secret_to_vec(&self) -> Vec<u8> {
        self.secret.to_bytes().as_slice().to_vec()
    }
}

impl signature::Signature for Signature {
    fn from_bytes(input: &[u8]) -> std::result::Result<Self, signature::Error> {
        Ok(Signature(signature::Signature::from_bytes(input)?))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        Ok(Signature(self.secret.sign(msg)))
    }
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Signature(signature::Signature::from_bytes(bytes)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_der().as_bytes().to_vec()
    }
}

impl PublicKeySize for PublicKey {
    fn public_key_size(&self) -> usize {
        PUBLIC_KEY_LENGTH
    }
}

impl public_key::Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        use signature::Verifier;
        let signature = p256::ecdsa::Signature::from_der(signature).map_err(Error::from)?;
        Ok(p256::ecdsa::VerifyingKey::from(self.0).verify(msg, &signature)?)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        if input.len() == PUBLIC_KEY_LENGTH {
            // Assume this is a compact key we've encoded before, strip of the network/type tag
            match p256::AffinePoint::decompact(FieldBytes::from_slice(&input[1..])).into() {
                Some(point) => Ok(PublicKey(
                    p256::PublicKey::from_affine(point).map_err(Error::from)?,
                )),
                None => Err(Error::not_compact()),
            }
        } else {
            // Otherwise assume it's just raw bytes
            use p256::elliptic_curve::sec1::FromEncodedPoint;
            let encoded_point = p256::EncodedPoint::from_bytes(input)?;
            // Convert to an affine point, then to the compact encoded form.
            // Then finally convert to the p256 public key.
            let public_key = p256::AffinePoint::from_encoded_point(&encoded_point)
                .and_then(|affine_point| affine_point.to_compact_encoded_point())
                .and_then(|compact_point| p256::PublicKey::from_encoded_point(&compact_point))
                .ok_or_else(Error::not_compact)?;
            Ok(PublicKey(public_key))
        }
    }
}

impl IntoBytes for PublicKey {
    fn bytes_into(&self, output: &mut [u8]) {
        let encoded = self
            .0
            .as_affine()
            .to_compact_encoded_point()
            .expect("compact point");
        output.copy_from_slice(&encoded.as_bytes()[1..])
    }
}

#[cfg(test)]
mod tests {
    use super::{Keypair, PublicKey, TryFrom};
    use crate::{Network, Sign, Verify};
    use hex_literal::hex;
    use rand::rngs::OsRng;

    #[test]
    fn sign_roundtrip() {
        let keypair = Keypair::generate(Network::MainNet, &mut OsRng);
        let signature = keypair.sign(b"hello world").expect("signature");
        assert!(keypair
            .public_key
            .verify(b"hello world", &signature)
            .is_ok())
    }

    #[test]
    fn bytes_roundtrip() {
        use rand::rngs::OsRng;
        let keypair = Keypair::generate(Network::MainNet, &mut OsRng);
        let bytes = keypair.to_vec();
        assert_eq!(
            keypair,
            super::Keypair::try_from(&bytes[..]).expect("keypair")
        );
    }

    #[test]
    fn verify() {
        // Test a msg signed and verified with a keypair generated with erlang libp2p_crypto
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "11nYr7TBMbpGiQadiCxGCPZFZ8ENo1JNtbS7aB5U7UXn4a8Dvb3";
        const SIG: &[u8] =
            &hex!("304402206d791eb96bcc7d0ef403bc7a653fd99a6906374ec9e4aff1d5907d4890e8dd3302204b4c93c7637b22565b944201df9c806d684165802b8a1cd91d4d7799c950e466");

        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        assert!(public_key.verify(MSG, SIG).is_ok());
    }

    #[test]
    fn b58_roundtrip() {
        const B58: &str = "112jXiCTi9DpLC5nLdSZ2zccRVEtZizRJMizziCebaNbRDi8k6wR";
        let decoded: crate::PublicKey = B58.parse().expect("b58 public key");
        assert_eq!(B58, decoded.to_string());
    }

    #[test]
    fn non_compact_key() {
        const NON_COMPACT_KEY: &[u8] =
            &hex!("003ca9d8667de0c07aa71d98b3c8065d2e97ab7bb9cb8776bcc0577a7ac58acd4e");
        assert!(PublicKey::try_from(NON_COMPACT_KEY).is_err());
    }
}
