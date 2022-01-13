use crate::*;
use p256::{
    ecdsa,
    elliptic_curve::{ecdh, sec1::ToCompactEncodedPoint, DecompactPoint},
    FieldBytes,
};
use std::{
    convert::TryFrom,
    hash::{Hash, Hasher},
    ops::Deref,
};

#[derive(Debug, Clone)]
pub struct PublicKey(pub(crate) p256::PublicKey);

pub struct SharedSecret(pub(crate) p256::ecdh::SharedSecret);

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
        let secret =
            p256::SecretKey::from_be_bytes(&input[1..usize::min(input.len(), KEYPAIR_LENGTH)])?;
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
        let secret = p256::SecretKey::from_be_bytes(entropy)?;
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

    pub fn ecdh<'a, C>(&self, public_key: C) -> Result<SharedSecret>
    where
        C: TryInto<&'a PublicKey, Error = Error>,
    {
        let public_key = public_key.try_into()?;
        let secret_key = p256::SecretKey::from_be_bytes(&self.secret.to_bytes())?;
        let shared_secret =
            ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), public_key.0.as_affine());
        Ok(SharedSecret(shared_secret))
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
            let encoded_point =
                p256::EncodedPoint::from_bytes(input).map_err(p256::elliptic_curve::Error::from)?;
            // Convert to an affine point, then to the compact encoded form.
            // Then finally convert to the p256 public key.
            let public_key = Option::from(p256::AffinePoint::from_encoded_point(&encoded_point))
                .and_then(|affine_point: p256::AffinePoint| affine_point.to_compact_encoded_point())
                .and_then(|compact_point| {
                    Option::from(p256::PublicKey::from_encoded_point(&compact_point))
                })
                .ok_or_else(Error::not_compact)?;
            Ok(PublicKey(public_key))
        }
    }
}

impl IntoBytes for PublicKey {
    fn bytes_into(&self, output: &mut [u8]) {
        use std::hint::unreachable_unchecked;
        let encoded = self
            .0
            .as_affine()
            .to_compact_encoded_point()
            .unwrap_or_else(|| unsafe { unreachable_unchecked() });
        output.copy_from_slice(&encoded.as_bytes()[1..])
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let encoded = self.0.as_affine().to_encoded_point(false);
        state.write(encoded.as_bytes())
    }
}

impl Deref for SharedSecret {
    type Target = p256::ecdh::SharedSecret;
    fn deref(&self) -> &Self::Target {
        &self.0
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

    #[test]
    fn ecdh_interop() {
        // Generated a rust ecc_cmopact keypair and encoded it's to_vec
        const KEYPAIR: &[u8] =
            &hex!("00ec2a8e3984220e819ed2067c519244029ae51d572773e5895cf1f5c80ecb4487");

        // Generated keypair in erlang libp2p_crypto, did an ecdh with that
        // keypair and the public key from the keypair above which generated the
        // other_shared_secret
        const OTHER_PUBLIC_KEY: &str = "112DcRUBD21ZDZfysHaLtvKDw5j7GhWKZB29dxY8ykiYwNxz71aN";
        const OTHER_SHARED_SECRET: &[u8] =
            &hex!("254f56333bc10a6b6cc194ace2d88e3644226bbe07b28d88f6377cc5f23f8bcc");

        // Reinstantiate my keypair
        let keypair = Keypair::try_from(KEYPAIR).expect("keypair");
        // Reinstantiate the other public key
        let other_public_key: crate::PublicKey =
            OTHER_PUBLIC_KEY.parse().expect("other public key");

        // And now do an ecdh with my keypair and the other public key and
        // compare it with the shared secret that the erlang ecdh generated
        let shared_secret = keypair.ecdh(&other_public_key).expect("shared secret");
        assert_eq!(shared_secret.as_bytes().as_slice(), OTHER_SHARED_SECRET);
    }
}
