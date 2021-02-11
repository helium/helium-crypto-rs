use crate::{error, keypair, public_key, FromBytes, IntoBytes};
use p256::{
    ecdsa,
    elliptic_curve::{sec1::ToCompactEncodedPoint, weierstrass::point::Decompact},
    FieldBytes,
};

pub type PublicKey = p256::PublicKey;
pub type Signature = ecdsa::Signature;
pub type Keypair = keypair::Keypair<p256::SecretKey>;

pub const KEYPAIR_LENGTH: usize = 32;

pub fn generate<R>(csprng: &mut R) -> Keypair
where
    R: rand_core::CryptoRng + rand_core::RngCore,
{
    let mut secret_key = p256::SecretKey::random(&mut *csprng);
    let mut public_key = secret_key.public_key();
    while !bool::from(public_key.as_affine().is_compactable()) {
        secret_key = p256::SecretKey::random(&mut *csprng);
        public_key = secret_key.public_key();
    }
    Keypair {
        inner: secret_key,
        public_key: public_key::PublicKey::EccCompact(public_key),
    }
}

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> error::Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

impl FromBytes for Keypair {
    fn from_bytes(input: &[u8]) -> error::Result<Self> {
        let secret_key = p256::SecretKey::from_bytes(input)?;
        let public_key = secret_key.public_key();
        Ok(Keypair {
            inner: secret_key,
            public_key: public_key::PublicKey::EccCompact(public_key),
        })
    }
}

impl IntoBytes for Keypair {
    fn bytes_into(&self, output: &mut [u8]) {
        output.copy_from_slice(&self.inner.to_bytes());
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        // TODO: Thre has to be a way to avoid cloning for every signature?
        Ok(p256::ecdsa::SigningKey::from(self.inner.clone()).sign(msg))
    }
}

impl public_key::Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> error::Result {
        use signature::Verifier;
        let signature = p256::ecdsa::Signature::from_der(signature).map_err(error::Error::from)?;
        Ok(p256::ecdsa::VerifyingKey::from(self).verify(msg, &signature)?)
    }
}

impl FromBytes for PublicKey {
    fn from_bytes(input: &[u8]) -> error::Result<Self> {
        match p256::AffinePoint::decompact(&FieldBytes::from_slice(input)).into() {
            Some(point) => Ok(p256::PublicKey::from_affine(point).map_err(error::Error::from)?),
            None => Err(error::not_compact()),
        }
    }
}

impl IntoBytes for PublicKey {
    fn bytes_into(&self, output: &mut [u8]) {
        let encoded = self
            .as_affine()
            .to_compact_encoded_point()
            .expect("compact point");
        output.copy_from_slice(&encoded.as_bytes()[1..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FromBytes, Sign, Verify};
    use hex_literal::hex;
    use rand::rngs::OsRng;

    #[test]
    fn sign_roundtrip() {
        let keypair = super::generate(&mut OsRng);
        let signature = keypair.sign(b"hello world").expect("signature");
        assert!(keypair
            .public_key
            .verify(b"hello world", &signature)
            .is_ok())
    }

    #[test]
    fn bytes_roundtrip() {
        use rand::rngs::OsRng;
        let keypair = super::generate(&mut OsRng);
        let mut output = [0u8; super::KEYPAIR_LENGTH];
        keypair.bytes_into(&mut output);
        assert_eq!(
            keypair,
            super::Keypair::from_bytes(&output).expect("keypair")
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
            &hex!("3ca9d8667de0c07aa71d98b3c8065d2e97ab7bb9cb8776bcc0577a7ac58acd4e");
        assert!(PublicKey::from_bytes(NON_COMPACT_KEY).is_err());
    }
}
