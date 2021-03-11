use crate::{
    error::{Error, Result},
    keypair, public_key, IntoBytes, KeyTag, KeyType, Network,
};
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Clone)]
pub struct PublicKey(ed25519_dalek::PublicKey);

#[derive(Debug, PartialEq, Clone)]
pub struct Signature(ed25519_dalek::Signature);

pub type Keypair = keypair::Keypair<ed25519_dalek::Keypair>;

pub const KEYPAIR_LENGTH: usize = ed25519_dalek::KEYPAIR_LENGTH + 1;

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.as_ref().to_vec())
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        let network = Network::try_from(input[0])?;
        let inner = ed25519_dalek::Keypair::from_bytes(&input[1..])?;
        let public_key = public_key::PublicKey::for_network(network, PublicKey(inner.public));
        Ok(Keypair {
            network,
            public_key,
            inner,
        })
    }
}

impl IntoBytes for Keypair {
    fn bytes_into(&self, output: &mut [u8]) {
        output[0] = u8::from(KeyTag {
            network: self.network,
            key_type: KeyType::Ed25519,
        });
        output[1..].copy_from_slice(&self.inner.to_bytes());
    }
}

impl Keypair {
    pub fn generate<R>(network: Network, csprng: &mut R) -> Keypair
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let inner = ed25519_dalek::Keypair::generate(csprng);
        let public_key = public_key::PublicKey::for_network(network, PublicKey(inner.public));
        Keypair {
            network,
            public_key,
            inner,
        }
    }

    pub fn generate_from_entropy(network: Network, entropy: &[u8]) -> Result<Keypair> {
        let secret = ed25519_dalek::SecretKey::from_bytes(entropy)?;
        let public = ed25519_dalek::PublicKey::from(&secret);
        let inner = ed25519_dalek::Keypair { secret, public };
        let public_key = public_key::PublicKey::for_network(network, PublicKey(inner.public));
        Ok(Keypair {
            network,
            public_key,
            inner,
        })
    }

    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut result = [0u8; KEYPAIR_LENGTH];
        self.bytes_into(&mut result);
        result
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
        Ok(Signature(self.inner.sign(msg)))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        signature::Signature::from_bytes(input)
            .map(Signature)
            .map_err(Error::from)
    }
}

impl public_key::Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> std::result::Result<(), Error> {
        use ed25519_dalek::Verifier;
        let signature = Signature::try_from(signature)?;
        Verifier::<ed25519_dalek::Signature>::verify(&self.0, msg, &signature.0)
            .map_err(Error::from)
    }
}

impl IntoBytes for PublicKey {
    fn bytes_into(&self, output: &mut [u8]) {
        output.copy_from_slice(self.as_ref())
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        Ok(PublicKey(ed25519_dalek::PublicKey::from_bytes(
            &input[1..],
        )?))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::Keypair;
    use crate::{Network, Sign, Verify};
    use hex_literal::hex;
    use std::convert::TryFrom;

    #[test]
    fn seed() {
        const ENTROPY: [u8; 32] = [
            248, 55, 78, 168, 99, 123, 22, 203, 36, 250, 136, 86, 110, 119, 198, 170, 248, 55, 78,
            168, 99, 123, 22, 203, 36, 250, 136, 86, 110, 119, 198, 170,
        ];
        let keypair = Keypair::generate_from_entropy(Network::MainNet, &ENTROPY).expect("keypair");
        assert_eq!(
            "14MRZY2jc2ABDq1faCCMmXrkm2PXY9UBRTP1j9PWnFTKnCb7Hyn",
            keypair.public_key.to_string()
        );
    }

    #[test]
    fn sign_roundtrip() {
        use rand::rngs::OsRng;
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
        let bytes = keypair.to_bytes();
        assert_eq!(
            keypair,
            super::Keypair::try_from(&bytes[..]).expect("keypair")
        );
        assert_eq!(keypair.public_key.network, Network::MainNet);
        // Testnet
        let keypair = Keypair::generate(Network::TestNet, &mut OsRng);
        let bytes = keypair.to_bytes();
        assert_eq!(
            keypair,
            super::Keypair::try_from(&bytes[..]).expect("keypair")
        );
        assert_eq!(keypair.public_key.network, Network::TestNet);
    }

    #[test]
    fn verify() {
        // Test a msg signed and verified with a keypair generated with erlang libp2p_crypto
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "13WvV82S7QN3VMzMSieiGxvuaPKknMtf213E5JwPnboDkUfesKw";
        const SIG: &[u8] =
            &hex!("ef3e85dc7ea338c6b67399873131ea7b2265c516222e105fc39a59dda71f668a3b95fe27457d941a3cf5c422c9efbf0da112171d2997d74bc68f7b8118c6930e");

        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        assert!(public_key.verify(MSG, SIG).is_ok());
    }

    #[test]
    fn b58_roundtrip_ecc() {
        const B58: &str = "14HZVR4bdF9QMowYxWrumcFBNfWnhDdD5XXA5za1fWwUhHxxFS1";
        let decoded: crate::PublicKey = B58.parse().expect("b58 key");
        assert_eq!(B58, decoded.to_string());
    }
}
