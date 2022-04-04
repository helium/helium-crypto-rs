use crate::*;
use ed25519_consensus::{
    Signature as EdSignature, SigningKey as EdSigningKey, VerificationKey as EdPublicKey,
};
use std::{
    convert::TryFrom,
    hash::{Hash, Hasher},
};

#[derive(Debug, Clone)]
pub struct PublicKey(EdPublicKey);

#[derive(Debug, PartialEq, Clone)]
pub struct Signature([u8; 64]);

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    secret: EdSigningKey,
}

pub const KEYPAIR_LENGTH: usize = 32 + 1;
pub const PUBLIC_KEY_LENGTH: usize = 32 + 1;

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
        let secret = EdSigningKey::try_from(&input[1..usize::min(input.len(), KEYPAIR_LENGTH)])?;
        let public_key = public_key::PublicKey::for_network(network, PublicKey::from(&secret));
        Ok(Keypair {
            network,
            public_key,
            secret,
        })
    }
}

impl WriteTo for Keypair {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        output.write_all(&[u8::from(self.key_tag())])?;
        output.write_all(&self.secret.to_bytes())
    }
}

impl Keypair {
    pub fn generate<R>(network: Network, csprng: &mut R) -> Keypair
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let secret = EdSigningKey::new(csprng);
        let public_key = public_key::PublicKey::for_network(network, PublicKey::from(&secret));
        Keypair {
            network,
            public_key,
            secret,
        }
    }

    pub fn generate_from_entropy(network: Network, entropy: &[u8]) -> Result<Keypair> {
        let secret = EdSigningKey::try_from(entropy)?;
        let public_key = public_key::PublicKey::for_network(network, PublicKey::from(&secret));
        Ok(Keypair {
            network,
            public_key,
            secret,
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = vec![0u8; KEYPAIR_LENGTH];
        self.write_to(&mut std::io::Cursor::new(&mut result))
            .unwrap();
        result
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: KeyType::Ed25519,
        }
    }

    pub fn secret_to_vec(&self) -> Vec<u8> {
        self.secret.to_bytes().to_vec()
    }
}

impl signature::Signature for Signature {
    fn from_bytes(input: &[u8]) -> std::result::Result<Self, signature::Error> {
        Self::try_from(input).map_err(signature::Error::from_source)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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

impl PartialEq for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network && self.public_key == other.public_key
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        Ok(Signature(self.secret.sign(msg).to_bytes()))
    }
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Signature::try_from(bytes)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        if input.len() != 64 {
            return Err(Error::Ed25519(ed25519_consensus::Error::InvalidSliceLength));
        }
        let mut bytes = [0u8; 64];
        bytes[..].copy_from_slice(input);
        Ok(Signature(bytes))
    }
}

impl From<&EdSigningKey> for PublicKey {
    fn from(v: &EdSigningKey) -> Self {
        Self(EdPublicKey::from(v))
    }
}

impl PublicKeySize for PublicKey {
    const PUBLIC_KEY_SIZE: usize = PUBLIC_KEY_LENGTH;
}

impl public_key::Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        let signature = EdSignature::try_from(signature)?;
        self.0.verify(&signature, msg).map_err(Error::from)
    }
}

impl WriteTo for PublicKey {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        output.write_all(self.as_ref())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.as_ref())
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        let mut input = std::io::Cursor::new(&input[1..]);
        Self::read_from(&mut input)
    }
}

impl ReadFrom for PublicKey {
    fn read_from<R: std::io::Read>(input: &mut R) -> Result<Self> {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH - 1];
        input.read_exact(&mut buf)?;
        Ok(PublicKey(EdPublicKey::try_from(buf)?))
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
        let bytes = keypair.to_vec();
        assert_eq!(
            keypair,
            super::Keypair::try_from(&bytes[..]).expect("keypair")
        );
        assert_eq!(keypair.public_key.network, Network::MainNet);
        // Testnet
        let keypair = Keypair::generate(Network::TestNet, &mut OsRng);
        let bytes = keypair.to_vec();
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
