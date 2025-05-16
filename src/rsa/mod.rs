use crate::{public_key, Error, KeyTag, KeyType, Network, ReadFrom, Result, Sign, Verify, WriteTo};
use ::rsa::{PrivateKeyEncoding, PublicKey as _, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::{
    convert::TryFrom,
    fmt,
    hash::{Hash, Hasher},
};

#[derive(Debug, Clone)]
pub struct PublicKey(pub(crate) RSAPublicKey);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature(pub(crate) Vec<u8>);

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    secret: RSAPrivateKey,
}

impl PartialEq for Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network && self.public_key == other.public_key
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        f.debug_struct("Keypair")
            .field("tag", &self.key_tag())
            .field("public", &self.public_key)
            .finish()
    }
}

const PADDING_SCHEME: ::rsa::PaddingScheme = ::rsa::PaddingScheme::PKCS1v15Sign {
    hash: Some(::rsa::hash::Hash::SHA2_256),
};

impl Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(msg);
        let signature = self.secret.sign(PADDING_SCHEME, &digest)?;
        Ok(signature)
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = Error;
    fn try_from(input: &[u8]) -> Result<Self> {
        let network = Network::try_from(input[0])?;
        let secret = ::rsa::RSAPrivateKey::from_pkcs8(&input[1..])?;
        let public_key =
            public_key::PublicKey::for_network(network, PublicKey(secret.to_public_key()));
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
        let document = self.secret.to_pkcs8().map_err(std::io::Error::other)?;
        output.write_all(&document)
    }
}

impl Keypair {
    pub fn generate<R>(network: Network, csprng: &mut R) -> Keypair
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        // This is ok to unwrap because we know the size of the key and the
        // library only returns an error when bits < 64
        let secret = ::rsa::RSAPrivateKey::new(csprng, 2048).expect("key generation");
        let public_key = secret.to_public_key();
        Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, PublicKey(public_key)),
            secret,
        }
    }

    pub fn generate_from_entropy(network: Network, entropy: &[u8]) -> Result<Keypair> {
        let secret = ::rsa::RSAPrivateKey::from_pkcs8(entropy)?;
        let public_key =
            public_key::PublicKey::for_network(network, PublicKey(secret.to_public_key()));
        Ok(Keypair {
            network,
            public_key,
            secret,
        })
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut result = Vec::new();
        self.write_to(&mut std::io::Cursor::new(&mut result))
            .unwrap();
        result
    }

    pub fn key_tag(&self) -> KeyTag {
        KeyTag {
            network: self.network,
            key_type: KeyType::Rsa,
        }
    }

    pub fn secret_to_vec(&self) -> Vec<u8> {
        self.secret.to_pkcs8().expect("pkcs8 encoding").to_vec()
    }
}

impl Signature {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.n().cmp(other.0.n())
    }
}

impl Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        use sha2::Digest;
        let hashed = sha2::Sha256::digest(msg);
        self.0.verify(PADDING_SCHEME, &hashed, signature)?;
        Ok(())
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;
    fn try_from(input: &[u8]) -> Result<Self> {
        let mut input = std::io::Cursor::new(&input[1..]);
        Self::read_from(&mut input)
    }
}

impl WriteTo for PublicKey {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        let n_bytes = self.0.n().to_bytes_be();
        let e_bytes = self.0.e().to_bytes_be();

        output.write_u16::<BigEndian>((n_bytes.len() + e_bytes.len()) as u16)?;
        output.write_u16::<BigEndian>(n_bytes.len() as u16)?;
        output.write_all(n_bytes.as_slice())?;
        output.write_all(e_bytes.as_slice())
    }
}

impl ReadFrom for PublicKey {
    fn read_from<R: std::io::Read>(input: &mut R) -> Result<Self> {
        let buf_size = input.read_u16::<BigEndian>()?;
        let n_size = input.read_u16::<BigEndian>()?;

        let mut buf = vec![0u8; buf_size as usize];
        input.read_exact(&mut buf)?;
        let (n_buf, e_buf) = buf.split_at(n_size as usize);

        let n = rsa::BigUint::from_bytes_be(n_buf);
        let e = rsa::BigUint::from_bytes_be(e_buf);
        let public_key = RSAPublicKey::new(n, e)?;
        Ok(PublicKey(public_key))
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.n().hash(state);
        self.0.e().hash(state);
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PublicKey {
    pub fn public_key_size(&self) -> usize {
        self.0.n().to_bytes_be().len() + self.0.e().to_bytes_be().len() + 5
    }
}

#[cfg(test)]
mod tests {
    use super::{Keypair, TryFrom};
    use crate::{Network, Sign, Verify};
    use hex_literal::hex;
    use rand::rngs::OsRng;

    #[test]
    fn sign_roundtrip() {
        let keypair = Keypair::generate(Network::MainNet, &mut OsRng);
        let signature = keypair.sign(b"hello world").expect("signature");
        keypair
            .public_key
            .verify(b"hello world", &signature)
            .expect("roundtrip signatures should always verify");
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
        // Test a msg signed and verified with an external rsa library
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "1trSusebcQv2kJfLEUV1D4RQyHZyTfFkvFxWBUa1iv53eZKhyg1iDWGsWo89w8HzQBx3vzoeB85aDYK9w2oX1LdWdnrq5QL4M8iGDDacdp5FeSvXTwr6RB9Hv86qQSFT3ppdTSk6Jbe8eDK81NcNNrkhRXqfmH3CAHRCmrKwLcNBLzxo2a8hqQi1rsW8z9dJgWKMsx2cWoboaGgqrfsRC54WJuPWZwkRCmP7dHArxyWqibicaicBoq5yqW3QsTvxTXLHMUVXr59BQriu75QFiztCYiFjq13Qp6kVkFdXwZ5S2cSVZSsg9d1uB4eN3VK4wYefKFnR9qQT5S93CFFX9nXQx7wi5Z6MdAj1mmu6yZczCE";
        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        assert_eq!(PUBKEY, public_key.to_string());
        const SIG: &[u8] =
            &hex!("315050906cd1d58e056e6d9cd0311621a3ad04a60f4b778803c53da335be8239592420cd1910b91fee50fca6d030150356bf86bbe7066b5476da5016f988ec58c1d25fe1d50651de839c897d8e07eb2612e77f44abceef14d40a3358aa93498cd0361516ea29684f94001ea1800beae9cb5a701b371bcbd556b26a125f8fe4b7e9fd4395f5ad1bc80f48c0d40de56d14b2cd2fe109b4ba9cd26fe06dd79d2c236364448873b6a0aeccff87dba44db49b3fb2adb9274c09480e4ee9f281b92314c0fd375e862d349f32f2479775e60c98e11fefc6d99908238862640f356aaa755922dc7932433c4a1ab256c114255651f6b17b3076e6b06b0b79093a7409f03b");
        public_key
            .verify(MSG, SIG)
            .expect("precomputed signature should always verify");
    }

    #[test]
    #[should_panic]
    fn verify_invalid_sig() {
        // Test a msg signed and verified with a keypair generated with erlang crypto
        // and compressed by hand but with a truncated signature
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "1trSusebcQv2kJfLEUV1D4RQyHZyTfFkvFxWBUa1iv53eZKhyg1iDWGsWo89w8HzQBx3vzoeB85aDYK9w2oX1LdWdnrq5QL4M8iGDDacdp5FeSvXTwr6RB9Hv86qQSFT3ppdTSk6Jbe8eDK81NcNNrkhRXqfmH3CAHRCmrKwLcNBLzxo2a8hqQi1rsW8z9dJgWKMsx2cWoboaGgqrfsRC54WJuPWZwkRCmP7dHArxyWqibicaicBoq5yqW3QsTvxTXLHMUVXr59BQriu75QFiztCYiFjq13Qp6kVkFdXwZ5S2cSVZSsg9d1uB4eN3VK4wYefKFnR9qQT5S93CFFX9nXQx7wi5Z6MdAj1mmu6yZczCE";
        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        const SIG: &[u8] = &hex!("3045022100b72de78c39ecdb7db78429362bcdea509cd414");
        public_key
            .verify(MSG, SIG)
            .expect("precomputed signature should always verify");
    }

    #[test]
    fn b58_roundtrip() {
        const B58: &str = "1trSusePJgLdAaRpW3zM9wdWy2AT7ULPAApnvaw1TZZ9KgmYNtkkCv6JP4sGezNJ2PxyzLEgL83FtTk547osJTJU9NYnYwH4wchHV8ndXFDb2ZBXrSn2uuhzKMA47iXVcBzayxZgotZxqd8WJnLHYRQmSf4sxF5DfG8kQSBWGFdKLZTPzVoGiZTfaeTVcjrA5Fb91NBeY7A4W7CeyjmtF6dHDsP7PqmfgYPb6dcFo289eaZ6aeJTonWAnAx1n9ncbSaeBsyXHj8qTa5fvyimLdLfn97BsHb3vTH5ZDGna9FWad9UCi9C1MBFbPYtYURtHR1St2e7VrP9t1CvDYDR9cWYxwyof5BkoEnQ9oV6t6S3ku";
        let decoded: crate::PublicKey = B58.parse().expect("b58 public key");
        assert_eq!(B58, decoded.to_string());
    }
}
