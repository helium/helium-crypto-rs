use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use k256::{ecdsa, elliptic_curve::sec1::ToEncodedPoint};
use std::hash::Hasher;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct PublicKey(k256::PublicKey);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature(ecdsa::Signature);

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    secret: ecdsa::SigningKey,
}

// Network/type byte plus 32 bytes of secret scalar.
pub const KEYPAIR_LENGTH: usize = 33;
// Network/type byte plus even/odd byte plus 32 bytes of X coordinate.
pub const PUBLIC_KEY_LENGTH: usize = 34;

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

impl Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.to_vec())
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = super::error::Error;
    fn try_from(input: &[u8]) -> Result<Self> {
        let network = Network::try_from(input[0])?;
        let secret = k256::SecretKey::from_be_bytes(&input[1..])?;
        let public_key =
            public_key::PublicKey::for_network(network, PublicKey(secret.public_key()));
        Ok(Keypair {
            network,
            public_key,
            secret: k256::ecdsa::SigningKey::from(secret),
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
        let secret = k256::SecretKey::random(&mut *csprng);
        let public_key = secret.public_key();
        Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, PublicKey(public_key)),
            secret: k256::ecdsa::SigningKey::from(secret),
        }
    }

    pub fn generate_from_entropy(network: Network, entropy: &[u8]) -> Result<Keypair> {
        let secret = k256::SecretKey::from_be_bytes(entropy)?;
        let public_key = secret.public_key();
        Ok(Keypair {
            network,
            public_key: public_key::PublicKey::for_network(network, PublicKey(public_key)),
            secret: k256::ecdsa::SigningKey::from(secret),
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
            key_type: KeyType::Secp256k1,
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
    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Signature(signature::Signature::from_bytes(bytes)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_der().as_bytes().to_vec()
    }
}

impl PublicKeySize for PublicKey {
    const PUBLIC_KEY_SIZE: usize = PUBLIC_KEY_LENGTH;
}

impl Eq for PublicKey {}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        use signature::Verifier;
        let signature = ecdsa::Signature::from_der(signature).map_err(super::error::Error::from)?;
        Ok(k256::ecdsa::VerifyingKey::from(self.0).verify(msg, &signature)?)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = super::error::Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        // Assume this is a compressed key we've encoded before. Strip off the
        // network/type tag and attempt to decode the encoded point
        let encoded_point = k256::EncodedPoint::from_bytes(&input[1..])
            .map_err(|e| Error::Sec1Decoding(e.to_string()))?;
        // If the encoded point did not projected onto the k256 curve, this unwrap would fail
        // Since we continue to assume we were the previous encoder, we unwrap instead of dealing
        // with the CtOption
        let public_key = k256::PublicKey::from_encoded_point(&encoded_point).unwrap();
        Ok(PublicKey(public_key))
    }
}

impl WriteTo for PublicKey {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        let encoded = self.0.as_affine().to_encoded_point(true);
        output.write_all(encoded.as_bytes())
    }
}

impl ReadFrom for PublicKey {
    fn read_from<R: std::io::Read>(input: &mut R) -> Result<Self> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        let mut buf = [0u8; PUBLIC_KEY_LENGTH - 1];
        input.read_exact(&mut buf)?;
        match k256::EncodedPoint::from_bytes(k256::FieldBytes::from_slice(&buf)).into() {
            Some(Ok(point)) => Ok(PublicKey(
                // If the encoded point did not projected onto the k256 curve, this unwrap would fail
                k256::PublicKey::from_encoded_point(&point).unwrap(),
            )),
            _ => Err(Error::InvalidEncodedPoint.into()),
        }
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let encoded = self.0.as_affine().to_encoded_point(false);
        state.write(encoded.as_bytes())
    }
}

const TOTAL_PEM_LEN: usize = 88;
const PEM_HEADER_LEN: usize = 23;
const LEADING_PEM_BYTES: [u8; PEM_HEADER_LEN] = [
    48, 86, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 10, 3, 66, 0,
];

impl PublicKey {
    pub fn from_pem_str(pem_str: &str) -> Result<super::PublicKey> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        let iterator = pem_str.lines();
        let mut collect = String::new();
        // collect the base64 from the PEM by stripping away the BEGIN and END markers
        for line in iterator {
            if line != "-----BEGIN PUBLIC KEY-----" && line != "-----END PUBLIC KEY-----" {
                collect.push_str(line);
            }
        }
        let bytes = STANDARD
            .decode(&collect)
            .map_err(|e| super::Error::Secp256k1(Error::Base64Decode(e)))?;
        // all PEM encodings should be the same length
        if bytes.len() != TOTAL_PEM_LEN {
            return Err(Error::UnexpectedAmountOfBytesInPem(bytes.len()).into());
        }
        // the first bytes in the PEM should always be the same
        if bytes[..PEM_HEADER_LEN] != LEADING_PEM_BYTES {
            return Err(Error::UnexpectedLeadingBytesForPemDecode(
                bytes[..PEM_HEADER_LEN].to_vec(),
            )
            .into());
        }

        let uncompressed_encoded_point = &bytes[PEM_HEADER_LEN..];
        let encoded_point = k256::EncodedPoint::from_bytes(uncompressed_encoded_point).unwrap();
        let inner = super::public_key::PublicKeyRepr::Secp256k1(PublicKey(
            k256::PublicKey::from_encoded_point(&encoded_point).unwrap(),
        ));
        Ok(public_key::PublicKey {
            inner,
            network: Network::MainNet,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    // sec1::error::Error is not public when using the k256 crate.
    // It does convert into k256::elliptic_curve::Error.
    // However, k256::elliptic_curve::Error does not impl std::error::Error
    // So map_err into a string is the workaround here.
    #[error("sec1 decoding error curve error")]
    Sec1Decoding(String),
    #[error("invalid encoded point")]
    InvalidEncodedPoint,
    #[error("unexpected amount of bytes while decoding pem. expected: {LEADING_PEM_BYTES:?}, got: {0:?}")]
    UnexpectedAmountOfBytesInPem(usize),
    #[error(
        "unexpected leading bytes while decoding pem. expected: {LEADING_PEM_BYTES:?}, got: {0:?}"
    )]
    UnexpectedLeadingBytesForPemDecode(Vec<u8>),
    #[error("base64 decode: {0}")]
    Base64Decode(#[from] base64::DecodeError),
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
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
        // Test a msg signed and verified with a keypair generated with erlang crypto
        // and compressed by hand.
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "1SpLY6fic4fGthLGjeAUdLVNVYk1gJGrWTGhsukm2dnELaSEQmhL";
        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        const SIG: &[u8] =
            &hex!("3045022100b72de78c39ecdb7db78429362bcdea509cd414dc75c84303d8b7128d864600d002204b857cc29ab999b2b7df9c8c2ab25678787d5632c6aa98227b444aaa9b42df3b");
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
        const PUBKEY: &str = "1SpLY6fic4fGthLGjeAUdLVNVYk1gJGrWTGhsukm2dnELaSEQmhL";
        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        const SIG: &[u8] = &hex!("3045022100b72de78c39ecdb7db78429362bcdea509cd414");
        public_key
            .verify(MSG, SIG)
            .expect("precomputed signature should always verify");
    }

    #[test]
    #[ignore]
    // Test to be skipped until BIP-0062 adjustments to k256 ECDSA are removed
    // from elliptic-curves library.
    fn verify_high_s() {
        // Test a msg signed and verified with a keypair generated with erlang crypto
        // and compressed by hand.
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "1SpLY6fic4fGthLGjeAUdLVNVYk1gJGrWTGhsukm2dnELaSEQmhL";
        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        const SIG: &[u8] =
            &hex!("304502205fa60e66389d90894fa65f47cd50eae6486bfcb8c80ae6209a90a380e46343250221008902ac3932100615ad4db3eecb89a86da8bd97eefb357c5226952b7b3c4aa385");
        public_key
            .verify(MSG, SIG)
            .expect("precomputed signature should always verify");
    }

    #[test]
    fn b58_roundtrip() {
        const B58: &str = "1SpLY6fic4fGthLGjeAUdLVNVYk1gJGrWTGhsukm2dnELaSEQmhL";
        let decoded: crate::PublicKey = B58.parse().expect("b58 public key");
        assert_eq!(B58, decoded.to_string());
    }

    #[test]
    fn from_pem_str() {
        const OPENSSL: &str = "\
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEr+4ucvPOloAI+C6A6LkeDWwJjCS/SB+7
WYLNCoSQb8d1oXTQ+gUV0iFuwGP8DT/wW61lR7tXx5VcHn8ellNgog==
-----END PUBLIC KEY-----";
        let public_key = super::PublicKey::from_pem_str(OPENSSL).unwrap();
        assert_eq!(
            "1Sq7gk5sZRQdWKDTVj2QBM8oUHoKx5sGmqEiH2QViMyknd7LBHiN",
            public_key.to_string()
        )
    }

    #[test]
    fn from_another_pem_str() {
        const OPENSSL: &str = "\
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEjcYgVFld11WnxAfVt9FLSe+7AMyO5BWY
Rwe8MMrzdOM0FGQ/mAiOYyfAMpmPvGfx/oQxcRRAZAhhINV1T2fWaA==
-----END PUBLIC KEY-----";
        let public_key = super::PublicKey::from_pem_str(OPENSSL).unwrap();
        assert_eq!(
            "1SpreGBZcPZJA4VC6SPqocBnw2bDUfkr8AkF3x35NmNBLnzAgf3J",
            public_key.to_string()
        )
    }
}
