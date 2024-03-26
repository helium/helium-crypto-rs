use crate::*;
use std::hash::Hasher;

#[derive(Debug, Clone)]
pub struct PublicKey(pub(crate) ed25519_compact::PublicKey);

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Signature(ed25519_compact::Signature);

pub struct Keypair {
    pub network: Network,
    pub public_key: public_key::PublicKey,
    secret: ed25519_compact::SecretKey,
}

pub const KEYPAIR_LENGTH: usize = ed25519_compact::SecretKey::BYTES + 1;
pub const PUBLIC_KEY_LENGTH: usize = ed25519_compact::PublicKey::BYTES + 1;

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
        let secret = ed25519_compact::SecretKey::from_slice(
            &input[1..usize::min(input.len(), KEYPAIR_LENGTH)],
        )?;
        let public_key =
            public_key::PublicKey::for_network(network, PublicKey(secret.public_key()));
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
        output.write_all(self.secret.as_ref())
    }
}

impl Keypair {
    pub fn generate<R>(network: Network, csprng: &mut R) -> Keypair
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        let mut seed = [0u8; ed25519_compact::Seed::BYTES];
        csprng.fill_bytes(&mut seed);
        let keypair = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed));
        let public_key = public_key::PublicKey::for_network(network, PublicKey(keypair.pk));
        Keypair {
            network,
            public_key,
            secret: keypair.sk,
        }
    }

    pub fn generate_from_entropy(network: Network, entropy: &[u8]) -> Result<Keypair> {
        let seed = ed25519_compact::Seed::from_slice(entropy)?;
        let keypair = ed25519_compact::KeyPair::from_seed(seed);
        let public_key = public_key::PublicKey::for_network(network, PublicKey(keypair.pk));
        Ok(Keypair {
            network,
            public_key,
            secret: keypair.sk,
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
        self.secret.seed().to_vec()
    }
}

impl signature::Signature for Signature {
    fn from_bytes(input: &[u8]) -> std::result::Result<Self, signature::Error> {
        Ok(Signature(
            ed25519_compact::Signature::from_slice(input)
                .map_err(|_| signature::Error::default())?,
        ))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
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
        let noise = ed25519_compact::Noise::generate();
        Ok(Signature(self.secret.sign(msg, Some(noise))))
    }
}

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Signature(ed25519_compact::Signature::from_slice(bytes)?))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        ed25519_compact::Signature::from_slice(input)
            .map(Signature)
            .map_err(Error::from)
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

impl public_key::Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        if signature.len() != ed25519_compact::Signature::BYTES {
            return Err(ed25519_compact::Error::InvalidSignature.into());
        }
        let signature = Signature::try_from(signature)?;
        self.0.verify(msg, &signature.0).map_err(Error::from)
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
        Ok(PublicKey(ed25519_compact::PublicKey::new(buf)))
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

    // The first 32 bytes are entropy.
    // The following 32 bytes are the pubkey.
    const BYTES: [u8; 64] = [
        248, 55, 78, 168, 99, 123, 22, 203, 36, 250, 136, 86, 110, 119, 198, 170, 248, 55, 78, 168,
        99, 123, 22, 203, 36, 250, 136, 86, 110, 119, 198, 170, 185, 118, 86, 186, 8, 131, 178,
        232, 103, 147, 246, 193, 186, 72, 71, 232, 25, 244, 178, 49, 35, 157, 89, 72, 28, 17, 212,
        63, 72, 54, 42, 9,
    ];

    #[test]
    fn seed() {
        let entropy = &BYTES[..32];
        let keypair = Keypair::generate_from_entropy(Network::MainNet, entropy).expect("keypair");
        assert_eq!(
            "14MRZY2jc2ABDq1faCCMmXrkm2PXY9UBRTP1j9PWnFTKnCb7Hyn",
            keypair.public_key.to_string()
        );
    }

    #[test]
    #[cfg(feature = "solana")]
    fn solana_pubkey() {
        use solana_sdk::signature as solana_sdk;
        use std::convert::TryInto;

        let solana_wallet = solana_sdk::Keypair::from_bytes(&BYTES).unwrap();
        let solana_pubkey = solana_sdk::Signer::pubkey(&solana_wallet);

        let entropy = &BYTES[..32];
        let keypair = Keypair::generate_from_entropy(Network::MainNet, &entropy).expect("keypair");
        let solana_pubkey_from_helium = keypair.public_key.try_into().unwrap();
        assert_eq!(solana_pubkey, solana_pubkey_from_helium);
    }

    #[test]
    fn sign_roundtrip() {
        use rand::rngs::OsRng;
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
        public_key
            .verify(MSG, SIG)
            .expect("precomputed signature should always verify");
    }

    #[test]
    #[should_panic]
    fn verify_invalid_sig() {
        // Test a msg signed and verified with a keypair generated with erlang
        // libp2p_crypto but with a truncated signature
        const MSG: &[u8] = b"hello world";
        const PUBKEY: &str = "13WvV82S7QN3VMzMSieiGxvuaPKknMtf213E5JwPnboDkUfesKw";
        const SIG: &[u8] = &hex!("ef3e85dc7ea338c6b67399873131ea7b2265c51622");

        let public_key: crate::PublicKey = PUBKEY.parse().expect("b58 public key");
        public_key
            .verify(MSG, SIG)
            .expect("precomputed signature should always verify");
    }

    #[test]
    fn b58_roundtrip_ecc() {
        const B58: &str = "14HZVR4bdF9QMowYxWrumcFBNfWnhDdD5XXA5za1fWwUhHxxFS1";
        let decoded: crate::PublicKey = B58.parse().expect("b58 key");
        assert_eq!(B58, decoded.to_string());
    }
}
