use crate::{error, keypair, public_key, FromBytes, IntoBytes};

pub type PublicKey = ed25519_dalek::PublicKey;
pub type Signature = ed25519_dalek::Signature;
pub type Keypair = keypair::Keypair<ed25519_dalek::Keypair>;

pub fn generate<R>(csprng: &mut R) -> Keypair
where
    R: rand_core::CryptoRng + rand_core::RngCore,
{
    let secret_key = ed25519_dalek::Keypair::generate(csprng);
    let public_key = secret_key.public;
    Keypair {
        inner: secret_key,
        public_key: public_key::PublicKey::Ed25519(public_key),
    }
}

impl keypair::Sign for Keypair {
    fn sign(&self, msg: &[u8]) -> error::Result<Vec<u8>> {
        use signature::Signer;
        let signature = self.try_sign(msg)?;
        Ok(signature.as_ref().to_vec())
    }
}

impl signature::Signer<Signature> for Keypair {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Signature, signature::Error> {
        Ok(self.inner.sign(msg))
    }
}

impl FromBytes for Signature {
    fn from_bytes(input: &[u8]) -> error::Result<Self> {
        signature::Signature::from_bytes(input).map_err(error::Error::from)
    }
}

impl public_key::Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> std::result::Result<(), error::Error> {
        use ed25519_dalek::Verifier;
        let signature = Signature::from_bytes(signature)?;
        Verifier::<Signature>::verify(self, msg, &signature).map_err(error::Error::from)
    }
}

impl IntoBytes for PublicKey {
    fn into_bytes(&self, output: &mut [u8]) {
        output.copy_from_slice(self.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Sign, Verify};
    use hex_literal::hex;

    #[test]
    fn sign_roundtrip() {
        use rand::rngs::OsRng;
        let keypair = super::generate(&mut OsRng);
        let signature = keypair.sign(b"hello world").expect("signature");
        assert!(keypair
            .public_key
            .verify(b"hello world", &signature)
            .is_ok())
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
    fn b58_roundtrip() {
        const B58: &str = "14HZVR4bdF9QMowYxWrumcFBNfWnhDdD5XXA5za1fWwUhHxxFS1";
        let decoded: crate::PublicKey = B58.parse().expect("b58 key");
        assert_eq!(B58, decoded.to_string());
    }
}
