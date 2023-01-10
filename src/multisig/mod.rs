use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use multihash::{Multihash, MultihashDigest};
use std::{
    convert::TryFrom,
    fmt,
    hash::{Hash, Hasher},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("insufficient signatures {0}, expected {1}")]
    InsufficientSignatures(usize, u8),
    #[error("insufficient keys {0}, expected {1}")]
    InsufficientKeys(usize, u8),
    #[error("too many keys {0}, expected {1}")]
    TooManyKeys(usize, u8),
    #[error("not a multisig key")]
    NotMultisig,
    #[error("multihash error")]
    Multihash(multihash::Error),
    #[error("key digest error")]
    KeyDigest,
    #[error("not a multisig member: {0}")]
    NotMember(public_key::PublicKey),
}

impl Error {
    pub fn insufficient_signatures(actual: usize, expected: u8) -> crate::Error {
        Self::InsufficientSignatures(actual, expected).into()
    }

    pub fn insufficient_keys(actual: usize, expected: u8) -> crate::Error {
        Self::InsufficientKeys(actual, expected).into()
    }

    pub fn too_many_keys(actual: usize, expected: u8) -> crate::Error {
        Self::TooManyKeys(actual, expected).into()
    }

    pub fn not_multisig() -> crate::Error {
        Self::NotMultisig.into()
    }

    pub fn multihash(err: multihash::Error) -> crate::Error {
        Self::Multihash(err).into()
    }

    pub fn key_digest() -> crate::Error {
        Self::KeyDigest.into()
    }

    pub fn not_member(public_key: public_key::PublicKey) -> crate::Error {
        Self::NotMember(public_key).into()
    }
}

#[derive(Clone, Eq)]
pub struct PublicKey {
    pub(crate) m: u8,
    pub(crate) n: u8,
    pub(crate) keys_digest: Vec<u8>,
}

pub const PUBLIC_KEY_LENGTH: usize = 37;

#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    public_keys: Vec<public_key::PublicKey>,
    key_signatures: Vec<KeySignature>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct KeySignature {
    index: u8,
    signature: Vec<u8>,
}

impl fmt::Debug for KeySignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySignature")
            .field("index", &self.index)
            .field("signature", &STANDARD.encode(&self.signature))
            .finish()
    }
}

impl PublicKey {
    pub fn generate(
        network: Network,
        m: u8,
        hash: multihash::Code,
        public_keys: &[public_key::PublicKey],
    ) -> Result<public_key::PublicKey> {
        let mut public_keys = public_keys.to_owned();
        public_key_sort(&mut public_keys);
        if public_keys.len() > u8::MAX as usize {
            return Err(Error::too_many_keys(public_keys.len(), u8::MAX));
        }
        let n = public_keys.len() as u8;
        let keys_digest = public_key_digest(&network, &public_keys, &hash)?;
        Ok(public_key::PublicKey::for_network(
            network,
            Self { m, n, keys_digest },
        ))
    }
}

impl Signature {
    pub fn new(
        public_key: &public_key::PublicKey,
        keys: &[public_key::PublicKey],
        signatures: &[(public_key::PublicKey, Vec<u8>)],
    ) -> Result<Self> {
        let network = public_key.network;
        let public_key = to_multisig(public_key).ok_or_else(Error::not_multisig)?;
        let mut public_keys = keys.to_owned();
        public_key_sort(&mut public_keys);
        match public_keys.len() {
            l if usize::from(public_key.m) > l => {
                return Err(Error::insufficient_signatures(
                    public_keys.len(),
                    public_key.m,
                ))
            }
            l if usize::from(public_key.n) > l => {
                return Err(Error::insufficient_keys(public_keys.len(), public_key.n))
            }
            l if usize::from(public_key.n) < l => {
                return Err(Error::too_many_keys(public_keys.len(), public_key.n))
            }
            _ => (),
        }
        let hash_type = Multihash::from_bytes(&public_key.keys_digest)
            .and_then(|hash| multihash::Code::try_from(hash.code()))
            .map_err(Error::multihash)?;
        if public_key_digest(&network, &public_keys, &hash_type)? != public_key.keys_digest {
            return Err(Error::key_digest());
        }

        let mut key_signatures = Vec::with_capacity(signatures.len());
        for (public_key, signature) in signatures {
            let key_signature = KeySignature::new(&public_keys, public_key, signature.clone())?;
            key_signatures.push(key_signature);
        }
        key_signature_sort(&mut key_signatures);

        Ok(Self {
            public_keys,
            key_signatures,
        })
    }

    fn from_input<R: std::io::Read>(public_key: &PublicKey, input: &mut R) -> Result<Self> {
        let mut public_keys = Vec::with_capacity(public_key.n.into());
        for _ in 0..public_key.n {
            let public_key = public_key::PublicKey::read_from(input)?;
            if to_multisig(&public_key).is_some() {
                return Err(crate::Error::invalid_keytype(KeyType::MultiSig.into()));
            }
            public_keys.push(public_key);
        }
        let mut key_signatures = Vec::with_capacity(public_key.m.into());
        loop {
            match KeySignature::read_from(input) {
                Ok(key_signature) => key_signatures.push(key_signature),
                Err(crate::Error::Io(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break
                }
                Err(err) => return Err(err),
            }
        }
        key_signature_sort(&mut key_signatures);

        Ok(Self {
            public_keys,
            key_signatures,
        })
    }

    /// Returns the number of key signatures that successfully verified the
    /// given message
    fn verify(&self, msg: &[u8]) -> u8 {
        self.key_signatures
            .iter()
            .filter(|key_signature| {
                let public_key = &self.public_keys[key_signature.index as usize];
                public_key.verify(msg, &key_signature.signature).is_ok()
            })
            .count() as u8
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut data);
        self.write_to(&mut cursor).unwrap();
        data.to_vec()
    }
}

impl KeySignature {
    fn new(
        public_keys: &[public_key::PublicKey],
        public_key: &public_key::PublicKey,
        signature: Vec<u8>,
    ) -> Result<Self> {
        if to_multisig(public_key).is_some() {
            return Err(crate::Error::invalid_keytype(public_key.key_type().into()));
        }
        let index = public_keys
            .iter()
            .position(|k| k == public_key)
            .ok_or_else(|| Error::not_member(public_key.clone()))?;
        Ok(Self {
            index: index as u8,
            signature,
        })
    }
}

fn public_key_digest(
    network: &Network,
    keys: &[public_key::PublicKey],
    hash_type: &multihash::Code,
) -> Result<Vec<u8>> {
    let mut keys_bin = Vec::new();
    for key in keys.iter() {
        if key.network != *network {
            return Err(crate::Error::invalid_network());
        }
        if key.key_type() == KeyType::MultiSig {
            return Err(crate::Error::invalid_keytype(key.key_type().into()));
        }
        keys_bin.extend_from_slice(&key.to_vec());
    }
    Ok(hash_type.digest(&keys_bin).to_bytes())
}

fn public_key_sort(keys: &mut Vec<public_key::PublicKey>) {
    keys.sort_unstable_by_key(|a| a.to_string());
    keys.dedup();
}

fn key_signature_sort(key_signatures: &mut Vec<KeySignature>) {
    key_signatures.sort_unstable();
    key_signatures.dedup();
}

fn to_multisig(public_key: &public_key::PublicKey) -> Option<&PublicKey> {
    match &public_key.inner {
        public_key::PublicKeyRepr::MultiSig(key) => Some(key),
        _ => None,
    }
}

impl PublicKeySize for PublicKey {
    const PUBLIC_KEY_SIZE: usize = PUBLIC_KEY_LENGTH;
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.keys_digest.as_ref()
    }
}

impl WriteTo for PublicKey {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        output.write_all(&[self.m])?;
        output.write_all(&[self.n])?;
        output.write_all(&self.keys_digest)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.keys_digest == other.keys_digest
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.keys_digest.partial_cmp(&other.keys_digest)
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.keys_digest.cmp(&other.keys_digest)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.as_ref())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("m", &self.m)
            .field("n", &self.n)
            .field("key_digest", &STANDARD.encode(&self.keys_digest))
            .finish()
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = crate::Error;

    fn try_from(input: &[u8]) -> Result<Self> {
        let mut input = std::io::Cursor::new(&input[1..]);
        Self::read_from(&mut input)
    }
}

impl ReadFrom for PublicKey {
    fn read_from<R: std::io::Read>(input: &mut R) -> Result<Self> {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH - 1];
        input.read_exact(&mut buf)?;
        let m = buf[0];
        let n = buf[1];
        let keys_digest = buf[2..].to_vec();
        Ok(Self { m, n, keys_digest })
    }
}

impl public_key::Verify for PublicKey {
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result {
        let mut input = std::io::Cursor::new(signature);
        let signature = Signature::from_input(self, &mut input)?;
        if signature.verify(msg) >= self.m {
            return Ok(());
        }
        Err(signature::Error::new().into())
    }
}

impl WriteTo for KeySignature {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        output.write_all(&[self.index, self.signature.len() as u8])?;
        output.write_all(self.signature.as_ref())
    }
}

impl ReadFrom for KeySignature {
    fn read_from<R: std::io::Read>(input: &mut R) -> Result<Self> {
        let mut buf = [0u8; 2];
        input.read_exact(&mut buf)?;
        let index = buf[0];
        let mut signature = vec![0u8; usize::from(buf[1])];
        input.read_exact(&mut signature)?;
        Ok(Self { index, signature })
    }
}

impl WriteTo for Signature {
    fn write_to<W: std::io::Write>(&self, output: &mut W) -> std::io::Result<()> {
        for public_key in &self.public_keys {
            output.write_all(&public_key.to_vec())?;
        }
        for key_signature in &self.key_signatures {
            key_signature.write_to(output)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, seq::SliceRandom};

    fn gen_keys(n: u8) -> Vec<crate::Keypair> {
        let key_type = [KeyType::EccCompact, KeyType::Ed25519]
            .choose(&mut OsRng)
            .unwrap();
        let key_tag = KeyTag {
            network: Network::MainNet,
            key_type: *key_type,
        };
        (0..n)
            .map(|_| crate::Keypair::generate(key_tag, &mut OsRng))
            .collect()
    }

    fn public_keys(keypairs: &[crate::Keypair]) -> Vec<public_key::PublicKey> {
        keypairs
            .iter()
            .map(|keypair| keypair.public_key().to_owned())
            .collect()
    }

    #[test]
    fn pubkey_bytes_roundtrip() {
        let public_keys = public_keys(&gen_keys(2));

        let pubkey = super::PublicKey::generate(
            Network::MainNet,
            1,
            multihash::Code::Sha2_256,
            &public_keys,
        )
        .expect("multisig pubkey");

        let bytes = pubkey.to_vec();
        assert_eq!(
            pubkey,
            public_key::PublicKey::try_from(&bytes[..]).expect("multisig pubkey")
        );
    }

    #[test]
    fn erlang_interop() {
        // Take two keys generated in the libp2p_crypto multisig implementation
        // and ensure it generates the same multisig key as the erlang side did
        let external_keys: Vec<public_key::PublicKey> = [
            "11MJXxoWFp2bMsqKM6QZin6ync9DQ3fjjFjUrFiRCaKunmBEBhK",
            "11x7jP9yAnyk5jeYywmsYDFdYq5xvKLKjP2zjhGzCwDSQtxcUDt",
        ]
        .iter()
        .map(|s| s.parse().expect("public key"))
        .collect();

        let pubkey = super::PublicKey::generate(
            Network::MainNet,
            1,
            multihash::Code::Sha2_256,
            &external_keys,
        )
        .expect("multisig pubkey");
        assert_eq!(
            "1SVRdbaAev7zSpUsMjvQrbRBGFHLXEa63SGntYCqChC4CTpqwftTPGbZ",
            pubkey.to_string()
        );
    }

    #[test]
    fn sign_test() {
        let keys = gen_keys(3);
        let public_keys = public_keys(&keys);
        const MSG: &[u8] = b"hello world";

        assert_eq!(3, public_keys.len());
        let pubkey = super::PublicKey::generate(
            Network::MainNet,
            2,
            multihash::Code::Sha2_256,
            &public_keys,
        )
        .expect("multisig pubkey");

        let signatures: Vec<(public_key::PublicKey, Vec<u8>)> = keys[0..2]
            .iter()
            .map(|key| {
                (
                    key.public_key().to_owned(),
                    key.sign(MSG).expect("signature"),
                )
            })
            .collect();
        assert_eq!(2, signatures.len());

        let signature = Signature::new(&pubkey, &public_keys, &signatures).expect("signature");

        pubkey
            .verify(MSG, &signature.to_vec())
            .expect("verify success");
    }
}
