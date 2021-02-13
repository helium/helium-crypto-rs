use crate::{error, public_key, Network};

/// Defines a trait for signing messages. Rather than the signature::Signer
/// trait which deals with exact signature sizes, this trait allows for variable
/// sized signatures, since the ECDSA signature is DER encoded.
pub trait Sign {
    /// Sign the given message
    fn sign(&self, msg: &[u8]) -> error::Result<Vec<u8>>;
}

/// Abstract keypair definition
pub struct Keypair<C> {
    /// The network this keypair is valid for
    pub network: Network,
    /// The public key for this keypair
    pub public_key: public_key::PublicKey,
    pub(crate) inner: C,
}

impl<C> PartialEq for Keypair<C> {
    fn eq(&self, other: &Self) -> bool {
        self.network == other.network && self.public_key == other.public_key
    }
}

impl<C> std::fmt::Debug for Keypair<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("network", &self.network)
            .field("public", &self.public_key)
            .finish()
    }
}
