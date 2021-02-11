use crate::{error, public_key::PublicKey};

pub struct Keypair<C> {
    pub public_key: PublicKey,
    pub(crate) inner: C,
}

impl<C> PartialEq for Keypair<C> {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl<C> std::fmt::Debug for Keypair<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.debug_struct("Keypair")
            .field("public", &self.public_key)
            .finish()
    }
}

pub trait Sign {
    fn sign(&self, msg: &[u8]) -> error::Result<Vec<u8>>;
}
