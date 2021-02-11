use crate::{error, public_key::PublicKey};

#[derive(Debug)]
pub struct Keypair<C> {
    pub public_key: PublicKey,
    pub(crate) inner: C,
}

impl<C> PartialEq for Keypair<C> {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

pub trait Sign {
    fn sign(&self, msg: &[u8]) -> error::Result<Vec<u8>>;
}
