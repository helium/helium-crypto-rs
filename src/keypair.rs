use crate::{error, public_key::PublicKey};

pub struct Keypair<C> {
    pub public_key: PublicKey,
    pub(crate) inner: C,
}

pub trait Sign {
    fn sign(&self, msg: &[u8]) -> error::Result<Vec<u8>>;
}
