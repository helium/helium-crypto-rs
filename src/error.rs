use p256::elliptic_curve;
use thiserror::Error;
pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("decode error")]
    Decode(#[from] DecodeError),
    #[error("elliptic_curve error")]
    EccCompact(elliptic_curve::Error),
    #[error("signature error")]
    Signature(#[from] signature::Error),
}

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("b58 decode error")]
    B58(#[from] bs58::decode::Error),
    #[error("unrecognized type value {0}")]
    Type(u8),
    #[error("unrecognized type string {0}")]
    TypeString(String),
    #[error("not a compact key")]
    NotCompact,
}

impl From<elliptic_curve::Error> for Error {
    fn from(v: elliptic_curve::Error) -> Self {
        Self::EccCompact(v)
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(v: bs58::decode::Error) -> Self {
        Error::Decode(DecodeError::B58(v))
    }
}

pub fn invalid_keytype(v: u8) -> Error {
    Error::Decode(DecodeError::Type(v))
}

pub fn invalid_keytype_str(v: &str) -> Error {
    Error::Decode(DecodeError::TypeString(v.to_string()))
}

pub fn not_compact() -> Error {
    Error::Decode(DecodeError::NotCompact)
}
