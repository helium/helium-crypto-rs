use thiserror::Error;
pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("decode error")]
    Decode(#[from] DecodeError),
    #[error("elliptic_curve error")]
    EccCompact(p256::elliptic_curve::Error),
    #[error("signature error")]
    Signature(#[from] signature::Error),

    #[cfg(feature = "ecc608")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecc608")))]
    #[error("ecc608 error")]
    Ecc608(#[from] ecc608_linux::Error),
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
    #[error("missing type byte")]
    MissingType,
}

impl From<bs58::decode::Error> for Error {
    fn from(v: bs58::decode::Error) -> Self {
        Self::from(DecodeError::from(v))
    }
}

// Required since the standard thiserror implementation and the way p256 does
// errors does not match all the required traits
impl From<p256::elliptic_curve::Error> for Error {
    fn from(v: p256::elliptic_curve::Error) -> Self {
        Self::EccCompact(v)
    }
}

impl Error {
    pub fn invalid_keytype(v: u8) -> Error {
        Error::Decode(DecodeError::Type(v))
    }

    pub fn invalid_keytype_str(v: &str) -> Error {
        Error::Decode(DecodeError::TypeString(v.to_string()))
    }

    pub fn not_compact() -> Error {
        Error::Decode(DecodeError::NotCompact)
    }

    pub fn missing_keytype() -> Error {
        Error::Decode(DecodeError::MissingType)
    }
}
