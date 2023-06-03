use thiserror::Error;

pub type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("decode error")]
    Decode(#[from] DecodeError),
    #[error("elliptic_curve error")]
    EccCompact(p256::elliptic_curve::Error),
    #[error("ed25519 error")]
    Ed25519(#[from] ed25519_compact::Error),
    #[error("signature error")]
    Signature(#[from] signature::Error),
    #[error("invalid curve error")]
    InvalidCurve,
    #[error("invalid network")]
    InvalidNetwork,
    #[error("io error")]
    Io(std::io::Error),

    #[cfg(feature = "ecc608")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ecc608")))]
    #[error("ecc608 error")]
    Ecc608(#[from] ecc608_linux::Error),

    #[cfg(feature = "multisig")]
    #[cfg_attr(docsrs, doc(cfg(feature = "multisig")))]
    #[error("multisig error")]
    MultiSig(#[from] crate::multisig::Error),

    #[cfg(feature = "tpm")]
    #[cfg_attr(docsrs, doc(cfg(feature = "tpm")))]
    #[error("TPM error")]
    TPM(#[from] crate::tpm::Error),

    #[error("secp256k1 error")]
    Secp256k1(#[from] crate::secp256k1::Error),

    #[cfg(feature = "rsa")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rsa")))]
    #[error("rsa error")]
    Rsa(#[from] ::rsa::Error),
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
    #[error("unsupported {0}")]
    Unsupported(&'static str),
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

impl From<std::io::Error> for Error {
    fn from(v: std::io::Error) -> Self {
        Self::Io(v)
    }
}

impl Error {
    pub fn invalid_curve() -> Error {
        Error::InvalidCurve
    }

    pub fn invalid_network() -> Error {
        Error::InvalidNetwork
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

    pub fn missing_keytype() -> Error {
        Error::Decode(DecodeError::MissingType)
    }
}
