use std::convert::TryFrom;
use std::convert::TryInto;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Can't parse key blob: {0}")]
    BadKeyBlob(String),
}

pub enum DigestPadAlgo {
    RsaDigestPaddingNone = 0,
    RsaPkcs115Sha2_256 = 1,
    RsaPssSha2_256 = 2,
}

impl TryFrom<u32> for DigestPadAlgo {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DigestPadAlgo::RsaDigestPaddingNone),
            1 => Ok(DigestPadAlgo::RsaPkcs115Sha2_256),
            2 => Ok(DigestPadAlgo::RsaPssSha2_256),
            _ => Err(Error::BadKeyBlob(format!(
                "Bad digest padding algorithm {}",
                value
            ))),
        }
    }
}

pub struct KeyBlob {
    pub magic_num: u32,
    pub version: u32,
    pub digest_padding: DigestPadAlgo,
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub iv: Vec<u8>,
    pub pvt_exponent: Vec<u8>,
    pub hmac: Vec<u8>,
}

const RSA_KEY_SIZE_MAX: usize = 512 + 16;
const RSA_IV_LENGTH: usize = 16;
const RSA_HMAC_LENGTH: usize = 32;

fn read_u32_le(data: &[u8], start: usize) -> (u32, usize) {
    return (
        u32::from_le_bytes(data[start..start + 4].try_into().unwrap()),
        start.clone() + 4,
    );
}

fn read_u8_array_dynamic(data: &[u8], start: usize, maxsize: usize) -> (Vec<u8>, usize) {
    let size: usize = u32::from_le_bytes(
        data[start + maxsize..start.clone() + maxsize.clone() + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    return (
        data[start..start.clone() + size].to_vec(),
        start.clone() + maxsize.clone() + 4,
    );
}

fn read_u8_array(data: &[u8], start: usize, size: usize) -> (Vec<u8>, usize) {
    return (
        data[start..start.clone() + size].to_vec(),
        start.clone() + size.clone(),
    );
}

impl TryFrom<&[u8]> for KeyBlob {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Error> {
        let start = 0;
        let (magic_num, start) = read_u32_le(value, start);
        let (version, start) = read_u32_le(value, start);
        let (digest_padding, start) = read_u32_le(value, start);
        let digest_padding = DigestPadAlgo::try_from(digest_padding)?;
        let (modulus, start) = read_u8_array_dynamic(value, start, RSA_KEY_SIZE_MAX);
        let (public_exponent, start) = read_u8_array_dynamic(value, start, RSA_KEY_SIZE_MAX);
        let (iv, start) = read_u8_array(value, start, RSA_IV_LENGTH);
        let (pvt_exponent, start) = read_u8_array_dynamic(value, start, RSA_KEY_SIZE_MAX);
        let (hmac, _) = read_u8_array(value, start, RSA_HMAC_LENGTH);

        Ok(KeyBlob {
            magic_num,
            version,
            digest_padding,
            modulus,
            public_exponent,
            iv,
            pvt_exponent,
            hmac,
        })
    }
}
