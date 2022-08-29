use crate::tpm::Error::{BadKeyType, Other};
use p256::ecdsa;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use tss_esapi::handles::TpmHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    EccParameter, EccPoint, HashScheme, MaxBuffer, Public, Signature, SignatureScheme,
};
use tss_esapi::{handles::KeyHandle, Context, TctiNameConf};

pub type Result<T = ()> = std::result::Result<T, crate::tpm::Error>;

pub fn public_key(key_handle: u32) -> Result<Vec<u8>> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0").expect("Error parsing TEST_TCTI");
    let mut context = Context::new(tcti).unwrap();
    let key_handle = context.tr_from_tpm_public(TpmHandle::try_from(key_handle)?)?;

    let (object_public, _, _) = context.read_public(KeyHandle::from(key_handle))?;

    let (x, y) = match object_public {
        Public::Ecc { unique, .. } => (unique.x().to_vec(), unique.y().to_vec()),
        _ => Err(BadKeyType())?,
    };

    let mut key_bytes = Vec::new();
    key_bytes.extend_from_slice(x.as_slice());
    key_bytes.extend_from_slice(y.as_slice());

    Ok(key_bytes)
}

pub fn ecdh(x: &[u8], y: &[u8], key_handle: u32) -> Result<Vec<u8>> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0").expect("Error parsing TEST_TCTI");
    let mut context = Context::new(tcti).unwrap();
    let key_handle = context.tr_from_tpm_public(TpmHandle::try_from(key_handle)?)?;

    let raw_point = EccPoint::new(EccParameter::try_from(x)?, EccParameter::try_from(y)?);
    let point = context
        .execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
            ctx.ecdh_z_gen(KeyHandle::from(key_handle), raw_point)
        })?;

    let mut shared_secret_bytes = Vec::new();
    shared_secret_bytes.extend_from_slice(point.x().as_slice());
    shared_secret_bytes.extend_from_slice(point.y().as_slice());

    Ok(shared_secret_bytes)
}

pub fn sign(key_handle: u32, msg: &[u8]) -> Result<ecdsa::Signature> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0").expect("Error parsing TEST_TCTI");
    let mut context = Context::new(tcti).unwrap();
    let key_handle = context.tr_from_tpm_public(TpmHandle::try_from(key_handle)?)?;

    let (digest, hashcheck_ticket) = context.hash(
        MaxBuffer::try_from(msg)?,
        HashingAlgorithm::Sha256,
        Hierarchy::Owner,
    )?;

    let signature_scheme = SignatureScheme::EcDsa {
        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
    };

    let raw_signature =
        context.execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
            ctx.sign(
                KeyHandle::from(key_handle),
                digest.clone(),
                signature_scheme,
                hashcheck_ticket,
            )
        })?;

    let signature = match raw_signature {
        Signature::EcDsa(sig) => {
            let array_s: [u8; 32] = sig.signature_s().to_vec().try_into().unwrap();
            let array_r: [u8; 32] = sig.signature_r().to_vec().try_into().unwrap();
            ecdsa::Signature::from_scalars(array_r, array_s).map_err(|e| Other(e.to_string()))
        }
        _ => Err(BadKeyType()),
    }?;

    Ok(signature)
}
