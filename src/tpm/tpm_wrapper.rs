use crate::{error, tpm};
use drop_guard::guard;
use lazy_static::lazy_static;
use libc::c_void;
use std::{ffi::CString, mem::MaybeUninit, ptr::null_mut, ptr::NonNull, sync::Mutex};
use tpm::Error as TpmError;
use tss2::{
    Esys_ContextLoad, Esys_ECDH_ZGen, Esys_Finalize, Esys_FlushContext, Esys_Free, Esys_Initialize,
    Esys_ReadPublic, Fapi_Finalize, Fapi_GetEsysBlob, Fapi_GetTcti, Fapi_Initialize, Fapi_Sign,
    Tss2_MU_TPMS_CONTEXT_Unmarshal, ESYS_CONTEXT, ESYS_TR, ESYS_TR_NONE, ESYS_TR_PASSWORD,
    FAPI_CONTEXT, FAPI_ESYSBLOB_CONTEXTLOAD, TPM2B_ECC_POINT, TPM2B_PUBLIC, TPMS_CONTEXT,
    TSS2_RC_SUCCESS, TSS2_TCTI_CONTEXT,
};

pub type Result<T = ()> = std::result::Result<T, error::Error>;

// A wrapper which wraps TSS2 APIs and handles converting the return
// code from an integer to a `Result`.
macro_rules! tss2_call{
    ( $func:ident ( $( $arg:expr ),* $(,)? ) ) => {{
        match $func($($arg),*) {
            TSS2_RC_SUCCESS => Ok(()),
            e => Err(TpmError::TPMError(stringify!($func), e)),
        }
    }};
}

/// An RAII wrapper for FAPI_CONTEXT.
struct FapiContext(NonNull<FAPI_CONTEXT>);

impl FapiContext {
    pub fn new() -> Result<Self> {
        let mut tpm_ctx: *mut FAPI_CONTEXT = null_mut();
        unsafe {
            tss2_call!(Fapi_Initialize(
                &mut tpm_ctx as *mut *mut FAPI_CONTEXT,
                null_mut(),
            ))?;
        };
        Ok(Self(NonNull::new(tpm_ctx).expect("ptr is null")))
    }

    pub unsafe fn as_mut(&mut self) -> *mut FAPI_CONTEXT {
        self.0.as_mut()
    }
}

unsafe impl Send for FapiContext {}

impl Drop for FapiContext {
    fn drop(&mut self) {
        unsafe {
            Fapi_Finalize(&mut self.as_mut());
        }
    }
}

lazy_static! {
    // TODO: figure out an ergonomic way to not panic when
    //       `FapiContext::new()` errors.
    static ref TPM_CTX: Mutex<FapiContext> = Mutex::new(FapiContext::new().unwrap());
}

pub fn public_key(key_path: &str) -> Result<Vec<u8>> {
    unsafe {
        let mut tpm_ctx = TPM_CTX.lock().unwrap();
        let mut esys_key_handle: ESYS_TR = u32::MAX;
        let mut blob_type: u8 = 0;
        let mut esys_blob: *mut u8 = null_mut();
        let mut blob_sz: tss2::size_t = 0;
        let mut offset: tss2::size_t = 0;
        let c_path = CString::new(key_path.as_bytes())
            .map_err(|_| TpmError::BadKeyPath(key_path.to_owned()))?;

        tss2_call!(Fapi_GetEsysBlob(
            tpm_ctx.as_mut(),
            c_path.as_ptr(),
            &mut blob_type as *mut u8,
            &mut esys_blob as *mut *mut u8,
            &mut blob_sz as *mut tss2::size_t,
        ))?;
        let esys_blob = guard(esys_blob, |p| Esys_Free(p as *mut c_void));

        if blob_type != FAPI_ESYSBLOB_CONTEXTLOAD as u8 {
            return Err(TpmError::BadKeyPath(key_path.into()).into());
        }

        let mut key_context: MaybeUninit<TPMS_CONTEXT> = MaybeUninit::uninit();
        tss2_call!(Tss2_MU_TPMS_CONTEXT_Unmarshal(
            *esys_blob,
            blob_sz,
            &mut offset as *mut tss2::size_t,
            key_context.as_mut_ptr(),
        ))?;
        let key_context = key_context.assume_init();

        let mut tcti_ctx: *mut TSS2_TCTI_CONTEXT = null_mut();
        tss2_call!(Fapi_GetTcti(
            tpm_ctx.as_mut(),
            // NOTE: we explicitly do not free this out pointer, as we
            // believe it is part of the context.
            &mut tcti_ctx as *mut *mut TSS2_TCTI_CONTEXT,
        ))?;

        let mut esys_ctx: *mut ESYS_CONTEXT = null_mut();

        tss2_call!(Esys_Initialize(
            &mut esys_ctx as *mut *mut ESYS_CONTEXT,
            tcti_ctx,
            null_mut(),
        ))?;
        let esys_ctx = guard(esys_ctx, |mut p| Esys_Finalize(&mut p));

        tss2_call!(Esys_ContextLoad(
            *esys_ctx,
            &key_context,
            &mut esys_key_handle as *mut ESYS_TR,
        ))?;
        let esys_key_handle = guard(esys_key_handle, |p| {
            Esys_FlushContext(*esys_ctx, p);
        });

        let mut public_part: *mut TPM2B_PUBLIC = null_mut();
        tss2_call!(Esys_ReadPublic(
            *esys_ctx,
            *esys_key_handle,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut public_part as *mut *mut TPM2B_PUBLIC,
            null_mut(),
            null_mut(),
        ))?;
        let public_part = guard(public_part, |p| Esys_Free(p as *mut c_void));

        let ecc_point = (**public_part).publicArea.unique.ecc;
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(&ecc_point.x.buffer.as_slice()[..ecc_point.x.size as usize]);
        key_bytes.extend_from_slice(&ecc_point.y.buffer.as_slice()[..ecc_point.y.size as usize]);

        Ok(key_bytes)
    }
}

pub fn ecdh(x: &[u8], y: &[u8], key_path: &str) -> Result<Vec<u8>> {
    unsafe {
        let mut tpm_ctx = TPM_CTX.lock().unwrap();
        let mut esys_key_handle: ESYS_TR = u32::MAX;
        let mut blob_type: u8 = 0;
        let mut esys_blob: *mut u8 = null_mut();
        let mut blob_sz: tss2::size_t = 0;
        let mut offset: tss2::size_t = 0;
        let c_path = CString::new(key_path.as_bytes())
            .map_err(|_| TpmError::BadKeyPath(key_path.to_string()))?;

        tss2_call!(Fapi_GetEsysBlob(
            tpm_ctx.as_mut(),
            c_path.as_ptr(),
            &mut blob_type as *mut u8,
            &mut esys_blob as *mut *mut u8,
            &mut blob_sz as *mut tss2::size_t,
        ))?;
        let esys_blob = guard(esys_blob, |p| Esys_Free(p as *mut c_void));

        if blob_type != FAPI_ESYSBLOB_CONTEXTLOAD as u8 {
            return Err(TpmError::BadKeyPath(key_path.into()).into());
        }

        let mut key_context: MaybeUninit<TPMS_CONTEXT> = MaybeUninit::uninit();
        tss2_call!(Tss2_MU_TPMS_CONTEXT_Unmarshal(
            *esys_blob,
            blob_sz,
            &mut offset as *mut tss2::size_t,
            key_context.as_mut_ptr(),
        ))?;
        let key_context = key_context.assume_init();

        let mut tcti_ctx: *mut TSS2_TCTI_CONTEXT = null_mut();
        tss2_call!(Fapi_GetTcti(
            tpm_ctx.as_mut(),
            // NOTE: we explicitly do not free this out pointer, as we
            // believe it is part of the context.
            &mut tcti_ctx as *mut *mut TSS2_TCTI_CONTEXT
        ))?;

        let mut esys_ctx: *mut ESYS_CONTEXT = null_mut();
        tss2_call!(Esys_Initialize(
            &mut esys_ctx as *mut *mut ESYS_CONTEXT,
            tcti_ctx,
            null_mut(),
        ))?;
        let esys_ctx = guard(esys_ctx, |mut p| Esys_Finalize(&mut p));

        tss2_call!(Esys_ContextLoad(
            *esys_ctx,
            &key_context,
            &mut esys_key_handle as *mut ESYS_TR,
        ))?;
        let esys_key_handle = guard(esys_key_handle, |p| {
            Esys_FlushContext(*esys_ctx, p);
        });

        let pub_point = {
            let mut p: MaybeUninit<TPM2B_ECC_POINT> = MaybeUninit::zeroed();
            (*p.as_mut_ptr()).point.x.size = x.len() as u16;
            (*p.as_mut_ptr()).point.x.buffer[..x.len()].copy_from_slice(x);
            (*p.as_mut_ptr()).point.y.size = y.len() as u16;
            (*p.as_mut_ptr()).point.y.buffer[..y.len()].copy_from_slice(y);
            (*p.as_mut_ptr()).size = x.len() as u16 + y.len() as u16;
            p.assume_init()
        };

        let mut secret: *mut TPM2B_ECC_POINT = null_mut();

        tss2_call!(Esys_ECDH_ZGen(
            *esys_ctx,
            *esys_key_handle,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &pub_point,
            &mut secret as *mut *mut TPM2B_ECC_POINT,
        ))?;
        let secret = guard(secret, |p| Esys_Free(p as *mut libc::c_void));

        let mut shared_secret_bytes = Vec::new();
        shared_secret_bytes.extend_from_slice(
            &(**secret).point.x.buffer.as_slice()[..(**secret).point.x.size as usize],
        );
        shared_secret_bytes.extend_from_slice(
            &(**secret).point.y.buffer.as_slice()[..(**secret).point.y.size as usize],
        );

        Ok(shared_secret_bytes)
    }
}

pub fn sign(key_path: &str, digest: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut tpm_ctx = TPM_CTX.lock().unwrap();
        let mut raw_signature: *mut u8 = null_mut();
        let mut signature_sz: tss2::size_t = 0;
        let c_path =
            CString::new(key_path.as_bytes()).map_err(|_| TpmError::BadKeyPath(key_path.into()))?;
        tss2_call!(Fapi_Sign(
            tpm_ctx.as_mut(),
            c_path.as_ptr(),
            null_mut(),
            digest.as_ptr(),
            digest.len() as tss2::size_t,
            &mut raw_signature as *mut *mut u8,
            &mut signature_sz as *mut tss2::size_t,
            null_mut(),
            null_mut(),
        ))?;

        let sign_slice = std::slice::from_raw_parts(raw_signature, signature_sz as usize).to_vec();
        Esys_Free(raw_signature as *mut c_void);

        Ok(sign_slice)
    }
}
