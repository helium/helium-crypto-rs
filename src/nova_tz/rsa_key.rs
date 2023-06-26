use crate::nova_tz::keyblob;
use crate::nova_tz::Error;
use crate::nova_tz::Result;
use dynfmt::{Format, SimpleCurlyFormat};
use std::convert::TryFrom;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub struct RsaKey {
    key_name: String,
    key_blob: keyblob::KeyBlob,
}

impl RsaKey {
    const NOVA_RSA_ADD_PATH: &'static str = "/sys/nova-rsa/add";
    const NOVA_RSA_REMOVE_PATH: &'static str = "/sys/nova-rsa/remove";
    const NOVA_RSA_SIGN_PATH: &'static str = "/sys/nova-rsa/keys/{}/sign";
    const NOVA_RSA_BLOB_PATH: &'static str = "/sys/nova-rsa/keys/{}/key";

    pub fn new(key_path: &str) -> Result<Self> {
        let key_name = Uuid::new_v4().to_string();

        if !Path::new(key_path).exists() {
            return Err(Error::BadKeyPath(key_path.to_string()).into());
        }

        let key_blob_data =
            fs::read(key_path).map_err(|_| Error::BadKeyPath(key_path.to_string()))?;
        let key_blob =
            keyblob::KeyBlob::try_from(key_blob_data.as_ref()).map_err(Error::KeyBlobError)?;

        fs::write(RsaKey::NOVA_RSA_ADD_PATH, &key_name)
            .map_err(|e| Error::QseecomError(e.to_string()))?;
        fs::write(
            SimpleCurlyFormat
                .format(RsaKey::NOVA_RSA_BLOB_PATH, [&key_name])
                .unwrap()
                .to_string(),
            key_blob_data,
        )
        .map_err(|e| Error::QseecomError(e.to_string()))?;

        Ok(RsaKey { key_name, key_blob })
    }

    pub fn public_key(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Ok((
            self.key_blob.modulus.clone(),
            self.key_blob.public_exponent.clone(),
        ))
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sign_path = SimpleCurlyFormat
            .format(RsaKey::NOVA_RSA_SIGN_PATH, [&self.key_name])
            .unwrap()
            .to_string();

        fs::write(&sign_path, msg).map_err(|e| Error::QseecomError(e.to_string()))?;
        let signed = fs::read(&sign_path).map_err(|e| Error::QseecomError(e.to_string()))?;
        Ok(signed)
    }

    fn remove_key(&self) -> Result {
        fs::write(RsaKey::NOVA_RSA_REMOVE_PATH, &self.key_name).unwrap();
        Ok(())
    }
}

impl Drop for RsaKey {
    fn drop(&mut self) {
        self.remove_key().expect("Failed to remove key");
    }
}
