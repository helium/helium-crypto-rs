use crate::nova_tz::keyblob;
use crate::nova_tz::Error;
use crate::nova_tz::Result;
use rsa::RsaPublicKey;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub struct TzRsaKeyInfo {
    key_name: String,
    rsa_key: RsaPublicKey,
}

impl TzRsaKeyInfo {
    const NOVA_RSA_KEYS_PATH: &'static str = "/sys/nova-rsa/keys/";
    const NOVA_RSA_ADD_PATH: &'static str = "/sys/nova-rsa/add";
    const NOVA_RSA_REMOVE_PATH: &'static str = "/sys/nova-rsa/remove";

    pub fn from_path(key_path: &Path) -> Result<Self> {
        if !key_path.exists() {
            return Err(Error::BadKeyPath(
                key_path.to_string_lossy().to_string(),
                "file doesn't exist".to_string(),
            )
            .into());
        }

        let key_blob_data = fs::read(key_path).map_err(|e| {
            Error::BadKeyPath(key_path.to_string_lossy().to_string(), e.to_string())
        })?;

        TzRsaKeyInfo::from_key_blob_data(key_blob_data.as_slice())
    }

    pub fn from_key_blob_data(key_blob_data: &[u8]) -> Result<Self> {
        let key_name = Uuid::new_v4().to_string();
        let rsa_key = keyblob::parse_key_blob(key_blob_data).map_err(Error::KeyBlobError)?;

        fs::write(TzRsaKeyInfo::NOVA_RSA_ADD_PATH, &key_name).map_err(Error::QseecomError)?;
        fs::write(
            format!("{}{}{}", TzRsaKeyInfo::NOVA_RSA_KEYS_PATH, key_name, "/key"),
            key_blob_data,
        )
        .map_err(Error::QseecomError)?;

        Ok(TzRsaKeyInfo { key_name, rsa_key })
    }

    pub fn public_key(&self) -> Result<RsaPublicKey> {
        Ok(self.rsa_key.clone())
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sign_path = format!(
            "{}{}{}",
            TzRsaKeyInfo::NOVA_RSA_KEYS_PATH,
            self.key_name,
            "/sign"
        );

        fs::write(&sign_path, msg).map_err(Error::QseecomError)?;
        let signed = fs::read(&sign_path).map_err(Error::QseecomError)?;
        Ok(signed)
    }

    fn remove_key(&self) -> Result {
        fs::write(TzRsaKeyInfo::NOVA_RSA_REMOVE_PATH, &self.key_name)
            .map_err(Error::QseecomError)?;
        Ok(())
    }
}

impl Drop for TzRsaKeyInfo {
    fn drop(&mut self) {
        self.remove_key().expect("Failed to remove key");
    }
}
