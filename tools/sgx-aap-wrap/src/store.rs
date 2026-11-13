// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! AAP material stored as one JSON object inside the protected file.

use std::path::Path;

use anyhow::{Context, Result};

#[cfg(test)]
use anyhow::bail;

use crate::material::{material_from_json, AapMaterial, MaterialFile};
use crate::sgxfs::{self, FILE_KEY_LEN};

const MATERIAL_LIMIT: usize = 64 * 1024;

pub trait AapStore: Send + Sync {
    fn create(&self, path: &Path, material: &AapMaterial) -> Result<()>;
    fn read(&self, path: &Path) -> Result<AapMaterial>;
    fn export_file_key(&self, path: &Path) -> Result<[u8; FILE_KEY_LEN]>;
    fn import_file_key(&self, path: &Path, file_key: &[u8; FILE_KEY_LEN]) -> Result<()>;
}

pub struct SgxProtectedFs;

impl AapStore for SgxProtectedFs {
    fn create(&self, path: &Path, material: &AapMaterial) -> Result<()> {
        let bytes = serde_json::to_vec(&MaterialFile::from(material))?;
        sgxfs::write(path, &bytes)
    }

    fn read(&self, path: &Path) -> Result<AapMaterial> {
        let bytes = sgxfs::read(path, MATERIAL_LIMIT)?;
        material_from_json(&bytes).context("protected file contents")
    }

    fn export_file_key(&self, path: &Path) -> Result<[u8; FILE_KEY_LEN]> {
        sgxfs::export_auto_key(path)
    }

    fn import_file_key(&self, path: &Path, file_key: &[u8; FILE_KEY_LEN]) -> Result<()> {
        sgxfs::import_auto_key(path, file_key)
    }
}

#[cfg(test)]
pub struct TestStore {
    inner: std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, AapMaterial>>,
}

#[cfg(test)]
impl TestStore {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(test)]
impl AapStore for TestStore {
    fn create(&self, path: &Path, material: &AapMaterial) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), clone_material(material));
        Ok(())
    }

    fn read(&self, path: &Path) -> Result<AapMaterial> {
        self.inner
            .lock()
            .unwrap()
            .get(path)
            .map(clone_material)
            .context("protected file is not open on this enclave")
    }

    fn export_file_key(&self, path: &Path) -> Result<[u8; FILE_KEY_LEN]> {
        let _ = self.read(path)?;
        Ok([9u8; FILE_KEY_LEN])
    }

    fn import_file_key(&self, path: &Path, file_key: &[u8; FILE_KEY_LEN]) -> Result<()> {
        if file_key != &[9u8; FILE_KEY_LEN] {
            bail!("file key does not open {}", path.display());
        }
        if !self.inner.lock().unwrap().contains_key(path) {
            bail!("missing protected file {}", path.display());
        }
        Ok(())
    }
}

#[cfg(test)]
fn clone_material(material: &AapMaterial) -> AapMaterial {
    use zeroize::Zeroizing;
    AapMaterial {
        client_key: Zeroizing::new(material.client_key.to_string()),
        password: Zeroizing::new(material.password.to_string()),
        cert_pem: material.cert_pem.clone(),
        kms_instance_id: material.kms_instance_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn material() -> AapMaterial {
        AapMaterial {
            client_key: Zeroizing::new("CLIENT-KEY-SHOULD-NOT-LEAK".into()),
            password: Zeroizing::new("pw".into()),
            cert_pem: "cert".into(),
            kms_instance_id: "kst-lab".into(),
        }
    }

    #[test]
    fn export_then_import_uses_the_file_key() {
        let store = TestStore::new();
        let path = Path::new("/tmp/aap-client.protected");
        store.create(path, &material()).unwrap();
        let key = store.export_file_key(path).unwrap();
        assert_eq!(key.len(), FILE_KEY_LEN);
        store.import_file_key(path, &key).unwrap();
        assert_eq!(
            store.read(path).unwrap().client_key.as_str(),
            "CLIENT-KEY-SHOULD-NOT-LEAK"
        );
        assert!(store.import_file_key(path, &[0u8; FILE_KEY_LEN]).is_err());
    }

    #[test]
    #[ignore = "requires /dev/sgx_enclave and the sgx group"]
    fn hardware_protected_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("sgx-aap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.protected");
        let store = SgxProtectedFs;
        store.create(&path, &material()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(!bytes
            .windows(26)
            .any(|w| w == b"CLIENT-KEY-SHOULD-NOT-LEAK"));
        let key = store.export_file_key(&path).unwrap();
        assert_eq!(
            store.read(&path).unwrap().client_key.as_str(),
            "CLIENT-KEY-SHOULD-NOT-LEAK"
        );
        let migrated = dir.join("other-cpu");
        std::fs::create_dir_all(&migrated).unwrap();
        let copy = migrated.join("client.protected");
        std::fs::copy(&path, &copy).unwrap();
        store.import_file_key(&copy, &key).unwrap();
        assert_eq!(
            store.read(&copy).unwrap().client_key.as_str(),
            "CLIENT-KEY-SHOULD-NOT-LEAK"
        );
        let renamed = dir.join("renamed.protected");
        std::fs::copy(&path, &renamed).unwrap();
        let renamed_err = store
            .import_file_key(&renamed, &key)
            .unwrap_err()
            .to_string();
        assert!(renamed_err.contains("basename"), "{renamed_err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
