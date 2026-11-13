// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// KBS-side configuration. `client_key` is not a field; serde rejects it.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KbsAliyunEnclaveConfig {
    pub enclave_url: String,
    pub kms_instance_id: String,
}

/// Plaintext AAP credential. It exists only after unseal and is wiped on drop.
pub struct AapMaterial {
    pub client_key: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub cert_pem: String,
    pub kms_instance_id: String,
}

impl fmt::Debug for AapMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AapMaterial")
            .field("kms_instance_id", &self.kms_instance_id)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MaterialFile {
    client_key: String,
    password: String,
    cert_pem: String,
    kms_instance_id: String,
}

impl From<MaterialFile> for AapMaterial {
    fn from(file: MaterialFile) -> Self {
        Self {
            client_key: Zeroizing::new(file.client_key),
            password: Zeroizing::new(file.password),
            cert_pem: file.cert_pem,
            kms_instance_id: file.kms_instance_id,
        }
    }
}

pub fn material_from_json(bytes: &[u8]) -> anyhow::Result<AapMaterial> {
    let file: MaterialFile = serde_json::from_slice(bytes)?;
    Ok(file.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn material_json_round_trip_keeps_the_client_key_out_of_debug() {
        let raw = br#"{"client_key":"CLIENT-KEY-SHOULD-NOT-LEAK","password":"pw","cert_pem":"cert","kms_instance_id":"kst-lab"}"#;
        let material = material_from_json(raw).unwrap();
        assert_eq!(material.client_key.as_str(), "CLIENT-KEY-SHOULD-NOT-LEAK");
        assert_eq!(material.kms_instance_id, "kst-lab");
        let encoded = serde_json::to_vec(&MaterialFile::from(&material)).unwrap();
        assert_eq!(
            material_from_json(&encoded).unwrap().password.as_str(),
            "pw"
        );
        let debug = format!("{material:?}");
        assert!(!debug.contains("CLIENT-KEY"));
        assert!(debug.contains("kst-lab"));
        assert!(material_from_json(br#"{"client_key":"x"}"#).is_err());
    }
}

impl From<&AapMaterial> for MaterialFile {
    fn from(material: &AapMaterial) -> Self {
        Self {
            client_key: material.client_key.to_string(),
            password: material.password.to_string(),
            cert_pem: material.cert_pem.clone(),
            kms_instance_id: material.kms_instance_id.clone(),
        }
    }
}
