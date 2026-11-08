// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};

use crate::material::{AapMaterial, MaterialFile};

const DEV_MAGIC: &[u8; 4] = b"DEVS";

pub trait AapSealer: Send + Sync {
    fn seal(&self, material: &AapMaterial) -> Result<Vec<u8>>;
    fn unseal(&self, blob: &[u8]) -> Result<AapMaterial>;
}

/// Production sealer. This build does not link the SGX SDK, so it refuses
/// rather than sealing in an ordinary process.
pub struct SgxSealer;

impl AapSealer for SgxSealer {
    fn seal(&self, _material: &AapMaterial) -> Result<Vec<u8>> {
        bail!("SGX seal is not linked into this build; refusing to write AAP material from a normal process");
    }

    fn unseal(&self, _blob: &[u8]) -> Result<AapMaterial> {
        bail!("SGX seal is not linked into this build; refusing to unseal AAP material in a normal process");
    }
}

/// Test sealer. The key is an ordinary 32-byte file, not an SGX sealing key.
pub struct DevSealer {
    key: [u8; 32],
}

impl DevSealer {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl AapSealer for DevSealer {
    fn seal(&self, material: &AapMaterial) -> Result<Vec<u8>> {
        let plaintext = serde_json::to_vec(&MaterialFile::from(material))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = Aes256Gcm::new_from_slice(&self.key).context("dev seal key")?;
        let nonce = Nonce::try_from(nonce_bytes.as_slice()).context("dev seal nonce")?;
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: &plaintext, aad: DEV_MAGIC })
            .map_err(|_| anyhow::anyhow!("dev seal"))?;
        let mut out = DEV_MAGIC.to_vec();
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn unseal(&self, blob: &[u8]) -> Result<AapMaterial> {
        let rest = blob
            .strip_prefix(DEV_MAGIC.as_slice())
            .context("dev seal header")?;
        if rest.len() < 12 + 16 {
            bail!("dev seal blob is too short");
        }
        let (nonce_bytes, ciphertext) = rest.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.key).context("dev seal key")?;
        let nonce = Nonce::try_from(nonce_bytes).context("dev seal nonce")?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: DEV_MAGIC,
                },
            )
            .map_err(|_| anyhow::anyhow!("dev unseal"))?;
        let file: MaterialFile = serde_json::from_slice(&plaintext).context("sealed AAP material")?;
        Ok(file.into())
    }
}

pub fn open_sealer(kind: &str, key: Option<&[u8]>) -> Result<Box<dyn AapSealer>> {
    match kind {
        "sgx" => Ok(Box::new(SgxSealer)),
        "dev" => {
            let key = key.context("dev seal requires a 32-byte key")?;
            let key: [u8; 32] = key.try_into().context("dev seal key must be 32 bytes")?;
            Ok(Box::new(DevSealer::new(key)))
        }
        other => bail!("unknown seal backend {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn material() -> AapMaterial {
        AapMaterial {
            client_key: Zeroizing::new("CLIENT-KEY-SHOULD-NOT-LEAK".to_string()),
            password: Zeroizing::new("password".to_string()),
            cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".to_string(),
            kms_instance_id: "kst-lab".to_string(),
        }
    }

    #[test]
    fn dev_blob_hides_the_client_key_and_sgx_refuses() {
        let sealer = DevSealer::new([7u8; 32]);
        let blob = sealer.seal(&material()).unwrap();
        assert!(!blob.windows(26).any(|w| w == b"CLIENT-KEY-SHOULD-NOT-LEAK"));
        let opened = sealer.unseal(&blob).unwrap();
        assert_eq!(opened.client_key.as_str(), "CLIENT-KEY-SHOULD-NOT-LEAK");
        assert!(SgxSealer.seal(&material()).is_err());
        assert!(SgxSealer.unseal(&blob).is_err());
    }
}
