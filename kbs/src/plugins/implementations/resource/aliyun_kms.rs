// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{bail, Context, Result};
use educe::Educe;
use kms::{plugins::aliyun::AliyunKmsClient, Annotations, Getter};
use serde::Deserialize;
use tracing::info;

#[derive(Educe, Deserialize, Clone, PartialEq)]
#[educe(Debug)]
pub struct AliyunKmsBackendConfig {
    #[serde(default)]
    #[educe(Debug(ignore))]
    client_key: String,
    kms_instance_id: String,
    #[serde(default)]
    #[educe(Debug(ignore))]
    password: String,
    #[serde(default)]
    cert_pem: String,
    #[serde(default)]
    protected_credentials: Option<Box<trustee_platform_api::credentials::KeyReference>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AliyunCredentials {
    client_key: String,
    password: String,
    cert_pem: String,
}

impl Drop for AliyunCredentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_key.zeroize();
        self.password.zeroize();
    }
}

pub struct AliyunKmsBackend {
    client: AliyunKmsClient,
}

#[async_trait::async_trait]
impl StorageBackend for AliyunKmsBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        info!(
            "Use aliyun KMS backend. Ignore {}/{}",
            resource_desc.repository_name, resource_desc.resource_type
        );
        let name = resource_desc.resource_tag;
        let resource_bytes = self
            .client
            .get_secret(&name, &Annotations::default())
            .await
            .context("failed to get resource from aliyun KMS")?;
        Ok(resource_bytes)
    }

    async fn write_secret_resource(
        &self,
        _resource_desc: ResourceDesc,
        _data: &[u8],
    ) -> Result<()> {
        bail!("Aliyun backend is read-only")
    }

    async fn delete_secret_resource(&self, _resource_desc: ResourceDesc) -> Result<()> {
        bail!("Aliyun backend is read-only")
    }
}

impl AliyunKmsBackend {
    pub async fn new(repo_desc: &AliyunKmsBackendConfig) -> Result<Self> {
        let credentials = if let Some(reference) = &repo_desc.protected_credentials {
            if !repo_desc.client_key.is_empty()
                || !repo_desc.password.is_empty()
                || !repo_desc.cert_pem.is_empty()
            {
                bail!("protected_credentials is exclusive with plaintext Aliyun credentials");
            }
            let bytes = reference.load("kbs-aliyun-credentials").await?;
            serde_json::from_slice::<AliyunCredentials>(&bytes)
                .context("invalid protected Aliyun credential schema")?
        } else {
            AliyunCredentials {
                client_key: repo_desc.client_key.clone(),
                password: repo_desc.password.clone(),
                cert_pem: repo_desc.cert_pem.clone(),
            }
        };
        if credentials.client_key.is_empty()
            || credentials.password.is_empty()
            || credentials.cert_pem.is_empty()
        {
            bail!("incomplete Aliyun credentials");
        }
        let client = AliyunKmsClient::new(
            &credentials.client_key,
            &repo_desc.kms_instance_id,
            &credentials.password,
            &credentials.cert_pem,
        )
        .context("create aliyun KMS backend")?;
        Ok(Self { client })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn protected_credentials_cannot_mix_sources_or_cross_service_purposes() {
        let mut config: AliyunKmsBackendConfig = serde_json::from_value(serde_json::json!({
            "kms_instance_id":"test-instance", "client_key":"PUBLIC_TEST_FIXTURE",
            "protected_credentials": {
                "provider":{"command":"/not-executed", "expected_provider":"test"},
                "sealed_path":"/not-read",
                "binding":{"key_id":"test-key", "purpose":"as-token-signing"}
            }
        }))
        .unwrap();
        let error = AliyunKmsBackend::new(&config).await.err().unwrap();
        assert!(error.to_string().contains("exclusive"));
        config.client_key.clear();
        let error = AliyunKmsBackend::new(&config).await.err().unwrap();
        assert!(error.to_string().contains("purpose mismatch"));
        assert!(!format!("{config:?}").contains("PUBLIC_TEST_FIXTURE"));
    }
}
