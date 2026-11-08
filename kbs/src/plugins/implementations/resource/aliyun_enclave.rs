// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{bail, Result};
use sgx_aap_wrap::{
    encode_pubkey, fetch_secret, generate_kbs_key, read_host_tdx_quote, report_data,
    KbsAliyunEnclaveConfig,
};

pub type AliyunEnclaveBackendConfig = KbsAliyunEnclaveConfig;

pub struct AliyunEnclaveBackend {
    config: AliyunEnclaveBackendConfig,
}

impl AliyunEnclaveBackend {
    pub fn new(config: AliyunEnclaveBackendConfig) -> Result<Self> {
        if config.enclave_url.is_empty() || config.kms_instance_id.is_empty() {
            bail!("AliyunEnclave requires enclave_url and kms_instance_id");
        }
        Ok(Self { config })
    }
}

#[async_trait::async_trait]
impl StorageBackend for AliyunEnclaveBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let kbs_key = generate_kbs_key();
        let pubkey = encode_pubkey(&kbs_key.public_key());
        let report = report_data(&pubkey);
        let quote = read_host_tdx_quote(&report)?;
        fetch_secret(
            &self.config.enclave_url,
            &self.config.kms_instance_id,
            &resource_desc.resource_tag,
            &quote,
            &kbs_key,
        )
        .await
    }

    async fn write_secret_resource(&self, _resource_desc: ResourceDesc, _data: &[u8]) -> Result<()> {
        bail!("AliyunEnclave backend is read-only")
    }

    async fn delete_secret_resource(&self, _resource_desc: ResourceDesc) -> Result<()> {
        bail!("AliyunEnclave backend is read-only")
    }
}
