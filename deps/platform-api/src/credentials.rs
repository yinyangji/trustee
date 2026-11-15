//! Versioned local driver protocol. No network endpoint exposes long-lived keys.
//! Drivers are trusted, administrator-installed executables, not workload input.
//! Unseal intentionally returns plaintext to the service's memory. Signing with
//! a non-exportable hardware key is a separate capability, not claimed here.
use std::{collections::BTreeMap, path::PathBuf, process::Stdio, time::Duration};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use zeroize::Zeroize;
use zeroize::Zeroizing;

pub const API_VERSION: u32 = 1;
pub const MAX_SECRET: usize = 64 * 1024;
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// Serialized only on private IPC pipes; redacted and wiped on drop.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct SecretBase64(String);
impl SecretBase64 {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Drop for SecretBase64 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBinding {
    pub key_id: String,
    pub purpose: String,
}

impl KeyBinding {
    pub fn validate(&self) -> Result<()> {
        for field in [&self.key_id, &self.purpose] {
            if field.is_empty()
                || field.len() > 128
                || !field
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
            {
                bail!("invalid key id or purpose");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInfo {
    pub api_version: u32,
    /// Driver identity, e.g. intel-sgx-pfs. Not a client CPU selector.
    pub provider: String,
    pub hardware_sealing: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderRequest {
    Describe,
    Seal {
        binding: KeyBinding,
        plaintext: SecretBase64,
    },
    Unseal {
        binding: KeyBinding,
        ciphertext: String,
    },
}

// Deliberately no Debug for messages that may contain plaintext credentials.
#[derive(Deserialize, Serialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderResponse {
    Description { info: ProviderInfo },
    Sealed { ciphertext: String },
    Unsealed { plaintext: SecretBase64 },
    Error { code: String },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub command: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub expected_provider: String,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

impl ProviderConfig {
    async fn exchange(&self, request: &ProviderRequest) -> Result<ProviderResponse> {
        if !self.command.is_absolute() || self.expected_provider.is_empty() {
            bail!("provider requires an absolute executable and an expected identity");
        }
        let input = Zeroizing::new(serde_json::to_vec(request)?);
        if input.len() > MAX_MESSAGE {
            bail!("provider request too large");
        }
        let mut child = Command::new(&self.command)
            .args(&self.arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .envs(&self.environment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("start hardware credential provider")?;
        let mut stdin = child.stdin.take().context("provider stdin")?;
        let stdout = child.stdout.take().context("provider stdout")?;
        let output = tokio::time::timeout(Duration::from_secs(30), async {
            let send = async move {
                stdin.write_all(&input).await?;
                // JSON drivers read to EOF; dropping the pipe is essential.
                drop(stdin);
                Ok::<(), std::io::Error>(())
            };
            let receive = async {
                let mut output = Zeroizing::new(Vec::new());
                stdout
                    .take((MAX_MESSAGE + 1) as u64)
                    .read_to_end(&mut output)
                    .await?;
                if output.len() > MAX_MESSAGE {
                    bail!("provider response too large");
                }
                Ok::<_, anyhow::Error>(output)
            };
            let ((), output) =
                tokio::try_join!(async { Ok::<_, anyhow::Error>(send.await?) }, receive)?;
            if !child.wait().await?.success() {
                bail!("hardware credential provider failed");
            }
            Ok::<_, anyhow::Error>(output)
        })
        .await
        .context("hardware credential provider timeout")??;
        let response =
            serde_json::from_slice(&output).context("invalid provider protocol response")?;
        if matches!(response, ProviderResponse::Error { .. }) {
            bail!("hardware credential provider rejected operation");
        }
        Ok(response)
    }

    pub async fn describe(&self) -> Result<ProviderInfo> {
        match self.exchange(&ProviderRequest::Describe).await? {
            ProviderResponse::Description { info }
                if info.api_version == API_VERSION
                    && info.provider == self.expected_provider
                    && info.hardware_sealing =>
            {
                Ok(info)
            }
            _ => bail!("provider identity, version or hardware sealing capability mismatch"),
        }
    }

    pub async fn seal(&self, binding: KeyBinding, plaintext: &[u8]) -> Result<SealedKey> {
        binding.validate()?;
        if plaintext.is_empty() || plaintext.len() > MAX_SECRET {
            bail!("invalid credential length");
        }
        self.describe().await?;
        let encoded = SecretBase64::new(STANDARD.encode(plaintext));
        let response = self
            .exchange(&ProviderRequest::Seal {
                binding: binding.clone(),
                plaintext: encoded,
            })
            .await?;
        match response {
            ProviderResponse::Sealed { ciphertext } if !ciphertext.is_empty() => Ok(SealedKey {
                api_version: API_VERSION,
                provider: self.expected_provider.clone(),
                binding,
                ciphertext,
            }),
            _ => bail!("expected a sealed credential"),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedKey {
    pub api_version: u32,
    pub provider: String,
    pub binding: KeyBinding,
    pub ciphertext: String,
}

/// The same reference is used by AS signing and KBS external-service credentials.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyReference {
    pub provider: ProviderConfig,
    pub sealed_path: PathBuf,
    pub binding: KeyBinding,
}

impl KeyReference {
    pub async fn load(&self, expected_purpose: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.binding.validate()?;
        if !self.sealed_path.is_absolute() {
            bail!("sealed credential path must be absolute");
        }
        if self.binding.purpose != expected_purpose {
            bail!("credential purpose mismatch");
        }
        let file = tokio::fs::File::open(&self.sealed_path)
            .await
            .context("open sealed credential")?;
        let mut bytes = Vec::new();
        file.take((MAX_MESSAGE + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > MAX_MESSAGE {
            bail!("sealed credential too large");
        }
        let sealed: SealedKey =
            serde_json::from_slice(&bytes).context("invalid sealed credential")?;
        if sealed.api_version != API_VERSION
            || sealed.provider != self.provider.expected_provider
            || sealed.binding != self.binding
        {
            bail!("sealed credential identity or purpose mismatch");
        }
        self.provider.describe().await?;
        match self
            .provider
            .exchange(&ProviderRequest::Unseal {
                binding: self.binding.clone(),
                ciphertext: sealed.ciphertext,
            })
            .await?
        {
            ProviderResponse::Unsealed { plaintext } => {
                let secret = Zeroizing::new(
                    STANDARD
                        .decode(plaintext.as_bytes())
                        .context("invalid unsealed credential encoding")?,
                );
                if secret.is_empty() || secret.len() > MAX_SECRET {
                    bail!("invalid unsealed credential length");
                }
                Ok(secret)
            }
            _ => bail!("expected an unsealed credential"),
        }
    }
}
