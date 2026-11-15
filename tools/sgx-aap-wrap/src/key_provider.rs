//! SGX implementation of the hardware-neutral credential-provider protocol.
//! PFS encrypts an inner envelope containing the caller's key id and purpose.
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use trustee_platform_api::credentials::{
    KeyBinding, ProviderInfo, ProviderRequest, ProviderResponse, SecretBase64, API_VERSION,
    MAX_MESSAGE, MAX_SECRET,
};
use zeroize::Zeroizing;

const PROVIDER: &str = "intel-sgx-pfs";
const BASENAME: &str = "credential.protected";

#[derive(Deserialize, Serialize)]
struct Envelope {
    version: u32,
    binding: KeyBinding,
    plaintext: SecretBase64,
}

pub fn handle(request: ProviderRequest) -> Result<ProviderResponse> {
    match request {
        ProviderRequest::Describe => Ok(ProviderResponse::Description {
            info: ProviderInfo {
                api_version: API_VERSION,
                provider: PROVIDER.into(),
                hardware_sealing: true,
            },
        }),
        ProviderRequest::Seal { binding, plaintext } => {
            binding.validate()?;
            let decoded = Zeroizing::new(STANDARD.decode(plaintext.as_bytes())?);
            if decoded.is_empty() || decoded.len() > MAX_SECRET {
                bail!("invalid credential length");
            }
            let envelope = Envelope {
                version: API_VERSION,
                binding,
                plaintext,
            };
            let bytes = Zeroizing::new(serde_json::to_vec(&envelope)?);
            let dir = tempfile::tempdir()?;
            let path = dir.path().join(BASENAME);
            crate::sgxfs::write(&path, &bytes)?;
            let ciphertext = std::fs::read(path)?;
            Ok(ProviderResponse::Sealed {
                ciphertext: STANDARD.encode(ciphertext),
            })
        }
        ProviderRequest::Unseal {
            binding,
            ciphertext,
        } => {
            binding.validate()?;
            let ciphertext = STANDARD.decode(ciphertext)?;
            if ciphertext.is_empty() || ciphertext.len() > MAX_MESSAGE / 2 {
                bail!("invalid sealed blob length");
            }
            let dir = tempfile::tempdir()?;
            let path = dir.path().join(BASENAME);
            std::fs::write(&path, ciphertext)?;
            let bytes = Zeroizing::new(crate::sgxfs::read(&path, MAX_MESSAGE)?);
            let envelope: Envelope =
                serde_json::from_slice(&bytes).context("invalid protected envelope")?;
            if envelope.version != API_VERSION || envelope.binding != binding {
                bail!("protected key binding mismatch");
            }
            let decoded = Zeroizing::new(STANDARD.decode(envelope.plaintext.as_bytes())?);
            if decoded.is_empty() || decoded.len() > MAX_SECRET {
                bail!("invalid credential length");
            }
            Ok(ProviderResponse::Unsealed {
                plaintext: envelope.plaintext,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires production SGX hardware and enclave launch permission"]
    fn hardware_seal_binds_key_and_purpose() {
        let binding = KeyBinding {
            key_id: "fixture-v1".into(),
            purpose: "test-credential".into(),
        };
        let plaintext = STANDARD.encode(b"PUBLIC_HARDWARE_TEST_FIXTURE");
        let ProviderResponse::Sealed { ciphertext } = handle(ProviderRequest::Seal {
            binding: binding.clone(),
            plaintext: SecretBase64::new(plaintext.clone()),
        })
        .unwrap() else {
            panic!("expected sealed blob")
        };
        let ProviderResponse::Unsealed { plaintext: actual } = handle(ProviderRequest::Unseal {
            binding: binding.clone(),
            ciphertext: ciphertext.clone(),
        })
        .unwrap() else {
            panic!("expected unsealed fixture")
        };
        assert_eq!(actual.as_str(), plaintext);
        let mut wrong = binding;
        wrong.purpose = "another-service".into();
        assert!(handle(ProviderRequest::Unseal {
            binding: wrong,
            ciphertext
        })
        .is_err());
    }
}
