// SPDX-License-Identifier: Apache-2.0

//! Transport-independent appraisal of a TLS-bound inference session.

use anyhow::{anyhow, bail, Context, Result};
use key_value_storage::StorageProvider;
use serde_json::Value;
use std::sync::Arc;
use trustee_attested_signer::{
    inference::{InferenceBinding, InferenceRequest, InferenceResponse, SignerEndorsement},
    Governance, InferenceReleaseReference,
};

use crate::{
    config::Config,
    ear_token::{broker::PolicyRejected, EarAttestationTokenBroker},
    new_token_broker, EvidenceVerifier, HashAlgorithm, InitDataInput, Initdata, RuntimeData, Tee,
    VerificationRequest,
};

#[derive(Debug, thiserror::Error)]
pub enum InferenceError {
    #[error("invalid inference request")]
    InvalidRequest(#[source] anyhow::Error),
    #[error("inference attestation rejected")]
    Rejected(#[source] anyhow::Error),
    #[error("inference verification unavailable")]
    Unavailable(#[source] anyhow::Error),
}

/// The endorsement and EAR are owned by the same signer. Construction must
/// complete local appraisal of the AS endorsement before any route can use it.
pub struct InferenceService {
    evidence_verifier: EvidenceVerifier,
    token_broker: EarAttestationTokenBroker,
    endorsement: SignerEndorsement,
}

impl InferenceService {
    pub async fn new(config: Config, storage_provider: Arc<dyn StorageProvider>) -> Result<Self> {
        if !cfg!(any(feature = "tdx-verifier", feature = "all-verifier")) {
            bail!("Inference requires the native TDX verifier");
        }
        if config.storage_backend.storage_type != key_value_storage::KeyValueStorageType::Memory
            || config.rvps_config != crate::rvps::RvpsConfig::default()
        {
            bail!("Inference requires local policy storage and its own governance snapshot");
        }
        let token_broker = new_token_broker(&config, storage_provider.as_ref()).await?;
        let governance = token_broker
            .governance()
            .context("inference requires AS self-attestation")?;
        if governance.inference_releases.is_empty() {
            bail!("inference requires at least one approved workload release");
        }
        let evidence_verifier = EvidenceVerifier {
            config: config.verifier_config,
            storage_provider,
        };
        let endorsement = token_broker.inference_endorsement().await?;
        let report_data = endorsement.binding.report_data()?;
        let claims = evidence_verifier
            .verify(VerificationRequest {
                evidence: endorsement.evidence.clone(),
                tee: Tee::Tdx,
                runtime_data: Some(RuntimeData::Raw(report_data)),
                runtime_data_hash_algorithm: HashAlgorithm::Sha384,
                init_data: None,
            })
            .await
            .context("verify this instance's signer Quote and CCEL before readiness")?;
        let [claim]: [_; 1] = claims
            .try_into()
            .map_err(|_| anyhow!("AS self-attestation requires one native CPU report"))?;
        if claim.tee_class != "cpu" {
            bail!("AS self-attestation requires one native CPU report");
        }
        let (rtmr3, _) = tdx_measurements(&claim.claims)?;
        if rtmr3.len() != 96 || rtmr3.bytes().all(|b| b == b'0') {
            bail!("AS ELF measurement is missing");
        }
        Ok(Self {
            evidence_verifier,
            token_broker,
            endorsement,
        })
    }

    fn governance(&self) -> &Governance {
        self.token_broker
            .governance()
            .expect("inference service always has an approved signer")
    }

    pub fn is_ready(&self) -> bool {
        trustee_attested_signer::unix_time().is_ok_and(|now| now < self.governance().expires_at)
    }

    pub async fn appraise(
        &self,
        request: InferenceRequest,
    ) -> Result<InferenceResponse, InferenceError> {
        if !self.is_ready() {
            return Err(InferenceError::Unavailable(anyhow!(
                "governance snapshot expired"
            )));
        }
        let request = request
            .decode(&self.endorsement.binding.kid)
            .map_err(|err| InferenceError::InvalidRequest(err.into()))?;
        let init_data: Initdata = toml::from_str(&request.init_data_toml)
            .map_err(|err| InferenceError::InvalidRequest(err.into()))?;
        if !matches!(init_data.algorithm, HashAlgorithm::Sha384) {
            return Err(InferenceError::InvalidRequest(anyhow!(
                "TDX launch binding requires SHA-384"
            )));
        }
        let expected = release_reference(self.governance(), &request.binding)?;
        let runtime = serde_json::to_value(request.binding)
            .map_err(|err| InferenceError::Unavailable(err.into()))?;
        let claims = self
            .evidence_verifier
            .verify(VerificationRequest {
                evidence: request.evidence,
                tee: Tee::Tdx,
                runtime_data: Some(RuntimeData::Structured(runtime)),
                runtime_data_hash_algorithm: HashAlgorithm::Sha384,
                init_data: Some(InitDataInput::Toml(request.init_data_toml)),
            })
            .await
            .map_err(evidence_error)?;
        let [claim]: [_; 1] = claims
            .try_into()
            .map_err(|_| InferenceError::Rejected(anyhow!("expected one verified CPU report")))?;
        if claim.tee_class != "cpu" {
            return Err(InferenceError::Rejected(anyhow!(
                "expected a verified CPU report"
            )));
        }
        match_release(expected, &claim.claims)?;
        let ear = self
            .token_broker
            .issue_inference(claim)
            .await
            .map_err(|err| {
                if err.is::<PolicyRejected>() {
                    InferenceError::Rejected(err)
                } else {
                    InferenceError::Unavailable(err)
                }
            })?;
        Ok(InferenceResponse {
            ear,
            signer_evidence: request.include_signer.then(|| self.endorsement.clone()),
        })
    }
}

fn evidence_error(err: anyhow::Error) -> InferenceError {
    if err.is::<verifier::EvidenceUnavailable>() {
        InferenceError::Unavailable(err)
    } else {
        InferenceError::Rejected(err)
    }
}

fn release_reference<'a>(
    governance: &'a Governance,
    binding: &InferenceBinding,
) -> Result<&'a InferenceReleaseReference, InferenceError> {
    governance
        .inference_releases
        .get(&binding.audience)
        .and_then(|releases| releases.get(&binding.release_id))
        .ok_or_else(|| InferenceError::Rejected(anyhow!("no approved workload release")))
}

fn tdx_measurements(claims: &Value) -> Result<(&str, &str), InferenceError> {
    if claims["collateral_expiration_status"].as_str() != Some("0") {
        return Err(InferenceError::Unavailable(anyhow!(
            "missing or expired TDX collateral"
        )));
    }
    if claims
        .pointer("/td_attributes/debug")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err(InferenceError::Rejected(anyhow!("expected non-debug TDX")));
    }
    let body = &claims["quote"]["body"];
    let (Some(rtmr3), Some(init_data)) = (body["rtmr_3"].as_str(), body["mr_config_id"].as_str())
    else {
        return Err(InferenceError::Rejected(anyhow!(
            "missing TDX workload measurements"
        )));
    };
    Ok((rtmr3, init_data))
}

fn match_release(
    expected: &InferenceReleaseReference,
    claims: &Value,
) -> Result<(), InferenceError> {
    let (rtmr3, init_data) = tdx_measurements(claims)?;
    if expected.application_rtmr3 != rtmr3 || expected.init_data_sha384 != init_data {
        return Err(InferenceError::Rejected(anyhow!(
            "measurements do not match the approved release"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use trustee_attested_signer::inference::RUNTIME_PROFILE;

    fn binding(audience: &str, release_id: &str) -> InferenceBinding {
        InferenceBinding {
            profile: RUNTIME_PROFILE.into(),
            audience: audience.into(),
            nonce: "01".repeat(32),
            session_id: "02".repeat(32),
            release_id: release_id.into(),
            tls_spki_sha256: "03".repeat(32),
        }
    }

    #[test]
    fn release_requires_one_approved_tuple_for_the_requested_audience() {
        let governance: Governance = serde_json::from_value(json!({
            "policy_hashes": {"default_cpu": "aa".repeat(48)},
            "reference_values": {
                "application_rtmr_3": ["ab".repeat(48), "cd".repeat(48)],
                "application_init_data": ["12".repeat(48), "34".repeat(48)]
            },
            "inference_releases": {
                "https://tenant-a.example": {
                    "r1": {"application_rtmr3": "ab".repeat(48), "init_data_sha384": "12".repeat(48)}
                },
                "https://tenant-b.example": {
                    "r1": {"application_rtmr3": "cd".repeat(48), "init_data_sha384": "34".repeat(48)}
                }
            },
            "expires_at": trustee_attested_signer::unix_time().unwrap() + 120
        })).unwrap();
        governance.validate().unwrap();
        let tenant_a =
            release_reference(&governance, &binding("https://tenant-a.example", "r1")).unwrap();
        let mut claims = json!({
            "collateral_expiration_status": "0",
            "td_attributes": {"debug": false},
            "quote": {"body": {"rtmr_3": "ab".repeat(48), "mr_config_id": "12".repeat(48)}}
        });

        assert!(match_release(tenant_a, &claims).is_ok());
        assert!(matches!(
            release_reference(
                &governance,
                &binding("https://tenant-a.example", "wrong-release")
            ),
            Err(InferenceError::Rejected(_))
        ));
        claims["quote"]["body"]["mr_config_id"] = json!("34".repeat(48));
        assert!(matches!(
            match_release(tenant_a, &claims),
            Err(InferenceError::Rejected(_))
        ));
        claims["quote"]["body"]["rtmr_3"] = json!("cd".repeat(48));
        assert!(matches!(
            match_release(tenant_a, &claims),
            Err(InferenceError::Rejected(_))
        ));
        let tenant_b =
            release_reference(&governance, &binding("https://tenant-b.example", "r1")).unwrap();
        assert!(match_release(tenant_b, &claims).is_ok());

        claims["collateral_expiration_status"] = json!("1");
        assert!(matches!(
            match_release(tenant_b, &claims),
            Err(InferenceError::Unavailable(_))
        ));
    }

    #[test]
    fn dependency_errors_are_preserved_through_evidence_context() {
        let unavailable = Err::<(), _>(verifier::EvidenceUnavailable::from(anyhow!(
            "test PCCS outage"
        )))
        .context("native verifier")
        .unwrap_err();
        assert!(matches!(
            evidence_error(unavailable),
            InferenceError::Unavailable(_)
        ));
        assert!(matches!(
            evidence_error(anyhow!("test signature mismatch")),
            InferenceError::Rejected(_)
        ));
    }
}
