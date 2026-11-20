// SPDX-License-Identifier: Apache-2.0

use super::broker::*;
use super::{EarTokenConfiguration, TokenSignerConfig};
#[cfg(feature = "tdx-self-attestation")]
use crate::TeeClaims;
#[cfg(feature = "tdx-self-attestation")]
use base64::Engine;
#[cfg(feature = "tdx-self-attestation")]
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
#[cfg(feature = "tdx-self-attestation")]
use kbs_types::Tee;
use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};
use serde_json::json;
#[cfg(feature = "tdx-self-attestation")]
use serde_json::Value;
use sha2::{Digest, Sha384};
use trustee_attested_signer::{Governance, SignerConfig};

fn config() -> EarTokenConfiguration {
    EarTokenConfiguration {
        issuer_name: "https://as.example".into(),
        self_attestation: Some(SignerConfig {
            as_release_manifest_digest: "aa".repeat(32),
            governance: Governance {
                policy_hashes: std::collections::BTreeMap::from([
                    (
                        "default_cpu".into(),
                        hex::encode(Sha384::digest(include_str!("ear_default_policy_cpu.rego"))),
                    ),
                    (
                        "application_cpu".into(),
                        hex::encode(Sha384::digest(include_str!(
                            "ear_application_policy_cpu.rego"
                        ))),
                    ),
                ]),
                reference_values: std::collections::BTreeMap::from([
                    ("mr_td".into(), json!(["firmware"])),
                    ("rtmr_1".into(), json!(["kernel"])),
                    ("rtmr_2".into(), json!(["cmdline"])),
                    ("xfam".into(), json!(["xfam"])),
                    ("application_rtmr_3".into(), json!(["ab".repeat(48)])),
                    ("application_init_data".into(), json!(["fa".repeat(48)])),
                ]),
                expires_at: trustee_attested_signer::unix_time().unwrap() + 3600,
            },
        }),
        ..Default::default()
    }
}

async fn broker(config: EarTokenConfiguration) -> anyhow::Result<EarAttestationTokenBroker> {
    let storage = KeyValueStorageStructConfig::default()
        .to_client_with_namespace(KeyValueStorageType::Memory, "attested-signer-test")
        .await?;
    EarAttestationTokenBroker::new(config, storage).await
}

// Synthetic native-verifier output tests the signing gate, not a TDX Quote.
#[cfg(feature = "tdx-self-attestation")]
fn verified_claims(app: bool, kernel: bool) -> TeeClaims {
    TeeClaims {
        tee: Tee::Tdx,
        tee_class: "cpu".into(),
        claims: json!({"init_data":"fa".repeat(48), "report_data":"dd".repeat(64),
            "quote":{"header":{"tee_type":"81000000","vendor_id":"939a7233f79c4ca9940a0db3957f0607"},
                "body":{"mr_td":"firmware","rtmr_1":if kernel {"kernel"} else {"tampered"},
                    "rtmr_2":"cmdline","xfam":"xfam","rtmr_3": if app {"ab".repeat(48)} else {"cd".repeat(48)},"mr_config_id":"fa".repeat(48)}},
            "tcb_status":"UpToDate","collateral_expiration_status":"0","td_attributes":{"debug":false}}),
        init_data_claims: json!({"agent_policy_claims":{"containers":[{"OCI":{}}]}}),
        runtime_data_claims: json!({"audience":"customer","nonce":"11".repeat(32),"session_id":"22".repeat(32)}),
    }
}

#[tokio::test]
async fn persistent_keys_are_rejected() {
    let mut config = config();
    config.signer = Some(TokenSignerConfig {
        key_path: "/not-read".into(),
        protected_key: None,
        cert_url: None,
        cert_path: None,
    });
    assert!(broker(config).await.is_err());
}

#[cfg(not(feature = "tdx-self-attestation"))]
#[tokio::test]
async fn unsupported_self_attestation_fails_at_startup() {
    let error = broker(config()).await.err().unwrap();
    assert!(error.to_string().contains("tdx-self-attestation"));
}

#[cfg(feature = "tdx-self-attestation")]
#[tokio::test]
async fn deployment_and_application_use_distinct_signing_gates() {
    let config = config();
    let expected_digest = config
        .self_attestation
        .as_ref()
        .unwrap()
        .governance
        .digest()
        .unwrap();
    let broker = broker(config).await.unwrap();
    let jwks = broker.get_jwks().unwrap();
    let key = DecodingKey::from_jwk(&jwks.keys[0]).unwrap();
    for (application, kernel, policies, allowed) in [
        (true, true, vec!["default", "application"], true),
        (false, true, vec!["default"], true),
        (false, true, vec!["default", "application"], false),
        (true, false, vec!["default", "application"], false),
    ] {
        let result = broker
            .issue(
                vec![verified_claims(application, kernel)],
                policies.iter().map(|v| v.to_string()).collect(),
                None,
            )
            .await;
        assert_eq!(
            result.is_ok(),
            allowed,
            "app={application}, kernel={kernel}, policies={policies:?}"
        );
        if let Ok(token) = result {
            let header = jsonwebtoken::decode_header(&token).unwrap();
            assert_eq!(header.kid, jwks.keys[0].common.key_id);
            let claims =
                jsonwebtoken::decode::<Value>(&token, &key, &Validation::new(Algorithm::ES256))
                    .unwrap()
                    .claims;
            assert_eq!(claims["ear.trustee.signer-governance"], expected_digest);
            assert_eq!(
                claims["submods"]["cpu0"]["ear.trustee.policy-results"]
                    .as_array()
                    .unwrap()
                    .len(),
                policies.len()
            );
        }
    }
    assert!(broker
        .issue(vec![], vec!["default".into()], None)
        .await
        .is_err());
    let mut sample = verified_claims(true, true);
    sample.tee = Tee::Sample;
    assert!(broker
        .issue(vec![sample], vec!["default".into()], None)
        .await
        .is_err());
    assert!(broker
        .set_policy(
            "application_cpu".into(),
            "package policy\ntrust_claims := {\"executables\":2}".into()
        )
        .await
        .is_err());
}

#[cfg(feature = "tdx-self-attestation")]
#[tokio::test]
async fn tampered_policy_and_missing_reference_do_not_produce_a_token() {
    for case in ["policy", "reference", "expired"] {
        let mut config = config();
        let profile = config.self_attestation.as_mut().unwrap();
        match case {
            "policy" => {
                profile
                    .governance
                    .policy_hashes
                    .insert("application_cpu".into(), "00".repeat(48));
            }
            "reference" => {
                profile
                    .governance
                    .reference_values
                    .remove("application_rtmr_3");
            }
            "expired" => {
                profile.governance.expires_at = 1;
            }
            _ => unreachable!(),
        }
        let result = broker(config).await;
        if let Ok(broker) = result {
            assert!(
                broker
                    .issue(
                        vec![verified_claims(true, true)],
                        vec!["default".into(), "application".into()],
                        None
                    )
                    .await
                    .is_err(),
                "{case}"
            );
        } else {
            assert_eq!(case, "expired");
        }
    }
}

#[cfg(feature = "tdx-self-attestation")]
#[tokio::test]
async fn changing_external_rvps_cannot_change_the_attested_snapshot() {
    use crate::rvps::{initialize_rvps_client, RvpsConfig};
    let provider = key_value_storage::KvStorageProvider::new(Default::default());
    let rvps = initialize_rvps_client(
        &RvpsConfig::default(),
        provider,
        KeyValueStorageType::Memory,
    )
    .await
    .unwrap();
    let malicious = json!({"application_rtmr_3":["cd".repeat(48)]});
    rvps.lock().await.verify_and_extract(&json!({"version":"0.1.0","type":"sample","payload":base64::engine::general_purpose::STANDARD.encode(malicious.to_string())}).to_string()).await.unwrap();
    let broker = broker(config()).await.unwrap();
    assert!(broker
        .issue(
            vec![verified_claims(false, true)],
            vec!["default".into(), "application".into()],
            Some(rvps)
        )
        .await
        .is_err());
}

#[cfg(feature = "tdx-self-attestation")]
#[tokio::test]
async fn evidence_endpoint_rejects_a_replacement_signing_key() {
    let broker = broker(config()).await.unwrap();
    let result = broker
        .signer_evidence(trustee_attested_signer::EvidenceRequest {
            kid: "ff".repeat(32),
            nonce: "aa".repeat(32),
        })
        .await;
    assert!(result.err().unwrap().to_string().contains("not active"));
}
