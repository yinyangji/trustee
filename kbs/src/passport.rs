// Copyright (c) 2026.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Passport-mode release for a data or model KMS.
//!
//! The workload attests through KBS. AS signs an EAR token whose
//! `REPORTDATA` is SHA-384 of the canonical runtime data, padded to 64 bytes.
//! The KMS checks that token and wraps its own DEK to the bound tee public key.
//! The DEK is not stored in KBS.

use anyhow::{anyhow, bail, Context, Result};
use kbs_types::{Response, TeePubKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};

pub const AUDIENCE_PARAM: &str = "passport-audience";
pub const CHALLENGE_PARAM: &str = "passport-nonce";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassportBinding {
    pub audience: String,
    pub challenge: String,
}

impl PassportBinding {
    pub fn from_extra(extra_params: &Value) -> Result<Option<Self>> {
        let audience = extra_params.get(AUDIENCE_PARAM);
        let challenge = extra_params.get(CHALLENGE_PARAM);
        match (audience, challenge) {
            (None, None) => Ok(None),
            (Some(audience), Some(challenge)) => {
                let audience = audience
                    .as_str()
                    .context("passport-audience is not a string")?;
                let challenge = challenge
                    .as_str()
                    .context("passport-nonce is not a string")?;
                validate_audience(audience)?;
                validate_challenge(challenge)?;
                Ok(Some(Self {
                    audience: audience.to_string(),
                    challenge: challenge.to_string(),
                }))
            }
            _ => bail!("passport-audience and passport-nonce must be supplied together"),
        }
    }
}

pub fn bound_challenge(generated: &str, extra_params: &Value) -> Result<String> {
    Ok(match PassportBinding::from_extra(extra_params)? {
        Some(binding) => binding.challenge,
        None => generated.to_string(),
    })
}

pub fn runtime_data(
    challenge: &str,
    tee_pubkey: &TeePubKey,
    audience: Option<&str>,
    additional_evidence: &str,
) -> Value {
    let mut value = json!({
        "additional-evidence": additional_evidence,
        "nonce": challenge,
        "tee-pubkey": tee_pubkey,
    });
    if let Some(audience) = audience {
        value["audience"] = json!(audience);
    }
    value
}

pub fn release_wrapped_dek(
    as_public_pem: &str,
    audience: &str,
    challenge: &str,
    tee_pubkey: &TeePubKey,
    token: &str,
    dek: &[u8],
) -> Result<Response> {
    if dek.is_empty() {
        bail!("DEK is empty");
    }
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_required_spec_claims(&["exp"]);
    let header = jsonwebtoken::decode_header(token).context("decode attestation token header")?;
    if header.alg != jsonwebtoken::Algorithm::ES256 {
        bail!("attestation token algorithm is not ES256");
    }
    let claims = jsonwebtoken::decode::<Value>(
        token,
        &jsonwebtoken::DecodingKey::from_ec_pem(as_public_pem.as_bytes())
            .context("AS public key is not EC P-256 PEM")?,
        &validation,
    )
    .context("verify attestation token")?
    .claims;

    let cpu = claims
        .pointer("/submods/cpu0")
        .context("token has no cpu appraisal")?;
    if cpu.get("ear.status").and_then(Value::as_str) != Some("affirming") {
        bail!("cpu appraisal is not affirming");
    }
    let results = cpu
        .get("ear.trustee.policy-results")
        .and_then(Value::as_array)
        .context("token has no per-policy results")?;
    for policy_id in ["default", "application"] {
        let matched = results.iter().any(|result| {
            result.get("policy_id").and_then(Value::as_str) == Some(policy_id)
                && result.get("status").and_then(Value::as_str) == Some("affirming")
        });
        if !matched {
            bail!("{policy_id} policy is not affirming");
        }
    }
    accept_trust_vector(cpu)?;

    let evidence = cpu
        .pointer("/ear.veraison.annotated-evidence")
        .context("token has no annotated evidence")?;
    let report_data = evidence
        .get("report_data")
        .and_then(Value::as_str)
        .context("token has no report data")?;
    accept_launch_binding(evidence)?;
    let runtime = evidence
        .get("runtime_data_claims")
        .context("token has no runtime data")?;
    if runtime.get("audience").and_then(Value::as_str) != Some(audience) {
        bail!("token audience does not match this KMS");
    }
    if runtime.get("nonce").and_then(Value::as_str) != Some(challenge) {
        bail!("token challenge does not match this KMS");
    }
    let bound_key: TeePubKey = serde_json::from_value(
        runtime
            .get("tee-pubkey")
            .cloned()
            .context("token has no tee public key")?,
    )
    .context("token tee public key is malformed")?;
    if serde_json::to_value(&bound_key)? != serde_json::to_value(tee_pubkey)? {
        bail!("presented tee public key does not match the token");
    }
    let digest = Sha384::digest(serde_json_canonicalizer::to_vec(runtime)?);
    let report = hex::decode(report_data).context("report data is not hex")?;
    if report.len() != 64 || report[..48] != digest[..] || report[48..] != [0; 16] {
        bail!("report data does not bind the runtime data");
    }

    crate::jwe::jwe(bound_key, dek.to_vec()).context("wrap DEK to the attested tee public key")
}

fn accept_trust_vector(cpu: &Value) -> Result<()> {
    let vector = cpu
        .get("ear.trustworthiness-vector")
        .context("token has no trustworthiness vector")?;
    let executables = vector
        .get("executables")
        .and_then(Value::as_i64)
        .context("token has no executables claim")?;
    let hardware = vector
        .get("hardware")
        .and_then(Value::as_i64)
        .context("token has no hardware claim")?;
    let configuration = vector
        .get("configuration")
        .and_then(Value::as_i64)
        .context("token has no configuration claim")?;
    if !matches!(executables, 2 | 3 | 4) || hardware != 2 || !matches!(configuration, 2 | 3) {
        bail!("trustworthiness vector does not meet the workload minimum");
    }
    Ok(())
}

fn accept_launch_binding(evidence: &Value) -> Result<()> {
    if evidence.get("sample").is_some() || evidence.get("sample-device").is_some() {
        bail!("sample evidence cannot release a DEK");
    }
    let native = ["tdx", "sgx", "snp", "csv", "cca", "se", "tpm", "az-tdx-vtpm", "az-snp-vtpm"]
        .into_iter()
        .any(|tee| evidence.get(tee).is_some_and(Value::is_object));
    if !native {
        bail!("token has no native TEE evidence");
    }
    let init = evidence
        .get("init_data")
        .and_then(Value::as_str)
        .context("token has no init data")?;
    if !is_nonzero_digest(init) {
        bail!("init data is not an approved digest");
    }
    let workload = evidence
        .get("workload")
        .context("token has no workload binding")?;
    if workload.get("version").and_then(Value::as_i64) != Some(1)
        || workload.get("launch_digest").and_then(Value::as_str) != Some(init)
    {
        bail!("workload launch binding does not match init data");
    }
    let containers = evidence
        .pointer("/init_data_claims/agent_policy_claims/containers")
        .and_then(Value::as_array)
        .context("token has no approved agent policy")?;
    if containers.is_empty() {
        bail!("approved agent policy has no containers");
    }
    Ok(())
}

fn is_nonzero_digest(value: &str) -> bool {
    matches!(value.len(), 64 | 96 | 128)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn validate_audience(audience: &str) -> Result<()> {
    let bytes = audience.as_bytes();
    if (1..=64).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !audience.starts_with('-')
        && !audience.ends_with('-')
    {
        Ok(())
    } else {
        Err(anyhow!("passport audience is not a short lowercase name"))
    }
}

fn validate_challenge(challenge: &str) -> Result<()> {
    let bytes = challenge.as_bytes();
    if (16..=128).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'+' | b'/' | b'-' | b'_' | b'='))
    {
        Ok(())
    } else {
        Err(anyhow!("passport challenge has an unexpected form"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use josekit::jwe::{alg::ecdh_es::EcdhEsJweAlgorithm::EcdhEsA256kw, JweContext, JweHeaderSet};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use p256::pkcs8::EncodePrivateKey;
    use rsa::rand_core::OsRng;

    fn signed_token(claims: &Value) -> (String, String) {
        let key = openssl::pkey::PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
            claims,
            &jsonwebtoken::EncodingKey::from_ec_pem(&key.private_key_to_pem_pkcs8().unwrap())
                .unwrap(),
        )
        .unwrap();
        (
            token,
            String::from_utf8(key.public_key_to_pem().unwrap()).unwrap(),
        )
    }

    fn workload_claims(runtime: &Value, report_data: &str, application_status: &str) -> Value {
        json!({
            "exp": jsonwebtoken::get_current_timestamp() + 60,
            "submods": {
                "cpu0": {
                    "ear.status": "affirming",
                    "ear.trustworthiness-vector": {"executables": 2, "hardware": 2, "configuration": 2},
                    "ear.trustee.policy-results": [
                        {"policy_id": "default", "status": "affirming"},
                        {"policy_id": "application", "status": application_status}
                    ],
                    "ear.veraison.annotated-evidence": {
                        "tdx": {"quote": {}},
                        "init_data": "ab".repeat(48),
                        "workload": {"version": 1, "launch_digest": "ab".repeat(48)},
                        "init_data_claims": {"agent_policy_claims": {"containers": [{"oci": {}}]}},
                        "report_data": report_data,
                        "runtime_data_claims": runtime
                    }
                }
            }
        })
    }

    fn tee_key() -> (TeePubKey, p256::SecretKey) {
        let private_key = p256::SecretKey::random(&mut OsRng);
        let point = p256::EncodedPoint::from(private_key.public_key());
        let tee_key = TeePubKey::EC {
            crv: "P-256".into(),
            alg: "ECDH-ES+A256KW".into(),
            x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        };
        (tee_key, private_key)
    }

    fn report_hex(runtime: &Value) -> String {
        let digest = Sha384::digest(serde_json_canonicalizer::to_vec(runtime).unwrap());
        let mut report = vec![0u8; 64];
        report[..48].copy_from_slice(&digest);
        hex::encode(report)
    }

    #[test]
    fn model_kms_wraps_dek_for_an_affirming_workload_token() {
        let (tee_key, private_key) = tee_key();
        let runtime = runtime_data("challenge-nonce-1", &tee_key, Some("model-kms"), "{}");
        let (token, public_pem) = signed_token(&workload_claims(
            &runtime,
            &report_hex(&runtime),
            "affirming",
        ));
        let wrapped = release_wrapped_dek(
            &public_pem,
            "model-kms",
            "challenge-nonce-1",
            &tee_key,
            &token,
            b"model-dek",
        )
        .unwrap();

        let mut header = JweHeaderSet::new();
        header.set_algorithm("ECDH-ES+A256KW", true);
        header.set_content_encryption("A256GCM", true);
        let pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let (dek, _) = JweContext::new()
            .deserialize_json(
                &serde_json::to_string(&wrapped).unwrap(),
                &EcdhEsA256kw.decrypter_from_pem(&pem).unwrap(),
            )
            .unwrap();
        assert_eq!(dek, b"model-dek");
    }

    #[test]
    fn data_kms_rejects_a_token_whose_application_measurement_failed() {
        let (tee_key, _) = tee_key();
        let runtime = runtime_data("challenge-nonce-1", &tee_key, Some("data-kms"), "{}");
        let (token, public_pem) = signed_token(&workload_claims(
            &runtime,
            &report_hex(&runtime),
            "contraindicated",
        ));
        let error = release_wrapped_dek(
            &public_pem,
            "data-kms",
            "challenge-nonce-1",
            &tee_key,
            &token,
            b"data-dek",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("application"), "{error}");
    }

    #[test]
    fn passport_parameters_are_all_or_nothing() {
        assert!(PassportBinding::from_extra(&json!({})).unwrap().is_none());
        assert!(PassportBinding::from_extra(&json!({AUDIENCE_PARAM: "model-kms"})).is_err());
        let binding = PassportBinding::from_extra(&json!({
            AUDIENCE_PARAM: "model-kms",
            CHALLENGE_PARAM: "challenge-nonce-1"
        }))
        .unwrap()
        .unwrap();
        assert_eq!(binding.audience, "model-kms");
        assert_eq!(
            bound_challenge(
                "kbs-generated-nonce",
                &json!({AUDIENCE_PARAM: "data-kms", CHALLENGE_PARAM: "data-challenge-01"})
            )
            .unwrap(),
            "data-challenge-01"
        );
        assert_eq!(
            bound_challenge("kbs-generated-nonce", &json!({})).unwrap(),
            "kbs-generated-nonce"
        );
    }

    fn release_error(claims: Value, audience: &str, challenge: &str, key: &TeePubKey) -> String {
        let (token, public_pem) = signed_token(&claims);
        release_wrapped_dek(&public_pem, audience, challenge, key, &token, b"dek")
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn each_relying_party_rejects_the_other_partys_token() {
        let (tee_key, _) = tee_key();
        let runtime = runtime_data("model-challenge-1", &tee_key, Some("model-kms"), "{}");
        let error = release_error(
            workload_claims(&runtime, &report_hex(&runtime), "affirming"),
            "data-kms",
            "model-challenge-1",
            &tee_key,
        );
        assert!(error.contains("audience"), "{error}");
    }

    #[test]
    fn release_rejects_stale_challenge_wrong_key_and_unbound_report() {
        let (first_key, _) = tee_key();
        let (other_key, _) = tee_key();
        let runtime = runtime_data("data-challenge-01", &first_key, Some("data-kms"), "{}");
        let claims = workload_claims(&runtime, &report_hex(&runtime), "affirming");
        assert!(release_error(claims.clone(), "data-kms", "other-challenge-1", &first_key).contains("challenge"));
        assert!(release_error(claims.clone(), "data-kms", "data-challenge-01", &other_key).contains("public key"));
        let mut unbound = claims.clone();
        unbound["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["report_data"] =
            json!("00".repeat(64));
        assert!(release_error(unbound, "data-kms", "data-challenge-01", &first_key).contains("report data"));
    }

    #[test]
    fn release_rejects_boot_only_expired_and_unsafe_hardware_tokens() {
        let (tee_key, _) = tee_key();
        let runtime = runtime_data("data-challenge-01", &tee_key, Some("data-kms"), "{}");
        let mut boot_only = workload_claims(&runtime, &report_hex(&runtime), "affirming");
        boot_only["submods"]["cpu0"]["ear.trustee.policy-results"] =
            json!([{"policy_id": "default", "status": "affirming"}]);
        assert!(release_error(boot_only, "data-kms", "data-challenge-01", &tee_key).contains("application"));

        let mut unsafe_hardware = workload_claims(&runtime, &report_hex(&runtime), "affirming");
        unsafe_hardware["submods"]["cpu0"]["ear.trustworthiness-vector"]["hardware"] = json!(97);
        assert!(
            release_error(unsafe_hardware, "data-kms", "data-challenge-01", &tee_key)
                .contains("trustworthiness")
        );

        let mut expired = workload_claims(&runtime, &report_hex(&runtime), "affirming");
        expired["exp"] = json!(jsonwebtoken::get_current_timestamp().saturating_sub(120));
        let (token, public_pem) = signed_token(&expired);
        assert!(release_wrapped_dek(
            &public_pem,
            "data-kms",
            "data-challenge-01",
            &tee_key,
            &token,
            b"dek"
        )
        .is_err());

        let (token, _) = signed_token(&workload_claims(
            &runtime,
            &report_hex(&runtime),
            "affirming",
        ));
        let (_other, wrong_pem) = signed_token(&json!({"exp": 1}));
        assert!(release_wrapped_dek(
            &wrong_pem,
            "data-kms",
            "data-challenge-01",
            &tee_key,
            &token,
            b"dek"
        )
        .is_err());
    }
}
