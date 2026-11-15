// Copyright (c) 2024 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Error, Result};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ear::{Algorithm, Appraisal, Ear, Extensions, RawValue, RawValueKind, VerifierID};
use jsonwebtoken::jwk::{self, JwkSet};
use kbs_types::Tee;
use key_value_storage::KeyValueStorageInstance;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use policy_engine::rego::RegorusExtension;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde::Deserialize;
use serde_json::{json, Value};
use serde_variant::to_variant_name;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::{debug, info, warn};

use crate::ear_token::EarTokenConfiguration;
use crate::rvps::RvpsClient;
use crate::TeeClaims;

/// The policy claim that will hold trust claims.
pub const TRUST_CLAIMS_RULE: &str = "data.policy.trust_claims";
/// The policy claim that will hold extensions.
pub const EXTENSIONS_RULE: &str = "data.policy.extensions";

pub struct EarAttestationTokenBroker {
    config: EarTokenConfiguration,
    private_key: EcKey<Private>,
    cert_url: Option<String>,
    cert_chain: Option<Vec<X509>>,
    policy_engine: PolicyEngine<Regorus>,
}

impl EarAttestationTokenBroker {
    pub async fn new(
        config: EarTokenConfiguration,
        storage: KeyValueStorageInstance,
    ) -> Result<Self> {
        if let Some(trust) = &config.cc_ai {
            trust.validate()?;
        }
        let policy_engine = PolicyEngine::<Regorus>::new(storage);

        let default_cpu_policy = include_str!("ear_default_policy_cpu.rego");

        policy_engine
            .set_policy("default_cpu", default_cpu_policy, false)
            .await?;

        let default_gpu_policy = include_str!("ear_default_policy_gpu.rego");

        policy_engine
            .set_policy("default_gpu", default_gpu_policy, false)
            .await?;

        let default_switch_policy = include_str!("ear_default_policy_switch.rego");

        policy_engine
            .set_policy("default_switch", default_switch_policy, false)
            .await?;

        let default_ppcie_policy = include_str!("ear_default_policy_ppcie.rego");

        policy_engine
            .set_policy("default_ppcie", default_ppcie_policy, false)
            .await?;

        policy_engine
            .set_policy(
                "application_cpu",
                include_str!("ear_application_policy_cpu.rego"),
                false,
            )
            .await?;

        if config.signer.is_none() {
            info!("No Token Signer key in config file, create an ephemeral key and without CA pubkey cert");
            return Ok(Self {
                private_key: generate_ec_keys()?.0,
                config,
                cert_url: None,
                cert_chain: None,
                policy_engine,
            });
        }

        let signer = config.signer.clone().unwrap();
        let pem_data = match (&signer.protected_key, signer.key_path.is_empty()) {
            (Some(reference), true) => reference.load("as-token-signing").await?,
            (None, false) => zeroize::Zeroizing::new(
                std::fs::read(&signer.key_path).context("Read Token Signer private key failed")?,
            ),
            _ => bail!("Configure exactly one of signer.key_path and signer.protected_key"),
        };
        let private_key = EcKey::private_key_from_pem(&pem_data)?;
        if private_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            bail!("Only P-256 attestation token signing keys are supported");
        }

        let cert_chain = signer
            .cert_path
            .as_ref()
            .map(|cert_path| -> Result<Vec<X509>> {
                let pem_cert_chain = std::fs::read_to_string(cert_path)
                    .map_err(|e| anyhow!("Read Token Signer cert file failed: {:?}", e))?;
                X509::stack_from_pem(pem_cert_chain.as_bytes())
                    .map_err(|_| anyhow!("Invalid PEM certificate chain"))
            })
            .transpose()?;

        Ok(Self {
            config,
            private_key,
            cert_url: signer.cert_url,
            cert_chain,
            policy_engine,
        })
    }
}

/// Extensions that will be added to the attestation token.
#[derive(Debug, Deserialize)]
pub struct TokenExtension {
    pub name: String,
    pub key: i32,
    pub value: Value,
}

#[derive(Debug)]
pub struct EvaluationResult {
    pub trust_claims: Value,
    /// Extensions to be added to the attestation token.
    pub extensions: Vec<TokenExtension>,
    pub policy_hash: String,
}

impl EarAttestationTokenBroker {
    pub async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        rvps_client: Option<RvpsClient>,
    ) -> Result<String> {
        if policy_ids.len() > 16 {
            bail!("At most 16 attestation policies may be evaluated per request");
        }
        if policy_ids.is_empty() {
            bail!("No policy is given for EAR token generation.");
        }

        let mut seen = HashSet::new();
        for id in &policy_ids {
            if id.is_empty() || !seen.insert(id) {
                bail!("Policy IDs must be nonempty and unique");
            }
        }
        let mut tee_class_indices: HashMap<String, u8> = HashMap::new();
        let mut submods = BTreeMap::new();

        // Create an appraisal for each device
        for tee_claims in all_tee_claims {
            let mut appraisal = Appraisal::new();

            let tcb_claims = transform_claims(
                tee_claims.claims,
                tee_claims.init_data_claims.clone(),
                tee_claims.runtime_data_claims.clone(),
                tee_claims.tee,
                self.config.verbose_token,
            )?;

            let tcb_claims_json = serde_json::to_string(&tcb_claims)?;

            let mut results = vec![];
            for id in &policy_ids {
                let actual_id = format!("{}_{}", id, tee_claims.tee_class);
                let (evaluated, hash) = self
                    .evaluate_policy(&actual_id, &tcb_claims_json, &rvps_client)
                    .await
                    .with_context(|| format!("Evaluate policy {actual_id}"))?;
                results.push(json!({
                    "policy_id": id, "policy_hash": hash,
                    "trust_claims": evaluated.trust_vector,
                    "status": evaluated.status,
                    "appraisal": &evaluated,
                }));
                if results.len() == 1 {
                    appraisal = evaluated;
                } else {
                    for incoming in evaluated.trust_vector {
                        let current = appraisal.trust_vector.mut_by_name(incoming.tag()).unwrap();
                        if incoming.is_set()
                            && (!current.is_set()
                                || incoming.tier() > current.tier()
                                || (incoming.tier() == current.tier()
                                    && (i16::from(incoming.value()).abs(), incoming.value())
                                        > (i16::from(current.value()).abs(), current.value())))
                        {
                            current.set(incoming.value());
                        }
                    }
                }
            }
            if policy_ids.len() > 1 {
                let value: RawValue = serde_json::from_value(json!(results))?;
                appraisal
                    .extensions
                    .register("ear.trustee.policy-results", -19, value.kind())?;
                appraisal
                    .extensions
                    .set_by_name("ear.trustee.policy-results", value)?;
            }
            appraisal.annotated_evidence = tcb_claims;
            appraisal.policy_id = Some(policy_ids[0].clone());
            appraisal.update_status_from_trust_vector();

            if let Some(index) = tee_class_indices.get_mut(&tee_claims.tee_class) {
                *index += 1;
            } else {
                tee_class_indices.insert(tee_claims.tee_class.clone(), 0);
            }

            let submod_name = format!(
                "{}{}",
                tee_claims.tee_class,
                // We know this key will exist because of the logic above.
                tee_class_indices.get(&tee_claims.tee_class).unwrap()
            );
            submods.insert(submod_name, appraisal);
        }

        let now = OffsetDateTime::now_utc();
        let mut exp = now
            .checked_add(TimeDuration::minutes(self.config.duration_min))
            .ok_or(anyhow!("Token expiration overflow."))?;

        let mut extensions = Extensions::new();
        extensions.register("exp", 4, RawValueKind::Integer)?;
        extensions.set_by_name("exp", RawValue::Integer(exp.unix_timestamp()))?;

        extensions.register("iss", 1, RawValueKind::String)?;
        extensions.set_by_name("iss", RawValue::String(self.config.issuer_name.clone()))?;

        // Only verifier-derived InitData can opt into the job profile.
        let claims = json!({"submods": submods});
        let evidence = &claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"];
        if evidence["init_data_claims"]
            .get(trustee_cc_ai::INIT_DATA_KEY)
            .is_some()
        {
            if submods.len() != 1 {
                bail!("CC-AI currently supports one CPU TDX protection domain only");
            }
            let trust = self
                .config
                .cc_ai
                .as_ref()
                .context("CC-AI contract trust is not configured")?;
            trustee_cc_ai::check_appraisals(&claims)?;
            let (signed, binding) =
                trustee_cc_ai::evaluate_verified_evidence(evidence, trust, now.unix_timestamp())?;
            let stage = signed
                .contract
                .stages
                .iter()
                .find(|s| s.stage == binding.stage)
                .context("Missing job stage")?;
            let mut audiences: BTreeSet<String> =
                stage.grants.iter().map(|g| g.audience.clone()).collect();
            if binding.stage == trustee_cc_ai::Stage::ModelVerified
                && signed.contract.purpose == trustee_cc_ai::Purpose::Infer
            {
                audiences.extend(signed.contract.service_audiences.clone());
            }
            for (name, key, value) in [
                ("aud", 3, json!(audiences)),
                (
                    "cnf",
                    8,
                    json!({"jwk": trustee_cc_ai::public_jwk(&evidence["runtime_data_claims"]["tee-pubkey"])?}),
                ),
                (trustee_cc_ai::CLAIM, -710, serde_json::to_value(&binding)?),
            ] {
                let raw: RawValue = serde_json::from_value(value)?;
                extensions.register(name, key, raw.kind())?;
                extensions.set_by_name(name, raw)?;
            }
            exp =
                exp.min(now + TimeDuration::seconds(120))
                    .min(OffsetDateTime::from_unix_timestamp(
                        signed.contract.expires_at,
                    )?);
            extensions.set_by_name("exp", RawValue::Integer(exp.unix_timestamp()))?;
        }

        let ear = Ear {
            profile: self.config.profile_name.clone(),
            iat: now.unix_timestamp(),
            vid: VerifierID {
                build: self.config.build_name.clone(),
                developer: self.config.developer_name.clone(),
            },
            raw_evidence: None,
            nonce: None,
            submods,
            extensions,
        };

        debug!(ear =? ear, "Unsigned EAR Token");

        let mut jwt_header = ear::new_jwt_header(&Algorithm::ES256)?;
        jwt_header.jwk = Some(self.pubkey_jwk()?);

        let pkey = PKey::from_ec_key(self.private_key.clone())?;
        let private_key_bytes = pkey.private_key_to_pem_pkcs8()?;

        let signed_ear = ear.sign_jwt_pem_with_header(&jwt_header, &private_key_bytes)?;

        Ok(signed_ear)
    }

    async fn evaluate_policy(
        &self,
        policy_id: &str,
        tcb_claims_json: &str,
        rvps_client: &Option<RvpsClient>,
    ) -> Result<(Appraisal, String)> {
        let mut appraisal = Appraisal::new();
        let mut extensions = vec![];
        if let Some(ref rvps_client) = rvps_client {
            let rvps_client = rvps_client.clone();
            let extension = RegorusExtension {
                name: "query_reference_value".to_string(),
                id: 1,
                extension: Box::new(move |params: Vec<regorus::Value>| {
                    if params.len() != 1 {
                        bail!("query_reference_value extension requires exactly one parameter");
                    }
                    let id = params[0]
                        .as_string()
                        .context("query_reference_value extension parameter must be a string")?
                        .to_string();
                    debug!("query reference value from RVPS: {id}");
                    let rvps_client = rvps_client.clone();
                    let reference_value_id = params[0].as_string()?.to_string();
                    // Policy evaluation runs on tokio's blocking pool, so it is
                    // safe to block_on the RVPS query here without starving
                    // runtime workers that drive the gRPC connection pool.
                    let result = tokio::runtime::Handle::current()
                        .block_on(async move {
                            tokio::time::timeout(Duration::from_secs(10), async {
                                rvps_client
                                    .lock()
                                    .await
                                    .query_reference_value(&reference_value_id)
                                    .await
                            })
                            .await
                            .map_err(|e| anyhow!("Get Reference Value from RVPS timeout: {e:?}"))?
                        })
                        .map_err(|e| anyhow!("Get Reference Value from RVPS failed: {e:?}"))?;

                    match result {
                        Some(v) => {
                            let json_value = serde_json::to_value(v)?;
                            let value: regorus::Value = serde_json::from_value(json_value)?;
                            Ok(value)
                        }
                        None => {
                            warn!("No reference value found for the given id: {id}, use NULL as the returned value");
                            Ok(regorus::Value::Null)
                        }
                    }
                }),
            };

            extensions.push(extension);
        }

        let policy_results = self
            .policy_engine
            .evaluate_rego(
                None,
                tcb_claims_json.to_owned(),
                policy_id,
                vec![TRUST_CLAIMS_RULE.to_string(), EXTENSIONS_RULE.to_string()],
                extensions,
            )
            .await?;

        match policy_results
            .eval_rules_result
            .get(TRUST_CLAIMS_RULE)
            .with_context(|| {
                format!("Trust claims rule {TRUST_CLAIMS_RULE} not found for policy {policy_id}")
            })? {
            Some(value) => {
                let trust_claims = value.as_object().context("Trust claims is not an object")?;
                for (k, v) in trust_claims {
                    let claim_value = v.as_i64().context("Trust claim value not number")?;
                    if matches!(claim_value, -1 | 1) {
                        bail!("Policy reported verifier malfunction or unexpected evidence");
                    }
                    debug!("Trust claim: {}: {}", k, claim_value);

                    appraisal
                        .trust_vector
                        .mut_by_name(k)
                        .with_context(|| format!("Unknown trust claim {k}"))?
                        .set(
                            i8::try_from(claim_value)
                                .ok()
                                .filter(|v| *v != i8::MIN)
                                .context("Trust claim must be an integer in -127..=127")?,
                        );
                }
            }
            None => {
                warn!("No trust claims found by enforcing policy {policy_id}, set all TrustVector claims to 0");
                appraisal.trust_vector.set_all(0);
            }
        }

        if !appraisal
            .trust_vector
            .into_iter()
            .any(|claim| claim.value() != 0)
        {
            bail!("At least one policy claim must be set.");
        }

        // Set extensions from policy result
        let mut extensions = Extensions::new();
        let extension_claims = policy_results
            .eval_rules_result
            .get(EXTENSIONS_RULE)
            .context("Extensions rule not found")?
            .as_ref()
            .cloned()
            .unwrap_or(json!([]));

        let extension_claims =
            serde_json::from_value::<Vec<TokenExtension>>(extension_claims.clone())?;
        for extension in extension_claims {
            let extension_value: RawValue =
                serde_json::from_str(&serde_json::to_string(&extension.value)?)?;

            extensions.register(&extension.name, extension.key, extension_value.kind())?;
            extensions.set_by_name(&extension.name, extension_value)?;
        }

        appraisal.extensions = extensions;

        appraisal.update_status_from_trust_vector();
        Ok((appraisal, policy_results.policy_hash))
    }

    pub async fn set_policy(&self, policy_id: String, policy: String) -> Result<()> {
        self.policy_engine
            .set_policy(&policy_id, &policy, true)
            .await
            .map_err(Error::from)
    }

    pub async fn list_policies(&self) -> Result<Vec<String>> {
        self.policy_engine
            .list_policies()
            .await
            .map_err(Error::from)
    }

    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.policy_engine
            .get_policy(&policy_id)
            .await
            .map_err(Error::from)
    }

    pub fn get_jwks(&self) -> Result<JwkSet> {
        Ok(JwkSet {
            keys: vec![self.pubkey_jwk()?],
        })
    }
}

impl EarAttestationTokenBroker {
    fn pubkey_jwk(&self) -> Result<jwk::Jwk> {
        let chain = self
            .cert_chain
            .as_ref()
            .map(|certs| -> Result<Vec<String>> {
                let mut chain = vec![];
                for cert in certs {
                    let der = cert.to_der()?;
                    chain.push(STANDARD.encode(der));
                }
                Ok(chain)
            })
            .transpose()?;

        let common = jwk::CommonParameters {
            key_algorithm: Some(jwk::KeyAlgorithm::ES256),
            x509_url: self.cert_url.clone(),
            x509_chain: chain,
            ..Default::default()
        };

        let public_key = self.private_key.public_key();
        let group = self.private_key.group();

        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        public_key.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        // RFC 7518 requires fixed-length coordinate octet strings (32 bytes for P-256).
        let field_size = group.degree().div_ceil(8);

        let algorithm = jwk::AlgorithmParameters::EllipticCurve(jwk::EllipticCurveKeyParameters {
            key_type: jwk::EllipticCurveKeyType::EC,
            curve: jwk::EllipticCurve::P256,
            x: URL_SAFE_NO_PAD.encode(x.to_vec_padded(field_size as i32)?),
            y: URL_SAFE_NO_PAD.encode(y.to_vec_padded(field_size as i32)?),
        });

        let jwk = jwk::Jwk { common, algorithm };

        Ok(jwk)
    }
}

fn generate_ec_keys() -> Result<(EcKey<Private>, Vec<u8>, Vec<u8>)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key.clone())?;

    Ok((
        ec_key,
        pkey.private_key_to_pem_pkcs8()?,
        pkey.public_key_to_pem()?,
    ))
}

#[cfg(test)]
mod cc_ai_tests {
    use super::*;
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};
    // Synthetic verified claims exercise AS/RP integration, not hardware quote
    // verification. Actual TDX acceptance requires the separate cluster suite.
    #[allow(dead_code)]
    mod common {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../deps/cc-ai/tests/common/mod.rs"
        ));
    }

    async fn broker(trust: trustee_cc_ai::TrustPolicy) -> EarAttestationTokenBroker {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, "cc_ai_unit")
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(
            EarTokenConfiguration {
                issuer_name: "https://as.example".into(),
                cc_ai: Some(trust),
                ..Default::default()
            },
            storage,
        )
        .await
        .unwrap();
        for id in ["default_cpu", "application_cpu"] {
            broker.set_policy(id.into(), "package policy\ntrust_claims := {\"executables\":2,\"hardware\":2,\"configuration\":2}\nextensions := []".into()).await.unwrap();
        }
        broker
    }
    fn verified(e: &Value) -> TeeClaims {
        TeeClaims {
            tee: Tee::Tdx,
            tee_class: "cpu".into(),
            claims: json!({"quote":{"body":{"rtmr_3":"22".repeat(48),"mr_config_id":"cc".repeat(48)}},
                "init_data":"cc".repeat(48),"report_data":"dd".repeat(48)}),
            init_data_claims: e["init_data_claims"].clone(),
            runtime_data_claims: e["runtime_data_claims"].clone(),
        }
    }

    #[tokio::test]
    async fn as_signature_background_authorization_and_passport_roundtrip() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let (trust, signed, fixture) = common::fixture(now);
        let broker = broker(trust.clone()).await;
        let e = &fixture["submods"]["cpu0"]["ear.veraison.annotated-evidence"];
        let token = broker
            .issue(
                vec![verified(e)],
                vec!["default".into(), "application".into()],
                None,
            )
            .await
            .unwrap();
        let pem = PKey::from_ec_key(broker.private_key.clone())
            .unwrap()
            .public_key_to_pem()
            .unwrap();
        let claims = trustee_cc_ai::verify_pinned_result(&token, &pem).unwrap();
        assert!(claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap() <= 120);
        common::data_policy(trust.clone())
            .authorize(&claims, "workload/data/v1", now)
            .unwrap();
        let mut user = common::data_policy(trust);
        user.role = trustee_cc_ai::Role::User;
        user.audience = "https://client.example".into();
        trustee_cc_ai::verify_passport(
            &claims,
            &user,
            &trustee_cc_ai::PassportExpectation {
                nonce: "fresh-challenge-0123456789",
                job_id: "job-1",
                contract_digest: &trustee_cc_ai::sha384(
                    &trustee_cc_ai::canonical(&signed.contract).unwrap(),
                ),
                peer_key: &claims["cnf"]["jwk"],
            },
            now,
        )
        .unwrap();
        let (_, _, wrong) = generate_ec_keys().unwrap();
        assert!(trustee_cc_ai::verify_pinned_result(&token, &wrong).is_err());
    }

    #[tokio::test]
    async fn missing_trust_failed_appraisal_and_modified_measurement_cannot_get_job_token() {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let (trust, _, fixture) = common::fixture(now);
        let e = &fixture["submods"]["cpu0"]["ear.veraison.annotated-evidence"];
        let mut broker = broker(trust.clone()).await;
        broker.config.cc_ai = None;
        assert!(broker
            .issue(
                vec![verified(e)],
                vec!["default".into(), "application".into()],
                None
            )
            .await
            .is_err());
        broker.config.cc_ai = Some(trust);
        let mut changed = verified(e);
        changed.claims["quote"]["body"]["rtmr_3"] = json!("99".repeat(48));
        assert!(broker
            .issue(
                vec![changed],
                vec!["default".into(), "application".into()],
                None
            )
            .await
            .is_err());
        broker
            .set_policy(
                "application_cpu".into(),
                "package policy\ntrust_claims := {\"executables\":97}\nextensions := []".into(),
            )
            .await
            .unwrap();
        assert!(broker
            .issue(
                vec![verified(e)],
                vec!["default".into(), "application".into()],
                None
            )
            .await
            .is_err());
    }
}

/// This function does three things.
///
/// 1) If the input claims include an init_data claim (meaning that
///    the verifier has validated the init_data), add the JSON
///    init_data_claims to the output claims. Do the same thing
///    for the report_data and runtime_data_claims.
///
///    This means that the full init_data and report_data will be
///    available in the token.
///
/// 2) Move all claims from input_claims except the ones mentioned
///    in the previous step into their own Object under the tee name.
///
/// 3) Convert the claims from serde_json Values to RawValues from the
///    EAR crate.
///
pub fn transform_claims(
    mut input_claims: Value,
    init_data_claims: Value,
    mut runtime_data_claims: Value,
    tee: Tee,
    verbose: bool,
) -> Result<BTreeMap<String, RawValue>> {
    let mut output_claims = BTreeMap::new();
    if let Some(binding) = trustee_platform_api::attestation::application_binding(
        to_variant_name(&tee)?,
        &input_claims,
    ) {
        output_claims.insert(
            "workload".into(),
            serde_json::from_value(serde_json::to_value(binding)?)?,
        );
    }

    // If the verifier produces an init_data claim (meaning that
    // it has validated the init_data hash), add the JSON init_data_claims,
    // to the claims map. Do the same for the report data.
    //
    // These claims will be flattened and provided to the policy engine.
    // They will also end up in the EAR token as part of the annotated evidence.
    if let Some(claims_map) = input_claims.as_object_mut() {
        if let Some(init_data) = claims_map.remove("init_data") {
            output_claims.insert(
                "init_data".to_string(),
                RawValue::String(init_data.as_str().unwrap().to_string()),
            );

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&init_data_claims)?)?;
            output_claims.insert("init_data_claims".to_string(), transformed_claims);
        }

        if let Some(report_data) = claims_map.remove("report_data") {
            output_claims.insert(
                "report_data".to_string(),
                RawValue::String(report_data.as_str().unwrap().to_string()),
            );

            // When attesting environments with lots of devices, the additional evidence
            // can create a token that is very large. This can overwhelm the header size
            // limitation of some http servers (including the KBS).
            // If verbose is false, don't include the additional evidence in the token.
            if !verbose {
                runtime_data_claims
                    .as_object_mut()
                    .and_then(|map| map.remove("additional-evidence"));
            }

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&runtime_data_claims)?)?;

            output_claims.insert("runtime_data_claims".to_string(), transformed_claims);
        }
    }

    let transformed_claims: RawValue =
        serde_json::from_str(&serde_json::to_string(&input_claims)?)?;
    output_claims.insert(to_variant_name(&tee)?.to_string(), transformed_claims);

    Ok(output_claims)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
    use jsonwebtoken::DecodingKey;
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType, SetParameters};
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::{ear_token::TokenSignerConfig, TeeClaims, AS_POLICY_STORAGE_NAMESPACE};

    use super::*;

    #[tokio::test]
    async fn conflicting_signer_sources_are_rejected_before_loading_secrets() {
        let provider = key_value_storage::KvStorageProvider::new(
            key_value_storage::StorageBackendConfig::default(),
        );
        use key_value_storage::StorageProvider;
        let storage = provider
            .get_or_register(AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let config: EarTokenConfiguration = serde_json::from_value(json!({"signer": {
            "key_path": "/not-read",
            "protected_key": {
                "provider": {"command": "/not-executed", "expected_provider": "test"},
                "sealed_path": "/not-read-either",
                "binding": {"key_id":"signer-v1", "purpose":"as-token-signing"}
            }
        }}))
        .unwrap();
        let result = EarAttestationTokenBroker::new(config, storage).await;
        assert!(result.err().unwrap().to_string().contains("exactly one"));
    }

    #[tokio::test]
    async fn two_modes_close_rvps_appraisal_signature_and_resource_authorization() {
        use crate::rvps::{initialize_rvps_client, RvpsConfig};
        use key_value_storage::{KvStorageProvider, StorageBackendConfig, StorageProvider};
        use trustee_platform_api::policy::PolicyMode;

        let provider = KvStorageProvider::new(StorageBackendConfig::default());
        let rvps = initialize_rvps_client(
            &RvpsConfig::default(),
            provider.clone(),
            KeyValueStorageType::Memory,
        )
        .await
        .unwrap();
        let refs = json!({"mr_td": ["firmware"], "rtmr_1": ["kernel"], "rtmr_2": ["cmdline"],
            "xfam": ["xfam"], "application_rtmr_3": ["ab".repeat(48)], "application_init_data": ["fa".repeat(48)]});
        rvps.lock()
            .await
            .verify_and_extract(
                &json!({"version":"0.1.0", "type":"sample",
            "payload":STANDARD.encode(refs.to_string())})
                .to_string(),
            )
            .await
            .unwrap();
        let storage = provider
            .get_or_register(AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(EarTokenConfiguration::default(), storage)
            .await
            .unwrap();
        let key = DecodingKey::from_jwk(&broker.pubkey_jwk().unwrap()).unwrap();
        let resource_policy = include_str!("../../../kbs/sample_policies/default.rego");

        for (mode, app, boot, launch, repo, expected) in [
            (PolicyMode::Default, true, true, true, "default", true),
            (PolicyMode::Default, false, true, false, "default", true),
            (PolicyMode::Default, true, true, true, "workload", false),
            (PolicyMode::Workload, true, true, true, "workload", true),
            (PolicyMode::Workload, false, true, true, "workload", false),
            (PolicyMode::Workload, true, false, true, "workload", false),
            (PolicyMode::Workload, true, true, false, "workload", false),
        ] {
            let raw = json!({"init_data": "fa".repeat(48), "quote": {
                "header": {"tee_type":"81000000", "vendor_id":"939a7233f79c4ca9940a0db3957f0607"},
                "body": {"mr_td": if boot {"firmware"} else {"tampered"}, "rtmr_1":"kernel", "rtmr_2":"cmdline",
                    "xfam":"xfam", "rtmr_3": if app {"ab".repeat(48)} else {"cd".repeat(48)}, "mr_config_id":"fa".repeat(48)}},
                "tcb_status":"UpToDate", "collateral_expiration_status":"0", "td_attributes":{"debug":false}});
            // These are synthetic native-verifier outputs. No quote signature is claimed.
            let token = broker
                .issue(
                    vec![TeeClaims {
                        tee: Tee::Tdx,
                        tee_class: "cpu".into(),
                        claims: raw,
                        init_data_claims: if launch {
                            json!({"agent_policy_claims":{"containers":[{"OCI":{}}]}})
                        } else {
                            Value::Null
                        },
                        runtime_data_claims: json!({"workload":{"measurement":"spoofed"}}),
                    }],
                    mode.policy_ids(),
                    Some(rvps.clone()),
                )
                .await
                .unwrap();
            let claims = jsonwebtoken::decode::<Value>(
                &token,
                &key,
                &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256),
            )
            .unwrap()
            .claims;
            let result = Regorus::default()
                .evaluate(
                    Some(
                        json!({"plugin":"resource", "resource-path":[repo,"test","key"]})
                            .to_string(),
                    ),
                    claims.to_string(),
                    resource_policy.into(),
                    vec!["data.policy.allow".into()],
                    vec![],
                )
                .await
                .unwrap();
            assert_eq!(
                result.eval_rules_result["data.policy.allow"],
                Some(json!(expected)),
                "{mode:?} app={app} boot={boot} launch={launch}"
            );
            assert_ne!(
                claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["workload"]
                    ["measurement"],
                "spoofed"
            );
        }
    }

    #[rstest::rstest]
    #[case(3, 33, 33)]
    #[case(33, 3, 33)]
    #[case(3, -96, -96)]
    #[case(-96, 3, -96)]
    #[case(3, 2, 3)]
    #[tokio::test]
    async fn test_all_policies_are_appraised(
        #[case] first: i64,
        #[case] second: i64,
        #[case] expected: i64,
    ) {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(EarTokenConfiguration::default(), storage)
            .await
            .unwrap();
        for (id, value) in [("base", first), ("app", second)] {
            broker
                .set_policy(
                    format!("{id}_cpu"),
                    format!("package policy\ntrust_claims := {{\"executables\": {value}}}"),
                )
                .await
                .unwrap();
        }
        let token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Tdx,
                    tee_class: "cpu".into(),
                    claims: json!({}),
                    init_data_claims: Value::Null,
                    runtime_data_claims: Value::Null,
                }],
                vec!["base".into(), "app".into()],
                None,
            )
            .await
            .unwrap();
        let key = DecodingKey::from_jwk(&broker.pubkey_jwk().unwrap()).unwrap();
        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &key).unwrap();
        let cpu = &ear.submods["cpu0"];
        assert_eq!(i64::from(cpu.trust_vector.executables.value()), expected);
        let decoded = jsonwebtoken::decode::<Value>(
            &token,
            &key,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256),
        )
        .unwrap()
        .claims;
        let results = &decoded["submods"]["cpu0"]["ear.trustee.policy-results"];
        assert_eq!(results.as_array().unwrap().len(), 2);
        assert_eq!(results[0]["policy_id"], "base");
        assert_eq!(results[1]["policy_id"], "app");
        assert_eq!(results[1]["trust_claims"]["executables"], second);
        assert_eq!(results[1]["policy_hash"].as_str().unwrap().len(), 96);
    }

    #[rstest::rstest]
    #[case("{\"unknown\": 3}")]
    #[case("{\"executables\": 128}")]
    #[case("{\"executables\": -128}")]
    #[case("{\"executables\": 3.5}")]
    #[case("{\"executables\": 0}")]
    #[case("{\"executables\": -1}")]
    #[case("{\"executables\": 1}")]
    #[case("{}")]
    #[tokio::test]
    async fn test_bad_additional_policy_is_not_ignored(#[case] claims: &str) {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(EarTokenConfiguration::default(), storage)
            .await
            .unwrap();
        broker
            .set_policy(
                "base_cpu".into(),
                "package policy\ntrust_claims := {\"executables\": 3}".into(),
            )
            .await
            .unwrap();
        broker
            .set_policy(
                "bad_cpu".into(),
                format!("package policy\ntrust_claims := {claims}"),
            )
            .await
            .unwrap();
        for ids in [
            vec!["base", "bad"],
            vec!["base", "missing"],
            vec!["base", "base"],
            vec!["base", ""],
            vec![],
        ] {
            assert!(broker
                .issue(
                    vec![TeeClaims {
                        tee: Tee::Tdx,
                        tee_class: "cpu".into(),
                        claims: json!({}),
                        init_data_claims: Value::Null,
                        runtime_data_claims: Value::Null,
                    }],
                    ids.into_iter().map(str::to_owned).collect(),
                    None
                )
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn test_issue_ear_ephemeral_key() {
        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = EarTokenConfiguration::default();

        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        storage
            .set(
                "ear_no_rv_policy_cpu.rego",
                include_bytes!("../../tests/coco-as/policy/opa/ear_no_rv_policy_cpu.rego"),
                SetParameters { overwrite: true },
            )
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();

        let _token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    tee_class: "cpu".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                }],
                vec!["ear_no_rv_policy".into()],
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_issue_and_validate_ear() {
        let (_pkey, private_key_bytes, public_key_bytes) = generate_ec_keys().unwrap();
        let mut private_key_file = NamedTempFile::new().unwrap();
        private_key_file.write_all(&private_key_bytes).unwrap();

        let signer = TokenSignerConfig {
            protected_key: None,
            key_path: private_key_file.path().to_str().unwrap().to_string(),
            cert_url: None,
            cert_path: None,
        };

        let config = EarTokenConfiguration {
            signer: Some(signer),
            ..Default::default()
        };
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        storage
            .set(
                "ear_no_rv_policy_cpu.rego",
                include_bytes!("../../tests/coco-as/policy/opa/ear_no_rv_policy_cpu.rego"),
                SetParameters { overwrite: true },
            )
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();
        let token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    tee_class: "cpu".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                }],
                vec!["ear_no_rv_policy".into()],
                None,
            )
            .await
            .unwrap();

        let public_key = DecodingKey::from_ec_pem(&public_key_bytes).unwrap();

        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &public_key).unwrap();
        ear.validate().unwrap();
    }

    #[tokio::test]
    async fn test_get_jwks() {
        let config = EarTokenConfiguration::default();
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();

        let jwks = broker.get_jwks().unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(
            jwks.keys[0].common.key_algorithm,
            Some(jwk::KeyAlgorithm::ES256)
        );
        match &jwks.keys[0].algorithm {
            AlgorithmParameters::EllipticCurve(ec) => {
                assert_eq!(ec.curve, EllipticCurve::P256);
                let x = URL_SAFE_NO_PAD.decode(&ec.x).unwrap();
                let y = URL_SAFE_NO_PAD.decode(&ec.y).unwrap();
                assert_eq!(x.len(), 32, "x coordinate must be 32 bytes for P-256");
                assert_eq!(y.len(), 32, "y coordinate must be 32 bytes for P-256");
            }
            other => panic!("unexpected key type: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_get_jwks_matches_fixture() {
        let signer = TokenSignerConfig {
            protected_key: None,
            key_path: "tests/fixtures/jwk/signing-key.pem".to_string(),
            cert_url: None,
            cert_path: Some("tests/fixtures/jwk/cert-chain.pem".to_string()),
        };

        let config = EarTokenConfiguration {
            signer: Some(signer),
            ..Default::default()
        };
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();

        let jwks = broker.get_jwks().unwrap();
        let expected: JwkSet =
            serde_json::from_str(include_str!("../../tests/fixtures/jwk/expected-jwks.json"))
                .unwrap();

        assert_eq!(jwks, expected);
    }

    #[test]
    fn test_transform_claims() {
        let json = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": ""
                }
            },
            "quote": {
                "header":{
                    "version": "0400",
                    "att_key_type": "0200",
                    "tee_type": "81000000",
                    "reserved": "00000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                    "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                },
                "body":{
                    "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                    "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                    "seam_attributes": "0000000000000000",
                    "td_attributes": "0100001000000000",
                    "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                    "tcb_svn": "03000500000000000000000000000000",
                    "xfam": "e742060000000000"
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });

        let init_data_claims = Value::String("".to_string());
        let runtime_data_claims = Value::String("".to_string());
        let transformed_claims =
            transform_claims(json, init_data_claims, runtime_data_claims, Tee::Tdx, true)
                .expect("flatten failed");

        let expected_claims = json!({
            "tdx": {
                "ccel": {
                    "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                    "kernel_parameters": {
                        "console": "hvc0",
                        "root": "/dev/vda1",
                        "rw": ""
                    }
                },
                "quote": {
                    "header":{
                        "version": "0400",
                        "att_key_type": "0200",
                        "tee_type": "81000000",
                        "reserved": "00000000",
                        "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                        "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                    },
                    "body":{
                        "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                        "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                        "seam_attributes": "0000000000000000",
                        "td_attributes": "0100001000000000",
                        "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                        "tcb_svn": "03000500000000000000000000000000",
                        "xfam": "e742060000000000"
                    }
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "runtime_data_claims": "",
            "init_data_claims": ""
        });

        assert_json_eq!(expected_claims, transformed_claims);
    }
}
