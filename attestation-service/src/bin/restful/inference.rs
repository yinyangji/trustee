// SPDX-License-Identifier: Apache-2.0

use super::InitDataInput;
use actix_web::{web, HttpResponse};
use anyhow::{bail, ensure, Result};
use attestation_service::{
    AttestationService, HashAlgorithm, RuntimeData, Tee, VerificationRequest,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::sync::{RwLock, Semaphore};
use tracing::warn;
use trustee_attested_signer::inference::{
    require_tdx_evidence, InferenceBinding, InferenceResponse, SignerEndorsement,
};

const DEADLINE: Duration = Duration::from_secs(5);
pub(super) const BODY_LIMIT: usize = 1024 * 1024;

pub struct InferenceState {
    endorsement: SignerEndorsement,
    slots: Arc<Semaphore>,
}

impl InferenceState {
    pub fn new(endorsement: SignerEndorsement, capacity: u16) -> Self {
        Self {
            endorsement,
            slots: Arc::new(Semaphore::new(usize::from(capacity))),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceRequest {
    #[serde(default)]
    known_signer_kids: Vec<String>,
    attestation_request: InferenceAppraisal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InferenceAppraisal {
    verification_requests: Vec<InferenceQuote>,
    policy_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InferenceQuote {
    tee: String,
    evidence: String,
    runtime_data: StructuredRuntime,
    init_data: InitDataInput,
    runtime_data_hash_algorithm: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredRuntime {
    structured: InferenceBinding,
}

impl InferenceRequest {
    fn into_verified_shape(self, kid: &str) -> Result<(VerificationRequest, bool)> {
        ensure!(
            self.known_signer_kids.len() <= 16
                && self.known_signer_kids.iter().all(|id| {
                    id.len() == 64
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }),
            "invalid signer key hints"
        );
        let include_signer = !self.known_signer_kids.iter().any(|known| known == kid);
        let mut request = self.attestation_request;
        ensure!(
            request.verification_requests.len() == 1
                && request.policy_ids == ["default", "application"],
            "inference requires one report and both policies"
        );
        let request = request.verification_requests.remove(0);
        ensure!(request.tee == "tdx", "inference requires native TDX");
        let binding = request.runtime_data.structured;
        binding.validate()?;
        let InitDataInput::InitDataToml(init_data) = request.init_data else {
            bail!("inference requires structured InitData");
        };
        let parsed: attestation_service::Initdata = toml::from_str(&init_data)?;
        ensure!(
            matches!(parsed.algorithm, HashAlgorithm::Sha384)
                && request
                    .runtime_data_hash_algorithm
                    .as_deref()
                    .is_none_or(|a| a == "sha384"),
            "TDX runtime and launch bindings require SHA-384"
        );
        let request = VerificationRequest {
            tee: Tee::Tdx,
            evidence: serde_json::from_slice(&URL_SAFE_NO_PAD.decode(request.evidence)?)?,
            runtime_data: Some(RuntimeData::Structured(serde_json::to_value(binding)?)),
            init_data: Some(attestation_service::InitDataInput::Toml(init_data)),
            runtime_data_hash_algorithm: HashAlgorithm::Sha384,
        };
        require_tdx_evidence(&request.evidence)?;
        ensure!(
            !request.evidence.as_object().is_some_and(|object| {
                object
                    .keys()
                    .any(|key| key != "quote" && key != "cc_eventlog")
            }),
            "unexpected evidence fields"
        );
        Ok((request, include_signer))
    }
}

pub async fn readiness(service: web::Data<Arc<RwLock<AttestationService>>>) -> HttpResponse {
    if service.read().await.inference_ready() {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::ServiceUnavailable().finish()
    }
}

pub async fn verify(
    request: web::Json<InferenceRequest>,
    state: web::Data<InferenceState>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> HttpResponse {
    let Ok(permit) = state.slots.clone().try_acquire_owned() else {
        return HttpResponse::ServiceUnavailable()
            .insert_header(("Retry-After", "1"))
            .finish();
    };
    if !service.read().await.inference_ready() {
        return HttpResponse::ServiceUnavailable().finish();
    }
    let Ok((request, include_signer)) = request
        .into_inner()
        .into_verified_shape(&state.endorsement.binding.kid)
    else {
        return HttpResponse::BadRequest().finish();
    };

    // If the connection is dropped or times out, this task still owns the
    // permit until verification (including native work) actually finishes.
    let evaluation = tokio::spawn(async move {
        let _permit = permit;
        service.read().await.evaluate_inference(request).await
    });
    match tokio::time::timeout(DEADLINE, evaluation).await {
        Ok(Ok(Ok(ear))) => HttpResponse::Ok()
            .insert_header(("Cache-Control", "no-store"))
            .json(InferenceResponse {
                ear,
                signer_evidence: include_signer.then(|| state.endorsement.clone()),
            }),
        Ok(Ok(Err(_))) => {
            warn!("Inference attestation appraisal was unsuccessful");
            HttpResponse::UnprocessableEntity().finish()
        }
        _ => HttpResponse::ServiceUnavailable()
            .insert_header(("Retry-After", "1"))
            .finish(),
    }
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .route("/healthz", web::get().to(HttpResponse::Ok))
        .route("/readyz", web::get().to(readiness))
        .service(
            web::resource("/v1/verify")
                .app_data(web::JsonConfig::default().limit(BODY_LIMIT))
                .route(web::post().to(verify)),
        );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use trustee_attested_signer::inference::RUNTIME_PROFILE;

    fn request() -> Value {
        json!({
            "attestation_request": {
                "policy_ids": ["default", "application"],
                "verification_requests": [{
                    "tee": "tdx",
                    "evidence": URL_SAFE_NO_PAD.encode(br#"{"quote":"YQ==","cc_eventlog":"Yg=="}"#),
                    "runtime_data": {"structured": {
                        "profile": RUNTIME_PROFILE,
                        "audience": "https://inference.example",
                        "nonce": "01".repeat(32),
                        "session_id": "02".repeat(32),
                        "release_id": "release-v1",
                        "tls_spki_sha256": "03".repeat(32)
                    }},
                    "init_data": {"init_data_toml": "version='0.1.0'\nalgorithm='sha384'\n[data]\n"},
                    "runtime_data_hash_algorithm": "sha384"
                }]
            }
        })
    }

    fn parse(value: Value, kid: &str) -> Result<(VerificationRequest, bool)> {
        serde_json::from_value::<InferenceRequest>(value)?.into_verified_shape(kid)
    }

    #[test]
    fn only_exact_tdx_and_dual_policy_profile_is_admitted() {
        let kids = "aa".repeat(32);
        let (parsed, include) = parse(request(), &kids).unwrap();
        assert_eq!(parsed.tee, Tee::Tdx);
        assert!(include);

        let mut known = request();
        known["known_signer_kids"] = json!([kids]);
        assert!(!parse(known.clone(), &kids).unwrap().1);
        assert!(parse(known, &"ff".repeat(32)).unwrap().1);

        let prefix = "/attestation_request/verification_requests/0";
        for (path, replacement) in [
            ("/attestation_request/policy_ids".into(), json!(["default"])),
            (format!("{prefix}/tee"), json!("sample")),
            (
                format!("{prefix}/evidence"),
                json!(URL_SAFE_NO_PAD.encode(br#"{"quote":"YQ=="}"#)),
            ),
            (
                format!("{prefix}/runtime_data_hash_algorithm"),
                json!("sha256"),
            ),
            (
                format!("{prefix}/runtime_data/structured/session_id"),
                json!("01".repeat(32)),
            ),
        ] {
            let mut invalid = request();
            *invalid.pointer_mut(&path).unwrap() = replacement;
            assert!(parse(invalid, &kids).is_err(), "{path}");
        }
        let mut gpu = request();
        gpu.pointer_mut(prefix).unwrap()["gpu_evidence"] = json!({});
        assert!(parse(gpu, &kids).is_err());
    }

    #[actix_web::test]
    async fn inference_only_route_excludes_legacy_signing_and_admin_routes() {
        use actix_web::{test, App};

        let app = test::init_service(App::new().configure(configure)).await;
        for (method, path) in [
            ("POST", "/attestation"),
            ("POST", "/policy"),
            ("GET", "/.well-known/jwks.json"),
            ("POST", "/signer-evidence"),
        ] {
            let request = test::TestRequest::default()
                .method(method.parse().unwrap())
                .uri(path)
                .to_request();
            assert_eq!(
                test::call_service(&app, request).await.status(),
                actix_web::http::StatusCode::NOT_FOUND
            );
        }
    }
}
