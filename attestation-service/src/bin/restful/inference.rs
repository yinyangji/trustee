// SPDX-License-Identifier: Apache-2.0

use actix_web::{web, HttpResponse};
use attestation_service::inference::{InferenceError, InferenceService};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tracing::warn;
use trustee_attested_signer::inference::{InferenceRequest, VERIFY_PATH};

const DEADLINE: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 1024 * 1024;

pub struct InferenceState {
    service: InferenceService,
    slots: Arc<Semaphore>,
}

impl InferenceState {
    pub fn new(service: InferenceService, capacity: u16) -> Self {
        Self {
            service,
            slots: Arc::new(Semaphore::new(usize::from(capacity))),
        }
    }
}

async fn readiness(state: web::Data<InferenceState>) -> HttpResponse {
    if state.service.is_ready() {
        HttpResponse::Ok().finish()
    } else {
        unavailable()
    }
}

fn unavailable() -> HttpResponse {
    HttpResponse::ServiceUnavailable()
        .insert_header(("Retry-After", "1"))
        .finish()
}

fn appraisal_failure(error: InferenceError) -> HttpResponse {
    match error {
        InferenceError::InvalidRequest(_) => HttpResponse::BadRequest().finish(),
        InferenceError::Rejected(_) => HttpResponse::UnprocessableEntity().finish(),
        InferenceError::Unavailable(_) => {
            // Only log the error's public category. A dependency error may
            // contain collateral endpoint data or platform identifiers.
            warn!(%error, "Inference dependency could not complete appraisal");
            unavailable()
        }
    }
}

async fn verify(
    request: web::Json<InferenceRequest>,
    state: web::Data<InferenceState>,
) -> HttpResponse {
    let Ok(permit) = state.slots.clone().try_acquire_owned() else {
        return unavailable();
    };
    // The evaluation retains admission until native work finishes, even
    // when the HTTP client disconnects or its deadline expires.
    let evaluation = tokio::spawn(async move {
        let _permit = permit;
        state.service.appraise(request.into_inner()).await
    });
    match tokio::time::timeout(DEADLINE, evaluation).await {
        Ok(Ok(Ok(response))) => HttpResponse::Ok()
            .insert_header(("Cache-Control", "no-store"))
            .json(response),
        Ok(Ok(Err(error))) => appraisal_failure(error),
        _ => unavailable(),
    }
}

pub fn configure(config: &mut web::ServiceConfig) {
    config
        .route("/healthz", web::get().to(HttpResponse::Ok))
        .route("/readyz", web::get().to(readiness))
        .service(
            web::resource(VERIFY_PATH)
                .app_data(web::JsonConfig::default().limit(BODY_LIMIT))
                .route(web::post().to(verify)),
        );
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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

    fn parse(value: Value, kid: &str) -> anyhow::Result<bool> {
        let request: InferenceRequest = serde_json::from_value(value)?;
        Ok(request.decode(kid)?.include_signer)
    }

    #[test]
    fn only_exact_tdx_and_dual_policy_profile_is_admitted() {
        let kid = "aa".repeat(32);
        assert!(parse(request(), &kid).unwrap());

        let mut known = request();
        known["known_signer_kids"] = json!([kid]);
        assert!(!parse(known.clone(), &kid).unwrap());
        assert!(parse(known, &"ff".repeat(32)).unwrap());

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
            assert!(parse(invalid, &kid).is_err(), "{path}");
        }
        let mut gpu = request();
        gpu.pointer_mut(prefix).unwrap()["gpu_evidence"] = json!({});
        assert!(parse(gpu, &kid).is_err());
    }

    #[test]
    fn temporary_appraisal_failure_has_retry_after() {
        let temporary =
            appraisal_failure(InferenceError::Unavailable(anyhow::anyhow!("PCCS failed")));
        assert_eq!(
            temporary.status(),
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(temporary.headers().get("Retry-After").unwrap(), "1");

        let rejected =
            appraisal_failure(InferenceError::Rejected(anyhow::anyhow!("policy rejected")));
        assert_eq!(
            rejected.status(),
            actix_web::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(rejected.headers().get("Retry-After").is_none());
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
