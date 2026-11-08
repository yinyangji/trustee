// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use actix_web::{post, web, App, HttpResponse, HttpServer, ResponseError};
use anyhow::{Context, Result};
use async_trait::async_trait;
use p256::SecretKey;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, decode_pubkey, report_data};
use crate::material::AapMaterial;
use crate::quote::QuotePolicy;
use crate::store::AapStore;

#[derive(Debug, Deserialize, Serialize)]
pub struct GetSecretRequest {
    pub kms_instance_id: String,
    pub secret_name: String,
    /// Uncompressed SEC1 P-256 public key, standard base64.
    pub kbs_pubkey: String,
    /// TDX quote, standard base64.
    pub quote: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetSecretResponse {
    /// Uncompressed SEC1 P-256 public key of the wrap service, standard base64.
    pub enclave_pubkey: String,
    /// `nonce || ciphertext`, standard base64.
    pub encrypted_secret: String,
}

#[async_trait]
pub trait KmsGet: Send + Sync {
    async fn get_secret(&self, material: &AapMaterial, name: &str) -> Result<Vec<u8>>;
}

#[cfg(feature = "aliyun")]
pub struct AliyunKmsOp;

#[cfg(feature = "aliyun")]
#[async_trait]
impl KmsGet for AliyunKmsOp {
    async fn get_secret(&self, material: &AapMaterial, name: &str) -> Result<Vec<u8>> {
        let client = kms::plugins::aliyun::AliyunKmsClient::new(
            &material.client_key,
            &material.kms_instance_id,
            &material.password,
            &material.cert_pem,
        )
        .map_err(|err| anyhow::anyhow!("create Aliyun KMS client: {err}"))?;
        client
            .get_secret(name, &kms::Annotations::default())
            .await
            .map_err(|err| anyhow::anyhow!("Aliyun GetSecret: {err}"))
    }
}

#[derive(Clone)]
pub struct WrapState {
    pub store: Arc<dyn AapStore>,
    pub quotes: Arc<dyn QuotePolicy>,
    pub kms: Arc<dyn KmsGet>,
    pub file: std::path::PathBuf,
}

#[derive(Debug)]
struct ApiError(anyhow::Error);

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Forbidden().body(self.0.to_string())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        Self(err)
    }
}

pub async fn release_secret(
    state: &WrapState,
    request: GetSecretRequest,
) -> Result<GetSecretResponse> {
    let pubkey_bytes = crypto::b64_decode(&request.kbs_pubkey)?;
    let pubkey = decode_pubkey(&pubkey_bytes)?;
    let expected = report_data(&pubkey_bytes);
    let quote = crypto::b64_decode(&request.quote)?;
    state.quotes.verify(&quote, &expected)?;
    let material = state.store.read(&state.file)?;
    if material.kms_instance_id != request.kms_instance_id {
        anyhow::bail!("sealed AAP credential is for a different KMS instance");
    }
    let secret = state
        .kms
        .get_secret(&material, &request.secret_name)
        .await?;
    let enclave_key = crypto::generate_kbs_key();
    let encrypted = crypto::encrypt_for(
        &enclave_key,
        &pubkey,
        &request.kms_instance_id,
        &request.secret_name,
        &secret,
    )?;
    Ok(GetSecretResponse {
        enclave_pubkey: crypto::b64_encode(&crypto::encode_pubkey(&enclave_key.public_key())),
        encrypted_secret: crypto::b64_encode(&encrypted),
    })
}

#[post("/v1/get-secret")]
async fn get_secret(
    state: web::Data<WrapState>,
    request: web::Json<GetSecretRequest>,
) -> Result<HttpResponse, ApiError> {
    let response = release_secret(state.get_ref(), request.into_inner()).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn serve(listen: &str, state: WrapState) -> Result<()> {
    let state = web::Data::new(state);
    HttpServer::new(move || App::new().app_data(state.clone()).service(get_secret))
        .bind(listen)
        .with_context(|| format!("bind {listen}"))?
        .run()
        .await
        .context("wrap server")
}

pub async fn fetch_secret(
    enclave_url: &str,
    kms_instance_id: &str,
    secret_name: &str,
    quote: &[u8],
    kbs_secret: &SecretKey,
) -> Result<Vec<u8>> {
    let pubkey = crypto::encode_pubkey(&kbs_secret.public_key());
    let request = GetSecretRequest {
        kms_instance_id: kms_instance_id.to_string(),
        secret_name: secret_name.to_string(),
        kbs_pubkey: crypto::b64_encode(&pubkey),
        quote: crypto::b64_encode(quote),
    };
    let url = format!("{}/v1/get-secret", enclave_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request)
        .send()
        .await
        .context("call AAP wrap service")?
        .error_for_status()
        .context("AAP wrap service rejected the quote or the secret request")?;
    let body: GetSecretResponse = response.json().await.context("AAP wrap response")?;
    let enclave_pubkey = decode_pubkey(&crypto::b64_decode(&body.enclave_pubkey)?)?;
    let encrypted = crypto::b64_decode(&body.encrypted_secret)?;
    crypto::decrypt_from(
        kbs_secret,
        &enclave_pubkey,
        kms_instance_id,
        secret_name,
        &encrypted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::quote::{test_quote, TestQuotePolicy};
    use crate::store::TestStore;
    use zeroize::Zeroizing;

    struct Fixture {
        called: AtomicBool,
        body: Vec<u8>,
    }

    #[async_trait]
    impl KmsGet for Fixture {
        async fn get_secret(&self, material: &AapMaterial, name: &str) -> Result<Vec<u8>> {
            assert_eq!(material.client_key.as_str(), "CLIENT-KEY-SHOULD-NOT-LEAK");
            assert_eq!(name, "key.bin");
            self.called.store(true, Ordering::SeqCst);
            Ok(self.body.clone())
        }
    }

    fn state(called: Arc<Fixture>) -> WrapState {
        let material = AapMaterial {
            client_key: Zeroizing::new("CLIENT-KEY-SHOULD-NOT-LEAK".to_string()),
            password: Zeroizing::new("pw".to_string()),
            cert_pem: "cert".to_string(),
            kms_instance_id: "kst-lab".to_string(),
        };
        let store = Arc::new(TestStore::new());
        store
            .create(std::path::Path::new("aap-client.protected"), &material)
            .unwrap();
        WrapState {
            store,
            quotes: Arc::new(TestQuotePolicy),
            kms: called,
            file: std::path::PathBuf::from("aap-client.protected"),
        }
    }

    #[tokio::test]
    async fn attested_kbs_receives_the_secret_without_putting_the_client_key_on_the_request() {
        let fixture = Arc::new(Fixture {
            called: AtomicBool::new(false),
            body: b"coco-lab-sample-resource".to_vec(),
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = HttpServer::new({
            let fixture = fixture.clone();
            move || {
                App::new()
                    .app_data(web::Data::new(state(fixture.clone())))
                    .service(get_secret)
            }
        })
        .listen(listener)
        .unwrap()
        .run();
        let handle = tokio::spawn(server);

        let kbs = crypto::generate_kbs_key();
        let pubkey = crypto::encode_pubkey(&kbs.public_key());
        let quote = test_quote(&report_data(&pubkey));
        let secret = fetch_secret(
            &format!("http://{addr}"),
            "kst-lab",
            "key.bin",
            &quote,
            &kbs,
        )
        .await
        .unwrap();
        assert_eq!(secret, b"coco-lab-sample-resource");
        assert!(fixture.called.load(Ordering::SeqCst));

        let request = GetSecretRequest {
            kms_instance_id: "kst-lab".into(),
            secret_name: "key.bin".into(),
            kbs_pubkey: crypto::b64_encode(&pubkey),
            quote: crypto::b64_encode(&quote),
        };
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(!encoded.contains("CLIENT-KEY"));

        let bad = test_quote(&[0u8; 64]);
        assert!(
            fetch_secret(&format!("http://{addr}"), "kst-lab", "key.bin", &bad, &kbs)
                .await
                .is_err()
        );
        handle.abort();
    }

    #[test]
    fn kbs_config_rejects_client_key() {
        let err = serde_json::from_str::<crate::KbsAliyunEnclaveConfig>(
            r#"{"enclave_url":"http://127.0.0.1:8443","kms_instance_id":"kst-lab","client_key":"KA"}"#,
        );
        assert!(err.is_err());
    }
}
