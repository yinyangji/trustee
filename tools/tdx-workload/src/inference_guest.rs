// SPDX-License-Identifier: Apache-2.0

//! HTTPS entry point inside an already measured, policy-restricted TDX guest.
//! The inference engine listens on the same guest's loopback interface.

use tdx_workload::tdx_evidence;

use actix_web::{http::header, web, App, HttpRequest, HttpResponse, HttpServer};
use anyhow::{ensure, Context, Result};
use clap::Parser;
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
    x509::X509,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use trustee_attested_signer::inference::{require_tdx_evidence, InferenceBinding, RUNTIME_PROFILE};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    socket: SocketAddr,
    #[arg(long)]
    backend_port: u16,
    #[arg(long)]
    audience: String,
    #[arg(long)]
    release_id: String,
    #[arg(long)]
    expected_rtmr3: String,
    #[arg(long)]
    tls_cert: PathBuf,
    #[arg(long)]
    tls_key: PathBuf,
    /// Tenant API authentication material, provisioned inside this guest.
    #[arg(long)]
    token_file: PathBuf,
    /// The trusted measurement loader's binary TCG event journal.
    #[arg(long, default_value = "/run/tdx-workload/events.bin")]
    journal: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    nonce: String,
    session_id: String,
}

struct Guest {
    audience: String,
    release_id: String,
    tls_spki_sha256: String,
    expected_rtmr3: Vec<u8>,
    events: Vec<u8>,
    token: String,
    quote_slot: Arc<Semaphore>,
    backend: reqwest::Client,
    backend_port: u16,
}

impl Guest {
    fn authenticate(&self, request: &HttpRequest) -> bool {
        request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok())
            .and_then(|header| header.strip_prefix("Bearer "))
            .is_some_and(|token| {
                token.len() == self.token.len()
                    && openssl::memcmp::eq(token.as_bytes(), self.token.as_bytes())
            })
    }

    fn measurement_is_current(&self) -> bool {
        fs::read(tdx_evidence::RTMR3).is_ok_and(|rtmr| rtmr == self.expected_rtmr3)
    }

    async fn is_ready(&self) -> bool {
        if !self.measurement_is_current() {
            return false;
        }
        let backend = self
            .backend
            .get(format!("http://127.0.0.1:{}/health", self.backend_port));
        backend
            .timeout(Duration::from_secs(1))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }

    fn binding(&self, challenge: Challenge) -> InferenceBinding {
        InferenceBinding {
            profile: RUNTIME_PROFILE.into(),
            audience: self.audience.clone(),
            release_id: self.release_id.clone(),
            tls_spki_sha256: self.tls_spki_sha256.clone(),
            nonce: challenge.nonce,
            session_id: challenge.session_id,
        }
    }
}

async fn ready(guest: web::Data<Guest>) -> HttpResponse {
    if guest.is_ready().await {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::ServiceUnavailable().finish()
    }
}

async fn evidence(
    guest: web::Data<Guest>,
    request: HttpRequest,
    challenge: web::Json<Challenge>,
) -> HttpResponse {
    if !guest.authenticate(&request) {
        return HttpResponse::Unauthorized().finish();
    }
    if !guest.is_ready().await {
        return HttpResponse::ServiceUnavailable().finish();
    }
    let binding = guest.binding(challenge.into_inner());
    let Ok(report_data) = binding.report_data() else {
        return HttpResponse::BadRequest().finish();
    };
    let Ok(permit) = guest.quote_slot.clone().try_acquire_owned() else {
        return HttpResponse::ServiceUnavailable().finish();
    };
    let runtime = tokio::runtime::Handle::current();
    let quote = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        ensure!(
            guest.measurement_is_current(),
            "Workload measurement changed"
        );
        let evidence = runtime.block_on(tdx_evidence::collect(report_data, &guest.events))?;
        require_tdx_evidence(&evidence)?;
        ensure!(
            guest.measurement_is_current(),
            "Workload measurement changed"
        );
        Ok::<_, anyhow::Error>(evidence)
    });
    match tokio::time::timeout(Duration::from_secs(4), quote).await {
        Ok(Ok(Ok(evidence))) => HttpResponse::Ok()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(json!({"tee":"tdx", "evidence":evidence, "runtime_data":binding})),
        _ => HttpResponse::ServiceUnavailable().finish(),
    }
}

async fn infer(guest: web::Data<Guest>, request: HttpRequest, body: web::Bytes) -> HttpResponse {
    if !guest.authenticate(&request) {
        return HttpResponse::Unauthorized().finish();
    }
    if !guest.measurement_is_current() {
        return HttpResponse::ServiceUnavailable().finish();
    }
    let Ok(response) = guest
        .backend
        .post(format!(
            "http://127.0.0.1:{}/v1/chat/completions",
            guest.backend_port
        ))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
    else {
        return HttpResponse::BadGateway().finish();
    };
    let Ok(status) = actix_web::http::StatusCode::from_u16(response.status().as_u16()) else {
        return HttpResponse::BadGateway().finish();
    };
    let mut outgoing = HttpResponse::build(status);
    if let Some(content_type) = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
    {
        outgoing.insert_header((header::CONTENT_TYPE, content_type));
    }
    outgoing.streaming(response.bytes_stream())
}

#[actix_web::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let expected_rtmr3 = hex::decode(args.expected_rtmr3)?;
    ensure!(
        expected_rtmr3.len() == 48 && expected_rtmr3.iter().any(|b| *b != 0),
        "An approved, nonempty application RTMR[3] is required"
    );
    let mut events = Vec::new();
    let max_events = 256 * 1024;
    fs::File::open(&args.journal)?
        .take(max_events + 1)
        .read_to_end(&mut events)?;
    ensure!(
        !events.is_empty() && events.len() <= max_events as usize,
        "Invalid TCG event journal length"
    );
    let token = fs::read_to_string(args.token_file)?.trim().to_string();
    ensure!(
        token.len() >= 32 && token.len() <= 512 && token.bytes().all(|b| b.is_ascii_graphic()),
        "Invalid tenant API token"
    );

    let chain_path = args.tls_cert;
    let cert = X509::from_pem(&fs::read(&chain_path)?)?;
    let tls_spki_sha256 = hex::encode(Sha256::digest(cert.public_key()?.public_key_to_der()?));
    let mut tls = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    let key = PKey::private_key_from_pem(&fs::read(args.tls_key)?)?;
    tls.set_private_key(&key)?;
    tls.set_certificate_chain_file(chain_path)?;
    tls.check_private_key()?;

    let guest = web::Data::new(Guest {
        audience: args.audience,
        release_id: args.release_id,
        tls_spki_sha256,
        expected_rtmr3,
        events,
        token,
        backend_port: args.backend_port,
        quote_slot: Arc::new(Semaphore::new(1)),
        backend: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(300))
            .build()?,
    });
    guest
        .binding(Challenge {
            nonce: "01".repeat(32),
            session_id: "02".repeat(32),
        })
        .validate()?;
    ensure!(
        guest.measurement_is_current(),
        "Approved application RTMR[3] is not loaded"
    );
    HttpServer::new(move || {
        App::new()
            .app_data(guest.clone())
            .app_data(web::PayloadConfig::new(2 * 1024 * 1024))
            .app_data(web::JsonConfig::default().limit(1024))
            .route("/readyz", web::get().to(ready))
            .route("/attestation/evidence", web::post().to(evidence))
            .route("/v1/chat/completions", web::post().to(infer))
    })
    .bind_openssl(args.socket, tls)
    .context("start the TDX guest HTTPS endpoint")?
    .run()
    .await?;
    Ok(())
}
