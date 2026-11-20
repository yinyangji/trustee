// SPDX-License-Identifier: Apache-2.0

use anyhow::{ensure, Context, Result};
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, client::conn::http1, header, Request};
use hyper_util::rt::TokioIo;
use openssl::ssl::{SslConnector, SslMethod};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, pin::Pin, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_openssl::SslStream;
use trustee_attested_signer::{
    inference::{
        parse_audience, InferenceBinding, InferenceChallenge, InferenceRelease, InferenceResponse,
        InferenceSession, EVIDENCE_PATH, INFERENCE_PATH, VERIFY_PATH,
    },
    SignerTrustPolicy,
};

mod common;

const MAX_PROOF: usize = 2 * 1024 * 1024;

#[derive(Parser)]
struct Args {
    /// Local trust policy supplied by the relying party before opening a connection.
    #[arg(long)]
    trust: PathBuf,
    #[arg(long)]
    release: PathBuf,
    #[arg(long)]
    init_data: PathBuf,
    /// Independent admission token for the evidence route.
    #[arg(long)]
    evidence_token_file: PathBuf,
    /// Business credential sent only after the connection passes attestation.
    #[arg(long)]
    token_file: Option<PathBuf>,
    /// Optional trust anchor for the inference service's HTTPS certificate.
    #[arg(long)]
    guest_ca: Option<PathBuf>,
    /// Optional trust anchor for verify-as's HTTPS certificate.
    #[arg(long)]
    as_ca: Option<PathBuf>,
    /// Normal OpenAI-compatible request JSON to submit after successful appraisal.
    #[arg(long, requires = "token_file")]
    prompt_request: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    audience: String,
    release_id: String,
    as_release_manifest_digest: String,
    governance_digest: String,
    policy_hashes: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestEvidence {
    tee: String,
    evidence: Value,
    runtime_data: InferenceBinding,
}

async fn read_body(mut body: hyper::body::Incoming, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(chunk) = frame.into_data() {
            ensure!(
                chunk.len() <= max - bytes.len(),
                "response exceeds size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
    }
    Ok(bytes)
}

fn load_token(path: &std::path::Path) -> Result<String> {
    let bytes = common::read_limited(path, 1024)?;
    let token = std::str::from_utf8(&bytes)?.trim();
    ensure!(
        (32..=512).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid API token"
    );
    Ok(token.to_owned())
}

fn post_json(
    authority: &str,
    path: &str,
    token: &str,
    body: Vec<u8>,
) -> Result<Request<Full<Bytes>>> {
    Ok(Request::post(path)
        .header(header::HOST, authority)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Full::new(Bytes::from(body)))?)
}

fn evidence_request(
    authority: &str,
    admission_token: &str,
    binding: &InferenceBinding,
) -> Result<Request<Full<Bytes>>> {
    post_json(
        authority,
        EVIDENCE_PATH,
        admission_token,
        serde_json::to_vec(&InferenceChallenge {
            nonce: binding.nonce.clone(),
            session_id: binding.session_id.clone(),
        })?,
    )
}

/// One verified TLS connection is used for both requests. Hyper's connection-
/// level sender cannot reconnect or send the inference request to a new peer.
async fn verify_then_infer(args: Args) -> Result<()> {
    let trust: SignerTrustPolicy = common::read_json(&args.trust)?;
    trust.validate()?;
    let release: Release = common::read_json(&args.release)?;
    let target = parse_audience(&release.audience)?;
    let hostname = target.host_str().context("missing HTTPS hostname")?;
    let port = target
        .port_or_known_default()
        .context("missing HTTPS port")?;
    let evidence_token = load_token(&args.evidence_token_file)?;
    let inference_token = args.token_file.as_deref().map(load_token).transpose()?;
    ensure!(
        inference_token.as_ref() != Some(&evidence_token),
        "evidence and inference credentials must differ"
    );

    let mut connector = SslConnector::builder(SslMethod::tls_client())?;
    if let Some(path) = &args.guest_ca {
        connector.set_ca_file(path)?;
    }
    let ssl = connector.build().configure()?.into_ssl(hostname)?;
    let socket = TcpStream::connect((hostname, port)).await?;
    let mut tls = SslStream::new(ssl, socket)?;
    Pin::new(&mut tls).connect().await?;
    let peer_key = tls
        .ssl()
        .peer_certificate()
        .context("missing inference TLS peer certificate")?
        .public_key()?
        .public_key_to_der()?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(tls)).await?;
    let connection = tokio::spawn(connection);
    let host = target.authority();
    let session = InferenceSession::new(release.audience, release.release_id, &peer_key)?;
    let binding = session.binding();
    let result = sender
        .send_request(evidence_request(host, &evidence_token, binding)?)
        .await?;
    ensure!(
        result.status().is_success(),
        "guest attestation HTTP {}",
        result.status()
    );
    let guest: GuestEvidence =
        serde_json::from_slice(&read_body(result.into_body(), MAX_PROOF).await?)?;
    ensure!(
        guest.tee == "tdx" && &guest.runtime_data == binding,
        "guest evidence has a different binding"
    );
    let init_data = common::read_limited(&args.init_data, 256 * 1024)?;
    let appraisal = session.request(&guest.evidence, std::str::from_utf8(&init_data)?, None)?;

    let mut client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15));
    if let Some(path) = &args.as_ca {
        client = client.add_root_certificate(reqwest::Certificate::from_pem(
            &common::read_limited(path, 256 * 1024)?,
        )?);
    }
    let mut response = client
        .build()?
        .post(format!("{}{VERIFY_PATH}", trust.issuer))
        .json(&appraisal)
        .send()
        .await?
        .error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= MAX_PROOF - body.len(),
            "AS response exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    let response: InferenceResponse = serde_json::from_slice(&body)?;
    let signer = response
        .signer_evidence
        .context("missing AS signer evidence")?
        .verify(
            &trust,
            key_value_storage::KvStorageProvider::new(Default::default()),
        )
        .await?;
    session.verify(
        &response.ear,
        &signer,
        &trust,
        &InferenceRelease {
            as_release_manifest_digest: &release.as_release_manifest_digest,
            governance_digest: &release.governance_digest,
            policy_hashes: &release.policy_hashes,
        },
    )?;
    eprintln!("Inference guest and AS signer verified");

    if let Some(path) = &args.prompt_request {
        let prompt = common::read_limited(path, MAX_PROOF)?;
        let token = inference_token
            .as_deref()
            .context("missing inference credential")?;
        let response = sender
            .send_request(post_json(host, INFERENCE_PATH, token, prompt)?)
            .await?;
        ensure!(
            response.status().is_success(),
            "inference HTTP {}",
            response.status()
        );
        let mut body = response.into_body();
        let mut out = tokio::io::stdout();
        while let Some(frame) = body.frame().await {
            if let Ok(chunk) = frame?.into_data() {
                out.write_all(&chunk).await?;
                out.flush().await?;
            }
        }
    }
    connection.abort();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(300), verify_then_infer(Args::parse()))
        .await
        .context("inference session deadline exceeded")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_request_carries_only_the_admission_credential() {
        let binding = InferenceBinding {
            profile: trustee_attested_signer::inference::RUNTIME_PROFILE.into(),
            audience: "https://guest.example".into(),
            nonce: "01".repeat(32),
            session_id: "02".repeat(32),
            release_id: "r1".into(),
            tls_spki_sha256: "03".repeat(32),
        };
        let request = evidence_request("guest.example", &"e".repeat(32), &binding).unwrap();
        assert_eq!(request.uri().path(), EVIDENCE_PATH);
        assert_eq!(
            request.headers()[header::AUTHORIZATION],
            format!("Bearer {}", "e".repeat(32))
        );
    }
}
