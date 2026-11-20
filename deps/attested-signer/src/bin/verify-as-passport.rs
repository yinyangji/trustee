// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use clap::Parser;
use trustee_attested_signer::{
    SessionExpectation, SignerChallenge, SignerEvidenceBundle, SignerTrustPolicy,
};

mod common;
use common::{read_json, read_limited};

/// Verify the AS's native TDX proof, then its application passport.
#[derive(Parser)]
struct Args {
    /// Locally approved release tuples and governance digests, not downloaded
    /// from the AS being verified.
    #[arg(long)]
    trust: PathBuf,
    /// Audience, locally generated session nonce/ID, actual session recipient,
    /// and the customer's expected policy hashes.
    #[arg(long)]
    session: PathBuf,
    #[arg(long)]
    token: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let trust: SignerTrustPolicy = read_json(&args.trust)?;
    trust.validate()?;
    let session: SessionExpectation = read_json(&args.session)?;
    let token = read_limited(&args.token, 256 * 1024)?;
    let token = std::str::from_utf8(&token)?.trim();
    // The unverified kid only selects the proof to request; it grants no trust.
    let kid = jsonwebtoken::decode_header(token)?
        .kid
        .context("passport is missing kid")?;
    let challenge = SignerChallenge::new()?;
    let request = challenge.request(kid)?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(45))
        .build()?;
    let mut response = client
        .post(format!("{}/signer-evidence", trust.issuer))
        .json(&request)
        .send()
        .await?
        .error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > 1024 * 1024 - body.len() {
            bail!("AS signer evidence exceeds 1 MiB");
        }
        body.extend_from_slice(&chunk);
    }
    let bundle: SignerEvidenceBundle = serde_json::from_slice(&body)?;
    let storage = key_value_storage::KvStorageProvider::new(Default::default());
    let verified = challenge.verify(bundle, &trust, storage).await?;
    verified.verify_application_passport(token, &session)?;
    println!("AS runtime, signing key, governance and application session verified");
    Ok(())
}
