// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::Value;
use trustee_attested_signer::SignerConfig;

mod common;

/// Hash the actual self-attestation governance snapshot in an AS config file.
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config: Value = common::read_json(&args.config)?;
    let broker = &config["attestation_token_broker"];
    let profile: SignerConfig = serde_json::from_value(broker["self_attestation"].clone())?;
    profile.validate(
        broker["issuer_name"]
            .as_str()
            .context("missing issuer_name")?,
    )?;
    println!("{}", profile.governance.digest()?);
    Ok(())
}
