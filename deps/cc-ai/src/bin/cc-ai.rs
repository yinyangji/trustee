//! Offline control-plane tools. Private keys are read from files, never argv.
use anyhow::{ensure, Context, Result};
use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use std::{fs, path::PathBuf};
use trustee_cc_ai::*;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Sign the canonical contract using one party's P-256 private key.
    Sign {
        #[arg(long)]
        contract: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Combine three detached files containing compact JWSs and verify them.
    Assemble {
        #[arg(long)]
        contract: PathBuf,
        #[arg(long, num_args = 3)]
        signatures: Vec<PathBuf>,
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        job: PathBuf,
        #[arg(long)]
        trust: PathBuf,
    },
    /// Add the verified job to TOML BEFORE calculating launch InitData digest.
    InitData {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        job: PathBuf,
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify an AS signature plus passport claims. peer-key must be obtained
    /// from an authenticated TLS/application channel; this is not a TLS client.
    VerifyPassport {
        #[arg(long)]
        token: PathBuf,
        #[arg(long)]
        as_public_key: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        contract_digest: String,
        #[arg(long)]
        peer_key: PathBuf,
    },
    /// Print a fresh 256-bit nonce for a service passport request.
    Challenge,
}
fn read<T: DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let bytes = fs::read(path)?;
    ensure!(bytes.len() <= 256 * 1024, "Input document too large");
    Ok(serde_json::from_slice(&bytes)?)
}
fn save(path: PathBuf, content: &[u8]) -> Result<()> {
    use std::io::Write;
    // Never overwrite an existing approval artifact accidentally.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    f.write_all(content)?;
    Ok(())
}
fn main() -> Result<()> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    match Args::parse().command {
        Command::Sign {
            contract,
            key_id,
            key,
            output,
        } => {
            let contract: JobContract = read(&contract)?;
            contract.validate(now)?;
            let signature = sign_contract(&contract, &key_id, &fs::read(key)?)?;
            save(output, signature.as_bytes())?;
        }
        Command::Assemble {
            contract,
            signatures,
            trust,
            output,
        } => {
            let job = SignedJob {
                contract: read(&contract)?,
                signatures: signatures
                    .into_iter()
                    .map(|p| fs::read_to_string(p).map(|s| s.trim().to_string()))
                    .collect::<std::io::Result<_>>()?,
            };
            job.verify(&read(&trust)?, now)?;
            save(output, &canonical(&job)?)?;
        }
        Command::Verify { job, trust } => {
            let job: SignedJob = read(&job)?;
            job.verify(&read(&trust)?, now)?;
            println!("{}", sha384(&canonical(&job.contract)?));
        }
        Command::InitData {
            input,
            job,
            trust,
            output,
        } => {
            let job: SignedJob = read(&job)?;
            job.verify(&read(&trust)?, now)?;
            let mut data: toml::Value = toml::from_str(&fs::read_to_string(input)?)?;
            ensure!(
                data["algorithm"].as_str() == Some("sha384"),
                "TDX job InitData must use sha384"
            );
            let fields = data
                .get_mut("data")
                .and_then(toml::Value::as_table_mut)
                .context("Missing InitData data table")?;
            ensure!(
                fields.contains_key("policy.rego") && !fields.contains_key(INIT_DATA_KEY),
                "Agent Policy required; job must not already be present"
            );
            ensure!(
                fields["policy.rego"]
                    .as_str()
                    .is_some_and(|p| sha384(p.as_bytes()) == job.contract.agent_policy_digest),
                "Agent Policy is not approved by contract"
            );
            fields.insert(
                INIT_DATA_KEY.into(),
                toml::Value::String(String::from_utf8(canonical(&job)?)?),
            );
            save(output, toml::to_string(&data)?.as_bytes())?;
        }
        Command::VerifyPassport {
            token,
            as_public_key,
            policy,
            nonce,
            job_id,
            contract_digest,
            peer_key,
        } => {
            let claims =
                verify_pinned_result(fs::read_to_string(token)?.trim(), &fs::read(as_public_key)?)?;
            let binding = verify_passport(
                &claims,
                &read(&policy)?,
                &PassportExpectation {
                    nonce: &nonce,
                    job_id: &job_id,
                    contract_digest: &contract_digest,
                    peer_key: &read(&peer_key)?,
                },
                now,
            )?;
            println!("{}", serde_json::to_string(&binding)?);
        }
        Command::Challenge => {
            let mut nonce = [0u8; 32];
            openssl::rand::rand_bytes(&mut nonce)?;
            println!("{}", hex::encode(nonce));
        }
    }
    Ok(())
}
