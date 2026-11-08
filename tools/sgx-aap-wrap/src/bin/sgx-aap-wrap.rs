// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sgx_aap_wrap::{
    material_from_json, open_quote_policy, open_sealer, serve, KmsGet, WrapState,
};

#[derive(Parser)]
#[command(name = "sgx-aap-wrap")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Seal an AAP material JSON file. `--seal sgx` refuses in this build.
    Seal {
        #[arg(long, default_value = "sgx")]
        seal: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        material: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Serve secret requests. `--seal sgx` and `--quote-policy dcap` refuse in this build.
    Serve {
        #[arg(long, default_value = "sgx")]
        seal: String,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long)]
        blob: PathBuf,
        #[arg(long, default_value = "dcap")]
        quote_policy: String,
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Seal {
            seal,
            key_file,
            material,
            out,
        } => {
            let key = read_key(key_file.as_deref())?;
            let sealer = open_sealer(&seal, key.as_deref())?;
            let loaded = material_from_json(&std::fs::read(&material)?)
                .with_context(|| format!("read {}", material.display()))?;
            let sealed = sealer.seal(&loaded)?;
            std::fs::write(&out, sealed).with_context(|| format!("write {}", out.display()))?;
            Ok(())
        }
        Command::Serve {
            seal,
            key_file,
            blob,
            quote_policy,
            listen,
        } => {
            if seal == "sgx" {
                bail!("SGX seal is not linked into this build; refusing to unseal an AAP client key in a normal process");
            }
            if quote_policy == "dcap" {
                bail!("DCAP quote verification is not linked into this build; refusing to release secrets");
            }
            let key = read_key(key_file.as_deref())?;
            let sealer = open_sealer(&seal, key.as_deref())?;
            let quotes = open_quote_policy(&quote_policy)?;
            let bytes = std::fs::read(&blob).with_context(|| format!("read {}", blob.display()))?;
            serve(
                &listen,
                WrapState {
                    sealer: sealer.into(),
                    quotes: quotes.into(),
                    kms: aliyun_kms()?,
                    blob: Arc::new(bytes),
                },
            )
            .await
        }
    }
}

fn aliyun_kms() -> Result<Arc<dyn KmsGet>> {
    #[cfg(feature = "aliyun")]
    {
        Ok(Arc::new(sgx_aap_wrap::AliyunKmsOp))
    }
    #[cfg(not(feature = "aliyun"))]
    {
        bail!("rebuild sgx-aap-wrap with --features aliyun before it can call KMS")
    }
}

fn read_key(path: Option<&std::path::Path>) -> Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(Some(bytes))
}
