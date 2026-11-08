// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sgx_aap_wrap::{
    material_from_json, open_quote_policy, serve, AapStore, KmsGet, SgxProtectedFs, WrapState,
    FILE_KEY_LEN,
};

#[derive(Parser)]
#[command(name = "sgx-aap-wrap")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write AAP material into an SGX protected file with sgx_fopen_auto_key.
    Store {
        #[arg(long)]
        material: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    /// Export the 128-bit protected-file key with sgx_fexport_auto_key.
    ExportKey {
        #[arg(long)]
        file: PathBuf,
        /// Destination for the 16-byte file key. Copy it off this host, then delete this copy.
        #[arg(long)]
        key_out: PathBuf,
    },
    /// Bind a protected file copied from another CPU with sgx_fimport_auto_key.
    Import {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
    },
    /// Serve secret requests. The client key is read inside the enclave.
    Serve {
        #[arg(long)]
        file: PathBuf,
        #[arg(long, default_value = "dcap")]
        quote_policy: String,
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let store = SgxProtectedFs;
    match cli.command {
        Command::Store { material, file } => {
            let loaded = material_from_json(&std::fs::read(&material)?)
                .with_context(|| format!("read {}", material.display()))?;
            store.create(&file, &loaded)?;
            Ok(())
        }
        Command::ExportKey { file, key_out } => {
            let key = store.export_file_key(&file)?;
            write_secret(&key_out, &key)?;
            eprintln!(
                "exported file key to {}. copy it off this host and delete the local copy",
                key_out.display()
            );
            Ok(())
        }
        Command::Import { file, key_file } => {
            let bytes =
                std::fs::read(&key_file).with_context(|| format!("read {}", key_file.display()))?;
            let key: [u8; FILE_KEY_LEN] = bytes
                .as_slice()
                .try_into()
                .context("file key must be 16 bytes")?;
            store.import_file_key(&file, &key)?;
            Ok(())
        }
        Command::Serve {
            file,
            quote_policy,
            listen,
        } => {
            if quote_policy == "dcap" {
                bail!("DCAP quote verification is not linked into this build; refusing to release secrets");
            }
            let quotes = open_quote_policy(&quote_policy)?;
            serve(
                &listen,
                WrapState {
                    store: Arc::new(store),
                    quotes: quotes.into(),
                    kms: aliyun_kms()?,
                    file,
                },
            )
            .await
        }
    }
}

fn write_secret(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    Ok(())
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
