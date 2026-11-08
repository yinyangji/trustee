// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};

/// Write exactly 64 bytes to `inblob` and read `outblob`.
///
/// `provider` and `generation` are read-only kernel files. This function does not open them.
pub fn exchange_report(report: &Path, report_data: &[u8; 64]) -> Result<Vec<u8>> {
    let mut input = OpenOptions::new()
        .write(true)
        .open(report.join("inblob"))
        .context("open TSM inblob")?;
    input.write_all(report_data)?;
    input.flush()?;
    let output = fs::read(report.join("outblob")).context("read TSM outblob")?;
    if output.is_empty() {
        bail!("TSM outblob is empty");
    }
    Ok(output)
}

pub fn read_host_tdx_quote(report_data: &[u8; 64]) -> Result<Vec<u8>> {
    let parent = PathBuf::from("/sys/kernel/config/tsm/report");
    let mut suffix = [0u8; 4];
    OsRng.fill_bytes(&mut suffix);
    let dir = parent.join(format!("kbs-{}-{}", std::process::id(), u32::from_ne_bytes(suffix)));
    fs::create_dir(&dir).context(
        "create TSM report directory; mount configfs at /sys/kernel/config and run with CAP_SYS_ADMIN",
    )?;
    let result = exchange_report(&dir, report_data);
    let _ = fs::remove_dir_all(&dir);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_writes_inblob_and_leaves_provider_untouched() {
        let dir = tempfile_dir();
        let provider = dir.join("provider");
        fs::write(&provider, b"tdx_guest").unwrap();
        fs::write(dir.join("inblob"), b"").unwrap();
        fs::write(dir.join("outblob"), b"quote-bytes").unwrap();
        let data = [9u8; 64];
        let quote = exchange_report(&dir, &data).unwrap();
        assert_eq!(quote, b"quote-bytes");
        assert_eq!(fs::read(dir.join("inblob")).unwrap(), data);
        assert_eq!(fs::read(provider).unwrap(), b"tdx_guest");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_outblob_is_an_error() {
        let dir = tempfile_dir();
        fs::write(dir.join("inblob"), b"").unwrap();
        fs::write(dir.join("outblob"), b"").unwrap();
        assert!(exchange_report(&dir, &[1u8; 64]).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    fn tempfile_dir() -> PathBuf {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let dir = std::env::temp_dir().join(format!("tsm-report-{}", u64::from_ne_bytes(nonce)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
