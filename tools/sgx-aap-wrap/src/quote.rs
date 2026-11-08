// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};

pub trait QuotePolicy: Send + Sync {
    fn verify(&self, quote: &[u8], report_data: &[u8; 64]) -> Result<()>;
}

/// Production policy. DCAP is not linked, so verification fails closed.
pub struct DcapQuotePolicy;

impl QuotePolicy for DcapQuotePolicy {
    fn verify(&self, _quote: &[u8], _report_data: &[u8; 64]) -> Result<()> {
        bail!("DCAP quote verification is not linked into this build");
    }
}

/// Test policy. A quote is the prefix `test-quote:` followed by the 64-byte report data.
pub struct TestQuotePolicy;

impl QuotePolicy for TestQuotePolicy {
    fn verify(&self, quote: &[u8], report_data: &[u8; 64]) -> Result<()> {
        let found = quote
            .strip_prefix(b"test-quote:")
            .ok_or_else(|| anyhow::anyhow!("test quote prefix"))?;
        if found != report_data.as_slice() {
            bail!("quote report data does not bind the KBS public key");
        }
        Ok(())
    }
}

pub fn open_quote_policy(kind: &str) -> Result<Box<dyn QuotePolicy>> {
    match kind {
        "dcap" => Ok(Box::new(DcapQuotePolicy)),
        "test" => Ok(Box::new(TestQuotePolicy)),
        other => bail!("unknown quote policy {other}"),
    }
}

#[cfg(test)]
pub fn test_quote(report_data: &[u8; 64]) -> Vec<u8> {
    let mut quote = b"test-quote:".to_vec();
    quote.extend_from_slice(report_data);
    quote
}
