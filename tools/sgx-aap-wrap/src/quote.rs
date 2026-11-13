// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};

pub trait QuotePolicy: Send + Sync {
    fn verify(&self, quote: &[u8], report_data: &[u8; 64]) -> Result<()>;
}

/// Accepts the quote bytes without checking them. This is the default while
/// Quote Verification Enclave is not installed.
pub struct AcceptQuotePolicy;

impl QuotePolicy for AcceptQuotePolicy {
    fn verify(&self, _quote: &[u8], _report_data: &[u8; 64]) -> Result<()> {
        Ok(())
    }
}

/// Host runs `tee_verify_quote`. The enclave then checks the QvE report.
pub struct DcapQuotePolicy;

impl QuotePolicy for DcapQuotePolicy {
    fn verify(&self, quote: &[u8], report_data: &[u8; 64]) -> Result<()> {
        crate::sgxfs::verify_tdx_quote(quote, report_data)
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
        "accept" => Ok(Box::new(AcceptQuotePolicy)),
        "dcap" => Ok(Box::new(DcapQuotePolicy)),
        "test" => Ok(Box::new(TestQuotePolicy)),
        other => bail!("unknown quote policy {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcap_policy_rejects_a_short_quote() {
        let err = DcapQuotePolicy
            .verify(b"quote", &[1u8; 64])
            .unwrap_err()
            .to_string();
        assert!(err.contains("too small"), "{err}");
    }

    #[test]
    fn accept_policy_ignores_the_quote_bytes() {
        let policy = open_quote_policy("accept").unwrap();
        policy.verify(b"", &[1u8; 64]).unwrap();
        policy.verify(b"not-a-quote", &[2u8; 64]).unwrap();
    }

    #[test]
    fn test_policy_requires_the_bound_report_data() {
        let policy = open_quote_policy("test").unwrap();
        let report = [7u8; 64];
        let mut quote = b"test-quote:".to_vec();
        quote.extend_from_slice(&report);
        policy.verify(&quote, &report).unwrap();
        assert!(policy.verify(&quote, &[8u8; 64]).is_err());
        assert!(open_quote_policy("other").is_err());
    }
}

#[cfg(test)]
pub fn test_quote(report_data: &[u8; 64]) -> Vec<u8> {
    let mut quote = b"test-quote:".to_vec();
    quote.extend_from_slice(report_data);
    quote
}
