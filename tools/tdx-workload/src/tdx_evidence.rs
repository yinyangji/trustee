// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use attester::{tdx::TdxAttester, Attester};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};

pub const RTMR3: &str = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384";

pub async fn collect(report_data: Vec<u8>, events: &[u8]) -> Result<Value> {
    let mut evidence = TdxAttester::new().get_evidence(report_data).await?;
    if !events.is_empty() {
        let encoded = evidence["cc_eventlog"]
            .as_str()
            .context("A boot event log is required for measured workloads")?;
        let mut log = STANDARD.decode(encoded)?;
        if !log.ends_with(&[0xff; 8]) {
            bail!("Unexpected CC event log terminator");
        }
        log.truncate(log.len() - 8);
        log.extend_from_slice(events);
        log.extend([0xff; 8]);
        evidence["cc_eventlog"] = json!(STANDARD.encode(log));
    }
    Ok(evidence)
}

pub fn tcg_event(content: &[u8]) -> Vec<u8> {
    let mut event = vec![];
    event.extend(4u32.to_le_bytes()); // TDX RTMR[3] maps to CC measurement register 4.
    event.extend(5u32.to_le_bytes()); // EV_ACTION; UTF-8 JSON manifest.
    event.extend(1u32.to_le_bytes());
    event.extend(0xcu16.to_le_bytes()); // SHA-384
    event.extend(Sha384::digest(content));
    event.extend((content.len() as u32).to_le_bytes());
    event.extend(content);
    event
}
