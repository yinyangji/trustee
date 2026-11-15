//! One request per process. Secrets travel over private pipes, never argv/logs.
use anyhow::{bail, Result};
use std::io::{Read, Write};
use trustee_platform_api::credentials::{ProviderRequest, ProviderResponse, MAX_MESSAGE};
use zeroize::Zeroizing;

fn run() -> Result<()> {
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((MAX_MESSAGE + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() > MAX_MESSAGE {
        bail!("request too large");
    }
    let request: ProviderRequest = serde_json::from_slice(&input)?;
    let response = sgx_aap_wrap::key_provider::handle(request)?;
    let output = Zeroizing::new(serde_json::to_vec(&response)?);
    std::io::stdout().write_all(&output)?;
    Ok(())
}

fn main() {
    if run().is_err() {
        let error = ProviderResponse::Error {
            code: "operation_failed".into(),
        };
        if let Ok(output) = serde_json::to_vec(&error) {
            let _ = std::io::stdout().write_all(&output);
        }
        std::process::exit(1);
    }
}
