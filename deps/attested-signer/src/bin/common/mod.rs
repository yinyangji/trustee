// SPDX-License-Identifier: Apache-2.0

use std::{io::Read, path::Path};

use anyhow::{bail, Context, Result};

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_limited(path, 1024 * 1024)?)
        .with_context(|| format!("parse {}", path.display()))
}

pub fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    std::fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take((limit + 1) as u64)
        .read_to_end(&mut body)?;
    if body.len() > limit {
        bail!("input exceeds size limit");
    }
    Ok(body)
}
