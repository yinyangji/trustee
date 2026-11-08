// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Host-side calls into the enclave protected file.
//!
//! The enclave owns `sgx_fopen_auto_key`, `sgx_fexport_auto_key`, and
//! `sgx_fimport_auto_key`. This module only passes bytes across that boundary.

use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

pub const FILE_KEY_LEN: usize = 16;
const FILE_NAME_MISMATCH: i32 = 0x7003;

pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    Enclave::get()?;
    let path = c_path(path)?;
    let rc = unsafe { aap_fs_create(path.as_ptr(), bytes.as_ptr(), bytes.len()) };
    check("sgx_fopen_auto_key", &path, rc)
}

pub fn read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    Enclave::get()?;
    let path = c_path(path)?;
    let mut buf = vec![0u8; cap];
    let mut out_len = 0usize;
    let rc = unsafe { aap_fs_read(path.as_ptr(), buf.as_mut_ptr(), buf.len(), &mut out_len) };
    check("sgx_fopen_auto_key", &path, rc)?;
    buf.truncate(out_len);
    Ok(buf)
}

pub fn export_auto_key(path: &Path) -> Result<[u8; FILE_KEY_LEN]> {
    Enclave::get()?;
    let path = c_path(path)?;
    let mut key = [0u8; FILE_KEY_LEN];
    let rc = unsafe { aap_fs_export_key(path.as_ptr(), key.as_mut_ptr()) };
    check("sgx_fexport_auto_key", &path, rc)?;
    Ok(key)
}

pub fn import_auto_key(path: &Path, key: &[u8; FILE_KEY_LEN]) -> Result<()> {
    Enclave::get()?;
    let path = c_path(path)?;
    let rc = unsafe { aap_fs_import_key(path.as_ptr(), key.as_ptr()) };
    check("sgx_fimport_auto_key", &path, rc)
}

struct Enclave;

impl Enclave {
    fn get() -> Result<()> {
        static INIT: OnceLock<Result<(), String>> = OnceLock::new();
        let result = INIT.get_or_init(|| {
            let path = enclave_path();
            let c_path = CString::new(os_bytes(path.as_os_str()))
                .map_err(|_| format!("enclave path {}", path.display()))?;
            let rc = unsafe { aap_fs_init(c_path.as_ptr()) };
            if rc != 0 {
                return Err(format!(
                    "sgx_create_enclave {} returned {rc}",
                    path.display()
                ));
            }
            Ok(())
        });
        result.clone().map_err(|err| anyhow::anyhow!(err))
    }
}

fn enclave_path() -> PathBuf {
    std::env::var_os("SGX_AAP_ENCLAVE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("enclave/build/libenclave.signed.so")
        })
}

fn c_path(path: &Path) -> Result<CString> {
    CString::new(os_bytes(path.as_os_str())).context("path contains an interior nul")
}

fn os_bytes(path: &OsStr) -> &[u8] {
    path.as_bytes()
}

fn check(op: &str, path: &CString, rc: i32) -> Result<()> {
    if rc == 0 {
        return Ok(());
    }
    let shown = path.to_string_lossy();
    if rc == -FILE_NAME_MISMATCH {
        bail!("{op} {shown} failed: the protected file basename is bound into the metadata and must stay unchanged");
    }
    bail!("{op} {shown} returned {rc}")
}

extern "C" {
    fn aap_fs_init(signed_enclave: *const libc::c_char) -> i32;
    fn aap_fs_create(path: *const libc::c_char, data: *const u8, len: usize) -> i32;
    fn aap_fs_read(path: *const libc::c_char, buf: *mut u8, cap: usize, out_len: *mut usize)
        -> i32;
    fn aap_fs_export_key(path: *const libc::c_char, key: *mut u8) -> i32;
    fn aap_fs_import_key(path: *const libc::c_char, key: *const u8) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renamed_import_reports_the_basename_constraint() {
        let path = CString::new("renamed.protected").unwrap();
        let err = check("sgx_fimport_auto_key", &path, -FILE_NAME_MISMATCH)
            .unwrap_err()
            .to_string();
        assert!(err.contains("basename"), "{err}");
    }
}
