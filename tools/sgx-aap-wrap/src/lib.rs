// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! AAP client-key wrap.
//!
//! The KBS process never receives `client_key`. It proves a TDX quote whose
//! `REPORTDATA` binds an ephemeral P-256 key, and this service returns the
//! requested KMS secret encrypted to that key.
//!
//! The client key is stored with `sgx_fopen_auto_key`. `sgx_fexport_auto_key`
//! exports the 128-bit file key for backup. `sgx_fimport_auto_key` opens that
//! file on another CPU. `sgx_seal_data` is not used.

mod crypto;
mod material;
mod quote;
mod server;
mod sgxfs;
mod store;
mod tdx;

pub use crypto::{encode_pubkey, generate_kbs_key, report_data};
pub use material::{material_from_json, AapMaterial, KbsAliyunEnclaveConfig};
pub use quote::{open_quote_policy, DcapQuotePolicy, QuotePolicy, TestQuotePolicy};
pub use server::{fetch_secret, serve, GetSecretRequest, GetSecretResponse, KmsGet, WrapState};
pub use sgxfs::FILE_KEY_LEN;
pub use store::{AapStore, SgxProtectedFs};
pub use tdx::{exchange_report, read_host_tdx_quote};

#[cfg(feature = "aliyun")]
pub use server::AliyunKmsOp;
