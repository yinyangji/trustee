// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! AAP client-key wrap.
//!
//! The KBS process never receives `client_key`. It proves a TDX quote whose
//! `REPORTDATA` binds an ephemeral P-256 key, and this service returns the
//! requested KMS secret encrypted to that key.
//!
//! SGX sealing and DCAP verification are fail-closed in this tree. The `dev`
//! sealer and `test` quote policy exist so the protocol can be tested without
//! pretending to be SGX.

mod crypto;
mod material;
mod quote;
mod seal;
mod server;
mod tdx;

pub use crypto::{encode_pubkey, generate_kbs_key, report_data};
pub use material::{material_from_json, AapMaterial, KbsAliyunEnclaveConfig};
pub use quote::{open_quote_policy, DcapQuotePolicy, QuotePolicy, TestQuotePolicy};
pub use seal::{open_sealer, AapSealer, DevSealer, SgxSealer};
pub use server::{
    fetch_secret, serve, GetSecretRequest, GetSecretResponse, KmsGet, WrapState,
};
pub use tdx::{exchange_report, read_host_tdx_quote};

#[cfg(feature = "aliyun")]
pub use server::AliyunKmsOp;
