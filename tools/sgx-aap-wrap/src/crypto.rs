// Copyright (c) 2026 The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha384};

pub fn generate_kbs_key() -> SecretKey {
    SecretKey::random(&mut OsRng)
}

pub fn encode_pubkey(key: &PublicKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

/// First 48 bytes are SHA-384 of the uncompressed SEC1 public key. The rest is zero.
pub fn report_data(pubkey: &[u8]) -> [u8; 64] {
    let digest = Sha384::digest(pubkey);
    let mut out = [0u8; 64];
    out[..48].copy_from_slice(&digest);
    out
}

pub fn decode_pubkey(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes).context("KBS public key")
}

fn aad(kms_instance_id: &str, secret_name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(kms_instance_id.len() as u64).to_be_bytes());
    out.extend_from_slice(kms_instance_id.as_bytes());
    out.extend_from_slice(&(secret_name.len() as u64).to_be_bytes());
    out.extend_from_slice(secret_name.as_bytes());
    out
}

fn aead_key(shared: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"sgx-aap-wrap-v1");
    hasher.update(shared);
    hasher.finalize().into()
}

fn shared_secret(secret: &SecretKey, peer: &PublicKey) -> Result<Vec<u8>> {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}

pub fn encrypt_for(
    sender: &SecretKey,
    recipient: &PublicKey,
    kms_instance_id: &str,
    secret_name: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let shared = shared_secret(sender, recipient)?;
    let key = aead_key(&shared);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key).context("AES-256-GCM key")?;
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).context("AES-GCM nonce")?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &aad(kms_instance_id, secret_name),
            },
        )
        .map_err(|_| anyhow::anyhow!("encrypt KMS secret"))?;
    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_from(
    recipient: &SecretKey,
    sender: &PublicKey,
    kms_instance_id: &str,
    secret_name: &str,
    blob: &[u8],
) -> Result<Vec<u8>> {
    if blob.len() < 12 + 16 {
        bail!("encrypted secret is too short");
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let shared = shared_secret(recipient, sender)?;
    let key = aead_key(&shared);
    let cipher = Aes256Gcm::new_from_slice(&key).context("AES-256-GCM key")?;
    let nonce = Nonce::try_from(nonce_bytes).context("AES-GCM nonce")?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad(kms_instance_id, secret_name),
            },
        )
        .map_err(|_| anyhow::anyhow!("decrypt KMS secret"))
}

pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Result<Vec<u8>> {
    STANDARD.decode(text).context("base64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_binds_the_public_key() {
        let secret = generate_kbs_key();
        let encoded = encode_pubkey(&secret.public_key());
        let bound = report_data(&encoded);
        assert_eq!(&bound[..48], Sha384::digest(&encoded).as_slice());
        assert!(bound[48..].iter().all(|byte| *byte == 0));
        assert_ne!(report_data(b"other"), bound);
    }

    #[test]
    fn encrypt_round_trip() {
        let kbs = generate_kbs_key();
        let enclave = generate_kbs_key();
        let blob = encrypt_for(
            &enclave,
            &kbs.public_key(),
            "kst-1",
            "key.bin",
            b"resource",
        )
        .unwrap();
        let plain = decrypt_from(&kbs, &enclave.public_key(), "kst-1", "key.bin", &blob).unwrap();
        assert_eq!(plain, b"resource");
        assert!(decrypt_from(&kbs, &enclave.public_key(), "kst-2", "key.bin", &blob).is_err());
    }
}
