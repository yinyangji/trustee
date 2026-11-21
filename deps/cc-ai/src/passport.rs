//! Lightweight asset-owner RP: verify a normalized AS passport, an offline
//! approved job and fresh holder-of-key proof. No native evidence parsing and
//! no calls from KMS to AS, RVPS, or vendor collateral services.
use crate::*;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use openssl::{ecdsa::EcdsaSig, hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, sync::Mutex};

pub const CLAIM: &str = "tag:github.com,2026:confidential-containers/cc-ai-passport";
pub const POP_KEY: &str = "passport-pop-key";

/// Issued only after the AS verifies native evidence and all required policies.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Passport {
    pub profile: String,
    pub job: JobBinding,
    pub recipient_key: Value,
    pub pop_key: Value,
}

/// Only the AS calls this with quote-verified evidence and derived job binding.
pub fn from_verified_evidence(e: &Value, job: JobBinding) -> Result<Passport> {
    let recipient_key = public_jwk(&e["runtime_data_claims"]["tee-pubkey"])?;
    let pop_key = public_jwk(&e["runtime_data_claims"][POP_KEY])?;
    ensure!(
        pop_key != recipient_key,
        "PoP signing and resource encryption keys must be distinct"
    );
    ensure!(
        job.public_key_digest == sha384(&canonical(&recipient_key)?),
        "Recipient binding mismatch"
    );
    Ok(Passport {
        profile: "cc-ai.passport.v1".into(),
        job,
        recipient_key,
        pop_key,
    })
}

/// Register once in the owner's approval plane. Request-path verification does
/// not parse InitData, recompute measurements, or repeat the three signatures.
pub struct RegisteredJob {
    signed: SignedJob,
    digest: String,
    trust_digest: String,
}
impl RegisteredJob {
    pub fn new(signed: SignedJob, trust: &TrustPolicy, now: i64) -> Result<Self> {
        signed.verify(trust, now)?;
        Ok(Self {
            digest: sha384(&canonical(&signed.contract)?),
            trust_digest: sha384(&canonical(trust)?),
            signed,
        })
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub nonce: String,
    pub audience: String,
    pub resource: String,
    pub contract_digest: String,
    pub passport_digest: String,
    pub expires_at: i64,
}

/// A private JWS profile, NOT an assertion of OAuth DPoP conformance. ES256
/// signs the entire resource, audience, token hash and one-time nonce scope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RedemptionProof {
    pub profile: String,
    pub challenge: Challenge,
    pub issued_at: i64,
}

pub fn sign_redemption(challenge: &Challenge, private_pem: &[u8], now: i64) -> Result<String> {
    let header = B64.encode(br#"{"alg":"ES256","typ":"cc-ai-pop+jws"}"#);
    let payload = B64.encode(canonical(&RedemptionProof {
        profile: "cc-ai.redemption.v1".into(),
        challenge: challenge.clone(),
        issued_at: now,
    })?);
    let input = format!("{header}.{payload}");
    let key = PKey::private_key_from_pem(private_pem)?;
    // Same curve/point checks as the AS-confirmed public key.
    public_jwk_from_pem(&key.public_key_to_pem()?)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(input.as_bytes())?;
    let sig = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
    Ok(format!(
        "{input}.{}",
        B64.encode([sig.r().to_vec_padded(32)?, sig.s().to_vec_padded(32)?].concat())
    ))
}

fn jwk_pem(key: &Value) -> Result<Vec<u8>> {
    let k = public_jwk(key)?;
    let x = openssl::bn::BigNum::from_slice(&B64.decode(k["x"].as_str().context("Missing x")?)?)?;
    let y = openssl::bn::BigNum::from_slice(&B64.decode(k["y"].as_str().context("Missing y")?)?)?;
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
    let ec = openssl::ec::EcKey::from_public_key_affine_coordinates(&group, &x, &y)?;
    Ok(PKey::from_ec_key(ec)?.public_key_to_pem()?)
}

/// Host adapter passes this one-use authorization to its existing KMS backend.
/// It must wrap only this resource to recipient_key (JWE/approved KMS wrapping).
/// Never return a plaintext DEK or reinterpret this as permission for any key.
pub struct VerifiedRelease {
    resource: String,
    recipient_key: Value,
    job_id: String,
    contract_digest: String,
}
impl VerifiedRelease {
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn recipient_key(&self) -> &Value {
        &self.recipient_key
    }
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }
}

pub struct AssetPassportVerifier {
    policy: RelyingPartyPolicy,
    as_public_key: Vec<u8>,
    challenges: Mutex<BTreeMap<String, Challenge>>,
}
impl AssetPassportVerifier {
    pub fn new(policy: RelyingPartyPolicy, as_public_key: Vec<u8>) -> Result<Self> {
        policy.validate()?;
        ensure!(
            policy.role != Role::User,
            "Asset RP must be a data/model owner"
        );
        public_jwk_from_pem(&as_public_key)?;
        Ok(Self {
            policy,
            as_public_key,
            challenges: Mutex::new(BTreeMap::new()),
        })
    }

    fn appraise(
        &self,
        registered: &RegisteredJob,
        token: &str,
        resource: &str,
        now: i64,
    ) -> Result<Passport> {
        ensure!(
            registered.trust_digest == sha384(&canonical(&self.policy.trust)?),
            "Approval must be re-registered after trust policy changes"
        );
        let c = &registered.signed.contract;
        c.validate(now)?;
        ensure!(
            !self.policy.trust.revoked_jobs.contains(&c.job_id)
                && c.policy_epoch >= self.policy.trust.minimum_policy_epoch,
            "Job approval revoked"
        );
        let claims = verify_pinned_result(token, &self.as_public_key)?;
        check_token(
            &claims,
            &self.policy.issuer,
            &self.policy.audience,
            self.policy.max_token_age_seconds,
            now,
        )?;
        let p: Passport = serde_json::from_value(claims[CLAIM].clone())?;
        ensure!(
            p.profile == "cc-ai.passport.v1"
                && p.job.contract_digest == registered.digest
                && p.job.job_id == c.job_id
                && p.job.tenant_id == c.tenant_id
                && p.job.policy_epoch == c.policy_epoch,
            "Passport is not for the owner's approved job"
        );
        ensure!(
            p.pop_key == public_jwk(&p.pop_key)?
                && p.recipient_key == public_jwk(&p.recipient_key)?
                && claims["cnf"]["jwk"] == p.pop_key
                && p.pop_key != p.recipient_key,
            "Invalid PoP confirmation or key separation"
        );
        ensure!(
            p.job.public_key_digest == sha384(&canonical(&public_jwk(&p.recipient_key)?)?),
            "Invalid recipient key binding"
        );
        let stage = c
            .stages
            .iter()
            .find(|s| s.stage == p.job.stage)
            .context("Unapproved passport stage")?;
        ensure!(
            stage.grants.iter().any(|g| g.role == self.policy.role
                && g.audience == self.policy.audience
                && g.resource == resource),
            "Asset not granted at this stage"
        );
        Ok(p)
    }

    /// Called by an authenticated/rate-limited KMS adapter. Caches only a bounded
    /// pending redemption, never a DEK. Nonces expire after at most 60 seconds.
    pub fn challenge(
        &self,
        job: &RegisteredJob,
        token: &str,
        resource: &str,
        now: i64,
    ) -> Result<Challenge> {
        self.appraise(job, token, resource, now)?;
        let mut random = [0u8; 32];
        openssl::rand::rand_bytes(&mut random)?;
        let challenge = Challenge {
            nonce: hex::encode(random),
            audience: self.policy.audience.clone(),
            resource: resource.into(),
            contract_digest: job.digest.clone(),
            passport_digest: sha384(token.as_bytes()),
            expires_at: now
                .checked_add(60)
                .context("Challenge timestamp overflow")?,
        };
        let mut cache = self
            .challenges
            .lock()
            .map_err(|_| anyhow::anyhow!("Challenge cache unavailable"))?;
        cache.retain(|_, c| c.expires_at > now);
        ensure!(cache.len() < 4096, "Pending challenge capacity reached");
        cache.insert(challenge.nonce.clone(), challenge.clone());
        Ok(challenge)
    }

    /// Proof is checked against AS-confirmed PoP key, never a proof-header JWK.
    /// Atomic removal permits one backend call per nonce under concurrency.
    pub fn redeem(
        &self,
        job: &RegisteredJob,
        token: &str,
        nonce: &str,
        proof: &str,
        now: i64,
    ) -> Result<VerifiedRelease> {
        ensure!(
            proof.len() <= 8192 && nonce.len() == 64,
            "Invalid PoP message size"
        );
        let challenge = self
            .challenges
            .lock()
            .map_err(|_| anyhow::anyhow!("Challenge cache unavailable"))?
            .get(nonce)
            .cloned()
            .context("Unknown or already consumed challenge")?;
        ensure!(
            now < challenge.expires_at && challenge.passport_digest == sha384(token.as_bytes()),
            "Expired challenge or token substitution"
        );
        let p = self.appraise(job, token, &challenge.resource, now)?;
        let header: Value = serde_json::from_slice(
            &B64.decode(proof.split('.').next().context("Invalid PoP JWS")?)?,
        )?;
        ensure!(header["typ"] == "cc-ai-pop+jws", "Wrong PoP JWS type");
        let verified: RedemptionProof =
            serde_json::from_value(verify_pinned_result(proof, &jwk_pem(&p.pop_key)?)?)?;
        ensure!(
            verified.profile == "cc-ai.redemption.v1"
                && verified.challenge == challenge
                && verified.issued_at <= now
                && now
                    .checked_sub(verified.issued_at)
                    .is_some_and(|age| (0..=60).contains(&age)),
            "PoP scope or freshness mismatch"
        );
        let consumed = self
            .challenges
            .lock()
            .map_err(|_| anyhow::anyhow!("Challenge cache unavailable"))?
            .remove(nonce);
        ensure!(
            consumed.as_ref() == Some(&challenge),
            "Challenge already consumed concurrently"
        );
        Ok(VerifiedRelease {
            resource: challenge.resource,
            recipient_key: p.recipient_key,
            job_id: p.job.job_id,
            contract_digest: p.job.contract_digest,
        })
    }
}
