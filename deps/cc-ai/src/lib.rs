//! Three-party job authorization. Evidence inputs MUST already have passed a
//! native verifier (AS), or a pinned AS signature verifier (RP).
//! This module never promotes guest runtime-data into application measurements.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    sign::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};

pub const INIT_DATA_KEY: &str = "cc-ai.job";
pub const AGENT_POLICY_DIGEST: &str = "cc-ai.agent-policy-sha384";
pub const CLAIM: &str = "tag:github.com,2026:confidential-containers/cc-ai";
pub const SCHEMA: &str = "cc-ai.job.v1";
const MAX_DOCUMENT: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Data,
    Model,
    User,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    Train,
    Infer,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    ApplicationReady,
    ModelVerified,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub role: Role,
    pub audience: String,
    /// Existing KBS three-component resource path, e.g. workload/model/v7.
    pub resource: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StageReference {
    pub stage: Stage,
    /// Approved final TDX RTMR3 value, derived OFFLINE from release artifacts.
    pub measurement: String,
    pub grants: Vec<Grant>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobContract {
    pub schema: String,
    pub job_id: String,
    pub tenant_id: String,
    pub purpose: Purpose,
    /// Party identifiers, not caller-selected signing key identifiers.
    pub parties: BTreeMap<Role, String>,
    pub release_id: String,
    pub model_id: String,
    /// Digest of the exact Agent Policy, avoiding an InitData self-hash cycle.
    pub agent_policy_digest: String,
    pub output_policy_digest: String,
    pub recipient_key_digest: String,
    pub policy_epoch: u64,
    pub not_before: i64,
    pub expires_at: i64,
    /// This release supports one CPU TDX protection domain only.
    pub require_gpu: bool,
    pub members: u32,
    pub stages: Vec<StageReference>,
    /// Audiences allowed to verify a model-verified service passport.
    pub service_audiences: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedJob {
    pub contract: JobContract,
    /// Three compact ES256 JWSs over the identical JCS-encoded contract.
    pub signatures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub key_id: String,
    pub party_id: String,
    pub role: Role,
    pub public_key_pem: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub authorities: Vec<Authority>,
    pub minimum_policy_epoch: u64,
    #[serde(default)]
    pub revoked_jobs: BTreeSet<String>,
}

fn identifier(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._:/@".contains(&c))
}

fn digest(v: &str) -> bool {
    v.len() == 96
        && v.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && v.bytes().any(|c| c != b'0')
}

pub fn canonical<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let bytes = serde_json_canonicalizer::to_vec(v)?;
    ensure!(
        bytes.len() <= MAX_DOCUMENT,
        "CC-AI document exceeds size limit"
    );
    Ok(bytes)
}

pub fn sha384(v: &[u8]) -> String {
    hex::encode(Sha384::digest(v))
}

/// P-256 is the initial AI profile. Normalize away key usage hints so a TLS
/// certificate and the RCAR ECDH key have the same cryptographic identity.
pub fn public_jwk(v: &Value) -> Result<Value> {
    ensure!(
        v["kty"] == "EC" && v["crv"] == "P-256",
        "CC-AI requires a P-256 public key"
    );
    let x = B64.decode(v["x"].as_str().context("Missing key x")?)?;
    let y = B64.decode(v["y"].as_str().context("Missing key y")?)?;
    ensure!(
        x.len() == 32 && y.len() == 32,
        "Invalid P-256 coordinate length"
    );
    let group = openssl::ec::EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let (bx, by) = (BigNum::from_slice(&x)?, BigNum::from_slice(&y)?);
    openssl::ec::EcKey::from_public_key_affine_coordinates(&group, &bx, &by)?.check_key()?;
    Ok(json!({"kty":"EC","crv":"P-256","x":B64.encode(x),"y":B64.encode(y)}))
}

pub fn public_jwk_from_pem(pem: &[u8]) -> Result<Value> {
    let key = PKey::public_key_from_pem(pem)?.ec_key()?;
    ensure!(
        key.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
        "Channel key must be P-256"
    );
    let (mut x, mut y) = (BigNum::new()?, BigNum::new()?);
    let mut ctx = openssl::bn::BigNumContext::new()?;
    key.public_key()
        .affine_coordinates_gfp(key.group(), &mut x, &mut y, &mut ctx)?;
    public_jwk(
        &json!({"kty":"EC","crv":"P-256","x":B64.encode(x.to_vec_padded(32)?),"y":B64.encode(y.to_vec_padded(32)?)}),
    )
}

impl TrustPolicy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (3..=64).contains(&self.authorities.len()),
            "Configure 3..64 contract authorities"
        );
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for a in &self.authorities {
            ensure!(
                identifier(&a.key_id) && identifier(&a.party_id),
                "Invalid authority identifier"
            );
            ensure!(ids.insert(&a.key_id), "Duplicate authority key ID");
            let key = PKey::public_key_from_pem(a.public_key_pem.as_bytes())?;
            ensure!(
                key.ec_key()?.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
                "Contract key must be P-256"
            );
            ensure!(
                keys.insert(key.public_key_to_der()?),
                "Authority keys must be independent"
            );
            roles.insert(a.role.clone());
        }
        ensure!(roles.len() == 3, "All three authority roles are required");
        Ok(())
    }
}

impl JobContract {
    pub fn validate(&self, now: i64) -> Result<()> {
        ensure!(self.schema == SCHEMA, "Unsupported job contract schema");
        for v in [
            &self.job_id,
            &self.tenant_id,
            &self.release_id,
            &self.model_id,
        ] {
            ensure!(identifier(v), "Invalid job identifier");
        }
        ensure!(
            self.parties.len() == 3
                && [Role::Data, Role::Model, Role::User]
                    .iter()
                    .all(|r| self.parties.get(r).is_some_and(|p| identifier(p))),
            "Three named parties required"
        );
        ensure!(
            digest(&self.output_policy_digest) && digest(&self.recipient_key_digest),
            "Invalid output or recipient digest"
        );
        ensure!(
            digest(&self.agent_policy_digest),
            "Missing approved Agent Policy digest"
        );
        ensure!(
            self.not_before <= now && now < self.expires_at,
            "Job is not currently valid"
        );
        ensure!(
            self.expires_at
                .checked_sub(self.not_before)
                .is_some_and(|n| (1..=604800).contains(&n)),
            "Job lifetime must be at most seven days"
        );
        ensure!(
            !self.require_gpu && self.members == 1,
            "GPU/distributed CC-AI profile is not implemented; refusing fallback"
        );
        ensure!(
            !self.stages.is_empty() && self.stages.len() <= 2,
            "Invalid stage count"
        );
        ensure!(
            self.service_audiences.len() <= 32
                && self.service_audiences.iter().all(|v| identifier(v)),
            "Invalid service audiences"
        );
        let mut stages = BTreeSet::new();
        let mut measurements = BTreeSet::new();
        for s in &self.stages {
            ensure!(
                stages.insert(&s.stage)
                    && measurements.insert(&s.measurement)
                    && digest(&s.measurement),
                "Stages require distinct approved measurements"
            );
            ensure!(s.grants.len() <= 32, "Too many resource grants");
            for g in &s.grants {
                ensure!(
                    identifier(&g.audience) && valid_resource(&g.resource),
                    "Invalid resource grant"
                );
                ensure!(g.role != Role::User, "User cannot grant asset keys");
                ensure!(
                    g.role != Role::Data || s.stage == Stage::ModelVerified,
                    "Data requires verified model artifacts"
                );
            }
        }
        Ok(())
    }
}

fn valid_resource(v: &str) -> bool {
    let p: Vec<_> = v.split('/').collect();
    p.len() == 3 && p[0] == "workload" && p.iter().all(|s| identifier(s) && *s != "." && *s != "..")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwsHeader {
    alg: String,
    kid: String,
    typ: String,
}

pub fn sign_contract(contract: &JobContract, key_id: &str, private_pem: &[u8]) -> Result<String> {
    let header = B64.encode(serde_json::to_vec(
        &json!({"alg":"ES256", "kid":key_id, "typ":"cc-ai-contract+jws"}),
    )?);
    let payload = B64.encode(canonical(contract)?);
    let input = format!("{header}.{payload}");
    let key = PKey::private_key_from_pem(private_pem)?;
    ensure!(
        key.ec_key()?.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
        "Contract key must be P-256"
    );
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(input.as_bytes())?;
    let sig = EcdsaSig::from_der(&signer.sign_to_vec()?)?;
    let raw = [sig.r().to_vec_padded(32)?, sig.s().to_vec_padded(32)?].concat();
    Ok(format!("{input}.{}", B64.encode(raw)))
}

impl SignedJob {
    pub fn verify(&self, trust: &TrustPolicy, now: i64) -> Result<()> {
        trust.validate()?;
        self.contract.validate(now)?;
        ensure!(
            self.contract.policy_epoch >= trust.minimum_policy_epoch
                && !trust.revoked_jobs.contains(&self.contract.job_id),
            "Job revoked or policy epoch rolled back"
        );
        ensure!(
            self.signatures.len() == 3,
            "Exactly three role signatures required"
        );
        let payload = canonical(&self.contract)?;
        let mut roles = BTreeSet::new();
        for compact in &self.signatures {
            ensure!(compact.len() <= 2 * MAX_DOCUMENT, "JWS too large");
            let parts: Vec<_> = compact.split('.').collect();
            ensure!(parts.len() == 3, "Invalid compact JWS");
            let h: JwsHeader = serde_json::from_slice(&B64.decode(parts[0])?)?;
            ensure!(
                h.alg == "ES256" && h.typ == "cc-ai-contract+jws",
                "Invalid JWS algorithm or type"
            );
            let a = trust
                .authorities
                .iter()
                .find(|a| a.key_id == h.kid)
                .context("Unknown contract signing key")?;
            ensure!(
                self.contract.parties.get(&a.role) == Some(&a.party_id) && roles.insert(&a.role),
                "Wrong party or duplicate role signature"
            );
            ensure!(
                B64.decode(parts[1])? == payload,
                "Signature payload differs from canonical job contract"
            );
            let raw = B64.decode(parts[2])?;
            ensure!(raw.len() == 64, "Invalid ES256 signature length");
            let sig = EcdsaSig::from_private_components(
                BigNum::from_slice(&raw[..32])?,
                BigNum::from_slice(&raw[32..])?,
            )?;
            let key = PKey::public_key_from_pem(a.public_key_pem.as_bytes())?;
            let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
            verifier.update(format!("{}.{}", parts[0], parts[1]).as_bytes())?;
            ensure!(
                verifier.verify(&sig.to_der()?)?,
                "Invalid contract signature"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobBinding {
    pub job_id: String,
    pub tenant_id: String,
    pub contract_digest: String,
    pub stage: Stage,
    pub nonce: String,
    pub public_key_digest: String,
    pub policy_epoch: u64,
}

/// Only call after native quote + InitData/ReportData binding verification.
/// Stage is derived from the signed reference, never a runtime-data boolean.
pub fn evaluate_verified_evidence(
    e: &Value,
    trust: &TrustPolicy,
    now: i64,
) -> Result<(SignedJob, JobBinding)> {
    let init = e["init_data"]
        .as_str()
        .context("Missing verified InitData")?;
    ensure!(
        digest(init) && e.pointer("/workload/launch_digest").and_then(Value::as_str) == Some(init),
        "Invalid launch binding"
    );
    ensure!(
        e.pointer("/workload/profile").and_then(Value::as_str) == Some("trustee.tdx-workload.v2"),
        "Unsupported application profile"
    );
    ensure!(
        e.pointer("/init_data_claims/agent_policy_claims/containers")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty()),
        "Launch-bound Agent Policy required"
    );
    let encoded = e["init_data_claims"][INIT_DATA_KEY]
        .as_str()
        .context("Missing launch-bound job contract")?;
    ensure!(
        encoded.len() <= 4 * MAX_DOCUMENT,
        "Signed contract too large"
    );
    let signed: SignedJob = serde_json::from_str(encoded)?;
    signed.verify(trust, now)?;
    ensure!(
        e["init_data_claims"][AGENT_POLICY_DIGEST].as_str()
            == Some(&signed.contract.agent_policy_digest),
        "Agent Policy differs from three-party approval"
    );
    let measurement = e
        .pointer("/workload/measurement")
        .and_then(Value::as_str)
        .context("Missing verified workload measurement")?;
    let stage = signed
        .contract
        .stages
        .iter()
        .find(|s| s.measurement == measurement)
        .context("No approved stage matches actual application measurement")?
        .stage
        .clone();
    let nonce = e
        .pointer("/runtime_data_claims/nonce")
        .and_then(Value::as_str)
        .context("Missing verified nonce")?;
    ensure!(
        (16..=256).contains(&nonce.len()),
        "Invalid challenge length"
    );
    let key = e
        .pointer("/runtime_data_claims/tee-pubkey")
        .filter(|k| k.is_object())
        .context("Missing verified recipient public key")?;
    let binding = JobBinding {
        job_id: signed.contract.job_id.clone(),
        tenant_id: signed.contract.tenant_id.clone(),
        contract_digest: sha384(&canonical(&signed.contract)?),
        stage,
        nonce: nonce.to_string(),
        public_key_digest: sha384(&canonical(&public_jwk(key)?)?),
        policy_epoch: signed.contract.policy_epoch,
    };
    Ok((signed, binding))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelyingPartyPolicy {
    pub trust: TrustPolicy,
    pub issuer: String,
    pub audience: String,
    pub role: Role,
    pub max_token_age_seconds: u64,
}

impl RelyingPartyPolicy {
    pub fn validate(&self) -> Result<()> {
        self.trust.validate()?;
        ensure!(
            identifier(&self.issuer)
                && identifier(&self.audience)
                && (1..=300).contains(&self.max_token_age_seconds),
            "Invalid relying party policy"
        );
        Ok(())
    }

    /// Caller must verify the AS signature FIRST. No header-provided trust roots.
    /// Resource responses remain encrypted to the quote-bound TEE key by KBS.
    pub fn authorize(&self, claims: &Value, resource: &str, now: i64) -> Result<()> {
        self.validate()?;
        check_token(
            claims,
            &self.issuer,
            &self.audience,
            self.max_token_age_seconds,
            now,
        )?;
        let e = &claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"];
        ensure!(
            claims["cnf"]["jwk"] == public_jwk(&e["runtime_data_claims"]["tee-pubkey"])?,
            "Confirmation key mismatch"
        );
        let (signed, actual) = evaluate_verified_evidence(e, &self.trust, now)?;
        let declared: JobBinding = serde_json::from_value(claims[CLAIM].clone())?;
        ensure!(
            declared == actual,
            "AS job binding differs from verified evidence"
        );
        let stage = signed
            .contract
            .stages
            .iter()
            .find(|s| s.stage == actual.stage)
            .context("Missing stage")?;
        ensure!(
            stage.grants.iter().any(|g| g.role == self.role
                && g.audience == self.audience
                && g.resource == resource),
            "Resource, owner or stage not authorized by all three parties"
        );
        check_appraisals(claims)?;
        Ok(())
    }
}

pub fn check_token(
    claims: &Value,
    issuer: &str,
    audience: &str,
    max_age: u64,
    now: i64,
) -> Result<()> {
    ensure!((1..=300).contains(&max_age), "Invalid token age limit");
    ensure!(claims["iss"].as_str() == Some(issuer), "Wrong AS issuer");
    let aud = &claims["aud"];
    ensure!(
        aud.as_str() == Some(audience)
            || aud
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(audience))),
        "Wrong token audience"
    );
    let iat = claims["iat"].as_i64().context("Missing issued-at")?;
    let exp = claims["exp"].as_i64().context("Missing expiry")?;
    ensure!(
        iat <= now && now < exp && now.checked_sub(iat).is_some_and(|n| n <= max_age as i64),
        "Expired, future or stale token"
    );
    if let Some(nbf) = claims.get("nbf") {
        ensure!(
            nbf.as_i64().is_some_and(|n| n <= now),
            "Token not yet valid"
        );
    }
    Ok(())
}

pub fn check_appraisals(claims: &Value) -> Result<()> {
    ensure!(
        claims["submods"].as_object().is_some_and(|s| s.len() == 1),
        "Unsupported composite CC-AI profile"
    );
    let cpu = &claims["submods"]["cpu0"];
    ensure!(
        cpu["ear.status"] == "affirming",
        "CPU appraisal did not pass"
    );
    let r = cpu["ear.trustee.policy-results"]
        .as_array()
        .context("Both platform and application appraisals required")?;
    ensure!(
        r.len() >= 2 && r.iter().all(|v| v["status"] == "affirming"),
        "A required appraisal failed"
    );
    for required in ["default", "application"] {
        ensure!(
            r.iter().filter(|v| v["policy_id"] == required).count() == 1,
            "Missing or duplicate appraisal"
        );
    }
    Ok(())
}

/// Public part of a service passport check. Caller MUST also verify the AS
/// signature and match this digest to the TLS/application channel peer key.
pub struct PassportExpectation<'a> {
    pub nonce: &'a str,
    pub job_id: &'a str,
    pub contract_digest: &'a str,
    /// Must come from the authenticated connection, not from the passport.
    pub peer_key: &'a Value,
}

pub fn verify_passport(
    claims: &Value,
    policy: &RelyingPartyPolicy,
    expected: &PassportExpectation<'_>,
    now: i64,
) -> Result<JobBinding> {
    ensure!(
        policy.role == Role::User,
        "Service passport requires a user RP"
    );
    policy.validate()?;
    check_token(
        claims,
        &policy.issuer,
        &policy.audience,
        policy.max_token_age_seconds,
        now,
    )?;
    check_appraisals(claims)?;
    let peer_key = public_jwk(expected.peer_key)?;
    ensure!(
        claims["cnf"]["jwk"] == peer_key,
        "Confirmation key differs from channel key"
    );
    let (signed, binding) = evaluate_verified_evidence(
        &claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"],
        &policy.trust,
        now,
    )?;
    ensure!(
        serde_json::from_value::<JobBinding>(claims[CLAIM].clone())? == binding,
        "Invalid passport binding"
    );
    ensure!(
        binding.stage == Stage::ModelVerified
            && binding.nonce == expected.nonce
            && binding.job_id == expected.job_id
            && binding.contract_digest == expected.contract_digest
            && binding.public_key_digest == sha384(&canonical(&peer_key)?),
        "Passport challenge, job, contract, stage or channel key mismatch"
    );
    ensure!(
        signed.contract.purpose == Purpose::Infer
            && signed.contract.service_audiences.contains(&policy.audience),
        "Service use not authorized"
    );
    Ok(binding)
}

/// Offline verification with an explicitly pinned AS P-256 public key. Header
/// JWK/x5c/jku never affect trust. The RP policy still checks issuer and age.
pub fn verify_pinned_result(token: &str, public_pem: &[u8]) -> Result<Value> {
    ensure!(token.len() <= 512 * 1024, "Result token too large");
    let p: Vec<_> = token.split('.').collect();
    ensure!(p.len() == 3, "Invalid result JWS");
    let header: Value = serde_json::from_slice(&B64.decode(p[0])?)?;
    ensure!(
        header["alg"] == "ES256" && header.get("crit").is_none(),
        "Unsupported result JWS algorithm/critical header"
    );
    let key = PKey::public_key_from_pem(public_pem)?;
    ensure!(
        key.ec_key()?.group().curve_name() == Some(Nid::X9_62_PRIME256V1),
        "AS key must be P-256"
    );
    let raw = B64.decode(p[2])?;
    ensure!(raw.len() == 64, "Invalid result signature length");
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&raw[..32])?,
        BigNum::from_slice(&raw[32..])?,
    )?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
    verifier.update(format!("{}.{}", p[0], p[1]).as_bytes())?;
    ensure!(
        verifier.verify(&sig.to_der()?)?,
        "Invalid AS result signature"
    );
    Ok(serde_json::from_slice(&B64.decode(p[1])?)?)
}
