// SPDX-License-Identifier: Apache-2.0

//! Bootstrap a passport signing key from native TDX evidence, never from an
//! unendorsed JWT header. This profile is not Azure's wire protocol.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::{PKey, Public},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

pub mod inference;

pub const DOMAIN: &str = "platform-as-signer-v1";
const MAX_TOKEN_BYTES: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid attested signer profile: {0}")]
    Invalid(&'static str),
    #[error("crypto operation failed: {0}")]
    Crypto(#[from] openssl::error::ErrorStack),
    #[error("JSON operation failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JWT verification failed: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("native TDX verification failed: {0}")]
    Hardware(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Immutable appraisal inputs. The digest covers the actual values used by the
/// policy extension, not an operator-supplied label for an external RVPS.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Governance {
    pub policy_hashes: BTreeMap<String, String>,
    pub reference_values: BTreeMap<String, Value>,
    /// HTTPS audience scopes each tenant-facing service and its release IDs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inference_releases: BTreeMap<String, BTreeMap<String, InferenceReleaseReference>>,
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceReleaseReference {
    pub application_rtmr3: String,
    pub init_data_sha384: String,
}

impl Governance {
    pub fn validate(&self) -> Result<()> {
        if self.policy_hashes.is_empty() || self.expires_at <= unix_time()? {
            return Err(Error::Invalid("empty or expired governance"));
        }
        for (name, hash) in &self.policy_hashes {
            if name.is_empty() || !valid_hex(hash, 48) {
                return Err(Error::Invalid("invalid policy ID or SHA-384 hash"));
            }
        }
        if self.reference_values.is_empty()
            || self
                .reference_values
                .values()
                .any(|v| !v.is_array() || v.as_array().is_some_and(Vec::is_empty))
        {
            return Err(Error::Invalid(
                "reference snapshot must contain nonempty arrays",
            ));
        }
        for (audience, releases) in &self.inference_releases {
            inference::parse_audience(audience)?;
            if releases.is_empty() {
                return Err(Error::Invalid(
                    "inference audience has no approved releases",
                ));
            }
            for (release_id, reference) in releases {
                if release_id.is_empty() || release_id.len() > 256 {
                    return Err(Error::Invalid("invalid inference release ID"));
                }
                for (list, measured) in [
                    ("application_rtmr_3", &reference.application_rtmr3),
                    ("application_init_data", &reference.init_data_sha384),
                ] {
                    if !valid_hex(measured, 48)
                        || !measured.bytes().any(|b| b != b'0')
                        || !self
                            .reference_values
                            .get(list)
                            .and_then(Value::as_array)
                            .is_some_and(|values| {
                                values.iter().any(|v| v.as_str() == Some(measured))
                            })
                    {
                        return Err(Error::Invalid(
                            "inference reference is outside the approved baseline",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(
            serde_json_canonicalizer::to_vec(self)?,
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerConfig {
    pub as_release_manifest_digest: String,
    pub governance: Governance,
}

impl SignerConfig {
    pub fn validate(&self, issuer: &str) -> Result<()> {
        validate_issuer(issuer)?;
        if !valid_hex(&self.as_release_manifest_digest, 32) {
            return Err(Error::Invalid("invalid AS release manifest SHA-256"));
        }
        self.governance.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequest {
    pub kid: String,
    pub nonce: String,
}

impl EvidenceRequest {
    pub fn validate(&self) -> Result<()> {
        if !valid_hex(&self.kid, 32) || !valid_hex(&self.nonce, 32) {
            return Err(Error::Invalid(
                "kid and nonce must be 32-byte lowercase hex",
            ));
        }
        Ok(())
    }
}

/// Only public key material; JWS URL/certificate indirection is not accepted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl SigningKey {
    pub fn from_key(key: &PKey<Public>) -> Result<Self> {
        let ec = key.ec_key()?;
        if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(Error::Invalid("signing key must be P-256"));
        }
        let mut ctx = BigNumContext::new()?;
        let mut x = openssl::bn::BigNum::new()?;
        let mut y = openssl::bn::BigNum::new()?;
        ec.public_key()
            .affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut ctx)?;
        Ok(Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(x.to_vec_padded(32)?),
            y: URL_SAFE_NO_PAD.encode(y.to_vec_padded(32)?),
        })
    }

    fn to_key(&self) -> Result<PKey<Public>> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(Error::Invalid("signing key must be P-256"));
        }
        let mut octets = vec![4];
        for coordinate in [&self.x, &self.y] {
            let bytes = URL_SAFE_NO_PAD
                .decode(coordinate)
                .map_err(|_| Error::Invalid("invalid JWK coordinate"))?;
            if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != *coordinate {
                return Err(Error::Invalid("invalid JWK coordinate size or encoding"));
            }
            octets.extend(bytes);
        }
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, &octets, &mut ctx)?;
        let ec = EcKey::from_public_key(&group, &point)?;
        ec.check_key()?;
        Ok(PKey::from_ec_key(ec)?)
    }

    pub fn kid(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(
            self.to_key()?.public_key_to_der()?,
        )))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub domain: String,
    pub issuer: String,
    pub kid: String,
    pub instance_id: String,
    pub signing_spki_sha256: String,
    pub as_release_manifest_digest: String,
    pub governance_profile_digest: String,
    pub verifier_nonce: String,
}

impl Binding {
    pub fn report_data(&self) -> Result<Vec<u8>> {
        Ok(Sha512::digest(serde_json_canonicalizer::to_vec(self)?).to_vec())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerEvidenceBundle {
    pub binding: Binding,
    pub signing_key: SigningKey,
    pub evidence: Value,
}

/// One correlated TDX release tuple; fields from different releases must never
/// be mixed. MRCONFIGID must endorse an immutable launch and restrictive agent
/// policy; RTMR3 must measure the AS executable and its dependencies.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TdxRelease {
    pub as_release_manifest_digest: String,
    pub mr_td: String,
    pub mr_config_id: String,
    pub rtmr_0: String,
    pub rtmr_1: String,
    pub rtmr_2: String,
    pub rtmr_3: String,
    pub xfam: String,
    pub td_attributes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerTrustPolicy {
    pub issuer: String,
    pub releases: Vec<TdxRelease>,
    pub governance_profile_digests: Vec<String>,
    /// UpToDate is recommended; weaker states require explicit local consent.
    pub allowed_tcb_statuses: Vec<String>,
    pub expires_at: i64,
    pub revoked_kids: Vec<String>,
}

impl SignerTrustPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_issuer(&self.issuer)?;
        if self.expires_at <= unix_time()?
            || self.releases.is_empty()
            || self.governance_profile_digests.is_empty()
            || self.allowed_tcb_statuses.is_empty()
        {
            return Err(Error::Invalid("empty or expired signer trust policy"));
        }
        if self
            .governance_profile_digests
            .iter()
            .any(|v| !valid_hex(v, 32))
            || self.revoked_kids.iter().any(|v| !valid_hex(v, 32))
        {
            return Err(Error::Invalid("invalid governance digest"));
        }
        if self.allowed_tcb_statuses.iter().any(|v| {
            !matches!(
                v.as_str(),
                "UpToDate"
                    | "OutOfDate"
                    | "SWHardeningNeeded"
                    | "ConfigurationNeeded"
                    | "ConfigurationAndSWHardeningNeeded"
                    | "OutOfDateConfigurationNeeded"
            )
        }) {
            return Err(Error::Invalid("unsupported TCB status"));
        }
        for r in &self.releases {
            if !valid_hex(&r.as_release_manifest_digest, 32)
                || [
                    &r.mr_td,
                    &r.mr_config_id,
                    &r.rtmr_0,
                    &r.rtmr_1,
                    &r.rtmr_2,
                    &r.rtmr_3,
                ]
                .iter()
                .any(|v| !valid_hex(v, 48))
                || !valid_hex(&r.xfam, 8)
                || !valid_hex(&r.td_attributes, 8)
                || r.mr_config_id.bytes().all(|b| b == b'0')
                || r.rtmr_3.bytes().all(|b| b == b'0')
            {
                return Err(Error::Invalid("invalid or unbound AS release tuple"));
            }
        }
        Ok(())
    }
}

/// Non-cloneable local challenge, consumed by verification even on failure.
/// No API accepts a caller-asserted nonce as proof of freshness.
pub struct SignerChallenge {
    nonce: String,
    created: Instant,
}

impl SignerChallenge {
    pub fn new() -> Result<Self> {
        let mut random = [0u8; 32];
        openssl::rand::rand_bytes(&mut random)?;
        Ok(Self {
            nonce: hex::encode(random),
            created: Instant::now(),
        })
    }

    pub fn request(&self, kid: String) -> Result<EvidenceRequest> {
        if self.created.elapsed() >= Duration::from_secs(60) {
            return Err(Error::Invalid("signer challenge expired"));
        }
        let request = EvidenceRequest {
            kid,
            nonce: self.nonce.clone(),
        };
        request.validate()?;
        Ok(request)
    }

    #[cfg(any(feature = "tdx-verifier", test))]
    fn check(&self, bundle: &SignerEvidenceBundle, trust: &SignerTrustPolicy) -> Result<()> {
        trust.validate()?;
        let b = &bundle.binding;
        let kid = bundle.signing_key.kid()?;
        if self.created.elapsed() >= Duration::from_secs(60)
            || b.verifier_nonce != self.nonce
            || b.domain != DOMAIN
            || b.issuer != trust.issuer
            || b.kid != kid
            || b.instance_id != kid
            || b.signing_spki_sha256 != kid
            || trust.revoked_kids.contains(&kid)
            || !trust
                .governance_profile_digests
                .contains(&b.governance_profile_digest)
        {
            return Err(Error::Invalid(
                "signer binding, governance, revocation or freshness mismatch",
            ));
        }
        Ok(())
    }

    /// Native DCAP validation precedes appraisal. No sample verifier, injected
    /// hardware claims, self-signed JWT, or generic 'already verified' hook.
    #[cfg(feature = "tdx-verifier")]
    pub async fn verify(
        self,
        bundle: SignerEvidenceBundle,
        trust: &SignerTrustPolicy,
        storage: std::sync::Arc<dyn key_value_storage::StorageProvider>,
    ) -> Result<VerifiedSigner> {
        self.check(&bundle, trust)?;
        let report_data = bundle.binding.report_data()?;
        let remaining = Duration::from_secs(60)
            .checked_sub(self.created.elapsed())
            .ok_or(Error::Invalid("signer challenge expired"))?;
        let claims = tokio::time::timeout(
            remaining,
            verify_native_tdx(bundle.evidence.clone(), report_data, storage),
        )
        .await
        .map_err(|_| Error::Invalid("native signer verification timed out"))??;
        let signer = self.appraise(bundle, trust, &claims)?;
        // DCAP may have performed network I/O; recheck local challenge age.
        if self.created.elapsed() >= Duration::from_secs(60) {
            return Err(Error::Invalid(
                "signer verification exceeded challenge deadline",
            ));
        }
        Ok(signer)
    }

    #[cfg(any(feature = "tdx-verifier", test))]
    fn appraise(
        &self,
        bundle: SignerEvidenceBundle,
        trust: &SignerTrustPolicy,
        claims: &Value,
    ) -> Result<VerifiedSigner> {
        self.check(&bundle, trust)?;
        appraise_signer(
            bundle.signing_key,
            &bundle.binding.as_release_manifest_digest,
            bundle.binding.governance_profile_digest,
            trust,
            claims,
        )
    }
}

#[cfg(feature = "tdx-verifier")]
async fn verify_native_tdx(
    evidence: Value,
    report_data: Vec<u8>,
    storage: std::sync::Arc<dyn key_value_storage::StorageProvider>,
) -> Result<Value> {
    let native = verifier::to_verifier(&kbs_types::Tee::Tdx, None, storage)
        .await
        .map_err(|e| Error::Hardware(e.to_string()))?;
    let mut results = native
        .evaluate(
            evidence,
            &verifier::ReportData::Value(&report_data),
            &verifier::InitDataHash::NotProvided,
        )
        .await
        .map_err(|e| Error::Hardware(e.to_string()))?;
    match results.pop() {
        Some((claims, class)) if class == "cpu" && results.is_empty() => Ok(claims),
        _ => Err(Error::Invalid("unexpected TDX appraisal structure")),
    }
}

#[cfg(any(feature = "tdx-verifier", test))]
fn appraise_signer(
    signing_key: SigningKey,
    release_digest: &str,
    governance_digest: String,
    trust: &SignerTrustPolicy,
    claims: &Value,
) -> Result<VerifiedSigner> {
    if claims
        .pointer("/td_attributes/debug")
        .and_then(Value::as_bool)
        != Some(false)
        || claims
            .get("collateral_expiration_status")
            .and_then(Value::as_str)
            != Some("0")
        || !claims
            .get("tcb_status")
            .and_then(Value::as_str)
            .is_some_and(|s| trust.allowed_tcb_statuses.iter().any(|v| v == s))
    {
        return Err(Error::Invalid(
            "unacceptable AS TCB, debug or collateral state",
        ));
    }
    let release = trust.releases.iter().any(|r| {
        r.as_release_manifest_digest == release_digest
            && [
                ("mr_td", &r.mr_td),
                ("mr_config_id", &r.mr_config_id),
                ("rtmr_0", &r.rtmr_0),
                ("rtmr_1", &r.rtmr_1),
                ("rtmr_2", &r.rtmr_2),
                ("rtmr_3", &r.rtmr_3),
                ("xfam", &r.xfam),
                ("td_attributes", &r.td_attributes),
            ]
            .iter()
            .all(|(name, expected)| {
                claims
                    .pointer(&format!("/quote/body/{name}"))
                    .and_then(Value::as_str)
                    == Some(expected.as_str())
            })
    });
    if !release {
        return Err(Error::Invalid("AS runtime is not an approved release"));
    }
    Ok(VerifiedSigner {
        key: signing_key,
        issuer: trust.issuer.clone(),
        governance_digest,
        verified_at: Instant::now(),
        trust_expires_at: trust.expires_at,
    })
}

/// Constructible only after native proof validation and local AS appraisal.
/// Deliberately does not implement Deserialize or expose the inner key.
pub struct VerifiedSigner {
    key: SigningKey,
    issuer: String,
    governance_digest: String,
    verified_at: Instant,
    trust_expires_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionExpectation {
    pub audience: String,
    pub nonce: String,
    pub session_id: String,
    pub recipient_jwk: SigningKey,
    /// Exactly the expected default + application policies for this session.
    pub policy_hashes: BTreeMap<String, String>,
}

impl SessionExpectation {
    /// Generate independent client challenges before requesting an application
    /// passport. The recipient is only a candidate until verification succeeds.
    pub fn new(
        audience: String,
        recipient_jwk: SigningKey,
        policy_hashes: BTreeMap<String, String>,
    ) -> Result<Self> {
        let mut random = [0u8; 64];
        openssl::rand::rand_bytes(&mut random)?;
        let expected = Self {
            audience,
            nonce: hex::encode(&random[..32]),
            session_id: hex::encode(&random[32..]),
            recipient_jwk,
            policy_hashes,
        };
        expected.validate()?;
        Ok(expected)
    }

    pub fn auth_extra_params(&self) -> Result<Value> {
        self.validate()?;
        Ok(serde_json::json!({
            "attestation-policy-selector": "workload",
            "passport-audience": self.audience,
            "passport-nonce": self.nonce,
            "passport-session-id": self.session_id,
        }))
    }

    fn validate(&self) -> Result<()> {
        if self.audience.is_empty()
            || !valid_hex(&self.nonce, 32)
            || !valid_hex(&self.session_id, 32)
            || self.policy_hashes.len() != 2
            || !self.policy_hashes.contains_key("default")
            || !self.policy_hashes.contains_key("application")
            || self.policy_hashes.values().any(|v| !valid_hex(v, 48))
        {
            return Err(Error::Invalid("invalid application session expectations"));
        }
        self.recipient_jwk.to_key()?;
        Ok(())
    }
}

/// Authenticated application/session result. This type cannot be deserialized
/// from network input; use its recipient only after verifying the passport.
pub struct VerifiedApplicationPassport {
    claims: Value,
    recipient: SigningKey,
}

impl VerifiedApplicationPassport {
    pub fn claims(&self) -> &Value {
        &self.claims
    }

    pub fn recipient(&self) -> &SigningKey {
        &self.recipient
    }
}

impl VerifiedSigner {
    /// Verify an application passport before encrypting to the attested recipient.
    /// The caller must bind this recipient to its TLS/HPKE session and must not
    /// reuse a session challenge after accepting it.
    pub fn verify_application_passport(
        &self,
        token: &str,
        expected: &SessionExpectation,
    ) -> Result<VerifiedApplicationPassport> {
        expected.validate()?;
        let decoded = self.verify_ear(token)?;
        let submods = decoded["submods"]
            .as_object()
            .ok_or(Error::Invalid("missing submodules"))?;
        if submods.is_empty() || submods.values().any(|v| v["ear.status"] != "affirming") {
            return Err(Error::Invalid("non-affirming attestation result"));
        }
        let cpu = &decoded["submods"]["cpu0"];
        let runtime = &cpu["ear.veraison.annotated-evidence"]["runtime_data_claims"];
        let recipient = &runtime["tee-pubkey"];
        let expected_recipient = serde_json::to_value(&expected.recipient_jwk)?;
        if runtime["audience"] != expected.audience
            || runtime["nonce"] != expected.nonce
            || runtime["session_id"] != expected.session_id
            || recipient["alg"] != "ECDH-ES+A256KW"
            || ["kty", "crv", "x", "y"]
                .iter()
                .any(|field| recipient[field] != expected_recipient[field])
        {
            return Err(Error::Invalid(
                "quote-bound audience, challenge, session or recipient mismatch",
            ));
        }
        check_policy_results(cpu, &expected.policy_hashes)?;
        Ok(VerifiedApplicationPassport {
            claims: decoded,
            recipient: expected.recipient_jwk.clone(),
        })
    }

    fn verify_ear(&self, token: &str) -> Result<Value> {
        let now = unix_time()?;
        if self.verified_at.elapsed() >= Duration::from_secs(300)
            || now >= self.trust_expires_at
            || token.len() > MAX_TOKEN_BYTES
        {
            return Err(Error::Invalid(
                "expired signer or invalid session expectations",
            ));
        }
        let header = jsonwebtoken::decode_header(token)?;
        if header.alg != Algorithm::ES256
            || header.kid.as_deref() != Some(&self.key.kid()?)
            || header.jku.is_some()
            || header.x5u.is_some()
            || header
                .crit
                .as_ref()
                .is_some_and(|values| !values.is_empty())
            || header.jwk.is_some_and(|jwk| {
                let value = serde_json::to_value(jwk).unwrap_or(Value::Null);
                value["kty"] != self.key.kty
                    || value["crv"] != self.key.crv
                    || value["x"] != self.key.x
                    || value["y"] != self.key.y
            })
        {
            return Err(Error::Invalid(
                "unexpected JWS algorithm, key ID or embedded key",
            ));
        }
        let mut validation = Validation::new(Algorithm::ES256);
        validation.leeway = 0;
        validation.set_issuer(&[&self.issuer]);
        // Audience is quote-bound runtime data in the CoCo EAR profile, not an
        // unauthenticated top-level claim synthesized by a gateway.
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["iss", "iat", "exp"]);
        let decoded = jsonwebtoken::decode::<Value>(
            token,
            &DecodingKey::from_ec_pem(&self.key.to_key()?.public_key_to_pem()?)?,
            &validation,
        )?
        .claims;
        let iat = decoded["iat"]
            .as_i64()
            .ok_or(Error::Invalid("missing issuance time"))?;
        let exp = decoded["exp"]
            .as_i64()
            .ok_or(Error::Invalid("missing expiry time"))?;
        if iat > now
            || iat < now.saturating_sub(300)
            || exp <= now
            || exp <= iat
            || exp > iat.saturating_add(300)
            || decoded["ear.trustee.signer-governance"] != self.governance_digest
        {
            return Err(Error::Invalid("passport lifetime or governance mismatch"));
        }
        Ok(decoded)
    }
}

fn check_policy_results(cpu: &Value, policy_hashes: &BTreeMap<String, String>) -> Result<()> {
    let results = cpu["ear.trustee.policy-results"]
        .as_array()
        .ok_or(Error::Invalid("missing per-policy appraisal"))?;
    if results.len() != policy_hashes.len() {
        return Err(Error::Invalid("unexpected policy set"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for result in results {
        let id = result["policy_id"]
            .as_str()
            .ok_or(Error::Invalid("missing policy ID"))?;
        if !seen.insert(id)
            || result["status"] != "affirming"
            || policy_hashes.get(id).map(String::as_str) != result["policy_hash"].as_str()
        {
            return Err(Error::Invalid(
                "policy mismatch or failed application appraisal",
            ));
        }
    }
    Ok(())
}

pub fn unix_time() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid("clock before Unix epoch"))?
        .as_secs();
    i64::try_from(seconds).map_err(|_| Error::Invalid("clock overflow"))
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn validate_issuer(issuer: &str) -> Result<()> {
    let url = url::Url::parse(issuer).map_err(|_| Error::Invalid("invalid issuer URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || issuer.ends_with('/')
    {
        return Err(Error::Invalid(
            "issuer must be a fixed HTTPS URL without trailing slash, query or credentials",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
