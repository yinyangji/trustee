// SPDX-License-Identifier: Apache-2.0

//! Reusable signer evidence and single-use inference session verification.

use super::*;
mod protocol;

pub use protocol::{
    parse_audience, require_tdx_evidence, DecodedInferenceRequest, InferenceBinding,
    InferenceChallenge, InferenceRequest, EVIDENCE_PATH, INFERENCE_PATH, POLICY_IDS,
    RUNTIME_PROFILE, VERIFY_PATH,
};

pub const ENDORSEMENT_DOMAIN: &str = "trustee.as-signer-endorsement.v1";

/// This domain and wire type are separate from nonce-bound signer evidence.
/// The public evidence may be independently checked by any relying party.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndorsementBinding {
    pub domain: String,
    pub issuer: String,
    pub kid: String,
    pub instance_id: String,
    pub signing_spki_sha256: String,
    pub as_release_manifest_digest: String,
    pub governance_profile_digest: String,
}

impl EndorsementBinding {
    pub fn report_data(&self) -> Result<Vec<u8>> {
        Ok(Sha512::digest(serde_json_canonicalizer::to_vec(self)?).to_vec())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerEndorsement {
    pub binding: EndorsementBinding,
    pub signing_key: SigningKey,
    pub evidence: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceResponse {
    pub ear: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_evidence: Option<SignerEndorsement>,
}

impl SignerEndorsement {
    #[cfg(any(feature = "tdx-verifier", test))]
    fn check(&self, trust: &SignerTrustPolicy) -> Result<()> {
        trust.validate()?;
        require_tdx_evidence(&self.evidence)?;
        let b = &self.binding;
        let kid = self.signing_key.kid()?;
        if b.domain != ENDORSEMENT_DOMAIN
            || b.issuer != trust.issuer
            || b.kid != kid
            || b.instance_id != kid
            || b.signing_spki_sha256 != kid
            || trust.revoked_kids.contains(&kid)
            || !trust
                .governance_profile_digests
                .contains(&b.governance_profile_digest)
            || !trust
                .releases
                .iter()
                .any(|r| r.as_release_manifest_digest == b.as_release_manifest_digest)
        {
            return Err(Error::Invalid("unapproved inference signer binding"));
        }
        Ok(())
    }

    /// Validate native TDX evidence locally before creating a cache entry.
    #[cfg(feature = "tdx-verifier")]
    pub async fn verify(
        self,
        trust: &SignerTrustPolicy,
        storage: std::sync::Arc<dyn key_value_storage::StorageProvider>,
    ) -> Result<VerifiedInferenceSigner> {
        self.check(trust)?;
        let report_data = self.binding.report_data()?;
        let claims = tokio::time::timeout(
            Duration::from_secs(30),
            verify_native_tdx(self.evidence.clone(), report_data, storage),
        )
        .await
        .map_err(|_| Error::Invalid("native signer verification timed out"))??;
        self.appraise(trust, &claims)
    }

    #[cfg(any(feature = "tdx-verifier", test))]
    fn appraise(
        self,
        trust: &SignerTrustPolicy,
        claims: &Value,
    ) -> Result<VerifiedInferenceSigner> {
        self.check(trust)?;
        let release_digest = self.binding.as_release_manifest_digest;
        let signer = appraise_signer(
            self.signing_key,
            &release_digest,
            self.binding.governance_profile_digest,
            trust,
            claims,
        )?;
        let expiration = claims["earliest_expiration_date"]
            .as_str()
            .ok_or(Error::Invalid("missing signer collateral expiration"))?;
        let collateral_expires_at =
            time::OffsetDateTime::parse(expiration, &time::format_description::well_known::Rfc3339)
                .map_err(|_| Error::Invalid("invalid signer collateral expiration"))?
                .unix_timestamp();
        if collateral_expires_at <= unix_time()? {
            return Err(Error::Invalid("signer collateral expired"));
        }
        Ok(VerifiedInferenceSigner {
            signer,
            release_digest,
            collateral_expires_at,
            trust_digest: trust_digest(trust)?,
        })
    }
}

/// The cache is scoped to this signer, release, governance, and trust record.
/// Verification reuses no workload Quote or EAR from an earlier request.
pub struct VerifiedInferenceSigner {
    signer: VerifiedSigner,
    release_digest: String,
    collateral_expires_at: i64,
    trust_digest: [u8; 32],
}

fn trust_digest(trust: &SignerTrustPolicy) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serde_json_canonicalizer::to_vec(trust)?).into())
}

impl VerifiedInferenceSigner {
    pub fn known_kid(&self, trust: &SignerTrustPolicy) -> Result<String> {
        trust.validate()?;
        let kid = self.signer.key.kid()?;
        if self.signer.verified_at.elapsed() >= Duration::from_secs(300)
            || unix_time()? >= self.collateral_expires_at
            || self.trust_digest != trust_digest(trust)?
        {
            return Err(Error::Invalid(
                "cached inference signer is no longer trusted",
            ));
        }
        Ok(kid)
    }
}

/// A session owns its fresh challenges. Verification consumes it, including on
/// failure. Use the EAR only with the same live connection used for its Quote.
pub struct InferenceSession {
    binding: InferenceBinding,
    created: Instant,
}

pub struct InferenceRelease<'a> {
    pub as_release_manifest_digest: &'a str,
    pub governance_digest: &'a str,
    pub policy_hashes: &'a BTreeMap<String, String>,
}

impl InferenceSession {
    pub fn new(audience: String, release_id: String, peer_spki_der: &[u8]) -> Result<Self> {
        let key = PKey::public_key_from_der(peer_spki_der)?;
        if key.public_key_to_der()? != peer_spki_der {
            return Err(Error::Invalid("noncanonical TLS SPKI"));
        }
        let mut random = [0u8; 64];
        openssl::rand::rand_bytes(&mut random)?;
        let binding = InferenceBinding {
            profile: RUNTIME_PROFILE.into(),
            audience,
            nonce: hex::encode(&random[..32]),
            session_id: hex::encode(&random[32..]),
            release_id,
            tls_spki_sha256: hex::encode(Sha256::digest(peer_spki_der)),
        };
        binding.validate()?;
        Ok(Self {
            binding,
            created: Instant::now(),
        })
    }

    pub fn binding(&self) -> &InferenceBinding {
        &self.binding
    }

    pub fn request(
        &self,
        evidence: &Value,
        approved_init_data: &str,
        cached_signer: Option<(&VerifiedInferenceSigner, &SignerTrustPolicy)>,
    ) -> Result<InferenceRequest> {
        if self.created.elapsed() >= Duration::from_secs(60) {
            return Err(Error::Invalid("inference challenge expired"));
        }
        let known_signer_kids = cached_signer
            .and_then(|(signer, trust)| signer.known_kid(trust).ok())
            .into_iter()
            .collect();
        InferenceRequest::new(
            known_signer_kids,
            evidence,
            &self.binding,
            approved_init_data,
        )
    }

    pub fn verify(
        self,
        ear: &str,
        signer: &VerifiedInferenceSigner,
        trust: &SignerTrustPolicy,
        expected: &InferenceRelease<'_>,
    ) -> Result<Value> {
        signer.known_kid(trust)?;
        if self.created.elapsed() >= Duration::from_secs(60)
            || signer.release_digest != expected.as_release_manifest_digest
            || signer.signer.governance_digest != expected.governance_digest
            || expected.policy_hashes.len() != POLICY_IDS.len()
            || POLICY_IDS
                .iter()
                .any(|id| !expected.policy_hashes.contains_key(*id))
            || expected
                .policy_hashes
                .values()
                .any(|hash| !valid_hex(hash, 48))
        {
            return Err(Error::Invalid(
                "inference session or release expectations mismatch",
            ));
        }
        let claims = signer.signer.verify_ear(ear)?;
        let cpu = &claims["submods"]["cpu0"];
        if claims["submods"].as_object().map(serde_json::Map::len) != Some(1)
            || cpu["ear.status"] != "affirming"
            || cpu["ear.veraison.annotated-evidence"]["runtime_data_claims"]
                != serde_json::to_value(self.binding)?
        {
            return Err(Error::Invalid(
                "inference appraisal or live TLS binding mismatch",
            ));
        }
        check_policy_results(cpu, expected.policy_hashes)?;
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{fixture, key, sign};
    use openssl::pkey::Private;
    use serde_json::json;

    fn endorsement() -> (PKey<Private>, SignerEndorsement, SignerTrustPolicy, Value) {
        let (private, bundle, trust, mut claims) = fixture(&SignerChallenge::new().unwrap());
        let b = bundle.binding;
        let bundle = SignerEndorsement {
            binding: EndorsementBinding {
                domain: ENDORSEMENT_DOMAIN.into(),
                issuer: b.issuer,
                kid: b.kid,
                instance_id: b.instance_id,
                signing_spki_sha256: b.signing_spki_sha256,
                as_release_manifest_digest: b.as_release_manifest_digest,
                governance_profile_digest: b.governance_profile_digest,
            },
            signing_key: bundle.signing_key,
            evidence: json!({"quote":"YQ==","cc_eventlog":"Yg=="}),
        };
        let expires = time::OffsetDateTime::from_unix_timestamp(unix_time().unwrap() + 600)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        claims["earliest_expiration_date"] = json!(expires);
        (private, bundle, trust, claims)
    }

    #[test]
    fn shared_endorsement_does_not_make_the_ear_reusable() {
        let (private, bundle, mut trust, claims) = endorsement();
        let first = bundle.clone().appraise(&trust, &claims).unwrap();
        let second = bundle.appraise(&trust, &claims).unwrap();
        let kid = first.known_kid(&trust).unwrap();
        assert_eq!(kid, second.known_kid(&trust).unwrap());
        let policies = BTreeMap::from([
            ("default".into(), "01".repeat(48)),
            ("application".into(), "02".repeat(48)),
        ]);
        let expected = InferenceRelease {
            as_release_manifest_digest: &first.release_digest,
            governance_digest: &first.signer.governance_digest,
            policy_hashes: &policies,
        };
        let peer = key().public_key_to_der().unwrap();
        let session = || {
            InferenceSession::new("https://inference.example".into(), "r1".into(), &peer).unwrap()
        };
        let request = session();
        let now = unix_time().unwrap();
        let mut signed = json!({
            "iss": trust.issuer, "iat": now, "exp": now+120,
            "ear.trustee.signer-governance": expected.governance_digest,
            "submods": {"cpu0": {
                "ear.status": "affirming",
                "ear.trustee.policy-results": [
                    {"policy_id":"default","policy_hash":policies["default"],"status":"affirming"},
                    {"policy_id":"application","policy_hash":policies["application"],"status":"affirming"}
                ],
                "ear.veraison.annotated-evidence": {"runtime_data_claims": request.binding()}
            }}
        });
        let ear = sign(&private, &kid, &signed);
        assert!(session().verify(&ear, &second, &trust, &expected).is_err());
        assert!(request.verify(&ear, &first, &trust, &expected).is_ok());

        let wrong_tls = session();
        signed["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["runtime_data_claims"] =
            json!(wrong_tls.binding());
        signed["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["runtime_data_claims"]
            ["tls_spki_sha256"] = json!("ff".repeat(32));
        assert!(wrong_tls
            .verify(&sign(&private, &kid, &signed), &first, &trust, &expected)
            .is_err());

        trust.revoked_kids.push(kid);
        assert!(first.known_kid(&trust).is_err());
    }

    #[test]
    fn wrong_domain_key_and_collateral_are_rejected() {
        let (_, bundle, trust, mut claims) = endorsement();
        let mut wrong = bundle.clone();
        wrong.binding.domain = DOMAIN.into();
        assert!(wrong.appraise(&trust, &claims).is_err());
        let mut wrong = bundle.clone();
        wrong.signing_key = endorsement().1.signing_key;
        assert!(wrong.appraise(&trust, &claims).is_err());
        claims["earliest_expiration_date"] = json!("1970-01-01T00:00:00Z");
        assert!(bundle.appraise(&trust, &claims).is_err());
    }

    #[cfg(feature = "tdx-verifier")]
    #[tokio::test]
    async fn network_endorsements_require_actual_tdx() {
        let (_, bundle, trust, _) = endorsement();
        let storage = key_value_storage::KvStorageProvider::new(Default::default());
        assert!(bundle.verify(&trust, storage).await.is_err());
    }
}
