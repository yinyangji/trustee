// SPDX-License-Identifier: Apache-2.0

//! Synthetic appraisals test policy enforcement, not DCAP authenticity. Only
//! the feature-gated native verifier can construct VerifiedSigner in production.

use super::*;
use jsonwebtoken::{EncodingKey, Header};
use openssl::pkey::Private;
use serde_json::json;

pub(super) fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

pub(super) fn fixture(
    challenge: &SignerChallenge,
) -> (
    PKey<Private>,
    SignerEvidenceBundle,
    SignerTrustPolicy,
    Value,
) {
    let private = key();
    let public = PKey::public_key_from_der(&private.public_key_to_der().unwrap()).unwrap();
    let signing_key = SigningKey::from_key(&public).unwrap();
    let kid = signing_key.kid().unwrap();
    let bundle = SignerEvidenceBundle {
        binding: Binding {
            domain: DOMAIN.into(),
            issuer: "https://as.example".into(),
            kid: kid.clone(),
            instance_id: kid.clone(),
            signing_spki_sha256: kid,
            as_release_manifest_digest: "aa".repeat(32),
            governance_profile_digest: "bb".repeat(32),
            verifier_nonce: challenge.nonce.clone(),
        },
        signing_key,
        evidence: json!({"quote":"invalid"}),
    };
    let release = TdxRelease {
        as_release_manifest_digest: "aa".repeat(32),
        mr_td: "11".repeat(48),
        mr_config_id: "22".repeat(48),
        rtmr_0: "33".repeat(48),
        rtmr_1: "44".repeat(48),
        rtmr_2: "55".repeat(48),
        rtmr_3: "66".repeat(48),
        xfam: "01".repeat(8),
        td_attributes: "00".repeat(8),
    };
    let mut body = serde_json::to_value(&release).unwrap();
    body.as_object_mut()
        .unwrap()
        .remove("as_release_manifest_digest");
    let claims = json!({"quote":{"body":body}, "td_attributes":{"debug":false},
        "collateral_expiration_status":"0", "tcb_status":"UpToDate"});
    let trust = SignerTrustPolicy {
        issuer: "https://as.example".into(),
        releases: vec![release],
        governance_profile_digests: vec!["bb".repeat(32)],
        allowed_tcb_statuses: vec!["UpToDate".into()],
        expires_at: unix_time().unwrap() + 3600,
        revoked_kids: vec![],
    };
    (private, bundle, trust, claims)
}

#[test]
fn canonical_binding_covers_key_nonce_release_and_governance() {
    let challenge = SignerChallenge::new().unwrap();
    let (_, bundle, _, _) = fixture(&challenge);
    let binding = serde_json::to_value(bundle.binding).unwrap();
    let original: Binding = serde_json::from_value(binding.clone()).unwrap();
    assert_eq!(original.report_data().unwrap().len(), 64);
    for field in [
        "domain",
        "issuer",
        "kid",
        "instance_id",
        "signing_spki_sha256",
        "as_release_manifest_digest",
        "governance_profile_digest",
        "verifier_nonce",
    ] {
        let mut changed = binding.clone();
        changed[field] = json!("changed");
        let changed: Binding = serde_json::from_value(changed).unwrap();
        assert_ne!(
            original.report_data().unwrap(),
            changed.report_data().unwrap(),
            "{field}"
        );
    }
}

#[test]
fn signer_rejects_unapproved_measurements_and_tcb_states() {
    let challenge = SignerChallenge::new().unwrap();
    let (_, bundle, trust, claims) = fixture(&challenge);
    let bundle_json = serde_json::to_value(bundle).unwrap();
    for path in [
        "/quote/body/mr_td",
        "/quote/body/mr_config_id",
        "/quote/body/rtmr_0",
        "/quote/body/rtmr_1",
        "/quote/body/rtmr_2",
        "/quote/body/rtmr_3",
        "/quote/body/xfam",
        "/quote/body/td_attributes",
        "/tcb_status",
        "/collateral_expiration_status",
    ] {
        let mut altered = claims.clone();
        *altered.pointer_mut(path).unwrap() = json!("tampered");
        assert!(
            challenge
                .appraise(
                    serde_json::from_value(bundle_json.clone()).unwrap(),
                    &trust,
                    &altered
                )
                .is_err(),
            "{path}"
        );
    }
    let mut debug = claims.clone();
    debug["td_attributes"]["debug"] = json!(true);
    assert!(challenge
        .appraise(
            serde_json::from_value(bundle_json.clone()).unwrap(),
            &trust,
            &debug
        )
        .is_err());
    let mut missing = claims.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("collateral_expiration_status");
    assert!(challenge
        .appraise(
            serde_json::from_value(bundle_json).unwrap(),
            &trust,
            &missing
        )
        .is_err());
}

#[test]
fn signer_binding_is_not_its_own_endorsement() {
    for field in [
        "domain",
        "issuer",
        "kid",
        "instance_id",
        "signing_spki_sha256",
        "as_release_manifest_digest",
        "governance_profile_digest",
        "verifier_nonce",
    ] {
        let challenge = SignerChallenge::new().unwrap();
        let (_, bundle, trust, claims) = fixture(&challenge);
        let mut value = serde_json::to_value(bundle).unwrap();
        value["binding"][field] = json!("ff".repeat(32));
        assert!(
            challenge
                .appraise(serde_json::from_value(value).unwrap(), &trust, &claims)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn release_tuples_cannot_be_mixed() {
    let challenge = SignerChallenge::new().unwrap();
    let (_, bundle, mut trust, mut claims) = fixture(&challenge);
    let mut second = trust.releases[0].clone();
    second.mr_td = "ab".repeat(48);
    second.rtmr_3 = "cd".repeat(48);
    trust.releases.push(second.clone());
    claims["quote"]["body"]["rtmr_3"] = json!(second.rtmr_3);
    assert!(challenge.appraise(bundle, &trust, &claims).is_err());
}

#[test]
fn revocation_expiry_and_challenge_deadline_are_enforced() {
    for case in [
        "revoked",
        "expired_trust",
        "expired_challenge",
        "zero_init",
        "zero_application",
    ] {
        let mut challenge = SignerChallenge::new().unwrap();
        let (_, bundle, mut trust, claims) = fixture(&challenge);
        match case {
            "revoked" => trust.revoked_kids.push(bundle.binding.kid.clone()),
            "expired_trust" => trust.expires_at = unix_time().unwrap() - 1,
            "expired_challenge" => challenge.created = Instant::now() - Duration::from_secs(61),
            "zero_init" => trust.releases[0].mr_config_id = "00".repeat(48),
            "zero_application" => trust.releases[0].rtmr_3 = "00".repeat(48),
            _ => unreachable!(),
        }
        assert!(
            challenge.appraise(bundle, &trust, &claims).is_err(),
            "{case}"
        );
    }
}

fn passport(signer: &VerifiedSigner) -> (Value, SessionExpectation) {
    let now = unix_time().unwrap();
    let recipient = key();
    let recipient = SigningKey::from_key(
        &PKey::public_key_from_der(&recipient.public_key_to_der().unwrap()).unwrap(),
    )
    .unwrap();
    let expected = SessionExpectation {
        audience: "inference-customer".into(),
        nonce: "12".repeat(32),
        session_id: "34".repeat(32),
        recipient_jwk: recipient,
        policy_hashes: BTreeMap::from([
            ("default".into(), "aa".repeat(48)),
            ("application".into(), "bb".repeat(48)),
        ]),
    };
    let mut recipient = serde_json::to_value(&expected.recipient_jwk).unwrap();
    recipient["alg"] = json!("ECDH-ES+A256KW");
    let value = json!({"iss":signer.issuer,"iat":now,"exp":now+120,"ear.trustee.signer-governance":signer.governance_digest,
        "submods":{"cpu0":{"ear.status":"affirming", "ear.trustee.policy-results":[
            {"policy_id":"default","policy_hash":expected.policy_hashes["default"],"status":"affirming"},
            {"policy_id":"application","policy_hash":expected.policy_hashes["application"],"status":"affirming"}],
            "ear.veraison.annotated-evidence":{"runtime_data_claims":{"audience":expected.audience,"nonce":expected.nonce,
                "session_id":expected.session_id,"tee-pubkey":recipient}}}}});
    (value, expected)
}

pub(super) fn sign(private: &PKey<Private>, kid: &str, value: &Value) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.into());
    jsonwebtoken::encode(
        &header,
        value,
        &EncodingKey::from_ec_pem(&private.private_key_to_pem_pkcs8().unwrap()).unwrap(),
    )
    .unwrap()
}

#[test]
fn approved_signer_and_application_passport_are_accepted() {
    let challenge = SignerChallenge::new().unwrap();
    let (private, bundle, trust, claims) = fixture(&challenge);
    let signer = challenge.appraise(bundle, &trust, &claims).unwrap();
    let (value, expected) = passport(&signer);
    assert!(signer
        .verify_application_passport(
            &sign(&private, &signer.key.kid().unwrap(), &value),
            &expected
        )
        .is_ok());
}

#[test]
fn correctly_signed_but_unacceptable_passports_are_rejected() {
    let challenge = SignerChallenge::new().unwrap();
    let (private, bundle, trust, claims) = fixture(&challenge);
    let signer = challenge.appraise(bundle, &trust, &claims).unwrap();
    let (value, expected) = passport(&signer);
    for (path, replacement) in [
        ("/iss", json!("https://other.example")),
        ("/iat", json!(unix_time().unwrap() + 60)),
        ("/exp", json!(unix_time().unwrap() - 1)),
        ("/ear.trustee.signer-governance", json!("cc".repeat(32))),
        ("/submods/cpu0/ear.status", json!("warning")),
        (
            "/submods/cpu0/ear.trustee.policy-results/1/status",
            json!("contraindicated"),
        ),
        (
            "/submods/cpu0/ear.trustee.policy-results/1/policy_hash",
            json!("cc".repeat(48)),
        ),
        (
            "/submods/cpu0/ear.trustee.policy-results/1/policy_id",
            json!("default"),
        ),
        (
            "/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims/audience",
            json!("other-customer"),
        ),
        (
            "/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims/nonce",
            json!("ff".repeat(32)),
        ),
        (
            "/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims/session_id",
            json!("ff".repeat(32)),
        ),
        (
            "/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims/tee-pubkey/x",
            json!("wrong-key"),
        ),
    ] {
        let mut altered = value.clone();
        *altered.pointer_mut(path).unwrap() = replacement;
        assert!(
            signer
                .verify_application_passport(
                    &sign(&private, &signer.key.kid().unwrap(), &altered),
                    &expected
                )
                .is_err(),
            "{path}"
        );
    }
    assert!(signer
        .verify_application_passport(&sign(&key(), &signer.key.kid().unwrap(), &value), &expected)
        .is_err());
    assert!(signer
        .verify_application_passport(&sign(&private, &"ff".repeat(32), &value), &expected)
        .is_err());
}

#[test]
fn governance_digest_commits_to_actual_reference_values() {
    let mut governance = Governance {
        policy_hashes: BTreeMap::from([("application_cpu".into(), "aa".repeat(48))]),
        reference_values: BTreeMap::from([("application_rtmr_3".into(), json!(["bb".repeat(48)]))]),
        inference_releases: BTreeMap::new(),
        expires_at: unix_time().unwrap() + 3600,
    };
    governance.validate().unwrap();
    assert!(serde_json::to_value(&governance)
        .unwrap()
        .get("inference_releases")
        .is_none());
    let initial = governance.digest().unwrap();
    governance
        .reference_values
        .insert("application_init_data".into(), json!(["dd".repeat(48)]));
    assert_ne!(initial, governance.digest().unwrap());
    let baseline_digest = governance.digest().unwrap();
    governance.inference_releases = BTreeMap::from([(
        "https://tenant.example".into(),
        BTreeMap::from([(
            "r1".into(),
            InferenceReleaseReference {
                application_rtmr3: "bb".repeat(48),
                init_data_sha384: "dd".repeat(48),
            },
        )]),
    )]);
    governance.validate().unwrap();
    assert_ne!(baseline_digest, governance.digest().unwrap());
    governance
        .reference_values
        .insert("application_rtmr_3".into(), json!(["cc".repeat(48)]));
    assert!(governance.validate().is_err());
    governance.inference_releases.clear();
    governance.expires_at = unix_time().unwrap() - 1;
    assert!(governance.validate().is_err());
}

#[test]
fn cached_signer_cannot_outlive_its_proof_or_local_policy() {
    for expired_policy in [false, true] {
        let challenge = SignerChallenge::new().unwrap();
        let (private, bundle, trust, claims) = fixture(&challenge);
        let mut signer = challenge.appraise(bundle, &trust, &claims).unwrap();
        let (value, expected) = passport(&signer);
        let token = sign(&private, &signer.key.kid().unwrap(), &value);
        if expired_policy {
            signer.trust_expires_at = unix_time().unwrap() - 1;
        } else {
            signer.verified_at = Instant::now() - Duration::from_secs(301);
        }
        assert!(signer
            .verify_application_passport(&token, &expected)
            .is_err());
    }
}

#[test]
fn client_session_challenges_are_fresh_and_select_application_appraisal() {
    let challenge = SignerChallenge::new().unwrap();
    let (_, bundle, trust, claims) = fixture(&challenge);
    let signer = challenge.appraise(bundle, &trust, &claims).unwrap();
    let (_, expected) = passport(&signer);
    let first = SessionExpectation::new(
        expected.audience.clone(),
        expected.recipient_jwk.clone(),
        expected.policy_hashes.clone(),
    )
    .unwrap();
    let second = SessionExpectation::new(
        expected.audience,
        expected.recipient_jwk,
        expected.policy_hashes,
    )
    .unwrap();
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.session_id, second.session_id);
    assert_ne!(first.nonce, first.session_id);
    let parameters = first.auth_extra_params().unwrap();
    assert_eq!(parameters["attestation-policy-selector"], "workload");
    assert_eq!(parameters["passport-nonce"], first.nonce);
    assert_eq!(parameters["passport-session-id"], first.session_id);
}

#[test]
fn embedded_keys_and_critical_headers_cannot_override_the_attested_signer() {
    let challenge = SignerChallenge::new().unwrap();
    let (private, bundle, trust, claims) = fixture(&challenge);
    let signer = challenge.appraise(bundle, &trust, &claims).unwrap();
    let (value, expected) = passport(&signer);
    let encoding = EncodingKey::from_ec_pem(&private.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(signer.key.kid().unwrap());
    header.jwk = Some(serde_json::from_value(serde_json::to_value(&signer.key).unwrap()).unwrap());
    let token = jsonwebtoken::encode(&header, &value, &encoding).unwrap();
    assert!(signer
        .verify_application_passport(&token, &expected)
        .is_ok());
    header.crit = Some(vec!["unsupported-critical-extension".into()]);
    let token = jsonwebtoken::encode(&header, &value, &encoding).unwrap();
    assert!(signer
        .verify_application_passport(&token, &expected)
        .is_err());
    header.crit = None;
    let other = key();
    let other = SigningKey::from_key(
        &PKey::public_key_from_der(&other.public_key_to_der().unwrap()).unwrap(),
    )
    .unwrap();
    header.jwk = Some(serde_json::from_value(serde_json::to_value(other).unwrap()).unwrap());
    let token = jsonwebtoken::encode(&header, &value, &encoding).unwrap();
    assert!(signer
        .verify_application_passport(&token, &expected)
        .is_err());
}

#[cfg(feature = "tdx-verifier")]
#[tokio::test]
async fn native_verifier_rejects_fabricated_quote() {
    let challenge = SignerChallenge::new().unwrap();
    let (_, bundle, trust, _) = fixture(&challenge);
    assert!(challenge
        .verify(
            bundle,
            &trust,
            key_value_storage::KvStorageProvider::new(Default::default())
        )
        .await
        .is_err());
}
