mod common;
use common::*;
use serde_json::json;
use trustee_cc_ai::*;
const NOW: i64 = 1_794_747_600;

#[test]
fn three_party_authorization_and_service_passport() {
    let (trust, signed, claims) = fixture(NOW);
    signed.verify(&trust, NOW).unwrap();
    data_policy(trust.clone())
        .authorize(&claims, "workload/data/v1", NOW)
        .unwrap();
    assert!(data_policy(trust.clone())
        .authorize(&claims, "workload/data/another", NOW)
        .is_err());
    let mut user = data_policy(trust);
    user.role = Role::User;
    user.audience = "https://client.example".into();
    verify_passport(
        &claims,
        &user,
        &PassportExpectation {
            nonce: "fresh-challenge-0123456789",
            job_id: "job-1",
            contract_digest: &sha384(&canonical(&signed.contract).unwrap()),
            peer_key: &claims["cnf"]["jwk"],
        },
        NOW,
    )
    .unwrap();
    assert!(verify_passport(
        &claims,
        &user,
        &PassportExpectation {
            nonce: "replayed-nonce",
            job_id: "job-1",
            contract_digest: &sha384(&canonical(&signed.contract).unwrap()),
            peer_key: &claims["cnf"]["jwk"]
        },
        NOW
    )
    .is_err());
    assert!(verify_passport(
        &claims,
        &user,
        &PassportExpectation {
            nonce: "fresh-challenge-0123456789",
            job_id: "job-2",
            contract_digest: &sha384(&canonical(&signed.contract).unwrap()),
            peer_key: &claims["cnf"]["jwk"]
        },
        NOW
    )
    .is_err());
    assert!(verify_passport(
        &claims,
        &user,
        &PassportExpectation {
            nonce: "fresh-challenge-0123456789",
            job_id: "job-1",
            contract_digest: &sha384(&canonical(&signed.contract).unwrap()),
            peer_key: &json!({"kty":"EC"})
        },
        NOW
    )
    .is_err());
}

#[test]
fn signatures_cannot_be_omitted_reused_or_attached_to_modified_contract() {
    let (trust, signed, _) = fixture(NOW);
    let mut missing = signed.clone();
    missing.signatures.pop();
    assert!(missing.verify(&trust, NOW).is_err());
    let mut repeated = signed.clone();
    repeated.signatures[2] = repeated.signatures[0].clone();
    assert!(repeated.verify(&trust, NOW).is_err());
    let mut modified = signed.clone();
    modified.contract.tenant_id = "attacker".into();
    assert!(modified.verify(&trust, NOW).is_err());
    let mut unknown = signed.clone();
    unknown.signatures[0].push('A');
    assert!(unknown.verify(&trust, NOW).is_err());
    let mut confused = trust.clone();
    confused.authorities[0].party_id = "another-party".into();
    assert!(signed.verify(&confused, NOW).is_err());
    let mut same_key = trust;
    same_key.authorities[1].public_key_pem = same_key.authorities[0].public_key_pem.clone();
    assert!(same_key.validate().is_err());
}

#[test]
fn revocation_epoch_and_time_are_asset_owner_controls() {
    let (trust, signed, claims) = fixture(NOW);
    let mut revoked = trust.clone();
    revoked.revoked_jobs.insert("job-1".into());
    assert!(signed.verify(&revoked, NOW).is_err());
    let mut newer = trust.clone();
    newer.minimum_policy_epoch = 43;
    assert!(signed.verify(&newer, NOW).is_err());
    assert!(signed.verify(&trust, NOW + 3600).is_err());
    assert!(signed.verify(&trust, NOW - 11).is_err());
    let rp = data_policy(trust);
    assert!(rp.authorize(&claims, "workload/data/v1", NOW + 61).is_err());
    assert!(rp.authorize(&claims, "workload/data/v1", NOW - 1).is_err());
}

#[test]
fn token_context_and_all_appraisals_are_mandatory() {
    let (trust, _, claims) = fixture(NOW);
    let rp = data_policy(trust);
    for (path,value) in [
        ("/iss",json!("attacker")),("/aud",json!("another-rp")),("/exp",json!(NOW)),
        ("/submods/cpu0/ear.status",json!("warning")),
        ("/submods/cpu0/ear.trustee.policy-results/1/status",json!("warning")),
        ("/submods/cpu0/ear.trustee.policy-results/1/policy_id",json!("default")),
        ("/cnf/jwk/x",json!("attacker-key")),
        ("/submods/cpu0/ear.veraison.annotated-evidence/workload/measurement",json!("99".repeat(48))),
        ("/submods/cpu0/ear.veraison.annotated-evidence/init_data",json!("00".repeat(48))),
        ("/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims/nonce",json!("changed-nonce-000000")),
        ("/submods/cpu0/ear.veraison.annotated-evidence/init_data_claims/agent_policy_claims/containers",json!([]))
    ] {
        let mut bad=claims.clone(); *bad.pointer_mut(path).unwrap()=value;
        assert!(rp.authorize(&bad,"workload/data/v1",NOW).is_err(),"accepted {path}");
    }
    let mut bad = claims.clone();
    bad.as_object_mut().unwrap().remove(CLAIM);
    assert!(rp.authorize(&bad, "workload/data/v1", NOW).is_err());
}

#[test]
fn stage_is_derived_from_measurement_and_self_report_cannot_release_data() {
    let (trust, _, mut claims) = fixture(NOW);
    let e = &mut claims["submods"]["cpu0"]["ear.veraison.annotated-evidence"];
    e["workload"]["measurement"] = json!("11".repeat(48));
    e["runtime_data_claims"]["model_loaded"] = json!(true);
    let (_, binding) = evaluate_verified_evidence(e, &trust, NOW).unwrap();
    assert_eq!(binding.stage, Stage::ApplicationReady);
    claims[CLAIM] = json!(binding);
    claims["aud"] = json!(["https://d-kbs.example", "https://m-kbs.example"]);
    assert!(data_policy(trust.clone())
        .authorize(&claims, "workload/data/v1", NOW)
        .is_err());
    let mut model = data_policy(trust);
    model.role = Role::Model;
    model.audience = "https://m-kbs.example".into();
    model.authorize(&claims, "workload/model/v7", NOW).unwrap();
}

#[test]
fn unsupported_profiles_and_unsafe_contracts_never_fall_back() {
    let (_, signed, _) = fixture(NOW);
    for change in [0, 1, 2, 3, 4] {
        let mut c = signed.contract.clone();
        match change {
            0 => c.require_gpu = true,
            1 => c.members = 2,
            2 => c.stages[0].grants.push(Grant {
                role: Role::Data,
                audience: "https://d-kbs.example".into(),
                resource: "workload/data/v1".into(),
            }),
            3 => c.stages[0].measurement = c.stages[1].measurement.clone(),
            _ => c.stages[1].grants[0].resource = "default/data/v1".into(),
        }
        assert!(
            c.validate(NOW).is_err(),
            "accepted unsafe contract {change}"
        );
    }
}
