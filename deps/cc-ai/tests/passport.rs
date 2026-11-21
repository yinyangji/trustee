#[allow(dead_code)]
mod common;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use openssl::{
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_json::{json, Value};
use trustee_cc_ai::{
    passport::{self, sign_redemption, AssetPassportVerifier, RegisteredJob},
    *,
};

const NOW: i64 = 1_794_747_600;
fn key() -> PKey<Private> {
    PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap()
}
fn jwt(claims: &Value, as_key: &PKey<Private>) -> String {
    let h = B64.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
    let p = B64.encode(serde_json::to_vec(claims).unwrap());
    let input = format!("{h}.{p}");
    let mut s = Signer::new(MessageDigest::sha256(), as_key).unwrap();
    s.update(input.as_bytes()).unwrap();
    let sig = EcdsaSig::from_der(&s.sign_to_vec().unwrap()).unwrap();
    format!(
        "{input}.{}",
        B64.encode(
            [
                sig.r().to_vec_padded(32).unwrap(),
                sig.s().to_vec_padded(32).unwrap()
            ]
            .concat()
        )
    )
}
struct Fixture {
    trust: TrustPolicy,
    job: SignedJob,
    as_key: PKey<Private>,
    pop: PKey<Private>,
    claims: Value,
}
fn fixture() -> Fixture {
    let (trust, job, mut raw) = common::fixture(NOW);
    let pop = key();
    let as_key = key();
    let evidence = &mut raw["submods"]["cpu0"]["ear.veraison.annotated-evidence"];
    evidence["runtime_data_claims"][passport::POP_KEY] =
        public_jwk_from_pem(&pop.public_key_to_pem().unwrap()).unwrap();
    let (_, binding) = evaluate_verified_evidence(evidence, &trust, NOW).unwrap();
    let p = passport::from_verified_evidence(evidence, binding).unwrap();
    // Deliberately no native evidence or EAR appraisals. Asset owners consume
    // only the versioned, AS-signed normalized result.
    let claims = json!({"iss":"https://as.example","aud":["https://d-kbs.example"],"iat":NOW,"exp":NOW+120,
        "cnf":{"jwk":p.pop_key},passport::CLAIM:p});
    Fixture {
        trust,
        job,
        as_key,
        pop,
        claims,
    }
}
fn adapter(f: &Fixture) -> AssetPassportVerifier {
    AssetPassportVerifier::new(
        common::data_policy(f.trust.clone()),
        f.as_key.public_key_to_pem().unwrap(),
    )
    .unwrap()
}

#[test]
fn kms_works_without_native_evidence_and_reuses_passport_with_fresh_proofs() {
    let f = fixture();
    let rp = adapter(&f);
    let registered = RegisteredJob::new(f.job.clone(), &f.trust, NOW).unwrap();
    let token = jwt(&f.claims, &f.as_key);
    for _ in 0..2 {
        let challenge = rp
            .challenge(&registered, &token, "workload/data/v1", NOW)
            .unwrap();
        let proof =
            sign_redemption(&challenge, &f.pop.private_key_to_pem_pkcs8().unwrap(), NOW).unwrap();
        let grant = rp
            .redeem(&registered, &token, &challenge.nonce, &proof, NOW)
            .unwrap();
        assert_eq!(grant.resource(), "workload/data/v1");
        assert_eq!(grant.job_id(), "job-1");
        assert!(rp
            .redeem(&registered, &token, &challenge.nonce, &proof, NOW)
            .is_err());
    }
}

#[test]
fn stolen_token_wrong_holder_changed_resource_and_expired_nonce_are_denied() {
    let f = fixture();
    let rp = adapter(&f);
    let job = RegisteredJob::new(f.job.clone(), &f.trust, NOW).unwrap();
    let token = jwt(&f.claims, &f.as_key);
    let challenge = rp.challenge(&job, &token, "workload/data/v1", NOW).unwrap();
    let bad = sign_redemption(&challenge, &key().private_key_to_pem_pkcs8().unwrap(), NOW).unwrap();
    assert!(rp
        .redeem(&job, &token, &challenge.nonce, &bad, NOW)
        .is_err());
    let mut changed = challenge.clone();
    changed.resource = "workload/data/other".into();
    let bad = sign_redemption(&changed, &f.pop.private_key_to_pem_pkcs8().unwrap(), NOW).unwrap();
    assert!(rp
        .redeem(&job, &token, &challenge.nonce, &bad, NOW)
        .is_err());
    let good =
        sign_redemption(&challenge, &f.pop.private_key_to_pem_pkcs8().unwrap(), NOW).unwrap();
    assert!(rp
        .redeem(&job, &token, &challenge.nonce, &good, NOW + 60)
        .is_err());
    // Invalid proofs do not consume another holder's valid pending challenge.
    rp.redeem(&job, &token, &challenge.nonce, &good, NOW)
        .unwrap();
}

#[test]
fn normalized_result_must_match_issuer_audience_job_stage_and_confirmation() {
    let f = fixture();
    let job = RegisteredJob::new(f.job.clone(), &f.trust, NOW).unwrap();
    for (path, v) in [
        ("/iss".to_string(), json!("attacker")),
        ("/aud".to_string(), json!("wrong-rp")),
        (
            format!("/{}/profile", passport::CLAIM.replace('/', "~1")),
            json!("unknown-profile"),
        ),
        (
            format!("/{}/job/stage", passport::CLAIM.replace('/', "~1")),
            json!("application-ready"),
        ),
        (
            format!(
                "/{}/job/contract_digest",
                passport::CLAIM.replace('/', "~1")
            ),
            json!("ff".repeat(48)),
        ),
        ("/cnf/jwk/x".to_string(), json!("unbound-key")),
    ] {
        let mut c = f.claims.clone();
        *c.pointer_mut(&path).unwrap() = v;
        assert!(
            adapter(&f)
                .challenge(&job, &jwt(&c, &f.as_key), "workload/data/v1", NOW)
                .is_err(),
            "accepted {path}"
        );
    }
    assert!(adapter(&f)
        .challenge(&job, &jwt(&f.claims, &key()), "workload/data/v1", NOW)
        .is_err());
    assert!(adapter(&f)
        .challenge(&job, &jwt(&f.claims, &f.as_key), "workload/data/other", NOW)
        .is_err());
}

#[test]
fn one_nonce_can_only_be_consumed_once_under_concurrent_redemption() {
    use std::sync::{Arc, Barrier};
    let f = fixture();
    let rp = Arc::new(adapter(&f));
    let job = Arc::new(RegisteredJob::new(f.job.clone(), &f.trust, NOW).unwrap());
    let token = jwt(&f.claims, &f.as_key);
    let c = rp.challenge(&job, &token, "workload/data/v1", NOW).unwrap();
    let proof = sign_redemption(&c, &f.pop.private_key_to_pem_pkcs8().unwrap(), NOW).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let (rp, job, token, proof, nonce, b) = (
                rp.clone(),
                job.clone(),
                token.clone(),
                proof.clone(),
                c.nonce.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                b.wait();
                rp.redeem(&job, &token, &nonce, &proof, NOW).is_ok()
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .filter_map(|w| w.join().ok())
            .filter(|ok| *ok)
            .count(),
        1
    );
}

#[test]
fn changed_owner_approval_and_old_ear_cannot_be_used_as_passport() {
    let f = fixture();
    let job = RegisteredJob::new(f.job.clone(), &f.trust, NOW).unwrap();
    let mut policy = common::data_policy(f.trust.clone());
    policy.trust.minimum_policy_epoch += 1;
    let rp = AssetPassportVerifier::new(policy, f.as_key.public_key_to_pem().unwrap()).unwrap();
    assert!(rp
        .challenge(&job, &jwt(&f.claims, &f.as_key), "workload/data/v1", NOW)
        .is_err());
    let (_, _, legacy) = common::fixture(NOW);
    assert!(adapter(&f)
        .challenge(&job, &jwt(&legacy, &f.as_key), "workload/data/v1", NOW)
        .is_err());
}

#[test]
fn application_passport_can_get_model_but_cannot_get_data() {
    let mut f = fixture();
    f.claims[passport::CLAIM]["job"]["stage"] = json!("application-ready");
    f.claims["aud"] = json!(["https://m-kbs.example", "https://d-kbs.example"]);
    let job = RegisteredJob::new(f.job.clone(), &f.trust, NOW).unwrap();
    let mut policy = common::data_policy(f.trust.clone());
    policy.role = Role::Model;
    policy.audience = "https://m-kbs.example".into();
    let rp = AssetPassportVerifier::new(policy, f.as_key.public_key_to_pem().unwrap()).unwrap();
    let token = jwt(&f.claims, &f.as_key);
    let c = rp
        .challenge(&job, &token, "workload/model/v7", NOW)
        .unwrap();
    let proof = sign_redemption(&c, &f.pop.private_key_to_pem_pkcs8().unwrap(), NOW).unwrap();
    assert_eq!(
        rp.redeem(&job, &token, &c.nonce, &proof, NOW)
            .unwrap()
            .resource(),
        "workload/model/v7"
    );
    assert!(adapter(&f)
        .challenge(&job, &token, "workload/data/v1", NOW)
        .is_err());
}
