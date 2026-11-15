use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use trustee_cc_ai::*;

pub fn fixture(now: i64) -> (TrustPolicy, SignedJob, Value) {
    let mut keys = vec![];
    let mut authorities = vec![];
    let roles = [Role::Data, Role::Model, Role::User];
    for (i, role) in roles.iter().enumerate() {
        let key = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        authorities.push(Authority {
            key_id: format!("key-{i}"),
            party_id: format!("party-{i}"),
            role: role.clone(),
            public_key_pem: String::from_utf8(key.public_key_to_pem().unwrap()).unwrap(),
        });
        keys.push(key.private_key_to_pem_pkcs8().unwrap());
    }
    let trust = TrustPolicy {
        authorities,
        minimum_policy_epoch: 42,
        revoked_jobs: BTreeSet::new(),
    };
    let contract = JobContract {
        schema: SCHEMA.into(),
        job_id: "job-1".into(),
        tenant_id: "tenant-a".into(),
        purpose: Purpose::Infer,
        parties: roles
            .into_iter()
            .enumerate()
            .map(|(i, r)| (r, format!("party-{i}")))
            .collect::<BTreeMap<_, _>>(),
        release_id: "release-1".into(),
        model_id: "model-7".into(),
        agent_policy_digest: sha384(b"approved-agent-policy"),
        output_policy_digest: "aa".repeat(48),
        recipient_key_digest: "bb".repeat(48),
        policy_epoch: 42,
        not_before: now - 10,
        expires_at: now + 3600,
        require_gpu: false,
        members: 1,
        stages: vec![
            StageReference {
                stage: Stage::ApplicationReady,
                measurement: "11".repeat(48),
                grants: vec![Grant {
                    role: Role::Model,
                    audience: "https://m-kbs.example".into(),
                    resource: "workload/model/v7".into(),
                }],
            },
            StageReference {
                stage: Stage::ModelVerified,
                measurement: "22".repeat(48),
                grants: vec![Grant {
                    role: Role::Data,
                    audience: "https://d-kbs.example".into(),
                    resource: "workload/data/v1".into(),
                }],
            },
        ],
        service_audiences: ["https://client.example".into()].into(),
    };
    let signed = SignedJob {
        signatures: keys
            .iter()
            .enumerate()
            .map(|(i, k)| sign_contract(&contract, &format!("key-{i}"), k).unwrap())
            .collect(),
        contract,
    };
    let channel = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let key = public_jwk_from_pem(&channel.public_key_to_pem().unwrap()).unwrap();
    let e = json!({"init_data":"cc".repeat(48),
        "init_data_claims": {"agent_policy_claims":{"containers":[{}]},AGENT_POLICY_DIGEST:sha384(b"approved-agent-policy"),INIT_DATA_KEY:serde_json::to_string(&signed).unwrap()},
        "workload":{"profile":"trustee.tdx-workload.v2","launch_digest":"cc".repeat(48),"measurement":"22".repeat(48)},
        "runtime_data_claims":{"nonce":"fresh-challenge-0123456789","tee-pubkey":key}});
    let (_, binding) = evaluate_verified_evidence(&e, &trust, now).unwrap();
    let claims = json!({"iss":"https://as.example","aud":["https://d-kbs.example","https://client.example"],
        "iat":now,"exp":now+120,"cnf":{"jwk":key},CLAIM:binding,
        "submods":{"cpu0":{"ear.status":"affirming","ear.trustee.policy-results":[
            {"policy_id":"default","status":"affirming"},{"policy_id":"application","status":"affirming"}],
            "ear.veraison.annotated-evidence":e}}});
    (trust, signed, claims)
}

pub fn data_policy(trust: TrustPolicy) -> RelyingPartyPolicy {
    RelyingPartyPolicy {
        trust,
        issuer: "https://as.example".into(),
        audience: "https://d-kbs.example".into(),
        role: Role::Data,
        max_token_age_seconds: 60,
    }
}
