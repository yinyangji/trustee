// SPDX-License-Identifier: Apache-2.0

use std::{process::Command, sync::Arc};

use base64::{engine::general_purpose::STANDARD, Engine};
use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};
use policy_engine::rego::{Regorus, RegorusExtension};
use reference_value_provider_service::Rvps;
use serde_json::{json, Value};

#[tokio::test]
async fn single_policy_requires_an_approved_boot_application_and_binding() {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../hack/build-tdx-inference-policy.py"
        ))
        .output()
        .expect("run the TDX inference policy generator");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let policy = String::from_utf8(output.stdout).unwrap();

    let storage = KeyValueStorageStructConfig::default()
        .to_client_with_namespace(KeyValueStorageType::Memory, "tdx-inference-policy")
        .await
        .unwrap();
    let mut rvps = Rvps::new_with_storage(None, storage).await.unwrap();
    let references = json!({
        "mr_td": ["firmware"],
        "rtmr_1": ["kernel"],
        "rtmr_2": ["cmdline"],
        "xfam": ["xfam"],
        "tdvfkernel": "kernel-event",
        "tdvfkernelparams": "cmdline-event",
        "snp_launch_measurement": ["snp-firmware"],
        "tdx_inference_releases": {
            "https://inference.example": {
                "r1": {"rtmr3": "ab".repeat(48), "init_data_sha384": "cd".repeat(48)},
                "r2": {"rtmr3": "ef".repeat(48), "init_data_sha384": "12".repeat(48)},
                "zero": {"rtmr3": "00".repeat(48), "init_data_sha384": "cd".repeat(48)}
            }
        }
    });
    rvps.verify_and_extract(
        &json!({"type": "sample", "payload": STANDARD.encode(references.to_string())}).to_string(),
    )
    .await
    .unwrap();
    let rvps = Arc::new(rvps);

    let approved = json!({
        "tdx": {
            "quote": {
                "header": {"tee_type": "81000000", "vendor_id": "939a7233f79c4ca9940a0db3957f0607"},
                "body": {
                    "mr_td": "firmware", "rtmr_1": "kernel", "rtmr_2": "cmdline",
                    "rtmr_3": "ab".repeat(48), "mr_config_id": "cd".repeat(48), "xfam": "xfam"
                }
            },
            "td_attributes": {"debug": false},
            "tcb_status": "UpToDate",
            "collateral_expiration_status": "0",
            "uefi_event_logs": [{
                "type_name": "EV_EFI_BOOT_SERVICES_APPLICATION",
                "details": {"device_paths": ["File(kernel)"]},
                "digests": [{"digest": "kernel-event"}]
            }, {
                "type_name": "EV_EVENT_TAG",
                "details": {"string": "LOADED_IMAGE::LoadOptions"},
                "digests": [{"digest": "cmdline-event"}]
            }]
        },
        "init_data": "cd".repeat(48),
        "init_data_claims": {"agent_policy_claims": {"containers": [{}]}},
        "runtime_data_claims": {
            "audience": "https://inference.example",
            "release_id": "r1",
            "nonce": "34".repeat(32),
            "tls_spki_sha256": "56".repeat(32)
        }
    });
    let cases = [
        ("approved UEFI", vec![], 3),
        (
            "approved GRUB",
            vec![("/tdx/uefi_event_logs", json!([]))],
            4,
        ),
        (
            "different application",
            vec![("/tdx/quote/body/rtmr_3", json!("78".repeat(48)))],
            33,
        ),
        (
            "different kernel",
            vec![("/tdx/quote/body/rtmr_1", json!("other"))],
            33,
        ),
        (
            "mixed release measurements",
            vec![
                ("/init_data", json!("12".repeat(48))),
                ("/tdx/quote/body/mr_config_id", json!("12".repeat(48))),
            ],
            33,
        ),
        (
            "unbound InitData",
            vec![("/tdx/quote/body/mr_config_id", json!("12".repeat(48)))],
            33,
        ),
        (
            "missing guest policy",
            vec![("/init_data_claims", Value::Null)],
            33,
        ),
        (
            "missing runtime binding",
            vec![("/runtime_data_claims", Value::Null)],
            33,
        ),
        (
            "malformed nonce",
            vec![("/runtime_data_claims/nonce", json!("short"))],
            33,
        ),
        (
            "malformed TLS key digest",
            vec![("/runtime_data_claims/tls_spki_sha256", json!("short"))],
            33,
        ),
        (
            "unapproved audience",
            vec![(
                "/runtime_data_claims/audience",
                json!("https://other.example"),
            )],
            33,
        ),
        (
            "zero register",
            vec![
                ("/tdx/quote/body/rtmr_3", json!("00".repeat(48))),
                ("/runtime_data_claims/release_id", json!("zero")),
            ],
            33,
        ),
        ("old TCB", vec![("/tdx/tcb_status", json!("OutOfDate"))], 33),
        (
            "expired collateral",
            vec![("/tdx/collateral_expiration_status", json!("1"))],
            33,
        ),
        (
            "debug enabled",
            vec![("/tdx/td_attributes/debug", json!(true))],
            33,
        ),
    ];
    for (label, replacements, expected) in cases {
        let mut claims = approved.clone();
        for (path, value) in replacements {
            *claims.pointer_mut(path).unwrap() = value;
        }
        assert_eq!(
            evaluate(&policy, claims, Arc::clone(&rvps)).await,
            expected,
            "{label}"
        );
    }
    let snp = json!({"snp":{"measurement":"snp-firmware"}});
    assert_eq!(evaluate(&policy, snp, rvps).await, 33);
}

async fn evaluate(policy: &str, claims: Value, rvps: Arc<Rvps>) -> Value {
    let results = Regorus::default()
        .evaluate(
            None,
            claims.to_string(),
            policy.to_owned(),
            vec!["data.policy.trust_claims".into()],
            vec![RegorusExtension {
                name: "query_reference_value".into(),
                id: 1,
                extension: Box::new(move |args| {
                    let id = args[0].as_string()?.to_string();
                    let value = tokio::runtime::Handle::current()
                        .block_on(rvps.query_reference_value(&id))?
                        .unwrap_or(Value::Null);
                    Ok(serde_json::from_value(value)?)
                }),
            }],
        )
        .await
        .unwrap();
    results.eval_rules_result["data.policy.trust_claims"]
        .as_ref()
        .unwrap()["executables"]
        .clone()
}
