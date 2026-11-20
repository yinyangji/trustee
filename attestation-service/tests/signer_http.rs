// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "grpc-bin",
    feature = "restful-bin",
    feature = "tdx-self-attestation"
))]

use std::{process::Stdio, time::Duration};

use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::process::Command;

/// Exercise both shipped HTTP frontends. These tests never manufacture a
/// successful hardware proof; acceptance of genuine Quotes needs a TDX guest.
#[tokio::test]
async fn bootstrap_frontends_reject_key_injection_and_unbounded_input() {
    for binary in [
        env!("CARGO_BIN_EXE_grpc-as"),
        env!("CARGO_BIN_EXE_restful-as"),
    ] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("as.json");
        let config = json!({"attestation_token_broker":{
            "issuer_name":"https://as.example", "self_attestation":{
                "as_release_manifest_digest":"aa".repeat(32),
                "governance":{
                    "policy_hashes":{"default_cpu":"bb".repeat(48)},
                    "reference_values":{"mr_td":["cc".repeat(48)]},
                    "expires_at":trustee_attested_signer::unix_time().unwrap()+3600
                }
            }
        }});
        std::fs::write(&path, config.to_string()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut child = Command::new(binary)
            .args([
                "--socket",
                &address.to_string(),
                "--config-file",
                path.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let url = format!("http://{address}");
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "AS exited before serving: {binary}"
                );
                if client
                    .get(format!("{url}/.well-known/jwks.json"))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let metadata: Value = client
            .get(format!("{url}/.well-known/attestation-configuration"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(metadata["issuer"], "https://as.example");
        let jwks: Value = client
            .get(format!("{url}/.well-known/jwks.json"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(jwks["keys"][0]["kid"].as_str().unwrap().len(), 64);
        let proof_url = format!("{url}/signer-evidence");
        for body in [
            json!({"kid":"ff".repeat(32),"nonce":"invalid"}),
            json!({"kid":"ff".repeat(32),"nonce":"aa".repeat(32),"signing_key":{"x":"replacement"}}),
            json!({"kid":"ff".repeat(32),"nonce":"a".repeat(2048)}),
        ] {
            let response = client.post(&proof_url).json(&body).send().await.unwrap();
            assert!(
                response.status().is_client_error(),
                "{binary}: {}",
                response.status()
            );
        }
        let response = client
            .post(&proof_url)
            .json(&json!({"kid":"ff".repeat(32),"nonce":"aa".repeat(32)}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.text().await.unwrap().contains("private"));
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
}
