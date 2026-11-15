//! Protocol tests use a test-only driver. They assert no hardware properties.
use std::{collections::BTreeMap, path::PathBuf};
use trustee_platform_api::credentials::{KeyBinding, KeyReference, ProviderConfig};

fn provider(mode: &str) -> ProviderConfig {
    let driver = r#"
import base64,json,os,sys
r=json.load(sys.stdin)
mode=os.environ['TEST_DRIVER_MODE']
if r['operation']=='describe':
 print(json.dumps({'result':'description','info':{'api_version': 99 if mode=='version' else 1,'provider':'test-contract','hardware_sealing':mode!='software'}}))
elif mode=='malformed': print('invalid json')
elif mode=='failure': sys.exit(1)
elif r['operation']=='seal':
 print(json.dumps({'result':'sealed','ciphertext':base64.b64encode(json.dumps({'binding':r['binding'],'plaintext':r['plaintext']}).encode()).decode()}))
else:
 data=json.loads(base64.b64decode(r['ciphertext']))
 if data['binding']!=r['binding']: sys.exit(1)
 print(json.dumps({'result':'unsealed','plaintext':data['plaintext']}))
"#;
    ProviderConfig {
        command: PathBuf::from("/usr/bin/python3"),
        arguments: vec!["-I".into(), "-S".into(), "-c".into(), driver.into()],
        expected_provider: "test-contract".into(),
        environment: BTreeMap::from([("TEST_DRIVER_MODE".into(), mode.into())]),
    }
}

#[tokio::test]
async fn sealing_roundtrip_binds_identity_and_purpose_across_processes() {
    let dir = tempfile::tempdir().unwrap();
    let binding = KeyBinding {
        key_id: "service-ak-v1".into(),
        purpose: "kbs-credentials".into(),
    };
    let config = provider("ok");
    let sealed = config
        .seal(binding.clone(), b"PUBLIC_TEST_ACCESS_KEY")
        .await
        .unwrap();
    let path = dir.path().join("key.json");
    std::fs::write(&path, serde_json::to_vec(&sealed).unwrap()).unwrap();
    let mut reference = KeyReference {
        provider: config,
        binding,
        sealed_path: path.clone(),
    };
    assert_eq!(
        reference.load("kbs-credentials").await.unwrap().as_slice(),
        b"PUBLIC_TEST_ACCESS_KEY"
    );
    assert!(reference.load("as-token-signing").await.is_err());
    reference.binding.key_id = "different-key".into();
    assert!(reference.load("kbs-credentials").await.is_err());
    // Even rewriting the outer metadata cannot bypass the driver's inner binding.
    let mut modified = serde_json::to_value(&sealed).unwrap();
    modified["binding"]["key_id"] = serde_json::json!("different-key");
    std::fs::write(path, serde_json::to_vec(&modified).unwrap()).unwrap();
    assert!(reference.load("kbs-credentials").await.is_err());
}

#[tokio::test]
async fn unavailable_or_wrong_capability_never_falls_back_to_plaintext() {
    let binding = KeyBinding {
        key_id: "key-v1".into(),
        purpose: "service".into(),
    };
    for mode in ["software", "version", "failure", "malformed"] {
        assert!(provider(mode)
            .seal(binding.clone(), b"PUBLIC_TEST_SECRET")
            .await
            .is_err());
    }
    let mut wrong = provider("ok");
    wrong.expected_provider = "another-provider".into();
    assert!(wrong.describe().await.is_err());
    wrong.command = "/no-such-platform-driver".into();
    assert!(wrong.describe().await.is_err());
    assert!(provider("ok").seal(binding, &[]).await.is_err());
}
