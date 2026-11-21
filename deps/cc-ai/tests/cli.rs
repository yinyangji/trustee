#[allow(dead_code)]
mod common;
use std::{fs, process::Command};
use trustee_cc_ai::*;

#[test]
fn offline_approvals_assembly_launch_binding_and_create_new_semantics() {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let (trust, signed, _) = common::fixture(now);
    let dir = tempfile::tempdir().unwrap();
    let path = |n: &str| dir.path().join(n);
    fs::write(
        path("contract.json"),
        serde_json::to_vec(&signed.contract).unwrap(),
    )
    .unwrap();
    fs::write(path("trust.json"), serde_json::to_vec(&trust).unwrap()).unwrap();
    for (i, sig) in signed.signatures.iter().enumerate() {
        fs::write(path(&format!("{i}.jws")), sig).unwrap();
    }
    let result = Command::new(env!("CARGO_BIN_EXE_cc-ai"))
        .args(["assemble", "--contract"])
        .arg(path("contract.json"))
        .arg("--signatures")
        .args([path("0.jws"), path("1.jws"), path("2.jws")])
        .arg("--trust")
        .arg(path("trust.json"))
        .arg("--output")
        .arg(path("job.json"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let parsed: SignedJob = serde_json::from_slice(&fs::read(path("job.json")).unwrap()).unwrap();
    parsed.verify(&trust, now).unwrap();
    fs::write(path("initdata.toml"),"version = \"0.1.0\"\nalgorithm = \"sha384\"\n[data]\n\"policy.rego\" = \"approved-agent-policy\"\n").unwrap();
    let args = vec![
        "init-data".into(),
        "--input".into(),
        path("initdata.toml"),
        "--job".into(),
        path("job.json"),
        "--trust".into(),
        path("trust.json"),
        "--output".into(),
        path("bound.toml"),
    ];
    let good = Command::new(env!("CARGO_BIN_EXE_cc-ai"))
        .args(&args)
        .output()
        .unwrap();
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    let bound: toml::Value =
        toml::from_str(&fs::read_to_string(path("bound.toml")).unwrap()).unwrap();
    assert_eq!(
        serde_json::from_str::<SignedJob>(bound["data"][INIT_DATA_KEY].as_str().unwrap()).unwrap(),
        signed
    );
    assert!(!Command::new(env!("CARGO_BIN_EXE_cc-ai"))
        .args(&args)
        .status()
        .unwrap()
        .success());
    fs::write(
        path("initdata.toml"),
        "algorithm=\"sha384\"\n[data]\n\"policy.rego\"=\"unapproved\"",
    )
    .unwrap();
    fs::remove_file(path("bound.toml")).unwrap();
    assert!(!Command::new(env!("CARGO_BIN_EXE_cc-ai"))
        .args(&args)
        .status()
        .unwrap()
        .success());
    assert!(!path("bound.toml").exists());
}
