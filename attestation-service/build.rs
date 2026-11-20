use std::{env, fs, path::PathBuf, process::exit};

use shadow_rs::{BuildPattern, ShadowBuilder};

fn real_main() -> Result<(), String> {
    #[cfg(feature = "grpc-bin")]
    tonic_prost_build::compile_protos("../protos/attestation.proto").map_err(|e| format!("{e}"))?;

    #[cfg(feature = "grpc-bin")]
    tonic_prost_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(&["../protos/reference.proto"], &["../protos"])
        .map_err(|e| format!("{e}"))?;
    Ok(())
}

fn main() -> shadow_rs::SdResult<()> {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {e}");
        exit(1);
    }

    println!("cargo:rerun-if-env-changed=TRUSTEE_AS_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    if let Some(commit) = env::var("TRUSTEE_AS_BUILD_COMMIT")
        .ok()
        .filter(|s| !s.is_empty())
    {
        if let Err(err) = release_metadata(&commit) {
            eprintln!("ERROR: {err}");
            exit(1);
        }
        return Ok(());
    }

    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()?;
    Ok(())
}

fn release_metadata(commit: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(commit.len(), 40 | 64)
        || !commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("TRUSTEE_AS_BUILD_COMMIT must be a full lowercase Git object ID".into());
    }
    let epoch: u64 = env::var("SOURCE_DATE_EPOCH")?.parse()?;
    let path = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?).join("shadow.rs");
    let version = env!("CARGO_PKG_VERSION");
    fs::write(
        path,
        format!(
            "pub const PKG_VERSION: &str = {version:?};\n             pub const COMMIT_HASH: &str = {commit:?};\n             pub const BUILD_TIME: &str = \"{epoch}\";\n"
        ),
    )?;
    Ok(())
}
