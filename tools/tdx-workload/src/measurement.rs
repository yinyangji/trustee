//! Versioned, RFC 8785 canonical measurement transcript shared with the offline tool.
use anyhow::{bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};

pub const PROFILE: &str = "trustee.tdx-workload.v2";

pub fn manifest(
    files: Vec<Value>,
    python: bool,
    arguments: &[String],
    uid: u32,
    gid: u32,
) -> Result<Vec<u8>> {
    if uid == 0 || gid == 0 {
        bail!("Workloads must run with a non-root UID and GID");
    }
    if files.is_empty() || (python && files.len() < 2) {
        bail!("A workload and, for Python, an interpreter are required");
    }
    Ok(serde_json_canonicalizer::to_vec(&json!({
        "version": 2,
        "profile": PROFILE,
        "files": files,
        "execution": {
            "kind": if python { "python-isolated" } else { "native" },
            "arguments": arguments,
            "uid": uid, "gid": gid,
            "environment": {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "TZ": "UTC"},
            "working_directory": "/",
            "resource": "sealed-inherited-fd",
        },
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_transcript_matches_offline_protocol_vector() {
        let v: Value =
            serde_json::from_str(include_str!("../testdata/measurement-v2.json")).unwrap();
        let files = v["files"].as_array().unwrap().clone();
        let args = vec!["--mode".to_owned(), "α".to_owned()];
        let content = manifest(files.clone(), true, &args, 65534, 65534).unwrap();
        assert_eq!(
            std::str::from_utf8(&content).unwrap(),
            v["canonical"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(extend(&[0; 48], &content).unwrap()),
            v["expected"].as_str().unwrap()
        );
        assert_ne!(
            manifest(files.clone(), false, &args, 65534, 65534).unwrap(),
            content
        );
        assert_ne!(
            manifest(files.clone(), true, &[], 65534, 65534).unwrap(),
            content
        );
        assert_ne!(
            manifest(files.clone(), true, &args, 1000, 65534).unwrap(),
            content
        );
        assert!(manifest(files, true, &args, 0, 65534).is_err());
        assert!(extend(&[0; 47], &content).is_err());
    }
}

pub fn extend(initial: &[u8], content: &[u8]) -> Result<Vec<u8>> {
    if initial.len() != 48 {
        bail!("Initial RTMR[3] must contain exactly 48 bytes");
    }
    Ok(Sha384::digest([initial, Sha384::digest(content).as_slice()].concat()).to_vec())
}
