//! Measure immutable executable/script snapshots, attest, retrieve a resource,
//! and execute those same snapshots. Linux native TDX only.
use anyhow::{bail, Context, Result};
#[cfg(feature = "integration-test")]
use base64::engine::general_purpose::STANDARD;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use kbs_protocol::keypair::TeeKeyPair;
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
};

mod measurement;
use tdx_workload::tdx_evidence;

use tdx_evidence::RTMR3 as REGISTER;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    url: String,
    /// Attestation policy selector. A Pod sets this at start with
    /// ATTESTATION_POLICY_SELECTOR; an explicit flag overrides the variable.
    #[arg(long, env = "ATTESTATION_POLICY_SELECTOR")]
    selector: Option<String>,
    /// Relying-party name for a passport attestation. Used with --passport-nonce.
    #[arg(long)]
    passport_audience: Option<String>,
    /// Challenge issued by the data or model KMS. KBS uses it as the attestation nonce.
    #[arg(long)]
    passport_nonce: Option<String>,
    /// Client session ID included in the primary Quote's runtime data.
    #[arg(long, requires_all = ["passport_audience", "passport_nonce"])]
    passport_session_id: Option<String>,
    #[arg(long)]
    resource: Option<String>,
    /// Files in manifest order. The first is the executable, or script with --interpreter.
    #[arg(long = "file")]
    files: Vec<PathBuf>,
    /// Python 3 interpreter; executed with -I -S. Include and seal it first.
    #[arg(long)]
    interpreter: Option<PathBuf>,
    /// Structured CoCo Init-Data TOML, already bound to MRCONFIGID at VM launch.
    #[arg(long)]
    init_data: Option<PathBuf>,
    #[arg(long, default_value_t = 65534)]
    run_uid: u32,
    #[arg(long, default_value_t = 65534)]
    run_gid: u32,
    /// Execute measured snapshots after the resource is successfully decrypted.
    #[arg(long, requires = "resource")]
    execute: bool,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, default_value = "/run/tdx-workload/events.bin")]
    journal: PathBuf,
    /// Corrupt a fresh hardware quote to test AS rejection (lab builds only).
    #[cfg(feature = "integration-test")]
    #[arg(long)]
    corrupt_quote: bool,
    #[arg(last = true)]
    arguments: Vec<String>,
}

struct Snapshot {
    file: File,
    path: PathBuf,
    digest: String,
}

fn insert_passport(
    params: &mut Value,
    audience: &Option<String>,
    nonce: &Option<String>,
) -> Result<()> {
    match (audience, nonce) {
        (None, None) => Ok(()),
        (Some(audience), Some(nonce)) => {
            params["passport-audience"] = json!(audience);
            params["passport-nonce"] = json!(nonce);
            Ok(())
        }
        _ => bail!("passport audience and nonce must be supplied together"),
    }
}

fn bind_passport_audience(mut runtime: Value, audience: &Option<String>) -> Value {
    if let Some(audience) = audience {
        runtime["audience"] = json!(audience);
    }
    runtime
}

fn insert_passport_session(params: &mut Value, session_id: &Option<String>) -> Result<()> {
    if let Some(id) = session_id {
        if id.len() != 64
            || !id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            bail!("passport-session-id must be 32-byte lowercase hex");
        }
        params["passport-session-id"] = json!(id);
    }
    Ok(())
}

fn snapshot(path: &Path) -> Result<Snapshot> {
    let mut source = File::open(path).with_context(|| format!("Read {}", path.display()))?;
    if !source.metadata()?.is_file() {
        bail!("Measured input must be a regular file");
    }
    let mut file = sealed_file(&mut source)?;
    let mut hash = Sha384::new();
    let mut buffer = [0u8; 65536];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(Snapshot {
        file,
        path: path.to_owned(),
        digest: hex::encode(hash.finalize()),
    })
}

fn sealed_file(source: &mut impl Read) -> Result<File> {
    let name = CString::new("trustee-measured-workload")?;
    // No CLOEXEC: the interpreter must be able to open its sealed script FD.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    std::io::copy(source, &mut file)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

fn manifest(snapshots: &[Snapshot], args: &Args) -> Result<Vec<u8>> {
    let files: Vec<_> = snapshots
        .iter()
        .map(|s| json!({"path": s.path, "sha384": s.digest}))
        .collect();
    measurement::manifest(
        files,
        args.interpreter.is_some(),
        &args.arguments,
        args.run_uid,
        args.run_gid,
    )
}

fn private_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!(
            "Directory {} must be owned by this user and mode 0700",
            path.display()
        );
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

fn workload_command(snapshots: &[Snapshot], args: &Args, resource: &File) -> Result<Command> {
    if args.run_uid == 0 || args.run_gid == 0 {
        bail!("Workloads must not run as root");
    }
    let fd_path = |s: &Snapshot| format!("/proc/self/fd/{}", s.file.as_raw_fd());
    let mut command = Command::new(fd_path(&snapshots[0]));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("TZ", "UTC")
        .env("TDX_WORKLOAD_RESOURCE_FD", resource.as_raw_fd().to_string())
        .current_dir("/");
    if args.interpreter.is_some() {
        command.args(["-I", "-S"]).arg(fd_path(&snapshots[1]));
    }
    command.args(&args.arguments);
    let (uid, gid) = (args.run_uid, args.run_gid);
    // Only async-signal-safe system calls may run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::geteuid() == 0 {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::geteuid() != uid || libc::getegid() != gid {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
    Ok(command)
}

async fn checked(response: reqwest::Response) -> Result<Value> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("HTTP {status}: {body}");
    }
    Ok(serde_json::from_str(&body)?)
}

fn validate_execution(args: &Args, service_uid: u32) -> Result<()> {
    if args.run_uid == 0 || args.run_gid == 0 {
        bail!("Workloads must not run as root");
    }
    if args.execute {
        if service_uid != 0 {
            bail!("--execute requires a dedicated root measurement service and a different workload UID");
        }
        if args.init_data.is_none() {
            bail!("--execute requires launch-bound --init-data and an approved Agent Policy");
        }
        if args.selector.as_deref() != Some("workload")
            || !args
                .resource
                .as_deref()
                .is_some_and(|r| r.starts_with("workload/"))
        {
            bail!("--execute requires the workload selector and a workload resource; boot-only authorization is insufficient");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if (args.execute || args.interpreter.is_some()) && args.files.is_empty() {
        bail!("--execute requires a measured file");
    }
    validate_execution(&args, unsafe { libc::geteuid() })?;
    let init_data = args
        .init_data
        .as_ref()
        .map(fs::read_to_string)
        .transpose()?;
    private_directory(&args.output_dir)?;
    private_directory(
        args.journal
            .parent()
            .context("Journal needs a parent directory")?,
    )?;
    let journal_file = fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&args.journal)?;
    let metadata = journal_file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("Journal must be a private regular file owned by the measurement service");
    }
    if unsafe { libc::flock(journal_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut previous = vec![];
    (&journal_file).read_to_end(&mut previous)?;

    let mut paths = vec![];
    if let Some(interpreter) = &args.interpreter {
        paths.push(interpreter.clone());
    }
    paths.extend(args.files.clone());
    let snapshots = paths
        .iter()
        .map(|p| snapshot(p))
        .collect::<Result<Vec<_>>>()?;
    let event = if snapshots.is_empty() {
        None
    } else {
        let content = manifest(&snapshots, &args)?;
        let initial = fs::read(REGISTER).context("Read native TDX RTMR[3]")?;
        if initial.len() != 48 {
            bail!("Unexpected RTMR[3] length");
        }
        let digest = Sha384::digest(&content);
        let mut extend = fs::OpenOptions::new().write(true).open(REGISTER)?;
        extend.write_all(&digest)?;
        let final_value = fs::read(REGISTER)?;
        let expected = measurement::extend(&initial, &content)?;
        if final_value.as_slice() != expected.as_slice() {
            bail!("Concurrent or unsuccessful RTMR[3] extension");
        }
        write_private(
            &args.output_dir.join("measurement.json"),
            &serde_json::to_vec_pretty(&json!({
                "manifest": serde_json::from_slice::<Value>(&content)?,
                "event_digest": hex::encode(digest), "initial_rtmr_3": hex::encode(initial),
                "expected_rtmr_3": hex::encode(final_value)
            }))?,
        )?;
        Some(tdx_evidence::tcg_event(&content))
    };
    if let Some(ref event) = event {
        let mut writer = &journal_file;
        writer.write_all(event)?;
        writer.sync_all()?;
    }
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .timeout(std::time::Duration::from_secs(90))
        .build()?;
    let mut params = json!({"supported-hash-algorithms": ["sha384"]});
    if let Some(selector) = args.selector.as_ref().filter(|value| !value.is_empty()) {
        params["attestation-policy-selector"] = json!(selector);
    }
    insert_passport(&mut params, &args.passport_audience, &args.passport_nonce)?;
    insert_passport_session(&mut params, &args.passport_session_id)?;
    let challenge = checked(
        client
            .post(format!("{}/kbs/v0/auth", args.url))
            .json(&json!({"version":"0.4.0", "tee":"tdx", "extra-params": params}))
            .send()
            .await?,
    )
    .await?;
    if let Some(nonce) = &args.passport_nonce {
        if challenge["nonce"].as_str() != Some(nonce.as_str()) {
            bail!("KBS did not bind the relying-party challenge");
        }
    }
    let key = TeeKeyPair::new()?;
    let runtime_data = json!({"nonce":challenge["nonce"], "tee-pubkey":key.export_pubkey()?});
    let mut primary_runtime_data = bind_passport_audience(
        json!({
            "nonce": challenge["nonce"], "tee-pubkey": runtime_data["tee-pubkey"],
            "additional-evidence": "{}",
        }),
        &args.passport_audience,
    );
    if let Some(session_id) = &args.passport_session_id {
        primary_runtime_data["session_id"] = json!(session_id);
    }
    let report_data =
        Sha384::digest(serde_json_canonicalizer::to_vec(&primary_runtime_data)?).to_vec();
    previous.extend(event.into_iter().flatten());
    let evidence = tdx_evidence::collect(report_data, &previous).await?;
    #[cfg(feature = "integration-test")]
    let mut evidence = evidence;
    #[cfg(feature = "integration-test")]
    if args.corrupt_quote {
        let encoded = evidence["quote"].as_str().context("Missing quote")?;
        let mut quote = STANDARD.decode(encoded)?;
        if quote.len() <= 600 {
            bail!("Quote is too short for the corruption test");
        }
        // Alter the signed TDX report body while preserving its wire encoding.
        quote[600] ^= 1;
        evidence["quote"] = json!(STANDARD.encode(quote));
    }
    write_private(
        &args.output_dir.join("evidence.json"),
        &serde_json::to_vec(&evidence)?,
    )?;
    let result = checked(
        client
            .post(format!("{}/kbs/v0/attest", args.url))
            .json(&json!({
                "init-data": init_data.map(|body| json!({"format": "toml", "body": body})), "runtime-data": runtime_data,
                "tee-evidence": {"primary_evidence": evidence, "additional_evidence": "{}"}
            }))
            .send()
            .await?,
    )
    .await?;
    let token = result["token"]
        .as_str()
        .context("Missing attestation token")?;
    write_private(&args.output_dir.join("token.jwt"), token.as_bytes())?;
    let decoded = URL_SAFE_NO_PAD.decode(token.split('.').nth(1).context("Invalid token")?)?;
    write_private(&args.output_dir.join("claims.json"), &decoded)?;
    let mut resource_file = None;
    if let Some(resource) = &args.resource {
        if resource.split('/').count() != 3 {
            bail!("Resource must have three path components");
        }
        let response = client
            .get(format!("{}/kbs/v0/resource/{resource}", args.url))
            .bearer_auth(token)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            bail!("Resource HTTP {status}: {}", response.text().await?);
        }
        let plaintext = key.decrypt_response(response.json().await?)?;
        write_private(&args.output_dir.join("resource.bin"), &plaintext)?;
        resource_file = Some(sealed_file(&mut plaintext.as_slice())?);
        println!(
            "RESOURCE_OK sha384={}",
            hex::encode(Sha384::digest(&plaintext))
        );
    }
    if args.execute {
        let status = workload_command(
            &snapshots,
            &args,
            resource_file.as_ref().context("Missing resource")?,
        )?
        .status()
        .context("Execute sealed measured snapshot")?;
        if !status.success() {
            bail!("Measured workload failed: {status}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_session_argument_requires_passport_and_canonical_id() {
        let base = [
            "tdx-workload",
            "--url",
            "http://kbs",
            "--output-dir",
            "/tmp/out",
        ];
        let mut args = base.to_vec();
        args.extend(["--passport-session-id", "session-without-passport"]);
        assert!(Args::try_parse_from(args).is_err());
        let mut params = json!({});
        insert_passport_session(&mut params, &Some("ab".repeat(32))).unwrap();
        assert_eq!(params["passport-session-id"], "ab".repeat(32));
        for id in ["short".into(), "AB".repeat(32), "g".repeat(64)] {
            assert!(insert_passport_session(&mut params, &Some(id)).is_err());
        }
    }

    #[test]
    fn passport_audience_is_bound_into_the_quoted_runtime_data() {
        let mut params = json!({});
        assert!(insert_passport(&mut params, &None, &None).is_ok());
        assert!(insert_passport(&mut params, &Some("model-kms".into()), &None).is_err());
        insert_passport(
            &mut params,
            &Some("model-kms".into()),
            &Some("model-challenge-1".into()),
        )
        .unwrap();
        assert_eq!(params["passport-audience"], "model-kms");
        let plain =
            bind_passport_audience(json!({"nonce": "n", "additional-evidence": "{}"}), &None);
        assert!(plain.get("audience").is_none());
        let bound = bind_passport_audience(plain, &Some("data-kms".into()));
        assert_eq!(bound["audience"], "data-kms");
    }

    #[test]
    fn execution_cannot_downgrade_to_boot_only_or_share_service_identity() {
        let mut args = Args::try_parse_from([
            "tdx-workload",
            "--url",
            "http://kbs",
            "--output-dir",
            "/tmp/out",
        ])
        .unwrap();
        args.execute = true;
        args.resource = Some("workload/test/probe".into());
        args.selector = Some("workload".into());
        assert!(validate_execution(&args, 0).is_err());
        args.init_data = Some("/trusted/initdata.toml".into());
        assert!(validate_execution(&args, 0).is_ok());
        assert!(validate_execution(&args, 1000).is_err());
        args.selector = None;
        assert!(validate_execution(&args, 0).is_err());
        args.selector = Some("workload".into());
        args.resource = Some("default/test/probe".into());
        assert!(validate_execution(&args, 0).is_err());
    }

    #[test]
    fn private_state_rejects_world_access_and_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        private_directory(dir.path()).unwrap();
        let link = dir.path().join("link");
        symlink(dir.path(), &link).unwrap();
        assert!(private_directory(&link).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_directory(dir.path()).is_err());
    }

    #[test]
    fn python_exec_ignores_inherited_code_and_drops_privileges() {
        if std::env::var_os("TRUSTEE_TEST_ENV_CHILD").is_none() {
            let injected = tempfile::tempdir().unwrap();
            fs::write(
                injected.path().join("sitecustomize.py"),
                "print('UNMEASURED_CODE_EXECUTED')\n",
            )
            .unwrap();
            let out = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::python_exec_ignores_inherited_code_and_drops_privileges",
                    "--nocapture",
                ])
                .env("TRUSTEE_TEST_ENV_CHILD", "1")
                .env("PYTHONPATH", injected.path())
                .env("LD_PRELOAD", "/nonexistent-trustee-test-library.so")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        // Execute without a TDX quote to test the launcher boundary itself.
        // Integration tests independently verify KBS's launch-bound policy gate.
        let python = ["/usr/local/bin/python3", "/usr/bin/python3"]
            .iter()
            .map(Path::new)
            .find(|p| p.exists())
            .expect("Python 3 is required for this regression test");
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("app.py");
        fs::write(&script, "import os; print('APPROVED', os.getuid(), os.environ.get('LD_PRELOAD'), os.environ.get('PYTHONPATH')); print(open('/proc/self/status').read().split('NoNewPrivs:')[1].split()[0])\n").unwrap();
        fs::write(
            dir.path().join("sitecustomize.py"),
            "print('UNMEASURED_CODE_EXECUTED')\n",
        )
        .unwrap();
        let mut args = Args::try_parse_from([
            "tdx-workload",
            "--url",
            "http://kbs",
            "--output-dir",
            "/tmp/out",
        ])
        .unwrap();
        args.interpreter = Some(python.to_path_buf());
        if unsafe { libc::geteuid() } != 0 {
            args.run_uid = unsafe { libc::geteuid() };
            args.run_gid = unsafe { libc::getegid() };
        }
        let snapshots = [snapshot(python).unwrap(), snapshot(&script).unwrap()];
        let resource = sealed_file(&mut b"public fixture".as_slice()).unwrap();
        let mut cmd = workload_command(&snapshots, &args, &resource).unwrap();
        // A hostile inherited variable is omitted, not passed to the dynamic loader.
        assert!(cmd
            .get_envs()
            .all(|(key, _)| key != "LD_PRELOAD" && key != "PYTHONPATH"));
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8(out.stdout).unwrap();
        assert!(
            stdout.contains(&format!("APPROVED {} None None", args.run_uid)),
            "{stdout}"
        );
        assert!(stdout.lines().any(|l| l == "1"), "{stdout}");
        assert!(!stdout.contains("UNMEASURED_CODE_EXECUTED"));
    }
    #[test]
    fn sealed_snapshot_survives_source_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.py");
        fs::write(&path, b"print('approved')\n").unwrap();
        let mut measured = snapshot(&path).unwrap();
        fs::write(&path, b"print('changed')\n").unwrap();
        let mut content = String::new();
        measured.file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "print('approved')\n");
        assert!(measured.file.write_all(b"tamper").is_err());
        assert!(measured.file.set_len(0).is_err());
        let args = Args::try_parse_from([
            "tdx-workload",
            "--url",
            "http://kbs",
            "--output-dir",
            "/tmp/out",
        ])
        .unwrap();
        let encoded = manifest(&[measured], &args).unwrap();
        let event = tdx_evidence::tcg_event(&encoded);
        assert_eq!(&event[14..62], Sha384::digest(&encoded).as_slice());
        assert_eq!(&event[66..], encoded.as_slice());
    }

    #[test]
    fn pod_env_configures_selector() {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        let base = [
            "tdx-workload",
            "--url",
            "http://kbs",
            "--output-dir",
            "/tmp",
        ];
        std::env::remove_var("ATTESTATION_POLICY_SELECTOR");
        let bare = Args::try_parse_from(base).unwrap();
        assert!(bare.selector.is_none());
        std::env::set_var("ATTESTATION_POLICY_SELECTOR", "default");
        let from_pod = Args::try_parse_from(base).unwrap();
        assert_eq!(from_pod.selector.as_deref(), Some("default"));
        std::env::set_var("ATTESTATION_POLICY_SELECTOR", "workload");
        let mut with_flag = base.to_vec();
        with_flag.extend(["--selector", "default"]);
        let cli = Args::try_parse_from(with_flag).unwrap();
        assert_eq!(cli.selector.as_deref(), Some("default"));
        std::env::set_var("ATTESTATION_POLICY_SELECTOR", "");
        let empty = Args::try_parse_from(base).unwrap();
        assert_eq!(empty.selector.as_deref(), Some(""));
        std::env::remove_var("ATTESTATION_POLICY_SELECTOR");
    }
}
