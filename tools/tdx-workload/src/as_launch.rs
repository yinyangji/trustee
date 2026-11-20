// SPDX-License-Identifier: Apache-2.0

//! Verify immutable AS files and extend RTMR[3] before executing the measured
//! binary. The caller's launch policy must bind this loader and its inputs.

use anyhow::{ensure, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
};
use tdx_workload::tdx_evidence::{tcg_event, RTMR3};

const PROFILE: &str = "trustee.as-elf-load.v1";
const MAX_INPUT: usize = 256 * 1024;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    initial_rtmr3: String,
    /// Compute the expected RTMR[3] from the approved manifest for offline appraisal.
    #[arg(long)]
    print_measurement: bool,
    #[arg(long, default_value = "/run/attestation-agent/eventlog")]
    boot_aael: PathBuf,
    #[arg(long, default_value = "/run/verify-as/events.bin")]
    journal: PathBuf,
    #[arg(last = true)]
    arguments: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    profile: String,
    as_release_manifest_digest: String,
    files: Vec<MeasuredFile>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MeasuredFile {
    role: String,
    path: String,
    size: u64,
    sha384: String,
}

fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Manifest {
    fn canonicalize(&mut self) -> Result<&str> {
        ensure!(self.profile == PROFILE, "unexpected AS load profile");
        ensure!(
            valid_hex(&self.as_release_manifest_digest, 64),
            "invalid AS release manifest digest"
        );
        ensure!(
            !self.files.is_empty() && self.files.len() <= 512,
            "invalid AS load list"
        );
        self.files
            .sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        let mut paths = BTreeSet::new();
        for file in &self.files {
            let path = Path::new(&file.path);
            ensure!(
                path.is_absolute()
                    && path.file_name().is_some()
                    && !file.path[1..]
                        .split('/')
                        .any(|part| matches!(part, "" | "." | ".."))
                    && paths.insert(&file.path)
                    && !file.role.is_empty()
                    && valid_hex(&file.sha384, 96),
                "invalid or duplicate measured file"
            );
        }
        let mut bin = self.files.iter().filter(|file| file.role == "restful-as");
        let entry = &bin
            .next()
            .context("AS load event is missing the executable")?
            .path;
        ensure!(
            bin.next().is_none(),
            "AS load event has more than one executable"
        );
        Ok(entry)
    }
}

fn verify_file(file: &MeasuredFile) -> Result<()> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&file.path)?;
    let metadata = input.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() == file.size,
        "measured file size or type mismatch"
    );
    let mut info = MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(input.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // The mounted filesystem and boot identity must also be verified by
    // the relying party's policy. ST_RDONLY is a local integrity precondition.
    let info = unsafe { info.assume_init() };
    ensure!(
        info.f_flag & libc::ST_RDONLY != 0,
        "measured file is not on a read-only mount"
    );
    let mut digest = Sha384::new();
    let mut read = 0;
    let mut chunk = [0; 32 * 1024];
    loop {
        let bytes = input.read(&mut chunk)?;
        if bytes == 0 {
            break;
        }
        read += bytes as u64;
        digest.update(&chunk[..bytes]);
    }
    ensure!(
        read == file.size && hex::encode(digest.finalize()) == file.sha384,
        "measured file digest mismatch"
    );
    Ok(())
}

fn read_limited(file: File) -> Result<Vec<u8>> {
    let mut contents = Vec::new();
    file.take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut contents)?;
    ensure!(
        contents.len() <= MAX_INPUT,
        "AS launch input exceeds size limit"
    );
    Ok(contents)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut manifest: Manifest =
        serde_json::from_slice(&read_limited(File::open(&args.manifest)?)?)?;
    let executable = manifest.canonicalize()?.to_owned();
    ensure!(
        valid_hex(&args.initial_rtmr3, 96),
        "invalid approved starting RTMR[3]"
    );
    let initial = hex::decode(args.initial_rtmr3)?;
    let event = serde_json_canonicalizer::to_vec(&manifest)?;
    let digest = Sha384::digest(&event);
    let mut expected = Sha384::new();
    expected.update(&initial);
    expected.update(digest);
    let expected = expected.finalize();
    if args.print_measurement {
        println!(
            "{}",
            serde_json::json!({
                "event_digest": hex::encode(digest),
                "expected_rtmr3": hex::encode(expected)
            })
        );
        return Ok(());
    }

    for file in &manifest.files {
        verify_file(file).with_context(|| format!("verify {}", file.path))?;
    }
    let mut events = match File::open(args.boot_aael) {
        Ok(file) => read_limited(file)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    events.extend(tcg_event(&event));
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&args.journal)?;
    let metadata = journal.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "AS launch journal is not a private guest-owned file"
    );
    if unsafe { libc::flock(journal.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let state = fs::read(RTMR3)?;
    if state == initial {
        // Persist the journal first. If the process dies before the extend,
        // the next launch can rebuild the journal from the same inputs.
        journal.set_len(0)?;
        journal.seek(SeekFrom::Start(0))?;
        journal.write_all(&events)?;
        journal.sync_all()?;
        OpenOptions::new()
            .write(true)
            .open(RTMR3)?
            .write_all(&digest)?;
    } else {
        // Reuse the measurement after an AS process restart in the same TD.
        ensure!(
            state == expected.as_slice(),
            "approved AS RTMR[3] does not match"
        );
        let mut recorded = Vec::new();
        (&journal)
            .take(events.len() as u64 + 1)
            .read_to_end(&mut recorded)?;
        ensure!(
            recorded == events,
            "existing AS event journal does not match"
        );
    }
    ensure!(
        fs::read(RTMR3)? == expected.as_slice(),
        "unexpected measurement extension"
    );
    drop(journal);

    Err(Command::new(executable)
        .args(args.arguments)
        .env_clear()
        .env("AAEL_PATH", args.journal)
        .env("LANG", "C.UTF-8")
        .env("TZ", "UTC")
        .exec()
        .into())
}
