use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::{
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
};
use trustee_platform_api::credentials::{KeyReference, SealedKey, MAX_SECRET};
use zeroize::Zeroizing;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Operation,
}
#[derive(Subcommand)]
enum Operation {
    /// Seal stdin using a reference configuration. Refuses to overwrite a key.
    Seal {
        #[arg(long)]
        reference: PathBuf,
    },
    /// Verify driver identity, protocol version and sealing capability.
    Describe {
        #[arg(long)]
        reference: PathBuf,
    },
    /// Planned migration/rotation: unseal in memory, seal with the target driver.
    /// Both drivers and the old hardware must be available. No plaintext output.
    Rewrap {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
}

fn read_reference(path: &PathBuf) -> Result<KeyReference> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn persist(reference: &KeyReference, sealed: &SealedKey) -> Result<()> {
    if !reference.sealed_path.is_absolute() {
        bail!("sealed path must be absolute");
    }
    let parent = reference
        .sealed_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("key directory required"))?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        bail!("key directory must be private (0700)");
    }
    let mut pending = tempfile::NamedTempFile::new_in(parent)?;
    pending.write_all(&serde_json::to_vec(sealed)?)?;
    pending.as_file().sync_all()?;
    pending.persist_noclobber(&reference.sealed_path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Operation::Describe { reference } => println!(
            "{}",
            serde_json::to_string(&read_reference(&reference)?.provider.describe().await?)?
        ),
        Operation::Seal { reference } => {
            let reference = read_reference(&reference)?;
            let mut secret = Zeroizing::new(Vec::new());
            std::io::stdin()
                .take((MAX_SECRET + 1) as u64)
                .read_to_end(&mut secret)?;
            if secret.len() > MAX_SECRET {
                bail!("credential too large");
            }
            let sealed = reference
                .provider
                .seal(reference.binding.clone(), &secret)
                .await?;
            persist(&reference, &sealed)?;
        }
        Operation::Rewrap {
            source,
            destination,
        } => {
            let source = read_reference(&source)?;
            let destination = read_reference(&destination)?;
            if source.binding != destination.binding {
                bail!("rewrap must preserve key identity and purpose");
            }
            let secret = source.load(&source.binding.purpose).await?;
            let sealed = destination
                .provider
                .seal(destination.binding.clone(), &secret)
                .await?;
            persist(&destination, &sealed)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use trustee_platform_api::credentials::{KeyBinding, ProviderConfig, API_VERSION};

    #[test]
    fn provisioning_persists_private_ciphertext_and_never_replaces_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let binding = KeyBinding {
            key_id: "key-v1".into(),
            purpose: "service".into(),
        };
        let reference = KeyReference {
            provider: ProviderConfig {
                command: "/unused-provider".into(),
                arguments: vec![],
                expected_provider: "test".into(),
                environment: BTreeMap::new(),
            },
            sealed_path: dir.path().join("key.json"),
            binding: binding.clone(),
        };
        let sealed = SealedKey {
            api_version: API_VERSION,
            provider: "test".into(),
            binding,
            ciphertext: "fixture-ciphertext".into(),
        };
        persist(&reference, &sealed).unwrap();
        let before = std::fs::read(&reference.sealed_path).unwrap();
        assert_eq!(
            std::fs::metadata(&reference.sealed_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(persist(&reference, &sealed).is_err());
        assert_eq!(std::fs::read(&reference.sealed_path).unwrap(), before);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(persist(&reference, &sealed).is_err());
    }
}
