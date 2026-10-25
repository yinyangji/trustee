// SPDX-License-Identifier: Apache-2.0

//! Public GetSecretValue with Alibaba Cloud AAP ClientKey authentication.
//! Protocol reference: aliyun-secretsmanager-client-go, sdk/auth/client_key_signer.go.

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    rsa::Padding,
    sign::Signer,
};
use serde::Deserialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

use super::{
    aliyun_openapi::{encode, form, parse_text_secret, send_form},
    backend::{ResourceDesc, StorageBackend},
};

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AliyunAapPublicConfig {
    region_id: String,
    client_key_file: PathBuf,
    password_file: PathBuf,
    #[serde(default = "default_version_stage")]
    version_stage: String,
}

fn default_version_stage() -> String {
    "ACSCurrent".into()
}

pub struct AliyunAapPublicBackend {
    config: AliyunAapPublicConfig,
    http: reqwest::Client,
    kms_url: String,
}

// No Debug: the encrypted container and parsed private key are credential material.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ClientKeyFile {
    key_id: String,
    private_key_data: String,
}

impl Drop for ClientKeyFile {
    fn drop(&mut self) {
        self.private_key_data.zeroize();
    }
}

struct ClientKeySigner {
    key_id: String,
    private_key: PKey<Private>,
}

fn read_limited(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .context("cannot open AAP credential file")?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .context("cannot read AAP credential file")?;
    ensure!(
        bytes.len() as u64 <= limit,
        "AAP credential file exceeds size limit"
    );
    Ok(bytes)
}

impl ClientKeySigner {
    fn load(key_file: &Path, password_file: &Path) -> Result<Self> {
        let raw = read_limited(key_file, 1024 * 1024)?;
        let key_file: ClientKeyFile = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("invalid AAP ClientKey JSON"))?;
        ensure!(!key_file.key_id.is_empty(), "missing AAP KeyId");
        let password_bytes = read_limited(password_file, 4096)?;
        let password = std::str::from_utf8(&password_bytes)
            .map_err(|_| anyhow::anyhow!("AAP password is not UTF-8"))?
            .trim_end_matches(['\r', '\n']);
        ensure!(!password.is_empty(), "empty AAP password");
        let der = Zeroizing::new(
            STANDARD
                .decode(key_file.private_key_data.as_bytes())
                .map_err(|_| anyhow::anyhow!("invalid AAP PrivateKeyData base64"))?,
        );
        // p12 already backs the existing Aliyun dependency. It supports the AAP
        // RC2/3DES containers without enabling legacy algorithms for TLS globally.
        let pfx = p12::PFX::parse(&der)
            .map_err(|_| anyhow::anyhow!("invalid or unsupported AAP PKCS#12 container"))?;
        ensure!(
            pfx.version == 3 && pfx.mac_data.is_some(),
            "AAP PKCS#12 requires a version-3 authenticated container"
        );
        ensure!(
            pfx.verify_mac(password),
            "AAP ClientKey password or integrity check failed"
        );
        let keys = pfx
            .key_bags(password)
            .map_err(|_| anyhow::anyhow!("cannot decrypt AAP private key"))?;
        ensure!(
            keys.len() == 1,
            "AAP ClientKey must contain exactly one private key"
        );
        let key_der = Zeroizing::new(keys.into_iter().next().context("missing AAP private key")?);
        let private_key = PKey::private_key_from_pkcs8(&key_der)
            .map_err(|_| anyhow::anyhow!("invalid AAP PKCS#8 private key"))?;
        ensure!(
            private_key.id() == Id::RSA && private_key.bits() >= 2048,
            "AAP requires an RSA private key of at least 2048 bits"
        );
        Ok(Self {
            key_id: key_file.key_id.clone(),
            private_key,
        })
    }

    fn sign_form(&self, mut params: BTreeMap<String, String>) -> Result<Zeroizing<String>> {
        // Match the official ClientKeySigner and RPC signature composer.
        params.insert("AccessKeyId".into(), self.key_id.clone());
        params.insert("SignatureMethod".into(), "SHA256withRSA".into());
        params.insert("SignatureType".into(), "PRIVATEKEY".into());
        params.insert("SignatureVersion".into(), "1.0".into());
        params.remove("Signature");
        let canonical = Zeroizing::new(form(&params));
        let to_sign = Zeroizing::new(format!("POST&%2F&{}", encode(&canonical)));
        let mut signer = Signer::new(MessageDigest::sha256(), &self.private_key)?;
        signer.set_rsa_padding(Padding::PKCS1)?;
        signer.update(to_sign.as_bytes())?;
        params.insert("Signature".into(), STANDARD.encode(signer.sign_to_vec()?));
        let signed = Zeroizing::new(form(&params));
        for value in params.values_mut() {
            value.zeroize();
        }
        Ok(signed)
    }
}

impl AliyunAapPublicBackend {
    pub fn new(config: AliyunAapPublicConfig) -> Result<Self> {
        ensure!(
            !config.region_id.is_empty()
                && config
                    .region_id
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
            "invalid Aliyun region_id"
        );
        ensure!(
            !config.version_stage.is_empty(),
            "version_stage must not be empty"
        );
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            kms_url: format!("https://kms.{}.aliyuncs.com/", config.region_id),
            config,
            http,
        })
    }
}

#[async_trait::async_trait]
impl StorageBackend for AliyunAapPublicBackend {
    async fn read_secret_resource(&self, resource: ResourceDesc) -> Result<Vec<u8>> {
        let key_path = self.config.client_key_file.clone();
        let password_path = self.config.password_file.clone();
        let params = BTreeMap::from([
            ("Action".into(), "GetSecretValue".into()),
            ("Version".into(), "2016-01-20".into()),
            ("Format".into(), "JSON".into()),
            ("RegionId".into(), self.config.region_id.clone()),
            ("SecretName".into(), resource.resource_tag),
            ("VersionStage".into(), self.config.version_stage.clone()),
            ("SignatureNonce".into(), uuid::Uuid::new_v4().to_string()),
            (
                "Timestamp".into(),
                OffsetDateTime::now_utc()
                    .replace_nanosecond(0)?
                    .format(&Rfc3339)?,
            ),
        ]);
        // Loading, decrypting and signing can be CPU-bound. Reload for each read
        // to support credential rotation without caching either keys or secrets.
        let body = tokio::task::spawn_blocking(move || {
            ClientKeySigner::load(&key_path, &password_path)?.sign_form(params)
        })
        .await
        .map_err(|_| anyhow::anyhow!("AAP signing task failed"))??;
        let response = send_form(&self.http, &self.kms_url, "GetSecretValue", body).await?;
        parse_text_secret(&response)
    }

    async fn write_secret_resource(&self, _: ResourceDesc, _: &[u8]) -> Result<()> {
        bail!("AliyunAapPublic resource backend is read-only")
    }

    async fn delete_secret_resource(&self, _: ResourceDesc) -> Result<()> {
        bail!("AliyunAapPublic resource backend is read-only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        nid::Nid,
        rsa::Rsa,
        sign::Verifier,
        x509::{X509NameBuilder, X509},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    struct Fixture {
        _dir: tempfile::TempDir,
        key_path: PathBuf,
        password_path: PathBuf,
        key: PKey<Private>,
    }

    fn fixture_with_key(key: PKey<Private>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("client-key.json");
        let password_path = dir.path().join("password.txt");
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "generated-test-only")
            .unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let pfx = p12::PFX::new(
            &cert.build().to_der().unwrap(),
            &key.private_key_to_pkcs8().unwrap(),
            None,
            "test-password",
            "generated-test-only",
        )
        .unwrap();
        std::fs::write(&key_path, serde_json::json!({"KeyId":"KAAP.test", "PrivateKeyData":STANDARD.encode(pfx.to_der())}).to_string()).unwrap();
        std::fs::write(&password_path, "test-password\n").unwrap();
        Fixture {
            _dir: dir,
            key_path,
            password_path,
            key,
        }
    }

    fn fixture() -> Fixture {
        fixture_with_key(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap())
    }

    fn config(f: &Fixture) -> AliyunAapPublicConfig {
        AliyunAapPublicConfig {
            region_id: "cn-hangzhou".into(),
            client_key_file: f.key_path.clone(),
            password_file: f.password_path.clone(),
            version_stage: default_version_stage(),
        }
    }

    fn params_from_form(body: &str) -> BTreeMap<String, String> {
        reqwest::Url::parse(&format!("http://localhost/?{body}"))
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect()
    }

    fn verify_signature(request: &str, key: &PKey<Private>) -> BTreeMap<String, String> {
        let body = request.split_once("\r\n\r\n").unwrap().1;
        let mut params = params_from_form(body);
        let signature = STANDARD
            .decode(params.remove("Signature").unwrap())
            .unwrap();
        let to_sign = format!("POST&%2F&{}", encode(&form(&params)));
        let mut verifier = Verifier::new(MessageDigest::sha256(), key).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1).unwrap();
        verifier.update(to_sign.as_bytes()).unwrap();
        assert!(verifier.verify(&signature).unwrap());
        params
    }

    async fn mock(responses: Vec<(u16, String)>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buffer[..n]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if request.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8(request).unwrap());
                // A real redirect target lets the test detect accidental following.
                let response = format!("HTTP/1.1 {status} Test\r\nLocation: http://127.0.0.1:1/should-not-follow\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (url, task)
    }

    fn test_backend(f: &Fixture, url: String) -> AliyunAapPublicBackend {
        let mut backend = AliyunAapPublicBackend::new(config(f)).unwrap();
        backend.http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        backend.kms_url = url;
        backend
    }

    fn resource() -> ResourceDesc {
        ResourceDesc {
            repository_name: "default".into(),
            resource_type: "key".into(),
            resource_tag: "test-secret".into(),
        }
    }

    #[test]
    fn loads_rc2_and_3des_pkcs12_and_matches_rpc_canonical_vector() {
        let f = fixture();
        let signer = ClientKeySigner::load(&f.key_path, &f.password_path).unwrap();
        let signed = signer
            .sign_form(BTreeMap::from([
                ("Action".into(), "GetSecretValue".into()),
                ("SecretName".into(), "a b/中".into()),
            ]))
            .unwrap();
        let params = params_from_form(&signed);
        let signature = STANDARD.decode(&params["Signature"]).unwrap();
        // Independently specified RPC canonical string, including double escaping.
        let expected = "POST&%2F&AccessKeyId%3DKAAP.test%26Action%3DGetSecretValue%26SecretName%3Da%2520b%252F%25E4%25B8%25AD%26SignatureMethod%3DSHA256withRSA%26SignatureType%3DPRIVATEKEY%26SignatureVersion%3D1.0";
        let mut verifier = Verifier::new(MessageDigest::sha256(), &f.key).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1).unwrap();
        verifier.update(expected.as_bytes()).unwrap();
        assert!(verifier.verify(&signature).unwrap());
        assert!(!params.contains_key("SecurityToken"));
    }

    #[test]
    fn rejects_wrong_password_corruption_and_missing_mac() {
        let f = fixture();
        std::fs::write(&f.password_path, "do-not-echo-wrong-password").unwrap();
        let error = ClientKeySigner::load(&f.key_path, &f.password_path)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("do-not-echo"));
        std::fs::write(&f.password_path, "test-password").unwrap();
        let mut data: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&f.key_path).unwrap()).unwrap();
        let mut der = STANDARD
            .decode(data["PrivateKeyData"].as_str().unwrap())
            .unwrap();
        let mut pfx = p12::PFX::parse(&der).unwrap();
        *der.last_mut().unwrap() ^= 1;
        data["PrivateKeyData"] = STANDARD.encode(&der).into();
        std::fs::write(&f.key_path, data.to_string()).unwrap();
        assert!(ClientKeySigner::load(&f.key_path, &f.password_path).is_err());
        pfx.mac_data = None;
        data["PrivateKeyData"] = STANDARD.encode(pfx.to_der()).into();
        std::fs::write(&f.key_path, data.to_string()).unwrap();
        assert!(ClientKeySigner::load(&f.key_path, &f.password_path).is_err());
    }

    #[test]
    fn rejects_non_rsa_and_weak_rsa_keys() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = fixture_with_key(PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap());
        assert!(ClientKeySigner::load(&ec.key_path, &ec.password_path).is_err());
        let weak = fixture_with_key(PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap());
        assert!(ClientKeySigner::load(&weak.key_path, &weak.password_path).is_err());
    }

    #[test]
    fn rejects_malformed_files_without_echoing_contents() {
        let f = fixture();
        for data in [
            r#"{"KeyId":"private-marker", "PrivateKeyData": }"#,
            r#"{"KeyId":"KAAP.test", "PrivateKeyData":"private-marker"}"#,
            r#"{"KeyId":"", "PrivateKeyData":"private-marker"}"#,
        ] {
            std::fs::write(&f.key_path, data).unwrap();
            let error = ClientKeySigner::load(&f.key_path, &f.password_path)
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("private-marker"));
        }
        std::fs::write(&f.password_path, vec![b'x'; 4097]).unwrap();
        assert!(read_limited(&f.password_path, 4096).is_err());
    }

    #[test]
    fn registers_public_aap_config_and_rejects_mixed_auth() {
        use super::super::backend::RepositoryConfig;
        let value = serde_json::json!({"storage_backend_type":"AliyunAapPublic", "region_id":"cn-hangzhou", "client_key_file":"/run/key.json", "password_file":"/run/password"});
        assert!(matches!(
            serde_json::from_value::<RepositoryConfig>(value.clone()).unwrap(),
            RepositoryConfig::AliyunAapPublic(_)
        ));
        let mut mixed = value;
        mixed["role_arn"] = "must-not-use-sts".into();
        assert!(serde_json::from_value::<RepositoryConfig>(mixed).is_err());
        let f = fixture();
        let mut cfg = config(&f);
        cfg.region_id = "attacker/".into();
        assert!(AliyunAapPublicBackend::new(cfg).is_err());
    }

    #[tokio::test]
    async fn uses_public_aap_without_sts_and_preserves_text() {
        let f = fixture();
        let (url, task) = mock(vec![(
            200,
            r#"{"SecretData":"hello\n世界","SecretDataType":"text"}"#.into(),
        )])
        .await;
        let backend = test_backend(&f, url);
        assert_eq!(
            backend.read_secret_resource(resource()).await.unwrap(),
            "hello\n世界".as_bytes()
        );
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST / HTTP/1.1\r\n"));
        let params = verify_signature(&requests[0], &f.key);
        assert_eq!(params["SignatureMethod"], "SHA256withRSA");
        assert_eq!(params["SignatureType"], "PRIVATEKEY");
        assert_eq!(params["AccessKeyId"], "KAAP.test");
        assert_eq!(params["SecretName"], "test-secret");
        assert_eq!(params["VersionStage"], "ACSCurrent");
        assert!(!params.contains_key("SecurityToken"));
        assert!(!requests[0].contains("AssumeRole"));
    }

    #[tokio::test]
    async fn reloads_rotated_client_key() {
        let f = fixture();
        let second = fixture();
        let (url, task) = mock(vec![
            (
                200,
                r#"{"SecretData":"one","SecretDataType":"text"}"#.into(),
            ),
            (
                200,
                r#"{"SecretData":"two","SecretDataType":"text"}"#.into(),
            ),
        ])
        .await;
        let backend = test_backend(&f, url);
        assert_eq!(
            backend.read_secret_resource(resource()).await.unwrap(),
            b"one"
        );
        std::fs::copy(&second.key_path, &f.key_path).unwrap();
        assert_eq!(
            backend.read_secret_resource(resource()).await.unwrap(),
            b"two"
        );
        let requests = task.await.unwrap();
        verify_signature(&requests[0], &f.key);
        verify_signature(&requests[1], &second.key);
    }

    #[tokio::test]
    async fn errors_are_redacted_and_redirects_are_not_followed() {
        let f = fixture();
        for status in [403, 302] {
            let (url, task) = mock(vec![(status, "sensitive-upstream-body".into())]).await;
            let error = test_backend(&f, url)
                .read_secret_resource(resource())
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(&status.to_string()));
            assert!(!error.contains("sensitive-upstream-body"));
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_binary_and_read_only_operations() {
        let f = fixture();
        let (url, task) = mock(vec![(
            200,
            r#"{"SecretData":"AA==","SecretDataType":"binary"}"#.into(),
        )])
        .await;
        let backend = test_backend(&f, url);
        assert!(backend.read_secret_resource(resource()).await.is_err());
        assert!(backend
            .write_secret_resource(resource(), b"data")
            .await
            .is_err());
        assert!(backend.delete_secret_resource(resource()).await.is_err());
        task.await.unwrap();
    }
}
