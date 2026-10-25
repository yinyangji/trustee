// SPDX-License-Identifier: Apache-2.0

//! Public KMS OpenAPI access using RAM credentials and STS AssumeRole.
//! Credentials and signed parameters must never be logged.

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde::Deserialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

use super::backend::{ResourceDesc, StorageBackend};

const REFRESH_MARGIN_SECONDS: i64 = 120;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// The file contains AccessKeyId and AccessKeySecret, not AAP ClientKey data.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AliyunOpenApiConfig {
    region_id: String,
    credentials_file: PathBuf,
    role_arn: String,
    #[serde(default = "default_session_name")]
    role_session_name: String,
    #[serde(default = "default_duration")]
    duration_seconds: u32,
    #[serde(default = "default_version_stage")]
    version_stage: String,
}

fn default_session_name() -> String {
    "coco-kbs".into()
}

fn default_duration() -> u32 {
    3600
}

fn default_version_stage() -> String {
    "ACSCurrent".into()
}

// Deliberately no Debug implementation on any credential-bearing type.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Credentials {
    access_key_id: String,
    access_key_secret: String,
    #[serde(default)]
    security_token: String,
    #[serde(default)]
    expiration: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.access_key_secret.zeroize();
        self.security_token.zeroize();
    }
}

impl Credentials {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.access_key_id.is_empty() && !self.access_key_secret.is_empty(),
            "empty Alibaba Cloud credentials"
        );
        if !self.security_token.is_empty() {
            ensure!(
                self.expires_at()? > OffsetDateTime::now_utc() + time::Duration::seconds(120),
                "source STS credentials require renewal"
            );
        }
        Ok(())
    }

    fn expires_at(&self) -> Result<OffsetDateTime> {
        OffsetDateTime::parse(&self.expiration, &Rfc3339)
            .map_err(|_| anyhow::anyhow!("invalid STS credential expiration"))
    }
}

struct Session {
    credentials: Credentials,
    expires_at: OffsetDateTime,
}

impl Session {
    fn reusable(&self, now: OffsetDateTime) -> bool {
        self.expires_at > now + time::Duration::seconds(REFRESH_MARGIN_SECONDS)
    }
}

pub struct AliyunOpenApiBackend {
    config: AliyunOpenApiConfig,
    http: reqwest::Client,
    kms_url: String,
    sts_url: String,
    // Serializes refreshes only. Resource requests proceed outside this lock.
    session: Mutex<Option<Session>>,
}

impl AliyunOpenApiBackend {
    pub fn new(config: AliyunOpenApiConfig) -> Result<Self> {
        ensure!(
            !config.region_id.is_empty()
                && config
                    .region_id
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
            "invalid Aliyun region_id"
        );
        ensure!(
            config.role_arn.starts_with("acs:ram::") && config.role_arn.contains(":role/"),
            "invalid role_arn"
        );
        ensure!(
            (900..=43200).contains(&config.duration_seconds),
            "duration_seconds must be between 900 and 43200"
        );
        ensure!(
            (2..=64).contains(&config.role_session_name.len())
                && config
                    .role_session_name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".@-_".contains(&c)),
            "invalid role_session_name"
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
            sts_url: format!("https://sts.{}.aliyuncs.com/", config.region_id),
            config,
            http,
            session: Mutex::new(None),
        })
    }

    async fn session_credentials(&self) -> Result<Credentials> {
        let mut cache = self.session.lock().await;
        if !cache
            .as_ref()
            .is_some_and(|s| s.reusable(OffsetDateTime::now_utc()))
        {
            // Fail closed on refresh failure. Never fall back to the source AK for KMS.
            *cache = None;
            let raw = Zeroizing::new(
                tokio::fs::read_to_string(&self.config.credentials_file)
                    .await
                    .context("cannot read Aliyun credentials file")?,
            );
            let source: Credentials = serde_json::from_str(&raw)
                .map_err(|_| anyhow::anyhow!("invalid Aliyun credentials file"))?;
            source.validate()?;
            let params = BTreeMap::from([
                ("RoleArn".into(), self.config.role_arn.clone()),
                (
                    "RoleSessionName".into(),
                    self.config.role_session_name.clone(),
                ),
                (
                    "DurationSeconds".into(),
                    self.config.duration_seconds.to_string(),
                ),
            ]);
            let body = self
                .rpc(&self.sts_url, "2015-04-01", "AssumeRole", params, &source)
                .await?;
            #[derive(Deserialize)]
            struct Response {
                #[serde(rename = "Credentials")]
                credentials: Credentials,
            }
            let response: Response = serde_json::from_slice(&body)
                .map_err(|_| anyhow::anyhow!("invalid AssumeRole response"))?;
            response.credentials.validate()?;
            ensure!(
                !response.credentials.security_token.is_empty(),
                "AssumeRole returned no SecurityToken"
            );
            let expires_at = response.credentials.expires_at()?;
            *cache = Some(Session {
                credentials: response.credentials,
                expires_at,
            });
        }
        let session = cache.as_ref().context("missing STS session")?;
        Ok(Credentials {
            access_key_id: session.credentials.access_key_id.clone(),
            access_key_secret: session.credentials.access_key_secret.clone(),
            security_token: session.credentials.security_token.clone(),
            expiration: session.credentials.expiration.clone(),
        })
    }

    async fn rpc(
        &self,
        url: &str,
        version: &str,
        action: &str,
        mut params: BTreeMap<String, String>,
        credentials: &Credentials,
    ) -> Result<Zeroizing<Vec<u8>>> {
        params.extend(BTreeMap::from([
            ("Action".into(), action.into()),
            ("Version".into(), version.into()),
            ("Format".into(), "JSON".into()),
            ("AccessKeyId".into(), credentials.access_key_id.clone()),
            ("SignatureMethod".into(), "HMAC-SHA1".into()),
            ("SignatureVersion".into(), "1.0".into()),
            ("SignatureNonce".into(), uuid::Uuid::new_v4().to_string()),
            (
                "Timestamp".into(),
                OffsetDateTime::now_utc()
                    .replace_nanosecond(0)?
                    .format(&Rfc3339)?,
            ),
        ]));
        if !credentials.security_token.is_empty() {
            params.insert("SecurityToken".into(), credentials.security_token.clone());
        }
        let body = signed_form(params, &credentials.access_key_secret)?;
        send_form(&self.http, url, action, body).await
    }
}

/// Shared HTTPS transport; authentication is implemented by each caller.
pub(super) async fn send_form(
    http: &reqwest::Client,
    url: &str,
    action: &str,
    body: Zeroizing<String>,
) -> Result<Zeroizing<Vec<u8>>> {
    // Parameters belong in the POST body, never in URLs or request logs.
    let mut response = http
        .post(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body.to_string())
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Aliyun {action} transport failed"))?;
    let status = response.status();
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("Aliyun {action} response read failed"))?
    {
        ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE_BYTES,
            "Aliyun response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        // Do not echo upstream bodies, which may contain request parameters.
        bail!("Aliyun {action} failed with HTTP {}", status.as_u16());
    }
    Ok(bytes)
}

pub(super) fn encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            result.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(result, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    result
}

pub(super) fn form(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", encode(key), encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn signed_form(mut params: BTreeMap<String, String>, secret: &str) -> Result<Zeroizing<String>> {
    let canonical = Zeroizing::new(form(&params));
    let string_to_sign = Zeroizing::new(format!("POST&%2F&{}", encode(&canonical)));
    let key_material = Zeroizing::new(format!("{secret}&"));
    let key = PKey::hmac(key_material.as_bytes())?;
    let mut signer = Signer::new(MessageDigest::sha1(), &key)?;
    signer.update(string_to_sign.as_bytes())?;
    params.insert("Signature".into(), STANDARD.encode(signer.sign_to_vec()?));
    let result = Zeroizing::new(form(&params));
    for value in params.values_mut() {
        value.zeroize();
    }
    Ok(result)
}

pub(super) fn parse_text_secret(body: &[u8]) -> Result<Vec<u8>> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Response {
        secret_data: String,
        secret_data_type: String,
    }
    let response: Response = serde_json::from_slice(body)
        .map_err(|_| anyhow::anyhow!("invalid GetSecretValue response"))?;
    // Preserve exact text bytes. Do not silently misinterpret binary data.
    ensure!(
        response.secret_data_type == "text",
        "only text KMS secrets are supported"
    );
    Ok(response.secret_data.into_bytes())
}

#[async_trait::async_trait]
impl StorageBackend for AliyunOpenApiBackend {
    async fn read_secret_resource(&self, resource: ResourceDesc) -> Result<Vec<u8>> {
        let credentials = self.session_credentials().await?;
        let params = BTreeMap::from([
            ("SecretName".into(), resource.resource_tag),
            ("RegionId".into(), self.config.region_id.clone()),
            ("VersionStage".into(), self.config.version_stage.clone()),
        ]);
        let body = self
            .rpc(
                &self.kms_url,
                "2016-01-20",
                "GetSecretValue",
                params,
                &credentials,
            )
            .await?;
        parse_text_secret(&body)
    }

    async fn write_secret_resource(&self, _: ResourceDesc, _: &[u8]) -> Result<()> {
        bail!("AliyunOpenApi resource backend is read-only")
    }

    async fn delete_secret_resource(&self, _: ResourceDesc) -> Result<()> {
        bail!("AliyunOpenApi resource backend is read-only")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    fn config(path: PathBuf) -> AliyunOpenApiConfig {
        AliyunOpenApiConfig {
            region_id: "cn-hangzhou".into(),
            credentials_file: path,
            role_arn: "acs:ram::1234567890123456:role/kbs-test".into(),
            role_session_name: default_session_name(),
            duration_seconds: default_duration(),
            version_stage: default_version_stage(),
        }
    }

    fn resource() -> ResourceDesc {
        ResourceDesc {
            repository_name: "default".into(),
            resource_type: "key".into(),
            resource_tag: "test-secret".into(),
        }
    }

    fn sts_response(expiration: OffsetDateTime) -> String {
        serde_json::json!({"Credentials": {
            "AccessKeyId": "temporary-ak", "AccessKeySecret": "temporary-sk",
            "SecurityToken": "temporary-token", "Expiration": expiration.format(&Rfc3339).unwrap()
        }})
        .to_string()
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
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                requests.push(String::from_utf8(request).unwrap());
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (url, task)
    }

    fn test_backend(path: PathBuf, url: String) -> AliyunOpenApiBackend {
        let mut backend = AliyunOpenApiBackend::new(config(path)).unwrap();
        backend.http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        backend.kms_url = url.clone();
        backend.sts_url = url;
        backend
    }

    fn credential_file() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(
            file,
            r#"{{"AccessKeyId":"source-ak","AccessKeySecret":"source-sk"}}"#
        )
        .unwrap();
        file
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(encode("a b+c/*~中"), "a%20b%2Bc%2F%2A~%E4%B8%AD");
    }

    #[test]
    fn signature_known_vector() {
        let params = BTreeMap::from([
            ("Action".into(), "GetSecretValue".into()),
            ("SecretName".into(), "a b".into()),
        ]);
        let signed = signed_form(params, "test-secret").unwrap();
        assert_eq!(
            &*signed,
            "Action=GetSecretValue&SecretName=a%20b&Signature=egWEQ3zc0lvv61HdMT4Ki7CCgaA%3D"
        );
    }

    #[test]
    fn rejects_unsafe_region_and_invalid_session() {
        let mut cfg = config(PathBuf::new());
        cfg.region_id = "cn-hangzhou.attacker/".into();
        assert!(AliyunOpenApiBackend::new(cfg).is_err());
        let mut cfg = config(PathBuf::new());
        cfg.duration_seconds = 899;
        assert!(AliyunOpenApiBackend::new(cfg).is_err());
    }

    #[tokio::test]
    async fn assumes_role_and_reuses_session_for_concurrent_reads() {
        let file = credential_file();
        let secret = r#"{"SecretData":"exact text\n", "SecretDataType":"text"}"#.to_string();
        let (url, task) = mock(vec![
            (
                200,
                sts_response(OffsetDateTime::now_utc() + time::Duration::hours(1)),
            ),
            (200, secret.clone()),
            (200, secret),
        ])
        .await;
        let backend = test_backend(file.path().into(), url);
        let (one, two) = tokio::join!(
            backend.read_secret_resource(resource()),
            backend.read_secret_resource(resource())
        );
        assert_eq!(one.unwrap(), b"exact text\n");
        assert_eq!(two.unwrap(), b"exact text\n");
        let requests = task.await.unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.contains("Action=AssumeRole"))
                .count(),
            1
        );
        assert!(requests[0].contains("AccessKeyId=source-ak"));
        for request in &requests[1..] {
            assert!(request.contains("SecurityToken=temporary-token"));
            assert!(!request.contains("source-ak"));
            assert!(request.starts_with("POST / HTTP/1.1\r\n"));
        }
    }

    #[tokio::test]
    async fn failed_refresh_does_not_use_old_or_source_credentials() {
        let file = credential_file();
        let (url, task) = mock(vec![(403, "sensitive-upstream-message".into())]).await;
        let backend = test_backend(file.path().into(), url);
        let credentials: Credentials = serde_json::from_str(
            r#"{"AccessKeyId":"old","AccessKeySecret":"old-sk","SecurityToken":"old-token"}"#,
        )
        .unwrap();
        *backend.session.lock().await = Some(Session {
            credentials,
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
        });
        let error = backend
            .read_secret_resource(resource())
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("sensitive-upstream-message"));
        assert!(error.contains("403"));
        assert!(backend.session.lock().await.is_none());
        assert_eq!(task.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn rejects_expired_sts_response() {
        let file = credential_file();
        let (url, task) = mock(vec![(
            200,
            sts_response(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
        )])
        .await;
        let backend = test_backend(file.path().into(), url);
        assert!(backend.read_secret_resource(resource()).await.is_err());
        assert!(backend.session.lock().await.is_none());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_binary_and_unsupported_writes() {
        let file = credential_file();
        let (url, task) = mock(vec![
            (
                200,
                sts_response(OffsetDateTime::now_utc() + time::Duration::hours(1)),
            ),
            (
                200,
                r#"{"SecretData":"AA==","SecretDataType":"binary"}"#.into(),
            ),
        ])
        .await;
        let backend = test_backend(file.path().into(), url);
        assert!(backend
            .read_secret_resource(resource())
            .await
            .unwrap_err()
            .to_string()
            .contains("only text"));
        assert!(backend
            .write_secret_resource(resource(), b"data")
            .await
            .is_err());
        assert!(backend.delete_secret_resource(resource()).await.is_err());
        task.await.unwrap();
    }
    #[test]
    fn public_and_legacy_configuration_remain_distinct() {
        use super::super::backend::RepositoryConfig;
        let public = serde_json::json!({
            "storage_backend_type": "AliyunOpenApi", "region_id": "cn-hangzhou",
            "credentials_file": "/run/secrets/credentials.json",
            "role_arn": "acs:ram::1234567890123456:role/kbs-test"
        });
        assert!(matches!(
            serde_json::from_value::<RepositoryConfig>(public).unwrap(),
            RepositoryConfig::AliyunOpenApi(_)
        ));
        let legacy = serde_json::json!({
            "storage_backend_type": "Aliyun", "client_key": "placeholder",
            "kms_instance_id": "placeholder", "password": "placeholder", "cert_pem": "placeholder"
        });
        assert!(matches!(
            serde_json::from_value::<RepositoryConfig>(legacy).unwrap(),
            RepositoryConfig::Aliyun(_)
        ));
    }

    #[tokio::test]
    async fn refreshes_session_and_rereads_source_file() {
        let file = credential_file();
        let (url, task) = mock(vec![(
            200,
            sts_response(OffsetDateTime::now_utc() + time::Duration::hours(1)),
        )])
        .await;
        let backend = test_backend(file.path().into(), url);
        let credentials: Credentials = serde_json::from_str(
            r#"{"AccessKeyId":"old","AccessKeySecret":"old-sk","SecurityToken":"old-token"}"#,
        )
        .unwrap();
        *backend.session.lock().await = Some(Session {
            credentials,
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(30),
        });
        tokio::fs::write(
            file.path(),
            r#"{"AccessKeyId":"rotated-ak","AccessKeySecret":"rotated-sk"}"#,
        )
        .await
        .unwrap();
        let refreshed = backend.session_credentials().await.unwrap();
        assert_eq!(refreshed.access_key_id, "temporary-ak");
        assert!(task.await.unwrap()[0].contains("AccessKeyId=rotated-ak"));
    }

    #[tokio::test]
    async fn rejects_redirects_and_redacts_bad_credentials() {
        let file = credential_file();
        let (url, task) = mock(vec![(302, "upstream-sensitive".into())]).await;
        let backend = test_backend(file.path().into(), url);
        assert!(backend
            .session_credentials()
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("302"));
        task.await.unwrap();
        tokio::fs::write(
            file.path(),
            r#"{"AccessKeyId":"do-not-echo", "AccessKeySecret": }"#,
        )
        .await
        .unwrap();
        let error = backend
            .session_credentials()
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("do-not-echo"));
    }
}
