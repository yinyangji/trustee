# IDC 通过公网接入阿里云 KMS

`AliyunOpenApi` 是新增的 KBS 只读资源后端。它使用 RAM AK/SK 调用 STS
`AssumeRole`，再用临时 AK/SK 和 SecurityToken 调用 KMS OpenAPI
`GetSecretValue`。构建时启用现有 `aliyun` Cargo feature。
原有 `Aliyun` 后端和 AAP ClientKey 配置保持兼容。

使用的公网 HTTPS 端点为：

- `sts.<region_id>.aliyuncs.com`
- `kms.<region_id>.aliyuncs.com`

部署前核实所选地域提供这两个端点。此实现使用 `aliyuncs.com` 域名，不要求 IDC
建立到云上 VPC 的私网连接。使用公网 AAP ClientKey 时，改用独立的 [AliyunAapPublic 后端](./aliyun_aap_public.md)。

## 配置

将以下插件加入既有配置，继续保留 HTTPS、远程证明、令牌验证和资源授权配置。

```toml
[[plugins]]
name = "resource"
storage_backend_type = "AliyunOpenApi"
region_id = "cn-hangzhou"
credentials_file = "/run/secrets/aliyun/credentials.json"
role_arn = "acs:ram::<account-id>:role/<role-name>"
role_session_name = "coco-kbs"
duration_seconds = 3600
version_stage = "ACSCurrent"
```

由运维挂载凭据 JSON 文件，示意结构如下，禁止将实际凭据提交到仓库：

```json
{
  "AccessKeyId": "<RAM-user-access-key-id>",
  "AccessKeySecret": "<RAM-user-access-key-secret>"
}
```

文件应只读挂载，仅 KBS 服务身份可读。这是 RAM 凭据文件，不是 AAP ClientKey。
若源凭据本身是临时凭据，还需包含 `SecurityToken` 和 RFC3339 格式的 `Expiration`，
由外部服务负责续期源文件。

调用身份需要目标角色的 `sts:AssumeRole` 权限，角色信任策略需要允许该身份。
授予角色访问指定 secret 的最小权限。secret 使用用户指定主密钥保护时，还可能
需要该密钥的 `kms:Decrypt` 权限。`duration_seconds` 接受 900—43200 秒，
实际值不得超过角色的最大会话时间；角色约束由 STS 服务端检查。

资源路径 `repo/type/tag` 的 `tag` 映射到上游 secret 名称，`repo/type` 不创建云端
命名空间。必须结合命名和资源策略避免跨租户路径别名。现有资源路径解析器限制
单个 tag 的字符，因此本后端不支持直接填入任意 secret ARN。

## 续期和失败行为

- 第一次读取资源时申请 STS，之后复用会话，不缓存 secret 值。
- 在服务端返回的过期时间前 120 秒进入刷新窗口；由下一次资源请求触发刷新。
- 刷新过程持有互斥锁，避免并发申请同一会话；资源请求在锁外发送。
- 每次刷新重新读取源凭据文件。原子替换该文件可轮换 AK/SK；已缓存的有效会话
  会保留到刷新窗口，文件替换不会主动撤销旧会话。
- 刷新失败拒绝本次取钥，不退回使用源 AK/SK 访问 KMS。下一次请求可重新尝试。
- 对权限拒绝、限流或提前撤销的会话，不自动重试。云端可在有效期结束前拒绝旧会话。
- 禁止 HTTP 重定向，保持 HTTPS 证书校验。签名参数放 POST 请求体，不放 URL。
  应用错误不包含云端原始响应、签名参数或凭据。连接超时 10 秒，请求超时 30 秒，
  响应体上限 1 MiB。

当前仅支持 `SecretDataType = "text"`，返回精确 UTF-8 字节。对 binary 类型直接报错，
避免猜测编码导致密钥损坏。需要 base64 文本时，应显式以 text 保存并约定消费端格式。
写入、删除和通用 Encrypt/Decrypt 不属于本资源后端能力，调用时返回错误。
secret 明文存在于 KBS 内存；STS 不消除对 KBS 进程与源凭据保护的要求。

## 验证

不使用真实云凭据即可执行本地模拟服务测试：

```sh
cargo test -p kbs --no-default-features --features aliyun aliyun_openapi
```

上线前仍需在测试云账号中验证：角色信任、KMS 权限、端点可达性、secret 字节格式、
会话续期、凭据轮换，以及证明失败、资源越权、断网和凭据失效时的拒绝行为。
本地模拟测试不证明已与真实阿里云服务联通。

## 官方参考

- [STS AssumeRole](https://help.aliyun.com/zh/ram/developer-reference/api-sts-2015-04-01-assumerole)
- [KMS GetSecretValue](https://help.aliyun.com/zh/kms/key-management-service/developer-reference/api-kms-2016-01-20-getsecretvalue)
- [KMS RPC 公共参数](https://help.aliyun.com/zh/kms/key-management-service/common-parameters-1)
- [KMS 网关与端点](https://help.aliyun.com/zh/kms/key-management-service/developer-reference/overview-3)
