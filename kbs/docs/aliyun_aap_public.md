# IDC 通过公网 AAP 接入阿里云 KMS

`AliyunAapPublic` 是新增的只读资源后端。KBS 读取 AAP ClientKey 文件和口令文件，
直接对公网 `GetSecretValue` 请求做 RSA 签名。该后端不使用 RAM AK/SK，不调用 STS，
不要求 IDC 建立到 VPC 的私网连接。

构建时启用已有 `aliyun` Cargo feature。保留以下三种独立配置入口：

- `Aliyun`：原有 AAP ClientKey、私网实例端点与实例 API。
- `AliyunOpenApi`：RAM AK/SK 调用 STS，再访问公网 KMS OpenAPI。
- `AliyunAapPublic`：AAP ClientKey 直接访问公网 KMS OpenAPI。

## 1. 阿里云侧准备

1. 创建或调整 AAP 的权限策略，作用域选 **KMS 共享网关**，权限选 `SecretUser`，
   允许访问的资源限制为需要读取的 secret。将该策略绑定到使用的 AAP。
2. 创建并绑定网络规则，类型选 **Public**。填写 KBS 请求到达云端时实际使用的
   公网源 IP。存在 NAT、代理或统一出口时，使用其公网出口地址。
3. 为该 AAP 创建 ClientKey，保存下载的 JSON 和口令文件，核查有效期。
   仅有 Private 网络规则或实例作用域的旧策略，不满足此后端的公网授权要求。
4. 允许 KBS 访问 secret 所在地域的 `kms.<region_id>.aliyuncs.com:443`，
   并确保系统时间和 DNS 正常。无需开放入站业务端口。

以上为获取凭据的公网 OpenAPI 授权。不要将实例密码运算的“公网开关”作为统一前提；
本后端没有实现公网 AAP Encrypt/Decrypt。[官方 AAP 配置说明](https://help.aliyun.com/zh/kms/key-management-service/manage-aaps-1)

## 2. KBS 配置

在既有 KBS 配置中选择此资源后端。继续保留 HTTPS、远程证明、令牌验证和资源授权。
不要同时配置多个具有相同 resource 路由的插件来选择认证方式。

```toml
[[plugins]]
name = "resource"
storage_backend_type = "AliyunAapPublic"
region_id = "cn-hangzhou"
client_key_file = "/run/secrets/aliyun/client-key.json"
password_file = "/run/secrets/aliyun/client-key-password.txt"
version_stage = "ACSCurrent"
```

- `client_key_file`：阿里云下载的 JSON 文件，包含 `KeyId` 与 `PrivateKeyData`。
- `password_file`：下载的 ClientKey 口令文件；允许文件末尾有换行。
- `version_stage`：可省略，默认 `ACSCurrent`。

文件应只读挂载，仅 KBS 运行身份可读。禁止把实际凭据、口令或解密后的私钥写入仓库、
命令行参数、日志或普通 ConfigMap。此后端不接收 `kms_instance_id`、`cert_pem`、
RAM AK/SK 或 `role_arn`。公网 HTTPS 使用系统信任根并保持证书校验。

资源路径 `repo/type/tag` 中，`tag` 作为上游 secret 名称；`repo/type` 不创建云端
命名空间。必须在 KBS 资源策略和云端 AAP 策略中防止跨租户别名访问。
现有资源路径解析器不接受任意 secret ARN，本后端不修改该接口约束。

## 3. 协议实现依据

实现依据为阿里云官方 `aliyun-secretsmanager-client-go` 的 ClientKeySigner，
核查提交为 `cbee8b25ad28ba1b7c774896ff5709d6b7706c76`：

- `AccessKeyId` 使用 ClientKey 的 `KeyId`。
- `SignatureMethod` 为 `SHA256withRSA`。
- `SignatureType` 为 `PRIVATEKEY`，`SignatureVersion` 为 `1.0`。
- RSA PKCS#1 v1.5、SHA-256 对 RPC 规范化字符串签名，签名再作 base64 编码。
- API 为 `GetSecretValue`，版本为 `2016-01-20`。
- 使用公网 `kms.<region_id>.aliyuncs.com`，每次请求使用新的 nonce 和 UTC 时间戳。

ClientKey 的 `PrivateKeyData` 按 base64 PKCS#12 解析。显式检查容器 MAC、口令、
唯一私钥和 RSA 密钥强度；拒绝没有 MAC 的容器和小于 2048 bit 的 RSA 密钥。
复用现有依赖链中的 `p12` 0.6.3，以支持 AAP 的 RC2/3DES 容器，
不为 TLS 进程全局启用 OpenSSL legacy provider。其他容器算法没有兼容承诺，
解析不支持时返回错误。

## 4. 轮换、失败与能力边界

每次读取资源都会在阻塞任务中重新加载、解密 ClientKey 并签名，不缓存私钥或 secret。
替换文件后，后续请求使用新凭据。若密钥和口令同时更换，应协调更新两份文件；
更新过程中读到不匹配组合会拒绝请求。云端决定 ClientKey 到期或删除后的授权结果。

签名参数放在 POST 请求体，不放在 URL 中。禁止跟随 HTTP 重定向，连接超时 10 秒、
请求超时 30 秒、响应体上限 1 MiB。云端错误不回显原始响应，文件解析错误不包含
凭据内容。认证失败不会降级到 STS、RAM AK/SK 或其他后端，不自动重试。

当前只返回 `SecretDataType = "text"` 的精确 UTF-8 字节；对 binary 类型报错，
不猜测编码。需要 base64 文本时，显式以 text 保存并约定消费格式。
写入、删除以及通用 Encrypt/Decrypt 调用均返回不支持错误。

secret 明文存在于 KBS 内存。AAP 认证不替代 CoCo 工作负载的远程证明，也不消除
KBS 可信部署和凭据保护要求。该功能不会关闭现有 KBS 的证明、策略或响应加密流程。

## 5. 验证与联调

本地测试使用运行时生成的测试密钥和模拟 HTTP 服务，不需要真实云凭据：

```sh
cargo test -p kbs --no-default-features --features aliyun aliyun_aap_public
```

还需回归已有公网 STS 后端：

```sh
cargo test -p kbs --no-default-features --features aliyun aliyun_openapi
```

测试覆盖容器解密、MAC/口令错误、RSA 签名、规范化字符串、无 STS 调用、
文件轮换、重定向拒绝、错误脱敏和只读边界。模拟服务验证不能替代真实云账号联调。

上线前，在测试账号核验 Public 规则、实际公网来源、secret 授权、ClientKey 有效性、
目标地域和返回字节格式；再验证工作负载证明不通过、资源越权、密钥删除、错误口令
及网络中断时均无法获得 secret。不要通过关闭证明、授权或 TLS 校验来绕过联调错误。

## 6. 参考资料

- [阿里云 AAP 管理与 Public 网络规则](https://help.aliyun.com/zh/kms/key-management-service/manage-aaps-1)
- [KMS GetSecretValue](https://help.aliyun.com/zh/kms/key-management-service/developer-reference/api-kms-2016-01-20-getsecretvalue)
- [官方 ClientKey 签名器](https://github.com/aliyun/aliyun-secretsmanager-client-go/blob/cbee8b25ad28ba1b7c774896ff5709d6b7706c76/sdk/auth/client_key_signer.go)
- [官方 ClientKey 文件加载](https://github.com/aliyun/aliyun-secretsmanager-client-go/blob/cbee8b25ad28ba1b7c774896ff5709d6b7706c76/sdk/utils/client_key_utils.go)
- [官方 RPC 签名规范化实现](https://github.com/aliyun/alibaba-cloud-sdk-go/blob/v1.62.301/sdk/auth/rpc_signature_composer.go)
- [公网 STS 后端配置](./aliyun_public_kms.md)
