# AAP client key 的备份和迁移

`AliyunEnclave` 的 `client_key`、`password`、`cert_pem` 不进 KBS 配置，也不进 KBS 进程。它们由 `sgx-aap-wrap` 的 enclave 保存。本地持久化用 Intel SGX Protected File System，不用 `sgx_seal_data`。

## 本地保存

在 enclave 内用 `sgx_fopen_auto_key` 创建受保护文件，用 `sgx_fwrite` 写入 `client_key` 材料。

`sgx_fopen_auto_key` 把本机 enclave 的 seal key 当作密钥派生密钥，只用来保护元数据节点。seal key 来自 `EGETKEY`，没有导出接口，也不能拷到另一颗 CPU。文件内容的加密密钥放在元数据节点里。

## 为什么不用 sgx_seal_data

`sgx_seal_data` 只产出 `sgx_sealed_data_t`。对应的 seal key 不能导出，操作员看不到，也无法提前备份。CPU 损坏后，这块密文不能再 `sgx_unseal_data`。

## 机器正常时备份

在原来的 CPU 还能运行 enclave 时调用 `sgx_fexport_auto_key`。它按文件元数据里保存的 `key_id` 调用 `sgx_get_key`，把当前加密元数据节点的 128 位密钥复制出来。这把密钥是这次派生的结果，不是 `EGETKEY` 的根密钥，也不能在另一颗 CPU 上重新派生。

同时保留受保护文件本身。把导出的 128 位文件密钥备份到这台宿主机以外。它和受保护文件放在一起就能得到 `client_key`，不要以明文留在本机磁盘、etcd 或 `runc` 容器里。

只备份受保护文件、没有这把导出的密钥，新机器上打不开。

## 硬件损坏后的迁移

原 CPU 已经坏了之后，不能再调用 `sgx_fexport_auto_key`，也不能 `sgx_unseal_data`。

在新机器的 enclave 里，用事先备份的 128 位密钥调用 `sgx_fimport_auto_key`。这次打开不再调用 `EGETKEY`，直接用备份的密钥解密元数据，再用新 CPU 的 seal key 重新加密元数据。之后可以用 `sgx_fopen_auto_key` 打开，再继续用这把 `client_key` 访问阿里云 KMS。

受保护文件的 basename 写在加密元数据里。迁移时可以换目录，文件名必须保持不变。改名后 `sgx_fimport_auto_key` 返回 `SGX_ERROR_FILE_NAME_MISMATCH`（`0x7003`）。

导出必须发生在原 CPU 还能运行的时候。硬件已经损坏才第一次去导出，文件同样打不开。

## 命令

`sgx-aap-wrap` 在 enclave 里调用这些接口：

```bash
sgx-aap-wrap store --material aap.json --file /var/lib/sgx-aap/client.protected
sgx-aap-wrap export-key --file /var/lib/sgx-aap/client.protected --key-out /tmp/file.key
sgx-aap-wrap import --file /var/lib/sgx-aap/client.protected --key-file /tmp/file.key
```

`export-key` 写出的 16 字节是元数据密钥。把它复制到这台宿主机以外，然后删除本机这份。`import` 在新机器上执行，受保护文件要先拷过去，并且 basename 保持为 `client.protected`。同一颗 CPU 上重新打开文件还依赖原来的 enclave 签名私钥，那把私钥在 `enclave/build/Enclave_private.pem`，不要提交到仓库。
