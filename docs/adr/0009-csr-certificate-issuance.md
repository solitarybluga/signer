# ADR-0009：CSR 驱动的证书签发

- 状态：已接受（已实现）
- 日期：2026-10-23

## 背景

ADR-0008 把客户端权限放进证书，但最初的开发脚本在 CA 主机上集中生成 CA、服务端和客户端私钥。这个流程不适合多机部署：

- CA 主机能看到所有 endpoint 私钥；
- 私钥需要通过网络或人工拷贝到 endpoint；
- 客户端无法在自己的设备上生成并保管私钥。

需求是让客户端和服务端自己生成 `.key`，CA 只签署 CSR 并颁发证书。同时：

- 这是开源项目，不假设公司 CA、SPIFFE 或特定云服务；
- 桌面端和 `signer-admin` 不应依赖系统 openssl；
- CA 私钥必须口令保护；
- 权限位仍由 CA 在签发时决定，CSR 不能自行提权。

## 决策

1. **新增共享 crate `signer-permissions`**：
   - 权限位定义、权限名解析、u64 mask 校验、principal/holder 校验和默认 SAN URI 前缀只有一份；
   - server、`signer-pki`、`signer-admin`、desktop 共用，避免 CA 与 server 的位映射漂移。

2. **新增共享 crate `signer-pki`**：
   - 使用 `rcgen` + `pkcs8`，纯 Rust，ECDSA P-256；
   - 生成 CA、endpoint key + CSR、签名 CSR、解密加密私钥、校验证书与私钥；
   - CA 私钥使用 PKCS#8 PBES2（scrypt + AES-256-CBC）加密；
   - 不依赖系统 openssl。

3. **CA 签发只使用 CSR 公钥**：
   - 解析 CSR 时验证自签名（`CertificateSigningRequestParams::from_pem`）；
   - 完全丢弃 CSR 请求的 SAN、EKU、keyUsage、validity、serial 和自定义扩展；
   - 用调用方显式传入的 principal、holder IDs、permission mask、server SAN 重新构造证书；
   - 服务端/CA 都拒绝保留权限位；CA 不提供“原样签 CSR”模式。
   - 签发前检查 CA 的 `CA:TRUE`、`keyCertSign`、有效期和 CA key 匹配；签发后自检证书签名。

4. **CA 私钥保护**：
   - `tls-ca-init` 只写 `ca.key.enc`，不写明文 CA key；
   - `tls-sign-csr` 拒绝未加密的 CA key；
   - 口令来自环境变量，不接受命令行参数；
   - 生产应把 CA key 放在离线主机或 HSM，signer/桌面端/endpoint 不应持有。

5. **桌面端流程**：
   - 本机生成客户端私钥和 CSR，私钥用口令加密后保存；
   - 用户把 CSR 交给 CA，收到证书后导入路径；
   - 连接前可校验 CA 签名、有效期、EKU、证书与私钥匹配；
   - 桌面端永远不接触 CA 私钥。

6. **CLI 与脚本**：
   - `signer-admin tls-ca-init` / `tls-csr` / `tls-sign-csr`；
   - `scripts/mtls-csr.sh` / `.ps1` 只是 `signer-admin` 的薄封装，保证脚本和桌面端使用同一套 Rust 逻辑；
   - 旧 `scripts/gen-mtls.sh` / `.ps1` 保留为本地开发集中生成，文档明确不用于生产。

## 备选方案

| 方案 | 结论 |
|---|---|
| 继续集中生成所有私钥 | 拒绝：CA 接触 endpoint 私钥，不符合多机/开源部署 |
| 用 openssl 脚本做 CSR 签发 | 仅保留为开发便利；桌面端和 `signer-admin` 会引入系统 openssl 依赖 |
| 直接签署 CSR 请求的 SAN | 拒绝：客户端可自行申请 `unseal.seal`/`key.sign`，授权模型失效 |
| 只校验 CSR 签名、不校验 CA 权限 | 拒绝：CSR 签名只证明私钥持有，不证明授权 |
| 明文 CA key + 文件权限 | 拒绝：备份/误传会直接泄露授权根；至少做口令加密 |
| 用 HSM/KMS 托管 CA key | 生产推荐，但本版保持可移植的加密文件格式；接口可后续替换 |

## 影响

- 正面：
  - endpoint 私钥不离开生成主机；
  - CA 可以在离线环境签发，signer/桌面端不需要 CA 私钥；
  - 权限映射、CSR 校验和证书扩展只有一套实现；
  - CSR 请求字段不会变成实际授权。
- 负面：
  - 多了一步 CSR 传递和人工审批；
  - CA key 口令和 `tls-sign-csr` 调用权限成为关键资产；
  - 当前 signer 服务端和部分客户端仍只能读明文 TLS key（0600）；
  - 尚未实现 CRL/OCSP；撤销仍依赖短有效期和 CA。
- 兼容性：
  - `[tls]` 和证书 SAN 格式不变，已有证书继续有效；
  - 新增 crate 不改变现有 wire protocol；
  - 旧 `gen-mtls.sh` 产物仍可用于本地开发。

## 参考

- [mTLS 与客户端证书权限位](../mtls.md)
- [ADR-0008：mTLS + 客户端证书权限位掩码](0008-mtls-client-cert-permissions.md)
- [威胁模型](../threat-model.md)
