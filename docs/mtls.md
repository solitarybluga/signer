# mTLS 与客户端证书权限位

> 状态：已实现（2026-10-23）。服务端、loadtest、桌面端、CSR 签发工具和证书脚本已接入；本文描述实际行为。签发决策见 [ADR-0009](adr/0009-csr-certificate-issuance.md)。

## 1. 目标

- gRPC 使用标准 mTLS：服务端出示证书，客户端出示由受信 CA 签发的客户端证书。
- 客户端证书内直接携带“可调用方法集”，编码为一个 u64 权限位掩码。
- 服务端只保留静态权限位定义和逐 RPC 检查：
  - 没有本地授权策略文件；
  - 没有策略热加载；
  - 没有按客户端的配置白名单。
- 新增客户端、更换证书或调整权限 = CA 重新签发证书；signer 不重启、不重新解封。
- 客户端和服务端可以自行生成私钥与 CSR；CA 只签发 CSR，不接触 endpoint 私钥。
- 明文模式保留为本地开发默认；生产必须显式启用 `[tls]`。

## 2. 非目标

- 本版不实现 CRL/OCSP，也不维护本地 deny list；撤销依赖短有效期证书和 CA。
- 本版不做 key 级 label/tenant 范围；v1 只做 RPC 级权限和 holder 绑定。
- 本版不实现 ImportKey；mTLS 落地后再单独实现。
- 不把 mTLS 当作 Holder Ed25519 份额签名的替代品；两层认证都要保留。

## 3. 为什么不做本地策略文件热加载

服务重启会丢失内存中的 KEK，需要重新走门限解封，代价很高。但把授权策略放进本地文件并自动重载，会引入更大的安全问题：

- 谁能写策略文件，谁就能给自己加权限，等价于提权；
- 文件替换、部分写入、权限错误、备份泄露都会变成授权漏洞；
- 运行时可变授权根难以审计和复现。

因此授权信息放在 **CA 签名的客户端证书** 里。CA 是授权签发边界；signer 只验证证书和位掩码，不读取可写授权配置。

## 4. 证书要求

### 4.1 服务端证书

- `extendedKeyUsage = serverAuth`
- `subjectAltName` 必须包含客户端实际连接使用的主机名/IP，例如：

```ini
subjectAltName = DNS:localhost,IP:127.0.0.1
```

### 4.2 客户端证书

- `extendedKeyUsage = clientAuth`
- `basicConstraints = critical,CA:FALSE`
- 使用 SAN URI 携带身份和权限：

```ini
subjectAltName = URI:signer://principal/alice,
                 URI:signer://holder/holder-1,
                 URI:signer://permissions/0x0000000000000045
```

约束：

| 字段 | 数量 | 说明 |
|---|---|---|
| `signer://principal/<actor>` | 恰好 1 个 | 审计 actor；非空，长度上限 128 |
| `signer://holder/<holder-id>` | 0 个或多个 | `SubmitUnsealShare` 的 holder 绑定；每个非空 |
| `signer://permissions/0x<16-hex>` | 0 或 1 个 | u64 权限位掩码；缺失视为 0（无权限） |

- 多个 principal 或多个 permissions URI → 拒绝整张证书。
- 前缀可由服务端配置调整；默认如上。
- 其他命名空间下的 SAN URI 忽略。
- 证书链、有效期由 rustls 验证；signer 额外检查 EKU、CA 标志和 SAN 结构。

## 5. 权限位协议

权限掩码是 **u64**，低位在前。URI 中使用 `0x` + 最多 16 位十六进制；服务端接受 1–16 位并规范化为 u64，超过 16 位、负数样式或非法字符均拒绝。

| bit | 权限 | 对应 RPC |
|---|---|---|
| 0 | `unseal.start` | `StartUnseal` |
| 1 | `unseal.submit` | `SubmitUnsealShare` |
| 2 | `unseal.status` | `GetUnsealStatus` |
| 3 | `unseal.seal` | `Seal` |
| 4 | `key.create` | `CreateKey` |
| 5 | `key.import` | `ImportKey`（仍为 `UNIMPLEMENTED`） |
| 6 | `key.read` | `GetPublicKey`、`ListKeys` |
| 7 | `key.sign` | `Sign` |
| 8 | `key.destroy` | 预留，当前无 RPC，必须为 0 |
| 9 | `audit.read` | 预留，当前无 RPC，必须为 0 |
| 10–63 | 保留 | 必须为 0 |

规则：

- **保留位为 1 的风险**：任何保留位被置位（包括 bit 8/9、bit 63、`0xFFFFFFFFFFFFFFFF` 全 1）都必须拒绝整张证书，不能忽略，也不能当通配符。bit 8/9 只有在对应的 `key.destroy`/`audit.read` RPC 和检查真正实现后才会加入 `KNOWN_MASK`。
- mask `0` 表示“没有任何权限”，不是“全部权限”；禁止 all-ones/通配语义。
- 位号只追加，不能重排或复用；删除权限时该 bit 永久保留为空。
- 新增权限位时，必须先升级 signer（扩大 `KNOWN_MASK`），再更新 CA 模板并签发新证书；旧证书继续有效。
- 旧 signer 遇到带新 bit 的证书会拒绝整张证书，这是有意的 fail-closed 行为。
- 证书里的权限集合是公开信息，不得放 secret。

### 为什么保留位为 1 要拒绝整张证书

权限位不是普通配置，而是安全授权协议。服务端遇到自己无法解释的授权语义时，应该拒绝，而不是猜测或忽略：

1. **防止“潜伏权限”**：如果旧服务端忽略保留位，某张证书带了未来才会分配的 bit，旧服务端会接受它；等 signer 升级并给该 bit 分配了危险权限（例如 `unseal.seal`/`key.export`），这张旧证书会**突然获得新权限**，不需要重新签发。拒绝未知位可以避免这种跨版本提权。
2. **防止 all-ones / 模板错误变成 god mode**：`0xFFFFFFFFFFFFFFFF` 包含所有已知位。即使只“忽略未知位、保留已知位”，它仍会授予当前所有权限；如果把它当通配符，风险更大。拒绝整张证书可以阻止一次 CA 模板默认值或复制粘贴错误直接产生超级权限。
3. **防止解析截断**：u64 最多 16 位 hex；17 位及以上如果被截断，高位可能对应真实权限，导致权限被静默改变。拒绝超长/非法 mask，保证“证书里写的”与“服务端理解的”完全一致。
4. **让版本漂移显式失败**：保留位为 1 通常意味着 CA 模板比 signer 新，或签发配置有误。静默接受会让运维误以为权限已生效；拒绝会立即暴露升级顺序问题。
5. **审计一致性**：signer 应能准确说明“这张证书被授予了什么”。接受无法完全解释的掩码会破坏审计语义。

这和 X.509 的 critical extension 原则类似：验证方不认识 critical extension 时必须拒绝整张证书，而不是忽略。权限位在这里被视为“critical authorization data”。

代价是升级顺序必须是：**先升级 signer（扩大 `KNOWN_MASK`），再更新 CA 模板并签发带新 bit 的证书**。旧证书不受影响；如果 CA 先于服务端签发带新 bit 的证书，旧服务端会拒绝，这是有意的 fail-closed。

如果未来权限位变化非常频繁，可以引入版本化 URI（例如 `signer://permissions/v1/0x...`）并在版本内继续拒绝未知位；但不应退化成静默忽略未知授权位。

常见掩码示例：

| 场景 | 权限 | mask |
|---|---|---|
| 只读 | `key.read` | `0x0000000000000040` |
| 签名 | `key.sign` + `key.read` | `0x00000000000000C0` |
| 发起解封 | `unseal.start` + `unseal.status` | `0x0000000000000005` |
| 份额提交 | `unseal.submit` + `unseal.status` | `0x0000000000000006` |
| 密钥管理 | `key.create` + `key.read` | `0x0000000000000050` |

## 6. 服务端配置

`signer.toml`：

```toml
[tls]
cert_path = "data/tls/server.crt"
key_path = "data/tls/server.key"
client_ca_path = "data/tls/ca.crt"

# 可选，默认如下
principal_uri_prefix = "signer://principal/"
holder_uri_prefix = "signer://holder/"
permission_uri_prefix = "signer://permissions/"
```

- `[tls]` 缺失 → 明文模式，启动时 `WARN`，仅适合本机/可信网络。
- `[tls]` 存在 → 三个路径必填；启用严格 mTLS。
- 环境变量：`SIGNER_TLS_CERT`、`SIGNER_TLS_KEY`、`SIGNER_TLS_CLIENT_CA`，必须同时设置；全部存在时可在没有 `[tls]` 配置的情况下启用 TLS（prefix 使用默认值）。
- 相对路径按进程工作目录解析，与 `server.data_dir` 一致。
- 启动时读取并解析 PEM；文件缺失、为空、证书/私钥不匹配、CA 无法构建时直接退出（fail closed）。
- 不记录私钥内容；日志只记录 cert/CA 路径、启用状态和 URI prefix。

服务端 TLS 使用 `client_auth_optional(true)`，让“缺少客户端证书”进入应用层并返回 `UNAUTHENTICATED`；如果 CA 不信任，则在 TLS 握手阶段失败，客户端看到 transport error。

## 7. RPC 权限检查

| RPC | 必需权限 | 资源检查 |
|---|---|---|
| `StartUnseal` | `unseal.start` | — |
| `SubmitUnsealShare` | `unseal.submit` | `share_holder_id` 必须属于证书的 `holder/*` 集合 |
| `GetUnsealStatus` | `unseal.status` | — |
| `Seal` | `unseal.seal` | — |
| `CreateKey` | `key.create` | — |
| `ImportKey` | `key.import` | 有权后仍返回 `UNIMPLEMENTED` |
| `GetPublicKey` | `key.read` | — |
| `ListKeys` | `key.read` | — |
| `Sign` | `key.sign` | — |

- 权限检查在产生副作用前执行；`CreateKey`/`Sign` 的审计 actor 来自 `principal/*`。
- 授权失败统一返回通用 `PERMISSION_DENIED`，不暴露缺少哪个 bit。
- 明文本地开发模式不做权限检查，审计 actor 仍为 `"grpc"`。

## 8. 错误行为

| 情况 | 结果 |
|---|---|
| 无客户端证书 | `UNAUTHENTICATED`（应用层拦截器） |
| 客户端证书不是受信 CA 签发 | TLS 握手失败（transport error） |
| 证书解析失败、缺少 principal | `UNAUTHENTICATED` |
| 多个 principal / 多个 permissions URI | `PERMISSION_DENIED` |
| 权限 mask 非法、超过 16 位、保留位为 1 | `PERMISSION_DENIED` |
| 缺少 permissions URI | mask 0；TLS 成功，所有 RPC `PERMISSION_DENIED` |
| 有身份但缺少该 RPC 的 bit | `PERMISSION_DENIED` |
| holder 不在证书 `holder/*` 中 | `PERMISSION_DENIED` |

## 9. 客户端接入

### 9.1 loadtest

计划参数（随实现提供）：

```bash
SIGNER_LOADTEST_PASSPHRASE='test-passphrase' \
cargo run -p signer-loadtest -- \
  --server https://127.0.0.1:50051 \
  --ca-cert data/tls/ca.crt \
  --client-cert data/tls/loadtest.crt \
  --client-key data/tls/loadtest.key \
  --holder alice.key,alice.share \
  --holder bob.key,bob.share \
  --concurrency 50 --duration-secs 30
```

- 三个 TLS 参数必须同时提供；target 必须是 `https://`。
- 压测证书需要 `unseal.start/submit/status`、`key.create/read/sign` 位，并在 `holder/*` 中列出所有测试 holder ID。
- 如果客户端私钥是加密 PKCS#8，设置 `SIGNER_TLS_KEY_PASSPHRASE`（或 `--client-key-passphrase-env` 指定其他变量）；loadtest 在本地解密，不把口令发给服务端。
- 没有 TLS 参数时保持原有 `http://` 行为。

### 9.2 桌面端

- 顶部增加可选的 mTLS 设置：CA 证书、客户端证书、客户端私钥、可选 TLS domain 和客户端私钥口令。
- 独立「申请证书」tab：填写 principal、holder ID，权限以复选框勾选；选择私钥/CSR 保存路径并输入口令。私钥使用 PKCS#8 PBES2 加密后落盘，CA 不会接触私钥。
- 收到 CA 签发的证书后，把证书路径填入「客户端证书」，点击「校验证书与私钥」：客户端会检查证书是否由当前 CA 签发、是否在有效期内、EKU 是否为 clientAuth、证书与私钥是否匹配，并显示 principal/权限/指纹。
- 四个联网命令（发起会话、查询状态、封存、从 vault 提交）都使用同一套 TLS 设置；轮询 `GetUnsealStatus` 也不例外。加密私钥的口令只在连接调用中传入，不写 `localStorage`。
- 仅路径和 domain 持久化到本地，不保存私钥内容或口令。
- Operator 与 Holder 使用不同证书和不同权限位。

### 9.3 Apifox / grpcurl

Apifox 的 gRPC 请求在“服务器”齿轮中启用 TLS，上传 CA、客户端证书和客户端私钥。预检可用：

```bash
grpcurl \
  -cacert data/tls/ca.crt \
  -cert data/tls/alice.crt \
  -key data/tls/alice.key \
  -import-path proto -proto signer/v1/signer.proto \
  127.0.0.1:50051 \
  signer.v1.SignerService/StartUnseal
```

## 10. 证书签发

有两条路径：生产/多机部署使用 CSR，本机开发可以用集中生成脚本。

### 10.1 CSR 签发（推荐）

私钥只在 endpoint 生成，CA 只看到 CSR 和公钥。CA **必须忽略 CSR 请求的 SAN/扩展**，用审批后的 principal、holder、权限和 server SAN 重新签发；`signer-pki` 已按此实现。

`signer-admin` 命令：

```bash
# 1. 在离线 CA 主机创建 CA；私钥用 PKCS#8 PBES2 加密
export SIGNER_CA_PASSPHRASE='ca-key-passphrase'
cargo run -p signer-admin -- tls-ca-init --out-dir data/tls
# 生成 data/tls/ca.crt 和 data/tls/ca.key.enc

# 2. 在 endpoint 主机生成私钥和 CSR（不需要 CA 私钥）
export SIGNER_TLS_KEY_PASSPHRASE='client-key-passphrase'
cargo run -p signer-admin -- tls-csr --kind client \
  --principal alice --holder holder-1 \
  --permissions unseal.start,unseal.status,key.read \
  --out-key data/tls/alice.key --out-csr data/tls/alice.csr

# 3. 在 CA 主机审批并签发；CSR 中请求的字段会被覆盖
export SIGNER_CA_PASSPHRASE='ca-key-passphrase'
cargo run -p signer-admin -- tls-sign-csr --kind client \
  --ca-cert data/tls/ca.crt --ca-key data/tls/ca.key.enc \
  --principal alice --holder holder-1 \
  --permissions unseal.start,unseal.status,key.read \
  --csr alice.csr --out alice.crt
```

服务端证书：

```bash
cargo run -p signer-admin -- tls-csr --kind server --plaintext-key \
  --server-san DNS:localhost --server-san IP:127.0.0.1 \
  --out-key data/tls/server.key --out-csr data/tls/server.csr

cargo run -p signer-admin -- tls-sign-csr --kind server \
  --server-san DNS:localhost --server-san IP:127.0.0.1 \
  --csr data/tls/server.csr --out data/tls/server.crt
```

行为与约束：

- `--permissions` 使用本文的权限名；CA 只接受已知位，`signer-permissions` 是 server/CA/desktop 共用的唯一映射。
- 客户端私钥默认要求 `SIGNER_TLS_KEY_PASSPHRASE`；`--plaintext-key` 只用于无法解密 PKCS#8 的消费者。当前 signer 服务端证书要求明文 key（0600）；loadtest 和桌面端支持加密 key。
- CA 私钥必须是加密 PEM；`tls-sign-csr` 拒绝未加密的 CA key，并检查 CA 的 CA 标志、`keyCertSign`、有效期、CA key 与证书是否匹配、CSR 自签名；签发后再自检证书签名。
- 私钥写入 0600；证书 0644（Unix）。Windows 依赖用户目录 ACL。
- 口令不进入 argv：CA 口令来自 `SIGNER_CA_PASSPHRASE`，endpoint key 口令来自 `SIGNER_TLS_KEY_PASSPHRASE`；可用 `--passphrase-env` / `--key-passphrase-env` 改变量名。
- 默认拒绝覆盖，`--force` 才重写。
- 当前实现使用 rcgen + pkcs8（ECDSA P-256，PKCS#8 PBES2-scrypt/AES-256-CBC），桌面端和 `signer-admin` 不依赖系统 openssl。

脚本封装（内部调用 `signer-admin`，不需要系统 openssl）：

```bash
scripts/mtls-csr.sh ca-init --out-dir data/tls
SIGNER_TLS_KEY_PASSPHRASE=... scripts/mtls-csr.sh csr --kind client ...
SIGNER_CA_PASSPHRASE=... scripts/mtls-csr.sh sign-csr --kind client ...
```

PowerShell 对应 `scripts/mtls-csr.ps1`。这些脚本会在仓库根目录执行 `cargo run -p signer-admin`。

### 10.2 开发用集中生成（仅本地）

`scripts/gen-mtls.sh`（Git Bash/WSL）和 `scripts/gen-mtls.ps1`（Windows PowerShell）一次生成 CA、服务端和客户端证书，适合本机开发和测试。CA 主机会看到所有私钥，**不要用于生产或多机部署**；生产请使用 10.1 的 CSR 流程。

```bash
scripts/gen-mtls.sh --out data/tls \
  --server-san "DNS:localhost,IP:127.0.0.1" \
  --client alice:unseal.start,unseal.status,key.read \
  --holder alice:holder-1
```

PowerShell：

```powershell
.\scripts\gen-mtls.ps1 -Out data/tls `
  -Client "alice:unseal.start,unseal.status,key.read" `
  -Holder "alice:holder-1"
```

脚本行为：

- 自建 CA、服务端证书和客户端证书；RSA 2048/3072，PKCS#8 PEM，SHA-256。
- 客户端 SAN 写入 principal、holder 和 `0x` + 16 位权限 mask。
- 权限名→bit 映射与本文和 Rust 常量保持一致；脚本打印 mask 和证书 SHA-256 指纹，不打印私钥。
- Unix 下目录 `0700`、私钥 `0600`、证书 `0644`；PowerShell 用 `icacls` 限制当前用户。
- 默认拒绝覆盖，`--force` 才重建。
- 生成的 `ca.key` 未加密，只适合本地开发；CSR 流程的 `ca.key.enc` 才有口令保护。

### 10.3 测试 fixture

`scripts/gen-test-certs.sh` 生成 `crates/server/tests/fixtures/mtls/` 的静态测试证书。测试 fixture 只提交证书和 test-only 客户端/服务端私钥；**不提交 CA 私钥**。签发逻辑的单元测试在运行时临时生成密钥和证书，不依赖这些 fixture。

## 11. 运维与轮换

- **新增客户端 / 改权限**：CA 重新签发证书；signer 不重启、不解封。
- **撤销**：使用短有效期证书；本版没有 CRL/OCSP，也没有本地 deny list。证书被窃后在有效期内仍可使用，必须靠短有效期和 CA 流程降低风险。
- **服务端证书 / client CA bundle 轮换**：仍需重启 signer，重启会丢失 KEK，需要重新门限解封；应规划长有效期根 CA 或后续做自定义 rustls verifier 热加载。
- **CA 是授权根**：CA 必须强制限制客户端证书里的权限位。如果用户能自己在 CSR 里写 `unseal.seal`/`key.sign`，整套授权失效。`tls-sign-csr` 只接受命令行显式审批的字段，并丢弃 CSR 请求的 SAN；审批仍应由带外流程完成。建议 CA 模板、审批流程、专用签发入口或 SPIRE 类身份系统。
- **CA 私钥**：`ca.key.enc` 只能放在离线 CA 主机或 HSM；不要放到 signer、loadtest、桌面端或任何 endpoint 主机。口令只保护静态文件，不能阻止已控制 CA 主机的人签发证书。生产应使用离线 CA/HSM，并限制 `tls-sign-csr` 的调用权限。口令通过环境变量传入以避免出现在 argv，但同一用户仍可能读取进程环境；生产应在专用签发主机上执行。
- **endpoint 私钥**：桌面端和 loadtest 支持加密 PKCS#8 口令；signer 服务端和部分 gRPC 客户端仍使用明文 key（0600）。不要把 endpoint 私钥交给 CA；CSR 流程只需要公钥。
- **反向代理**：如果 TLS 在代理终止，代理能看到明文并能改写响应，客户端证书身份也会丢失；需要 TLS passthrough 或在代理到 signer 之间再加 mTLS。

## 12. 安全边界

- mTLS 只证明“证书由受信 CA 签发”；权限位由 CA 签发策略保证。CSR 只承载公钥和请求字段，CA 必须重新写入已审批字段；不能把 CSR 原样签成证书。
- `tls-sign-csr` 会验证 CSR 自签名，但不会因为 CSR 请求了某权限就授予该权限。
- `SubmitUnsealShare` 仍由 Holder Ed25519 签名、会话 nonce 和 VSS 校验保护；证书权限只是网络/接口层的额外约束。
- 解封后 KEK 和完整私钥在单进程内存中；mTLS 不改变这一点。
- 明文模式仍存在；生产必须启用 `[tls]` 并保持 `data/`、私钥文件和 CA 私钥的权限隔离。

## 13. 验收清单

自动化测试已覆盖：

- [x] 无客户端证书 → `UNAUTHENTICATED`；不受信 CA → 握手失败。
- [x] 只读证书只能调用 `GetPublicKey`/`ListKeys`。
- [x] `key.sign` 与 `key.create` 分离；交叉调用被拒。
- [x] `unseal.start` 与 `unseal.submit` 分离；holder 绑定正确。
- [x] 保留位/全 1/17 位 mask 被拒绝。
- [x] 新签发证书立即可用，无需重启 signer。
- [x] CSR 签发的证书可直接被服务端接受；服务端运行期间新签发的证书无需重启即可使用。
- [x] CA 忽略 CSR 请求的 principal/holder/权限/SAN，只写入审批值。
- [x] CSR 自签名被篡改时拒绝签发；CA 私钥未加密、口令错误、CA 与 key 不匹配时拒绝签发。
- [x] CA 私钥为加密 PKCS#8；桌面端私钥可为加密 PKCS#8，并校验证书与私钥匹配。
- [x] `audit_log.actor` 来自证书 principal。
- [x] 日志、错误和审计中没有私钥、key 内容或完整证书。

手工联调待完成：

- [ ] loadtest、桌面端、Apifox/grpcurl 均可用 mTLS 联调。
