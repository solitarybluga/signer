# signer

**基于 Rust 的 gRPC 签名服务，支持门限解封（quorum unsealing）。**

> ⚠️ 早期开发阶段，未经安全审计，请勿用于真实资产。

## 项目定位

`signer` 以密文形式保存私钥，启动时必须由预设数量的份额持有者共同提供 Shamir 份额，恢复出密钥加密密钥（KEK）后才能解密私钥并提供签名服务。当前解封使用 Ristretto255 Feldman VSS，持有者和服务端都能逐份验证份额。目标是支持 secp256k1 + ECDSA（EVM）与 edwards25519 + EdDSA（Solana）。

## 它不是什么（v0.1）

v0.1 的目标是**门限密钥托管 / 门限解封**，不是门限签名。解封之后，完整私钥存在于 signer 进程内存中，任何一个已解封的实例都可以独立签名。真正的门限签名——Ed25519 用 FROST、ECDSA 用 CGGMP21——在路线图中。

## 状态

| 里程碑 | 范围 | 状态 |
| --- | --- | --- |
| v0.1 | 单签 + VSS 门限解封 + mTLS | 🚧 进行中（VSS 解封与 mTLS 已实现） |
| v0.2 | 份额轮换、监控指标 | ☐ 计划中 |
| v0.3 | 门限签名（FROST / CGGMP21） | ☐ 计划中 |

## 当前进度

| 模块 | 状态 |
| --- | --- |
| 存储模型、迁移、SQLite / PostgreSQL 实现 | ✅ 已实现，含测试 |
| KEK 初始化与加密份额分发（signer-admin） | ✅ 已实现 |
| 门限解封（Ristretto255 Feldman VSS、会话、KEK 恢复与校验） | ✅ 核心已实现 |
| VSS 份额校验（Holder 导入 + Server 提交） | ✅ 已实现 |
| gRPC 解封接口（StartUnseal / SubmitUnsealShare / GetUnsealStatus / Seal） | ✅ 已实现 |
| 桌面端 Holder 身份、份额 vault 与解封提交（Tauri） | ✅ 已实现 |
| 加密 keystore（DEK/KEK 信封） | ✅ Ed25519 与 secp256k1 已实现 |
| 份额提交加密与持有者签名 | ✅ 已实现（每会话 X25519 + Ed25519） |
| gRPC mTLS + 客户端证书权限位 | ✅ 已实现（服务端、loadtest、桌面端；支持 CSR 签发；见 [docs/mtls.md](docs/mtls.md)） |
| 密钥管理接口与签名 | ✅ EdDSA/ECDSA 的 CreateKey/GetPublicKey/ListKeys/Sign 已实现；ImportKey 未实现 |

## v0.1 目标特性

以下为 v0.1 目标；存储、解封、份额分发、桌面端 Holder 流程和基于 Ed25519 / secp256k1 的密钥生成与签名已完成，ImportKey 仍在开发中。

- 加密存储：每密钥独立 DEK，KEK 信封包裹（XChaCha20-Poly1305）
- 支持导入已有私钥（secp256k1 标量 / edwards25519 种子）
- 份额分发：对 VSS 份额做 X25519 信封加密，每个持有者用本地私钥解密
- 门限解封：对 KEK 做 Ristretto255 Feldman VSS 分享，逐份校验份额，并用 KEK 校验密文验证重建结果
- 安全提交：会话 nonce 绑定、份额加密到每会话临时 X25519 公钥、持有者 Ed25519 签名，服务端验签/解密/VSS 后才计数
- 签名：secp256k1 + ECDSA（EVM）与 edwards25519 + EdDSA（Solana）
- gRPC 接口（tonic）：解封接口与 EdDSA 密钥管理/签名
- mTLS + 客户端证书权限位：证书携带 principal/holder 和 u64 方法权限位；新增客户端或改权限不重启 signer
- 所有密钥操作写入审计日志
- 存储层抽象：SQLite（单机）/ PostgreSQL（集群）共用同一套 trait

## 架构

```mermaid
flowchart LR
    C[客户端] -->|gRPC| S[signer]
    S --> K[密钥服务]
    S --> U[解封协调器]
    U -->|份额| P1[份额持有者 1]
    U -->|份额| P2[份额持有者 2]
    U -->|份额| P3[份额持有者 3]
    K --> DB[(SQLite / PostgreSQL)]
    K -.->|未来| HSM[HSM / KMS]
```

更多细节：[docs/architecture.md](docs/architecture.md)

## 快速开始

前置：Rust 1.90+、Docker（运行测试时）。protoc 已由 `protoc-bin-vendored` 随构建提供。

先完成一次初始化仪式：

```bash
# 1. 每个份额持有者在桌面客户端生成身份，并导出 public bundle
#    （Ed25519 签名密钥 + X25519 加密密钥，口令加密保存在本机）

# 2. 收集 public bundle 到 holders.json
#    [{"holder_id":"holder-1","ed25519_public":"<hex>","x25519_public":"<hex>",
#      "self_signature":"<hex>","version":1}, ...]

# 3. 生成 operator 签名密钥（桌面端验证 manifest 时需要）
cargo run -p signer-admin -- operator-keygen --out operator.key --pub-out operator.pub

# 4. 生成 KEK、VSS 分片并加密导出 share 文件
cargo run -p signer-admin -- init --holders holders.json --operator-key operator.key

# 5. 准备配置并启动服务
cp signer.example.toml signer.toml   # 按需修改；signer.toml 已被 gitignore
cargo run -p signer-server -- --config signer.toml
```

`holders.json` 只接受桌面端导出的 holder public bundle（`holder_id`、`x25519_public`、`ed25519_public`、`self_signature`）；旧的 X25519-only 格式会导致 `init` 报错。提供 `--operator-key` 时，`init` 还会写出 `manifest.json`、`manifest.sig` 和 `operator.pub`，桌面端可据此验证份额来源。

VSS 解封使用 `kek_check.json` v3（包含 holder Ed25519 注册表）、manifest v2 和 vault v2；旧 v1/v2 文件和旧份额不兼容，需要重新执行 `init` 并重新分发。

服务端不再自动生成 KEK；缺少 `data/kek_check.json` 会报错并提示先执行 `signer-admin init`。生成的 `data/shares/*.share` 必须交给对应持有者，`data/` 不能提交到仓库。

服务端默认读取工作目录下的 `signer.toml`；可用 `--config <path>` 或 `SIGNER_CONFIG` 指定其他路径。配置示例见 [`signer.example.toml`](signer.example.toml)，实际 `signer.toml` 已被 gitignore。环境变量 `SIGNER_GRPC_ADDR`、`SIGNER_DATA_DIR`、`SIGNER_SESSION_TTL_SECS`、`SIGNER_DATABASE_URL` 会覆盖配置文件中的对应值；mTLS 证书可用 `SIGNER_TLS_CERT`、`SIGNER_TLS_KEY`、`SIGNER_TLS_CLIENT_CA` 覆盖，三项必须同时存在。未配置 `database.url` 时，默认使用 `$data_dir/signer.db`（SQLite）；`postgres://...` 则使用 PostgreSQL。连接池参数（`max_connections`、`min_connections`、`acquire_timeout_secs`、`idle_timeout_secs`、`max_lifetime_secs`）也在 `[database]` 中配置。

mTLS 与客户端证书权限位已实现：配置、证书 SAN URI 格式、u64 权限位和运维边界见 [docs/mtls.md](docs/mtls.md) 与 [ADR-0008](docs/adr/0008-mtls-client-cert-permissions.md)。证书签发支持 CSR 流程：endpoint 自己生成私钥和 CSR，CA 使用口令加密的私钥签名，并用审批值覆盖 CSR 请求的身份/权限（[ADR-0009](docs/adr/0009-csr-certificate-issuance.md)）。未配置 `[tls]` 时 gRPC 仍是明文，只能在本机或可信网络使用。

日志使用 `tracing`，默认 `info` 级别并输出源码文件和行号；可在 `signer.toml` 的 `[logging]` 中设置 `level` / `format` / `location`，或用 `RUST_LOG` 覆盖级别，例如 `RUST_LOG=signer_server=debug,sqlx=warn`。`[audit].sign_enabled` 控制是否记录每次 Sign 审计，默认 `true`；生产环境不应关闭。

本地 PostgreSQL 可以用仓库根目录的 compose 文件启动：

```bash
docker compose up -d --wait postgres
# signer.toml:
# [database]
# url = "postgres://signer:signer-dev-password@127.0.0.1:5432/signer?sslmode=disable"

docker compose down          # 停止容器，保留数据卷
docker compose down -v       # 删除数据卷，数据会丢失

# 连同 signer server 一起构建并启动
# 需要 signer.toml 和 data/kek_check.json
cp signer.example.toml signer.toml
docker compose --profile server up -d --build
```

compose 会把 `./signer.toml` 挂载到容器的 `/etc/signer/signer.toml`，并通过环境变量把监听地址、数据目录和数据库 URL 覆盖成容器内值。

compose 默认密码仅用于本地开发；生产环境请通过 `POSTGRES_PASSWORD` 覆盖，或改用外部 PostgreSQL。

### 桌面客户端

`desktop/` 下是 Tauri 可视化客户端，覆盖操作员和份额持有者的流程：

```bash
cd desktop/src-tauri
cargo run
```

默认连接 `http://127.0.0.1:50051`。界面顶部可在「操作员」和「份额持有者」之间切换；持有者 tab 内再分「密钥分发」和「Unseal」：前者生成身份、导出公开信息、导入并验证 `.share`、把份额加密保存为本地 vault，后者用身份文件 + vault 解锁，把份额加密到会话临时公钥并用 Ed25519 签名后提交。manifest 三项（`manifest.json`、`manifest.sig`、`operator.pub`）可选；不提供时按 legacy 方式导入并显示未验签警告。顶部「mTLS 证书」可配置 CA、客户端证书、客户端私钥和加密私钥口令；独立「申请证书」tab 可勾选权限并在本机生成客户端私钥 + CSR，之后可校验证书与私钥。未配置时使用明文，仅限本机或可信网络。

### 压测

`signer-loadtest` 可以在测试环境自动解封、创建测试密钥并并发调用 `Sign`：

```bash
SIGNER_LOADTEST_PASSPHRASE='test-passphrase' \
cargo run -p signer-loadtest -- \
  --holder alice.key,alice.share \
  --holder bob.key,bob.share \
  --concurrency 50 --duration-secs 30
```

详见 [docs/operations.md](docs/operations.md#压测)。不要使用真实 Holder 身份或生产数据库。

## 仓库结构

| 路径 | 说明 |
| --- | --- |
| `crates/proto` | `signer.v1` proto 与生成的 Rust 代码 |
| `crates/core` | 存储层、门限解封与 keystore |
| `crates/vss` | Ristretto255 Feldman VSS：份额生成、验证与恢复 |
| `crates/holder` | Holder 身份、manifest 验签、share vault 与份额导入 |
| `crates/share` | X25519 份额信封加密 |
| `crates/permissions` | 客户端证书权限位协议（server/CA/desktop 共用） |
| `crates/pki` | CSR、CA 与证书签发（rcgen + pkcs8） |
| `crates/admin` | KEK 初始化、份额分发与 mTLS CA/CSR 工具 |
| `crates/server` | gRPC 服务与二进制入口 |
| `crates/loadtest` | 自动解封、创建测试密钥并压测 Sign 的辅助程序 |
| `desktop` | Tauri 桌面解封客户端 |
| `migrations` | PostgreSQL / SQLite 迁移 |
| `proto` | protobuf 源文件 |
| `docs` | 设计与运维文档 |

## API

gRPC 定义见 [`proto/signer/v1/signer.proto`](proto/signer/v1/signer.proto)。解封相关方法与 EdDSA/ECDSA 的 `CreateKey`、`GetPublicKey`、`ListKeys`、`Sign` 已实现；`ImportKey` 仍返回 `UNIMPLEMENTED`。

| 方法 | 说明 |
| --- | --- |
| `CreateKey` / `ImportKey` | 生成新密钥 / 导入已有私钥 |
| `GetPublicKey` / `ListKeys` | 查询公钥与密钥元数据 |
| `Sign` | 使用指定密钥签名（需已解封） |
| `StartUnseal` / `SubmitUnsealShare` / `GetUnsealStatus` | 门限解封 |
| `Seal` | 重新封存，擦除内存中的密钥材料 |

健康检查使用标准 `grpc.health.v1.Health`，错误码约定见 proto 文件顶部注释。

## 安全

- 威胁模型：[docs/threat-model.md](docs/threat-model.md)
- 密钥生命周期：[docs/key-lifecycle.md](docs/key-lifecycle.md)
- 解封协议：[docs/unseal-protocol.md](docs/unseal-protocol.md)
- 漏洞报告：[SECURITY.md](SECURITY.md)

## 文档

| 文档 | 用途 |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | 组件、数据流、部署拓扑 |
| [docs/threat-model.md](docs/threat-model.md) | 资产、信任边界、非目标 |
| [docs/cryptography.md](docs/cryptography.md) | 密码学原语、协议原理与项目中的使用位置 |
| [docs/key-lifecycle.md](docs/key-lifecycle.md) | 密钥创建、轮换、备份、销毁 |
| [docs/unseal-protocol.md](docs/unseal-protocol.md) | 门限解封协议 |
| [docs/vss-unseal.md](docs/vss-unseal.md) | VSS 增强解封方案与实现说明 |
| [docs/adr/0007-vss-feldman-ristretto255.md](docs/adr/0007-vss-feldman-ristretto255.md) | ADR-0007：Ristretto255 Feldman VSS |
| [docs/adr/0008-mtls-client-cert-permissions.md](docs/adr/0008-mtls-client-cert-permissions.md) | ADR-0008：mTLS 与客户端证书权限位 |
| [docs/adr/0009-csr-certificate-issuance.md](docs/adr/0009-csr-certificate-issuance.md) | ADR-0009：CSR 驱动的证书签发 |
| [docs/storage.md](docs/storage.md) | 存储 trait、表结构、HA |
| [docs/operations.md](docs/operations.md) | 配置、可观测性、运维手册 |
| [desktop/README.md](desktop/README.md) | Tauri 桌面客户端 |
| [docs/adr/](docs/adr/) | 架构决策记录 |
| [ROADMAP.md](ROADMAP.md) | 里程碑计划 |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更记录 |

## 许可证

[Apache-2.0](LICENSE)

## 免责声明

本项目为学习与作品集用途的实现，未经安全审计，不得用于保护真实资产。
