# 变更记录

本文件记录项目的所有重要变更。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增

- 项目初始骨架。
- 文档骨架：架构、威胁模型、密钥生命周期、解封协议、存储、运维、ADR。
- 采用每密钥独立 DEK、KEK 信封包裹的加密方案（ADR-0003）。
- 新增 `ImportKey` 接口，支持导入已有私钥。
- 新增 ADR-0004：使用 sqlx 作为数据库访问层。
- 新增存储模型、`KeyStore` trait 与 PostgreSQL/SQLite 初始迁移。
- 实现 `PostgresStore` 与 `SqliteStore`，补充存储测试；PostgreSQL 测试通过 testcontainers 自动启动容器。
- 新增 GitHub Actions CI（fmt、clippy、test）。
- 实现门限解封核心：Shamir 分片、解封会话、KEK 校验与重新封存。
- 新增 `signer-vss`：Ristretto255 Feldman VSS 的份额生成、承诺、逐份验证与恢复。
- 解封核心切换到 VSS：`kek_check.json` 保存承诺与 holder/index 注册表（v2，后续升至 v3）；服务端逐份校验后才计数，坏份额不再烧会话。
- Holder 导入时用 manifest 中的 VSS 承诺校验份额；vault v2 记录 `vss_verified` 和 scheme。
- `SubmitUnsealShare` 增加 `share_index` 字段；桌面端从 vault 提交时显式携带索引。
- 新增 ADR-0007：使用 Ristretto255 Feldman VSS。
- 新增 ADR-0008：mTLS + 客户端证书权限位掩码；新增 `docs/mtls.md` 设计与运维文档。
- 实现 gRPC mTLS：服务端 `[tls]` 配置、客户端证书 principal/holder/u64 权限位解析、逐 RPC 权限检查、holder 绑定，以及 CreateKey/Sign 的证书 actor 审计。
- `signer-loadtest` 与 Tauri 桌面端接入 mTLS；新增 `scripts/gen-mtls.sh` / `gen-mtls.ps1` 和静态测试证书。
- `signer.example.toml` 增加 `[tls]` 配置示例；默认仍为明文本地开发模式。
- 将解封接口接入 gRPC（StartUnseal / SubmitUnsealShare / GetUnsealStatus / Seal），新增服务启动流程与数据目录初始化。
- 新增 Tauri 桌面解封客户端（`desktop/`）：发起会话、提交份额、进度展示与重新封存。
- 新增 `signer-admin`：X25519 持有者密钥生成、KEK 初始化、加密份额导出。
- 服务端改为读取 `signer-admin` 生成的 KEK 校验文件，不再自动生成份额。
- 桌面客户端支持用持有者私钥解密 `.share` 后提交。
- 新增 ADR-0005：v0.1 不用 KMS 托管 KEK，保留门限信任模型。
- 新增 ADR-0006：门限签名采用 per-share 解封，每个 signer 的运维独立。
- 新增 `signer-holder`：Holder 身份（Ed25519 + X25519）、口令加解密、manifest 验签、share vault 与份额导入。
- 桌面端集成 Holder 操作：生成身份、导出公开信息、导入/验证 `.share`、加密保存 vault、从 vault 提交解封。
- `signer-admin` 新增 `operator-keygen`，`init` 支持 `--operator-key` 输出签名的 `manifest.json` / `manifest.sig` / `operator.pub`。
- `signer-admin init` 的 `holders.json` 兼容桌面端导出的 holder public bundle，并校验 self-signature。
- 桌面端使用原生文件对话框选择身份、份额和 vault 路径，避免密钥字节经过 JS。
- 新增 `docs/vss-unseal.md`：VSS 解封方案与实现说明。
- 新增 `docs/adr/0007-vss-feldman-ristretto255.md`：VSS 方案决策记录。
- 新增 `docs/cryptography.md`：按技术整理项目使用、历史使用、计划和评估过的密码学原语，说明原理与代码位置。
- 实现安全的在线份额提交：每会话临时 X25519 密钥、绑定会话上下文的 v2 信封、Holder Ed25519 签名；服务端验签、解密并通过 VSS 校验后才计数。
- `kek_check.json` 升级到 v3，注册每个 holder 的 Ed25519 公钥；`SubmitUnsealShareRequest` 新增 `nonce`，原 `share` 改为 `encrypted_share`；状态接口返回 `nonce` 和 `session_public_key`。
- 桌面端 Unseal 流程要求身份文件 + vault，提交前在本地加密份额并签名。
- 新增 Ed25519/secp256k1 keystore：`CreateKey` / `GetPublicKey` / `ListKeys` / `Sign`；每密钥独立 DEK，私钥用 DEK 加密、DEK 用 KEK 包裹，AAD 绑定 key_id/curve/algorithm/public_key。
- 新增 secp256k1 + ECDSA：RFC 6979 确定性 nonce、low-s 规范化、33 字节压缩公钥和 65 字节 `r || s || v` 签名。
- 新增 `signer-loadtest`：自动解封、创建测试密钥并并发调用 `Sign`，输出 QPS 和 p50/p95/p99/p999 延迟。
- 服务端接入 SQLite/PostgreSQL 存储：默认 `$data_dir/signer.db`，可通过 `database.url` 或 `SIGNER_DATABASE_URL` 切换 PostgreSQL。
- 服务端新增 `signer.toml` 配置文件（`signer.example.toml` 示例），支持 `--config` / `SIGNER_CONFIG`；环境变量仍可覆盖文件值。`signer.toml` 已加入 gitignore。
- 数据库配置新增连接池参数：`max_connections`、`min_connections`、`acquire_timeout_secs`、`idle_timeout_secs`、`max_lifetime_secs` 和 SQLite 专用的 `sqlite_busy_timeout_secs`。
- 新增 `docker-compose.yml`：本地 PostgreSQL 16，绑定 `127.0.0.1:5432`，带健康检查和持久化数据卷。
- 新增 server 多阶段 `Dockerfile`、`.dockerignore` 和 `docker/signer.toml`：非 root 运行，数据目录 `/var/lib/signer/data`，支持挂载配置和数据库 URL。
- compose 的 `signer` 服务通过 Compose configs 挂载 `./signer.toml`，并用环境变量覆盖容器内监听地址、数据目录和数据库 URL。
- 接入 `tracing` 结构化日志：`[logging]` 支持 `level`、`format`（text/json）和 `location`（源码文件/行号），`RUST_LOG` 可覆盖级别；记录启动、密钥、签名和解封事件，不记录载荷或密钥材料。
- `CreateKey` 在 v0.1 直接创建为 `ACTIVE`；`ImportKey` 仍返回 `UNIMPLEMENTED`。
- `CreateKey` / `Sign` 写入 `audit_log`：记录 actor、action、key_id、结果和 curve/algorithm；Sign 额外记录 `request_id` 和 `payload_len`，失败尝试记录 denied/error，不记录载荷内容或密钥材料。CreateKey 的密钥插入与审计在同一事务中提交，审计失败会回滚密钥；Sign 在审计提交成功后才返回签名。
- 新增 `[audit].sign_enabled` 配置项（默认 `true`），允许受控压测时关闭 Sign 审计；关闭时启动日志会给出警告，CreateKey 审计不受影响。
- keystore 增加内存缓存，缓存只包含加密后的 `KeyRecord`（密文、nonce、wrapped DEK），Sign 命中后不再查询数据库；容量上限 1024。

### 变更

- 完善 README 进度说明与安全报告渠道。
- 重构为 Cargo workspace：`signer-proto`、`signer-core`、`signer-server` 与桌面端共享依赖和锁文件。
- 桌面端界面拆分为「操作员」和「份额持有者」两个 tab；份额持有者内部再分为「密钥分发」和「Unseal」两个子 tab，事件日志常驻底部。
- 解封数据格式升级到 v3（`kek_check.json`）；manifest/vault 保持 v2。旧 v1/v2 文件与旧份额不兼容，需要重新执行 `init` 并重新分发。
- `kek_check.json` 的 nonce/ciphertext 改为 hex 字符串，便于人工检查。
- `holders.json` 只接受桌面端导出的 public bundle；旧 X25519-only 格式会被拒绝。
- 移除 `signer-admin holder-keygen` 和桌面端明文 `submit_share` 命令；身份统一由桌面端生成。

### 安全

- VSS 在分发和提交阶段校验份额一致性；服务端拒绝无效份额并保持会话 `Collecting`。
- 服务端在计数前校验会话 nonce、Holder Ed25519 签名，解密会话密文并通过 VSS 校验；密文、签名和上下文绑定 session/holder/index，不能跨会话重放。
- gRPC 仍未启用 TLS/服务端认证，只能部署在本机或可信网络。

## [0.1.0] — YYYY-MM-DD

### 新增

- TODO：首个版本内容。

<!--
可用分类：新增（Added）、变更（Changed）、弃用（Deprecated）、移除（Removed）、修复（Fixed）、安全（Security）。
-->
