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
- 解封核心切换到 VSS：`kek_check.json` v2 保存承诺与 holder/index 注册表；服务端逐份校验后才计数，坏份额不再烧会话。
- Holder 导入时用 manifest 中的 VSS 承诺校验份额；vault v2 记录 `vss_verified` 和 scheme。
- `SubmitUnsealShare` 增加 `share_index` 字段；桌面端从 vault 提交时显式携带索引。
- 新增 ADR-0007：使用 Ristretto255 Feldman VSS。
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

### 变更

- 完善 README 进度说明与安全报告渠道。
- 重构为 Cargo workspace：`signer-proto`、`signer-core`、`signer-server` 与桌面端共享依赖和锁文件。
- 桌面端界面拆分为「操作员」和「份额持有者」两个 tab；份额持有者内部再分为「密钥分发」和「Unseal」两个子 tab，事件日志常驻底部。
- 解封数据格式升级到 v2（`kek_check.json`、manifest、vault）；旧 v1 文件与旧份额不兼容，需要重新执行 `init` 并重新分发。
- `kek_check.json` 的 nonce/ciphertext 改为 hex 字符串，便于人工检查。

### 安全

- VSS 在分发和提交阶段校验份额一致性；服务端拒绝无效份额并保持会话 `Collecting`。
- 仍未实现持有者签名、session nonce 绑定和 gRPC 份额传输加密。

## [0.1.0] — YYYY-MM-DD

### 新增

- TODO：首个版本内容。

<!--
可用分类：新增（Added）、变更（Changed）、弃用（Deprecated）、移除（Removed）、修复（Fixed）、安全（Security）。
-->
