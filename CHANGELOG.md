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
- 将解封接口接入 gRPC（StartUnseal / SubmitUnsealShare / GetUnsealStatus / Seal），新增服务启动流程与数据目录初始化。

### 变更

- 完善 README 进度说明与安全报告渠道。

### 安全

- 暂无。

## [0.1.0] — YYYY-MM-DD

### 新增

- TODO：首个版本内容。

<!--
可用分类：新增（Added）、变更（Changed）、弃用（Deprecated）、移除（Removed）、修复（Fixed）、安全（Security）。
-->
