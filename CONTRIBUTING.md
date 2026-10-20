# 贡献指南

## 开发环境

- Rust 1.85+（edition 2024）
- 提交前运行：`cargo fmt`、`cargo clippy --all-targets -- -D warnings`、`cargo test`

```bash
git clone https://github.com/solitarybluga/signer.git
cd signer
cargo test
```

存储测试会通过 testcontainers 自动启动 PostgreSQL 容器，需要本机 Docker 可用。

## Pull Request

- 改动保持聚焦；重构与行为变更分开提交。
- 新行为必须附带测试；安全相关路径必须覆盖异常用例。
- 设计变更时同步更新 `docs/` 下对应文档。
- 不得包含秘密、真实密钥、生产端点或客户数据。

## 提交信息

建议使用 Conventional Commits：

```text
feat(keystore): 使用 XChaCha20-Poly1305 加密密钥
fix(unseal): 拒绝重放的份额
docs(threat-model): 明确阈值信任边界
```

## 安全相关改动

涉及密钥生成、加密、解封或签名的改动，必须做威胁模型评审，并引用
[docs/threat-model.md](docs/threat-model.md) 中的对应章节。

## 许可

提交贡献即表示你同意以 Apache-2.0 许可发布你的贡献。
