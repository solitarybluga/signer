# 路线图

## v0.1 — 单签 + 门限解封

- [x] edwards25519 + EdDSA 密钥生成
- [ ] secp256k1 + ECDSA 密钥生成
- [ ] 导入已有私钥（secp256k1 标量 / edwards25519 种子）
- [x] Ed25519 每密钥 DEK + KEK 信封加密（XChaCha20-Poly1305）
- [ ] secp256k1 DEK/KEK 信封加密
- [x] KEK 生成与加密 share 文件分发（signer-admin）
- [x] Ristretto255 Feldman VSS 分片、逐份校验与 KEK 校验
- [x] 解封会话、份额收集与 KEK 恢复（核心）
- [x] 持有者 Ed25519 签名、会话 nonce 绑定、每会话 X25519 份额加密与 VSS 校验
- [ ] gRPC TLS/mTLS 与服务端认证
- [x] 通过 gRPC 接入解封流程（`StartUnseal` / `SubmitUnsealShare` / `GetUnsealStatus` / `Seal`）
- [x] EdDSA gRPC 接口：`CreateKey`、`GetPublicKey`、`ListKeys`、`Sign`
- [ ] ECDSA 与 `ImportKey`
- [x] CreateKey / Sign 审计日志（其余操作待补）
- [x] SQLite 存储后端
- [ ] 基于 anvil 与 Solana 测试验证器的集成测试

## v0.2 — 生产化加固

- [x] PostgreSQL 存储后端
- [ ] signer 与份额持有者之间的 mTLS
- [ ] 份额轮换与重新分发
- [ ] 按密钥粒度的鉴权与限流
- [ ] 监控指标与链路追踪
- [ ] 备份 / 恢复运维手册

## v0.3 — 真正的门限签名

- [ ] Ed25519 的 FROST 门限签名（Solana）
- [ ] secp256k1 的 CGGMP21 门限 ECDSA（EVM）
- [ ] 跨独立 signer 实例的签名会话协调
- [ ] 每个 signer 的 per-share 解封与独立运维密钥（ADR-0006）
- [ ] 从签名路径中移除明文私钥重组

## v1.0 — 稳定版

- [ ] 外部安全审计
- [ ] 稳定的 API 与存储 schema 承诺
- [ ] 发布威胁模型与运维指南
