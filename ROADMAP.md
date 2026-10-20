# 路线图

## v0.1 — 单签 + 门限解封

- [ ] secp256k1 + ECDSA 与 edwards25519 + EdDSA 密钥生成
- [ ] 导入已有私钥（secp256k1 标量 / edwards25519 种子）
- [ ] 每密钥 DEK + KEK 信封加密（XChaCha20-Poly1305）
- [x] Shamir 分片与 KEK 校验
- [x] 解封会话、份额收集与 KEK 恢复（核心）
- [ ] 份额传输加密、持有者签名与 VSS 校验
- [ ] 通过 gRPC 接入启动解封流程
- [ ] gRPC 接口：`CreateKey`、`GetPublicKey`、`ListKeys`、`Sign`、`StartUnseal`、`SubmitUnsealShare`、`GetUnsealStatus`、`Seal`
- [ ] 审计日志
- [ ] SQLite 存储后端
- [ ] 基于 anvil 与 Solana 测试验证器的集成测试

## v0.2 — 生产化加固

- [ ] PostgreSQL 存储后端
- [ ] signer 与份额持有者之间的 mTLS
- [ ] 份额轮换与重新分发
- [ ] 按密钥粒度的鉴权与限流
- [ ] 监控指标与链路追踪
- [ ] 备份 / 恢复运维手册

## v0.3 — 真正的门限签名

- [ ] Ed25519 的 FROST 门限签名（Solana）
- [ ] secp256k1 的 CGGMP21 门限 ECDSA（EVM）
- [ ] 跨独立 signer 实例的签名会话协调
- [ ] 从签名路径中移除明文私钥重组

## v1.0 — 稳定版

- [ ] 外部安全审计
- [ ] 稳定的 API 与存储 schema 承诺
- [ ] 发布威胁模型与运维指南
