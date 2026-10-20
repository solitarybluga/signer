# 运维

> 状态：草稿。首个可部署版本落地后补全。

## 配置

所有配置通过环境变量提供；秘密绝不落盘为明文。

| 变量 | 说明 | 必填 |
| --- | --- | --- |
| `SIGNER_BIND` | gRPC 监听地址 | 是 |
| `SIGNER_STORAGE_URL` | SQLite 路径或 PostgreSQL URL | 是 |
| `SIGNER_TLS_CERT` / `SIGNER_TLS_KEY` | 服务端证书（计划支持 mTLS） | TODO |
| `SIGNER_UNSEAL_THRESHOLD` | 所需份额数 | 是 |
| `SIGNER_LOG_LEVEL` | 默认 `info`；生产环境禁止 `debug` | 否 |

TODO：补充 `.env.example`，启动时校验所有配置。

## 部署

### 单机

1. 以 sealed 状态启动 signer。
2. 与份额持有者完成解封仪式。
3. 验证 `GetPublicKey` 与一次测试签名。

### 高可用

1. 准备带同步复制的 PostgreSQL。
2. 在负载均衡后启动 N 个 signer 实例。
3. 对每个实例执行解封，或设计受控的启动自动解封策略。
4. 确认审计日志记录了每个实例的解封会话。

## 可观测性

### 指标

- `signer_unsealed`（gauge）
- `unseal_sessions_total{state}`
- `sign_requests_total{curve,algorithm,result}`
- `sign_latency_seconds`（histogram）
- `storage_errors_total`

### 日志

- 结构化 JSON；绝不记录载荷、份额、密钥、密文或 token。
- 脱敏 `authorization` 头，以及任何匹配 `secret|key|share` 的字段。
- 用 `session_id`、`key_id` 关联问题；绝不包含密钥材料。

### 链路追踪

- 追踪解封会话与签名请求；控制采样率以控制成本。
- span 属性遵循与日志相同的脱敏规则。

## 运维手册

### 解封失败

1. 检查接受了多少份额，以及每个份额被拒绝的原因。
2. 验证份额持有者身份与会话 nonce。
3. 确认数据库密文未被篡改。
4. 不得降低阈值或绕过流程重试。

### 份额丢失

1. 确认剩余份额是否仍满足阈值。
2. 若不满足，按既定应急流程处理（v0.1 不在范围内）。
3. 恢复后轮换份额。

### 疑似被攻破

1. 封存服务，停止接受签名。
2. 保留日志与审计记录。
3. 轮换密钥与份额。
4. 按 [SECURITY.md](../SECURITY.md) 的流程披露。

### 密钥轮换

1. 创建新密钥并标记为活跃。
2. 迁移客户端；旧公钥保留用于验签。
3. 保留期结束后销毁旧密钥。

## 备份与恢复

- 备份密文与审计数据；KEK 和份额绝不与备份放在一起。
- 在预发环境演练恢复；记录 RPO/RTO。
- TODO：补充保留策略与异地副本策略。

## 待决问题

- [ ] 每次进程启动都必须解封，还是允许仅内存缓存？
- [ ] 连续解封失败多少次触发告警？
- [ ] 迁移期间是否需要只读维护模式？
