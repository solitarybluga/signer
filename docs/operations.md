# 运维

> 状态：草稿。首个可部署版本落地后补全。

## 配置

所有配置通过环境变量提供；秘密绝不落盘为明文。

| 变量 | 说明 | 必填 |
| --- | --- | --- |
| `SIGNER_GRPC_ADDR` | gRPC 监听地址，默认 `127.0.0.1:50051` | 否 |
| `SIGNER_DATA_DIR` | KEK 校验文件目录，默认 `./data` | 否 |
| `SIGNER_SESSION_TTL_SECS` | 解封会话有效期（秒），默认 `600` | 否 |
| `SIGNER_STORAGE_URL` | SQLite 路径或 PostgreSQL URL（待接入） | TODO |
| `SIGNER_TLS_CERT` / `SIGNER_TLS_KEY` | 服务端证书（计划支持 mTLS） | TODO |
| `SIGNER_LOG_LEVEL` | 日志级别（待接入） | 否 |

TODO：补充 `.env.example`，启动时校验所有配置。

解封阈值和份额总数由 `signer-admin init` 写入 `kek_check.json`，服务端不再从环境变量读取，避免两边配置漂移。

## 初始化仪式

服务端只读取初始化结果，不会自动生成 KEK。

1. 每个份额持有者在自己的机器上用桌面客户端生成身份（Ed25519 签名密钥 + X25519 加密密钥），并导出 public bundle。身份文件用口令加密，留在持有者本机。

2. 操作员把各持有者的 public bundle 汇总为 `holders.json`：

   ```json
   [
     {
       "holder_id": "holder-1",
       "ed25519_public": "<hex>",
       "x25519_public": "<hex>",
       "self_signature": "<hex>",
       "version": 1
     },
     {
       "holder_id": "holder-2",
       "ed25519_public": "<hex>",
       "x25519_public": "<hex>",
       "self_signature": "<hex>",
       "version": 1
     }
   ]
   ```

   条目数量必须等于 `total_shares`。旧的 X25519-only 格式会被拒绝。

3. 生成 operator 签名密钥（离线保管私钥），然后生成 KEK、VSS 分片并导出加密份额：

   ```bash
   cargo run -p signer-admin -- operator-keygen --out operator.key --pub-out operator.pub
   cargo run -p signer-admin -- init --threshold 3 --total-shares 5 \
     --holders holders.json --operator-key operator.key
   ```

   输出 `data/kek_check.json` v3、`data/shares/<holder-id>.share`，以及 `manifest.json` / `manifest.sig` / `operator.pub`。每个 `.share` 都用对应持有者的 X25519 公钥加密。

4. 通过离线或安全渠道把每个 `.share` 和签名 manifest 发给对应持有者；不要和 KEK 校验文件、持有者私钥放在同一处。

5. 启动 signer。缺少 `kek_check.json` 会拒绝启动。

已有初始化时 `init` 默认拒绝覆盖；`--force` 会删除旧 shares 目录并重新生成，旧份额随即失效。

## 部署

### 单机

1. 完成初始化仪式，生成 KEK 校验文件和加密份额。
2. 以 sealed 状态启动 signer。
3. 与份额持有者完成解封仪式。
4. 验证 `GetPublicKey` 与一次测试签名。

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
