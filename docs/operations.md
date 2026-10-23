# 运维

> 状态：草稿。首个可部署版本落地后补全。

## 配置

服务端以 `signer.toml` 为主配置，示例见 [`signer.example.toml`](../signer.example.toml)。实际 `signer.toml` 已被 gitignore，避免把数据库密码等敏感配置提交到仓库。

加载优先级：

1. `--config <path>`
2. `SIGNER_CONFIG`
3. 工作目录下的 `signer.toml`
4. 内置默认值

文件解析后，环境变量会覆盖对应字段，便于容器和 CI 注入部署值或秘密。

| TOML 配置 | 环境变量覆盖 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `server.grpc_addr` | `SIGNER_GRPC_ADDR` | `127.0.0.1:50051` | gRPC 监听地址 |
| `server.data_dir` | `SIGNER_DATA_DIR` | `data` | `kek_check.json` 与默认 SQLite 数据库目录 |
| `server.session_ttl_secs` | `SIGNER_SESSION_TTL_SECS` | `600` | 解封会话有效期（秒） |
| `database.url` | `SIGNER_DATABASE_URL` | 未设置 | SQLite URL 或 PostgreSQL URL；未设置时使用 `$data_dir/signer.db` |
| `database.max_connections` | — | PostgreSQL `10` / SQLite `1` | 连接池上限；SQLite 建议保持 1 |
| `database.min_connections` | — | `0` | 连接池保底连接数 |
| `database.acquire_timeout_secs` | — | `5` | 获取连接的超时 |
| `database.idle_timeout_secs` | — | `600` | 空闲连接回收时间；`0` 禁用 |
| `database.max_lifetime_secs` | — | `1800` | 连接最大存活时间；`0` 禁用 |
| `database.sqlite_busy_timeout_secs` | — | `5` | SQLite 忙等待超时；PostgreSQL 忽略 |
| `audit.sign_enabled` | — | `true` | 是否为每次 Sign 写入审计；关闭仅用于受控压测 |
| `logging.level` | `RUST_LOG` | `info` | tracing 过滤级别；`RUST_LOG` 优先 |
| `logging.format` | — | `text` | `text` 或 `json` |
| `logging.location` | — | `true` | 是否输出源码文件和行号 |

`server.data_dir` 的相对路径按进程工作目录解析，不按配置文件所在目录解析。

示例：

```toml
[server]
grpc_addr = "127.0.0.1:50051"
data_dir = "data"
session_ttl_secs = 600

[database]
# url = "sqlite://data/signer.db"
# url = "postgres://signer:change-me@127.0.0.1:5432/signer"
# max_connections = 10
# min_connections = 0
# acquire_timeout_secs = 5
# idle_timeout_secs = 600
# max_lifetime_secs = 1800
# sqlite_busy_timeout_secs = 5

[audit]
# Production should keep this enabled.
sign_enabled = true

[logging]
level = "info"
format = "text"
location = true
```

### mTLS（已实现）

mTLS 和客户端证书权限位的完整设计见 [mtls.md](mtls.md)、[ADR-0008](adr/0008-mtls-client-cert-permissions.md) 与 [ADR-0009](adr/0009-csr-certificate-issuance.md)。配置：

| TOML 配置 | 环境变量覆盖 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `tls.cert_path` | `SIGNER_TLS_CERT` | 未设置 | 服务端证书链 PEM；设置 `[tls]` 后必填 |
| `tls.key_path` | `SIGNER_TLS_KEY` | 未设置 | 服务端私钥 PEM；设置 `[tls]` 后必填 |
| `tls.client_ca_path` | `SIGNER_TLS_CLIENT_CA` | 未设置 | 客户端 CA bundle；mTLS 必填 |
| `tls.principal_uri_prefix` | — | `signer://principal/` | 证书 principal SAN URI 前缀 |
| `tls.holder_uri_prefix` | — | `signer://holder/` | 证书 holder SAN URI 前缀 |
| `tls.permission_uri_prefix` | — | `signer://permissions/` | u64 权限位掩码 SAN URI 前缀 |

- 三个证书路径必须同时配置；`SIGNER_TLS_*` 三件套也必须同时出现。
- `[tls]` 缺失时保持明文模式，启动日志会 warn；生产必须显式启用。
- 客户端证书携带 `principal`、可选 `holder` 和 u64 权限位掩码；没有本地授权策略文件，也没有热加载。
- 未配置 `[tls]` 时保持明文模式，启动日志会 warn；生产必须显式启用。
- 推荐用 CSR 流程签发：endpoint 执行 `signer-admin tls-csr` 生成自己的 key+CSR，CA 执行 `tls-sign-csr` 并用审批值覆盖请求字段；CA key 用 `SIGNER_CA_PASSPHRASE` 保护的 `ca.key.enc`，只能放在离线 CA 主机/HSM，不能放到 signer 主机。
- 客户端加密私钥可用 `SIGNER_TLS_KEY_PASSPHRASE`（loadtest）或桌面端口令输入框解密；服务端 `tls.key_path` 目前仍要求明文 PEM（0600）。
- 镜像支持 TLS/mTLS，但默认关闭；启用后证书应以只读方式挂载，并确保容器运行用户可读。

`signer.toml` 可能包含数据库密码，建议权限设为 `0600`，不要把真实配置提交到仓库。

## 本地 PostgreSQL

仓库根目录的 `docker-compose.yml` 提供一个仅监听 `127.0.0.1:5432` 的 PostgreSQL 16 实例：

```bash
docker compose up -d --wait postgres
```

对应的 `signer.toml`：

```toml
[database]
url = "postgres://signer:signer-dev-password@127.0.0.1:5432/signer?sslmode=disable"
```

- 默认密码 `signer-dev-password` 只用于本地开发；可用 `POSTGRES_PASSWORD` 覆盖。
- 数据保存在命名卷 `signer_signer-postgres-data`。
- `docker compose down` 保留数据卷；`docker compose down -v` 会删除数据。
- 容器内已经使用 `pg_isready` 健康检查，`docker compose up --wait` 会等到数据库可用。
- 本地 compose 未启用 TLS，因此连接串使用 `sslmode=disable`；生产环境应使用 `require` 或 `verify-full`。

## Docker 镜像

仓库根目录的 `Dockerfile` 使用多阶段构建：`rust:1.90-bookworm` 编译，`debian:bookworm-slim` 运行。最终镜像以非 root 的 `signer` 用户运行，默认配置在 `/etc/signer/signer.toml`，数据目录是 `/var/lib/signer/data`。

构建：

```bash
docker build -t signer-server:local .
```

如果 Docker Hub 无法访问，可以用可信的 registry mirror 替换基础镜像。把 `REGISTRY` 换成实际可访问的镜像仓库地址：

```bash
REGISTRY=your-registry.example.com
docker build \
  --build-arg RUST_IMAGE="$REGISTRY/library/rust:1.90-bookworm" \
  --build-arg RUNTIME_IMAGE="$REGISTRY/library/debian:bookworm-slim" \
  -t signer-server:local .
```

不要把 `your-registry.example.com` 原样执行；它只是占位符。

运行时必须提供 `kek_check.json`。最简单的方式是把宿主机初始化好的 `data/` 挂载进去：

```bash
docker run --rm \
  -p 127.0.0.1:50051:50051 \
  -v "$PWD/data:/var/lib/signer/data" \
  -e SIGNER_DATABASE_URL='postgres://signer:signer-dev-password@host.docker.internal:5432/signer?sslmode=disable' \
  signer-server:local
```

仓库的 `docker-compose.yml` 还提供了一个 `signer` 服务，放在 `server` profile 下，避免只启动 PostgreSQL 时意外构建镜像：

```bash
cp signer.example.toml signer.toml
# 确保 data/kek_check.json 已由 signer-admin init 生成
docker compose --profile server up -d --build
docker compose --profile server logs -f signer
```

该服务会：

- 通过 Compose configs 把宿主机的 `./signer.toml` 挂载到 `/etc/signer/signer.toml`；
- 用环境变量覆盖容器内的监听地址、数据目录和数据库 URL；
- 自动连接 compose 内的 `postgres` 服务；
- 把宿主机的 `./data` 挂载到 `/var/lib/signer/data`。

`signer.toml` 必须存在；如果使用示例配置，容器内会通过环境变量覆盖 `127.0.0.1` 和相对路径。

说明：

- 镜像不包含 `kek_check.json`、份额或数据库密码；这些都应通过挂载或环境变量提供。
- `docker/signer.toml` 是镜像内默认配置，可以用 `-v /path/signer.toml:/etc/signer/signer.toml:ro` 覆盖。
- 容器内服务监听 `0.0.0.0:50051`；宿主机只映射到 `127.0.0.1`，不要直接暴露到公网。
- 使用 bind mount 时，宿主机 `data/` 需要允许 UID 10001 读取；SQLite 模式还需要写权限。
- `docker run --rm` 不会保留容器内未挂载的数据；生产环境应使用持久卷。
- 镜像默认不启用 TLS/mTLS；生产建议启用 mTLS，并把证书以只读方式挂载；配置与证书挂载方式见 [mtls.md](mtls.md)。

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

## 压测

`signer-loadtest` 是测试辅助程序，会自动解封、创建测试密钥并并发调用 `Sign`。它只应连接隔离环境，使用测试 Holder 身份和份额。

```bash
SIGNER_LOADTEST_PASSPHRASE='test-passphrase' \
cargo run -p signer-loadtest -- \
  --server http://127.0.0.1:50051 \
  --holder alice.key,alice.share \
  --holder bob.key,bob.share \
  --eddsa 10 \
  --ecdsa 10 \
  --concurrency 50 \
  --duration-secs 30
```

启用 mTLS 时使用 `https://`，并同时提供 CA、客户端证书和客户端私钥；压测证书需要 `unseal.start/submit/status`、`key.create/read/sign` 权限位，并在 `holder/*` 中列出所有测试 holder。客户端私钥可以是加密 PKCS#8，设置 `SIGNER_TLS_KEY_PASSPHRASE` 由 loadtest 本地解密：

```bash
SIGNER_LOADTEST_PASSPHRASE='test-passphrase' \
cargo run -p signer-loadtest -- \
  --server https://127.0.0.1:50051 \
  --ca-cert data/tls/ca.crt \
  --client-cert data/tls/loadtest.crt \
  --client-key data/tls/loadtest.key \
  --holder alice.key,alice.share \
  --holder bob.key,bob.share \
  --eddsa 10 --ecdsa 10 \
  --concurrency 50 --duration-secs 30
```

服务已解封时可以跳过解封：

```bash
cargo run -p signer-loadtest -- \
  --skip-unseal \
  --eddsa 1 --ecdsa 1 \
  --concurrency 50 --duration-secs 30
```

参数：

- `--holder KEY,SHARE`：Holder 身份文件和 `.share` 文件；可重复。
- `--skip-unseal`：要求服务已处于 unsealed。
- `--eddsa` / `--ecdsa`：创建的测试密钥数量。
- `--concurrency`：并发 `Sign` worker 数。
- `--duration-secs`：最长压测时间。
- `--requests`：可选总请求数，和 duration 同时生效。
- `--ca-cert` / `--client-cert` / `--client-key`：mTLS 三件套，必须同时提供。
- `--tls-domain`：证书 SAN 与连接地址不一致时的服务端名称覆盖。
- `--client-key-passphrase-env`：加密客户端私钥的口令环境变量，默认 `SIGNER_TLS_KEY_PASSPHRASE`。

程序输出 QPS、错误数和 p50/p95/p99/p999 延迟（微秒）。测试结束不会自动 `Seal`，需要手动封存或重置测试环境。

注意：

- 所有 Holder 身份使用 `SIGNER_LOADTEST_PASSPHRASE`，只适用于测试环境。
- 每次运行会创建新密钥，建议使用专用测试数据库并定期清理。
- ECDSA 的 payload 固定为 32 字节摘要；Ed25519 使用相同字节也可以。
- 不要使用真实 Holder 身份、真实份额或生产数据库。

## 可观测性

### 指标

- `signer_unsealed`（gauge）
- `unseal_sessions_total{state}`
- `sign_requests_total{curve,algorithm,result}`
- `sign_latency_seconds`（histogram）
- `storage_errors_total`

### 日志

当前使用 `tracing` + `tracing-subscriber`，默认输出到 stdout/stderr，Docker 可通过 `docker compose logs` 查看。

- `[logging].level` 控制默认过滤级别，未设置 `RUST_LOG` 时生效；
- `RUST_LOG` 可以覆盖配置文件，例如 `RUST_LOG=signer_server=debug,sqlx=warn`；
- `[logging].format = "json"` 输出结构化 JSON，适合日志采集；
- `[logging].location = true` 会输出事件所在源码文件和行号；JSON 格式中对应 `file` / `line` 字段；
- 默认 `info` 记录启动、解封会话、份额提交结果、密钥创建和签名结果；
- `debug` 额外记录 GetPublicKey、ListKeys 和份额提交细节；
- 记录字段包括 `key_id`、`session_id`、holder id、share index、状态和计数；
- 绝不记录载荷、份额、nonce、密文、签名、私钥、KEK、DEK、数据库密码或 token。

目前是基础 tracing 事件，尚未接入 OpenTelemetry/分布式链路追踪。若后续接入，span 属性必须遵循同样的脱敏规则。

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
