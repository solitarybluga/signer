# 解封流程的 VSS 改造方案

> 状态：已实现（v0.1）。实现位于 `crates/vss`，采用基于 `curve25519-dalek` 的 Ristretto255 Feldman VSS；决策记录见 [ADR-0007](adr/0007-vss-feldman-ristretto255.md)。
>
> 相关文档：[解封协议](unseal-protocol.md)、[威胁模型](threat-model.md)、[ADR-0002](adr/0002-unseal-vs-threshold.md)、[ADR-0006](adr/0006-per-share-unsealing.md)。

## 1. 背景

v0.1 的 KEK 使用 Shamir 秘密分享拆分给多个持有者。当前实现基于 `sharks` crate，工作在 GF(256) 上，解封时只有在收集到阈值份额、重建 KEK 并做完 KEK check 之后，才能发现某个份额是错的。

这带来两个问题：

- **分发阶段**：持有者无法判断自己收到的份额是否来自一个一致的 polynomial，只能相信 dealer。
- **提交阶段**：错误份额会被接收，直到达到阈值才导致整个会话失败，其他诚实持有者被迫重新发起会话。

桌面端已经引入 operator 签名的 manifest，能验证信封哈希和持有者条目，但 manifest 不校验份额本身的一致性。VSS（Verifiable Secret Sharing）补的就是这一层。

## 2. 目标与非目标

### 目标

1. 持有者在导入份额时，能用公开承诺验证自己的份额是否由 dealer 的 polynomial 正确生成。
2. 服务端在接收份额时逐份验证；无效份额直接拒绝，会话保持 `Collecting`，不因单个坏份额整体失败。
3. 重建 KEK 后，用承诺 `C0 = sG` 再验证一次重建结果，与现有 KEK check 形成双重校验。
4. 保持份额长度为 33 字节，尽量不改变现有分配和信道路径。
5. 所有新增数据可版本化、可测试、可审计。

### 非目标

- 不实现持有者签名、提交 nonce 绑定或 gRPC 传输加密；这些是独立的安全工作。
- 不解决持有者拒绝提交、离线或丢失份额导致的可用性问题。
- 不改变 `t-of-n` 的阈值语义。
- 不处理 v0.3 的 FROST / CGGMP21 门限签名；本方案只针对 v0.1 的 KEK 份额。
- 不引入抗量子假设。

## 3. 为什么不能直接在当前实现上加 VSS

`sharks` 使用 **GF(256) 逐字节 Shamir**：每个字节独立选取 polynomial，在 GF(256) 上求值。标准 Feldman/Pedersen VSS 需要：

- 在**素数域**上分享一个标量；
- 在一个满足离散对数假设的群中发布系数承诺 `C_j = a_j·G`；
- 利用群上的线性关系验证份额。

GF(256) 没有与多项式求值兼容的群承诺，因此不能直接给 `sharks` 的份额加标准 VSS。必须更换分享方案，这会影响：

- KEK 的生成方式；
- 份额的数学含义；
- `kek_check.json` 和 manifest 的格式；
- 服务端恢复逻辑；
- 已有 ceremony 的兼容性。

因此本方案是一个**分享方案迁移**，而不是在现有 `submit_share` 中增加一个函数调用。

## 4. 方案

### 4.1 密码学选择

- **群**：Ristretto255，素数阶群，压缩点 32 字节。
- **标量域**：Ristretto255 的标量域 `Z_l`，`l` 约 2²⁵²。
- **VSS**：Feldman VSS（非 Pedersen）。
- **实现**：`crates/vss` 直接基于 `curve25519-dalek` 的 `RistrettoPoint` / `Scalar` 实现 Feldman VSS。评估过 `vsss-rs 6.0.1`，它需要 curve25519-dalek 5 的 `ff`/`group` trait，会和现有 x25519/ed25519 依赖栈（curve25519-dalek 4.1.3）产生重复的曲线实现，因此没有采用。

选择 Ristretto255 的原因：

- 素数阶，避免 Curve25519 的 cofactor 问题；
- 压缩点 32 字节，承诺体积小；
- `curve25519-dalek` 已间接存在于依赖树；
- 常数时间实现成熟。

### 4.2 分享与承诺

设阈值 `t`，总份额 `n`：

```text
s ∈ Z_l                                  // KEK
f(x) = s + a_1·x + ... + a_{t-1}·x^{t-1} mod l
share_i = (i, y_i = f(i))                // i ∈ {1..n}
C_j = a_j·G, j = 0..t-1                  // 公开承诺
C_0 = s·G                                // KEK 承诺
```

KEK 的字节表示：

```text
kek = s.to_bytes()                       // 32 字节，little-endian
```

`kek` 继续用于现有的 KEK check（XChaCha20-Poly1305 加密固定明文）。`l` 约 2²⁵²，作为对称密钥的熵仍然足够。

### 4.3 验证与恢复

**份额验证**：

```text
y_i·G == Σ_{j=0}^{t-1} i^j·C_j
```

持有者在导入时验证；服务端在接收时验证。

**重建**：

1. 收集至少 `t` 个已验证份额 `(i, y_i)`。
2. 用拉格朗日插值在 0 点求值：

   ```text
   λ_i = Π_{j≠i} x_j / (x_j - x_i) mod l
   s = Σ λ_i·y_i mod l
   ```

3. 验证 `s·G == C_0`。
4. 用 `s.to_bytes()` 做现有 KEK check。
5. 任一步失败则保持 `Sealed`，不得进入 `Unsealed`。

## 5. 数据与格式

### 5.1 份额

份额格式保持 33 字节：

```text
index u8 | y [32]        // y = f(index) mod l, little-endian
```

与当前 `sharks` 份额长度相同，但数学含义不同。因此所有相关文件必须带 scheme 版本，禁止把旧份额解释成 VSS 份额。

### 5.2 `kek_check.json` v2

在现有字段上增加版本和承诺：

```json
{
  "version": 2,
  "threshold": 3,
  "total_shares": 5,
  "nonce": "<hex 24B>",
  "ciphertext": "<hex>",
  "vss": {
    "scheme": "ristretto255-feldman-v1",
    "commitments": ["<hex 32B>", "<hex 32B>", "<hex 32B>"]
  },
  "holders": [
    { "id": "alice", "index": 1 },
    { "id": "bob", "index": 2 },
    { "id": "carol", "index": 3 }
  ]
}
```

说明：

- `commitments.len() == threshold`。
- `holders` 用于服务端绑定 holder ID 与 share index；当前服务端没有这张表，VSS 校验必须与服务端索引绑定一起上线，否则一个有效份额仍可能被换到别的 holder 名下提交。
- `kek_check.json` 是本地可信配置，没有 operator 签名；长期可以让服务端加载并验证签名的 manifest。

### 5.3 manifest v2

manifest 增加 `vss` 字段，其他结构不变：

```json
{
  "version": 2,
  "ceremony_id": "...",
  "threshold": 3,
  "total_shares": 5,
  "vss": {
    "scheme": "ristretto255-feldman-v1",
    "commitments": ["...", "...", "..."]
  },
  "holders": [
    {
      "id": "alice",
      "index": 1,
      "x25519_public": "...",
      "ed25519_public": "...",
      "envelope_sha256": "..."
    }
  ]
}
```

manifest 由 operator 签名，因此承诺是经过认证的；持有者必须先验签，再使用承诺校验份额。

### 5.4 share vault

vault header 增加：

```text
vault_version u8          // 2
vss_scheme_len u8
vss_scheme bytes          // "ristretto255-feldman-v1"
vss_verified u8           // 1 = 已通过 VSS 校验
```

旧的 legacy 导入（无 manifest、无承诺）保持 `vss_verified = 0`，UI 显示“未 VSS 验证”。

## 6. 协议改动

### 6.1 初始化（`signer-admin init`）

1. 校验注册表和 `t <= n`。
2. 用 CSPRNG 生成标量 `s`（非零），作为 KEK。
3. 生成 `a_1..a_{t-1}`，构造 polynomial。
4. 对 `i = 1..n` 计算 `y_i`，生成 33 字节份额。
5. 计算 `C_0..C_{t-1}`。
6. 用 `s.to_bytes()` 生成 KEK check。
7. 用现有信封格式把份额加密给各持有者。
8. 写 `kek_check.json` v2、`manifest.json` v2 和签名。
9. zeroize `s`、系数和份额明文。

### 6.2 持有者导入

1. 验证 manifest 签名、holder entry、envelope SHA-256。
2. 解密得到 33 字节份额。
3. 解析 `index` 和 `y`。
4. 检查 `index` 与 manifest entry 一致。
5. 用 manifest 中的承诺验证 `y·G == Σ i^j·C_j`。
6. 验证失败：拒绝导入，不写入 vault，UI 显示“份额与 VSS 承诺不匹配”。
7. 验证成功：写入 vault，记录 scheme 和 `vss_verified = 1`。

### 6.3 提交

`SubmitUnsealShare` 的处理顺序：

1. 解析 `session_id`、`holder_id`、`share_index`、份额。
2. 检查会话存在、未过期、仍在 `Collecting`。
3. 用 `kek_check.json` 的 `holders` 表检查 `holder_id → index` 绑定。
4. 检查该 index 尚未提交（防止同一份额重复计数）。
5. 用承诺验证份额。
6. 验证失败：返回 `INVALID_ARGUMENT`，会话**保持 Collecting**，不把会话标记为 `Failed`；记录失败计数用于限流。
7. 验证成功：保存 `(index, y)`，更新 `shares_collected`。

达到阈值后：

1. 取 `t` 个已验证份额做拉格朗日插值。
2. 验证 `s·G == C_0`。
3. 做 KEK check。
4. 全部通过后进入 `Unsealed`；任一失败保持 `Sealed` 并将会话标记为 `Failed`。

### 6.4 与现有 proto 的关系

- 份额仍是 33 字节，可继续放在 `SubmitUnsealShareRequest.share` 中。
- 建议新增显式的 `share_index` 字段，避免只依赖首字节；同时为后续持有者签名留出绑定字段。
- VSS 失败映射为 `INVALID_ARGUMENT`，不与“重建失败”共用错误语义。
- 会话状态仍由现有 `UnsealState` 表达；不需要新增状态，但需要区分“单份被拒绝”和“整个会话失败”的日志/审计。

## 7. 组件改动清单

| 组件 | 改动 |
|---|---|
| `crates/vss`（`signer-vss`，新增） | polynomial、commitments、份额验证、拉格朗日恢复、测试 |
| `crates/core/src/unseal.rs` | `KekCheckFile` v2；会话保存已验证份额；提交时 VSS 校验；恢复改用新方案 |
| `crates/vss/Cargo.toml` | 依赖 `curve25519-dalek`；`signer-core` 移除 `sharks` |
| `crates/admin/src/main.rs` | 生成 KEK Scalar、系数、承诺；写 v2 文件和 manifest |
| `crates/holder/src/manifest.rs` | `VssCommitments` 类型、校验；manifest v2 |
| `crates/holder/src/lib.rs` | 导入时验证 VSS |
| `crates/holder/src/vault.rs` | vault v2 header、`vss_verified` |
| `crates/server/src/main.rs` | 读取 `KekCheckFile` v2 和 commitments |
| `crates/server/src/grpc.rs` | 传递 VSS 错误；可选 `share_index` |
| `proto/signer/v1/signer.proto` | 新增 `share_index`（建议）；错误码说明 |
| `desktop/` | 显示 VSS 验证状态；legacy 导入显示未 VSS |
| 文档 | 本文件、unseal-protocol、README、CHANGELOG |

## 8. 兼容性与迁移

### 已采用：clean break

v0.1 尚未发布，已直接切换到 v2：

- 新 ceremony 使用 VSS；
- 旧 `kek_check.json`（无 `version` / `vss`）拒绝加载；
- 旧份额不能被解释为 VSS 份额；
- 重新执行 `signer-admin init` 并重新分发份额。

### 可选：双方案并存

如果必须兼容已有数据：

- 在 `kek_check.json` 加 `sharing` 字段：`gf256-sharks-v1` 或 `ristretto255-feldman-v1`；
- 服务端按 scheme 分派验证和恢复逻辑；
- holder 在 manifest 没有 `vss` 时走 legacy 导入并显示警告。

这会增加测试矩阵和维护成本；非必要不建议。

## 9. 安全分析

### 提供的性质

- **正确性**：诚实 dealer 生成的份额必然通过承诺验证。
- **可靠性（soundness）**：承诺对应一个次数小于 `t` 的 polynomial；任何通过验证的 `t` 个份额都恢复出同一个 `f(0)`；错误份额无法通过等式。
- **dealer 偏心检测**：持有者在导入时能发现自己的份额与公开承诺不一致。恶意 dealer 仍可以让仪式失败，但无法悄悄给不同持有者不一致的份额而不被发现。
- **提交阶段早期拒绝**：无效份额不会消耗会话；诚实持有者不必因为一个坏份额重新开始。

### 假设

- Ristretto255 上的离散对数问题困难；
- `curve25519-dalek` / VSS 实现的常数时间性质可靠；
- CSPRNG 质量可靠；
- operator 签名密钥和 manifest 渠道可信；
- 服务端本地 `kek_check.json` 未被篡改（或未来改为加载签名 manifest）。

### 残余风险

- **不认证提交者**：VSS 只证明份额有效，不证明提交者就是该 holder。仍需持有者签名 + session nonce 绑定。
- **可用性**：持有者可以拒绝提交；恶意 dealer 可以中止仪式。
- **承诺公开**：`C_0 = sG` 公开 KEK 的群元素；在离散对数假设下不泄露 `s`，但 Feldman VSS 不是信息论隐藏的。如果需要更强的隐藏性，应使用 Pedersen VSS，代价是额外的生成元和承诺。
- **主机被攻破**：解封状态下内存中的 KEK/私钥不在 VSS 保护范围内。
- **抗量子**：Ristretto255 不是抗量子的；未来如需抗量子，需要更换群和承诺方案。
- **旧份额混用**：必须通过 scheme/version 明确拒绝；不能把 GF(256) 份额送进 VSS 验证。

## 10. 测试计划

### 单元测试

- 1-of-1、2-of-3、3-of-5 的生成、验证、恢复。
- 任意 `t` 个份额恢复出的 `s` 和 `C_0` 一致。
- 错误 `y`、错误 index、篡改 commitment、错误 threshold 全部拒绝。
- 同一 index 重复提交、holder ID 与 index 不匹配。
- 跨 ceremony 混用份额。
- 份额长度、commitment 长度、标量编码边界。
- 承诺与 KEK check 的绑定：commitments 与 manifest/kek_check 不一致时拒绝。
- zeroize 和日志检查（不出现份额/KEK）。

### 集成测试

1. `signer-admin init` 生成 v2 manifests、kek_check 和份额。
2. 桌面端导入：正确份额通过 VSS；篡改份额/承诺被拒绝。
3. 服务端提交：无效份额被拒，会话仍为 `Collecting`；其他持有者继续提交后成功解封。
4. 达到阈值后重建的 KEK 通过 `C_0` 和 KEK check。
5. 旧 v1 文件被明确拒绝（或按双方案路径处理）。
6. 端到端：operator → holder → server → unsealed → seal。

### 参考实现交叉验证

如果使用自研 Feldman 实现，建议用 `vsss-rs` 或独立测试向量交叉验证：

- 相同 polynomial 和 index 的份额；
- 相同 commitments；
- 相同恢复结果。

## 11. 实施顺序

1. 评估 `vsss-rs` 与自研 Ristretto255 Feldman，记录 ADR。
2. 实现 `vss` 模块和单元测试。
3. 升级 `KekCheckFile` / manifest / vault 格式。
4. 修改 `signer-admin init`。
5. 修改 `signer-holder` 导入验证。
6. 修改 `signer-server` 提交验证和恢复；补 `share_index`/holder 绑定。
7. 桌面端显示 VSS 状态，legacy 路径明确警告。
8. 文档、CHANGELOG、端到端测试。

## 12. 实现决策

- 使用基于 `curve25519-dalek` 4.1.3 的自研 Feldman VSS，不引入 `vsss-rs`。
- 采用 clean break：`KekCheckFile` v2、manifest v2、vault v2；旧 v1 文件拒绝加载，需要重新 `init` 和分发。
- 服务端从 `kek_check.json` v2 读取 commitments 和 holder/index 注册表；manifest 继续作为持有者侧验签与 VSS 校验的输入。
- `SubmitUnsealShareRequest` 新增 `share_index` 字段；为 0 时兼容旧客户端，回退到份额首字节。
- 选择 Feldman 而不是 Pedersen：VSS 只用于一致性和完整性，`C_0` 泄露在离散对数假设下可接受。
- `docs/threat-model.md` 的 T3 已更新为部分缓解；持有者签名、session nonce 绑定和份额传输加密仍待补。
