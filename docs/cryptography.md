# 密码学设计

> 状态：与当前实现同步（2026-10-22）。
>
> 本文按技术分节，介绍项目中已经使用、历史使用、计划使用以及评估后未采用的密码学技术，重点说明原理和它在系统中的具体位置。代码位置只写模块路径；数据格式以当前实现为准。
>
> 标记说明：
>
> - ✅ 现行：已接入主流程
> - 🕘 历史：曾经使用，已被替换
> - 🚧 计划：设计已确定，尚未实现
> - 🔍 评估未采用：比较过，但当前不采用

## 0. 总览

### 0.1 数据分层

v0.1 是**门限解封**，不是门限签名：

```text
KEK（32 字节随机密钥）
  ├── 通过 Ristretto255 Feldman VSS 拆成 n 份，阈值 t
  ├── 用于解开每个密钥的 DEK（Ed25519 已实现）
  └── 解封后驻留 signer 进程内存

私钥
  └── 用每密钥独立的 DEK 以 XChaCha20-Poly1305 加密（Ed25519 / secp256k1 已实现）
        └── DEK 再用 KEK 包裹（Ed25519 / secp256k1 已实现）
```

达到阈值后，signer 在内存中重建完整 KEK，之后可以解开 DEK 和私钥。因此本项目的安全边界是“门限解封”，不是“私钥永不重组”的门限签名（FROST / CGGMP21 在 v0.3 路线图中）。

当前真正落地的是 **KEK 的 VSS 分片、分发、提交、校验和恢复**，以及 **Ed25519 / secp256k1 的 DEK/KEK 信封 keystore**（CreateKey / GetPublicKey / ListKeys / Sign）。ImportKey 仍在开发中，文中会明确标注“计划”或“设计”。

### 0.2 技术清单

| 技术 | 作用 | 状态 | 主要代码 |
| --- | --- | --- | --- |
| CSPRNG（`OsRng`） | 生成密钥、nonce、salt、份额系数 | ✅ | `crates/vss`、`crates/share`、`crates/holder`、`crates/core` |
| SHA-256 | 哈希、指纹、签名输入、manifest 绑定 | ✅ | `crates/holder/src/file.rs`、`crates/share/src/lib.rs` |
| Ed25519 | Holder 身份、operator manifest、提交签名 | ✅ | `crates/holder`、`crates/core` |
| X25519 | 份额信封的 ECDH 密钥协商 | ✅ | `crates/share/src/lib.rs` |
| HKDF-SHA256 | 从 ECDH 共享秘密派生 AEAD 密钥 | ✅ | `crates/share/src/lib.rs` |
| XChaCha20-Poly1305 | 份额、身份文件、vault、KEK check、私钥/DEK 信封的 AEAD | ✅ | `crates/share`、`crates/holder`、`crates/core` |
| Argon2id | 口令派生身份/vault 加密密钥 | ✅ | `crates/holder/src/file.rs` |
| DEK/KEK 信封 | 每密钥独立 DEK，私钥用 DEK 加密、DEK 用 KEK 包裹 | ✅ Ed25519 / secp256k1 | `crates/core/src/keystore.rs` |
| Ristretto255 | Feldman VSS 的素数阶群 | ✅ | `crates/vss/src/lib.rs` |
| Feldman VSS | KEK 的可验证秘密分享 | ✅ | `crates/vss/src/lib.rs` |
| Shamir GF(256) | 旧版份额分享（`sharks`） | 🕘 | 已移除依赖 |
| Lagrange 插值 | 从 t 份份额恢复 KEK | ✅ | `crates/vss/src/lib.rs` |
| secp256k1 + ECDSA | EVM 业务签名 | ✅ | `crates/core/src/keystore.rs` |
| EdDSA 业务签名 | Solana 业务签名 | ✅ Ed25519 | `crates/core/src/keystore.rs` |
| FROST | 门限 Ed25519 签名 | 🚧 | v0.3 |
| CGGMP21 | 门限 ECDSA 签名 | 🚧 | v0.3 |
| Pedersen VSS | 信息论隐藏的 VSS 备选 | 🔍 | 未采用 |
| TLS / mTLS | 传输加密与服务端/客户端认证 | ✅ | 已实现，默认关闭 |
| KMS / HSM | 托管 KEK | 🔍 | ADR-0005 明确 v0.1 不采用 |

## 1. CSPRNG 与秘密生命周期

### 原理

所有密钥、份额、salt、nonce 都必须来自密码学安全的随机数生成器（CSPRNG），不能使用时间戳、计数器或普通 PRNG。项目统一使用 `rand::rngs::OsRng`，由操作系统提供熵源。

`Zeroize` / `Zeroizing` 用于在缓冲区离开作用域时尽力擦除秘密。它不是“内存安全”的完整保证：核心转储、交换分区、休眠文件、调试器、WebView 副本仍可能泄露，但在应用层能减少秘密驻留时间。

### 系统中的使用

- KEK 标量：`crates/vss/src/lib.rs::generate_secret` 生成 64 字节随机数，经 `Scalar::from_bytes_mod_order_wide` 归约到标量域；零值会被拒绝并重试。
- Feldman 多项式系数：`random_scalar` 同样从 64 字节随机数生成。
- 会话 nonce：32 字节。
- 会话 X25519 密钥对：`HolderKeypair::generate`。
- 份额信封的临时 X25519 密钥、24 字节 XChaCha nonce。
- 身份/vault 的 16 字节 Argon2 salt、24 字节 XChaCha nonce。
- Ed25519 / X25519 身份密钥种子。

### 注意

- `Zeroizing` 只能擦除 Rust 侧持有的缓冲区；桌面端 WebView 中的口令字符串无法可靠擦除，UI 在调用后清空输入框只是降低暴露面。
- 解封后的 KEK、解密后的份额、私钥缓冲区都应在使用后尽快 `zeroize`；当前代码对份额、KEK、DEK 和 Ed25519 种子使用了 `Zeroizing`，新增算法时需要继续保持这一约束。

## 2. SHA-256

### 原理

SHA-256 是输出 256 位的密码学哈希函数，性质包括：

- 抗原像：给定摘要难以找到原文；
- 抗第二原像：给定原文难以找到同摘要的另一原文；
- 抗碰撞：难以找到任意两条同摘要消息。

它不是口令 KDF。对低熵口令直接做 SHA-256 不能抵抗离线暴力破解，口令场景使用 Argon2id。

### 系统中的使用

| 用途 | 计算方式 | 说明 |
| --- | --- | --- |
| manifest 绑定份额信封 | `SHA-256(envelope bytes)` | 写入 `manifest.holders[].envelope_sha256`，Holder 导入前比对 |
| vault 记录 manifest | `SHA-256(manifest raw bytes)` | 写入 vault header 的 `manifest_hash`，便于审计 |
| Holder 公钥指纹 | `SHA-256("signer.holder.fingerprint.v1" || ed25519_pub || x25519_pub)` | 供带外核对，不是签名 |
| operator 公钥指纹 | `SHA-256("signer.operator.fingerprint.v1" || operator_pub)` | 供带外核对 |
| 提交签名输入 | `SHA-256(context)` 和 `SHA-256(ciphertext)` | 把可变长输入压缩成固定 32 字节 |
| 工具函数 | `sha256_hex` | 生成十六进制摘要 |

### 注意

- 单独使用 SHA-256 不提供来源认证；这里的完整性来自 operator 对 manifest 的 Ed25519 签名，哈希只是被签名的摘要。
- 指纹只用于人工带外核对；它不证明持有者身份，也不替代 Ed25519 签名。
- manifest 绑定的是**信封密文的哈希**，不是明文份额；Holder 先验证 manifest 和信封哈希，再解密。

## 3. Ed25519

### 原理

Ed25519 是基于 twisted Edwards 曲线 edwards25519 的 EdDSA 签名方案：

- 私钥通常表示为 32 字节种子；
- 公钥 32 字节；
- 签名 64 字节；
- 内部使用 SHA-512 生成确定性 nonce，签名过程不需要外部随机数；
- 验证时检查曲线点编码、标量范围和签名方程。

项目使用 `ed25519-dalek` 的 `Signer` / `VerifyingKey::verify_strict`。`verify_strict` 会拒绝一些非规范编码和小阶点边界情况，比宽松验证更适合协议输入。

### 系统中的使用

**1. Holder 身份（✅）**

`crates/holder/src/identity.rs` 为每个 Holder 生成一对密钥：

- Ed25519：用于签名；
- X25519：用于接收加密份额。

公开 bundle 包含 `holder_id`、两个公钥和 self-signature：

```text
self_signature = Ed25519_sign(
    "signer.holder.identity.v1"
    || u16_le(len(holder_id))
    || holder_id
    || ed25519_public
    || x25519_public
)
```

operator 注册 Holder 时验证 self-signature，确认公钥确实由该身份持有者生成，并防止 bundle 被替换。self-signature 只证明“持有对应私钥”，不证明现实身份；现实身份仍依赖注册和带外核对。

**2. Operator manifest（✅）**

`crates/holder/src/manifest.rs` 使用独立的 operator Ed25519 密钥对 manifest **原始 JSON 字节**做 detached 签名：

- `manifest.json`：格式化后的 JSON 字节（签名字节与文件字节完全一致）；
- `manifest.sig`：64 字节签名的 hex；
- `operator.pub`：32 字节公钥的 hex。

Holder 验证顺序是：operator 签名 → 解析 JSON → 校验结构 → 找到自己的 entry → 校验 Holder 公钥和信封哈希 → 解密 → VSS 校验。

注意：manifest 签名没有额外协议前缀，签的是原始字节；因此 operator 密钥应专用于 manifest 签名，不要复用到其他签名场景，避免跨协议混淆。

**3. 在线份额提交（✅）**

桌面端从 vault 取出份额后，用 Holder Ed25519 私钥签名：

```text
signing_input =
    "signer.unseal.submit.sig.v2"
    || SHA-256(context)
    || SHA-256(ciphertext)
```

服务端在计数前用 `kek_check.json` 中登记的 Holder Ed25519 公钥验证签名。签名绑定会话上下文和密文，攻击者不能把一份合法提交挪到另一个会话、Holder 或索引下重用。

**4. 业务签名密钥（✅ Ed25519）**

`crates/core/src/keystore.rs` 的 `CreateKey` / `Sign` 使用 edwards25519 + EdDSA：

- 生成 32 字节种子并派生公钥；
- 私钥种子用每密钥独立的 DEK 加密，DEK 再用解封后的 KEK 包裹；
- 签名时解包 DEK、解密种子、签名，然后立即 zeroize。

它和 Holder 身份密钥是不同用途的密钥，不能混用。secp256k1/ECDSA 见第 13 节。

### 注意

- Holder 身份密钥当前没有轮换机制；丢失或泄露需要重新分发份额。
- operator 私钥当前是 32 字节原始文件，依赖文件权限和离线保管；生产化应放入 HSM/KMS 或至少用口令加密。
- Ed25519 签名是公开可验证的，会暴露“哪个 Holder 提交过”这一事实；这是审计需要的，但也意味着提交不是匿名的。

## 4. X25519

### 原理

X25519 是 Curve25519 上的 ECDH 函数：

- 双方各有一个 32 字节私钥和 32 字节公钥；
- 双方用 `DH(secret, peer_public)` 得到相同的 32 字节共享秘密；
- 私钥在运算时会被 clamp（清除低位、设置高位），这是 X25519 规范的一部分；
- X25519 本身只提供密钥协商，不提供身份认证和密钥确认。

项目采用 ECIES 风格的信封加密：

```text
ephemeral keypair (e, E)
shared = X25519(e, recipient_public)
key = HKDF-SHA256(shared, salt = E || recipient_public, info = domain)
ciphertext = XChaCha20-Poly1305(key, nonce, plaintext, aad)
envelope = magic || version || E || nonce || ciphertext
```

### 系统中的使用

**1. 离线分发信封 v1（✅）**

`crates/share/src/lib.rs::encrypt_share`：

- 发送方是 operator；
- 接收方是 Holder 的长期 X25519 公钥；
- 每次加密生成新的临时 X25519 密钥对；
- 共享秘密经 HKDF 派生 32 字节 XChaCha 密钥；
- 信封头包含临时公钥和 24 字节 nonce；
- AAD 是 `magic || version`，只绑定信封格式，不绑定持有者或 ceremony。

v1 信封本身没有发送方认证，所以 operator 用 manifest 签名绑定 `envelope_sha256` 和 Holder 公钥；Holder 验证 manifest 后才能确认信封来源和完整性。

**2. 在线提交信封 v2（✅）**

`encrypt_share_with_context`：

- 接收方是 signer 为本次会话临时生成的 X25519 公钥；
- Holder 每次提交生成新的临时 X25519 密钥对；
- AAD 绑定完整提交上下文：

```text
"signer-share-envelope-v2"
|| context
```

其中 context 包含 `session_id`、`nonce`、`session_public_key`、`holder_id`、`share_index`。

服务端用会话私钥解密。会话私钥只存在于 `UnsealManager` 的内存中，随会话结束被擦除。

### 为什么每个会话生成临时密钥

- 不同会话的密文不能互相解密；
- 减少长期服务端密钥暴露带来的影响；
- 配合 nonce/上下文绑定，密文不能跨会话重放。

这不是完整的端到端前向保密：解封会话进行期间，会话私钥仍在服务端内存中；如果主机在收集阶段被攻破，攻击者仍可能拿到会话私钥。它主要缩小暴露窗口并实现会话隔离。

### 注意

- X25519 不认证对方；v1 依赖 manifest，v2 依赖 Holder Ed25519 签名。
- 未启用 `[tls]` 时没有 TLS，持有者无法认证服务端；中间人仍可能替换 `session_public_key`。这是 T12 残余风险；启用 mTLS 后可以认证服务端，生产环境必须启用。

## 5. HKDF-SHA256

### 原理

HKDF 是“提取—扩展”式密钥派生函数：

```text
PRK = HMAC-SHA256(salt, input_key_material)
OKM = HMAC-SHA256(PRK, info || 0x01)  // 输出 32 字节时只需一个块
```

- Extract 把可能不均匀的共享秘密转成伪随机密钥；
- Expand 用 `info` 做域分离，派生不同用途的密钥。

### 系统中的使用

`crates/share/src/lib.rs::derive_key`：

- IKM：X25519 共享秘密；
- salt：`ephemeral_public || recipient_public`，共 64 字节；
- info：`signer-share-envelope-v1` 或 `signer-share-envelope-v2`；
- 输出：32 字节 XChaCha20-Poly1305 密钥。

把双方公钥放进 salt 可以绑定“这对密钥”的上下文；`info` 区分离线分发和在线提交，避免同一共享秘密在不同协议中派生出相同密钥。

### 注意

- 不能直接把 X25519 共享秘密当 AEAD 密钥使用：共享秘密不是均匀随机，且缺少域分离。
- HKDF 不提供身份认证；认证由 manifest 或 Ed25519 签名完成。

## 6. XChaCha20-Poly1305

### 原理

XChaCha20-Poly1305 是 AEAD（带关联数据的认证加密）：

- 256 位密钥；
- 192 位 nonce（24 字节），随机生成时碰撞概率极低；
- 128 位认证标签；
- 加密保证机密性，标签保证完整性和真实性；
- AAD 只参与认证，不加密，适合放头部、上下文等公开但必须防篡改的数据。

XChaCha 先用 HChaCha20 从 24 字节 nonce 的前 16 字节派生 subkey，再用剩余的 8 字节 nonce 做 ChaCha20-Poly1305。相比 96 位 nonce 的 AES-GCM，它降低了随机 nonce 管理的压力，也不依赖 AES 硬件加速。

### 系统中的使用

| 场景 | 密钥来源 | nonce | AAD | 明文 |
| --- | --- | --- | --- | --- |
| 份额信封 v1 | HKDF（ECDH） | 随机 24B | `SSHR || 1` | 33 字节份额 |
| 份额信封 v2 | HKDF（ECDH） | 随机 24B | `signer-share-envelope-v2 || context` | 33 字节份额 |
| Holder 身份文件 | Argon2id（口令） | 随机 24B | 文件 header | holder_id + Ed25519 seed + X25519 seed |
| Share vault | Argon2id（口令） | 随机 24B | 文件 header | 33 字节份额 |
| KEK check | KEK 直接作为密钥 | 随机 24B | `signer.kek.check.v1` | 固定字符串 |
| Ed25519 私钥加密 | DEK | 随机 24B | `signer.key.private.v1 || key binding` | 32 字节种子 |
| DEK 包裹 | KEK | 随机 24B | `signer.key.dek.v1 || key binding` | 32 字节 DEK |

Ed25519 的 `key binding` 是：

```text
key_id [16] || curve_tag [1] || algorithm_tag [1]
|| u16_le(len(public_key)) || public_key
```

两段 AAD 分别使用 `signer.key.private.v1` 和 `signer.key.dek.v1` 前缀，避免私钥密文与 DEK 密文互换，也避免同一份密文被挪到另一个 key_id、曲线、算法或公钥下。

### 注意

- 每个加密操作都生成新 nonce；当前没有 nonce 重用检测，但 192 位随机 nonce 的碰撞风险可以忽略。
- AAD 必须与解密时完全一致；修改 header 或 context 会导致认证失败。
- 错误统一映射为“口令错误或文件损坏”或 `Decrypt`，不区分具体原因，避免给攻击者提供侧信道。

## 7. Argon2id

### 原理

Argon2 是内存硬（memory-hard）的口令哈希/KDF，有三种模式：

- Argon2d：数据依赖访问，抗 GPU 但侧信道风险较高；
- Argon2i：数据独立访问，抗侧信道但内存硬性较弱；
- Argon2id：混合模式，是当前推荐的口令哈希选择。

Argon2id 通过大量内存填充和多次迭代提高离线暴力破解成本；输出 32 字节密钥。

### 系统中的使用

`crates/holder/src/file.rs`：

```text
m_cost = 64 * 1024 KiB  （64 MiB）
t_cost = 3
p_cost = 1
salt   = 16 字节随机
output = 32 字节
```

- 身份文件（`SHK2`）和 share vault（`SHV1`）都使用同一口令；
- 两者使用**独立随机 salt**，因此派生出不同密钥，避免密钥复用；
- KDF 参数写入文件 header，读取时校验范围：`m_cost` 8–256 MiB、`t_cost` 1–10、`p_cost` 1–4，防止恶意文件造成内存/CPU 拒绝服务。

### 注意

- Argon2id 只保护“口令 → 文件加密密钥”这一步；它不能把弱口令变强。UI 建议至少 12 个字符的高熵口令。
- 桌面端 WebView 中的口令副本无法保证擦除；Rust 侧使用 `Zeroizing` 并限制口令生命周期。
- KEK 和 DEK 是随机密钥，不使用 Argon2id；不要把“口令保护文件”和“门限解封”混为一谈。

## 8. Ristretto255

### 原理

Ristretto255 是基于 Curve25519 的一个**素数阶群**抽象：

- 群阶 `l = 2^252 + 27742317777372353535851937790883648493`；
- 元素压缩编码为 32 字节；
- 提供规范的编码/解码，避免 Edwards 曲线 cofactor 和小阶点带来的协议歧义；
- 标量运算在模 `l` 的域中进行；
- 支持 `P = x·G` 形式的群运算和线性同态承诺。

项目使用 `curve25519-dalek` 的 `RistrettoPoint`、`CompressedRistretto` 和 `Scalar`。

### 为什么用 Ristretto255

Feldman VSS 需要：

1. 一个素数阶群，保证份额验证方程没有 cofactor 歧义；
2. 线性同态的承诺：`C_j = a_j·G`，验证时计算 `Σ i^j·C_j`；
3. 规范的 32 字节编码，便于写入 JSON 和二进制文件。

直接使用 edwards25519 需要额外处理 cofactor 和编码规范；Ristretto255 把这些细节封装成更适合协议使用的群。

### 系统中的使用

- `C_j = a_j·G`：每个多项式系数的承诺；
- `y_i·G`：份额对应的群元素；
- `C_0 = s·G`：KEK 的承诺，用于恢复后校验；
- 承诺以 32 字节压缩点、hex 字符串形式存储在 `kek_check.json` 和 manifest 中。

## 9. Feldman VSS

### 原理

Feldman VSS 是可验证秘密分享（VSS）的一种：

1. Dealer 选择随机秘密 `s` 和多项式：

   ```text
   f(x) = s + a_1·x + ... + a_{t-1}·x^{t-1}  mod l
   ```

2. 对每个系数计算承诺：

   ```text
   C_j = a_j·G,  j = 0..t-1
   ```

3. 给 Holder `i` 的份额是：

   ```text
   (i, y_i = f(i))
   ```

4. 任何持有承诺的人都可以验证：

   ```text
   y_i·G == Σ_{j=0}^{t-1} i^j·C_j
   ```

5. 任意 `t` 份份额通过 Lagrange 插值恢复 `s = f(0)`，并检查：

   ```text
   s·G == C_0
   ```

### 安全性质

- **阈值性**：少于 `t` 份份额不能恢复 `s`（Shamir 的信息论安全性）。
- **可验证性**：每份份额都能独立对照承诺验证，不需要先恢复秘密。
- **承诺绑定**：在离散对数假设下，承诺绑定系数；Holder 能发现自己的份额与公开承诺不一致。
- **计算隐藏**：`C_0 = s·G` 公开了 KEK 的群元素；在离散对数困难假设下不泄露 `s`，但 Feldman 不是信息论隐藏的。

### 系统中的使用

**初始化（operator）**

`crates/admin/src/main.rs` 调用 `UnsealManager::bootstrap`：

1. 生成随机 KEK 标量 `s`；
2. `split_secret` 生成 `n` 份 33 字节份额和 `t` 个承诺；
3. 用每个 Holder 的 X25519 公钥加密份额，写出 `.share`；
4. 把承诺、threshold/total、Holder 注册表写入 `kek_check.json` v3；
5. 把承诺、Holder 公钥、信封哈希写入 manifest v2，并用 operator 密钥签名；
6. 明文份额在加密后 zeroize。

**Holder 导入**

`crates/holder/src/lib.rs::import_share`：

1. 验证 operator manifest 签名；
2. 找到自己的 entry，核对 Ed25519/X25519 公钥；
3. 核对 `.share` 的 SHA-256 与 manifest 中的 `envelope_sha256`；
4. 用身份中的 X25519 私钥解密 v1 信封；
5. 检查份额索引和长度；
6. 用 manifest 中的承诺执行 `verify_share`；
7. 只有通过 VSS 才把 `vss_verified=true` 写入 vault。

**服务端提交**

`crates/core/src/unseal.rs::submit_share`：

1. 校验 Holder 注册、索引、nonce；
2. 验证 Holder Ed25519 签名；
3. 用会话 X25519 私钥解密 v2 信封；
4. 检查长度 33 和首字节索引；
5. 用 `kek_check.json` 中的承诺执行 `verify_share`；
6. 只有通过才计入会话；坏份额不会“烧掉”整个会话。

**恢复**

收集到 `t` 份后：

1. `recover_secret` 用 Lagrange 插值恢复 `s`；
2. 检查 `s·G == C_0`；
3. 用恢复出的 KEK 解密 `kek_check` 固定明文；
4. 两步都通过才进入 `Unsealed`。

### 参数与格式

- scheme：`ristretto255-feldman-v1`；
- 份额：`index u8 || y 32 bytes`，共 33 字节，`y` 为 little-endian 标量；
- 承诺：每个 32 字节压缩 Ristretto 点，数量等于 threshold；
- 份额索引从 1 开始，0 非法；
- `kek_check.json` v3 同时保存承诺和 Holder 注册表（id、index、Ed25519 公钥）。

### 限制

- **可信 dealer**：operator 在初始化时看到全部明文份额。它可以把份额留给自已，从而绕过阈值。这是 trusted-dealer VSS 的固有限制；更强方案是 DKG。
- **C0 公开**：Feldman 的隐藏性是计算性的，不是信息论隐藏。
- **自研实现**：`crates/vss` 是基于 `curve25519-dalek` 的自研 Feldman 实现，尚未经过独立审计；需要测试向量和外部评审。
- **不认证提交者**：VSS 只证明份额有效，不证明提交者身份；现在由 Holder Ed25519 签名补齐。

## 10. Shamir 秘密分享（GF(256)，历史）

### 原理

旧实现使用 `sharks` crate，在 GF(256) 上做逐字节 Shamir：

- 对 32 字节秘密的每个字节独立选择一个 `t-1` 次多项式；
- 每个 Holder 的份额是每个多项式在该 Holder 索引处的取值；
- 恢复时对每个字节做 Lagrange 插值，得到原始 32 字节。

份额编码为 33 字节：首字节索引 + 32 字节份额数据。它和现行的 Ristretto255 VSS 份额长度相同，但数学含义完全不同，不能混用。

### 为什么被替换

GF(256) 上没有与多项式求值兼容的群承诺，因此无法做标准 Feldman/Pedersen VSS：

- 只能在恢复出 KEK 后用 KEK check 判断份额是否正确；
- 一个坏份额会导致整个会话失败，其他 Holder 必须重新提交；
- 无法在导入时发现 dealer 给某个 Holder 发了不一致的份额。

因此项目在 v0.1 内直接切换到 Ristretto255 Feldman VSS，并通过 `kek_check.json` 版本、manifest scheme 和 vault scheme 拒绝旧数据。

### 状态

- 🕘 历史实现，`sharks` 依赖已移除；
- 旧 v1/v2 `kek_check.json` 和旧份额不兼容，必须重新 `init` 和分发。

## 11. Lagrange 插值

### 原理

给定 `t` 个点 `(x_i, y_i)`，存在唯一的次数小于 `t` 的多项式 `f` 经过这些点。秘密是 `f(0)`：

```text
s = f(0) = Σ_i y_i · λ_i
λ_i = Π_{j≠i} x_j / (x_j - x_i)   （模 l）
```

在 VSS 中，`x_i` 就是份额索引，`y_i` 是份额标量。

### 系统中的使用

`crates/vss/src/lib.rs::recover_secret`：

1. 解析所有份额，拒绝重复索引；
2. 对每个份额计算 Lagrange 系数 `λ_i`；
3. 求和得到 `s`；
4. 检查 `s·G == C_0`；
5. 清零中间标量和份额副本，返回 `Zeroizing<[u8; 32]>`。

如果传入超过 `t` 份份额，当前实现会全部使用；对于次数 `t-1` 的多项式，结果相同。服务端在达到阈值后立即恢复，不会等待更多份额。

### 注意

- 恢复前必须确保每份份额已经通过 `verify_share`；否则恶意份额会污染插值结果。
- 重复索引会让 Lagrange 系数失去意义，因此直接拒绝。
- 恢复后仍要做 `C_0` 校验和 KEK check，形成两层验证。

## 12. 域分离与上下文绑定

密码学协议中，同一把密钥不能在不同语境下签/加密相同字节，否则可能发生跨协议重放。项目用显式域字符串和长度前缀隔离不同用途。

| 用途 | 输入 | 域/前缀 |
| --- | --- | --- |
| Holder 身份 self-signature | `domain || u16_le(len(id)) || id || ed_pub || x_pub` | `signer.holder.identity.v1` |
| Holder 公钥指纹 | `domain || ed_pub || x_pub` | `signer.holder.fingerprint.v1` |
| operator 公钥指纹 | `domain || operator_pub` | `signer.operator.fingerprint.v1` |
| 提交上下文 | `domain || u8(len(session)) || session_id || nonce || session_pub || u8(len(holder)) || holder_id || index` | `signer.unseal.submit.v2` |
| 提交签名输入 | `domain || SHA-256(context) || SHA-256(ciphertext)` | `signer.unseal.submit.sig.v2` |
| 信封 HKDF v1 | `info` | `signer-share-envelope-v1` |
| 信封 HKDF v2 | `info` | `signer-share-envelope-v2` |
| 信封 AAD v2 | `domain || context` | `signer-share-envelope-v2` |
| KEK check AAD | 固定字符串 | `signer.kek.check.v1` |
| KEK check 明文 | 固定字符串 | `signer-kek-check-v1` |
| 私钥信封 AAD | `domain || key_binding` | `signer.key.private.v1` |
| DEK 包裹 AAD | `domain || key_binding` | `signer.key.dek.v1` |
| manifest 签名 | 原始 JSON 字节 | 无额外前缀 |

### 注意

- manifest 是唯一没有显式域前缀的签名对象；因此 operator 密钥要专用，不能拿去签其他消息。
- 长度前缀（`u8` / `u16_le`）避免字段拼接歧义，例如 `"ab" + "c"` 和 `"a" + "bc"` 不会得到相同 transcript。
- v2 提交同时绑定 AEAD AAD 和 Ed25519 签名输入；只改其中一个都会失败。

## 13. secp256k1 + ECDSA（✅）

### 原理

secp256k1 是 Bitcoin/EVM 使用的短 Weierstrass 曲线。ECDSA 签名基于椭圆曲线离散对数：

- 私钥是 32 字节标量；
- 公钥是曲线点，常用 33 字节压缩编码；
- 签名通常是 `(r, s)`，各 32 字节；
- 签名 nonce `k` 必须不可预测且不能重用，否则会泄露私钥；生产实现应使用 RFC 6979 确定性 nonce 或强随机 nonce；
- 需要对 `s` 做 low-s 规范化，避免签名可延展。

### 系统中的使用

- 作为 keystore 支持的 EVM 密钥类型；
- `CreateKey` 生成 secp256k1 私钥标量，用 DEK 加密、KEK 包裹；
- 公钥使用 33 字节压缩 SEC1 编码；
- `Sign` 接收调用方提供的 32 字节摘要，使用 RFC 6979 确定性 nonce，做 low-s 规范化；
- 返回 65 字节 `r || s || v`，`v` 为 27 或 28；
- 签名后立即 zeroize 私钥标量和 DEK。

### 状态

✅ 已实现 `CreateKey`、`GetPublicKey`、`ListKeys`、`Sign`；`ImportKey` 和密钥轮换仍待实现。

## 14. EdDSA 业务签名（✅ Ed25519）

### 原理

业务签名使用 edwards25519 + EdDSA（Ed25519）：

- 私钥是 32 字节种子；
- 公钥 32 字节，签名 64 字节；
- 与 Holder 身份使用的 Ed25519 是同一原语，但用途和密钥完全独立。

### 系统中的使用

- 作为 Solana 等 Ed25519 链的签名密钥；
- `CreateKey` 生成 32 字节种子，私钥种子由 keystore 用 DEK 加密，DEK 由 KEK 包裹；
- `Sign` 对 proto 中的 `payload` 原始消息签名；
- 公钥直接返回 32 字节 Ed25519 verifying key。

### 状态

✅ 已实现 `CreateKey`、`GetPublicKey`、`ListKeys`、`Sign`；`ImportKey` 和密钥轮换仍待实现。

## 15. FROST（🚧 计划）

### 原理

FROST（Flexible Round-Optimized Schnorr Threshold signatures）是门限 Schnorr/EdDSA 签名协议：

- 私钥份额由 DKG 或可信 dealer 生成；
- 签名通常分两轮：签名方先提交 nonce 承诺，再根据聚合挑战提交签名份额；
- 聚合者合并份额得到最终签名；
- 完整私钥从不出现在任何单一方。

### 计划中的使用

v0.3 计划用 FROST 实现 Ed25519 门限签名。与当前的“门限解封”不同，FROST 不重建完整私钥，签名由多个独立 signer 协作完成。

### 状态

🚧 仅路线图。ADR-0006 描述了 per-share 解封的运维模型，FROST 是 v0.3 的目标协议。

## 16. CGGMP21（🚧 计划）

### 原理

CGGMP21 是一类 UC 安全的门限 ECDSA 协议族，支持：

- 分布式密钥生成（DKG）；
- 预签名（presigning）和在线签名；
- 可识别中止（identifiable abort）：签名失败时能定位恶意参与方；
- secp256k1 等曲线。

它比 FROST 复杂得多，通常依赖 Paillier 加密、零知识证明和多方计算组件。

### 计划中的使用

v0.3 计划用 CGGMP21 实现 secp256k1 门限 ECDSA。当前没有引入相关依赖。

### 状态

🚧 仅路线图，未实现。

## 17. Pedersen VSS（🔍 评估未采用）

### 原理

Pedersen VSS 在 Feldman 的基础上增加一个盲化多项式：

```text
f(x) = s + a_1·x + ... + a_{t-1}·x^{t-1}
g(x) =     b_1·x + ... + b_{t-1}·x^{t-1}
承诺 C_j = a_j·G + b_j·H
```

其中 `H` 是另一个生成元，且没人知道 `log_G(H)`。份额验证同时使用 `y_i` 和盲化份额。

### 优点与代价

- 优点：信息论隐藏，`C_0` 不直接暴露 `s·G`；
- 代价：承诺和份额更大、通信更多、需要额外的生成元假设。

### 为什么未采用

当前 VSS 只需要一致性和完整性，不需要信息论隐藏；Feldman 的 `C_0 = s·G` 在离散对数假设下可接受。选择 Feldman 可以保持份额 33 字节、承诺数量等于 threshold，并减少实现复杂度。

## 18. TLS / mTLS（✅ 已实现，需显式启用）

### 原理

TLS 提供传输加密和服务端身份认证；mTLS 额外要求客户端出示 X.509 证书，服务端验证客户端身份。目标部署使用标准 CA：

- signer 服务端证书：`serverAuth`；
- Holder/operator 客户端证书：`clientAuth`；
- 双方验证证书链、有效期、SAN、EKU；本版不做 CRL/OCSP。

### 客户端证书权限位

服务端不读取本地策略文件，也不维护客户端白名单。客户端证书通过 SAN URI 携带：

```text
URI:signer://principal/<actor>
URI:signer://holder/<holder-id>        (零个或多个)
URI:signer://permissions/0x<16-hex>    (u64 权限位掩码，最多一个)
```

权限位使用 u64，bit 0–7 对应 `unseal.start/submit/status/seal`、`key.create/import/read/sign`；bit 8/9 预留给未来的 `key.destroy`/`audit.read`，在对应 RPC 实现前也必须为 0；bit 10–63 保留。**保留位为 1 的证书必须被拒绝**（包括 bit 8/9、bit 63、全 1 mask），不能忽略或当通配符；mask 0 表示无权限，不表示全部权限。位号只追加、不重排、不复用。

每个 RPC 在产生副作用前检查固定权限；`CreateKey`/`Sign` 审计 actor 来自证书 principal。CA 是授权根：CA 必须在签发时强制限制权限位，否则客户端可自行申请 `unseal.seal`/`key.sign`。详见 [mtls.md](mtls.md)、[ADR-0008](adr/0008-mtls-client-cert-permissions.md) 和 [ADR-0009](adr/0009-csr-certificate-issuance.md)。

### 证书签发

- Endpoint 在本机生成 ECDSA P-256 私钥和 PKCS#10 CSR（`signer-pki`，rcgen）；私钥可以再用 PKCS#8 PBES2（scrypt + AES-256-CBC）口令加密。
- CA 只使用 CSR 的公钥，并验证 CSR 自签名；CSR 请求的 SAN、EKU、keyUsage、有效期和扩展全部丢弃，证书内容来自 CA 的显式审批参数（principal、holder、permission mask、server SAN）。
- CA 私钥以加密 PKCS#8 保存，口令来自环境变量；`tls-sign-csr` 拒绝未加密的 CA key。CA key 是授权根，应离线保存或放入 HSM。
- 签发前检查 CA 的 `CA:TRUE`、`keyCertSign`、有效期和 key 匹配；签发后自检证书签名。桌面端导入证书时再校验 CA 签名、有效期、EKU 和证书/私钥匹配。

### 目标行为

- 消除“中间人替换 `session_public_key`”的 T12 风险；
- 服务端从客户端证书提取 principal 和 holder 集合，与 `SubmitUnsealShare` 的 `holder_id` 做绑定；
- 保留应用层 Ed25519 签名、会话 nonce 和每会话 X25519 加密，作为端到端防线；
- 新增客户端或调整权限只重签证书，不重启 signer；服务端证书/CA bundle 轮换仍需重启。

### 注意

- mTLS 不能替代授权：证书只证明“是谁”，权限位必须由 CA 签发策略保证；Holder 注册和 Ed25519 份额签名仍然必须校验。
- 如果 TLS 在反向代理终止，代理可以看到明文并能改写响应，客户端证书身份也会丢失；要保证端到端安全，应使用 TLS passthrough，或在代理到 signer 之间再加一段 mTLS。
- mTLS 已实现，但默认关闭；未配置 `[tls]` 时 gRPC 仍是明文，只能在本机或可信网络使用。生产环境必须启用。

## 19. KMS / HSM（🔍 评估未采用）

ADR-0005 明确 v0.1 不用 KMS 托管 KEK，以保持门限信任模型：如果 KMS 能单独解封，阈值就失去意义。未来可以把 operator 签名密钥或业务私钥放入 HSM，但 KEK 仍应由 Holder 份额控制。

## 20. 实现库与选型

| 库 | 用途 | 状态 |
| --- | --- | --- |
| `curve25519-dalek` 4 | Ristretto255、Scalar、点运算 | ✅ |
| `ed25519-dalek` 2 | Ed25519 签名/验签 | ✅ |
| `x25519-dalek` 2 | X25519 ECDH、静态密钥 | ✅ |
| `k256` 0.13 | secp256k1、ECDSA、RFC 6979 签名 | ✅ |
| `chacha20poly1305` 0.10 | XChaCha20-Poly1305 AEAD | ✅ |
| `hkdf` 0.12 + `sha2` 0.10 | HKDF-SHA256 和 SHA-256 | ✅ |
| `argon2` 0.5 | Argon2id 口令 KDF | ✅ |
| `rand` 0.8 | `OsRng` 随机数 | ✅ |
| `zeroize` 1 | 秘密内存擦除 | ✅ |
| `x509-parser` 0.18 | 解析客户端证书 SAN URI、校验 CA/证书签名 | ✅ |
| `rcgen` 0.14 | 生成 CA、endpoint key/CSR、签发证书 | ✅ |
| `pkcs8` 0.11 | 加密/解密 PKCS#8 私钥（PBES2） | ✅ |
| `sharks` | 旧 GF(256) Shamir | 🕘 已移除 |
| `vsss-rs` | 现成 VSS 实现 | 🔍 未采用：依赖 curve25519-dalek 5 的 `ff`/`group` trait，会与现有 4.x 依赖栈重复 |

### 为什么自研 Feldman

`vsss-rs` 6.0.1 需要 curve25519-dalek 5 和新的 trait 栈，而项目其余部分基于 4.x。为避免重复曲线实现和版本分裂，项目在 `crates/vss` 中基于 `curve25519-dalek` 4 实现 Feldman VSS，并记录在 ADR-0007。代价是这部分密码学代码是自研的，需要额外测试和审计。

## 21. 安全边界与已知限制

- **mTLS 默认关闭**：已实现，但未配置 `[tls]` 时 gRPC 仍是明文，服务端身份未认证；中间人可替换会话公钥。生产环境必须启用，见第 18 节。
- **CA key 只有文件级口令保护**：`ca.key.enc` 的 PBES2 口令不能阻止已控制 CA 主机或 `tls-sign-csr` 运行环境的攻击者签发证书；生产应使用离线 CA/HSM，并限制签发权限。CSR 流程降低私钥分发面，但不替代审批。
- **可信 dealer**：`signer-admin init` 在初始化时能看到全部明文份额；它必须被信任不会保留份额。
- **Feldman 的 C0 公开**：KEK 的群元素公开，隐藏性依赖离散对数假设。
- **自研 VSS**：`crates/vss` 未经独立审计；需要测试向量、外部评审和侧信道评估。
- **门限解封 ≠ 门限签名**：解封后完整 KEK 和私钥在单进程内存中；主机被攻破则门限失效。
- **Holder 身份/份额没有轮换**：丢失、泄露或人员变更需要重新初始化和分发。
- **ImportKey 尚未实现**：私钥导入必须等待 mTLS；当前不能安全地把已有私钥送入服务。
- **DEK 不缓存**：每次签名都会解包 DEK 并解密私钥，安全性较好但性能有限；缓存策略需要单独评审。
- **审计只覆盖部分操作**：CreateKey / Sign 已写入 `audit_log`；CreateKey 的密钥与审计在同一事务中提交，Sign 在审计提交后才返回签名。GetPublicKey / ListKeys 和 unseal 流程尚未审计。
- **口令强度**：Argon2id 只能提高离线猜测成本；弱口令仍可被爆破。WebView 中的口令副本无法可靠擦除。
- **非抗量子**：Ristretto255、X25519、Ed25519、secp256k1 都不是抗量子的；未来迁移需要新的群和签名方案。
- **侧信道**：实现依赖 dalek、chacha20poly1305 等库的常数时间性质；VSS 验证比较压缩字节，未做形式化侧信道分析。

## 22. 相关文档

- [解封协议](unseal-protocol.md)
- [VSS 解封方案](vss-unseal.md)
- [威胁模型](threat-model.md)
- [密钥生命周期](key-lifecycle.md)
- [ADR-0003：每密钥独立 DEK](adr/0003-per-key-dek.md)
- [ADR-0007：Ristretto255 Feldman VSS](adr/0007-vss-feldman-ristretto255.md)
