# ADR-0007：使用 Ristretto255 Feldman VSS 校验 KEK 份额

- 状态：已接受
- 日期：2026-10-21

## 背景

v0.1 的 KEK 使用 `sharks` 的 GF(256) Shamir 分享。持有者无法验证自己收到的份额是否由一致的 polynomial 生成；服务端也只能在收集到阈值、重建失败后才发现坏份额。已有 manifest 能验证信封哈希，但不能替代份额一致性校验。

标准 Feldman/Pedersen VSS 需要素数域和群承诺，无法直接应用到 GF(256) 的逐字节分享。

## 决策

- 使用 **Ristretto255 + Feldman VSS**：
  - 秘密 `s` 是 Ristretto255 标量域中的随机标量；
  - 分享 polynomial `f(x) = s + a_1x + ... + a_{t-1}x^{t-1} mod l`；
  - 份额为 `(i, f(i))`，编码为 33 字节；
  - 承诺为 `C_j = a_j·G`；
  - 验证公式为 `y_i·G == Σ i^j·C_j`；
  - 恢复后验证 `s·G == C_0`，再执行 KEK check。
- 在 `crates/vss` 中基于 `curve25519-dalek` 4.1.3 的 `RistrettoPoint` / `Scalar` 实现，不引入 `vsss-rs`。
- 采用 clean break：`kek_check.json` v2、manifest v2、vault v2；后续安全改动将 `kek_check.json` 升到 v3（登记 Holder Ed25519 公钥），manifest/vault 仍为 v2。
- 服务端从 `kek_check.json` 读取 commitments、holder/index 和 Ed25519 公钥；manifest 作为持有者侧输入。
- `SubmitUnsealShareRequest` 的 `share_index` 为必填；提交携带 `encrypted_share`、`nonce` 和 Ed25519 签名，服务端验签/解密后才做 VSS 校验。

## 备选方案

| 方案 | 结论 |
|---|---|
| 保持 `sharks` + 不引入 VSS | 拒绝：无法逐份验证，坏份额会导致会话失败 |
| 在 GF(256) 上自造哈希承诺 | 拒绝：缺少与多项式求值兼容的线性同态承诺，容易设计出错误协议 |
| 使用 `vsss-rs` | 暂不采用：6.0.1 依赖 curve25519-dalek 5 的 `ff`/`group` trait，会与现有 4.1.3 依赖栈重复 |
| Pedersen VSS | 不采用：需要额外生成元和承诺，当前只需一致性，不需要信息论隐藏 |
| 基于 `k256` 的 Feldman VSS | 备选：会增加 secp256k1 依赖；Ristretto255 已在依赖树中 |

## 影响

- 正面：
  - 持有者在导入时即可发现不一致份额；
  - 服务端逐份拒绝坏份额，会话保持 `Collecting`；
  - 重建结果多一层 `C_0` 校验；
  - 份额长度保持 33 字节，信封格式不变。
- 负面：
  - 更换了分享方案，旧 ceremony 和旧 share 不兼容；
  - `crates/vss` 是自研密码学代码，需要额外的测试向量和审计；
  - `C_0` 公开 KEK 的群元素；Feldman 的隐藏性依赖离散对数假设；
  - VSS 本身不认证提交者；后续已用 Holder Ed25519 签名、session nonce 绑定和每会话 X25519 加密补齐（gRPC TLS 仍待接入）。
- 兼容性：
  - 服务端拒绝 `kek_check.json` v1/v2，只接受 v3；
  - manifest v1（无 `vss`）仍可被持有者作为 legacy 导入，但不会设置 `vss_verified`。

## 参考

- [Feldman, 1987](https://www.cs.umd.edu/~gasarch/TOPICS/secretsharing/feldmanVSS.pdf)
- [Ristretto255](https://ristretto.group/)
- [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
- [VSS 改造方案](../vss-unseal.md)
