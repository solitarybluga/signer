# Signer Unseal Desktop

Tauri 2 桌面客户端，覆盖操作员和份额持有者的完整解封流程。顶部是「操作员」和「份额持有者」两个 tab；份额持有者内部再按「密钥分发」和「Unseal」两个流程划分，事件日志在下方常驻。

## 功能

**操作员**

- 发起解封会话、查看已收集份额与阈值进度、重新封存

**份额持有者 — 密钥分发**

- 生成身份：Ed25519 签名密钥 + X25519 加密密钥
- 导出公开信息（`holder.pub.json`），交给 operator 注册
- 导入 `signer-admin init` 生成的 `.share`
- 验证 operator 签名的 manifest（`manifest.json` + `manifest.sig` + `operator.pub`）
- 用 manifest 中的 VSS 承诺校验份额，解密后加密保存为本地 share vault

**份额持有者 — Unseal**

- 输入 Session ID、选择身份文件和 vault，解锁后提交
- 提交前从服务端取得会话 `nonce` 与临时 X25519 公钥，把份额加密到该公钥，并用 Holder Ed25519 私钥签名
- 查看当前会话已收集份额和阈值状态

## 运行

先启动 signer（默认监听 `127.0.0.1:50051`），然后：

```bash
cd desktop/src-tauri
cargo run
```

首次构建会下载 Tauri 依赖；Windows 需要 WebView2（Windows 11 已内置）。

## Holder 身份与 vault

- 身份文件（`.key`）：Ed25519 + X25519 私钥，使用口令经 **Argon2id** 派生的密钥 + XChaCha20-Poly1305 加密。
- Share vault（`.vault`）：解密后的 33 字节份额 + ceremony 元数据，使用**同一口令**但**独立 salt**派生密钥加密。
- 修改口令需要重新加密两个文件；当前 UI 暂不提供改口令功能。
- 两个文件都拒绝覆盖已有文件（导出公开信息除外）。

## 与 operator CLI 配合

1. Holder 在桌面端生成身份，导出 `holder.pub.json`，通过可信渠道交给 operator。
2. Operator 把各 holder 的 public bundle 汇总为 `holders.json`（数组）。
3. Operator 生成签名密钥并初始化：

```bash
cargo run -p signer-admin -- operator-keygen --out operator.key --pub-out operator.pub
cargo run -p signer-admin -- init \
  --data-dir data \
  --threshold 3 --total-shares 5 \
  --holders holders.json \
  --operator-key operator.key
```

4. 把每个 holder 的 `.share`、`manifest.json`、`manifest.sig`、`operator.pub` 交给对应 holder；通过**另一个渠道**公布 operator 公钥指纹。
5. Holder 在桌面端「导入份额」中验证 manifest、VSS 承诺并保存到 vault。可在「operator 指纹」中填入带外核对值；提供时会强制比对，不提供时 UI 会显示实际指纹并提示带外核对。建议把 `manifest.json`、`manifest.sig`、`operator.pub` 与 vault 一起归档，便于后续审计。
6. 解封时，Holder 在「提交份额」中粘贴 Session ID，选择身份文件和 vault、输入口令并提交；客户端会在本地完成加密和签名。

未提供 manifest 三项时，客户端按 legacy 方式导入：只校验信封和份额索引，**不验证 operator 签名，也不做 VSS 校验**。UI 会显示警告。

## 安全说明

- 口令输入在 WebView 中完成，调用后清空输入框；Rust 侧使用 `Zeroizing`，但无法擦除 JS/WebView 中的历史副本。只在可信设备上使用。
- 私钥和份额通过文件路径在 Rust 侧读取，不经过 JS；文件选择使用原生对话框。
- 份额在客户端加密到会话临时公钥并附 Ed25519 签名，明文份额不进入 gRPC；桌面端支持在顶部配置 CA、客户端证书和客户端私钥以启用 mTLS。未配置证书时使用明文，只适合本机或可信网络。
- Windows 没有 0600 权限语义，文件保护依赖用户目录 ACL；Unix 下新文件以 0600 创建。
- `bundle.active` 当前为 `false`，只支持 `cargo run`；需要安装包时再补图标和打包配置。
