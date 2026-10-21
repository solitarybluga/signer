# Signer Unseal Desktop

Tauri 2 桌面客户端，用于可视化解封流程：

- 操作员：发起解封会话、查看已收集份额与阈值进度、重新封存
- 份额持有者：粘贴 Session ID、填写持有者标识，选择自己的私钥和 `data/shares/<id>.share` 文件

## 运行

先启动 signer（默认监听 `127.0.0.1:50051`），然后：

```bash
cd desktop/src-tauri
cargo run
```

首次构建会下载 Tauri 依赖；Windows 需要 WebView2（Windows 11 已内置）。

## 说明

- 前端为 `desktop/ui/` 下的纯 HTML/CSS/JS，无需 Node 或打包器
- Rust 侧通过 tonic 客户端调用 signer 的 gRPC 接口
- 份额文件由 `signer-admin init` 生成并用持有者 X25519 公钥加密，客户端在本地解密后提交
- v0.1 的 gRPC 份额传输未加密，客户端仅适合本机或可信网络演示
- `bundle.active` 当前为 `false`，只支持 `cargo run`；需要安装包时再补图标和打包配置
