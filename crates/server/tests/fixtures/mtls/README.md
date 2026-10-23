# mTLS test fixtures

这些证书和私钥**仅用于本仓库的自动化测试**，由 `scripts/gen-test-certs.sh`
生成。它们没有、也不得用于任何真实环境。

- 有效期很长（36500 天），避免 CI 因证书过期失败。
- 不包含 CA 私钥；`ca.pem` 只作为测试信任根。
- `server.pem` 的 SAN 为 `DNS:localhost,IP:127.0.0.1`。
- 客户端证书带 `URI:signer://principal/<name>`、可选的
  `URI:signer://holder/<id>` 和 `URI:signer://permissions/0x<mask>`。

| 文件 | principal | 权限 | holder |
|---|---|---|---|
| `client-alice.pem` | alice | `unseal.start`, `unseal.status`, `key.read` | holder-1 |
| `client-bob.pem` | bob | `key.read` | — |
| `client-carol.pem` | carol | `key.sign`, `key.read` | — |
| `client-dave.pem` | dave | 无（mask 0） | — |
| `client-eve.pem` | eve | 保留位 `0x400`（服务端必须拒绝） | — |
| `client-rogue.pem` | rogue | `key.read`，由另一套 CA 签发 | — |

重新生成：

```bash
scripts/gen-test-certs.sh --force
```

不要把这些文件复制到 `data/tls`，也不要把真实 CA 私钥加入本目录。
