# 实测验证日志（已脱敏）

日期：2026-08-01  
环境：macOS 开发机 + Firefox ≥149 + 本人有资格的 FxA

> 本文已移除账号标识、profile 路径、session/JWT、以及实测出口 IP。
> 只保留可公开复述的协议结论与统计摘要。

## 背景

对 Firefox IP Protection（Guardian ProxyPass + Fastly CONNECT）做端到端验证，
作为逆向结论的实证依据。实现形态先后覆盖 Python 参考实现与本仓库 Go 实现
（`fxpool-proxy`）；链路与节点行为一致。

## 验证环境（摘要）

| 项 | 值 |
|---|---|
| Firefox | ≥149（实测 152.x） |
| 账号资格 | 本人 FxA，已启用 IP Protection；entitlement 含约 50GB 月配额 |
| 关键 prefs | `browser.ipProtection.enabled=true`；egress 可选（如 REC） |
| 凭据 | 最小续期包 `{schema, email, uid, session_token}`，权限 `0600`，不入文档 |

## 单元测试

参考实现：`python -m unittest discover -s tests -v` → 全通过。  
本仓库：`go test ./...`（见根 README / CI）。

## 节点同步（无凭据可复现）

`sync` 从 Remote Settings `vpn-serverlist` 拉到约 **27 条 / 26 国 + REC**。
缓存至 `data/vpn-serverlist.json`。

## 认证链路（本人账号实测通过）

```
FxA session_token（本机 signedInUser.json）
  → OAuth2 authorize_token
  → scope = "profile https://identity.mozilla.com/apps/vpn"
  → GET https://vpn.mozilla.org/api/v1/fpn/token
  → ProxyPass JWT（约 10 分钟有效期）
  → HTTPS CONNECT + Proxy-Authorization: Bearer <JWT>
```

公开端点：

| 角色 | URL |
|---|---|
| FxA API | `https://api.accounts.firefox.com/v1` |
| OAuth | `https://oauth.accounts.firefox.com/v1` |
| Guardian | `https://vpn.mozilla.org` → `GET /api/v1/fpn/token` |
| 出口节点 | `<code>.m1.fastly-masque.net:<port>`，协议 `connect` |

结果摘要：`last_status=200`，`automatic_renewal_ready=true`，ProxyPass TTL ≈ 600s，
续期策略约 30s 检查、到期前 120s 刷新。

## 代理池（26 国连通性）

为各出口节点建立独立 SOCKS5 / HTTP 监听，并提供综合随机入口
（默认 SOCKS5 `:1090` / HTTP `:8080`）。

端到端探测（经代理访问公开 IP 查询服务）摘要：

| 入口类型 | 结果 |
|---|---|
| 综合随机 | 出口落在启用国家之一；归属 AS54113 Fastly |
| 独立国家节点（抽样 AT/FR/GB/DE/JP 等） | CONNECT 成功；出口 hostname 形如 `ip-*.vpn.firefox.com` |
| HTTPS 目标（如 google.com） | HTTP 200 量级成功 |

具体出口 IP、本机监听口令、带认证 URL **不在此记录**。

## 已证实结论

1. OAuth scope 为 `apps/vpn`（Mozilla VPN 家族），与浏览器 IPP 共用 Guardian `/api/v1/fpn/token`。
2. 本仓库数据面为 **HTTPS CONNECT**；Firefox 完整能力含 MASQUE/HTTP3，此处未实现。
3. 节点发现：Remote Settings `vpn-serverlist`（country/city/hostname/port/protocols/filter_expression 等）。
4. 配额：Guardian `429` + `Retry-After` / `X-Quota-*`；客户端尊重配额，不绕过。
5. FxA `session_token` 为长期续期根；最小续期包即可离线换 OAuth + ProxyPass。

## 已知局限

- JWT 只做结构/claims 校验，不做签名密码学验证。
- Remote Settings 未做 Kinto canonical records / P-384 内容签名 / Mozilla PKI 全链验证。
- 无 MASQUE/HTTP3/QUIC/UDP。
- 端口→节点映射由 `data/port-map.json` 稳定化。

## 本地部署注意（不含敏感值）

- 凭据：`tokens/renewal_credentials.json`、`tokens/proxy_pass.jwt`（`0600`）
- 导出：`export/pool.json`、`export/socks5.txt`、`export/http.txt` 等
- **禁止**将 `tokens/`、带认证导出、日志中的凭据提交 git 或分享

## 相关文档

- [findings.md](../research/findings.md)
- [firefox-upstream-compatibility.md](../compatibility/firefox-upstream-compatibility.md)
- [extract-token-from-firefox.md](../guides/extract-token-from-firefox.md)
- 仓库 [README.md](../../README.md)
