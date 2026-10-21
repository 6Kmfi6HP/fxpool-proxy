# Firefox IP Protection 上游兼容性记录

更新时间：2026-07-28（整理入库：2026-08-01）

说明本地代理池如何对齐 Firefox 桌面端 IP Protection 的现行行为。
只记录公开协议与代码结构，不包含账号、会话、代理口令或运行时地址。

## 研究范围

- Firefox 桌面端 `fpn`（Firefox Private Network / IP Protection）授权链路。
- Remote Settings 的 `vpn-serverlist` 集合及其筛选、协议和缓存字段。
- Guardian token、配额响应和上游代理错误的兼容性。
- 本项目的 SOCKS5/HTTP 转发边界；Android `gpn` 不在范围内。

## 公开参考

1. [toolkit/components/ipprotection](https://searchfox.org/mozilla-central/source/toolkit/components/ipprotection)
2. [Remote Settings vpn-serverlist records](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records)
3. Guardian：https://vpn.mozilla.org
4. [Firefox version.txt](https://searchfox.org/firefox-main/source/browser/config/version.txt)
5. [GuardianClient.sys.mjs](https://searchfox.org/firefox-main/rev/4b4e59946a3db5ddf42ea730fc44c22a99877303/toolkit/components/ipprotection/fxa/GuardianClient.sys.mjs)
6. [vpn-serverlist metadata](https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist)

## 现行桌面链路

```text
FxA/OAuth
  -> Guardian 激活/状态
  -> GET /api/v1/fpn/token（ProxyPass JWT）
  -> TLS 连接 Fastly 节点
  -> HTTPS CONNECT + Proxy-Authorization: Bearer <JWT>
  -> 目标站点
```

Firefox 的 token、usage、status、activate 请求发送 `Content-Type: application/json` 并禁用缓存；
配额查询使用对 token 端点的 `HEAD`。代理层把 `401`/`403`/`407` 视为授权相关；
普通 `400` 不应盲目触发 token 刷新。

时序示意见 [firefox-ipp-flow.mmd](firefox-ipp-flow.mmd)。

## 上游变化与本地适配

| 上游行为 | 兼容策略 | 结果 |
|---|---|---|
| `filter_expression` 在选择记录前执行 | 受限 JEXL 子集；不识别则 fail closed | 不暴露版本不匹配节点 |
| 按 Firefox 版本门控的记录 | 跟随主干版本；可用 `FXPOOL_FIREFOX_VERSION` 覆盖 | 新旧记录选择一致 |
| `REC` 为推荐/任意出口 | 默认排除；`--recommended` 才用 | 不把 REC 当普通国家 |
| 记录缺端口 | 缺省 `443` 后做范围校验 | 兼容省略端口的记录 |
| 协议链 `masque` + `connect` | 解析 MASQUE 并标记 Supported，但实际未实现 | 不静默误用 MASQUE；运行时会失败 |
| `locked` / `quarantined` | 默认跳过 | 保守选健康节点 |
| Remote Settings `ETag`/`304` | `If-None-Match` + last-known-good | 减少请求、防坏缓存 |
| 节点列表重排 | 稳定身份 → `data/port-map.json` | 端口不漂移 |
| 多节点同国 | 综合入口先选国再选节点 | 国家等权 |
| Guardian JSON + no-cache | token/usage/status/activate 统一 header | 行为对齐 Firefox |
| `X-Quota-Unlimited` / 有限三元组 | unlimited 或严格校验 limit/remaining/reset | 坏 quota 不伪装 |
| 429/5xx / `Retry-After` | 有界重试、保留 last-good token | 避免刷新风暴 |
| JWT 验证（不含签名） | 结构、claims（sub/aud/iss/iat/nbf/exp）、域名匹配、时间窗口 | 坏 token 不覆盖 last-good；不验证签名 |

## 本地转发边界

- 默认启动全部可用非 `REC` 国家；综合入口国家等权。
- 默认 loopback；任一非回环监听必须完整鉴权（除非显式开放代理）。
- HTTP 明文仅 absolute-form `http://`；HTTPS 走 `CONNECT`。
- 拒绝 chunked、冲突/超限 `Content-Length`（上限 8MB），剥离 hop-by-hop。
- SOCKS 导出用 `socks5h://`（域名在代理端解析）。
- 仅 TCP CONNECT；无 MASQUE/HTTP3/UDP（代码中有 UDP 中继但文档未覆盖）。
- 端口范围：服务端记录缺端口时默认 443，本地分配端口从 `--socks-base`（默认 21000）和 `--http-base`（默认 31000）开始，范围校验 1-65535。

## 验证建议

```bash
./fxpool-proxy sync
./fxpool-proxy token-status
./fxpool-proxy usage
./fxpool-proxy probe --country COUNTRY_CODE
./fxpool-proxy run --rotate-mode random
go test ./...
```

只记录国家、协议、节点数量、HTTP 状态与地理结果摘要。
不要写入 JWT、FxA token、Cookie、密码或完整带认证代理 URL。

## 未覆盖的上游风险

1. **MASQUE/QUIC/UDP 未实现**；节点虽标记 `Supported: true` 但运行时不可用。未来可能弱化 CONNECT fallback。
2. **JWT 不验证 Guardian 签名**；若公布稳定 JWKS 应增加可选校验。
3. **未实现 Kinto canonical records**、P-384 内容签名与 Mozilla PKI 全链验证。
4. **Remote Settings / 配额 header 可能热更新**；保留 last-known-good 并回归测试。
5. **桌面 `fpn` 与 Android `gpn` 不可混用**。
6. **ProxyPass 拒绝记录无清理机制**；`rejected_proxy_pass.sha256` 持续增长可能影响启动。
7. **HTTP forward 限制 8MB body**；超出会返回 413，文档未说明。
8. **配额耗尽后仍接受新连接**；向上游发起注定失败的请求，增加延迟。
9. **测试覆盖率较低**；关键路径（JWT 验证、配额解析、节点过滤）边界情况可能未充分测试。
10. **节点选择失败无降级**；所有节点不可用时直接返回错误，未保留 last-good 列表。
