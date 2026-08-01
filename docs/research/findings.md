# IP Protection 逆向核心结论（findings）

> 基于 **Firefox 149.0 官方源码包** 静态分析，并结合独立代理实现的端到端验证（见 [verification-log](../notes/verification-log.md)）。
> 源码路径：`browser/components/ipprotection/` + `netwerk/`。

## 1. 总体架构

```
┌────────────────────────────────────────────────────────────────┐
│ Firefox (parent process)                                        │
│                                                                 │
│  IPProtectionService ── 服务级状态机                            │
│        │                                                        │
│  IPPProxyManager ── 代理连接生命周期                            │
│        │                                                        │
│  GuardianClient ── HTTPS → Guardian (vpn.mozilla.org)           │
│        │    获取 JWT ProxyPass + usage + entitlement             │
│        │                                                        │
│  IPPChannelFilter ── nsIProtocolProxyChannelFilter               │
│        │    把浏览器 channel 指向 MASQUE/CONNECT 代理            │
│        │                                                        │
│  Gecko netwerk 层                                               │
│   Http3ConnectUDPStream ── HTTP/3 CONNECT-UDP (RFC 9298)        │
│        │    URI 模板 /.well-known/masque/udp/{target}/{port}/   │
│        ▼                                                        │
│  Fastly egress proxy ── 以代理 IP 对外出站                       │
└────────────────────────────────────────────────────────────────┘
```

**两层分离**：控制平面（Guardian，HTTPS REST）与数据平面（MASQUE 隧道 / CONNECT fallback）。

## 2. 控制平面：Guardian 服务 API

生产端点：**`https://vpn.mozilla.org`**
（pref `browser.ipProtection.guardian.endpoint`）

### 2.1 认证流程

1. FxA 获取 OAuth token，scope：
   ```
   profile
   https://identity.mozilla.com/apps/vpn
   ```
   （注意：是 `apps/vpn`，不是 `apps/ipp`。）
2. 用 Bearer token 调 Guardian API。

### 2.2 API 端点（`GuardianClient.sys.mjs`）

| 方法 | HTTP | 路径 | 用途 |
|---|---|---|---|
| `fetchProxyPass` | GET | `/api/v1/fpn/token` | 换取 JWT ProxyPass |
| `fetchProxyUsage` | HEAD | `/api/v1/fpn/token` | 只查用量 |
| `fetchUserInfo` | GET | `/api/v1/fpn/status` | 查 entitlement |
| `enroll` | GET(重定向) | `/api/v1/fpn/auth?experiment=<type>` | OAuth enrollment |
| 成功回调 | — | `/oauth/success` | enrollment 完成 |
| 失败回调 | — | `/api/v1/fpn/error` | `?error=<msg>` |

- 控制平面：`Authorization: Bearer <FxA-OAuth-token>`
- 数据平面：另一套 **JWT ProxyPass**

### 2.3 JWT ProxyPass

- 响应体：`{ "token": "<JWT>" }`
- claims：`sub`、`aud`、`iat`、`nbf`、`exp`、`iss`
- 有效区间：`[nbf, exp)`；到期前约 **2 分钟** 自动轮换
- 实测有效期约 **600s**

### 2.4 用量（配额）响应头

```
X-Quota-Limit:     <最大字节数>
X-Quota-Remaining: <剩余字节数>
X-Quota-Reset:     <重置时间 ISO8601>
```

- 429 + `quota_exceeded` → PAUSED，尊重 `Retry-After`
- entitlement 中 `maxBytes` 为 BigInt 字符串（默认 50GB = `53687091200`）

### 2.5 Entitlement 字段

`GET /api/v1/fpn/status`：`autostart`、`created_at`、`limited_bandwidth`、
`location_controls`、`subscribed`、`uid`、`website_inclusion`、`maxBytes`

### 2.6 OAuth client id（GuardianClient 内映射）

| 环境 | endpoint | client id |
|---|---|---|
| prod | `https://fpn.firefox.com` / `https://vpn.mozilla.org` | `e6eb0d1e856335fc` |
| stage | `https://stage.vpn.nonprod.webservices.mozgcp.net` | `e6eb0d1e856335fc` |
| dev | `https://guardian-dev.herokuapp.com` | `64ef9b544a31bca8` |
| local | `http://localhost:3000` | `6089c54fdc970aed` |

> 独立代理实现另使用公开 client（如 `5882386c6d801776`）完成 OAuth；以各自实现与 FxA 注册为准。

## 3. 数据平面

### 3.1 MASQUE（Firefox 完整能力）

- HTTP/3 CONNECT-UDP（RFC 9298），`Http3ConnectUDPStream.cpp`
- URI 模板：`/.well-known/masque/udp/{target_host}/{target_port}/`
- `Proxy-Authorization: Bearer <JWT>`
- `connectionIsolationKey`：每连接随机，用于流隔离

### 3.2 CONNECT fallback（本仓库实现）

- 节点 hostname 形如 `<code>.m1.fastly-masque.net`，端口常见 `2499` 或记录指定值
- 协议：`HTTPS CONNECT` + `Proxy-Authorization: Bearer <JWT>`
- 本仓库不实现 MASQUE/HTTP3/QUIC/UDP

### 3.3 服务器列表（Remote Settings）

- collection：`vpn-serverlist`
- 结构：Country → cities → servers（hostname/port/quarantined/protocols）
- protocols：
  - `{name:"masque", host, port, templateString}`
  - `{name:"connect", host, port, scheme("https")}`
- 多协议 → fallback 链；无 protocols 时默认 `connect`
- 可用 pref `browser.ipProtection.override.serverlist` 注入调试 JSON

### 3.4 服务器选择（Firefox）

- `getDefaultLocation()` 固定选 US（alpha 行为）
- `selectServer(city)` 随机挑未 quarantine 的服务器

## 4. 代理模式（`IPPChannelFilter`）

`browser.ipProtection.mode`：

| 值 | 模式 |
|---|---|
| `0` | MODE_FULL — 全部流量 |
| `1` | MODE_PB — 仅隐私窗口 |
| `2` | MODE_TRACKER — 仅 tracker |
| `3` | MODE_INCLUSION — inclusion 列表 |

排除：本地地址、inclusion 例外、guardian/fxa/captivedetect 等系统 URL。

## 5. 关键 pref

```
browser.ipProtection.enabled
browser.ipProtection.optedOut
browser.ipProtection.features.autoStart
browser.ipProtection.userEnabled
browser.ipProtection.guardian.endpoint   # https://vpn.mozilla.org/
browser.ipProtection.log
browser.ipProtection.mode
browser.ipProtection.bandwidth.enabled
browser.ipProtection.egressLocationEnabled
browser.ipProtection.override.serverlist
browser.ipProtection.inclusion.match_patterns
```

## 6. 遥测（Glean）

- `ipprotection.started` / `stopped` / `paused` / `error` / `bandwidth_used_threshold`(50/75/90)

## 7. 验证状态

| 项 | 状态 |
|---|---|
| Remote Settings `vpn-serverlist` 实际拉取 | 已确认（约 26 国 + REC） |
| 认证链路 FxA → OAuth → Guardian → CONNECT | 已确认 |
| JWT `aud` / 签名密码学验证 | 结构校验有；签名验证未做（无稳定 JWKS） |
| CONNECT fallback 端到端 | 已确认 |
| QUIC/MASQUE 抓包 | 未做 |

## 参考源码

- `GuardianClient.sys.mjs` — 控制平面
- `IPPProxyManager.sys.mjs` — 连接生命周期
- `IPPChannelFilter.sys.mjs` — 代理注入
- `IPProtectionServerlist.sys.mjs` — 服务器列表
- `Http3ConnectUDPStream.cpp` — CONNECT-UDP
- `nsHttpChannelAuthProvider.cpp` — Proxy-Authorization 注入
