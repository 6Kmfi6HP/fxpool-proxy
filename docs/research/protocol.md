# 协议栈分析

## 1. 确认结论

- **MASQUE** 作为 Firefox 完整数据面的底层隧道协议（服务商 **Fastly**）。
- MASQUE 定义于 IETF [MASQUE WG](https://datatracker.ietf.org/wg/masque/about/)：
  - `CONNECT`（HTTP/2/3）→ RFC 9298（TCP/UDP 代理）
  - **`CONNECT-IP`** → draft-kuehlewind-masque-connect-ip（IP 层流转发）
- 源码实证（见 [findings.md](findings.md)）：Firefox 实现的是 **HTTP/3 CONNECT-UDP**（RFC 9298），
  URI 模板 `/.well-known/masque/udp/{target}/{port}/`。
- 本仓库 `fxpool-proxy` 仅实现 **HTTPS CONNECT**（TCP）fallback 路径，不实现 MASQUE/QUIC/UDP。

## 2. CONNECT-IP 关键语义（IETF draft 摘要）

- 客户端用 proxy 的 service address 建 HTTP/3 连接，发 CONNECT-IP 请求。
- Header：`IP-Version`（4 或 6）等结构化字段。
- proxy 从 IP 地址池借地址给客户端，转发客户端 IP 流。

## 3. 浏览器内可能的两条路径

| 路径 | 说明 | 状态 |
|---|---|---|
| A. 原生栈 | ipprotection 模块经 Gecko netwerk 实现 MASQUE / CONNECT | 已确认 |
| B. OHTTP 前置 | 通过 `moz-cached-ohttp` 匿名获取配置/token | 耦合关系待确认 |

## 4. 待确认 / 部分确认

| 项 | 状态 |
|---|---|
| MASQUE 用 CONNECT-UDP 还是 CONNECT-IP | 源码确认 CONNECT-UDP（RFC 9298） |
| 代理地址列表下发 | Remote Settings `vpn-serverlist`（已确认） |
| egress 鉴权 | `Proxy-Authorization: Bearer <ProxyPass JWT>`（已确认） |
| 50GB 限额 | Guardian 响应头 `X-Quota-*`（已确认） |
| 真实 QUIC 抓包 ALPN / SNI | 未做（本仓库数据面为 TCP CONNECT） |
| 遥测 `ipprotection.started` 通道 | 未深挖 |

## 5. 参考规范

- RFC 9298: https://www.rfc-editor.org/rfc/rfc9298
- draft-kuehlewind-masque-connect-ip: https://mirjak.github.io/draft-kuehlewind-masque-connect-ip/
- MASQUE WG: https://datatracker.ietf.org/wg/masque/about/
