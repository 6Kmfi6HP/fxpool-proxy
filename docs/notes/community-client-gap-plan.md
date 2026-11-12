# 社区客户端差距评估与实施计划

状态：Phase A–E 核心改造与实测已完成（DoH 单独立项，共享 H2/QUIC session 暂缓/不默认交付）  
日期：2026-11-10  
范围：将 `docs/research/community-clients.md` 的社区客户端能力与当前 `fxpool-proxy` 对照。第三方项目只作为能力线索，未审计其代码；服务端行为需在授权账号、网络和节点上验证。

## 1. 结论

本项目已经具备社区客户端中最接近本项目定位的核心能力：Remote Settings 节点发现、多节点 SOCKS5/HTTP 代理池、FxA 凭据导入与刷新、多账号存储、Guardian 配额读取，以及可选 MASQUE CONNECT-UDP 中继。无需另做一套基础代理池。

主要工程缺口是连接生命周期与资源管理、账号可用性策略、FxA 传输可靠性、UDP 能力边界验证、出口健康检查。Fastly 挑战自动求解、TLS 指纹伪装和通过畸形路径绕过地区限制不纳入实施计划；这些做法会规避服务端访问控制或地区策略。遇到拒绝时应保留明确错误，支持导入合法取得的凭据，并提供可诊断信息。

## 2. 现状与建议

| 项目 | 当前代码事实 | 评估与计划 |
|---|---|---|
| Fastly 406 与挑战页 | `internal/fxa/req.go` 的非 2xx 错误带 `Stage()`、`Status()`、`Errno()`、`EmptyBody()`；传输错误为 `TransportError{Stage,Err}`。406 经 `wafError` 保留诊断并匹配 `ErrWAFBlocked`。 | **不实现挑战求解器**，不解析/回传挑战、不伪造 clientmetrics 或 PAT。诊断只含阶段、状态码、是否空响应；不输出响应体或认证材料。 |
| FxA uTLS / Firefox ClientHello | `Manager.FxAClient` 与 `Manager.Client` 分离：FxA auth/OAuth 走前者，Guardian 走后者，Remote Settings 有自己的 client；均有测试。登录仍用浏览器形态 UA，Go transport。 | **不做 Firefox TLS 指纹伪装**，也不把 UA 当作规避 WAF 的承诺。2026-11-11 受控对照：`credentials/status` 的状态码随 UA 变化（旧 UA 400、浏览器 UA 406），`Accept-Encoding` identity/gzip/缺省三组结果相同；因此不启用 `identity`。 |
| 配额驱动多账号选择 | `store.Quota` 持久化；`accounts.Pool` 支持 opt-in `QuotaPolicy`（新鲜度、margin、reset、cooldown、后台刷新）。默认为纯 rr。`usage --all` 已取消配额合计。 | **已实施为可选过滤**：默认 rr 不变；未知/过期快照回退可用；全部账号被跳过时回退纯 rr。2026-11-11 抽样 4 个真实账号均为 `X-Quota-Unlimited: true`，无 limit/remaining/reset，故过滤实际不生效；未人为耗尽额度，429 语义未复现。不按剩余量加权，不合计账号配额。 |
| Guardian 451 地区错误 | `internal/token/manager.go` 已将 451 单独分类并持久化为 `unavailable_in_region`，包装为 `regionUnavailableError`；`accounts.Pool` 遇到该错误立即停止切号，保留原错误。 | **已实施分类与止损，不实现绕过**：不实现双斜杠路径或其他绕过 CDN/地区限制的请求路径，不自动切 relay 规避地区拒绝。仅保留可操作但不敏感的诊断；若服务端提供官方 relay/地区恢复流程，再按其文档接入。 |
| JWT 时钟偏差 | `internal/token/jwt.go` 的容差为有界常量（`nbf` +30s、`iat` +300s），边界测试覆盖快/慢时钟与 minTTL；`clock-check` 用可信 HTTPS `Date` 报告偏差（`ServerDateOffset`）。 | **只观测，不改写**：偏差不参与 claims 修改，`exp` 永不延长；超出一小时 skew 的 token 仍拒绝。 |
| UDP 目的端口与 DNS | `internal/pool/udp.go` 透传 SOCKS UDP 目的地址；`udp-probe` 已可在授权节点逐端口测 CONNECT-UDP。2026-11-11 实测 `us.m1.fastly-masque.net:2499` 接受 80/443/3478/51820/8080/8443，拒绝 53/123/500/1194/1900/4500（HTTP 502）。 | **已探测，策略归服务端**：客户端不做端口白名单，确保服务端策略变化时不被本地规则卡住；拒绝时数据报被丢弃并计数/限速记录。SOCKS5 UDP ASSOCIATE 没有逐数据报错误码，不能承诺 CONNECT 式错误。DNS-over-HTTPS 单独立项。 |
| TCP relay 半关闭 | `internal/pool/proxy.go` 的 `relay` 等待双向复制完成、客户端侧半关闭透传 `CloseWrite`（`bufferedConn` 对 `*tls.Conn` 不发送 `close_notify`，避免 Fastly 提前拆除 CONNECT 隧道），并具备活动感知的 `DrainTimeout`（默认 5s）、`IdleTimeout`（默认 10m）与 `MaxConns`（默认 512）；`socksReply` 映射 CONNECT 失败到 `0x02`/`0x03`/`0x04`/`0x05`/`0x06`/`0x01`。 | **已修复**：一侧 EOF 后保持隧道直至对端回包或活动感知 drain 超时；空闲超时和并发上限防止连接与 goroutine 泄漏。 |
| TCP 上游 H2 复用 | 需以 `internal/upstream/dialer.go` 当前建连方式为实施基线；当前计划目标是避免每个目标都重复 TLS/CONNECT 建连成本。 | **性能阶段评估**：确认 Fastly CONNECT 端点支持的 HTTP 版本、Go HTTP/2 隧道实现边界和取消语义，再决定是否引入可多路复用的 H2 session。必须保留节点/出口粘性；token 续期只更新新请求鉴权状态，不因刷新无故重建健康 session。PING/故障判定阈值须由测试确定，不照抄第三方常量。 |
| MASQUE QUIC 复用与 UDP 生命周期 | `internal/pool/udp.go` 以 `client|destination` 建 tunnel；已有空闲回收、每客户端上限、节点轮询和并发关闭保护。`masque-go` 提供 `Transport.NewClientConn`，可在一条 QUIC 连接上开多个 CONNECT-UDP stream。 | **复用时序：先基准后交付**。当前每次 tunnel 新建 QUIC 连接（实测建连 0.4–2.0s）。共享连接需保持节点/出口粘性、token 刷新不重建健康连接、连接空闲/故障回收，并验证响应仍路由到正确客户端。先在 Phase E 做 fresh-vs-reused 基准和出口一致性测试，再决定是否引入连接池；未测前不交付。 |
| 出口验证 | `probe` 经节点 CONNECT 采样 ipinfo.io 与 ifconfig.co，比较国家/城市/ASN；另测 IPv4 与 IPv6 出口。报告不输出 IP。 | **已实现警告式观测**：国家不一致、来源分歧只写入 `warnings`，不自动封禁；`REC` 不作为期望国家。2026-11-11 实测 US 节点：两来源均 US、IPv4/IPv6 均可达、无告警。 |

## 3. 实施顺序

### Phase A — 正确性与边界

1. 修复 TCP relay 等待两个方向、半关闭和有限 drain；加入有界空闲超时与连接上限。
2. 补 SOCKS5 错误码映射及其测试。
3. 将 Guardian 451 识别为地区不可用状态，只改错误分类与提示，不绕过限制。
4. 更新 README 对 UDP/DNS 的准确描述，待探测后再声明可用端口和 DNS 行为。

**验收：** EOF 后服务端仍可完成回包；一侧断开不会立即截断另一侧；超时能关闭连接并释放 goroutine；CONNECT 错误码符合可判断的 SOCKS5 状态；451 不触发隐式重试/换路径。

**进展（2026-11-11）：**
- `proxy.go` 与 `dialer.go`：`trackedConn` 透传 `CloseWrite`（`bufferedConn` 对 `*tls.Conn` 跳过 `close_notify`，避免 Fastly CONNECT 隧道在客户端半关闭时提前断开）；`relay` 等待双向复制结束，提供 `DrainTimeout`（默认 `5s`）、`IdleTimeout`（默认 `10m`，`--idle-timeout`）与 `MaxConns`（默认 `512`，`--max-conns`）；`socksReply` 映射网络/超时/DNS/上游鉴权错误到 SOCKS5 回复码。
- `token/manager.go`、`state.go`、`accounts/pool.go`：451 分类并持久化为 `unavailable_in_region`，`Pool.Ensure` 遇到 `IsUnavailableInRegion` 立即终止切号。
- `README.md` 已更新 UDP 端口策略边界、实测表与未实现 DoH 的说明。
- 测试：`TestRelayHalfCloseDeliversResponse`、`TestRelayDrainTimeout`、`TestRelayDrainDoesNotTruncateActiveResponse`、`TestIdleTimeoutClosesConn`、`TestIdleTimeoutKeepsActiveUpload`、`TestMaxConnsRejectsExcess`、`TestSOCKSReplyMapping`、`TestBufferedConnCloseWrite`、`TestRefresh451PersistsRegionState`、`TestPoolStopsOnRegionUnavailable`。

### Phase B — UDP 资源管理与实测

1. 建立授权节点 CONNECT-UDP 端口探针，保存不含凭据的状态摘要。
2. 增加 tunnel idle GC、per-client 上限和并发创建/关闭测试。
3. 基于探测结果定义端口策略；DNS-over-HTTPS 单独立项，不与 UDP relay 混在一起。
4. 评估每节点 QUIC 连接复用和 stream 生命周期。

**验收：** 空闲 tunnel 在设定时限内关闭；客户端达到上限时行为可预测；关闭与写入竞态无 panic/leak；端口策略只依据当前验证结果；DNS 能明确展示请求是否经 DoH 转发。

**进展（2026-11-11）：**
- `udp.go` 增加 `IdleTimeout` 清扫、`MaxTunnelsPerClient` 上限、节点轮询、写/关闭锁和 `Stats()`；并发创建同一 `client|destination` 时只保留一个 tunnel。
- 测试：`TestUDPServerIdleReclaimsTunnel`、`TestUDPServerPerClientTunnelLimit`、`TestUDPServerConcurrentSweepAndWrites`（`-race` 通过）。
- `udp-probe` 输出脱敏 JSON（hostname、目标、端口、隧道状态、耗时、错误）；实测端口表见 README。
- 默认 `--udp-idle-timeout=2m`、`--udp-max-tunnels-client=64`，`0` 关闭。
- QUIC 复用：决定推迟到 Phase E，先测收益与出口粘性；见上表。

### Phase C — 认证传输与时钟

1. 增加 FxA 406、网络错误和响应头的可测试诊断，不存储或输出挑战/认证材料。
2. 以官方兼容契约验证 FxA transport；单独评估 `Accept-Encoding`，不引入指纹伪装。
3. 增加本机时钟偏差观测和有界 JWT 时间验证策略。

**验收：** 406 仍清楚提示合法导入路径；FxA、Guardian、Remote Settings 传输配置互不串用；JWT 的有效截止时刻从不晚于签名 `exp`。

**进展（2026-11-11）：**
- FxA 错误诊断：阶段、状态码、errno、空响应体；406 包装保留 `errors.Is(ErrWAFBlocked)` 与 `errors.As(*errnoError)`。
- 传输隔离：`Manager.FxAClient` 用于 auth/OAuth，`Client` 用于 Guardian；`TestLoginUsesFxAClient`、`TestGuardianTransportIsolatedFromFxA`。
- `Accept-Encoding` 对照：同一 FxA 端点分别发送无头、`gzip`、`identity`，状态码均为 400（无请求体时），无可观测差异。决定不设置 `identity`、不伪造浏览器请求头，保持 Go 默认传输行为。
- 时钟偏差：`token.ServerDateOffset` 读取可信 HTTPS `Date`，`fxpool-proxy clock` 输出偏移；JWT 仅使用有界容差，绝不延长签名 `exp`。
- `Accept-Encoding` 受控对照无差异，未启用。
- `clock-check` 实测本机偏差 +1s（Date 分辨率 1s）。
- JWT 容差边界与 minTTL 测试：`TestJWTBoundedClockTolerance`、`TestJWTMinTTLBoundaryAndExpUnchanged`。

### Phase D — 多账号配额策略

1. 验证 quota 单位、过期语义、429 范围以及多账号自动切换的服务条款边界。
2. 设计 quota snapshot 的新鲜度、未知额度回退、冷却和恢复状态。
3. 在确认允许后实现候选过滤，默认策略先保持 rr；另行评估 margin 与探测周期。

**进展（2026-11-11）：**
- 实测：4 个账号均为 `X-Quota-Unlimited: true`，无 `X-Quota-Limit/Remaining/Reset`；过滤对这类账号不生效。未为避免风险而人为耗尽额度，429 未复现。
- `accounts.QuotaPolicy`：新鲜度 `MaxAge`、`MarginBytes`、`Cooldown`、`Now` 测试缝；`Pool.RefreshQuotas` 后台刷新；默认关闭。
- 选择顺序：先可用候选，全部不可用时回退 rr；451 仍立即停止且保留 region 标记。
- `usage --all` 不再把多账号配额相加。
- 测试：`TestQuotaPolicySkipsExhaustedAccount`、`TestQuotaPolicyFallbackWhenAllExhausted`、`TestQuotaEligibilityRecovery`、`TestParseQuotaReset`。

**验收：** 0 额度和明确账号级冷却账号不会被选择；未知/陈旧 quota 不会被误判为 0；不把账号配额求和或宣传为绕过服务限制；状态重启后可恢复且不泄漏凭据。

### Phase E — 出口观测与性能

1. 扩展 probe 到 IPv4/IPv6 和多个 geo 来源，增加国家不匹配告警。
2. 基准测试 TLS/H2 session 复用的收益、出口粘性和 token 更新行为。
3. 只有基准与故障测试证明收益后，再决定是否交付共享 H2/QUIC session。

**验收：** 能区分节点不可用、地址族不可达、地理信息不一致；复用前后出口稳定性符合设计；连接失败后 session 可回收，后台 goroutine 和缓存有明确上限。

**进展（2026-11-11）：**
- `probe` 扩展为双来源 + 双栈；告警不封禁。实测 US 节点两来源一致（US），IPv4/IPv6 均可达。
- 隧道基准（DE 节点，ipinfo.io）：新建 CONNECT 7 次，建连 661–2244ms；每条新隧道得到不同出口 IP（7 个唯一）。单条隧道内 7 次 keep-alive 请求各约 326–349ms，出口 IP 始终相同（1 个唯一）。
- **决定：不默认交付共享 session**。复用可省 0.7–2.2s 建连，但会把“每条新隧道轮换出口 IP”改为粘性出口，且 H2 Extended CONNECT 支持未验证；若实现须 opt-in，并按账号/节点隔离。
- 失败回收测试：CONNECT 401 触发一次 Reject + 强制刷新并重试新 token；503 不触发刷新。

## 4. 暂缓或不实施项

- 自动解析/回答 Fastly challenge、伪造浏览器遥测或凭据、伪造 PAT/cookie。
- 通过特殊 URL 形态绕过 HTTP 451 或地区策略。
- 以 Firefox ClientHello 指纹伪装规避服务端识别。
- 未确认服务条款和 Guardian 配额语义前，以多个账号累加或绕过单账号额度。
- 未有本项目节点实测前，将第三方报告的 UDP 端口列表写成保证，或声称普通 DNS 已可经该路径工作。

## 5. 参考与代码落点

- 社区线索：[community-clients.md](../research/community-clients.md)，其中注明第三方代码未经审计。
- FxA 请求与错误：[internal/fxa/req.go](../../internal/fxa/req.go)、[internal/fxa/login.go](../../internal/fxa/login.go)
- Token 状态与 JWT：[internal/token/manager.go](../../internal/token/manager.go)、[internal/token/jwt.go](../../internal/token/jwt.go)
- 账号池与配额：[internal/accounts/pool.go](../../internal/accounts/pool.go)、[internal/store/store.go](../../internal/store/store.go)
- TCP/UDP relay：[internal/pool/proxy.go](../../internal/pool/proxy.go)、[internal/pool/udp.go](../../internal/pool/udp.go)
- 运行和命令装配：[cmd/fxpool-proxy/main.go](../../cmd/fxpool-proxy/main.go)

实现前须更新对应阶段的实测证据与验收结果；本计划中的社区行为摘要不等于本项目已复现或已验证。
