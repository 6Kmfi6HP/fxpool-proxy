# 可切入的观测面（信息收集，非攻击）

逆向视角下值得跟踪的入口与信息源。仅针对本人有权使用的环境。

## A. 源码 / 文档（静态）

- `toolkit/components/ipprotection`（searchfox / 源码树）
- `browser/components/ipprotection` UI 层
- `browser/components/mozcachedohttp` — OHTTP，可能与 token 获取耦合
- source-docs：Components / Constants / Preferences / StateMachine
- 企业策略 `IPProtectionAvailable`

## B. 偏好（pref）

分类线索：

- feature enablement / experiments
- startup / caching
- **networking / routing**（代理地址、协议开关）
- UI / diagnostics
- Android / GPI

完整 pref 列表见 [findings.md](../research/findings.md) 与 source-docs Preferences 页。

## C. 网络观测（动态）

- `proxy-http-error` → `IPPNetworkErrorObserver`
- QUIC/HTTP3 抓包（`SSLKEYLOGFILE`）— 可选，本仓库数据面为 TCP
- Remote Settings：监控 `vpn-serverlist` 拉取

## D. 遥测

- `ipprotection.started` 等 Glean 事件
- 带宽用量相关标量（50GB/月）

## E. 认证

- FxA OAuth → ProxyPass JWT（`fxa/` / `GuardianClient`）
- Android `IPPGpiAuthProvider`：未登录免费路径（本仓库未实现）

## 建议顺序

1. Remote Settings server list（无需凭据即可同步公开列表）
2. FxA → Guardian token 兑换（源码 + 本人账号验证）
3. CONNECT 端到端；可选再抓 MASQUE wire 格式
