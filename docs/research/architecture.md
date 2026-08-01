# 架构与组件分析

来源：https://firefox-source-docs.mozilla.org/toolkit/ipprotection/ （2026-08-01）

## 1. 代码目录（官方确认）

- **`toolkit/components/ipprotection`** — 平台无关核心。无 browser UI/chrome 依赖。
  - 状态机、代理/网络栈、所有 core helpers
  - FxA 认证在子目录 `fxa/`
- **`browser/components/ipprotection`** — 浏览器 UI 层。
  - 面板 `IPProtectionPanel`、工具栏按钮、alert 与 infobar 管理器、onboarding

## 2. 组件清单（源码文档组件图）

### Toolkit 层

| 组件 | 职责 |
|---|---|
| `IPProtectionService` | 主状态机，管理资格判定与整体生命周期 |
| `IPPProxyManager` | 代理连接生命周期；监听 `IPProtectionService:StateChanged` 与 `proxy-http-error` |
| `IPProtectionActivator` | 组装全部 helper 列表并初始化 service |
| `IPPNetworkErrorObserver` | 观察代理 HTTP 错误（`proxy-http-error` 事件源） |
| `IPPAuthProvider` | 认证抽象接口，隔离 FxA 依赖 |
| `IPPFxaActivateAuthProvider` | 桌面端 FxA provider（browser 层注册） |
| `IPPAndroidAuthProvider` | Android FxA provider |
| `IPPGpiAuthProvider` | Android 未登录时的 provider（GPI） |
| `IPPUsageHelper` | 带宽用量（50GB 限额、月度循环） |
| `IPPOptOutHelper` | 用户 opt-out |
| `IPProtectionAlertManager` / `IPProtectionInfobarManager` | 提示 UI |

> helper 全名需以实际源码为准；本表来自官方文档组件页摘要。

## 3. 状态机要点

- 服务级状态机：`IPProtectionService` 判定资格 → 驱动代理层。
- 代理级状态机（`IPPProxyManager`）：
  - 服务 `READY` → 代理 `READY`（重置连接/错误历史）
  - 其他服务状态 → 代理 `NOT_READY`（停止活动连接）
  - `start(userAction)` from `READY` → `ACTIVATING` → `ACTIVE`（成功时发遥测 `ipprotection.started`）
  - 激活失败（缺 entitlement / server list / **proxy pass**）→ 回退上一状态
- **proxy pass** 暗示代理鉴权存在通行凭证机制（已在 findings 中确认：JWT ProxyPass）。

## 4. 认证链路

- 统一走 `IPPAuthProvider` 接口，FxA 依赖封闭在 `fxa/` 子目录。
- Desktop：provider 与 helpers 由 browser 层 `IPProtectionHelpers.sys.mjs` 注册。
- Android（GeckoView）：`GeckoViewIPProtection:Init` 读 pref `toolkit.ipProtection.android.authProvider`：
  - 已登录 FxA → `IPPAndroidAuthProvider`
  - 否则 → `IPPGpiAuthProvider`

## 5. 网络错误面

`IPPNetworkErrorObserver` 与 `proxy-http-error` 事件是观察代理协议的活体入口：
在未开通地区/无 entitlement 时触发，可捕获代理的真实响应码与 header。

## 6. 相关模块

- `browser/components/mozcachedohttp` — OHTTP relay/gateway 实现，与 ipprotection 的关系待确认。

## 参考链接

- [IP Protection 总览](https://firefox-source-docs.mozilla.org/toolkit/ipprotection/)
- [Components](https://firefox-source-docs.mozilla.org/toolkit/ipprotection/Components.html)
- [Constants](https://firefox-source-docs.mozilla.org/toolkit/ipprotection/Constants.html)
- [Preferences](https://firefox-source-docs.mozilla.org/toolkit/ipprotection/Preferences.html)
- [StateMachine](https://firefox-source-docs.mozilla.org/toolkit/ipprotection/StateMachine.html)
- [BandwidthUsageDisplay](https://firefox-source-docs.mozilla.org/toolkit/ipprotection/BandwidthUsageDisplay.html)
