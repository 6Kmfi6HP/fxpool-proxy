# 社区复刻项目与外部链接

> 来源：ntc.party 主题 [Firefox 149 поставляется с бесплатным VPN](https://ntc.party/t/22946)
> （417 帖，2026-03-19 → 2026-11-10）逐帖提取，`#N` 指 `/22946/N`。
> 仓库可用性在 2026-11-10 用 GitHub API 逐个核验；仅记录链接与定位，未审计第三方代码。
> 本文件不含账号、token、JWT、导出凭据或实测出口 IP。

## 1. 上游官方源码（协议与认证的事实来源）

| 链接 | 用途 | 出处 |
|------|------|------|
| [mozilla-firefox/firefox: toolkit/components/ipprotection](https://github.com/mozilla-firefox/firefox/tree/main/toolkit/components/ipprotection) | 内置 IP Protection 模块（代理生命周期、Guardian 客户端） | #104 |
| [mozilla-firefox/firefox: services/fxaccounts](https://github.com/mozilla-firefox/firefox/tree/main/services/fxaccounts) | FxA 客户端实现（登录、token、Cookie 签名） | #203 |
| [mozilla/fxa: packages/fxa-auth-client/lib](https://github.com/mozilla/fxa/tree/main/packages/fxa-auth-client/lib) | FxA 认证库，quickStretchV2 / 请求签名逻辑 | #203 |
| [mozilla.github.io/ecosystem-platform/api](https://mozilla.github.io/ecosystem-platform/api#section/Response-format) | FxA API 文档（`errno 110` 等错误语义） | #367, #377 |

对接细节见 [../research/protocol.md](protocol.md) 与 [../research/findings.md](findings.md)。

## 2. 独立客户端（去除 Firefox 依赖）

| 链接 | 形态 / 能力 | 出处 | 状态 |
|------|-------------|------|------|
| [UjuiUjuMandan/firefox-vpn-client](https://github.com/UjuiUjuMandan/firefox-vpn-client) | Go，`-h3`（HTTP/3）、`-session-token`；社区公认参考实现，Android 客户端多以此为基础 | #250, #251, #323, #394 | 可用 |
| [tututu-patch/firefox-vpn-proxy](https://github.com/tututu-patch/firefox-vpn-proxy) | 中文社区客户端 | #324 | 可用 |
| [multi-zhangyang/firefox-ip-protection-pool](https://github.com/multi-zhangyang/firefox-ip-protection-pool) | 多出口 → SOCKS5/HTTP 代理池 | #324 | 可用 |
| [Vauth/FoxyVPN](https://github.com/Vauth/FoxyVPN) | Android，非官方 Firefox VPN 客户端 | #347, #393 | 可用 |
| [armanlife/arman-vpn-client](https://github.com/armanlife/arman-vpn-client) | Android / Windows / macOS / Linux；自带 Mozilla 账号登录，支持 upstream SOCKS5 与 h1/h2/h3 | #421, #430 | 可用 |
| [M-RTZ1/FoxyVPN](https://github.com/M-RTZ1/FoxyVPN) | Windows | #421 | 可用 |
| [mostafa5804/foxyvpn_windows](https://github.com/mostafa5804/foxyvpn_windows) | Win10/11，Go + Wails v2 + Wintun，可做系统级 L3 VPN 或本地 SOCKS5/HTTP | #421 | 可用 |
| [omidrx0/RxFoxyVPN](https://github.com/omidrx0/RxFoxyVPN) | Android | #421 | 可用 |
| [meytiii/FoxyVPN-win](https://github.com/meytiii/FoxyVPN-win) | Windows | #421 | 可用 |
| [e3kskoy7wqk/Firefox-for-windows-7](https://github.com/e3kskoy7wqk/Firefox-for-windows-7/releases) | Win7 可用的 Firefox 构建（151 / 153a），内置 VPN 开关可直接用 | #69, #136, #301 | 可用（非独立客户端） |

> 帖内另有 tendy / user77 / Xunlei / Incos 直接挂附件的构建（`firefox-proxy.zip`、
> `ffproxy-tray.exe` 等），无独立仓库；节点清单、参数与版本演进见 #124–#146、#209、
> #239、#252–#253、#279–#291、#346、#371、#399–#406、#434–#443。

## 3. 相邻工具（DPI 绕过 / 代理前端）

| 链接 | 用途 | 出处 |
|------|------|------|
| [hufrea/byedpi](https://github.com/hufrea/byedpi) | C 实现 DPI 绕过，`--oob 1` 用于救活被 RST 的连接 | #268, #382 |
| [xvzc/spoofdpi](https://github.com/xvzc/spoofdpi) | Go 反审查工具，社区讨论与客户端拼接 | #378 |
| [Alexey71/opera-proxy](https://github.com/Alexey71/opera-proxy) | opera-proxy 维护分支；`-api-proxy` 用法被移植到 ff 客户端 | #328 |
| [SLY-F0X/opera-proxy-android-wrapper](https://github.com/SLY-F0X/opera-proxy-android-wrapper) | Opera 代理 Android 封装，Android 客户端的功能参照物 | #211, #348, #389 |
| [SLY-F0X/opera-proxy-android-wrapper: 3.0.21](https://github.com/SLY-F0X/opera-proxy-android-wrapper/releases/tag/3.0.21) | 具体 release，帖内推荐版本 | #348, #389 |
| [Zephyruso/zashboard](https://github.com/Zephyruso/zashboard) | sing-box 面板，出现在 masque 复用方案的 `external_ui` | #414 |
| [bropines/awg-wiresocks](https://github.com/bropines/awg-wiresocks) | 作为"无需 hack 的替代路径"被提及 | #198 |
| [microsoft/go: Downloads.md](https://github.com/microsoft/go/blob/microsoft/main/eng/doc/Downloads.md) | MS Build of Go 的 `GOEXPERIMENT=nosystemcrypto` 说明（编译 flags 参考） | #154 |

sing-box 侧的 MASQUE 复用配置见帖 #414（`type: http` outbound + `Proxy-Authorization`
+ `utls.fingerprint: firefox`），schema 来源 `SagerNet/sing-box`。

## 4. 失效 / 历史链接

| 链接 | 说明 |
|------|------|
| `github.com/STR97/STRUGOV/issues/15` | opera-proxy 代码版权争议 issue，帖内 #18 引用；**仓库已 404**（#5、#17、#19 讨论作者删库的先例） |

## 5. 使用注意

- 这些客户端都要消费 Mozilla 账号的 session/JWT，账号侧的风险与配额策略按上游变化
  （#195 FxA quickStretchV2、#415 Fastly 反机器人 406、#434 修复）。
- 免费层是 HTTPS/HTTP2 CONNECT 到 MASQUE 边缘，不是完整 MASQUE 隧道（#396）；
  需要 `private-key`/`public-key` 的 masque outbound 配置不适用（#372–#376）。
- 2026-05 后节点按 `${ICAO}${0-999}.m1.fastly-masque.net` 规律新增，节点清单会过期，
  应以 Remote Settings 的 `vpn-serverlist` 记录为准（#107, #145, #341）。
- 第三方客户端未经审计，仅从链接可见的 release 与 README 判断用途。
