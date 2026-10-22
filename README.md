# fxpool-proxy

纯 Go 实现的本地 SOCKS5 / HTTP 代理池：把流量经 Firefox IP Protection
（Mozilla Guardian ProxyPass + TLS HTTP CONNECT）送出，并自动续期凭据、
同步 Remote Settings 节点列表。可选配置 `--masque-uri` 后，额外提供
**SOCKS5 UDP ASSOCIATE 中继**，把 UDP 流量经 **MASQUE（HTTP/3 CONNECT-UDP，
RFC 9298）** 隧道出口。

TCP 流量始终走 HTTPS CONNECT；MASQUE CONNECT-UDP 只承载 UDP（如 QUIC/HTTP3/DNS），
由 `--masque-uri` 指向的代理端点承担。不支持 MASQUE/HTTP3 时行为与旧版一致。
未知上游协议、未知过滤表达式、未鉴权的非回环监听均会 fail closed。
与 Mozilla / Firefox / Fastly 无官方隶属关系。

要求 Go 1.26.10+（一键安装会自动 `go build`）。Linux 建议配合 systemd。

## 下载发布版本

从 [GitHub Releases](https://github.com/6Kmfi6HP/fxpool-proxy/releases) 下载与系统、
架构匹配的压缩包。每个包包含二进制、README 和 LICENSE；Linux 包还包含
`install.sh`。校验下载文件（示例使用 GNU `sha256sum`）：

```bash
sha256sum -c checksums.txt --ignore-missing
./fxpool-proxy version
```

也可用 GitHub CLI 验证构建来源证明：

```bash
gh attestation verify fxpool-proxy_v0.1.0_linux_amd64.tar.gz \
  --repo 6Kmfi6HP/fxpool-proxy
```

## Docker

镜像发布到 `ghcr.io/6kmfi6hp/fxpool-proxy`，支持 Linux amd64/arm64。容器以
非 root 用户运行，运行数据保存在 `/var/lib/fxpool`。容器默认监听所有接口，
因此必须提供成对的本地代理用户名和密码，否则安全检查会拒绝启动：

```bash
docker run -d --name fxpool-proxy \
  -p 1090:1090 -p 8080:8080 \
  -e FXPOOL_LISTEN_USER=fxpool \
  -e FXPOOL_LISTEN_PASS='replace-with-a-strong-password' \
  -v fxpool-data:/var/lib/fxpool \
  ghcr.io/6kmfi6hp/fxpool-proxy:0.1.0
```

需要从主机导入续期凭据时，优先将凭据复制进持久卷并保持 `0600` 权限；不要
把凭据构建进镜像或提交到仓库。稳定版同时发布完整版本、minor、major、
`latest` 和 `sha-<commit>` 标签；预发布版只发布完整版本与提交 SHA 标签。

## 一键安装

在部署目录执行：

```bash
chmod +x install.sh
./install.sh
```

默认动作 `install` 会：

1. 构建 `./fxpool-proxy`（若尚无可执行文件）
2. 创建 `tokens/` `data/` `export/` `logs/`
3. 写入 `fxpool-proxy.env`（若不存在，权限 `0600`）
4. 安装 systemd 单元并 `enable --now`
   - root → 系统单元 `/etc/systemd/system/fxpool-proxy.service`
   - 普通用户 → 用户单元 `~/.config/systemd/user/fxpool-proxy.service`

```bash
./install.sh status     # 查看状态
./install.sh restart    # 重启
./install.sh stop       # 停止
./install.sh uninstall  # 禁用并删除单元（保留二进制与数据）
./install.sh run        # 前台运行（不经 systemd；可先 token-refresh）
./install.sh --help
```

安装后导入凭据（注册机生成的凭据包，或本机 Firefox 导出）：

```bash
# 无 Firefox：在注册机生成 fxpool-bundles/<uid>.json 后
./fxpool-proxy import-credentials /path/to/<uid>.json --delete-source
# 或本机 Firefox
./fxpool-proxy export-credentials --import
./install.sh restart
```

注册机路径见 [docs/guides/headless-credentials.md](docs/guides/headless-credentials.md)。

编辑 `fxpool-proxy.env` 配置监听与鉴权，例如非回环：

```bash
FXPOOL_BIND=0.0.0.0
FXPOOL_LISTEN_USER=fxpool
FXPOOL_LISTEN_PASS=change-me
```

不要把密码写进 unit 或命令行；改完 env 后 `./install.sh restart`。

无 systemd（如 macOS 开发机）可只用前台：

```bash
./install.sh run
```

## 手动构建

```bash
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o fxpool-proxy ./cmd/fxpool-proxy
make cross   # /tmp/fxpool-proxy-linux-{amd64,arm64}
```

## 凭据

凭据包等同 FxA 登录会话，权限应为 `0600`，不要提交或分享。
三种获取方式：注册机（推荐，无需本机 Firefox）、`login`、从本机 Firefox 导出。
账号级数据（凭据、ProxyPass、刷新状态、拒绝列表）保存在 `data/fxpool.db`
（SQLite，权限 `0600`）；首次启动账号模式时会离线、幂等地把旧
`tokens/renewal_credentials.json`、`proxy_pass.jwt`、`refresh_state.json`
迁移进数据库，旧文件保持原位不动。

| 场景 | 命令 |
|------|------|
| 注册机生成账号、凭据包并开通（在注册机目录，无需 Firefox） | `python register.py --backend browser --count 1 --enroll --bundle-dir fxpool-bundles` |
| 在代理机导入凭据包 | `./fxpool-proxy import-credentials <uid>.json --delete-source` |
| 注册机与代理同机，直接写入 `tokens/`（在注册机目录） | `python register.py --backend browser --count 1 --enroll --fxpool-root /opt/fxpool` |
| 邮箱+密码自动登录（仅限未被 WAF 拦截的网络） | `./fxpool-proxy login` |
| 列出本机 Firefox 配置 | `./fxpool-proxy export-credentials --list` |
| 导出续期包 | `./fxpool-proxy export-credentials -o bundle.json` |
| 导出并写入 `tokens/` | `./fxpool-proxy export-credentials --import` |
| 查看状态 | `./fxpool-proxy token-status` |
| 强制刷新 ProxyPass | `./fxpool-proxy token-refresh --force` |
| 列出所有账号 | `./fxpool-proxy accounts list` |
| 启用 / 禁用账号 | `./fxpool-proxy accounts enable <uid>` / `accounts disable <uid>` |
| 删除账号及其数据 | `./fxpool-proxy accounts remove --yes <uid>` |

**无 Firefox（推荐）**：配套注册机
[mozilla-account-register](https://github.com/6Kmfi6HP/mozilla-account-register)
用反检测 Chromium 完成注册，从 `localStorage["__fxa_storage.accounts"]` 收割
FxA session，并可选地走一次开通，写出
`{"schema":"firefox-ip-protection-renewal-credentials-v1","email","uid","session_token"}`
凭据包。代理机只需 `import-credentials`。完整步骤、权限与排错见
[无 Firefox 获取续期凭据](docs/guides/headless-credentials.md)。

**WAF 边界**：在受 Fastly WAF 影响的网络上，`POST /v1/account/create` 与
`POST /v1/account/login` 返回 406（空响应体），因此 `login` 与注册机的
`--backend api` 都无法工作；`/v1/account/status`、OAuth 与 Guardian 正常。
遇到 406 时 `fxpool-proxy` 会提示改用 `import-credentials`。

**开通（entitlement）**：新账号在浏览器里走一次
`GET https://vpn.mozilla.org/api/v1/fpn/auth` 之前，`/api/v1/fpn/status` 与
`/api/v1/fpn/token` 返回 403，`fxpool-proxy` 报 `no_entitlement` 并阻断隧道。
注册机的 `--enroll` 负责这一步，且每账号只尝试一次。

`login` 交互式输入 FxA 邮箱与密码（密码不回显），自动完成登录、发布续期凭据
并换取 ProxyPass 验证；无需本机已登录的 Firefox，但无法在被 WAF 拦截的网络使用。
已启用两步验证（2FA）的账号会在提示时输入验证码。可选 `--email`、`--no-verify`
（发布但不刷新验证）、`--totp CODE`（非交互提供验证码）。

流程：`login` 派生 authPW 登录 FxA；`export-credentials` 读取 Firefox
`signedInUser.json`。两者都产出最小续期包（email / uid / session），随后
FxA HAWK + PKCE OAuth → Guardian ProxyPass JWT → `tokens/proxy_pass.jwt`。

JWT 会校验结构、算法（拒绝 `none`）、issuer、audience、时间与最小 TTL；
Guardian 无稳定 JWKS 合约，**不验证 JWT 签名**。

常用导出选项：`--profile NAME`、`--firefox-dir DIR`、`--stdout` / `-o -`、
`--no-verify`（仅写入、跳过 Guardian 验收）。

## 运行与端口

默认监听（`--bind` 默认 `127.0.0.1`）：

| 入口 | 地址 |
|------|------|
| 综合 SOCKS5（国家轮换） | `:1090` |
| 综合 HTTP | `:8080` |
| 每节点 SOCKS5 | `--socks-base` 起，默认 `21000+` |
| 每节点 HTTP | `--http-base` 起，默认 `31000+` |
| UDP 中继（MASQUE，SOCKS5 UDP ASSOCIATE） | `--udp-base` 起，默认 `41000`（需 `--masque-uri`） |

端口映射持久化在 `data/port-map.json`。验证：

```bash
curl --proxy socks5h://127.0.0.1:1090 https://ipinfo.io/json
```

仅美国 SOCKS：

```bash
./fxpool-proxy run --countries US --limit 1 --no-http --http-rotator off
# 或经 install.sh 前台（读环境变量）：
FXPOOL_COUNTRIES=US FXPOOL_LIMIT=1 ./install.sh run
```

## 命令

```text
fxpool-proxy sync
fxpool-proxy token-status
fxpool-proxy token-refresh [--force] [--uid UID] [--all]
fxpool-proxy usage
fxpool-proxy how-to-token
fxpool-proxy probe [--country US]
fxpool-proxy run
fxpool-proxy login
fxpool-proxy export-credentials [options]
fxpool-proxy import-credentials BUNDLE [--delete-source] [--no-verify]
fxpool-proxy accounts <list|enable|disable|remove>
fxpool-proxy version
```

| 命令 | 作用 |
|------|------|
| `sync` | 拉取节点列表，写出 `export/exits.json` |
| `token-status` | JSON：续期就绪、ProxyPass、刷新状态；多账号时输出所有账号列表 |
| `token-refresh` | 刷新 ProxyPass；`--uid` 指定账号，`--all` 刷新全部 |
| `usage` | Guardian 配额（多账号模式下查询当前选中账号） |
| `probe` | 经一节点 CONNECT 探测 ipinfo.io |
| `login` | 邮箱+密码自动登录并发布续期凭据（仅限未被 WAF 拦截的网络） |
| `export-credentials` | 从本机 Firefox 导出续期包 |
| `import-credentials` | 导入注册机或 Firefox 凭据包并验证；多账号模式下按 uid upsert |
| `accounts list` | 列出所有账号的 uid、email、启用状态与刷新状态；`--json` 输出 JSON |
| `accounts enable/disable` | 按 uid 启用或禁用账号（禁用不删历史状态） |
| `accounts remove --yes` | 按 uid 级联删除账号及其所有数据 |
| `run` | 启动代理池 |
| `how-to-token` | 打印凭据步骤摘要 |

`run` 常用标志：`--countries`、`--limit`、`--no-socks` / `--no-http`、
`--rotator` / `--http-rotator`（`off` 关闭综合入口）、`--rotate-mode random|rr`、
`--account-mode rr`（多账号轮询）、
`--force-sync`、`--allow-no-token`、`--recommended`、`--auth-user` / `--auth-pass`、
`--require-auth`、`--allow-open-proxy`、`--root`。

## 环境变量

二进制优先读 `FXPOOL_*`，未设置时回退已弃用的 `IPP_*`。也可写入 `fxpool-proxy.env`
（`install.sh run` 会 source 后以标志形式传给二进制）。标 † 的变量仅 `install.sh`
使用，二进制本身不读取。

| 变量 | 用途 | 默认 |
|------|------|------|
| `FXPOOL_BIND` | 监听地址 | `127.0.0.1` |
| `FXPOOL_ADVERTISE_HOST` | 导出 URL 中的主机 | 未设置时同 `BIND` |
| `FXPOOL_COUNTRIES` | 国家过滤（逗号分隔） | 全部可用 |
| `FXPOOL_ROTATE_MODE` | `random` / `rr` | `random` |
| `FXPOOL_ROTATOR` | 综合 SOCKS 地址或 `off` | 未设置时 `{bind}:1090` |
| `FXPOOL_HTTP_ROTATOR` | 综合 HTTP 地址或 `off` | 未设置时 `{bind}:8080` |
| `FXPOOL_LISTEN_USER` / `LISTEN_PASS` | 本地代理鉴权 | 空（仅回环可开） |
| `FXPOOL_GUARDIAN` | Guardian 基址 | `https://vpn.mozilla.org` |
| `FXPOOL_PROXY_PASS_JWT` | 显式 ProxyPass | — |
| `FXPOOL_FXA_TOKEN` | 临时 FxA OAuth access token | — |
| `FXPOOL_FIREFOX_VERSION` | Remote Settings 过滤用版本 | 内置默认 |
| `FXPOOL_CLIENT_COUNTRY` | 客户端国家过滤上下文 | — |
| `FXPOOL_MASQUE_URI` | MASQUE 代理 URI 模板（启用 UDP 中继） | — |
| `FXPOOL_ACCOUNT_MODE` | 多账号 token 选择策略（`rr`） | — |
| `FXPOOL_BINARY` † | 二进制路径 | `./fxpool-proxy` |
| `FXPOOL_REFRESH_BEFORE_START` † | `install.sh run` 启动前刷新 | `1` |
| `FXPOOL_LIMIT` † | 节点数上限（install.sh 转为 `--limit`） | — |
| `FXPOOL_SERVICE_NAME` † | systemd 单元名 | `fxpool-proxy.service` |

UDP 中继端口通过 `--udp-base` 标志设置（默认 `41000`），无对应环境变量。

`FXPOOL_PYTHON` / `IPP_PYTHON` 已弃用，仅警告，不会执行。

## 数据目录

运行根目录默认当前工作目录（`--root` 可改）。启动时创建权限 `0700` 的目录：

| 路径 | 内容 |
|------|------|
| `data/fxpool.db` | 账号库：凭据、ProxyPass、刷新状态、拒绝列表（SQLite，`0600`） |
| `tokens/renewal_credentials.json` | FxA 续期凭据——单账号模式或迁移保留文件（`0600`） |
| `tokens/proxy_pass.jwt` | ProxyPass JWT——单账号模式或迁移保留文件（`0600`） |
| `tokens/refresh_state.json` | 刷新状态——单账号模式或迁移保留文件（`0600`） |
| `data/vpn-serverlist.json` | Remote Settings 缓存 |
| `data/port-map.json` | 稳定端口映射 |
| `export/socks5.txt` / `http.txt` | 监听地址列表 |
| `export/socks5_urls.txt` / `http_urls.txt` | 代理 URL（含鉴权时 `0600`） |
| `export/pool.json` | 节点与端口元数据 |
| `export/exits.json` | `sync` 产出的节点快照 |
| `logs/` | 预留目录 |
| `fxpool-proxy.env` | 安装脚本生成的环境文件（勿提交） |

敏感文件拒绝符号链接，有大小上限；写入为临时文件 + fsync + 原子 rename。
账号库 `data/fxpool.db` 包含所有账号的 session token，按最高敏感度保护，
备份时保持 `0600` 权限。不要提交 `tokens/`、`data/fxpool.db`、运行时数据、日志或带鉴权的导出。

## 安全边界

- 非回环监听且无用户名密码时拒绝启动，除非 `--allow-open-proxy`
- 用户名与密码必须成对出现
- 上游仅接受 `protocol=connect` 且 `scheme=https`
- SOCKS 仅 CONNECT；HTTP 为 CONNECT 或 `http://` absolute-form
- 本地 SOCKS 用户口令 / HTTP `Proxy-Authorization` Basic
- 刷新失败进入 `reauth_required` / `rate_limited` / `no_entitlement` 等状态时会阻断隧道，直至恢复

## 开发与 CI

```bash
go test ./...
go test -race ./...
go vet ./...
govulncheck ./...
make cross
bash -n install.sh
```

GitHub Actions（`.github/workflows/ci.yml`）：gofmt、test、race、vet、govulncheck、
Linux amd64/arm64 交叉编译、`install.sh` 语法检查，以及 Docker amd64 构建和
版本冒烟测试。

维护者发布稳定版本时，先确认 `main` 的普通 CI 全部通过，再创建 annotated
SemVer 标签；标签提交必须属于 `main`：

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

`.github/workflows/release.yml` 会重新执行发布校验，构建六个平台包与多架构
GHCR 镜像，生成校验和、GitHub Release 和构建来源证明。发布失败时修复后使用
新的补丁版本，不移动或覆盖已发布标签。

## 多账号模式

同时保存多个 FxA 账号的凭据，`run` 在它们之间轮询分配出口 token，
单个账号认证失败时自动切换到其他可用账号。

启用：传入 `--account-mode rr`（或设置 `FXPOOL_ACCOUNT_MODE=rr`），
其余命令与单账号完全兼容。

### 导入多个账号

```bash
# 每个账号一个凭据包，逐个导入
./fxpool-proxy import-credentials fxpool-bundles/uid1.json --delete-source --account-mode rr
./fxpool-proxy import-credentials fxpool-bundles/uid2.json --delete-source --account-mode rr
```

### 查看账号列表

```bash
./fxpool-proxy accounts list
./fxpool-proxy accounts list --json
```

### 启动多账号代理池

```bash
./fxpool-proxy run --account-mode rr
# 或通过环境变量
FXPOOL_ACCOUNT_MODE=rr ./install.sh run
```

### 管理账号

```bash
# 临时禁用某账号（不删数据，冷却结束后可重新启用）
./fxpool-proxy accounts disable <uid>
./fxpool-proxy accounts enable <uid>

# 永久删除账号及其 ProxyPass、刷新状态、拒绝列表
./fxpool-proxy accounts remove --yes <uid>

# 查看所有账号刷新状态（多账号模式下 token-status 输出列表）
./fxpool-proxy token-status --account-mode rr

# 刷新指定账号
./fxpool-proxy token-refresh --account-mode rr --uid <uid>

# 刷新全部账号
./fxpool-proxy token-refresh --account-mode rr --all
```

账号数据存储在 `data/fxpool.db`（SQLite，`0600`）。首次以账号模式启动时，
现有 `tokens/renewal_credentials.json` 会自动离线迁移进数据库，旧文件保留原位。
数据库包含所有账号的 session token，备份时保持 `0600` 权限，不要提交或分享。

## 文档

逆向结论、上游兼容与凭据指南（已脱敏）见 [`docs/`](docs/README.md)：

| 分类 | 说明 |
|------|------|
| [docs/research/](docs/research/) | 架构、协议、源码实证 findings |
| [docs/notes/](docs/notes/) | 路线图、观测面、验证日志 |
| [docs/compatibility/](docs/compatibility/) | Remote Settings / Guardian 适配 |
| [docs/guides/](docs/guides/) | 无 Firefox 注册机凭据、WAF 边界、开通（entitlement）与 Firefox 导出 |
| [docs/SECURITY.md](docs/SECURITY.md) | 漏洞报告与凭据边界 |

配套项目：[mozilla-account-register](https://github.com/6Kmfi6HP/mozilla-account-register)
（反检测 Chromium 注册、FxA session 收割与一次性开通）。

## 法律

仅使用你本人有权使用的账号、网络与服务，并遵守适用条款与法律。
本项目与 Mozilla、Firefox 或 Fastly 没有官方隶属关系。
