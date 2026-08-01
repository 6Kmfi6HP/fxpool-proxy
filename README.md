# fxpool-proxy

纯 Go 实现的本地 SOCKS5 / HTTP 代理池：把流量经 Firefox IP Protection
（Mozilla Guardian ProxyPass + TLS HTTP CONNECT）送出，并自动续期凭据、
同步 Remote Settings 节点列表。

不支持 MASQUE / HTTP3 / QUIC / UDP；未知上游协议、未知过滤表达式、未鉴权的
非回环监听均会 fail closed。与 Mozilla / Firefox / Fastly 无官方隶属关系。

要求 Go 1.25+（一键安装会自动 `go build`）。Linux 建议配合 systemd。

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

安装后导入凭据（本机 Firefox 或拷贝续期包）：

```bash
./fxpool-proxy export-credentials --import
# 或
./fxpool-proxy import-credentials /path/to/bundle.json --delete-source
./install.sh restart
```

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

| 步骤 | 命令 |
|------|------|
| 列出本机 Firefox 配置 | `./fxpool-proxy export-credentials --list` |
| 导出续期包 | `./fxpool-proxy export-credentials -o bundle.json` |
| 导出并写入 `tokens/` | `./fxpool-proxy export-credentials --import` |
| 在另一台机器导入 | `./fxpool-proxy import-credentials bundle.json --delete-source` |
| 查看状态 | `./fxpool-proxy token-status` |
| 强制刷新 ProxyPass | `./fxpool-proxy token-refresh --force` |

流程：读取 Firefox `signedInUser.json` → 最小续期包（email / uid / session）→
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
fxpool-proxy token-refresh [--force]
fxpool-proxy usage
fxpool-proxy how-to-token
fxpool-proxy probe [--country US]
fxpool-proxy run
fxpool-proxy export-credentials [options]
fxpool-proxy import-credentials BUNDLE [--delete-source] [--no-verify]
fxpool-proxy version
```

| 命令 | 作用 |
|------|------|
| `sync` | 拉取节点列表，写出 `export/exits.json` |
| `token-status` | JSON：续期就绪、ProxyPass、刷新状态 |
| `token-refresh` | 刷新 ProxyPass |
| `usage` | Guardian 配额 |
| `probe` | 经一节点 CONNECT 探测 ipinfo.io |
| `run` | 启动代理池 |
| `how-to-token` | 打印凭据步骤摘要 |

`run` 常用标志：`--countries`、`--limit`、`--no-socks` / `--no-http`、
`--rotator` / `--http-rotator`（`off` 关闭综合入口）、`--rotate-mode random|rr`、
`--force-sync`、`--allow-no-token`、`--recommended`、`--auth-user` / `--auth-pass`、
`--require-auth`、`--allow-open-proxy`、`--root`。

## 环境变量

优先 `FXPOOL_*`，未设置时回退已弃用的 `IPP_*`。也可写入 `fxpool-proxy.env`。

| 变量 | 用途 | 默认 |
|------|------|------|
| `FXPOOL_BIND` | 监听地址 | `127.0.0.1` |
| `FXPOOL_ADVERTISE_HOST` | 导出 URL 中的主机 | 同 `BIND` |
| `FXPOOL_COUNTRIES` | 国家过滤（逗号分隔） | 全部可用 |
| `FXPOOL_ROTATE_MODE` | `random` / `rr` | `random` |
| `FXPOOL_ROTATOR` | 综合 SOCKS 地址或 `off` | `{bind}:1090` |
| `FXPOOL_HTTP_ROTATOR` | 综合 HTTP 地址或 `off` | `{bind}:8080` |
| `FXPOOL_LISTEN_USER` / `LISTEN_PASS` | 本地代理鉴权 | 空（仅回环可开） |
| `FXPOOL_GUARDIAN` | Guardian 基址 | `https://vpn.mozilla.org` |
| `FXPOOL_PROXY_PASS_JWT` | 显式 ProxyPass | — |
| `FXPOOL_FXA_TOKEN` | 临时 FxA OAuth access token | — |
| `FXPOOL_FIREFOX_VERSION` | Remote Settings 过滤用版本 | 内置默认 |
| `FXPOOL_CLIENT_COUNTRY` | 客户端国家过滤上下文 | — |
| `FXPOOL_BINARY` | 二进制路径 | `./fxpool-proxy` |
| `FXPOOL_REFRESH_BEFORE_START` | `install.sh run` 启动前刷新 | `1` |
| `FXPOOL_LIMIT` | 节点数上限 | — |
| `FXPOOL_SERVICE_NAME` | systemd 单元名 | `fxpool-proxy.service` |

`FXPOOL_PYTHON` / `IPP_PYTHON` 已弃用，仅警告，不会执行。

## 数据目录

运行根目录默认当前工作目录（`--root` 可改）。启动时创建权限 `0700` 的目录：

| 路径 | 内容 |
|------|------|
| `tokens/renewal_credentials.json` | FxA 续期凭据（`0600`） |
| `tokens/proxy_pass.jwt` | ProxyPass JWT（`0600`） |
| `tokens/refresh_state.json` | 刷新状态机（`0600`） |
| `data/vpn-serverlist.json` | Remote Settings 缓存 |
| `data/port-map.json` | 稳定端口映射 |
| `export/socks5.txt` / `http.txt` | 监听地址列表 |
| `export/socks5_urls.txt` / `http_urls.txt` | 代理 URL（含鉴权时 `0600`） |
| `export/pool.json` | 节点与端口元数据 |
| `export/exits.json` | `sync` 产出的节点快照 |
| `logs/` | 预留目录 |
| `fxpool-proxy.env` | 安装脚本生成的环境文件（勿提交） |

敏感文件拒绝符号链接，有大小上限；写入为临时文件 + fsync + 原子 rename。
不要提交 `tokens/`、运行时数据、日志或带鉴权的导出。

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

## 文档

逆向结论、上游兼容与凭据指南（已脱敏）见 [`docs/`](docs/README.md)：

| 分类 | 说明 |
|------|------|
| [docs/research/](docs/research/) | 架构、协议、源码实证 findings |
| [docs/notes/](docs/notes/) | 路线图、观测面、验证日志 |
| [docs/compatibility/](docs/compatibility/) | Remote Settings / Guardian 适配 |
| [docs/guides/](docs/guides/) | 从本机 Firefox 导出续期凭据 |
| [docs/SECURITY.md](docs/SECURITY.md) | 漏洞报告与凭据边界 |

## 法律

仅使用你本人有权使用的账号、网络与服务，并遵守适用条款与法律。
本项目与 Mozilla、Firefox 或 Fastly 没有官方隶属关系。
