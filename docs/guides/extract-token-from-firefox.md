# 获取续期凭据：注册机 / login / Firefox 导出

仅适用于你本人拥有且有权使用的 Firefox Account。
不要抓取或使用他人会话，不要尝试绕过资格、配额、CAPTCHA 或其他安全机制。

凭据包格式为 `{schema, email, uid, session_token}`，等同登录会话；
获取方式按可用性排序如下。

## 方式一（推荐，无需本机 Firefox）：注册机 + 导入

配套注册机 [mozilla-account-register](https://github.com/6Kmfi6HP/mozilla-account-register)
用反检测 Chromium 完成注册、收割 FxA session，并可选地走一次开通：

```bash
# 注册机
python register.py --backend browser --count 1 \
  --enroll --bundle-dir fxpool-bundles

# 代理机
./fxpool-proxy import-credentials /path/to/fxpool-bundles/<uid>.json --delete-source
./fxpool-proxy token-status
```

注册机与代理同机时，也可以直接写入 `tokens/`：

```bash
python register.py --backend browser --count 1 --enroll --fxpool-root /opt/fxpool
```

完整步骤、WAF 边界、开通约束与排错见
[无 Firefox 获取续期凭据](headless-credentials.md)。

## 方式二：邮箱+密码自动登录（仅限未被 WAF 拦截的网络）

```bash
./fxpool-proxy login
```

按提示输入 FxA 邮箱和密码（密码不回显），程序自动完成登录、发布续期凭据、
换取 ProxyPass 并验证。已开启两步验证（2FA）的账号会在提示时输入验证码。

**限制**：在受 Fastly WAF 影响的网络上，`POST /v1/account/login` 返回 406
（空响应体），`login` 无法工作；程序会识别该状态并提示改用
`import-credentials`。这不是配置问题，换代理或重试都无济于事。账号创建同理，
注册机的 `--backend api` 也会被同一个 WAF 拦截。

## 方式三：从本机已登录的 Firefox 导出

```bash
./fxpool-proxy how-to-token
./fxpool-proxy export-credentials --list
./fxpool-proxy export-credentials --import
./fxpool-proxy token-status
```

桌面导出续期包后，也可在另一台机器导入：

```bash
./fxpool-proxy import-credentials /path/to/bundle.json --delete-source
```

ProxyPass JWT 是短时凭据；长期运行依赖本人 FxA session 定期刷新。

## WAF 边界（实测）

| 请求 | 结果 |
|------|------|
| `POST https://api.accounts.firefox.com/v1/account/create` | 406，空响应体 |
| `POST https://api.accounts.firefox.com/v1/account/login` | 406，空响应体 |
| `POST .../v1/account/status` | 200 |
| `POST .../v1/account/credentials/status` | 200 |
| OAuth（HAWK + PKCE） | 正常 |

因此：在受 WAF 影响的网络上，创建账号、密码登录只能走浏览器路径（注册机）；
凭据导入后的 OAuth、Guardian 请求与节点同步不受影响。

## 开通（entitlement）

新账号在浏览器里走一次
`GET https://vpn.mozilla.org/api/v1/fpn/auth` 之前：

```text
GET https://vpn.mozilla.org/api/v1/fpn/status  → 403 {"error":"Forbidden"}
GET https://vpn.mozilla.org/api/v1/fpn/token   → 403
```

`fxpool-proxy` 会报 `no_entitlement` 并阻断隧道。开通成功后 `/oauth/success`
返回 `{"uid":<数字 Guardian id>,"created_at":...,"limited_bandwidth":true}`，
之后 `token-refresh --force` 才能取得 ProxyPass。注册机的 `--enroll` 负责这一步，
每个账号只尝试一次。

## Firefox 授权链路

桌面端用带有以下 scope 的 FxA access token 请求 Guardian：

```text
profile
https://identity.mozilla.com/apps/vpn
```

随后：

```http
GET https://vpn.mozilla.org/api/v1/fpn/token
Authorization: Bearer <自己的 FxA access token>
```

响应中的 `token` 字段是短时 ProxyPass JWT，与 session / access token 同属敏感凭据。

## 从自己的浏览器会话观察请求（可选）

若正常引导不可用，可在本人 Firefox 中用 Browser Toolbox 网络面板观察 Guardian 请求。
可在 `about:config` 临时开启相关日志，调试后关闭。

代理抓包会改变信任边界；仅在理解影响、只分析本人会话并能撤销证书时使用。
HAR、抓包与 Toolbox 导出可能含完整请求头、Cookie 与 token，**禁止**上传到 issue、网盘或公共仓库。

## 安全保存

```bash
mkdir -p tokens
# 由 export-credentials / import-credentials / token-refresh 写入；权限应为 0600
./fxpool-proxy token-status
```

不要把 token 写进命令行、shell 历史或文档。状态命令只输出安全摘要。
`import-credentials` 拒绝任何带 group/other 权限的凭据包（必须 `0600`），
也拒绝符号链接和超过 16KiB 的文件。

## 验证

```bash
./fxpool-proxy sync
./fxpool-proxy probe --country COUNTRY_CODE
```

只记录状态码、协议、国家或节点数量。不要保存完整认证代理 URL、请求头或 token。

## 必须保护的产物

- ProxyPass JWT、FxA access / session token
- Cookie、浏览器 storage、登录截图、profile
- HAR、抓包、Toolbox 导出、控制台历史
- 邮箱、账号 UID、验证码、监听用户名与密码
- 含认证信息的完整 SOCKS5/HTTP URL

若曾上传或分享：立即撤销会话、轮换凭据，并从公开历史移除泄露内容。
