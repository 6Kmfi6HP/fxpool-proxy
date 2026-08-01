# 从自己的 Firefox 获取续期凭据 / ProxyPass

仅适用于你本人拥有且有权使用的 Firefox Account。
不要抓取或使用他人会话，不要尝试绕过资格、配额、CAPTCHA 或其他安全机制。

## 优先使用本仓库命令

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
