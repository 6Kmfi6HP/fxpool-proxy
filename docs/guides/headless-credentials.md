# 无 Firefox 获取续期凭据（注册机 → fxpool-proxy）

目标：不安装、不登录本机 Firefox，也能取得 `fxpool-proxy` 需要的 FxA 续期凭据
`{schema, email, uid, session_token}`，并完成 IP Protection 开通（entitlement）。

配套注册机：[6Kmfi6HP/mozilla-account-register](https://github.com/6Kmfi6HP/mozilla-account-register)。
它用 cloakbrowser 驱动的反检测 Chromium 完成注册、从浏览器存储收割 FxA session，
并可选地走一次开通；`fxpool-proxy` 只负责导入和后续续期。

仅适用于你本人拥有且有权使用的账号。不要批量注册、抓取他人会话或规避平台风控。

## 为什么需要注册机

三个硬约束决定了“纯 HTTP”或“依赖本机 Firefox”的路径不可行：

1. **Fastly WAF 拦截账号创建与密码登录。** 在受影响的网络上，
   `POST https://api.accounts.firefox.com/v1/account/create` 与
   `POST .../v1/account/login` 返回 **406 且响应体为空**（按 TLS 指纹判定；
   curl、python-urllib、Go 均可复现）。`POST .../v1/account/status` 与
   `POST .../v1/account/credentials/status` 正常返回 200，OAuth（HAWK + PKCE）
   也正常。因此 `fxpool-proxy login`（邮箱+密码）在该网络下无法工作。
2. **session token 只存在于浏览器存储。** 登录后 FxA 把会话写在
   `localStorage["__fxa_storage.accounts"]`，按 32 位 hex uid 索引，条目里含
   64 位 hex `sessionToken`。密码登录被 WAF 挡住时，读取该 localStorage 是
   不安装 Firefox 也能拿到 session 的唯一路径。
3. **新账号必须先开通（enrollment）。** 未开通账号请求
   `GET https://vpn.mozilla.org/api/v1/fpn/status` 与 `.../api/v1/fpn/token`
   均返回 403，`fxpool-proxy` 会进入 `no_entitlement` 并阻断隧道。开通必须在
   已登录的浏览器上下文里走一次 `GET https://vpn.mozilla.org/api/v1/fpn/auth`。

注册机把这三步串起来：真实 Chromium 通过 WAF → 注册 → 收割 session →
一次性开通 → 写出凭据包。之后 `fxpool-proxy` 的 OAuth/Guardian 请求不再经过
被拦截的端点。

## 流程图

```text
注册机（任意能运行 Chromium 的机器）
  cloakbrowser（headless 反检测 Chromium）
    ├─ accounts.firefox.com/signup
    │    邮箱 → 新密码 → 邮件验证码 → /settings
    ├─ localStorage["__fxa_storage.accounts"] → uid + session_token
    ├─ GET vpn.mozilla.org/api/v1/fpn/auth（每账号仅一次）
    │    302 → accounts.firefox.com/authorization → vpn.mozilla.org/oauth/success
    └─ 写出 fxpool-bundles/<uid>.json（0600）
              │  拷贝到代理机
              ▼
代理机
  fxpool-proxy import-credentials <uid>.json
    └─ tokens/renewal_credentials.json（0600）
         → FxA HAWK + PKCE OAuth
         → GET vpn.mozilla.org/api/v1/fpn/token
         → ProxyPass JWT（约 600s）→ 代理池
```

## 准备

注册机：

```bash
git clone https://github.com/6Kmfi6HP/mozilla-account-register.git
cd mozilla-account-register
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
pip install cloakbrowser          # 浏览器后端依赖（requirements 中默认注释）
cp config.example.json config.json
# 编辑 config.json：email_provider / cloudmail_api_base /
# cloudmail_public_token / cloudmail_domains
```

代理机：已构建 `fxpool-proxy`（见根 [README](../../README.md) 的安装章节）。

## 端到端：注册并导入（推荐）

### 1. 注册机生成账号、凭据包并开通

```bash
python register.py --backend browser --count 1 \
  --enroll --bundle-dir fxpool-bundles
```

- `--backend browser` 是必须的；`--backend api` 会撞上同一个 406。
- `--enroll` 让注册机在同一个浏览器会话里走一次 `/api/v1/fpn/auth`。
- `--bundle-dir fxpool-bundles` 写出 `fxpool-bundles/<uid>.json`。
- 账号行仍追加到 `accounts_<时间戳>.txt`，格式不变：
  `邮箱----密码----browser-verified`。

这些选项也可写进 `config.json`：`fxpool_enroll`、`fxpool_root`、`bundle_dir`；
`--backend` 未给出时读 `register_backend`（默认 `api`）。`--fxpool-root` 未给出时
依次读配置 `fxpool_root`、环境变量 `FXPOOL_ROOT`。`--no-bridge` 可关闭凭据写出。

成功时日志包含：

```text
[+] 续期凭据包: /.../fxpool-bundles/<uid>.json
[+] 开通成功: entitlement uid=<数字> limited_bandwidth=true
```

### 2. 把凭据包拷到代理机并导入

```bash
scp fxpool-bundles/<uid>.json proxy:/tmp/<uid>.json
ssh proxy 'chmod 600 /tmp/<uid>.json'
# 单账号模式（默认）
ssh proxy 'cd /opt/fxpool && ./fxpool-proxy import-credentials /tmp/<uid>.json --delete-source'
# 多账号模式：逐个导入，每个账号按 uid upsert 进数据库
ssh proxy 'cd /opt/fxpool && ./fxpool-proxy import-credentials /tmp/<uid>.json --delete-source --account-mode rr'
```

`import-credentials` 默认会在发布后立即刷新一次 ProxyPass 作为验证；
`--no-verify` 只发布不验证；`--delete-source` 在成功后删除源文件
（使用 `--no-verify` 时导入后即删除）。也支持 `-` 从 stdin 读取。

多账号模式下，同一个 uid 重新导入会原子地重置该账号的 ProxyPass、刷新状态
和拒绝列表，不影响其他账号。

### 3. 验证

```bash
./fxpool-proxy token-status
./fxpool-proxy token-refresh --force
./fxpool-proxy usage
```

`token-status` 中 `automatic_renewal_ready` 与 `has_proxy_pass` 应为 `true`，
`refresh_state.result` 为 `success`。

多账号模式下，用 `./fxpool-proxy accounts list` 确认所有账号的启用状态与刷新状态；
用 `./fxpool-proxy token-status --account-mode rr` 查看所有账号详情（多账号时以列表形式输出）。

## 同机直写（可选）

注册机与代理同机时，可让注册机直接写
`<fxpool-root>/tokens/renewal_credentials.json`：

```bash
python register.py --backend browser --count 1 --enroll \
  --fxpool-root /opt/fxpool
```

成功后日志包含
`[+] 已写入 fxpool 凭据: /opt/fxpool/tokens/renewal_credentials.json`。
随后执行一次 `./fxpool-proxy token-refresh --force`（或重启 `run`）。

若目标 `renewal_credentials.json` 已属于另一个 uid，bridge 会拒绝覆盖并保持
原文件不变；此时改用 `--bundle-dir` 生成凭据包，再在代理机上
`import-credentials`（导入会原子替换现有凭据，不校验旧 uid）。

## 已有账号：只补 session / 开通

`--signin` 不创建账号，只登录并收割 session：

```bash
# accounts.txt，每行：邮箱----密码（按第一个 ---- 切分）
python register.py --backend browser --signin --emails accounts.txt \
  --enroll --fxpool-root /opt/fxpool
```

- `--signin` 需要邮箱来源，且不追加 `accounts_*.txt`、不写 `mail_credentials.txt`。
- 若登录触发新设备验证码，注册机会轮询一次邮箱；仅 TOTP 的账号不支持浏览器
  路径，会明确失败。
- 已经开通过的账号不要再跑 `--enroll`：每个账号只允许一次 `/fpn/auth` 尝试。

## WAF 边界（实测）

| 请求 | 结果 |
|------|------|
| `POST https://api.accounts.firefox.com/v1/account/create` | 406，空响应体 |
| `POST https://api.accounts.firefox.com/v1/account/login` | 406，空响应体 |
| `POST .../v1/account/status` | 200 |
| `POST .../v1/account/credentials/status` | 200 |
| `POST https://api.accounts.firefox.com/v1/oauth/authorization`（HAWK） | 正常 |
| `POST https://oauth.accounts.firefox.com/v1/token`（PKCE） | 正常 |

结论：

- 受 WAF 影响的网络不能用密码创建账号或登录。`fxpool-proxy login` 会失败；
  `internal/fxa` 将 406 识别为 `fxa.ErrWAFBlocked`，CLI 会提示改用
  `import-credentials`。这不是配置问题，换代理或重试都无济于事。
- 在该网络下，`register.py --backend api` 同样不可用；浏览器后端才是密码路径。
- 导入凭据后的 OAuth、Guardian、节点同步都不经过被拦截的端点。

## 开通（entitlement）与一次性约束

未开通账号的实测行为：

```text
GET https://vpn.mozilla.org/api/v1/fpn/status  → 403 {"error":"Forbidden"}
GET https://vpn.mozilla.org/api/v1/fpn/token   → 403
```

`fxpool-proxy` 把 403 归类为 `no_entitlement`，`run` / `token-refresh` 会阻断
隧道，直到开通完成。开通动作是浏览器里的一次导航：

```text
GET https://vpn.mozilla.org/api/v1/fpn/auth
  → 302 https://accounts.firefox.com/authorization?client_id=e6eb0d1e856335fc&...
  → https://vpn.mozilla.org/oauth/success?code=...
```

`/oauth/success` 的响应体就是 entitlement JSON：

```json
{"uid": 1234567, "created_at": "2026-10-20T22:10:01.968Z", "limited_bandwidth": true}
```

这里的 `uid` 是 **数字 Guardian id**，不是 FxA 的 32 位 hex uid。免费档
`limited_bandwidth=true`，约 50GB/月配额，无需付费。

约束：

- **每个账号只尝试一次。** 注册机用 `enrollment_attempts.txt`
  （`uid<TAB>status<TAB>ISO8601`，导航前先写 `started`）做持久化闸门；
  已尝试过的 uid 不会再次导航。
- **429 不重试。** Guardian 对 `/fpn/auth` 限流，重复请求很快返回 429；
  注册机记录 `rate_limited` 后直接放弃，不 reload、不轮询 `/fpn/status`。
- 如果忘了 `--enroll`：`import-credentials` 仍会写入凭据，但随后的验证刷新会以
  `no_entitlement` 失败（退出码 1，源文件保留）。补跑
  `--signin --enroll` 后再导入即可。

## 凭据文件

凭据包（`fxpool-bundles/<uid>.json`，`0600`，目录 `0700`，`indent=2` 加末尾换行）：

```json
{
  "schema": "firefox-ip-protection-renewal-credentials-v1",
  "email": "user@example.com",
  "uid": "<32 位 hex>",
  "session_token": "<64 位 hex>"
}
```

`<fxpool-root>/tokens/renewal_credentials.json`（`0600`；`tokens/` 与 root
新建时均为 `0700`）是同一份数据的紧凑单行形式，`schema` 为数字：

```json
{"schema":1,"email":"user@example.com","uid":"<32 位 hex>","session_token":"<64 位 hex>"}
```

| 文件 | 内容 | 权限 |
|------|------|------|
| `fxpool-bundles/<uid>.json` | 上方的四键凭据包 | 0600，目录 0700 |
| `<fxpool-root>/tokens/renewal_credentials.json` | 上方的紧凑单行 JSON | 0600，`tokens/` 0700 |
| `<注册机目录>/enrollment_attempts.txt` | 开通尝试账本 | 0600 |

导入端的硬性要求：

- 凭据包**只能**有 `schema` / `email` / `uid` / `session_token` 四个键。
  Go 导入器使用 `json.Decoder.DisallowUnknownFields()`，多一个 `password`
  之类的键整包作废。
- 文件必须是常规文件、非符号链接、不超过 16KiB，且权限为 `0600`
  （任何 group/other 位都会被拒绝）。
- `uid` 为 32 位 hex，`session_token` 为 64 位 hex，导入时统一转小写。

## 故障排查

| 现象 | 原因 | 处理 |
|------|------|------|
| `cannot safely read credential bundle` | 权限不是 0600、符号链接或文件过大 | `chmod 600`，使用注册机原始输出 |
| `invalid credential bundle` | 多了字段、schema 不符、uid/token 长度不对 | 不要手工编辑凭据包 |
| `token-refresh` 报 `no_entitlement` | 未走 `/fpn/auth` | `--signin --enroll`，再重新导入 |
| `refresh deferred by persisted cooldown` | 上次失败留下的冷却（最长 5 分钟） | 等待，或重新 `import-credentials`（会重置状态） |
| `login` 报 406 / WAF | 网络被 Fastly 拦截 | 改用注册机 + `import-credentials` |
| 注册 `stage=password` 超时 | 页面 DOM 变化 | 更新注册机；查看日志中的 url/body 摘要 |
| 注册 `stage=enroll` 429 | Guardian 限流 | 不要重试；该账号已记入尝试账本 |
| 登录要求 TOTP | 仅 TOTP 账号 | 浏览器路径不支持，改用邮箱验证码账号 |
| bridge 报 `already holds uid ...` | 目标已属于另一个 uid | 用 `--bundle-dir` + `import-credentials` |

## 安全

- 凭据包与 `renewal_credentials.json` 等同登录会话：`0600`，不提交、不分享。
- 注册机不会把密码写进凭据包；密码只留在 `accounts_*.txt`，同样敏感。
- `.gitignore` 应包含 `fxpool-bundles/`、`enrollment_attempts.txt`、
  `renewal_credentials*.json`。
- 只处理本人有权使用的账号；开通与配额受 Mozilla 条款约束。

## 相关文档

- [从 Firefox 或 login 获取凭据](extract-token-from-firefox.md)
- [协议与认证总览](../research/findings.md)
- [注册机仓库](https://github.com/6Kmfi6HP/mozilla-account-register)
- [根 README](../../README.md)
