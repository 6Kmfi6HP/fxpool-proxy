# 多账号负载均衡与 SQLite 存储改造计划

状态：修订提案，未实施
日期：2026-10-21
目标读者：维护者 / 实施者

## 1. 审查结论

原提案的目标合理，但有五个实现前提不成立，直接照做会破坏兼容性或让故障难以诊断：

1. 当前 `token.Manager` 是**账号级、有状态**对象，包含 `Root`、`AccessToken`、`ExplicitProxyPass`、互斥锁和刷新状态；`accounts.Pool` 不能持有一个共享 `*token.Manager` 来代表 N 个账号。每个账号必须有独立的 Manager 状态，HTTP client 和端点配置才可以共享。
2. 启动时联网刷新再把旧凭据改名，会让离线启动、`--allow-no-token` 和网络故障都变成迁移故障；而且原提案没有明确导入现有 `proxy_pass.jwt`、`refresh_state.json` 和拒绝列表，无法保证行为不变。
3. SQLite 的 `SetMaxOpenConns(1)` 只解决单进程连接并发，不能替代跨进程协调；通过路径直接打开数据库也不会自动提供当前 `securefile` 的符号链接拒绝语义。损坏数据库自动重建会有数据丢失风险，应失败关闭。
4. `token-status` 只有一个明确的 JSON 结构。把它直接改成多账号结构会无谓地破坏脚本；多账号详情应增加命令或显式选项，单账号默认输出保持兼容。
5. `X-Quota-*` 的单位和服务端限速范围尚未实证，`quota` 加权、`least-used` 和“额度扩大 N 倍”不能作为首个可交付版本的保证。首版先交付轮询和认证失败切换。

另外，仓库当前 `go.mod` 声明 Go 1.26.10，`make cross` 只构建 Linux amd64/arm64；计划不能写成“Go 1.25+、四平台交叉编译已覆盖”。四平台支持必须先有实际构建目标和 CI 证据。

## 2. 目标与边界

### 2.1 首个可交付版本

1. 同时保存 N 个 FxA 续期凭据，每个账号独立拥有 ProxyPass、刷新状态、冷却时间和拒绝 token 列表。
2. 新建 TCP 隧道和 MASQUE UDP 隧道都通过同一个 `upstream.TokenSource` 取得 token；默认按 `rr` 轮询可用账号。
3. CONNECT 或 CONNECT-UDP 返回认证相关失败时，拒绝当前 token，并在一次有界重试中切换到其他账号或刷新当前账号。
4. 用一个 `data/fxpool.db` 保存账号、token、刷新状态和拒绝列表；凭据迁移不需要联网，且可重复执行。
5. `FXPOOL_PROXY_PASS_JWT` 配置后采用明确的显式 source，绕过账号库和刷新。注意当前 `Manager.Current` 只在 token 文件不可读时才回退到该环境变量，`Ensure` 仍可能触发刷新；把环境变量定义为硬优先级是有意的兼容边界变化，Phase 0 必须固化旧行为基线并在 CLI 文档说明新优先级。

### 2.2 非目标

- 不实现账号自动注册。
- 不在代理本地验证 Guardian JWT 签名。
- 不在首版承诺额度按比例分配、免费额度一定扩大 N 倍或“隧道不断”；这些都取决于服务端额度单位、限速范围和仍有可用账号。
- 不自动删除旧凭据文件，不自动重建损坏的数据库，不自动扫描目录并重新导入任意 JSON。

## 3. 当前代码事实

| 组件 | 当前行为 | 对改造的约束 |
|---|---|---|
| `internal/token/manager.go` | `Manager` 绑定一个 `Root`，`LoadCredentials`、`Current`、`Refresh`、`Usage`、`Reject` 都是单账号操作 | 多账号必须使用账号级 Manager 或等价的账号上下文，不能共享可变 Manager |
| `internal/upstream/dialer.go` | `Open` 和 `OpenUDP` 都调用 `Ensure`；401/403/407 或 MASQUE 认证错误后调用 `Reject` 再 `Ensure(true)` 一次 | Pool 只需实现现有 `TokenSource`，但测试必须覆盖 TCP 与 UDP 两条路径 |
| `cmd/fxpool-proxy/main.go` | `run` 启动前调用一次 `Ensure`；`refreshLoop` 每 30 秒调用单个 Manager；`probe`、`usage`、`token-status` 也是单账号 | 启动检查、刷新循环和 CLI 装配都要改为 Pool 或显式账号选择 |
| `internal/token/state.go` | 状态枚举包含 `credentials_imported`、`rate_limited`、`oauth_rate_limited`、`reauth_required`、`no_entitlement` 等 | 状态名称和阻断语义先原样迁移，不在存储改造中重命名 |
| 构建 | `go.mod` 为 Go 1.26.10；`Makefile` 的 `cross` 为 Linux amd64/arm64 | 先验证 `modernc.org/sqlite` 的实际构建矩阵，再扩大 CI |

## 4. 账号与存储架构

### 4.1 Manager 与 Pool 的边界

保留 `token.Manager` 的账号级语义。可以共享不可变的 HTTP client、Guardian/FxA 端点和配置，但每个账号有自己的 Manager 实例：

```go
type Pool struct {
    Store    *store.DB
    Managers map[int64]*token.Manager // 每个 Manager 绑定一个 account_id
    Mode     string                    // rr；random 作为后续可选模式
}

func (p *Pool) Ensure(ctx context.Context, force bool) (string, error)
func (p *Pool) Reject(raw string) error
```

`Pool` 不把 OAuth access token 或刷新中的状态放在共享 Manager 中。`Reject` 按 token 的 SHA-256 digest 从数据库定位账号，再写入该账号的拒绝表；digest 必须唯一，避免同一个 token 被错误归属两个账号。

`Ensure(false)` 的顺序：

1. 读取 enabled 账号的持久化快照，过滤阻断状态、未到期冷却和无效/已拒绝 token。
2. 按 `rr` 选择一个候选并返回当前 token。
3. 没有可用 token 时，按同一候选顺序逐个尝试一次账号级刷新；使用调用方 context 的总超时，不添加隐式无限重试。
4. 全部失败时返回包含账号状态摘要的错误，不伪造 token，也不静默退回显式 token。

`Ensure(true)` 只绕过当前 token 的复用检查，不绕过持久化冷却；只有显式 `--force` 或已有的 dialer 认证失败重试才能清楚地表达强制刷新。每账号最多保留最近 32 个拒绝 digest，旧记录可在同一事务中删除。

显式 token 模式单独建 `ExplicitSource`：设置 `FXPOOL_PROXY_PASS_JWT` 时它是硬优先级，不查账号库、不调用 OAuth/Guardian 刷新；拒绝 digest 继续读写现有 `tokens/rejected_proxy_pass.sha256`，因此拒绝状态跨进程、跨重启保留。认证失败后再次 `Ensure` 必须返回“显式 token 已拒绝”错误，不能重发同一 JWT，也不能回退到账号池。这样静态 JWT 被拒绝后需要操作者更换 token。旧文件清理不得删除该拒绝列表；若未来要移除它，必须先迁移显式 source 的拒绝状态并保留等价性验证。只有设置 `FXPOOL_FXA_TOKEN` 而没有显式 JWT 时，必须通过 `--uid` 指定账号，否则多账号运行直接报配置歧义。

### 4.2 SQLite v1 schema

第一版只迁移当前运行所需的数据；配额表在 Phase 4 通过新的 `user_version` 迁移加入。

```sql
CREATE TABLE accounts (
  id            INTEGER PRIMARY KEY,
  uid           TEXT NOT NULL UNIQUE,
  email         TEXT NOT NULL,
  session_token TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  label         TEXT NOT NULL DEFAULT '',
  source        TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE TABLE proxy_pass (
  account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  jwt        TEXT NOT NULL,
  digest     TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  fetched_at INTEGER NOT NULL
);

CREATE TABLE refresh_state (
  account_id            INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  result                TEXT NOT NULL,
  last_attempt_at       INTEGER,
  last_success_at       INTEGER,
  next_attempt_at       INTEGER,
  proxy_pass_expires_at INTEGER,
  consecutive_failures  INTEGER NOT NULL DEFAULT 0,
  http_status           INTEGER,
  generation            INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE rejected_tokens (
  digest     TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);
CREATE INDEX rejected_tokens_account_created
  ON rejected_tokens(account_id, created_at);

CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```

`meta` 保存一次性旧文件导入标记，与 schema 版本 `PRAGMA user_version` 分开管理。账号拒绝 digest 必须关联账号；显式 JWT source 沿用旧拒绝文件，不写入账号拒绝表。

`uid`、`session_token`、email 和 digest 的校验沿用当前 `LoadCredentials` / `PublishCredentials` 规则，统一放在 store 的 upsert 入口。数据库中的 `session_token` 等同于旧的 `renewal_credentials.json`，必须按同等级别保护，不能进入日志、状态输出或错误文本。

数据库打开流程必须是显式的安全边界：

- `data/` 保持 `0700`；数据库创建使用 `0600`，打开后再次检查 owner/mode。
- 对已有数据库和 `-wal`、`-shm` 路径做 `Lstat`，发现符号链接或非普通文件就拒绝启动；sidecar 由 `0700` 目录保护，打开后检查权限。
- 使用 `database/sql` 初始化 `journal_mode=WAL`、`foreign_keys=ON`、`busy_timeout=5000`、`SetMaxOpenConns(1)`；写入使用事务，不把事务当作替代刷新锁。
- 保留现有 `tokens/.refresh.lock` 作为跨进程刷新互斥；SQLite 负责状态事务和读写可见性。
- `PRAGMA integrity_check` 或迁移失败时失败关闭并保留原文件，禁止“损坏 DB 自动重建”。提供单独的备份/恢复操作后再处理损坏库。

## 5. 离线、幂等迁移

账号模式下，所有 token/account 命令和 `run` 在执行自身逻辑前完成 `EnsureDirs`、打开 DB 和 schema migration；显式 JWT 模式不打开账号 DB。`version`、帮助和不读取账号状态的命令也不依赖 DB。schema 版本用 `PRAGMA user_version` 管理；旧文件导入是独立的一次性数据迁移，使用 `meta['legacy_import_v1']` 标记。迁移过程不访问 FxA 或 Guardian：

1. 开启写事务并检查 `legacy_import_v1`。标记已存在就跳过旧文件；标记不存在且 `accounts` 为空时，才读取旧文件。若标记不存在但数据库已有账号，不读取旧文件、不覆盖账号，账号模式失败关闭；操作者须先备份 DB 和旧文件，再通过文档化的显式恢复流程解决，不能仅警告后继续，也不能悄悄把未导入标记为完成。Phase 1 必须定义并测试该恢复流程。
2. 若旧 `tokens/renewal_credentials.json` 有效，按 `uid` 插入 `accounts`，`source='migrated'`。无效凭据不创建半个账号，记录可诊断的迁移结果；迁移不要求网络。
3. 只有凭据成功导入、账号归属明确时，才迁移旧 `proxy_pass.jwt` 和 `refresh_state.json`。有效 JWT 连同 digest 写入 `proxy_pass`；状态按字段映射到 `refresh_state`。无效 token 不覆盖有效数据。旧 `rejected_proxy_pass.sha256` 的合法 digest 导入 `rejected_tokens` 并关联迁移账号，保留最近 32 条。
4. 在同一事务内写入 `meta['legacy_import_v1']` 完成标记并提交。账号数据与标记原子可见：事务失败则两者都不落库；无效或缺失旧文件也会在记录诊断结果后完成一次性处理，避免每次启动重复读取。`PRAGMA user_version` 只由 schema migration 更新，不代替数据迁移标记。
5. 旧文件保持原位置和权限，默认不改名、不删除。显式清理命令完成备份、集合等价性检查和回滚验证后才可处理迁移源；当前仍被 `ExplicitSource` 使用的 `rejected_proxy_pass.sha256` 必须保留，除非同一操作先迁移其状态并证明新路径行为等价。

迁移完成后运行时只读 DB，注册机必须通过 `import-credentials` 导入；不再通过“启动时发现新 JSON”隐式覆盖数据库。数据库非空但缺少旧导入标记时，应要求显式导入/恢复处理旧文件，不能自动合并或消除歧义。

## 6. CLI 与兼容策略

兼容原则是“单账号默认行为不变，多账号功能显式可见”：

| 命令 | 计划 |
|---|---|
| `import-credentials`、`login`、`export-credentials --import` | 按 `uid` upsert；每次同 uid 重新导入都在同一事务删除该账号旧 ProxyPass 和关联拒绝 digest，重置刷新状态为 `credentials_imported`（清空上次尝试、冷却、失败计数和 HTTP 状态，并递增 generation）；`--no-verify` 仍然不联网刷新 |
| `token-status` | 无 `--uid` 且只有一个账号时保持现有 JSON 字段；多账号用 `--uid` 查看单账号，或用新增的 `accounts list --json` 查看列表，不直接替换旧 schema |
| `token-refresh` | 默认维持当前账号语义；新增 `--uid` 和 `--all`，`--force` 只影响选中账号 |
| `usage` | 默认查询当前/指定账号；新增 `--all` 汇总。配额未知时明确输出未知，不把 0 当作耗尽 |
| `accounts list` | 输出 uid、email、enabled、刷新状态和 token 剩余时间，不输出 session token/JWT |
| `accounts enable/disable` | 按 uid 修改 `enabled`；禁用账号不删除历史状态 |
| `accounts remove` | 必须带 uid，并要求显式 `--yes`；事务级联删除账号数据 |
| `run` | 新增 `--account-mode` / `FXPOOL_ACCOUNT_MODE`，首版只接受 `rr`；Pool 同时服务 TCP 与 UDP |

`token-status` 的单账号兼容输出是验收项，不能以“唯一 breaking change”作为默认设计。README 和 `docs/README.md` 只在新增命令稳定后补充说明。

## 7. 分阶段实施与验收门

### Phase 0 — 契约冻结

先补充账号级状态、显式 token 优先级、迁移失败行为和 CLI 输出的测试夹具；确认 `go.mod`、Makefile 与 CI 的实际构建矩阵。此阶段不引入 SQLite。

验收：现有 `go test ./...`、`go vet ./...`、`make fmt-check` 通过；记录当前 `token-status` JSON 作为兼容基线。

### Phase 1 — `internal/store`

引入纯 Go SQLite 驱动，完成数据库安全打开、`user_version` migration、事务 CRUD、账号 upsert、token/state/rejected 导入和完整性检查。不要在这个阶段改 Manager 或命令行为。

验收：离线迁移夹具重复执行结果相同；旧 token/state/rejected 数据全部可读；符号链接、错误权限、损坏 DB 均失败关闭；数据库与 sidecar 不泄露到 0644。

### Phase 2 — 单账号 DB-backed Manager

让 `token.Manager` 绑定 `account_id` 和 store，保留现有 Refresh/Current/Usage/Reject 状态语义。命令先只创建一个账号级 Manager，运行行为保持单账号不变。

验收：老用户仅重启二进制即可读到旧凭据、旧 token 和旧冷却状态；无网络时不触发迁移失败；`probe`、`run`、`token-refresh` 和 `usage` 的单账号行为与基线一致；运行时不再写新的 `refresh_state.json` 或 `proxy_pass.jwt`。

### Phase 3 — Pool 与多账号 CLI

增加账号级 Manager 工厂和 `accounts.Pool`，接入 `run`、刷新循环、`import/login/export` 和账号命令。Pool 只做候选选择与切换，刷新和状态写入由对应 Manager 完成。

验收使用两个 httptest 账号：

- 新建 CONNECT 和 CONNECT-UDP 隧道按 `rr` 在 A/B 间交替；
- A 对 CONNECT 请求返回 HTTP 401/403/407，或对 CONNECT-UDP 返回 MASQUE 认证错误后，下一次尝试走 B；这些响应来自隧道上游端点，不是 Guardian token API；
- A 进入冷却时不被选中，冷却结束后能恢复；
- 两个账号都不可用时返回可诊断错误；
- 显式 JWT 模式不访问账号记录或刷新端点；拒绝 digest 仍持久化到 `rejected_proxy_pass.sha256`，重启后拒绝同一 JWT；
- 单账号 `token-status` JSON 与 Phase 0 基线一致。

### Phase 4 — 配额与本地使用量（单独评审）

先用真实或固定响应确认 `X-Quota-*` 的单位、无限额语义和 429 的账号/全局范围，再增加 `quota` 模式和可选的 `least-used`。本地计数必须同时覆盖 `net.Conn` 和 `net.PacketConn`，在内存中批量刷入数据库，不能在每次读写上同步写 SQLite。

验收：不同配额响应下分布符合定义；`remaining=0` 的账号只在服务端语义确认后跳过；计数不可用时显式回退到 `rr`，不能静默声称额度准确。

### Phase 5 — 文档与构建矩阵

补 README、`docs/guides/multi-account.md`、迁移/回滚说明和变更日志。若要宣称四平台，新增真实的 `GOOS/GOARCH` 构建目标和 CI；否则验收只写当前 Linux amd64/arm64。

## 8. 测试矩阵

| 层 | 必测行为 |
|---|---|
| store | schema migration、迁移幂等、旧 token/state/rejected 导入、账号 upsert、级联删除、并发事务、权限/符号链接拒绝、integrity check 失败关闭 |
| token | 单账号状态机全量回归；按 uid 刷新互不影响；`credentials_imported` 阻断；冷却；旧文件不再写入 |
| accounts | `rr` 确定性、拒绝 token 定位、认证失败切换、冷却过滤、全不可用错误、显式 source 优先级 |
| upstream | TCP CONNECT 和 MASQUE UDP 都只在认证失败后 Reject；网络/模板错误不触发刷新；TokenSource 缺失可选计数能力时行为不变 |
| cmd | 两账号 import → list/status → refresh → run；`--no-verify` 离线路径；旧单账号 status JSON；`--allow-no-token` 启动路径 |
| CI | `go test ./...`、`go test -race ./...`、`go vet ./...`、`make fmt-check`、现有 `make cross`；新增平台只有在实际构建通过后才加入矩阵 |

## 9. 风险与开放问题

1. Guardian 的 quota 单位、429 范围和无限额响应仍需实测；在确认前不启用 quota 加权。
2. 全局刷新锁会让多个账号的刷新串行，但刷新频率低且保留了现有跨进程语义；若实测成为瓶颈，再设计按账号锁，不在首版提前引入。
3. 数据库包含所有账号的 session token，备份、容器卷和权限说明必须按最高敏感度处理。
4. 注册机从“直写 `tokens/`”切换为调用 `import-credentials` 是外部协作项；过渡期只保留手动导入，不做目录监听。
5. SQLite 驱动的二进制体积和各平台构建时间在 Phase 1 实测后记录，不预先写死“增加 8–12 MB”或“低于 25 MB”的未验证数字。

## 10. 验收总标准

- 单账号存量用户升级并重启后，无需联网迁移即可读取原凭据、token 和刷新状态；默认命令行为与基线一致。
- 双账号下，新建 TCP/UDP 隧道可按 `rr` 选择账号；单个账号认证失败时，在存在可用替代账号的条件下，新建连接按一次重试切换。
- 数据库、WAL sidecar 和旧凭据文件均保持受限权限；损坏数据库不会被自动覆盖。
- `tokens/` 不再产生新的运行时 JSON；旧文件仅作为保留的迁移源，直到显式清理。
- 全量测试、竞态测试、vet、格式检查和当前构建矩阵通过；任何新增平台都有对应构建证据。
