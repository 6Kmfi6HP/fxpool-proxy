# 逆向路线图

目标：还原 Firefox 内置 IP Protection 的协议、认证与配置下发，并产出可运行的本地代理（本仓库 `fxpool-proxy`）。

## 阶段 0：情报（已完成）

- 确认功能 = IP Protection，Firefox 149+，浏览器级代理，服务商 Fastly。
- 官方文档：`toolkit/components/ipprotection` + `browser/components/ipprotection`。
- 见 [architecture.md](../research/architecture.md)、[protocol.md](../research/protocol.md)。

## 阶段 1：静态源码分析

1. 通读 `IPProtectionService`、`IPPProxyManager`、`GuardianClient`、`IPProtectionServerlist`
2. 确认 MASQUE（CONNECT-UDP）与 CONNECT fallback
3. 确认 Remote Settings collection 与 pref 全集
4. 产出：写入 [findings.md](../research/findings.md)

## 阶段 2：动态验证

前置：支持地区 + Firefox 149+ + 有资格的本人 FxA。

验证项：

- 认证链路（FxA session → OAuth → Guardian ProxyPass → CONNECT）
- 多国出口端到端（SOCKS5 / HTTP CONNECT）
- 综合随机入口
- （可选）QUIC/HTTP3 抓包 — 本仓库未覆盖 MASQUE 数据面

实证见 [verification-log.md](verification-log.md)（已脱敏）。

## 阶段 3：协议复现

- 已完成：TCP CONNECT 代理池（本仓库）
- 未做：MASQUE / HTTP3 / QUIC / UDP 数据面

## 阶段 4：文档

- 研究结论与兼容记录归入本 `docs/` 目录
- 运行说明见仓库根 [README.md](../../README.md)

## 风险 / 注意

- 完整 egress 需要合法本人凭据；不可绕过配额或资格。
- JWT 仅做结构/claims 校验，不做签名密码学验证。
- Remote Settings 未实现 Kinto 内容签名 / Mozilla PKI 完整校验。
- 仅研究开源实现与合法自用；遵守 Mozilla / Fastly 服务条款。

## 任务追踪

- [x] 阶段 0 情报收集
- [x] 阶段 1 静态分析（核心结论已写入 findings）
- [x] 阶段 2 动态验证（CONNECT 路径；不含 MASQUE 抓包）
- [x] 阶段 3 TCP CONNECT 复现（`fxpool-proxy`）
- [ ] 阶段 3 补 MASQUE/HTTP3 数据面（可选）
- [x] 阶段 4 文档整理（本目录）
