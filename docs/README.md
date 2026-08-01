# Documentation

本目录汇集 Firefox IP Protection 逆向研究结论，以及 `fxpool-proxy` 与上游协议的兼容说明。
文档已脱敏：不含账号、session、JWT、真实邮箱、本机 profile 路径或实测出口 IP。

## 目录

| 分类 | 路径 | 内容 |
|------|------|------|
| 研究结论 | [research/](research/) | 架构、协议栈、源码实证 findings |
| 过程笔记 | [notes/](notes/) | 路线图、攻击面清单、脱敏验证日志 |
| 上游兼容 | [compatibility/](compatibility/) | Remote Settings / Guardian 适配与时序图 |
| 操作指南 | [guides/](guides/) | 从本机 Firefox 取得续期凭据 |
| 安全 | [SECURITY.md](SECURITY.md) | 漏洞报告与凭据处理边界 |

## 快速入口

1. **协议与认证总览** → [research/findings.md](research/findings.md)
2. **实测验证（已脱敏）** → [notes/verification-log.md](notes/verification-log.md)
3. **本仓库运行方式** → 仓库根目录 [README.md](../README.md)
4. **上游兼容细节** → [compatibility/firefox-upstream-compatibility.md](compatibility/firefox-upstream-compatibility.md)

## 隐私约定

写入或更新文档时：

- 用占位符替代 email、uid、session_token、OAuth/JWT、profile 路径、监听密码。
- 验证结果只保留国家/城市、协议、HTTP 状态、节点数量、AS 归属等非敏感摘要。
- 不要粘贴 HAR、抓包、Browser Toolbox 导出或带认证的代理 URL。
