# S15 证据归档（脱敏副本）

- 来源：私有仓库 `AstralLight`，S15 资产提交 `b38aaa7680f6c80e6841d05a17e08cd0e50627b1`。
- 原始文件：`astral-final9-evidence-20260906.tar.gz`
- 原始 SHA-256：`2cb200e005984f8142697cf7f21d6f5b2be37841be668f52f7f1e09d44a2cc6a`
- 本仓库文件：`astral-final9-evidence-20260906.redacted.tar.gz`

## 脱敏规则

原始归档中的 IPv4 地址已替换为 `<redacted-host>`，共修改 9 个文本文件。压缩包内的
`MANIFEST.md`、逐文件 checksum 和任何原始哈希均为脱敏前值，**不再与本归档逐字节匹配**；
需要验证原始证据时，应以私有仓库中的原始归档和上述 SHA-256 为准。

## 证据边界

本归档是 2026-09-06 的历史实验证据，只用于回溯当时的场景、失败项和测量方法。它：

- 不代表当前 `AstralLight.Next` 代码、当前部署或当前三节点环境的结果；
- 不构成任何 `PASS`、生产验收或安全证明；
- 不能替代当前源码快照下重新执行的 S15 campaign。
