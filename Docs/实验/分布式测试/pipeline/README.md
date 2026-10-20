# S15 pipeline 资产

本目录继承私有仓库 S15 提交 `b38aaa7680f6c80e6841d05a17e08cd0e50627b1` 的
campaign 编排、冻结、部署、清理和证据校验脚本，只作为历史实现参考。

## 使用边界

- 不是当前 `AstralLight.Next` 的默认测试入口，不参与 `scripts/test_campaign.py` 派发。
- 脚本中的 run ID、`/home/...` 路径、节点角色和中间件名称属于历史环境，
  必须由受保护环境重新提供；不得直接在当前机器执行。
- `runtime-cleanup.sh` 会执行 `docker stop/rm`、删除 Rabbit vhost 和远端 run 目录，
  属于破坏性操作，只能在已批准、run-scoped 的隔离环境使用。
- 两个 `*.runtime-cleanup.sh` 实际是 Python 脚本（上游保留了 `.sh` 后缀），
  应以 `python3` 运行，不能用 `bash`。
- `pipeline/` 不包含真实凭据；数据库/Redis/RabbitMQ 密码通过调用方环境注入。
  历史归档中的地址已脱敏，见 [`../archives/README.md`](../archives/README.md)。

## 文件类别

| 文件 | 用途 |
|---|---|
| `.astral-final8-*.sh` / `.astral-final9-*.sh` | 冻结、构建、部署、campaign、清理 |
| `.astral-final8-identities.txt` | harness/source 哈希身份，不是人员或节点凭据 |
| `.astral-final8-*-manifest.sha256` | 历史文件清单哈希 |
| `.astral-final8-filelist.txt` | 历史源码/测试文件清单 |
| `.astral-final8-scan-gate-test.py` | 秘钥泄露扫描门禁测试 |
| `.astral-final9-verify-archive.py` | 证据归档校验 |
