# Git 与 GitHub 协作规范 V1.0

> 本文是分支、Issue、Commit、PR、评审、合并、标签与发布的规范源。提交信息格式以 [Rust 后端编码规范](Rust后端编码规范_V1.0.md) §17.1 为基础，本文在此之上补充协作流程；破坏性变更的登记要求以该规范 §14 为准。Agent 执行门禁见根目录 [`AGENTS.md`](../../AGENTS.md)，贡献者授权条款见 [`CONTRIBUTING.md`](../../CONTRIBUTING.md)。

## 1. 分支模型

| 分支 | 用途 | 规则 |
|------|------|------|
| `main` | 稳定参考设计，对外默认分支 | 受保护；只能通过 PR 合并；禁止直接推送、禁止强推、禁止删除 |
| `<type>/<issue-id>-<short-desc>` | 短期功能、修复、文档分支 | 从最新 `main` 拉出，PR 合并后删除 |
| 长期实验分支（如 `memroy-v1`） | 维护者主导的重设计 | 不要求与 `main` 同步；合回 `main` 必须走 PR，并按 §14 登记破坏性变更 |

- 短期分支的 `type` 与 commit type 一致：`feat` / `fix` / `docs` / `refactor` / `test` / `chore`；实验性尝试用 `exp/`。
- `short-desc` 用英文小写短横线，例如 `fix/41-revoke-fence-timeout`、`docs/43-architecture-index-en`。无对应 Issue 的纯文档小改可省略 `issue-id`。
- 本仓库当前不设 `dev` 分支，PR 直接以 `main` 为目标；编码规范 §17.2 中的 `dev` 约定在本仓库不适用。
- 外部贡献者请 fork 后在自己的仓库建分支，再向 `main` 提 PR。

## 2. Issue

- 除拼写、链接等极小改动外，每项变更都应关联一个 Issue，说明动机、范围和验收方式。
- 较大的设计变更（授权路径、投影、撤销栅栏、schema）先在 Issue 中讨论，再动代码。
- 常用标签：`bug`、`enhancement`、`documentation`、`question`、`good first issue`（适合新人）、`help wanted`（需要外部帮助）。
- 安全问题不要开公开 Issue，按 README "Security and responsible use" 一节私下报告。

## 3. Commit

格式沿用编码规范 §17.1：

```
<type>(<scope>): <subject>

<body>

<footer>
```

- `subject`：英文小写、祈使语气、不超过 72 字符、结尾不加句号。
- `scope` 取受影响的 crate 或领域，例如 `auth`、`engine`、`gateway`、`identity`、`db`、`mq`、`trustgraph`、`single-node`、`monitor`、`sdk`、`harness`、`docs`、`ci`。
- `body` 说明为什么改、改了什么边界；涉及授权语义时写明 fail-closed 行为是否变化。
- `footer`：关联 Issue（`Refs #41` / `Closes #41`）；破坏性变更写 `BREAKING CHANGE:`，并按编码规范 §14.4 列出删除面、替代入口、影响范围、迁移和回退方案。
- 一个 commit 做一件事；不提交密钥、凭据、数据库地址、运行清单或生成的证据文件。

## 4. Pull Request

PR 描述至少包含：

1. 关联的 Issue 与变更目的；
2. 改动范围与不在范围内的内容；
3. 已运行的检查及环境（例如 `cargo test --workspace --locked`、某个 `test-campaign` suite、是否使用真实 MySQL/RabbitMQ）；依赖缺失时不得把结果写成通过；
4. 授权语义影响：是否可能产生 stale ALLOW、绕过 `PolicyEngine::evaluate()` 或新增 fallback；证据缺失时必须仍为 `PENDING`/`DENY`；
5. 破坏性变更说明（如有）；
6. `CONTRIBUTING.md` 要求的 AGPL 贡献确认声明。

PR 应保持聚焦；大改动拆成可独立评审的小 PR。草稿阶段请使用 Draft PR。

## 5. CI 与评审

- 所有指向 `main` 的 PR 必须通过 `Rust CI`（`.github/workflows/rust-ci.yml`）：零警告门禁、`cargo fmt --check`、`cargo check`、`cargo clippy -D warnings`、`cargo test --workspace`、`cargo doc`。
- 至少一位维护者批准后才能合并；有新提交时旧批准失效，需要重新评审。
- 评审重点依次为：授权正确性与 fail-closed、租户隔离、事务与投影边界、测试证据是否如实、代码风格。
- 评审意见由作者回复或修改后由评审者标记解决，不由作者自行关闭未答复的意见。

## 6. 合并

- 只有维护者可以合并到 `main`。
- 默认使用 merge commit（保留 PR 历史）；单 commit 的小 PR 可用 squash，squash 后的标题仍须符合 §3。
- 禁止 rebase 改写已推送到 `main` 的历史。合并后删除短期分支。

## 7. 标签与发布

- 版本号遵循编码规范 §14.5：workspace 内 crate 版本对齐，`0.x` 为开发阶段。
- 发布时在 `main` 的合并提交上打附注标签 `vX.Y.Z`，并在 GitHub Release 中列出主要变更、破坏性变更与已知限制。
- 发布说明只陈述已有证据支持的结果，不把未运行的集成或部署写成已验收。

## 8. 维护者与权限

- 仓库所有者负责分支保护、合并权限与发布；新增维护者由所有者授予。
- 自动化工具或 Agent 只能在功能分支上工作，推送需获得维护者明确批准，不得合并或推送 `main`（见 `AGENTS.md`）。
