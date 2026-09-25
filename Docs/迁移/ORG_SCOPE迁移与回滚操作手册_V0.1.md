# ORG_SCOPE 迁移与回滚操作手册（V0.1）

> 状态：**文档就绪；真实迁移、演练均未执行（BLOCKED，待 Exec-L3）**。
> 对象：additive 迁移 [20260922000001_org_scope_authority.sql](../../astral-db/migrations/20260922000001_org_scope_authority.sql)（多租户改造 Phase 2，ORG_SCOPE 行政授权链 DB owner 切片）。
> 交付状态（截至 2026-09-22）：迁移文件与全部 ORG_SCOPE 相关源码（迁移 SQL、`org_scope_repository`、org 治理 API/service、`org_admission`/`org_compiler`、`org_scope_projector`、preflight/回滚脚本及本手册）均为**当前工作区已创建、git 未跟踪（untracked）、尚未 stage/commit**。本文所有"完成"均指工作区状态，不等于已进入仓库提交历史；须由后续授权交付步骤完成 stage/commit，在此之前 release/CI checkout 不包含这些文件。**未对任何数据库应用**；应用与否属 Exec-L3 运维动作。本手册不记录服务器地址、凭据或连接串，数据库目标一律经 `ORG_MYSQL_URL` 环境变量注入。
> 关联：[Rust多租户聚合分区与组织层级设计_V0.1.md](../架构/Rust架构设计/Rust多租户聚合分区与组织层级设计_V0.1.md)（§4/§7 目标合同与 M2 状态）、[Rust后端编码规范_V1.0.md](../规范/Rust后端编码规范_V1.0.md)、[AGENTS.md](../../AGENTS.md)（Exec 分层、五链审查与迁移门禁）。

## 1. 迁移定位与边界

- **全增量（ADDITIVE）**：只创建 13 张新表，无 `ALTER`、无回填、无删除，不触碰任何既有表；`CREATE TABLE IF NOT EXISTS` 语义。
- **不写旧链事件**：不写 `authorization_delta_event` / `authorization_grant_revision`。旧 worker 以 `CanonicalGrant`（user_id 绑定）解码，org 载荷是独立 typed 合同，混入会被旧链误读；org 事件走 `org_scope_outbox`，由新的 org projector 消费。**当前工作区已完成 TrustGraph 的 default-off、显式 tenant allowlist 源码接线与 typed 覆盖；未在任何服务进程启动，未进行真实集成或部署验收，不得把源码接线写成运行时验收完成。**
- **应用迁移 ≠ 启用特性**：运行时默认关闭，由 `ASTRAL_ORG_SCOPE_ENABLED` 门控（严格 bool：unset/空 = 关闭；非法值 = 启动拒绝）。
- **应用入口**：既有显式迁移入口 `astral_db::migration::apply_migrations`（sqlx 内嵌 migrator，成功记录写入 `_sqlx_migrations`）。服务启动路径 `connect_and_validate_schema` 只做契约校验、不应用迁移。**本手册不新增、不调用任何迁移 API 端点。**

## 2. 13 表 additive 模型

| # | 表 | 角色 |
|---|----|------|
| 1 | `org_scope_node` | 行政树节点；每租户一个 unit aggregate（node 行即 `(tenant_id,'ORG_SCOPE',tenant_id)` 聚合根状态），携带 `generation`/`revoke_fence`/`relationship_revision` |
| 2 | `org_scope_request` | 审批请求（ROOT_INIT、root grant、attach、move、detach、scope grant），`payload_json` 对应 `astral_types::org_scope::OrgRequestPayload` |
| 3 | `org_scope_grant` | 授权当前状态；`subject_kind` 为 UNIT（共享单元贡献，subject 列为 NULL）或 PERSONAL（显式用户/卡对），不为 UNIT 伪造 user_id |
| 4 | `org_scope_revision` | NODE/GRANT/MASK/MEMBERSHIP 的 append-only 修订账，digest 绑定精确字节，历史不更新不删除 |
| 5 | `org_scope_mask` | 本地精确来源剪裁（屏蔽某一目标 grant revision），不改写来源 grant |
| 6 | `org_scope_membership` | 成员资格（user + identity_card + user_card 三元组绑定到受管单元），独立版本化事实 |
| 7 | `org_scope_publication` | 不可变 sealed 发布（insert-only，status 不离开 SEALED） |
| 8 | `org_scope_segment` | 发布 segment（insert-only，编译贡献内容，不含伪造 user_id） |
| 9 | `org_scope_current` | 每受管单元当前发布指针（generation 单调 CAS） |
| 10 | `org_scope_outbox` | org 专属 outbox（新 worker；状态机 PENDING/LEASED/FAILED/DONE，lease owner + token-hash + expiry + CAS、有限重试） |
| 11 | `org_scope_dependency` | durable 依赖 pin（与发布同事务写入，fan-out 与新鲜度校验的事实来源） |
| 12 | `org_scope_operation` | operation 幂等账（`operation_id` 主键 + `input_digest` 绑定；同 id 异 digest 为硬冲突） |
| 13 | `org_scope_audit` | org 审计轨迹（同一 source transaction 内逐 durable mutation 落行，关联 actor/request/operation/subject） |

## 3. 精确唯一/检查约束

- `org_scope_node`：`PRIMARY KEY (tenant_id)` —— 每租户至多一个行政节点行。
- `org_scope_request`：`UNIQUE uk_osr_operation (operation_id)`。
- `org_scope_grant`：
  - `CHECK chk_osg_subject`：`UNIT` ⇒ `subject_user_id`/`subject_card_id` 均 NULL；`PERSONAL` ⇒ 两者均 NOT NULL 且 > 0。
  - `CHECK chk_osg_parent`：`parent_tenant_id`/`parent_grant_id`/`parent_grant_revision` 三列全 NULL 或全 NOT NULL，且 `parent_tenant_id = origin_tenant_id` 且 `parent_grant_id <> grant_id`（禁止自父）。
- `org_scope_revision`：`UNIQUE uk_osv_subject (subject_kind, subject_id, revision)`。
- `org_scope_mask`：生成列 `active_flag = IF(active=1,1,NULL) STORED`；`UNIQUE uk_osm_active (tenant_id, target_grant_id, active_flag)` —— 每 (tenant, 目标 grant) 至多一条 active mask。
- `org_scope_membership`：生成列 `active_card_flag = IF(active=1,1,NULL) STORED`；`UNIQUE uk_osmem_active_card (card_id, active_card_flag)` —— 每张卡至多一条 active 成员资格；`KEY idx_osmem_card (card_id, active)` —— 卡级 active 检查的固定扫描范围；`KEY idx_osmem_user_active (user_id, active)` —— global-per-user active membership cap 的锁定计数范围，列序不得漂移。
- **identity-card 串行锚点前置**：既有基线必须存在唯一单列 `identity_card.uk_ic_user(user_id)`；membership create 先以它取得同用户单行 `FOR UPDATE` 锁，再校验物理卡绑定并读取 membership 范围。该锚点使全局 cap 不依赖 `READ COMMITTED` 下不存在的 gap-lock 保护；migration `20260922000001` 为 additive，绝不创建、回填或修复这个既有 identity schema 契约。缺失、非唯一或列序漂移时 preflight 必须拒绝 `MANAGED-CAPABLE`。
- **数据库版本前置**：目标 MySQL 必须为 **8.0.16 或更高版本**，以保证本迁移的 `CHECK` 约束受服务器实际执行；`GENERATED ALWAYS ... STORED` 和唯一索引也必须在 preflight/演练环境中按该版本验证。不得把仅能解析而未强制执行 `CHECK` 的旧版本当作满足本手册的验收目标。
- `org_scope_publication`：`UNIQUE uk_osp_generation (tenant_id, generation)`。
- `org_scope_segment`：`UNIQUE uk_oss_position (publication_id, segment_index)`。
- `org_scope_current`：`PRIMARY KEY (tenant_id)`；发布推进依赖 generation 单调 CAS（`cas_version`）。
- `org_scope_outbox`：`UNIQUE uk_oso_event (event_id)`。
- `org_scope_dependency`：`UNIQUE uk_osd_pin (dependent_tenant_id, depends_on_tenant_id, publication_id)`。
- `org_scope_operation`：`PRIMARY KEY (operation_id)`。

## 4. default-off 门禁与回退禁令

- 部署旗标 `ASTRAL_ORG_SCOPE_ENABLED`：严格 bool（unset/空 = 关闭；非法值 = Err，main 拒绝启动），默认 false。
- **projector tenant allowlist**：启用时必须显式设置 `ASTRAL_ORG_SCOPE_TENANTS`（正整数、去重、至多 64 个）。启动期在任何 worker/路由装配之前读取全部 `org_scope_node` 行；allowlist 漏掉任一当前管理态 tenant 即拒绝启动，不能让其 outbox 静默积压。准备 ROOT_INIT、ATTACH/MOVE 或其他可能使新 tenant 成为受管单元的 mutation 前，必须先把该 tenant 加入 allowlist 并完成重启；运行进程内 allowlist 冻结，控制面会拒绝对未覆盖 tenant 创建/批准新 authority work。inactive node 仍须列入，因为它可能保留撤销/拓扑 outbox。
- **资源属主解析前置**：正式 HTTP 授权只能使用服务器端权威 resource-owner resolver 填充 `PolicyContext.resource_tenant_id` / `resource_domain_id`；不得从客户端头、body 或 actor tenant 伪造。当前普通 TrustGraph HTTP 路由尚未接入该 resolver，因此跨 tenant 子单位的 ORG contribution 会 fail-closed 为 `DEFAULT_DENY`。在该 resolver 与目标资源路由接通、并完成真实集成验收前，**不得启用** ORG_SCOPE 生产流量；根租户同租户测试不构成跨 tenant 可用性验收。
- 读侧 gate 四态（`probe_org_scope_gate`）：
  - `SchemaUnmanaged`：确知 `org_scope_node` 不存在 → 特性从未激活，legacy 行为正确；
  - `Pending`：任何其他 DB 失败 → fail-closed，不得当作 Unmanaged；
  - `TenantUnmanaged`：表存在但该租户无 node 行 → legacy；
  - `TenantManaged`：存在 node 行 → 受 org 治理。
- **受管租户回退禁令**：租户成为受管的唯一途径是经批准的 ROOT_INIT request 创建 `org_scope_node` 行；此后即使旗标关闭、陈旧或状态未知，其组织业务授权分支也必须 `DENY`/Disabled，**不得回退 legacy grants、raw source 读取、旧快照或缓存**（[AGENTS.md §3.1/§3.2](../../AGENTS.md)）。
- 迁移文件存在不等于目标数据库已应用；受管状态只由 durable 的 node 行与已批准 mutation 决定。

## 5. 上线顺序（执行前置，逐项留证据）

1. **Exec-L3 审批**：批准对象、`runId`、allowlist、preflight、postcondition 与人工终审（[AGENTS.md §0C/§3.5](../../AGENTS.md)）；变更关联 Issue 或文档；确认目标 MySQL 为 8.0.16 或更高版本。
2. **只读 preflight（应用前）**：`ORG_MYSQL_URL=... bash scripts/org_scope_preflight.sh preflight`。脚本接受无 query/fragment 的 `mysql://user:percent-encoded-password@host:port/database` URI，通过 `--host/--port/--user/--database` 调用经典 `mysql` 客户端，密码经 `MYSQL_PWD` 环境变量传递，不放入客户端参数；为避免 shell/client 解析歧义，用户名、密码和库名仅接受 URI 未保留字符或 percent-encoded 保留字符。可先离线运行 `bash scripts/org_scope_preflight.sh self-test` 检查 URI 解析。期望输出：`_sqlx_migrations` 无 20260922000001 记录、13 表全部 `[missing]`、`schema state: UNMANAGED`。preflight 只读，不应用迁移、不做任何 DDL/DML；缺少 `mysql` 客户端时会 fail-closed。
3. **备份/恢复演练**：新表暂无业务数据，演练重点是迁移可重入（`IF NOT EXISTS` + `_sqlx_migrations` 历史行）与回滚边界（§6）；演练结果留档。
4. **应用迁移**：通过既有显式迁移入口执行 sqlx 内嵌 migrator（见 §1）。当前 `ensure_isolated_migration_target` 只允许 `ASTRAL_MIGRATION_ENV=isolated`，数据库名 `astral_test` 或 `astral_rehearsal`，且目标为 localhost/127.0.0.1/::1:3308；`astral-migrate --apply` 另有隔离目标守卫。因此本步骤仅适用于经批准的本机隔离演练库，不构成生产迁移流程；执行过程与 `_sqlx_migrations` 记录留证据。
5. **postcondition（应用后）**：再次运行 preflight，期望 13 表全部 `[ok]`、`org_scope_membership idx_osmem_user_active(user_id,active)` `[ok]`、`org_scope_membership idx_osmem_card(card_id,active)` `[ok]`、`identity_card uk_ic_user(user_id)` 唯一用户锚点 `[ok]`、`_sqlx_migrations` `[ok]` 记录 20260922000001、`schema state: MANAGED-CAPABLE`、`managed tenants: 0`、outbox 各状态计数为 0；`ASTRAL_ORG_SCOPE_ENABLED` 保持 false。
6. **启用前 tenant 覆盖证明**：设置冻结的 `ASTRAL_ORG_SCOPE_TENANTS`（每个现存 `org_scope_node.tenant_id` 都在内，含 inactive node；最多 64 个），以启用配置启动实例只读验证 coverage。遗漏任一管理态 tenant 会在 worker/路由启动前失败；准备 ROOT_INIT、ATTACH/MOVE 或其他可能新增受管 tenant 的操作时，先扩 allowlist 并滚动重启，不能依赖进程内动态刷新。
7. **资源属主 resolver 验收**：对每个受保护资源路径，服务器端 resolver 必须能在 `PolicyEngine.evaluate()` 前设置权威 `resource_tenant_id` / `resource_domain_id`，并覆盖跨 tenant 子单位请求、撤销和 source/resource tenant 不匹配反例。普通签名 actor tenant、请求 header/body 均不构成资源属主事实；在此验收完成前不得启用跨 tenant ORG_SCOPE 生产流量。
8. **启用是另一个 Exec-L3**：org worker 的 default-off 源码运行时接线与 event-kind 合同 typed 覆盖已完成；完成 tenant coverage、资源属主 resolver 和真实集成验收，并取得相应 Exec-L3 审批之后，才允许讨论显式启用；本迁移不承诺该步骤。

## 6. 回滚边界（破坏性）

- **唯一回滚路径**：`ORG_MYSQL_URL=... bash scripts/org_scope_preflight.sh rollback --i-understand-data-loss`。没有专用 rollback 脚本，也没有其他受支持的回滚入口。
- **破坏性**：DROP 全部 13 张 `org_scope_*` 表及其全部数据；除备份恢复外不可逆。
- **硬前置**：Exec-L3 批准；备份/恢复演练已完成；**每一张 `org_scope_*` 表均为空**（0 受管租户、`org_scope_outbox` 无 PENDING/LEASED 事件——行计数覆盖全部表，不止 node）。
- **脚本守卫**：发出任何 `DROP` 之前先逐表行计数校验，任一**已存在**表有行即整体拒绝；第二轮会在每张表的 `DROP` 紧前重新计数，若行数在首轮检查后增长即停止。DDL 不能用普通事务消除所有 TOCTOU，因此 Exec-L3 runbook 仍要求先关闭所有 ORG writer/projector/服务实例并确认无并发 source mutation；脚本不会把二次检查表述为 schema 原子性。脚本会跳过本就缺失的表，因此“整体拒绝”描述的是数据删除边界，而不是把部分 schema 自动补齐或回滚为原子 DDL。`--i-understand-data-loss` 显式确认必须保留。
- **迁移历史不可被 rollback 擅改**：脚本刻意不删除 `_sqlx_migrations` 中的 `20260922000001` 记录。故 rollback 后直接再次运行同一版本的 sqlx migrator 会被跳过，**不会**重建 13 张表；preflight 会把“version recorded + all tables absent”报告为 incoherent。恢复只能通过已验证的备份恢复，或另立、审查并应用新的 forward migration；不得手工删除 migration history 或把迁移当作普通重放任务。
- 回滚完成后，部署保持 `ASTRAL_ORG_SCOPE_ENABLED=false`，直至完成上述恢复路径、重新 preflight 并取得新的 Exec-L3 验收。
- 迁移不是普通重试任务；不使用通用自动重放（[AGENTS.md §3.5](../../AGENTS.md)）。

## 7. 执行状态（证据边界）

| 动作 | 状态 |
|------|------|
| 迁移文件、preflight/回滚脚本、本手册在当前工作区创建 | 完成（截至 2026-09-22：迁移 SQL、脚本和手册均未提交；`migration.rs` 与本目录 README 为已跟踪文件的未提交修改；未触碰任何数据库） |
| preflight 脚本离线契约验证（`ORG_SCOPE-PREFLIGHT-OFFLINE-20260922`） | **PASS**：`bash -n scripts/org_scope_preflight.sh`、`bash scripts/org_scope_preflight.sh self-test`、URI 连接参数/`MYSQL_PWD` 静态断言及无 CRLF 检查均通过；本机缺少 `mysql` 客户端时 `preflight` 在任何 DB 调用前 fail-closed。该证据仅覆盖脚本语法与 URI 边界，不等价于真实数据库 preflight。 |
| ORG_SCOPE 文件 stage/commit（后续授权交付步骤） | **未执行**；提交前 release/CI checkout 不包含上述文件 |
| 真实数据库迁移应用 | **未执行（BLOCKED，待 Exec-L3）** |
| preflight 对真实数据库运行 | **未执行** |
| 备份/恢复演练 | **未执行** |
| 回滚演练 | **未执行** |
| org worker 运行时接线 + event-kind 合同核对 | 完成（default-off 源码接线、tenant coverage/恢复边界与 typed 覆盖；未启动 worker） |
| 权威 resource-owner resolver 接入到全部受保护 HTTP 路径 | **未完成（BLOCKED；跨 tenant 子单位正式授权不得启用）** |
| 真实集成验收 | 未完成 |

以上未执行项不能由文档、typed 测试或任何 `exit 0` 折算为 `PASS`（[AGENTS.md §7.1](../../AGENTS.md)）；本手册描述的是目标流程，不构成执行证据。

## 8. 维护约定

- 迁移文件、脚本语义变化时先更新本手册，再同步 [Docs/迁移/README.md](./README.md) 清单。
- 本文为操作手册；运行时事实以 source、schema/migration 与 tests 为准，与 [AGENTS.md §3](../../AGENTS.md) 不变式冲突时先停、登记、补验证。
