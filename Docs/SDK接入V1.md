# SDK 接入 V1

V1 已实现平台独立 SDK、默认关闭的远程准入和最小身份映射管理，另有独立 Chat/Learn 接入样板。它不是生产开户、迁移或切流验收记录。验证状态见 [实施证据](SDK接入V1_实施证据.md)。

## 1. 必须建立的映射

```text
(app_id, issuer, subject) -> existing platform_user -> identity_card
```

第三方保留原业务数据库、本地账号、用户 ID 和密码。平台管理员把业务主体绑定到已有平台用户和身份卡，不按邮箱/手机号/名称自动合并，不自动建用户或卡。映射本身不发放 `user_card`，更不把旧角色转换为授权。

正式接入仍需平台 Access 会话、Gateway 验签后的 PlatformUser 双卡，以及有效用户卡资格和 published evidence。缺映射、停用/撤销、源用户或身份卡无效时拒绝；AppUser identity-only、机器主体、客户端自报卡和角色不能回退放行。现有第三方 OAuth/OIDC/token-exchange 保持 `OAUTH_DISABLED`，V1 不增加任意 IdP。

`app_id` 为最多 64 字节的小写 ASCII 标识，以字母开头；issuer/subject 为 1..256 字节可见 ASCII。合法 tuple 按字节精确比较，不 trim、case-fold 或 Unicode normalization；不符合 V1 的输入直接拒绝。

## 2. 接入顺序

1. 管理员批准应用 ID、公钥、issuer、资源/动作 manifest 和外部 tenant/domain 到平台范围的映射。每个资源只有一个应用 owner；内置资源只允许 Chat/Learn 业务资源，其他资源必须已在 ResourceRegistry 注册。注册不授予规则。
2. 使用集中路由声明生成 manifest，批准其 digest/revision。SDK 无自注册和自扩权入口。配置启动期冻结，修改应用或密钥、撤销应用须停用准入并更新批准配置/重启；映射停用则由数据库读取即时复核。
3. 在 Identity 的受保护管理入口预置已有身份映射。管理入口经 Gateway、PolicyEngine、ACTIVE GlobalAdmin，仓储事务内再次锁定管理员状态。
4. 业务认证适配器从可信本地会话给出 external subject、平台 token ID 和平台 Bearer。不能把业务客户端的身份头当成可信事实。
5. 业务 resolver 从本地权威数据提供 target、tenant/domain、owner 和 revision。应用私钥及 resolver 是接入方信任边界，SDK 无法证明被攻陷的业务服务没有谎报自己的数据。
6. SDK 请求远程完整准入，验签结果后业务在本地短事务/CAS 中复检事实再提交。不持锁等待 RPC。版本变化必须重新授权。

## 3. 已实现的组件

| 组件 | 职责 |
|---|---|
| `astral-sdk-contracts` | 严格 wire DTO、manifest、摘要、Ed25519 请求/决策签名 |
| `astral-sdk` | 有界 HTTPS 客户端、Bearer、签名和请求绑定验证、当前时钟复核 |
| `astral-sdk-axum` | 异步 actor/facts resolver、集中拦截、显式公开路由、一次性 proof extension |
| Identity / astral-db | 最小映射、前向状态、revision CAS、operation ledger 和事务内审计 |
| TrustGraph | 应用批准范围、nonce、当前会话/映射、PolicyEngine、SoD、原 fence、准入评估审计 |
| `integrations/` | 独立 SDK 消费 workspace，不依赖平台数据库、引擎或 MQ crate |

SDK manifests 使用具体依赖版本而不继承平台 workspace。许可保持 `AGPL-3.0-or-later`，未发布 crates，也未变更许可；第三方接入需遵守 [现有许可边界](../LEGAL.md)。

## 4. HTTP 契约

```text
POST /main/api/v1/integrations/authorization-decisions
Content-Type: application/json
Authorization: Bearer <platform-access-token>
```

请求/决策 DTO 使用 snake_case；外层平台 `ApiResponse` 和启动应用配置使用 camelCase。未知字段拒绝。签名域固定为 `astral-sdk-authorization-request-v1` / `astral-sdk-authorization-decision-v1`，并绑定固定准入端点，不依靠可由客户端扩大版本的字段。

请求为 `{ request, signature }`，request 必含 app_id、key_id、manifest_digest、revision（manifest revision）、request_id、nonce、timestamp（Unix 毫秒）、session_token_id、subject、method/path（业务请求）、action、operation_id 和 facts。facts 包含 resource_type、target_id、external_tenant_id/domain_id、owner、revision 和 operation。无平台 user/card/role/PolicyContext 或 Global classification 字段。

决策包含 request_digest、facts_digest、request_id、精确 scope、mapping_revision、outcome、reason、issued_at_ms/expires_at_ms。请求摘要间接绑定 action、operation ID、nonce、清单和完整事实。只有 `Allow` 可以消费，`Deny`/`Pending` 即使在 HTTP 200 内也不放行。协议失败用 400/401/403/503；SDK 只接受 HTTP 200 且 success=true、code=200、traceId=request_id 的签名数据。

- 请求/响应最多 64 KiB，manifest 最多 32 KiB/128 路由，启动配置最多 256 KiB/64 应用/每应用 256 个范围。
- target 是应用本地正十进制 i64，不允许前导零；无通用 opaque ID 或批量对象语义。
- resolver 必须指定单路径参数如 `/{id}`；`permits_request` 同时核对 route/resource/action/operation 和 path 参数等于 facts.target_id。重叠声明拒绝。
- collection 绑定明确范围 ID 和范围 revision，平台只使用类型级权限 `target_id=None`，业务再按精确范围过滤；单对象 grant 不能扩成全表许可。collection 不接受 owner。
- V1 同 tenant/domain，不隐式扩为跨组织。Axum adapter 暂不接受 query；集合分页/查询过滤不在 V1 通用合同内。
- 决策 TTL 最多 5 秒，未来签发和到达过期边界即拒绝；请求时钟偏差最多 30 秒。SDK 在网络前、响应后和消费前读取实际时钟。
- 默认 HTTPS，禁重定向、自动重试和 ALLOW 缓存；总超时最多 10 秒。HTTP 仅显式测试 opt-in 且回环 IP 字面量，loopback 不继承代理配置。平台准入限时 5 秒，两个 resolver 各限时 2 秒。

远程授权与业务提交不是同一个事务。有效期不能消除跨系统撤销窗口，不能承诺零窗口或全局 exactly-once。非 Clone proof 只保证同一内存对象不重复消费；消息/业务一致性由稳定 operation ID、业务摘要和本地 CAS/ledger 负责。

## 5. Rust / Axum 接入

SDK 客户端使用 `ClientConfig::new(endpoint, timeout, response_limit, decision_key_id, decision_public_key)` 和 `SdkClient::new`。每次构建并签署 AuthorizationRequest，再调用：

```rust
let proof = client.authorize(&signed_request, &access_token).await?;
proof.require_allow_current(&signed_request.request)?;
// Local owner now rechecks facts/revision and applies its transaction/CAS.
```

只需检查后退出的用例可调用按值 `consume_allow(proof, request)`。写业务不能用这一步替代本地事实复检。

Axum 按路由组集中装配 `AuthorizationLayer::new`，实现 `ActorResolver` 和 `ResourceFactsResolver`。事实 resolver 接收 method/URI/headers 的 `ResourceRequest`，不跨 await 借用请求 body；body-only 目标/通用批量写不在 V1 自动适配范围。先组装全部业务路由，再一次应用 layer；不能在 layer 后合并未保护的业务 Router。

handler 用 `AuthorizedRequestExtension::take()` 获取一次性 `{ request, proof }`，在本地事务前 `require_allow_current` 和事实 CAS。所有写请求必须提供稳定 `x-operation-id`，中间件不会用随机 ID 替代；读请求可自动生成标识。`x-request-id` 缺省自动生成，nonce 使用操作系统随机源。

公开路由通过 `public_route(method, exact_path)` 显式登记，只允许 GET/HEAD/OPTIONS、无动态参数/通配符/与保护路由重叠。未声明路由和方法拒绝。特殊动作显式声明，普通动作可使用小型 read/create/update/delete 映射。Learn publish 当前映射已注册的 `learn_course:update`，不凭空新增 publish 动作。

完整示例见 [Learn Axum 测试](../integrations/learn/tests/axum.rs)；WebSocket/后台逐目标调用见 [Chat WebSocket 测试](../integrations/chat/tests/websocket.rs)。

## 6. 映射管理和恢复

外部管理入口：

```text
POST /api/v1/auth/integrations/identity-mappings
PUT  /api/v1/auth/integrations/identity-mappings/status
```

创建 DTO 使用 appId/issuer/subject/userId/identityCardId/operationId；这些平台 ID 仅用于受保护管理员操作，不在 SDK 授权请求中。状态 DTO 使用 expectedRevision、status=`DISABLED`/`REVOKED` 和稳定 operationId。永久唯一绑定不 rebind，不重新 ACTIVE。

映射、完成 ledger 和审计同事务；操作相同重放返回已提交 revision，内容或 actor 不同为冲突。400 输入错误，409 CAS/操作冲突，404 无映射，503 依赖未知；未知 COMMIT 返回 `IDENTITY_MAPPING_OUTCOME_UNKNOWN`、原 operationId 和 reconcileRequired，不自动重试。管理停用源身份/管理员并发失败默认拒绝。

feature 默认关闭。Identity 用 `ASTRAL_SDK_IDENTITY_MAPPING_ENABLED`，TrustGraph 用 `ASTRAL_SDK_INTEGRATION_ENABLED`、`ASTRAL_SDK_APPLICATIONS_JSON`、`ASTRAL_SDK_DECISION_KEY_ID`、`ASTRAL_SDK_DECISION_SEED_HEX`。JSON 应用字段 appId/keyId/publicKeyHex/issuer/manifest/tenantBindings；范围字段 externalTenantId/externalDomainId/tenantId/domainId。密钥通过环境或 secret store 注入，仓库不保存实际密钥和连接串。

启用时做只读表形状、字节唯一索引/FK、事务引擎（包括 audit_log）和 request guard preflight，不自动迁移。新增 migration 进入显式迁移链，但不进入默认运行时 required schema；feature-off 运行时不读新表。迁移必须另获批准，见 [迁移与恢复](迁移/SDK身份映射迁移与恢复_V1.0.md)。

## 7. 审计及样板边界

平台在最终复核后记录签名候选 `ASSESSED`，审计等待后的状态漂移记录 `INVALIDATED` PENDING 并拒绝旧 ALLOW。所有记录绑定 request/decision/facts digest；审计不证明响应已送达，更不证明业务提交。`audit_log` 没有 request/phase 唯一约束，因此准入审计是单次尝试、未知结果先对账，不宣称 exactly-once；对账按事件类型、requestId、requestDigest、phase，不仅靠 operationId。无可信上下文时只记脱敏拒绝日志，不能伪造用户审计。

Learn/Chat 样板有界内存 ledger 记录本地提交的 operation ID、request/facts digest；真实业务需在自己的事务/outbox 中持久化这些证据。Learn 支持课程发布、父范围 revision、精确列表和授权期间对象迁移；Chat 支持握手、逐目标消息、出站范围、撤销、重连、背压和去重。签名 fixture、loopback HTTP、Axum 和真实 loopback WebSocket 测试只证明这些合同，不证明真实映射/数据库/投影的部署成功。

原 `astral-chat`、`astral-learn` 继续 workspace exclude，源码未改，本次不等于其完整服务迁移或独立部署完成。真实 MySQL/MQ、崩溃恢复、跨节点、迁移和部署未执行；未知审计/COMMIT 与撤销窗口仍需受保护环境验收。
