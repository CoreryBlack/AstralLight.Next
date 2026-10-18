# Rust SDK 如何把 ALLOW 变成请求绑定的 proof

> 面向：Rust SDK、Axum 服务与跨服务授权接入开发者
> 关键词：Ed25519、类型级信任边界、Axum、请求摘要、一次性 proof

远程授权服务返回 `ALLOW`，不等于调用方拿到一张可以在任意 handler、任意资源、任意时间重复使用的“通行证”。为了避免这一误用，AstralLight.Next 的 Rust SDK 把授权结果绑定到具体请求与事实摘要，再通过不同 Rust 类型区分“未验证的签名数据”和“已经验签的授权 proof”。

这里值得关注的不是 Ed25519 本身，而是它如何与 Rust 的类型边界、Axum middleware、一次性 proof 消费和业务侧复检协作。

## 一、签名请求绑定协议上下文和请求内容

`AuthorizationRequest` 携带 app/key、manifest digest/revision、request ID、nonce、时间戳、Gateway session token ID、外部主体、业务 method/path/action、operation ID 与资源 facts。合同在反序列化时拒绝未知字段，并限制标识符、nonce、时间窗和 payload 大小。

请求签名函数先校验 request，再生成 domain-separated payload：

```rust
fn request_signing_bytes(
    request: &AuthorizationRequest,
) -> Result<Vec<u8>, ContractError> {
    request.validate()?;
    let body = serde_json::to_vec(request).map_err(serialize_error)?;
    let payload = RequestSignaturePayload {
        domain: REQUEST_SIGNATURE_DOMAIN,
        http_method: AUTHORIZATION_HTTP_METHOD,
        http_path: AUTHORIZATION_PATH,
        method: &request.method,
        path: &request.path,
        body_sha256: &digest_hex(&body),
        app_id: &request.app_id,
        key_id: &request.key_id,
        manifest_digest: &request.manifest_digest,
        nonce: &request.nonce,
        session_token_id: &request.session_token_id,
    };
    serde_json::to_vec(&payload).map_err(serialize_error)
}
```

`SignedAuthorizationRequest::sign` 再对这个 helper 返回的字节调用 `key.sign(...)`，并将签名编码为无 padding 的 base64url。domain tag 避免把同一签名字节误用于另一个协议；method/path、body digest、manifest、nonce 与 Gateway session 都被绑定。验签方使用的公钥必须先从受信任的 app/key registry 选定，不能相信请求体自行声明的公钥。

## 二、从 `Signed...` 变成 `Verified...`

授权决策也有独立签名，且包含 request digest、facts digest、request ID、DecisionScope、mapping revision、outcome、签发时间与失效时间。合同将决策有效期限制为最多 5 秒，请求 timestamp 的协议时钟偏差上限为 30 秒。验证过程除了检查 Ed25519 签名，还要验证 key ID、决策是否对应本次 request/facts/scope，以及签发与失效时间是否有效。

Rust API 用 `VerifiedAuthorizationDecision` 包装已验证的决策。它的内部字段私有，构造入口收在 contracts crate 内，类型本身不实现 `Clone`。消费方拿到的是一个更窄的能力：可以检查 proof scope、mapping revision、ALLOW/DENY/PENDING，并通过 `require_allow_current` 重新校验请求绑定和有效期，而不是直接修改“已验证”状态。

```rust
pub fn require_allow_current(
    &self,
    request: &AuthorizationRequest,
) -> Result<(), ContractError> {
    self.validate_current(request)?;
    if !self.matches_request(request) || !self.is_allow() {
        return Err(ContractError::DecisionNotAllowed);
    }
    Ok(())
}
```

这不是编译器能证明的全局授权安全，但能减少应用代码把任意 JSON response 当作可信 allow 的机会。

## 三、Axum adapter 从受信任事实开始组 request

`AuthorizationLayer` 初始化时校验 application manifest 与 app ID。进入 middleware 后，未声明的路由直接拒绝；public route 也必须显式登记。

主体由 `ActorResolver` 从服务已有的本地 session 中解析，资源事实由 `ResourceFactsResolver` 从业务服务自己的状态读取。HTTP headers/path 可以提供查找 selector，但不能作为 tenant、owner、domain、成员关系或资源 revision 的最终权威值。resolver 超时或 unavailable 都返回拒绝/PENDING。

对于写请求，adapter 要求客户端提供稳定 `x-operation-id`，再组装、签名 AuthorizationRequest 并调用 SDK。远程回包必须通过 request match 与 `require_allow_current`，才会进入 handler extension。

## 四、用 `Mutex<Option<T>>` 实现同一请求内的一次性消费

Axum extensions 可随 request parts 被多个 extractor 借用。adapter 因此将不可 Clone 的 `AuthorizedRequest` 放入 `Arc<Mutex<Option<_>>>`：

```rust
#[derive(Clone)]
pub struct ProofSlot(Arc<Mutex<Option<AuthorizedRequest>>>);

pub fn take_authorized_request(
    request: &Request,
) -> Result<AuthorizedRequest, AdapterError> {
    let slot = request
        .extensions()
        .get::<ProofSlot>()
        .ok_or(AdapterError::ProofMissing)?;

    slot.0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .take()
        .ok_or(AdapterError::ProofMissing)
}
```

`Arc` 让多个 extractor handle 能指向同一个槽；`Option::take()` 保证成功消费后槽位为空，第二个 handler 再取会得到 `ProofMissing`。Mutex 的 poisoned lock 被恢复，是因为共享槽的结构仍能通过 `Option` 表达“proof 已取走/缺失”；这不是授权后端数据库锁，也不会跨请求共享。

“一次性”仅描述当前 HTTP pipeline 中这份 proof 对象的交接，不是跨进程 exactly-once，也不替业务数据库做幂等。

## 五、最终提交前仍由业务服务复核事实

从远程 authorize 到本地 commit 之间，资源可能被转移，课程 revision 可能变化，聊天成员可能被撤销。签名证明的是“决策服务对当时那份 request/facts 做过这个短期决定”，而不是“资源从此不会变化”。

因此消费方应把稳定 operation ID、payload digest、request/facts receipt 与本地业务写入放进自己的持久化事务/outbox；在 CAS/提交前再次验证本地版本和归属。结果未知时先对账，再决定能否重试。

仓库 Learn/Chat 样例验证了 facts 变化后拒绝旧 proof、以 operation ID 与 payload digest 检查重复/冲突、以及 WebSocket 每帧重新授权。但示例使用有界内存 store，不是生产 SQL transaction，也不证明跨进程恰好一次或真实平台身份映射。

**核心经验：** 在 Rust SDK 边界用签名数据类型、私有 verified wrapper、scope/time recheck 与一次性槽减少误用；在业务提交边界用持久化 operation receipt 和本地 CAS 处理并发。授权 proof 是受限证据，不是长期 bearer capability。
