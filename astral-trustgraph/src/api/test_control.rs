//! 内部测试控制面（S1-S15 分布式授权实验）—— 默认关闭、fail-closed 的只读状态端点。
//!
//! # 冻结契约（对齐 Java `TestControlController` 与
//! `Docs/实验/分布式测试/run_distributed_cluster_test.sh` 的 `wait_ready` 探针）
//!
//! - 路径：`GET /main/api/v1/internal/test-control/worker-id`（本模块只注册该
//!   只读端点；mutation/pump/probe/evaluate 等控制面能力明确不在本 slice）。
//! - 请求头：`X-Test-Control-Token: <token>`。
//! - 响应：顶层 JSON（刻意不包 `ApiResponse` 信封，探针直接读取顶层字段）：
//!   `nodeId` / `workerId` / `configFingerprint` / `jvmStartTime` /
//!   `processIdentityHash`。
//!
//! # 安全不变式（本模块存在的理由）
//!
//! 1. **默认关闭**：仅当 `ASTRAL_TEST_CONTROL_ENABLED=true` 且
//!    `ASTRAL_TEST_CONTROL_TOKEN` 非空时才注册路由；配置缺失/无效一律
//!    fail-closed——路由根本不存在（404），绝不暴露控制面。
//! 2. **专用 token，常量时间比较**：复用
//!    `astral_common::middleware::internal_signature::constant_time_eq` 字节
//!    比较（通用原语，不共享任何密钥材料）；不复用 Gateway HMAC secret，不
//!    硬编码 secret，绝不记录 token 值。
//! 3. **不绕过中间件**：路由挂在 `/main/api/v1` 子路由内，照常经过 Gateway
//!    签名与 `permission_check` 中间件（路径映射复用已注册资源 `monitor` 的
//!    `read` 动作，与 `/consistency`、`/arbiter` 同级）。Java 侧
//!    `SecurityConfig` 对该路径的 `permitAll` 是在案的 internal-test 例外；
//!    Rust 侧本 slice 采取更保守策略：正常中间件链路全部保留，token 检查是
//!    其上的额外纵深防御层，不是替代品。
//! 4. **非敏感响应**：响应字段只含进程身份元数据（UUID、节点标签、非敏感
//!    配置摘要哈希、进程启动时间、进程身份哈希——节点身份、pid 与进程 nonce
//!    的摘要）；绝不包含凭据、DB URL、文件系统路径或 token 本身。
//!
//! # 与 harness 的对齐现状（review 修正）
//!
//! 本 Rust 端点保留完整中间件链路：请求必须同时通过（a）Gateway 身份头
//! HMAC 验签、（b）`permission_check` 的 `monitor:read` 授权（映射见
//! `api::permission_check::TRUSTGRAPH_PATH_RESOURCE_MAP`）以及（c）本模块的
//! 常量时间 token 校验。harness（`run_distributed_cluster_test.sh`）的两种
//! 栈模式探针能力不同：
//! - Java 模式的 `wait_ready`（冻结契约）只发送 `X-Test-Control-Token`，不
//!   带 Gateway 签名头，也没有 `monitor:read` 授权上下文，因此不能到达本
//!   端点（会被签名/授权层拒绝）；
//! - Rust 模式使用 `wait_ready_rust` + `probe_worker_id.py`：携带完整
//!   Gateway v3 签名头、`monitor:read` 授权身份与 `X-Test-Control-Token`，
//!   可以到达本端点。
//!   Rust 场景协调器（scenario coordinator）仍未实现：就绪探针成功后，
//!   attempt 以 BLOCKED（ATTEMPT_ABORTED 标记）结束，绝不报告 PASS。本模块
//!   刻意不新增 `SKIP_PATHS` 或任何中间件旁路（安全不变式 3）。

use std::sync::{Arc, OnceLock};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use sha2::{Digest, Sha256};

use astral_common::error::AppError;
use astral_common::middleware::internal_signature::constant_time_eq;
use astral_types::AstralError;

use crate::AppState;

/// 测试控制面 token 请求头（对齐 Java `X-Test-Control-Token`）。
pub const TEST_CONTROL_TOKEN_HEADER: &str = "X-Test-Control-Token";

/// 冻结的只读探针路径（nest 在 `/main/api/v1` 下）。
pub const TEST_CONTROL_ROUTE: &str = "/internal/test-control/worker-id";

const ENABLED_ENV: &str = "ASTRAL_TEST_CONTROL_ENABLED";
const TOKEN_ENV: &str = "ASTRAL_TEST_CONTROL_TOKEN";
const NODE_ID_ENV: &str = "ASTRAL_NODE_ID";

/// 节点标签的安全上限：响应 JSON 里的自由文本字段不做无界透传。
const NODE_ID_MAX_LEN: usize = 64;

/// 已解析并激活的测试控制面配置。
///
/// token 刻意保持私有且无 `Debug`/`Display` 派生路径——该类型绝不进入日志。
pub struct TestControlConfig {
    token: String,
}

impl TestControlConfig {
    /// 从环境解析配置；任何缺失/无效输入都返回 `None`（= 不注册路由）。
    ///
    /// fail-closed 语义：`ASTRAL_TEST_CONTROL_ENABLED` 不是 `true`、或
    /// `ASTRAL_TEST_CONTROL_TOKEN` 缺失/空白，控制面一律保持关闭。启用但
    /// token 缺失属于配置错误，会记录一条不含任何 token 值的告警。
    pub fn from_env() -> Option<Arc<Self>> {
        let enabled_raw = std::env::var(ENABLED_ENV).ok();
        let token_raw = std::env::var(TOKEN_ENV).ok();
        match resolve_token(enabled_raw.as_deref(), token_raw.as_deref()) {
            Some(token) => Some(Arc::new(Self { token })),
            None => {
                if enabled_raw.as_deref().is_some_and(is_enabled_value) {
                    tracing::warn!(
                        env = TOKEN_ENV,
                        "test control enabled but token missing or blank; \
                         controls stay disabled (fail-closed)"
                    );
                }
                None
            }
        }
    }

    /// 常量时间 token 校验。缺失/空/不匹配一律 `false`，调用方映射为 403。
    pub(crate) fn tokens_match(&self, presented: Option<&str>) -> bool {
        let Some(presented) = presented else {
            return false;
        };
        if presented.is_empty() {
            return false;
        }
        constant_time_eq(self.token.as_bytes(), presented.as_bytes())
    }
}

/// 纯解析核心（便于单测覆盖 fail-closed 分支而不污染进程环境变量）。
///
/// 只有 `enabled` 严格等于 `true`（忽略大小写/首尾空白，对齐 Java
/// `@ConditionalOnProperty havingValue="true"`）且 token 非空白时才放行。
fn resolve_token(enabled_raw: Option<&str>, token_raw: Option<&str>) -> Option<String> {
    let enabled = enabled_raw.is_some_and(is_enabled_value);
    if !enabled {
        return None;
    }
    let token = token_raw?.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn is_enabled_value(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("true")
}

/// 进程级 worker 身份（OnceLock 保证进程内稳定）。
struct WorkerIdentity {
    /// 实例身份：进程内 OnceLock UUID（对齐 Java projection worker workerId）。
    worker_id: String,
    /// 逻辑节点标签：`ASTRAL_NODE_ID`，安全回退 `unknown`（对齐 Java 默认值）。
    node_id: String,
    /// 进程启动时间（毫秒 UTC）。字段名沿用 Java 契约 `jvmStartTime`，
    /// 值为 Rust 进程启动时间，供 harness 做节点独立性证据。
    started_at_unix_ms: i64,
    /// 非敏感运行配置摘要（SHA-256 hex）：节点标签 + 投影 tenant 范围。
    /// 绝不包含凭据/连接串/token。
    config_fingerprint: String,
    /// 进程身份哈希（SHA-256 hex）：材料为稳定节点身份（`ASTRAL_NODE_ID`，
    /// 缺失时主机名环境变量回退）+ pid + 进程级重启 nonce（worker UUID）。
    /// 诚实边界（review 修正）：pid 单独使用既不跨主机唯一（不同主机可能
    /// 撞号），也不跨重启唯一（pid 复用），本哈希不做该声称；跨主机区分度
    /// 由节点身份提供，依赖部署方保证 `ASTRAL_NODE_ID`/主机名互异；两者皆
    /// 缺失（`unknown`）时唯一性仅由 pid + nonce 支撑，不构成跨主机保证。
    /// 重启后变化，作为新 runtime 证据。
    process_identity_hash: String,
}

static WORKER_IDENTITY: OnceLock<WorkerIdentity> = OnceLock::new();

fn worker_identity() -> &'static WorkerIdentity {
    WORKER_IDENTITY.get_or_init(|| {
        let node_id = sanitized_node_id();
        // 进程级重启 nonce：OnceLock UUID，重启即变化；同时进入身份哈希
        // 材料，使同节点同 pid（pid 复用）的重启实例仍可区分。
        let restart_nonce = uuid::Uuid::new_v4().to_string();
        let process_identity_hash = compute_process_identity_hash(
            &stable_node_identity(&node_id),
            std::process::id(),
            &restart_nonce,
        );
        WorkerIdentity {
            worker_id: restart_nonce,
            // 对齐仓库既有毫秒换算惯例（api::arbiter）。
            started_at_unix_ms: time::OffsetDateTime::now_utc().unix_timestamp() * 1000,
            config_fingerprint: sha256_hex_lower(
                format!(
                    "astral-trustgraph-test-control-v1|node={}|projector_tenants={}",
                    node_id,
                    std::env::var("ASTRAL_PROJECTOR_TENANTS").unwrap_or_default()
                )
                .as_bytes(),
            ),
            process_identity_hash,
            node_id,
        }
    })
}

fn sanitized_node_id() -> String {
    sanitized_text_from_env(NODE_ID_ENV).unwrap_or_else(|| "unknown".to_string())
}

/// 读取并净化单个环境变量：trim、去空、截断到安全上限。
fn sanitized_text_from_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(NODE_ID_MAX_LEN).collect())
}

/// 主机名回退环境变量（部署侧提供的非敏感机器标识；绝不读取凭据类变量）。
/// Windows 约定 `COMPUTERNAME`，Unix shell 约定 `HOSTNAME`；systemd 等
/// 非交互环境下后者可能缺失——缺失时如实退化为 `unknown`，不做额外声称。
const HOST_FALLBACK_ENVS: [&str; 2] = ["COMPUTERNAME", "HOSTNAME"];

/// 参与进程身份哈希的稳定节点身份：`ASTRAL_NODE_ID`（部署方显式配置）优先，
/// 否则主机名环境变量回退；两者皆缺失时返回 `unknown`（此时跨主机唯一性
/// 不受保证，见 `process_identity_hash` 文档）。
fn stable_node_identity(node_id: &str) -> String {
    if node_id != "unknown" {
        return node_id.to_string();
    }
    HOST_FALLBACK_ENVS
        .iter()
        .find_map(|key| sanitized_text_from_env(key))
        .unwrap_or_else(|| "unknown".to_string())
}

/// 纯函数核心（便于单测验证同节点稳定 / 不同节点不同）：进程身份哈希材料
/// = 域分隔前缀 + 稳定节点身份 + pid + 进程级重启 nonce。
fn compute_process_identity_hash(node_identity: &str, pid: u32, restart_nonce: &str) -> String {
    sha256_hex_lower(
        format!(
            "rust-trustgraph-process-identity-v2|node={}|pid={}|nonce={}",
            node_identity, pid, restart_nonce
        )
        .as_bytes(),
    )
}

fn sha256_hex_lower(material: &[u8]) -> String {
    let digest = Sha256::digest(material);
    // hex 编码内联实现：astral-trustgraph 不直接依赖 hex crate，避免为
    // 两个摘要字段新增依赖面。
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `GET /internal/test-control/worker-id` 的响应载荷。
///
/// 顶层 camelCase 字段与 Java/harness 契约逐字段一致（探针读取顶层字段，
/// 不包 `ApiResponse` 信封）。序列化形状由单测锁定：只允许这五个键。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerIdStatus {
    pub node_id: String,
    pub worker_id: String,
    pub config_fingerprint: String,
    pub jvm_start_time: String,
    pub process_identity_hash: String,
}

impl WorkerIdStatus {
    fn from_identity(identity: &WorkerIdentity) -> Self {
        Self {
            node_id: identity.node_id.clone(),
            worker_id: identity.worker_id.clone(),
            config_fingerprint: identity.config_fingerprint.clone(),
            jvm_start_time: identity.started_at_unix_ms.to_string(),
            process_identity_hash: identity.process_identity_hash.clone(),
        }
    }
}

/// 测试控制面路由（在 main 启动期调用一次）。
///
/// `config` 为 `None`（未启用/配置无效）时不注册任何路由——请求在 Axum 层
/// 自然 404，控制面完全不可见。`Some` 时注册冻结路径；调用顺带把进程身份
/// 钉在启动期（`started_at`/`worker_id` 从启动即稳定，而不是首个请求时）。
/// 路由仍挂在 `/main/api/v1` 子路由内，正常经过 Gateway 签名与
/// `permission_check` 中间件；本函数不添加任何旁路。
pub fn test_control_routes(config: Option<&Arc<TestControlConfig>>) -> Router<AppState> {
    if config.is_none() {
        return Router::new();
    }
    // 启动期钉住进程身份（OnceLock 首次初始化）。
    let _ = worker_identity();
    Router::new().route(TEST_CONTROL_ROUTE, get(worker_id))
}

/// 只读探针 handler：启用检查（404）→ 常量时间 token 校验（403）→ 身份 JSON。
///
/// 404/403 的 reason 均为静态字符串；本 handler 任何路径都不记录、不返回
/// token 值或配置细节。
async fn worker_id(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<WorkerIdStatus>, AppError> {
    // 纵深防御：路由已注册但 state 未装配（不应发生）时同样 404。
    let Some(config) = state.test_control.as_ref() else {
        return Err(AppError(AstralError::NotFound(
            "test_control_disabled".into(),
        )));
    };
    let presented = headers
        .get(TEST_CONTROL_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok());
    if !config.tokens_match(presented) {
        // 只记录判定结果，绝不记录 token 值（安全不变式 2）。
        tracing::warn!("test control token rejected (missing or mismatch)");
        return Err(AppError(AstralError::Permission(
            "TEST_CONTROL_TOKEN_MISMATCH".into(),
        )));
    }
    Ok(Json(WorkerIdStatus::from_identity(worker_identity())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // ===== 配置解析：fail-closed 分支 =====

    #[test]
    fn resolve_token_fails_closed_when_disabled_or_missing() {
        // 未设置 enabled → 关闭（即使 token 存在）。
        assert_eq!(resolve_token(None, Some("t")), None);
        // enabled 不是 true → 关闭。
        assert_eq!(resolve_token(Some("false"), Some("t")), None);
        assert_eq!(resolve_token(Some("1"), Some("t")), None);
        assert_eq!(resolve_token(Some(""), Some("t")), None);
        assert_eq!(resolve_token(Some("yes"), Some("t")), None);
    }

    #[test]
    fn resolve_token_requires_non_blank_token_when_enabled() {
        assert_eq!(resolve_token(Some("true"), None), None);
        assert_eq!(resolve_token(Some("true"), Some("")), None);
        assert_eq!(resolve_token(Some("true"), Some("   ")), None);
    }

    #[test]
    fn resolve_token_accepts_enabled_true_with_non_blank_token() {
        assert_eq!(
            resolve_token(Some("true"), Some("harness-token")),
            Some("harness-token".to_string())
        );
        // 大小写/空白容错只作用于布尔开关与 token 首尾，不弱化判定。
        assert_eq!(
            resolve_token(Some(" TRUE "), Some("  harness-token ")),
            Some("harness-token".to_string())
        );
    }

    // ===== 常量时间比较原语（经 guard 缝隙验证行为） =====

    #[test]
    fn tokens_match_accepts_exact_and_rejects_mismatch_and_lengths() {
        let config = TestControlConfig {
            token: "correct-harness-token".to_string(),
        };
        assert!(config.tokens_match(Some("correct-harness-token")));
        // 错误 token（等长与否都拒绝）。
        assert!(!config.tokens_match(Some("wrong-token")));
        assert!(!config.tokens_match(Some("correct-harness-tokenX")));
        // 缺失/空 header 拒绝。
        assert!(!config.tokens_match(None));
        assert!(!config.tokens_match(Some("")));
        // 底层原语：等长不同字节必须判假（constant-time 合同）。
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    // ===== worker 身份：进程内稳定 =====

    #[test]
    fn worker_id_is_stable_across_calls() {
        let first = worker_identity();
        let second = worker_identity();
        assert_eq!(first.worker_id, second.worker_id);
        // OnceLock 返回同一实例。
        assert!(std::ptr::eq(first, second));
    }

    #[test]
    fn identity_fields_are_non_empty_and_shape_sane() {
        let identity = worker_identity();
        assert!(!identity.worker_id.is_empty());
        // UUID 形状（8-4-4-4-12）。
        assert_eq!(
            identity
                .worker_id
                .split('-')
                .map(str::len)
                .collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(!identity.node_id.is_empty());
        assert!(identity.started_at_unix_ms > 0);
        // 摘要是 64 位小写 hex。
        for digest in [
            &identity.config_fingerprint,
            &identity.process_identity_hash,
        ] {
            assert_eq!(digest.len(), 64);
            assert!(digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        }
    }

    // ===== 进程身份哈希：同节点稳定 / 不同节点不同（review 修正验证） =====

    #[test]
    fn process_identity_hash_is_stable_for_same_node_inputs() {
        let a = compute_process_identity_hash("node-a", 4242, "nonce-1");
        let b = compute_process_identity_hash("node-a", 4242, "nonce-1");
        assert_eq!(a, b, "same node/pid/nonce inputs must yield identical hash");
        assert_eq!(a.len(), 64);
        assert!(a
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }

    #[test]
    fn process_identity_hash_differs_for_different_node_inputs() {
        let base = compute_process_identity_hash("node-a", 4242, "nonce-1");
        // 跨主机区分度来自节点身份（不是 pid）：节点不同即哈希不同。
        assert_ne!(
            base,
            compute_process_identity_hash("node-b", 4242, "nonce-1")
        );
        // pid 相同、节点相同、重启 nonce 不同（同节点重启且 pid 复用的场景）
        // 仍区分。
        assert_ne!(
            base,
            compute_process_identity_hash("node-a", 4242, "nonce-2")
        );
        // pid 变化仍区分。
        assert_ne!(
            base,
            compute_process_identity_hash("node-a", 4243, "nonce-1")
        );
    }

    #[test]
    fn worker_identity_hash_is_reproducible_from_declared_material() {
        // 进程级身份的哈希必须能由其声称的材料（节点身份 + pid + worker UUID
        // nonce）逐位复算——证明哈希确实纳入节点身份，而非仅 pid。
        let identity = worker_identity();
        let recomputed = compute_process_identity_hash(
            &stable_node_identity(&identity.node_id),
            std::process::id(),
            &identity.worker_id,
        );
        assert_eq!(identity.process_identity_hash, recomputed);
    }

    #[test]
    fn stable_node_identity_prefers_configured_node_id() {
        // 已配置节点标签（非 unknown）→ 直接采用，不读主机名回退。
        assert_eq!(stable_node_identity("node-a"), "node-a");
        // 未配置（unknown）→ 主机名回退；测试环境无法保证主机名变量存在，
        // 只断言结果非空（保证哈希材料非空，退化时为 "unknown"）。
        assert!(!stable_node_identity("unknown").is_empty());
    }

    // ===== 响应形状：只暴露合同字段，绝无秘密 =====

    #[test]
    fn status_payload_exposes_exactly_the_contract_fields() {
        let payload = WorkerIdStatus::from_identity(worker_identity());
        let json = serde_json::to_value(&payload).expect("payload must serialize");
        let keys: BTreeSet<&str> = json
            .as_object()
            .expect("payload must be a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<&str> = [
            "nodeId",
            "workerId",
            "configFingerprint",
            "jvmStartTime",
            "processIdentityHash",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, expected, "response shape must match frozen contract");
    }

    #[test]
    fn status_payload_never_carries_secret_shaped_values() {
        let payload = WorkerIdStatus::from_identity(worker_identity());
        let json = serde_json::to_value(&payload).expect("payload must serialize");
        for (key, value) in json.as_object().expect("object").iter() {
            let key_lower = key.to_ascii_lowercase();
            assert!(
                !key_lower.contains("token")
                    && !key_lower.contains("secret")
                    && !key_lower.contains("password")
                    && !key_lower.contains("url"),
                "field {key} must never appear in test control response"
            );
            let value_str = value.as_str().expect("all fields are strings");
            assert!(!value_str.is_empty(), "{key} must be non-empty");
            // 自由文本字段不携带 token/秘密标记词。
            let value_lower = value_str.to_ascii_lowercase();
            assert!(
                !value_lower.contains("token=") && !value_lower.contains("password"),
                "{key} must not embed secret material"
            );
        }
    }

    // ===== 冻结路径与路由可见性 =====

    #[test]
    fn route_constant_matches_frozen_harness_path() {
        // harness（run_distributed_cluster_test.sh）请求的是
        // /main/api/v1/internal/test-control/worker-id；nest 前缀之外的本段
        // 必须逐字符一致。
        assert_eq!(TEST_CONTROL_ROUTE, "/internal/test-control/worker-id");
        assert_eq!(TEST_CONTROL_TOKEN_HEADER, "X-Test-Control-Token");
    }
}
