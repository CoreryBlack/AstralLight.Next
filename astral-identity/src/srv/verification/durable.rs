//! Verification 服务的 durable 原语（taskId
//! `global-authority-20261107-verification`）。
//!
//! 本模块只包含纯计算/配置原语：HMAC-SHA256 域分隔摘要（RFC 2104，含官方
//! 测试向量）、受保护环境密钥解析（fail-closed）、purpose 注册表、显式稳定
//! operation id 校验、预算窗口与 proof token 生成。持久化语句全部位于
//! `astral_db::verification_durable_repository`，事务组合位于
//! `verification.rs` 服务层。
//!
//! ## 密钥边界（fail-closed）
//!
//! HMAC 密钥只从环境变量 [`HMAC_ENV_KEY`] 解析（进程启动后首次使用时冻结；
//! 不入库、不入日志、不入 git）。缺失或长度 < 32 字节时 [`hmac_key`] 返回
//! `None`，send/verify/proof 全部拒绝（fail-closed）——绝不发明默认密钥或
//! 降级为无密钥摘要。
//!
//! ## purpose 注册表（兼容行为，已登记）
//!
//! 只有具备真实同事务消费方的 purpose 才被允许签发；当前仅
//! [`PURPOSE_REGISTER`]（消费方：`/api/v1/auth/register` 可选 proof，在
//! `insert_register_user` 事务内 one-shot CAS 消费）。RESET/SENSITIVE 等
//! purpose 在其绑定消费方落地前一律拒绝——这收窄了既有"任意 purpose 可
//! 签发"的行为（旧客户端传其它 purpose 将收到校验错误），属已登记的
//! fail-closed 兼容变更，不做静默放行。
//!
//! ## 预算（durable 跨副本）
//!
//! 预算按 (scope, subject, purpose, 窗口) 计数，subject 为
//! `HMAC(target)` 或 `HMAC(resolved client IP)`；跨副本原子性由
//! `verification_budget` 主键行锁保证（见仓储层）。窗口按 epoch 对齐分桶，
//! 旧窗口行由有界 GC 清理。

use std::sync::OnceLock;

use rand::Rng;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use astral_common::middleware::ip_rate_limit::{resolve_client_ip, TrustedProxySet};

/// HMAC 密钥环境变量（受保护：仅存在于运行进程环境，不入任何持久介质）。
pub const HMAC_ENV_KEY: &str = "ASTRAL_VERIFICATION_HMAC_KEY";

/// 最小密钥长度（字节）：256 位安全裕量。
const HMAC_KEY_MIN_BYTES: usize = 32;

/// 已注册 purpose：注册验证（真实同事务消费方 = register 端点）。
pub const PURPOSE_REGISTER: &str = "register";

/// challenge 有效期（对齐基线 `CODE_TTL_MINUTES` = 5 分钟）。
pub const CHALLENGE_TTL: Duration = Duration::minutes(5);
/// challenge 摘要不匹配尝试上限（对齐基线 `MAX_VERIFY_ATTEMPTS` = 5，现为
/// durable 行内原子计数，跨副本生效）。
pub const MAX_CHALLENGE_ATTEMPTS: u32 = 5;
/// proof 有效期：验证通过后消费方必须在期内完成业务事务（注册）。
pub const PROOF_TTL: Duration = Duration::minutes(10);

/// SEND 预算窗口（每 target / 每 IP）。
pub const SEND_WINDOW: Duration = Duration::minutes(10);
pub const SEND_CAP_PER_TARGET: i64 = 5;
pub const SEND_CAP_PER_IP: i64 = 30;
/// VERIFY 预算窗口（每 target / 每 IP）。
pub const VERIFY_WINDOW: Duration = Duration::minutes(5);
pub const VERIFY_CAP_PER_TARGET: i64 = 10;
pub const VERIFY_CAP_PER_IP: i64 = 60;

/// purpose 是否在注册表内（绑定真实消费方）。未注册 purpose 一律拒绝签发
/// 与校验（fail-closed；见模块文档兼容行为登记）。
pub fn is_registered_purpose(purpose: &str) -> bool {
    purpose == PURPOSE_REGISTER
}

static HMAC_KEY: OnceLock<Option<Vec<u8>>> = OnceLock::new();

/// 解析并冻结 HMAC 密钥（进程内单次）。无效/缺失 → `None`（全部验证操作
/// fail-closed），只告警一次。
pub fn hmac_key() -> Option<&'static [u8]> {
    let resolved = HMAC_KEY.get_or_init(|| match std::env::var(HMAC_ENV_KEY) {
        Ok(raw) if raw.trim().len() >= HMAC_KEY_MIN_BYTES => Some(raw.trim().as_bytes().to_vec()),
        Ok(_) => {
            tracing::error!(
                env = HMAC_ENV_KEY,
                "verification HMAC key too short; verification issuance/proof fail closed"
            );
            None
        }
        Err(_) => {
            tracing::error!(
                env = HMAC_ENV_KEY,
                "verification HMAC key not configured; verification issuance/proof fail closed"
            );
            None
        }
    });
    resolved.as_deref()
}

/// RFC 2104 HMAC-SHA256（身份 crate 未依赖 hmac crate；本实现以官方
/// RFC 4231 测试向量锁定正确性，见 tests）。
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut hasher = Sha256::new();
        hasher.update(key);
        block[..32].copy_from_slice(&hasher.finalize());
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = block.iter().map(|byte| byte ^ 0x36).collect();
    let opad: Vec<u8> = block.iter().map(|byte| byte ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// 域分隔 MAC：`HMAC(key, domain || 0x00 || parts...)`，杜绝跨域重放摘要。
fn mac(key: &[u8], domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut data =
        Vec::with_capacity(domain.len() + 1 + parts.iter().map(|p| p.len()).sum::<usize>());
    data.extend_from_slice(domain);
    data.push(0u8);
    for part in parts {
        data.extend_from_slice(part);
    }
    hmac_sha256(key, &data)
}

const DOMAIN_TARGET: &[u8] = b"astral-verification:v1:target";
const DOMAIN_IP: &[u8] = b"astral-verification:v1:ip";
const DOMAIN_CODE: &[u8] = b"astral-verification:v1:code";
const DOMAIN_PROOF: &[u8] = b"astral-verification:v1:proof";

/// 验证目标规范化 + HMAC（DB 只存摘要，不落 PII 明文）。规范化 =
/// trim + lowercase（email/phone 的稳定查找键）。
pub fn target_hash(key: &[u8], target: &str) -> [u8; 32] {
    let normalized = target.trim().to_lowercase();
    mac(key, DOMAIN_TARGET, &[normalized.as_bytes()])
}

/// 已解析客户端 IP 的 HMAC 预算主体。
pub fn ip_hash(key: &[u8], ip: std::net::IpAddr) -> [u8; 32] {
    mac(key, DOMAIN_IP, &[ip.to_string().as_bytes()])
}

/// 验证码摘要：绑定 purpose + target_hash + code（防止摘要跨 purpose/target
/// 重放）；明文 code 不落库不入日志。
pub fn code_digest(key: &[u8], purpose: &str, target_hash: &[u8; 32], code: &str) -> [u8; 32] {
    mac(
        key,
        DOMAIN_CODE,
        &[purpose.as_bytes(), target_hash, code.trim().as_bytes()],
    )
}

/// proof token 摘要：绑定 purpose + target_hash + 随机 token（256 位熵）。
pub fn proof_hash(key: &[u8], purpose: &str, target_hash: &[u8; 32], token: &str) -> [u8; 32] {
    mac(
        key,
        DOMAIN_PROOF,
        &[purpose.as_bytes(), target_hash, token.as_bytes()],
    )
}

/// 生成不透明 proof token（32 随机字节 hex，128 hex 字符）。只返回给客户端，
/// 服务端只存其 HMAC 摘要。
pub fn proof_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    let mut hex = String::with_capacity(64);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// 校验显式稳定 operation id（`X-Operation-Id` 头的字符串值）：8..=64 字符，
/// `[A-Za-z0-9_-]`。缺失/非法 → `Err`（send fail-closed：无稳定 id 不签发）。
pub fn validate_operation_id(raw: Option<&str>) -> Result<&str, &'static str> {
    let value = raw
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("VERIFICATION_OPERATION_ID_REQUIRED")?;
    if !(8..=64).contains(&value.len()) {
        return Err("VERIFICATION_OPERATION_ID_LENGTH_INVALID");
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("VERIFICATION_OPERATION_ID_CHARSET_INVALID");
    }
    Ok(value)
}

/// 预算窗口起始（按 epoch 对 `window` 对齐分桶，UTC；不 panic）。
pub fn budget_window_start(now: OffsetDateTime, window: Duration) -> PrimitiveDateTime {
    let secs = window.whole_seconds().max(1);
    let timestamp = now.unix_timestamp();
    let bucket = timestamp - timestamp.rem_euclid(secs);
    let start = OffsetDateTime::from_unix_timestamp(bucket).unwrap_or(now);
    PrimitiveDateTime::new(start.date(), start.time())
}

/// 已解析客户端 IP 的 HMAC 预算主体：复用共享限流器的受信代理解析
/// （同一 `trusted_proxy_ips` 配置、同一右most-untrusted 语义；配置启动期
/// 冻结，编译一次跨请求共享）。解析失败（无对端扩展）聚合到固定哨兵值，
/// 不 panic 也不放宽。
pub fn client_ip_hash(
    key: &[u8],
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::IpAddr>,
    trusted_proxy_ips: &[String],
) -> [u8; 32] {
    static TRUSTED: OnceLock<TrustedProxySet> = OnceLock::new();
    let trusted = TRUSTED.get_or_init(|| {
        let set = TrustedProxySet::compile(trusted_proxy_ips);
        for entry in set.invalid_entries() {
            tracing::warn!(entry = %entry, "invalid trusted_proxy_ips entry; ignored (fail closed)");
        }
        set
    });
    match resolve_client_ip(headers, peer, trusted) {
        Some(ip) => ip_hash(key, ip),
        None => mac(key, DOMAIN_IP, &[b"unresolved-peer"]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 Test Case 1（HMAC-SHA256）。
    #[test]
    fn hmac_sha256_matches_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(hmac_sha256(&key, b"Hi There"), expected);
    }

    /// RFC 4231 Test Case 2（HMAC-SHA256）。
    #[test]
    fn hmac_sha256_matches_rfc4231_case2() {
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            expected
        );
    }

    #[test]
    fn long_key_path_matches_short_key_path_shape() {
        // 长密钥（>64B）走 hash 压缩分支，仍需产生 32 字节稳定输出。
        let long_key = [0xa5u8; 100];
        let a = hmac_sha256(&long_key, b"payload");
        let b = hmac_sha256(&long_key, b"payload");
        assert_eq!(a, b);
        assert_ne!(a, hmac_sha256(&long_key, b"payload2"));
    }

    #[test]
    fn macs_are_domain_separated() {
        let key = b"unit-test-key-unit-test-key-1234".as_slice();
        let target = target_hash(key, "User@Example.COM ");
        // 规范化：大小写与首尾空白不影响哈希。
        assert_eq!(target, target_hash(key, "user@example.com"));
        // 跨域/跨输入摘要互异。
        assert_ne!(target, ip_hash(key, "203.0.113.9".parse().unwrap()));
        assert_ne!(
            code_digest(key, "register", &target, "123456"),
            code_digest(key, "reset", &target, "123456")
        );
        assert_ne!(
            code_digest(key, "register", &target, "123456"),
            code_digest(
                key,
                "register",
                &target_hash(key, "other@example.com"),
                "123456"
            )
        );
    }

    #[test]
    fn operation_id_validation_is_strict() {
        assert!(validate_operation_id(Some("send-20261107-0001")).is_ok());
        assert_eq!(
            validate_operation_id(None),
            Err("VERIFICATION_OPERATION_ID_REQUIRED")
        );
        assert_eq!(
            validate_operation_id(Some("short7")),
            Err("VERIFICATION_OPERATION_ID_LENGTH_INVALID")
        );
        let long = "a".repeat(65);
        assert_eq!(
            validate_operation_id(Some(long.as_str())),
            Err("VERIFICATION_OPERATION_ID_LENGTH_INVALID")
        );
        assert_eq!(
            validate_operation_id(Some("bad id with spaces!")),
            Err("VERIFICATION_OPERATION_ID_CHARSET_INVALID")
        );
    }

    #[test]
    fn purpose_registry_only_admits_bound_consumers() {
        assert!(is_registered_purpose("register"));
        // RESET/SENSITIVE 尚无绑定消费方：fail-closed（已登记兼容行为）。
        assert!(!is_registered_purpose("reset"));
        assert!(!is_registered_purpose(""));
        assert!(!is_registered_purpose("anything"));
    }

    #[test]
    fn budget_windows_are_epoch_aligned_and_stable() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_123).unwrap();
        let start = budget_window_start(now, Duration::minutes(10));
        let bucket = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert_eq!(start, PrimitiveDateTime::new(bucket.date(), bucket.time()));
        assert_eq!(
            start,
            budget_window_start(now.replace_second(0).unwrap(), Duration::minutes(10))
        );
        // 零长度窗口退化：不 panic（按 1s 分桶）。
        let _ = budget_window_start(now, Duration::ZERO);
    }

    #[test]
    fn proof_tokens_are_256bit_and_unique() {
        let a = proof_token();
        let b = proof_token();
        assert_eq!(a.len(), 64, "32 random bytes hex-encoded");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
