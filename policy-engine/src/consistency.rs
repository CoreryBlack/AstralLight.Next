//! 快照一致性巡检（1% 采样）
//!
//! 对齐 Java `SnapshotConsistencyChecker`。
//! 对约 1% 的 evaluate() 调用进行异步重评估。

#![allow(clippy::manual_is_multiple_of)]

use std::collections::HashMap;
use std::sync::Mutex;

use crate::PolicyEngine;
use crate::RuleRepository;
use astral_types::{PolicyContext, PolicyDecision};

/// 全局一致性检查器单例（1% 采样）
static CHECKER: std::sync::OnceLock<SnapshotConsistencyChecker> = std::sync::OnceLock::new();

/// 获取全局一致性检查器实例
pub fn get_consistency_checker() -> &'static SnapshotConsistencyChecker {
    CHECKER.get_or_init(SnapshotConsistencyChecker::new)
}

/// 违规记录上限
const MAX_VIOLATIONS: usize = 1000;

/// 一致性违规记录
#[derive(Debug, Clone)]
pub struct ConsistencyViolation {
    pub context: PolicyContext,
    pub snapshot_decision: PolicyDecision,
    pub realtime_decision: PolicyDecision,
}

/// 一致性巡检统计
#[derive(Debug, Clone, Default)]
pub struct ConsistencyStats {
    pub total_checks: u64,
    pub total_violations: u64,
    pub last_check_at: Option<String>,
}

/// 快照一致性巡检器
pub struct SnapshotConsistencyChecker {
    counter: std::sync::atomic::AtomicU64,
    sample_interval: u64,
    stats: Mutex<ConsistencyStats>,
    violations: Mutex<Vec<ConsistencyViolation>>,
}

impl SnapshotConsistencyChecker {
    pub fn new() -> Self {
        Self {
            counter: Default::default(),
            sample_interval: 100,
            stats: Mutex::new(ConsistencyStats::default()),
            violations: Mutex::new(Vec::new()),
        }
    }

    pub fn should_sample(&self) -> bool {
        let count = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        count % self.sample_interval == 0
    }

    pub async fn check_consistency<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        snapshot_decision: &PolicyDecision,
        engine: &PolicyEngine,
        repo: &R,
    ) -> Option<ConsistencyViolation> {
        if !self.should_sample() {
            return None;
        }

        // A consistency sample is meaningful only when both paths observe the
        // same readable projection generation. Pending or unstable projection
        // state is an expected transition, not a policy violation.
        let card_id = match ctx.card_id {
            Some(card_id) => card_id,
            None => return None,
        };
        let baseline_gate = match repo.get_projection_gate(card_id).await {
            Ok(gate) => gate,
            Err(e) => {
                tracing::debug!(card_id, error = %e, "skipping consistency check: projection gate unavailable");
                return None;
            }
        };
        if baseline_gate.as_ref().is_some_and(|gate| !gate.ready) {
            return None;
        }

        // 使用专用的实时评估路径（跳过快照/缓存层）比对
        let realtime_decision = engine.evaluate_realtime(ctx, repo).await;

        let same_projection = match repo.get_projection_gate(card_id).await {
            Ok(current) => match (&baseline_gate, &current) {
                (None, None) => true,
                (Some(before), Some(after)) => {
                    before.ready
                        && after.ready
                        && before.source_generation == after.source_generation
                        && before.revoke_fence == after.revoke_fence
                }
                _ => false,
            },
            Err(e) => {
                tracing::debug!(card_id, error = %e, "skipping consistency check: projection gate changed unreadably");
                false
            }
        };
        if !same_projection || realtime_decision.reason == "AUTHORIZATION_PENDING" {
            return None;
        }
        if let Ok(mut s) = self.stats.lock() {
            s.total_checks += 1;
        }

        // 对齐 Java `SnapshotConsistencyChecker`：仅比较 allowed 决策，不比较 reason。
        // realtime 路径的 reason 恒为 REALTIME_ALLOW/REALTIME_DENY，快照路径为
        // RULE_SET_ALLOW/RULE_ALLOW 等，直接比较 reason 会把每次 ALLOW 采样误判为违规。
        if snapshot_decision.allowed != realtime_decision.allowed {
            tracing::error!(
                consistency = "violation",
                snapshot_reason = %snapshot_decision.reason,
                realtime_reason = %realtime_decision.reason,
            );

            let violation = ConsistencyViolation {
                context: ctx.clone(),
                snapshot_decision: snapshot_decision.clone(),
                realtime_decision,
            };

            // 记录违规
            if let Ok(mut v) = self.violations.lock() {
                if v.len() < MAX_VIOLATIONS {
                    v.push(violation.clone());
                }
            }
            if let Ok(mut s) = self.stats.lock() {
                s.total_violations += 1;
                s.last_check_at = Some(
                    time::OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                );
            }

            return Some(violation);
        }

        if let Ok(mut s) = self.stats.lock() {
            s.last_check_at = Some(
                time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
        }

        None
    }

    /// 获取统计信息（对齐 Java SnapshotConsistencyChecker.getStats()）
    pub fn get_stats(&self) -> HashMap<String, serde_json::Value> {
        let s = self.stats.lock().unwrap_or_else(|e| e.into_inner());
        let v = self.violations.lock().unwrap_or_else(|e| e.into_inner());
        let mut map = HashMap::new();
        map.insert(
            "totalChecks".to_string(),
            serde_json::Value::Number(s.total_checks.into()),
        );
        map.insert(
            "totalViolations".to_string(),
            serde_json::Value::Number(s.total_violations.into()),
        );
        map.insert(
            "pendingViolations".to_string(),
            serde_json::Value::Number((v.len() as u64).into()),
        );
        map.insert(
            "sampleRate".to_string(),
            serde_json::Value::String("1%".into()),
        );
        if let Some(ref at) = s.last_check_at {
            map.insert(
                "lastCheckAt".to_string(),
                serde_json::Value::String(at.clone()),
            );
        }
        map
    }

    /// 获取当前违规列表（对齐 Java SnapshotConsistencyChecker.getViolations()）
    pub fn get_violations(&self) -> Vec<serde_json::Value> {
        let v = self.violations.lock().unwrap_or_else(|e| e.into_inner());
        v.iter()
            .map(|violation| {
                serde_json::json!({
                    "cardId": violation.context.card_id,
                    "resource": violation.context.resource,
                    "action": violation.context.action,
                    "snapshotAllowed": violation.snapshot_decision.allowed,
                    "snapshotReason": violation.snapshot_decision.reason,
                    "realtimeAllowed": violation.realtime_decision.allowed,
                    "realtimeReason": violation.realtime_decision.reason,
                })
            })
            .collect()
    }

    /// 清除违规记录（对齐 Java SnapshotConsistencyChecker.clearViolations()）
    pub fn clear_violations(&self) {
        if let Ok(mut v) = self.violations.lock() {
            v.clear();
        }
    }
}

impl Default for SnapshotConsistencyChecker {
    fn default() -> Self {
        Self::new()
    }
}
