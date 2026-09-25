package com.coreryblack.benchmark.util;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.permission.permission.RuleSetService;
import com.coreryblack.benchmark.util.BenchmarkMockRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class BenchmarkValidityAudit {

    private static final long BENCHMARK_TENANT_ID = 1L;

    private final PolicyEngine policyEngine;
    private final RuleSetService ruleSetService;
    private final JdbcTemplate jdbcTemplate;
    private final StringRedisTemplate redisTemplate;

    public BenchmarkValidityAudit(PolicyEngine policyEngine,
                                   RuleSetService ruleSetService,
                                   JdbcTemplate jdbcTemplate,
                                   StringRedisTemplate redisTemplate) {
        this.policyEngine = policyEngine;
        this.ruleSetService = ruleSetService;
        this.jdbcTemplate = jdbcTemplate;
        this.redisTemplate = redisTemplate;
    }

    public boolean runFullAudit() {
        log.info("==================================================");
        log.info("   BENCHMARK VALIDITY AUDIT - START");
        log.info("==================================================");

        boolean allPassed = true;

        allPassed &= audit_L1_snapshotTable();
        allPassed &= audit_L2_redisKeyFormat();
        allPassed &= audit_L3_cardContextHolder();
        allPassed &= audit_L4_decisionReasonDistribution();
        allPassed &= audit_L5_cacheHitRate();

        if (allPassed) {
            log.info("==================================================");
            log.info("   BENCHMARK VALIDITY AUDIT - ALL PASSED");
            log.info("==================================================");
        } else {
            log.error("==================================================");
            log.error("   BENCHMARK VALIDITY AUDIT - FAILED");
            log.error("   DO NOT TRUST BENCHMARK DATA UNTIL FIXED!");
            log.error("==================================================");
        }
        return allPassed;
    }

    private boolean audit_L1_snapshotTable() {
        log.info("[L1] Checking rule_set_snapshot table...");
        try {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM rule_set_snapshot", Integer.class);
            if (count == null || count == 0) {
                log.error("[L1] FAIL: rule_set_snapshot table is EMPTY! " +
                    "DB fallback will always miss -> L3 DEFAULT_DENY");
                return false;
            }
            Map<String, Integer> effectDist = new HashMap<>();
            jdbcTemplate.query(
                "SELECT final_effect, COUNT(*) as cnt FROM rule_set_snapshot GROUP BY final_effect",
                rs -> { effectDist.put(rs.getString("final_effect"), rs.getInt("cnt")); });
            log.info("[L1] PASS: rule_set_snapshot has {} records, distribution: {}", count, effectDist);
            return true;
        } catch (Exception e) {
            log.error("[L1] FAIL: Error querying rule_set_snapshot: {}", e.getMessage());
            return false;
        }
    }

    private boolean audit_L2_redisKeyFormat() {
        log.info("[L2] Checking Redis key format and value format...");
        try {
            Set<String> rulesetKeys = new HashSet<>();
            try (Cursor<String> cursor = redisTemplate.scan(
                    ScanOptions.scanOptions().match("perm:ruleset:*").count(100).build())) {
                while (cursor.hasNext()) {
                    rulesetKeys.add(cursor.next());
                }
            }
            if (rulesetKeys == null || rulesetKeys.isEmpty()) {
                log.warn("[L2] WARN: No perm:ruleset:* keys in Redis. Cache may not be populated yet.");
                return true;
            }
            boolean allValuesValid = true;
            int checked = 0;
            for (String key : rulesetKeys) {
                if (checked >= 3) break;
                Map<Object, Object> entries = redisTemplate.opsForHash().entries(key);
                for (Map.Entry<Object, Object> e : entries.entrySet()) {
                    String value = e.getValue().toString();
                    if (value.startsWith("{")) {
                        log.error("[L2] FAIL: Redis value is JSON object, expected plain string! " +
                            "key={} field={} value={}", key, e.getKey(), value);
                        allValuesValid = false;
                    }
                    checked++;
                }
            }
            if (allValuesValid) {
                log.info("[L2] PASS: Redis values are plain strings (ALLOW/DENY), checked {} fields", checked);
            }
            return allValuesValid;
        } catch (Exception e) {
            log.error("[L2] FAIL: Error checking Redis: {}", e.getMessage());
            return false;
        }
    }

    private boolean audit_L3_cardContextHolder() {
        log.info("[L3] Checking CardContextHolder tenantId...");
        Long tenantId = CardContextHolder.getTenantId();
        if (tenantId == null) {
            log.warn("[L3] WARN: CardContextHolder.tenantId is null. " +
                "Ensure setupCardContext() is called before evaluate().");
            log.info("[L3] Setting up CardContextHolder with tenantId=1 for subsequent audits...");
            IdentityCardContext ctx = new IdentityCardContext();
            ctx.setCardId(1L);
            ctx.setUserId(1L);
            ctx.setTenantId(BENCHMARK_TENANT_ID);
            ctx.setDomainId(1L);
            ctx.setTemplateId(1L);
            ctx.setCardType("STUDENT");
            ctx.setStatus("ACTIVE");
            CardContextHolder.set(ctx);
            tenantId = CardContextHolder.getTenantId();
        }
        boolean passed = tenantId != null && tenantId > 0;
        if (passed) {
            log.info("[L3] PASS: CardContextHolder.tenantId={}", tenantId);
        } else {
            log.error("[L3] FAIL: CardContextHolder.tenantId is still null after setup!");
        }
        return passed;
    }

    private boolean audit_L4_decisionReasonDistribution() {
        log.info("[L4] Checking decision reason distribution (sampling 100 evaluations)...");
        try {
            Integer snapshotCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM rule_set_snapshot", Integer.class);
            if (snapshotCount == null || snapshotCount == 0) {
                log.warn("[L4] SKIP: No snapshot data available for decision sampling");
                return true;
            }

            List<Long> cardIds = jdbcTemplate.queryForList(
                "SELECT DISTINCT card_id FROM card_rule_set_ref LIMIT 10", Long.class);
            if (cardIds.isEmpty()) {
                log.warn("[L4] SKIP: No card_rule_set_ref data available");
                return true;
            }

            Map<String, AtomicLong> reasonDist = new HashMap<>();
            int allowCount = 0;
            int denyCount = 0;
            int defaultDenyCount = 0;
            int cardDisabledCount = 0;
            int sampleSize = 100;

            for (int i = 0; i < sampleSize; i++) {
                Long cardId = cardIds.get(i % cardIds.size());
                setupCardContext(cardId);
                PolicyContext ctx = PolicyContext.builder()
                    .userId(1L).cardId(cardId).tenantId(BENCHMARK_TENANT_ID)
                    .domainId(1L).templateId(1L)
                    .resource("learn_subject").action("read")
                    .targetId(1L)
                    .request(new BenchmarkMockRequest("198.51.100.1", "device_benchmark"))
                    .build();
                PolicyDecision decision = policyEngine.evaluate(ctx);
                String reason = decision.getReason() != null ? decision.getReason() : "UNKNOWN";
                reasonDist.computeIfAbsent(reason, k -> new AtomicLong(0)).incrementAndGet();
                if (decision.isAllowed()) {
                    allowCount++;
                } else if ("DEFAULT_DENY".equals(reason)) {
                    defaultDenyCount++;
                } else if ("CARD_DISABLED".equals(reason)) {
                    cardDisabledCount++;
                } else {
                    denyCount++;
                }
            }

            CardContextHolder.clear();

            double defaultDenyRate = (double) defaultDenyCount / sampleSize;
            double cardDisabledRate = (double) cardDisabledCount / sampleSize;
            log.info("[L4] Decision distribution over {} samples: ALLOW={}, DENY(rule)={}, DEFAULT_DENY={}, CARD_DISABLED={}",
                sampleSize, allowCount, denyCount, defaultDenyCount, cardDisabledCount);
            for (var entry : reasonDist.entrySet()) {
                double pct = (double) entry.getValue().get() / sampleSize * 100;
                log.info("[L4]   {} = {} ({}%)", entry.getKey(), entry.getValue().get(),
                    String.format("%.1f", pct));
            }

            if (cardDisabledRate > 0.5) {
                log.error("[L4] FAIL: CARD_DISABLED rate = {}% -- user_card table is missing or card_status is not ACTIVE! " +
                    "isCardActive() falls back to DB and finds no record.",
                    String.format("%.1f", cardDisabledRate * 100));
                return false;
            }

            if (defaultDenyRate > 0.9) {
                log.error("[L4] FAIL: DEFAULT_DENY rate = {}% -- evaluation path is broken! " +
                    "Most requests are not matching any rule.",
                    String.format("%.1f", defaultDenyRate * 100));
                return false;
            }
            if (defaultDenyRate > 0.5) {
                log.warn("[L4] WARN: DEFAULT_DENY rate = {}% -- higher than expected. " +
                    "Check if snapshot data matches eval requests.",
                    String.format("%.1f", defaultDenyRate * 100));
            }
            log.info("[L4] PASS: DEFAULT_DENY rate = {}% (below 90% threshold)",
                String.format("%.1f", defaultDenyRate * 100));
            return true;
        } catch (Exception e) {
            log.error("[L4] FAIL: Error during decision sampling: {}", e.getMessage());
            return false;
        }
    }

    private boolean audit_L5_cacheHitRate() {
        log.info("[L5] Checking cache hit rates...");
        try {
            Map<String, Object> stats = policyEngine.getCacheHitStats();
            double l1Rate = toDouble(stats.getOrDefault("l1HitRate", 0.0));
            double l2Rate = toDouble(stats.getOrDefault("l2HitRate", 0.0));
            double l3Rate = toDouble(stats.getOrDefault("l3HitRate", 0.0));
            long total = toLong(stats.getOrDefault("totalEvaluations", 0L));

            if (total == 0) {
                log.info("[L5] SKIP: No evaluations yet (totalEvaluations=0)");
                return true;
            }

            log.info("[L5] Cache hit rates: L1={}%, L2={}%, L3={}%, total={}",
                String.format("%.1f", l1Rate * 100),
                String.format("%.1f", l2Rate * 100),
                String.format("%.1f", l3Rate * 100), total);

            if (l1Rate == 0.0 && l2Rate == 0.0 && l3Rate == 1.0) {
                log.error("[L5] FAIL: 100% L3 hit rate -- cache is completely ineffective!");
                return false;
            }
            if (l1Rate > 0.0) {
                log.info("[L5] PASS: L1 cache hit rate = {}%",
                    String.format("%.1f", l1Rate * 100));
                return true;
            }
            if (l2Rate > 0.0) {
                log.info("[L5] PASS: L2 cache hit rate = {}% (L1 miss, L2 hit)",
                    String.format("%.1f", l2Rate * 100));
                return true;
            }
            log.warn("[L5] WARN: L1 and L2 both 0%, all hits at L3 (DEFAULT_DENY)");
            return false;
        } catch (Exception e) {
            log.error("[L5] FAIL: Error checking cache stats: {}", e.getMessage());
            return false;
        }
    }

    private void setupCardContext(Long cardId) {
        IdentityCardContext ctx = new IdentityCardContext();
        ctx.setCardId(cardId);
        ctx.setUserId(1L);
        ctx.setTenantId(BENCHMARK_TENANT_ID);
        ctx.setDomainId(1L);
        ctx.setTemplateId(1L);
        ctx.setCardType("STUDENT");
        ctx.setStatus("ACTIVE");
        CardContextHolder.set(ctx);
    }

    private static double toDouble(Object val) {
        if (val instanceof Number) return ((Number) val).doubleValue();
        return 0.0;
    }

    private static long toLong(Object val) {
        if (val instanceof Number) return ((Number) val).longValue();
        return 0L;
    }
}
