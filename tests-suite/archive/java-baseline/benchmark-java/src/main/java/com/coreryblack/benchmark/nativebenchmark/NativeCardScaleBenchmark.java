package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.benchmark.nativebenchmark.NativeScaleConfig;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
public class NativeCardScaleBenchmark extends AbstractNativeBenchmark {

    public NativeCardScaleBenchmark(PolicyEngine policyEngine,
                                     NativeDataGenerator nativeDataGenerator,
                                     StringRedisTemplate redisTemplate,
                                     JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public List<NativeCardScaleResult> execute(NativeScaleConfig[] configs, int iterations) {
        log.info("=== Native Card Scale Benchmark (Multi-Template Multi-Domain) ===");
        List<NativeCardScaleResult> results = new ArrayList<>();

        for (NativeScaleConfig config : configs) {
            int totalRules = config.getCardCount() * (config.getBaseRulesPerCard() + config.getOverlayRulesPerCard());
            log.info("  cardCount={}, templateCount={}, domainCount={}, total={} rules",
                config.getCardCount(), config.getTemplateCount(), config.getDomainCount(), totalRules);

            cleanupBenchmarkData();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);

            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            LatencyRecorder.LatencySnapshot latencySnapshot = benchmarkAstral(
                dataset, bindingMap, iterations);

            long storageBytes = measureStorageSize();
            double astralTps = latencySnapshot.tps();

            Map<String, Object> cacheStats = policyEngine.getCacheHitStats();
            policyEngine.resetCacheHitStats();

            Map<String, Object> breakdownStats = policyEngine.getBreakdownStats();
            policyEngine.resetBreakdownStats();

            Map<String, Long> reasonDistribution = collectReasonDistribution(
                dataset, bindingMap, Math.min(iterations, 3000));

            NativeCardScaleResult result = new NativeCardScaleResult();
            result.cardCount = config.getCardCount();
            result.templateCount = config.getTemplateCount();
            result.domainCount = config.getDomainCount();
            result.totalRules = totalRules;
            result.latencySnapshot = latencySnapshot;
            result.storageBytes = storageBytes;
            result.astralTps = astralTps;
            result.l1HitRate = getDouble(cacheStats, "l1HitRate");
            result.l2HitRate = getDouble(cacheStats, "l2HitRate");
            result.l3HitRate = getDouble(cacheStats, "l3HitRate");
            result.refsLoadAvgUs = getDouble(breakdownStats, "refsLoadAvgUs");
            result.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
            result.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
            result.permRuleEvalAvgUs = getDouble(breakdownStats, "permRuleEvalAvgUs");
            result.reasonDistribution = reasonDistribution;

            log.info("    cards={}, tpl={}, dom={}, mean={}us, p99={}us, tps={}, storage={}MB",
                config.getCardCount(), config.getTemplateCount(), config.getDomainCount(),
                String.format("%.1f", latencySnapshot.meanUs()),
                String.format("%.1f", latencySnapshot.p99Us()),
                String.format("%.0f", astralTps),
                String.format("%.2f", storageBytes / (1024.0 * 1024.0)));

            results.add(result);
        }

        log.info("=== Native Card Scale Benchmark Complete ===");
        return results;
    }

    private LatencyRecorder.LatencySnapshot benchmarkAstral(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            policyEngine.evaluate(ctx);
        }

        // B20: warmup 后重置缓存和分解统计，避免 warmup 数据污染测量结果
        policyEngine.resetCacheHitStats();
        policyEngine.resetBreakdownStats();

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            long start = recorder.start();
            policyEngine.evaluate(ctx);
            long elapsed = recorder.stop(start);
            // Record first-call (cold) latency — only the first iteration
            if (i == 0) {
                recorder.recordColdStart(elapsed);
            }
        }

        return recorder.snapshot();
    }

    private long measureStorageSize() {
        try {
            // P3 修复：查询前先执行 ANALYZE TABLE 刷新 InnoDB 统计信息
            String[] tables = {"rule_set", "rule_set_entry", "rule_set_snapshot",
                "card_rule_set_ref", "permission_rule", "permission_rule_snapshot",
                "user_card", "user_card_template"};
            for (String table : tables) {
                try {
                    jdbcTemplate.execute("ANALYZE TABLE " + table);
                } catch (Exception e) { log.trace("ANALYZE TABLE skipped: {}", e.getMessage()); }
            }
            Long dbBytes = jdbcTemplate.queryForObject(
                "SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) " +
                "FROM information_schema.TABLES " +
                "WHERE TABLE_SCHEMA = DATABASE() " +
                "AND TABLE_NAME IN (" +
                "  'rule_set','rule_set_entry','rule_set_snapshot'," +
                "  'card_rule_set_ref','permission_rule','permission_rule_snapshot'," +
                "  'user_card','user_card_template')",
                Long.class);
            return dbBytes != null ? dbBytes : 0L;
        } catch (Exception e) {
            log.warn("Failed to measure storage size: {}", e.getMessage());
            return 0L;
        }
    }

    private Map<String, Long> collectReasonDistribution(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        Map<String, AtomicLong> reasonCounts = new LinkedHashMap<>();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            PolicyDecision decision = policyEngine.evaluate(ctx);
            reasonCounts.computeIfAbsent(decision.getReason(), k -> new AtomicLong(0))
                .incrementAndGet();
        }

        Map<String, Long> result = new LinkedHashMap<>();
        reasonCounts.forEach((k, v) -> result.put(k, v.get()));
        return result;
    }

    public static class NativeCardScaleResult {
        public int cardCount;
        public int templateCount;
        public int domainCount;
        public int totalRules;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public long storageBytes;
        public double astralTps;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
        public double refsLoadAvgUs;
        public double overlayEvalAvgUs;
        public double baseEvalAvgUs;
        public double permRuleEvalAvgUs;
        public Map<String, Long> reasonDistribution;
    }
}
