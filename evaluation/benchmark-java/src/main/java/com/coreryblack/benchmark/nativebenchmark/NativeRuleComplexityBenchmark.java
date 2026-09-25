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
public class NativeRuleComplexityBenchmark extends AbstractNativeBenchmark {

    public NativeRuleComplexityBenchmark(PolicyEngine policyEngine,
                                          NativeDataGenerator nativeDataGenerator,
                                          StringRedisTemplate redisTemplate,
                                          JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public List<NativeComplexityResult> execute(NativeScaleConfig[] configs, int iterations) {
        log.info("=== Native Rule Complexity Benchmark (with ABAC) ===");
        List<NativeComplexityResult> results = new ArrayList<>();

        for (NativeScaleConfig config : configs) {
            int totalRules = config.getCardCount() * (config.getBaseRulesPerCard() + config.getOverlayRulesPerCard());
            log.info("  rules_per_card={} (base={}, overlay={}), abacConditions={}, total={} rules",
                config.getBaseRulesPerCard() + config.getOverlayRulesPerCard(),
                config.getBaseRulesPerCard(), config.getOverlayRulesPerCard(),
                config.getAbacConditionsPerRule(), totalRules);

            cleanupBenchmarkData();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);

            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            LatencyRecorder.LatencySnapshot latencySnapshot = benchmarkAstral(
                dataset, bindingMap, iterations);

            Map<String, Object> breakdownStats = policyEngine.getBreakdownStats();
            policyEngine.resetBreakdownStats();

            Map<String, Object> cacheStats = policyEngine.getCacheHitStats();
            policyEngine.resetCacheHitStats();

            Map<String, Long> reasonDistribution = collectReasonDistribution(
                dataset, bindingMap, Math.min(iterations, 3000));

            NativeComplexityResult result = new NativeComplexityResult();
            result.abacConditionsPerRule = config.getAbacConditionsPerRule();
            result.rulesPerCard = config.getBaseRulesPerCard() + config.getOverlayRulesPerCard();
            result.baseRulesPerCard = config.getBaseRulesPerCard();
            result.overlayRulesPerCard = config.getOverlayRulesPerCard();
            result.totalRules = totalRules;
            result.latencySnapshot = latencySnapshot;
            result.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
            result.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
            result.permRuleEvalAvgUs = getDouble(breakdownStats, "permRuleEvalAvgUs");
            result.l1HitRate = getDouble(cacheStats, "l1HitRate");
            result.l2HitRate = getDouble(cacheStats, "l2HitRate");
            result.l3HitRate = getDouble(cacheStats, "l3HitRate");
            result.reasonDistribution = reasonDistribution;

            log.info("    abac={}, mean={}us, p95={}us, p99={}us, tps={}, L1={}%, L2={}%, L3={}%",
                config.getAbacConditionsPerRule(),
                String.format("%.1f", latencySnapshot.meanUs()),
                String.format("%.1f", latencySnapshot.p95Us()),
                String.format("%.1f", latencySnapshot.p99Us()),
                String.format("%.0f", latencySnapshot.tps()),
                String.format("%.1f", result.l1HitRate * 100),
                String.format("%.1f", result.l2HitRate * 100),
                String.format("%.1f", result.l3HitRate * 100));

            results.add(result);
        }

        log.info("=== Native Rule Complexity Benchmark Complete ===");
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
            recorder.stop(start);
        }

        return recorder.snapshot();
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

    public static class NativeComplexityResult {
        public int abacConditionsPerRule;
        public int rulesPerCard;
        public int baseRulesPerCard;
        public int overlayRulesPerCard;
        public int totalRules;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public double overlayEvalAvgUs;
        public double baseEvalAvgUs;
        public double permRuleEvalAvgUs;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
        public Map<String, Long> reasonDistribution;
    }
}
