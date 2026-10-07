package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
public class NativeCardIsolationBenchmark extends AbstractNativeBenchmark {

    public NativeCardIsolationBenchmark(PolicyEngine policyEngine,
                                         NativeDataGenerator nativeDataGenerator,
                                         StringRedisTemplate redisTemplate,
                                         JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public List<NativeCardIsolationResult> execute(NativeScaleConfig[] configs, int iterations) {
        log.info("=== Native Card Isolation Benchmark (O(1) w.r.t. N) ===");
        List<NativeCardIsolationResult> results = new ArrayList<>();

        for (NativeScaleConfig config : configs) {
            log.info("  cards={}, templates={}, baseRules={}",
                config.getCardCount(), Math.max(1, config.getTemplateCount()), config.getBaseRulesPerCard());

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

            NativeCardIsolationResult result = new NativeCardIsolationResult();
            result.cardCount = config.getCardCount();
            result.templateCount = Math.max(1, config.getTemplateCount());
            result.baseRulesPerCard = config.getBaseRulesPerCard();
            result.latencySnapshot = latencySnapshot;
            result.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
            result.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
            result.permRuleEvalAvgUs = getDouble(breakdownStats, "permRuleEvalAvgUs");
            result.l1HitRate = getDouble(cacheStats, "l1HitRate");
            result.l2HitRate = getDouble(cacheStats, "l2HitRate");
            result.l3HitRate = getDouble(cacheStats, "l3HitRate");
            result.reasonDistribution = reasonDistribution;

            log.info("    cards={}, mean={}us, p99={}us, L1={}%, L2={}%, L3={}%",
                result.cardCount,
                String.format("%.1f", latencySnapshot.meanUs()),
                String.format("%.1f", latencySnapshot.p99Us()),
                String.format("%.1f", result.l1HitRate * 100),
                String.format("%.1f", result.l2HitRate * 100),
                String.format("%.1f", result.l3HitRate * 100));

            results.add(result);
        }

        log.info("=== Native Card Isolation Benchmark Complete ===");
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

        policyEngine.resetCacheHitStats();
        policyEngine.resetBreakdownStats();

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            long start = recorder.start();
            policyEngine.evaluate(ctx);
            long elapsed = recorder.stop(start);
            if (i == 0) {
                recorder.recordColdStart(elapsed);
            }
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

    public static class NativeCardIsolationResult {
        public int cardCount;
        public int templateCount;
        public int baseRulesPerCard;
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
