package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.CardRuleSetRef;
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
public class NativeOverlayDepthBenchmark extends AbstractNativeBenchmark {

    public NativeOverlayDepthBenchmark(PolicyEngine policyEngine,
                                        NativeDataGenerator nativeDataGenerator,
                                        StringRedisTemplate redisTemplate,
                                        JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public List<NativeOverlayDepthResult> execute(NativeScaleConfig[] configs, int iterations) {
        log.info("=== Native Overlay Depth Benchmark (with Simulated Evaluation) ===");
        List<NativeOverlayDepthResult> results = new ArrayList<>();

        for (NativeScaleConfig config : configs) {
            log.info("  overlayRules={}, baseRules={}, total overlay depth test",
                config.getOverlayRulesPerCard(), config.getBaseRulesPerCard());

            cleanupBenchmarkData();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);

            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            LatencyRecorder.LatencySnapshot latencySnapshot = benchmarkAstral(
                dataset, bindingMap, iterations);

            LatencyRecorder.LatencySnapshot simulateSnapshot = benchmarkSimulate(
                dataset, bindingMap, iterations);

            Map<String, Object> breakdownStats = policyEngine.getBreakdownStats();
            policyEngine.resetBreakdownStats();

            Map<String, Object> cacheStats = policyEngine.getCacheHitStats();
            policyEngine.resetCacheHitStats();

            Map<String, Long> overlayConflictStats = collectOverlayConflictStats(
                dataset, bindingMap, Math.min(iterations, 3000));

            NativeOverlayDepthResult result = new NativeOverlayDepthResult();
            result.overlayRules = config.getOverlayRulesPerCard();
            result.baseRules = config.getBaseRulesPerCard();
            result.totalRules = config.getCardCount() * (config.getBaseRulesPerCard() + config.getOverlayRulesPerCard());
            result.latencySnapshot = latencySnapshot;
            result.simulateSnapshot = simulateSnapshot;
            result.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
            result.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
            result.l1HitRate = getDouble(cacheStats, "l1HitRate");
            result.l2HitRate = getDouble(cacheStats, "l2HitRate");
            result.l3HitRate = getDouble(cacheStats, "l3HitRate");
            result.overlayConflictStats = overlayConflictStats;

            log.info("    overlay={}, base={}, eval: mean={}us p99={}us, simulate: mean={}us p99={}us",
                config.getOverlayRulesPerCard(), config.getBaseRulesPerCard(),
                String.format("%.1f", latencySnapshot.meanUs()),
                String.format("%.1f", latencySnapshot.p99Us()),
                String.format("%.1f", simulateSnapshot.meanUs()),
                String.format("%.1f", simulateSnapshot.p99Us()));

            results.add(result);
        }

        log.info("=== Native Overlay Depth Benchmark Complete ===");
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

    private LatencyRecorder.LatencySnapshot benchmarkSimulate(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        log.info("    Simulate (hypothetical evaluation) benchmark: {} iterations", iterations);

        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        List<CardRuleSetRef> hypotheticalRefs = buildHypotheticalRefs(dataset);

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            try {
                policyEngine.simulate(ctx, hypotheticalRefs);
            } catch (Exception e) { log.trace("simulate warmup exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            long start = recorder.start();
            try {
                policyEngine.simulate(ctx, hypotheticalRefs);
                recorder.stop(start);
            } catch (Exception e) {
                recorder.recordError(System.nanoTime() - start);
            }
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        log.info("    Simulate: mean={}us, p95={}us, p99={}us, tps={}, errors={}",
            String.format("%.1f", snapshot.meanUs()),
            String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()),
            String.format("%.0f", snapshot.tps()),
            snapshot.errorOps());
        return snapshot;
    }

    private List<CardRuleSetRef> buildHypotheticalRefs(
            NativeDataGenerator.NativeGeneratedDataSet dataset) {
        List<CardRuleSetRef> refs = new ArrayList<>();

        if (dataset.ruleSets.size() > 1) {
            CardRuleSetRef hypotheticalOverlay = new CardRuleSetRef();
            hypotheticalOverlay.setCardId(0L);
            hypotheticalOverlay.setRuleSetId(dataset.ruleSets.get(dataset.ruleSets.size() - 1).getRuleSetId());
            hypotheticalOverlay.setTenantId(BENCHMARK_TENANT_ID);
            hypotheticalOverlay.setRefType("OVERLAY");
            hypotheticalOverlay.setCreatedAt(java.time.LocalDateTime.now());
            refs.add(hypotheticalOverlay);
        }

        return refs;
    }

    private Map<String, Long> collectOverlayConflictStats(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        Map<String, AtomicLong> conflictCounts = new LinkedHashMap<>();
        conflictCounts.put("OVERLAY_DENY", new AtomicLong(0));
        conflictCounts.put("OVERLAY_ALLOW", new AtomicLong(0));
        conflictCounts.put("BASE_DENY", new AtomicLong(0));
        conflictCounts.put("BASE_ALLOW", new AtomicLong(0));
        conflictCounts.put("PERMISSION_RULE", new AtomicLong(0));
        conflictCounts.put("DEFAULT_DENY", new AtomicLong(0));

        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            PolicyDecision decision = policyEngine.evaluate(ctx);

            if (decision.getEvaluationPath() != null) {
                for (PolicyDecision.EvaluationStep step : decision.getEvaluationPath()) {
                    if ("RULESET".equals(step.getPhase()) && step.getSource() != null) {
                        String key = step.getSource() + "_" + step.getResult();
                        if (conflictCounts.containsKey(key)) {
                            conflictCounts.get(key).incrementAndGet();
                        }
                    }
                    if ("PERMISSION_RULE".equals(step.getPhase())
                        && ("ALLOW".equals(step.getResult()) || "DENY".equals(step.getResult()))) {
                        conflictCounts.get("PERMISSION_RULE").incrementAndGet();
                    }
                    if ("DEFAULT".equals(step.getPhase())) {
                        conflictCounts.get("DEFAULT_DENY").incrementAndGet();
                    }
                }
            }
        }

        Map<String, Long> result = new LinkedHashMap<>();
        conflictCounts.forEach((k, v) -> result.put(k, v.get()));
        return result;
    }

    public static class NativeOverlayDepthResult {
        public int overlayRules;
        public int baseRules;
        public int totalRules;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public LatencyRecorder.LatencySnapshot simulateSnapshot;
        public double overlayEvalAvgUs;
        public double baseEvalAvgUs;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
        public Map<String, Long> overlayConflictStats;
    }
}
