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
public class NativeConflictDensityBenchmark extends AbstractNativeBenchmark {

    public NativeConflictDensityBenchmark(PolicyEngine policyEngine,
                                           NativeDataGenerator nativeDataGenerator,
                                           StringRedisTemplate redisTemplate,
                                           JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public List<NativeConflictDensityResult> execute(NativeScaleConfig[] configs, int iterations) {
        log.info("=== Native Conflict Density Benchmark ===");
        List<NativeConflictDensityResult> results = new ArrayList<>();

        for (NativeScaleConfig config : configs) {
            log.info("  denyRatio={}, abacDenyRatio={}",
                String.format("%.0f%%", config.getDenyRatio() * 100),
                String.format("%.0f%%", config.getAbacDenyRatio() * 100));

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

            ConflictResolutionStats conflictStats = collectConflictResolutionStats(
                dataset, bindingMap, Math.min(iterations, 5000));

            LatencyRecorder.LatencySnapshot abacDenyImpactSnapshot = benchmarkAbacDenyImpact(
                dataset, bindingMap, config.getAbacDenyRatio(), iterations);

            // Verify hierarchical-priority correctness
            verifyHierarchicalPriorityCorrectness(dataset, bindingMap, Math.min(iterations, 5000), conflictStats);

            NativeConflictDensityResult result = new NativeConflictDensityResult();
            result.denyRatio = config.getDenyRatio();
            result.abacDenyRatio = config.getAbacDenyRatio();
            result.latencySnapshot = latencySnapshot;
            result.abacDenyImpactSnapshot = abacDenyImpactSnapshot;
            result.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
            result.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
            result.permRuleEvalAvgUs = getDouble(breakdownStats, "permRuleEvalAvgUs");
            result.l1HitRate = getDouble(cacheStats, "l1HitRate");
            result.l2HitRate = getDouble(cacheStats, "l2HitRate");
            result.l3HitRate = getDouble(cacheStats, "l3HitRate");
            result.conflictStats = conflictStats;

            log.info("    deny={}%, abacDeny={}%, eval: mean={}us p99={}us, " +
                    "conflicts: overlayDeny={} baseDeny={} overlayOverrideBase={}",
                String.format("%.0f", config.getDenyRatio() * 100),
                String.format("%.0f", config.getAbacDenyRatio() * 100),
                String.format("%.1f", latencySnapshot.meanUs()),
                String.format("%.1f", latencySnapshot.p99Us()),
                conflictStats.overlayDenyCount, conflictStats.baseDenyCount,
                conflictStats.overlayOverrideBaseCount);

            results.add(result);
        }

        log.info("=== Native Conflict Density Benchmark Complete ===");
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
            if (i == 0) {
                recorder.recordColdStart(elapsed);
            }
        }

        return recorder.snapshot();
    }

    private ConflictResolutionStats collectConflictResolutionStats(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        ConflictResolutionStats stats = new ConflictResolutionStats();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        AtomicLong overlayDenyCount = new AtomicLong(0);
        AtomicLong overlayAllowCount = new AtomicLong(0);
        AtomicLong baseDenyCount = new AtomicLong(0);
        AtomicLong baseAllowCount = new AtomicLong(0);
        AtomicLong overlayOverrideBaseCount = new AtomicLong(0);
        AtomicLong baseOverrideOverlayCount = new AtomicLong(0);
        AtomicLong permRuleCount = new AtomicLong(0);
        AtomicLong defaultDenyCount = new AtomicLong(0);

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            PolicyDecision decision = policyEngine.evaluate(ctx);

            if (decision.getEvaluationPath() != null) {
                boolean hadOverlayResult = false;
                String overlayResult = null;
                String baseResult = null;

                for (PolicyDecision.EvaluationStep step : decision.getEvaluationPath()) {
                    if ("RULESET".equals(step.getPhase()) && step.getSource() != null) {
                        if ("OVERLAY".equals(step.getSource())) {
                            hadOverlayResult = true;
                            overlayResult = step.getResult();
                            if ("DENY".equals(step.getResult())) {
                                overlayDenyCount.incrementAndGet();
                            } else if ("ALLOW".equals(step.getResult())) {
                                overlayAllowCount.incrementAndGet();
                            }
                        } else if ("BASE".equals(step.getSource())) {
                            baseResult = step.getResult();
                            if ("DENY".equals(step.getResult())) {
                                baseDenyCount.incrementAndGet();
                            } else if ("ALLOW".equals(step.getResult())) {
                                baseAllowCount.incrementAndGet();
                            }
                        }
                    }
                    if ("PERMISSION_RULE".equals(step.getPhase())
                        && ("ALLOW".equals(step.getResult()) || "DENY".equals(step.getResult()))) {
                        permRuleCount.incrementAndGet();
                    }
                    if ("DEFAULT".equals(step.getPhase())) {
                        defaultDenyCount.incrementAndGet();
                    }
                }

                if (hadOverlayResult && overlayResult != null && baseResult != null) {
                    if (!overlayResult.equals(baseResult)) {
                        if ("DENY".equals(overlayResult) && "ALLOW".equals(baseResult)) {
                            overlayOverrideBaseCount.incrementAndGet();
                        } else if ("ALLOW".equals(overlayResult) && "DENY".equals(baseResult)) {
                            baseOverrideOverlayCount.incrementAndGet();
                        }
                    }
                }
            }
        }

        stats.overlayDenyCount = overlayDenyCount.get();
        stats.overlayAllowCount = overlayAllowCount.get();
        stats.baseDenyCount = baseDenyCount.get();
        stats.baseAllowCount = baseAllowCount.get();
        stats.overlayOverrideBaseCount = overlayOverrideBaseCount.get();
        stats.baseOverrideOverlayCount = baseOverrideOverlayCount.get();
        stats.permRuleCount = permRuleCount.get();
        stats.defaultDenyCount = defaultDenyCount.get();

        return stats;
    }

    private LatencyRecorder.LatencySnapshot benchmarkAbacDenyImpact(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            double abacDenyRatio,
            int iterations) {
        if (abacDenyRatio <= 0.0) {
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }

        log.info("    ABAC deny impact benchmark: abacDenyRatio={}%", (int)(abacDenyRatio * 100));

        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        long abacDenyCount = 0;
        long abacAllowCount = 0;

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            if (req.abacContext == null) continue;
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            policyEngine.evaluate(ctx);
        }

        // B20: warmup 后重置缓存和分解统计
        policyEngine.resetCacheHitStats();
        policyEngine.resetBreakdownStats();

        int abacIterations = Math.min(iterations, 3000);
        for (int i = 0; i < abacIterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            if (req.abacContext == null) continue;
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            long start = recorder.start();
            PolicyDecision decision = policyEngine.evaluate(ctx);
            recorder.stop(start);

            if (decision.getEvaluationPath() != null) {
                boolean hasAbacStep = decision.getEvaluationPath().stream()
                    .anyMatch(s -> s.getDetail() != null && s.getDetail().contains("abac"));
                if (hasAbacStep) {
                    if (decision.isAllowed()) {
                        abacAllowCount++;
                    } else {
                        abacDenyCount++;
                    }
                }
            }
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        log.info("    ABAC impact: mean={}us, p99={}us, abacDeny={}, abacAllow={}",
            String.format("%.1f", snapshot.meanUs()),
            String.format("%.1f", snapshot.p99Us()),
            abacDenyCount, abacAllowCount);
        return snapshot;
    }


    public static class NativeConflictDensityResult {
        public double denyRatio;
        public double abacDenyRatio;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public LatencyRecorder.LatencySnapshot abacDenyImpactSnapshot;
        public double overlayEvalAvgUs;
        public double baseEvalAvgUs;
        public double permRuleEvalAvgUs;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
        public ConflictResolutionStats conflictStats;
    }

    public static class ConflictResolutionStats {
        public long overlayDenyCount;
        public long overlayAllowCount;
        public long baseDenyCount;
        public long baseAllowCount;
        public long overlayOverrideBaseCount;
        public long baseOverrideOverlayCount;
        public long permRuleCount;
        public long defaultDenyCount;
        /** hierarchical-priority correctness: OVERLAY DENY must override BASE ALLOW */
        public long overlayDenyOverridesBaseAllowCount;
        /** hierarchical-priority correctness: OVERLAY ALLOW must override BASE DENY */
        public long overlayAllowOverridesBaseDenyCount;
        /** Violation count: cases where BASE DENY incorrectly overrides OVERLAY ALLOW */
        public long priorityViolationCount;
    }

    /**
     * Verify hierarchical-priority correctness: OVERLAY DENY > OVERLAY ALLOW > BASE DENY > BASE ALLOW.
     * When OVERLAY and BASE conflict, the final decision must follow hierarchical priority.
     */
    private void verifyHierarchicalPriorityCorrectness(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations,
            ConflictResolutionStats stats) {
        long overlayDenyOverridesBaseAllow = 0;
        long overlayAllowOverridesBaseDeny = 0;
        long violations = 0;
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            PolicyDecision decision = policyEngine.evaluate(ctx);

            if (decision.getEvaluationPath() != null) {
                String overlayResult = null;
                String baseResult = null;

                for (PolicyDecision.EvaluationStep step : decision.getEvaluationPath()) {
                    if ("RULESET".equals(step.getPhase()) && step.getSource() != null) {
                        if ("OVERLAY".equals(step.getSource())) {
                            overlayResult = step.getResult();
                        } else if ("BASE".equals(step.getSource())) {
                            baseResult = step.getResult();
                        }
                    }
                }

                if (overlayResult != null && baseResult != null && !overlayResult.equals(baseResult)) {
                    // hierarchical-priority: OVERLAY always wins over BASE
                    if ("DENY".equals(overlayResult) && "ALLOW".equals(baseResult)) {
                        overlayDenyOverridesBaseAllow++;
                        // Verify final decision is DENY
                        if (decision.isAllowed()) {
                            violations++;
                            log.warn("PRIORITY VIOLATION: OVERLAY DENY + BASE ALLOW → final ALLOW (cardId={})",
                                req.cardId);
                        }
                    } else if ("ALLOW".equals(overlayResult) && "DENY".equals(baseResult)) {
                        overlayAllowOverridesBaseDeny++;
                        // Verify final decision is ALLOW
                        if (!decision.isAllowed()) {
                            violations++;
                            log.warn("PRIORITY VIOLATION: OVERLAY ALLOW + BASE DENY → final DENY (cardId={})",
                                req.cardId);
                        }
                    }
                }
            }
        }

        // B28 fix: write computed values back to stats object
        stats.overlayDenyOverridesBaseAllowCount = overlayDenyOverridesBaseAllow;
        stats.overlayAllowOverridesBaseDenyCount = overlayAllowOverridesBaseDeny;
        stats.priorityViolationCount = violations;

        if (violations > 0) {
            log.error("HIERARCHICAL PRIORITY CORRECTNESS: {} violations out of {} conflict cases!",
                violations, overlayDenyOverridesBaseAllow + overlayAllowOverridesBaseDeny);
        } else if (overlayDenyOverridesBaseAllow + overlayAllowOverridesBaseDeny > 0) {
            log.info("HIERARCHICAL PRIORITY CORRECTNESS: PASS (0 violations in {} conflict cases)",
                overlayDenyOverridesBaseAllow + overlayAllowOverridesBaseDeny);
        }
    }
}
