package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.benchmark.util.BenchmarkDatasetValidator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.coreryblack.permission.auth.PolicyEngine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class NativePermRuleBenchmark extends AbstractNativeBenchmark {

    public NativePermRuleBenchmark(PolicyEngine policyEngine,
                                    NativeDataGenerator nativeDataGenerator,
                                    StringRedisTemplate redisTemplate,
                                    JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public List<NativePermRuleResult> execute(NativeScaleConfig[] configs, int iterations) {
        log.info("=== Native Permission Rule Benchmark (L2 path verification) ===");
        List<NativePermRuleResult> results = new ArrayList<>();

        for (NativeScaleConfig config : configs) {
            log.info("  permissionRules={}, baseRules={}, overlayRules={}",
                config.getPermissionRulesPerCard(), config.getBaseRulesPerCard(), config.getOverlayRulesPerCard());

            cleanupBenchmarkData();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            String datasetFingerprint = BenchmarkDatasetValidator.nativeFingerprint(dataset);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);

            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            BenchmarkMeasurement measurement = benchmarkAstral(
                dataset, bindingMap, iterations);

            Map<String, Object> breakdownStats = policyEngine.getBreakdownStats();
            policyEngine.resetBreakdownStats();

            Map<String, Object> cacheStats = policyEngine.getCacheHitStats();
            policyEngine.resetCacheHitStats();

            NativePermRuleResult result = new NativePermRuleResult();
            result.permissionRulesPerCard = config.getPermissionRulesPerCard();
            result.baseRulesPerCard = config.getBaseRulesPerCard();
            result.overlayRulesPerCard = config.getOverlayRulesPerCard();
            result.latencySnapshot = measurement.latencySnapshot;
            result.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
            result.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
            result.permRuleEvalAvgUs = getDouble(breakdownStats, "permRuleEvalAvgUs");
            result.l1HitRate = getDouble(cacheStats, "l1HitRate");
            result.l2HitRate = getDouble(cacheStats, "l2HitRate");
            result.l3HitRate = getDouble(cacheStats, "l3HitRate");
            result.l1StageRate = getDouble(cacheStats, "l1StageRate");
            result.l2StageRate = getDouble(cacheStats, "l2StageRate");
            result.l3StageRate = getDouble(cacheStats, "l3StageRate");
            result.earlyDenyCount = ((Number) cacheStats.getOrDefault("earlyDenyCount", 0L)).longValue();
            result.ruleStageEvaluations = ((Number) cacheStats.getOrDefault("ruleStageEvaluations", 0L)).longValue();
            result.reasonDistribution = measurement.reasonDistribution;
            result.measuredRequests = measurement.measuredRequests;
            result.injectedCardOnlyHitRequests = measurement.injectedCardOnlyHitRequests;
            result.expectedAllow = measurement.expectedAllow;
            result.expectedDeny = measurement.expectedDeny;
            result.actualL2Allow = measurement.actualL2Allow;
            result.actualL2Deny = measurement.actualL2Deny;
            result.l2Mismatches = measurement.l2Mismatches;
            result.errors = measurement.errors;
            result.totalEvaluations = ((Number) cacheStats.getOrDefault("totalEvaluations", 0L)).longValue();
            result.datasetFingerprint = datasetFingerprint;

            log.info("    permRules={}, mean={}us, p99={}us, L1={}%, L2={}%, L3={}%, earlyDeny={}, ruleStage={}, injectedCardOnlyHits={}, l2Mismatches={}, errors={}",
                result.permissionRulesPerCard,
                String.format("%.1f", result.latencySnapshot.meanUs()),
                String.format("%.1f", result.latencySnapshot.p99Us()),
                String.format("%.1f", result.l1HitRate * 100),
                String.format("%.1f", result.l2HitRate * 100),
                String.format("%.1f", result.l3HitRate * 100),
                result.earlyDenyCount,
                result.ruleStageEvaluations,
                result.injectedCardOnlyHitRequests,
                result.l2Mismatches,
                result.errors);

            results.add(result);
        }

        log.info("=== Native Permission Rule Benchmark Complete ===");
        return results;
    }

    private BenchmarkMeasurement benchmarkAstral(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        Map<String, Long> reasonCounts = new LinkedHashMap<>();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;
        BenchmarkMeasurement measurement = new BenchmarkMeasurement();

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            try {
                policyEngine.evaluate(buildPolicyContext(req));
            } catch (RuntimeException ignored) {
                // Warmup failures must not abort the measured run. They are not
                // included in measured counters or latency samples.
            }
        }

        policyEngine.resetCacheHitStats();
        policyEngine.resetBreakdownStats();

        try {
            for (int i = 0; i < iterations; i++) {
                NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
                setupCardContext(req, bindingMap);
                PolicyContext ctx = buildPolicyContext(req);
                if (req.expectedCardOnlyHit) {
                    // Count the injected trace before execution so the denominator
                    // remains stable even when the engine throws or returns a
                    // safe-default decision.
                    measurement.injectedCardOnlyHitRequests++;
                    if ("ALLOW".equals(req.expectedCardOnlyEffect)) {
                        measurement.expectedAllow++;
                    } else if ("DENY".equals(req.expectedCardOnlyEffect)) {
                        measurement.expectedDeny++;
                    }
                }
                long start = recorder.start();
                try {
                    PolicyDecision decision = policyEngine.evaluate(ctx);
                    long elapsed = recorder.stop(start);
                    if (measurement.measuredRequests == 0) {
                        recorder.recordColdStart(elapsed);
                    }
                    measurement.measuredRequests++;

                    String reason = decision.getReason() == null
                        ? "UNKNOWN" : decision.getReason();
                    reasonCounts.merge(reason, 1L, Long::sum);
                    if (req.expectedCardOnlyHit) {
                        if ("RULE_ALLOW".equals(reason)) {
                            measurement.actualL2Allow++;
                        } else if ("RULE_DENY".equals(reason)) {
                            measurement.actualL2Deny++;
                        }

                        boolean effectMatches =
                            ("ALLOW".equals(req.expectedCardOnlyEffect)
                                && "RULE_ALLOW".equals(reason))
                            || ("DENY".equals(req.expectedCardOnlyEffect)
                                && "RULE_DENY".equals(reason));
                        if (!effectMatches) {
                            measurement.l2Mismatches++;
                        }
                    }
                } catch (RuntimeException e) {
                    recorder.recordError(System.nanoTime() - start);
                    measurement.measuredRequests++;
                    measurement.errors++;
                    if (req.expectedCardOnlyHit) {
                        measurement.l2Mismatches++;
                    }
                    reasonCounts.merge("ERROR", 1L, Long::sum);
                    log.debug("RQ2-K evaluation failed for card {}: {}", req.cardId, e.getMessage());
                }
            }
        } finally {
            com.coreryblack.astral_general.common.context.CardContextHolder.clear();
        }

        measurement.latencySnapshot = recorder.snapshot();
        measurement.reasonDistribution = reasonCounts;
        return measurement;
    }

    private static class BenchmarkMeasurement {
        private LatencyRecorder.LatencySnapshot latencySnapshot;
        private Map<String, Long> reasonDistribution = Map.of();
        private long measuredRequests;
        private long injectedCardOnlyHitRequests;
        private long expectedAllow;
        private long expectedDeny;
        private long actualL2Allow;
        private long actualL2Deny;
        private long l2Mismatches;
        private long errors;
    }

    public static class NativePermRuleResult {
        public int permissionRulesPerCard;
        public int baseRulesPerCard;
        public int overlayRulesPerCard;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public double overlayEvalAvgUs;
        public double baseEvalAvgUs;
        public double permRuleEvalAvgUs;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
        public double l1StageRate;
        public double l2StageRate;
        public double l3StageRate;
        public long earlyDenyCount;
        public long ruleStageEvaluations;
        public Map<String, Long> reasonDistribution;
        public long measuredRequests;
        public long injectedCardOnlyHitRequests;
        public long expectedAllow;
        public long expectedDeny;
        public long actualL2Allow;
        public long actualL2Deny;
        public long l2Mismatches;
        public long errors;
        public long totalEvaluations;
        public String datasetFingerprint;

        /**
         * Validates the mutually exclusive measured counters before a result is
         * written to an artifact.  A mismatch means the trace is not auditable.
         */
        public boolean hasConservedCounts() {
            long classified = reasonDistribution == null ? 0L
                : reasonDistribution.values().stream().mapToLong(Long::longValue).sum();
            return latencySnapshot != null
                && totalEvaluations == measuredRequests
                && ruleStageEvaluations + earlyDenyCount == totalEvaluations
                && measuredRequests == latencySnapshot.totalOps()
                && measuredRequests == classified
                && injectedCardOnlyHitRequests == expectedAllow + expectedDeny
                && actualL2Allow + actualL2Deny <= injectedCardOnlyHitRequests
                && l2Mismatches <= injectedCardOnlyHitRequests
                && errors == latencySnapshot.errorOps();
        }
    }
}
