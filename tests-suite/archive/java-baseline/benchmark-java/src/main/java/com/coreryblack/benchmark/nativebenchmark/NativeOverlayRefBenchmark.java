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
public class NativeOverlayRefBenchmark extends AbstractNativeBenchmark {

    public NativeOverlayRefBenchmark(PolicyEngine policyEngine,
                                      NativeDataGenerator nativeDataGenerator,
                                      StringRedisTemplate redisTemplate,
                                      JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public List<NativeOverlayRefResult> execute(NativeScaleConfig[] configs, int iterations) {
        log.info("=== Native Overlay Ref Count Benchmark (O(K) verification) ===");
        List<NativeOverlayRefResult> results = new ArrayList<>();

        for (NativeScaleConfig config : configs) {
            cleanupBenchmarkData();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);

            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            // Compute actual ref counts from dataset (not config) for accurate reporting
            int baseRefCount = 0;
            int overlayRefCount = 0;
            for (NativeDataGenerator.NativeCardBinding b : dataset.bindings) {
                if (b.baseRef != null) baseRefCount++;
                overlayRefCount += b.overlayRefs.size();
            }
            int cardCount = dataset.bindings.size();
            int avgBaseRefs = cardCount > 0 ? baseRefCount / cardCount : 0;
            int avgOverlayRefs = cardCount > 0 ? overlayRefCount / cardCount : 0;
            int avgTotalRefs = avgBaseRefs + avgOverlayRefs;

            log.info("  config multiOverlayCount={}, actual avg refs={}(base={}+overlay={})",
                config.getMultiOverlayCount(), avgTotalRefs, avgBaseRefs, avgOverlayRefs);

            LatencyRecorder.LatencySnapshot latencySnapshot = benchmarkAstral(
                dataset, bindingMap, iterations);

            Map<String, Object> breakdownStats = policyEngine.getBreakdownStats();
            policyEngine.resetBreakdownStats();

            Map<String, Object> cacheStats = policyEngine.getCacheHitStats();
            policyEngine.resetCacheHitStats();

            Map<String, Long> reasonDistribution = collectReasonDistribution(
                dataset, bindingMap, Math.min(iterations, 3000));

            NativeOverlayRefResult result = new NativeOverlayRefResult();
            result.overlayRefCount = avgOverlayRefs;
            result.baseRefCount = avgBaseRefs;
            result.totalRefCount = avgTotalRefs;
            result.latencySnapshot = latencySnapshot;
            result.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
            result.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
            result.l1HitRate = getDouble(cacheStats, "l1HitRate");
            result.l2HitRate = getDouble(cacheStats, "l2HitRate");
            result.l3HitRate = getDouble(cacheStats, "l3HitRate");
            result.reasonDistribution = reasonDistribution;

            log.info("    refs={}(base={}+overlay={}), mean={}us, p99={}us, L1={}%",
                result.totalRefCount, result.baseRefCount, result.overlayRefCount,
                String.format("%.1f", latencySnapshot.meanUs()),
                String.format("%.1f", latencySnapshot.p99Us()),
                String.format("%.1f", result.l1HitRate * 100));

            results.add(result);
        }

        log.info("=== Native Overlay Ref Count Benchmark Complete ===");
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

    public static class NativeOverlayRefResult {
        public int overlayRefCount;
        public int baseRefCount;
        public int totalRefCount;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public double overlayEvalAvgUs;
        public double baseEvalAvgUs;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
        public Map<String, Long> reasonDistribution;
    }
}
