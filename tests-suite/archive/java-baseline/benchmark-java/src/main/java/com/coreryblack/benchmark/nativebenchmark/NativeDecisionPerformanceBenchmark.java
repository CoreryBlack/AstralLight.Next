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
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
public class NativeDecisionPerformanceBenchmark extends AbstractNativeBenchmark {

    public NativeDecisionPerformanceBenchmark(PolicyEngine policyEngine,
                                               NativeDataGenerator nativeDataGenerator,
                                               StringRedisTemplate redisTemplate,
                                               JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public NativeDecisionPerformanceResult execute(NativeScaleConfig[] gradientScales,
                                                     int iterationsPerScale,
                                                     int concurrency) {
        log.info("=== Native Decision Performance Benchmark (Full 6-Step Pipeline) ===");
        log.info("Scales: {}, iterations/scale: {}, concurrency: {}",
            gradientScales.length, iterationsPerScale, concurrency);

        NativeDecisionPerformanceResult result = new NativeDecisionPerformanceResult();

        for (NativeScaleConfig scale : gradientScales) {
            log.info("--- Scale: {} ---", scale.label());
            NativeScaleResult scaleResult = new NativeScaleResult();
            scaleResult.scale = scale;

            cleanupBenchmarkData();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(scale);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);

            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            scaleResult.singleThreadSnapshot = benchmarkSingleThread(dataset, bindingMap, iterationsPerScale);
            // Read single-thread breakdown/cache stats immediately after measurement
            scaleResult.singleThreadBreakdown = readAndResetStats();
            scaleResult.concurrentSnapshot = benchmarkConcurrent(dataset, bindingMap, iterationsPerScale, concurrency);
            scaleResult.coldStartSnapshot = benchmarkColdStart(dataset, bindingMap, iterationsPerScale);
            scaleResult.pipelineBreakdown = collectPipelineBreakdown(dataset, bindingMap, iterationsPerScale);

            log.info("  ST: mean={}us, p95={}us, p99={}us, tps={}",
                String.format("%.1f", scaleResult.singleThreadSnapshot.meanUs()),
                String.format("%.1f", scaleResult.singleThreadSnapshot.p95Us()),
                String.format("%.1f", scaleResult.singleThreadSnapshot.p99Us()),
                String.format("%.0f", scaleResult.singleThreadSnapshot.tps()));
            log.info("  MT: mean={}us, p95={}us, p99={}us, tps={}",
                String.format("%.1f", scaleResult.concurrentSnapshot.meanUs()),
                String.format("%.1f", scaleResult.concurrentSnapshot.p95Us()),
                String.format("%.1f", scaleResult.concurrentSnapshot.p99Us()),
                String.format("%.0f", scaleResult.concurrentSnapshot.tps()));
            log.info("  Cold: mean={}us, p95={}us, p99={}us, tps={}",
                String.format("%.1f", scaleResult.coldStartSnapshot.meanUs()),
                String.format("%.1f", scaleResult.coldStartSnapshot.p95Us()),
                String.format("%.1f", scaleResult.coldStartSnapshot.p99Us()),
                String.format("%.0f", scaleResult.coldStartSnapshot.tps()));
            log.info("  Pipeline: authn={}us, cardStatus={}us, refsLoad={}us, overlay={}us, base={}us, permRule={}us",
                String.format("%.1f", scaleResult.pipelineBreakdown.authnAvgUs),
                String.format("%.1f", scaleResult.pipelineBreakdown.cardStatusAvgUs),
                String.format("%.1f", scaleResult.pipelineBreakdown.refsLoadAvgUs),
                String.format("%.1f", scaleResult.pipelineBreakdown.overlayEvalAvgUs),
                String.format("%.1f", scaleResult.pipelineBreakdown.baseEvalAvgUs),
                String.format("%.1f", scaleResult.pipelineBreakdown.permRuleEvalAvgUs));

            result.scaleResults.add(scaleResult);
        }

        log.info("=== Native Decision Performance Benchmark Complete ===");
        return result;
    }

    private LatencyRecorder.LatencySnapshot benchmarkSingleThread(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        log.info("  Single-thread benchmark: {} iterations", iterations);

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

    private LatencyRecorder.LatencySnapshot benchmarkConcurrent(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations,
            int concurrency) {
        log.info("  Concurrent benchmark: {} iterations, {} threads", iterations, concurrency);

        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        // B21: 并发测试添加 warmup 阶段，预热 JIT 和缓存，避免冷启动影响测量
        final int CONCURRENT_WARMUP_ITERATIONS = 200;
        for (int i = 0; i < CONCURRENT_WARMUP_ITERATIONS; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            policyEngine.evaluate(ctx);
        }

        // B20: warmup 后重置缓存和分解统计
        policyEngine.resetCacheHitStats();
        policyEngine.resetBreakdownStats();

        LatencyRecorder recorder = new LatencyRecorder();
        AtomicInteger reqIdx = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < concurrency; t++) {
            futures.add(executor.submit(() -> {
                int perThread = iterations / concurrency;
                for (int i = 0; i < perThread; i++) {
                    NativeDataGenerator.NativeEvalRequest req = requests.get(
                        reqIdx.getAndIncrement() % requests.size());
                    setupCardContext(req, bindingMap);
                    PolicyContext ctx = buildPolicyContext(req);
                    long start = recorder.start();
                    try {
                        policyEngine.evaluate(ctx);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError();
                        // B27 fix: skip recorder.stop() for failed requests
                    }
                }
            }));
        }

        for (Future<?> f : futures) {
            try {
                f.get();
            } catch (Exception e) {
                log.error("Concurrent benchmark thread error", e);
            }
        }
        shutdownExecutor(executor);

        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkColdStart(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        log.info("  Cold-start benchmark (cache cleared, L3 fallback): {} iterations", iterations);

        nativeDataGenerator.flushAllCaches();
        policyEngine.resetCacheHitStats();
        policyEngine.resetBreakdownStats();

        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        int coldIterations = Math.min(iterations, 1000);
        for (int i = 0; i < coldIterations; i++) {
            // Each iteration clears cache to simulate true cold-start
            if (i > 0) {
                nativeDataGenerator.flushAllCaches();
            }
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            long start = recorder.start();
            long elapsed;
            try {
                policyEngine.evaluate(ctx);
                elapsed = recorder.stop(start);
            } catch (Exception e) {
                elapsed = System.nanoTime() - start;
                recorder.recordError(elapsed);
            }
            if (i == 0) {
                recorder.recordColdStart(elapsed);
            }
        }

        return recorder.snapshot();
    }

    private PipelineStageBreakdown collectPipelineBreakdown(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        log.info("  Collecting 6-step pipeline stage breakdown...");

        policyEngine.resetBreakdownStats();
        policyEngine.resetCacheHitStats();

        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        Map<String, AtomicLong> phaseCounts = new LinkedHashMap<>();
        phaseCounts.put("AUTHN", new AtomicLong(0));
        phaseCounts.put("CARD_STATUS", new AtomicLong(0));
        phaseCounts.put("RULESET", new AtomicLong(0));
        phaseCounts.put("OVERLAY", new AtomicLong(0));
        phaseCounts.put("BASE", new AtomicLong(0));
        phaseCounts.put("PERMISSION_RULE", new AtomicLong(0));
        phaseCounts.put("DEFAULT", new AtomicLong(0));

        Map<String, AtomicLong> reasonCounts = new LinkedHashMap<>();

        int breakdownIterations = Math.min(iterations, 5000);
        for (int i = 0; i < breakdownIterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            long start = recorder.start();
            PolicyDecision decision = policyEngine.evaluate(ctx);
            recorder.stop(start);

            if (decision.getEvaluationPath() != null) {
                for (PolicyDecision.EvaluationStep step : decision.getEvaluationPath()) {
                    String phase = step.getPhase();
                    if (phaseCounts.containsKey(phase)) {
                        phaseCounts.get(phase).incrementAndGet();
                    }
                    if ("RULESET".equals(phase) && step.getSource() != null) {
                        String subPhase = step.getSource();
                        if (phaseCounts.containsKey(subPhase)) {
                            phaseCounts.get(subPhase).incrementAndGet();
                        }
                    }
                }
            }

            reasonCounts.computeIfAbsent(decision.getReason(), k -> new AtomicLong(0))
                .incrementAndGet();
        }

        Map<String, Object> breakdownStats = policyEngine.getBreakdownStats();

        PipelineStageBreakdown breakdown = new PipelineStageBreakdown();
        breakdown.authnAvgUs = getDouble(breakdownStats, "cardActiveAvgUs");
        // B22: PolicyEngine 未单独追踪 cardStatus 阶段，暂设为 0.0
        breakdown.cardStatusAvgUs = 0.0;
        breakdown.refsLoadAvgUs = getDouble(breakdownStats, "refsLoadAvgUs");
        breakdown.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
        breakdown.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
        breakdown.permRuleEvalAvgUs = getDouble(breakdownStats, "permRuleEvalAvgUs");
        breakdown.totalEvalAvgUs = recorder.snapshot().meanUs();

        breakdown.phaseTraversalCounts = new LinkedHashMap<>();
        phaseCounts.forEach((k, v) -> breakdown.phaseTraversalCounts.put(k, v.get()));

        breakdown.decisionReasonDistribution = new LinkedHashMap<>();
        reasonCounts.forEach((k, v) -> breakdown.decisionReasonDistribution.put(k, v.get()));

        Map<String, Object> cacheStats = policyEngine.getCacheHitStats();
        breakdown.l1HitRate = getDouble(cacheStats, "l1HitRate");
        breakdown.l2HitRate = getDouble(cacheStats, "l2HitRate");
        breakdown.l3HitRate = getDouble(cacheStats, "l3HitRate");

        return breakdown;
    }

    /**
     * Read breakdown and cache stats from PolicyEngine, then reset.
     * Must be called immediately after a benchmark measurement to capture accurate stats.
     */
    private StatsSnapshot readAndResetStats() {
        Map<String, Object> breakdownStats = policyEngine.getBreakdownStats();
        policyEngine.resetBreakdownStats();
        Map<String, Object> cacheStats = policyEngine.getCacheHitStats();
        policyEngine.resetCacheHitStats();

        StatsSnapshot snapshot = new StatsSnapshot();
        snapshot.overlayEvalAvgUs = getDouble(breakdownStats, "overlayEvalAvgUs");
        snapshot.baseEvalAvgUs = getDouble(breakdownStats, "baseEvalAvgUs");
        snapshot.permRuleEvalAvgUs = getDouble(breakdownStats, "permRuleEvalAvgUs");
        snapshot.refsLoadAvgUs = getDouble(breakdownStats, "refsLoadAvgUs");
        snapshot.cardActiveAvgUs = getDouble(breakdownStats, "cardActiveAvgUs");
        snapshot.l1HitRate = getDouble(cacheStats, "l1HitRate");
        snapshot.l2HitRate = getDouble(cacheStats, "l2HitRate");
        snapshot.l3HitRate = getDouble(cacheStats, "l3HitRate");
        return snapshot;
    }

    public static class NativeDecisionPerformanceResult {
        public List<NativeScaleResult> scaleResults = new ArrayList<>();
    }

    public static class NativeScaleResult {
        public NativeScaleConfig scale;
        public LatencyRecorder.LatencySnapshot singleThreadSnapshot;
        public StatsSnapshot singleThreadBreakdown;
        public LatencyRecorder.LatencySnapshot concurrentSnapshot;
        public LatencyRecorder.LatencySnapshot coldStartSnapshot;
        public PipelineStageBreakdown pipelineBreakdown;
    }

    public static class StatsSnapshot {
        public double overlayEvalAvgUs;
        public double baseEvalAvgUs;
        public double permRuleEvalAvgUs;
        public double refsLoadAvgUs;
        public double cardActiveAvgUs;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
    }

    public static class PipelineStageBreakdown {
        public double authnAvgUs;
        public double cardStatusAvgUs;
        public double refsLoadAvgUs;
        public double overlayEvalAvgUs;
        public double baseEvalAvgUs;
        public double permRuleEvalAvgUs;
        public double totalEvalAvgUs;
        public Map<String, Long> phaseTraversalCounts;
        public Map<String, Long> decisionReasonDistribution;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
    }
}
