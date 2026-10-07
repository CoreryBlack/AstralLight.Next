package com.coreryblack.benchmark.rq2;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.benchmark.baseline.CasbinAdapter;
import com.coreryblack.benchmark.baseline.CasbinCachedAdapter;
import com.coreryblack.benchmark.baseline.OpaAdapter;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class DecisionPerformanceBenchmark {

    private static final int WARMUP_ITERATIONS = 1000;
    private static final long BENCHMARK_TENANT_ID = 1L;

    private void setupCardContext(Long cardId) {
        IdentityCardContext ctx = new IdentityCardContext();
        ctx.setCardId(cardId);
        ctx.setUserId(1L);
        ctx.setTenantId(BENCHMARK_TENANT_ID);
        ctx.setDomainId(1L);
        ctx.setTemplateId(1L);
        ctx.setCardType("PLATFORM_CARD");
        ctx.setStatus("ACTIVE");
        CardContextHolder.set(ctx);
    }

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final CasbinAdapter casbinAdapter;
    private final CasbinCachedAdapter casbinCachedAdapter;
    private final OpaAdapter opaAdapter;
    private final OpaAdapter opaNoCacheAdapter;
    private final JdbcTemplate jdbcTemplate;

    public DecisionPerformanceBenchmark(PolicyEngine policyEngine,
                                         DataGenerator dataGenerator,
                                         StringRedisTemplate redisTemplate,
                                         CasbinAdapter casbinAdapter,
                                         CasbinCachedAdapter casbinCachedAdapter,
                                         OpaAdapter opaAdapter,
                                         OpaAdapter opaNoCacheAdapter,
                                         JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.casbinAdapter = casbinAdapter;
        this.casbinCachedAdapter = casbinCachedAdapter;
        this.opaAdapter = opaAdapter;
        this.opaNoCacheAdapter = opaNoCacheAdapter;
        this.jdbcTemplate = jdbcTemplate;
    }

    public DecisionPerformanceResult execute(ScaleConfig[] gradientScales,
                                              int iterationsPerScale,
                                              int concurrency) {
        log.info("=== RQ2: Decision Performance Benchmark ===");
        log.info("Scales: {}, iterations/scale: {}, concurrency: {}",
            gradientScales.length, iterationsPerScale, concurrency);

        DecisionPerformanceResult result = new DecisionPerformanceResult();

        for (ScaleConfig scale : gradientScales) {
            log.info("--- Scale: {} ---", scale.label());
            ScaleResult scaleResult = new ScaleResult();
            scaleResult.scale = scale;

            cleanupBenchmarkData();
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            scaleResult.singleThreadAstral = benchmarkAstralSingleThread(dataset, iterationsPerScale);

            boolean skipCasbin = scale.getCardCount() >= 50000;
            if (skipCasbin) {
                log.info("  Skipping Casbin/CasbinCached for cardCount={} (O(n) policy scan infeasible)", scale.getCardCount());
            } else {
                casbinAdapter.initialize(dataset);
                scaleResult.singleThreadCasbin = benchmarkCasbinSingleThread(dataset, iterationsPerScale);

                casbinCachedAdapter.initialize(dataset);
                scaleResult.singleThreadCasbinCached = benchmarkCasbinCachedSingleThread(dataset, iterationsPerScale);
            }

            scaleResult.singleThreadOpa = benchmarkOpaSingleThread(dataset, iterationsPerScale);

            scaleResult.singleThreadOpaCached = benchmarkOpaCachedSingleThread(dataset, iterationsPerScale);

            scaleResult.concurrentAstral = benchmarkAstralConcurrent(dataset, iterationsPerScale, concurrency);

            if (!skipCasbin) {
                scaleResult.concurrentCasbin = benchmarkCasbinConcurrent(dataset, iterationsPerScale, concurrency);
            }

            scaleResult.concurrentOpa = benchmarkOpaConcurrent(dataset, iterationsPerScale, concurrency);

            dataGenerator.flushAllCaches();
            scaleResult.coldStartAstral = benchmarkAstralColdStart(dataset, iterationsPerScale, concurrency);

            result.scaleResults.add(scaleResult);
        }

        result.complexityResults = benchmarkRuleComplexity(iterationsPerScale);

        log.info("=== RQ2 Complete ===");
        return result;
    }

    private void cleanupBenchmarkData() {
        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
    }

    private LatencyRecorder.LatencySnapshot benchmarkAstralSingleThread(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        log.info("  AstralLight single-thread benchmark: {} iterations", iterations);

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            PolicyContext ctx = PolicyContext.builder()
                .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                .domainId(1L).templateId(1L)
                .resource(req.resourceType).action(req.actionCode)
                .targetId(req.resourceId).build();
            policyEngine.evaluate(ctx);
        }

        for (int i = 0; i < iterations; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            PolicyContext ctx = PolicyContext.builder()
                .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                .domainId(1L).templateId(1L)
                .resource(req.resourceType).action(req.actionCode)
                .targetId(req.resourceId).build();
            long start = recorder.start();
            policyEngine.evaluate(ctx);
            recorder.stop(start);
        }

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        log.info("  AstralLight single-thread: mean={}us, p95={}us, p99={}us, tps={}",
            String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()));
        return snapshot;
    }

    private LatencyRecorder.LatencySnapshot benchmarkCasbinSingleThread(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        log.info("  Casbin single-thread benchmark: {} iterations", iterations);
        LatencyRecorder.LatencySnapshot snapshot = casbinAdapter.benchmarkEval(dataset, iterations);
        log.info("  Casbin single-thread: mean={}us, p95={}us, p99={}us, tps={}",
            String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()));
        return snapshot;
    }

    private LatencyRecorder.LatencySnapshot benchmarkCasbinCachedSingleThread(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        log.info("  CasbinCached single-thread benchmark: {} iterations", iterations);
        LatencyRecorder.LatencySnapshot snapshot = casbinCachedAdapter.benchmarkEval(dataset, iterations);
        log.info("  CasbinCached single-thread: mean={}us, p95={}us, p99={}us, tps={}",
            String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()));
        return snapshot;
    }

    private LatencyRecorder.LatencySnapshot benchmarkOpaSingleThread(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        log.info("  OPA single-thread benchmark: {} iterations", iterations);
        try {
            opaAdapter.initialize(dataset);
            LatencyRecorder.LatencySnapshot snapshot = opaAdapter.benchmarkEval(dataset, iterations);
            log.info("  OPA single-thread: mean={}us, p95={}us, p99={}us, tps={}, errors={}",
                String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
                String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()),
                snapshot.errorOps());
            return snapshot;
        } catch (Exception e) {
            log.warn("OPA single-thread benchmark skipped: {}", e.getMessage());
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }
    }

    private LatencyRecorder.LatencySnapshot benchmarkOpaCachedSingleThread(
            DataGenerator.GeneratedDataSet dataset, int iterations) {
        log.info("  OPA Cached single-thread benchmark: {} iterations", iterations);
        try {
            opaNoCacheAdapter.initialize(dataset);
            LatencyRecorder.LatencySnapshot snapshot = opaNoCacheAdapter.benchmarkEval(dataset, iterations);
            log.info("  OPA Cached single-thread: mean={}us, p95={}us, p99={}us, tps={}, errors={}",
                String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
                String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()),
                snapshot.errorOps());
            return snapshot;
        } catch (Exception e) {
            log.warn("OPA Cached single-thread benchmark skipped: {}", e.getMessage());
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }
    }

    private LatencyRecorder.LatencySnapshot benchmarkAstralConcurrent(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        log.info("  AstralLight concurrent benchmark: {} iterations, {} threads", iterations, concurrency);

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        AtomicInteger reqIdx = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < concurrency; t++) {
            futures.add(executor.submit(() -> {
                int perThread = iterations / concurrency;
                for (int i = 0; i < perThread; i++) {
                    DataGenerator.EvalRequest req = requests.get(
                        reqIdx.getAndIncrement() % requests.size());
                    setupCardContext(req.cardId);
                    PolicyContext ctx = PolicyContext.builder()
                        .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                        .domainId(1L).templateId(1L)
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId).build();
                    long start = recorder.start();
                    try {
                        policyEngine.evaluate(ctx);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
            }));
        }

        for (Future<?> f : futures) {
            try { f.get(); } catch (Exception e) { log.error("AstralLight concurrent benchmark thread error", e); }
        }
        shutdownExecutor(executor);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        log.info("  AstralLight concurrent: mean={}us, p95={}us, p99={}us, tps={}",
            String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()));
        return snapshot;
    }

    private LatencyRecorder.LatencySnapshot benchmarkCasbinConcurrent(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        log.info("  Casbin concurrent benchmark: {} iterations, {} threads", iterations, concurrency);

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        AtomicInteger reqIdx = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < concurrency; t++) {
            futures.add(executor.submit(() -> {
                int perThread = iterations / concurrency;
                for (int i = 0; i < perThread; i++) {
                    DataGenerator.EvalRequest req = requests.get(
                        reqIdx.getAndIncrement() % requests.size());
                    long start = recorder.start();
                    try {
                        casbinAdapter.enforce(req.cardId, req.resourceType, req.actionCode);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
            }));
        }

        for (Future<?> f : futures) {
            try { f.get(); } catch (Exception e) { log.error("Casbin concurrent benchmark thread error", e); }
        }
        shutdownExecutor(executor);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        log.info("  Casbin concurrent: mean={}us, p95={}us, p99={}us, tps={}",
            String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()));
        return snapshot;
    }

    private LatencyRecorder.LatencySnapshot benchmarkOpaConcurrent(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        log.info("  OPA concurrent benchmark: {} iterations, {} threads", iterations, concurrency);

        if (!opaAdapter.isAvailable()) {
            log.warn("OPA not available, skipping concurrent benchmark");
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }

        try {
            opaAdapter.initialize(dataset);
        } catch (Exception e) {
            log.warn("OPA initialization failed, skipping concurrent benchmark: {}", e.getMessage());
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        AtomicInteger reqIdx = new AtomicInteger(0);

        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < concurrency; t++) {
            futures.add(executor.submit(() -> {
                int perThread = iterations / concurrency;
                for (int i = 0; i < perThread; i++) {
                    DataGenerator.EvalRequest req = requests.get(
                        reqIdx.getAndIncrement() % requests.size());
                    long start = recorder.start();
                    try {
                        opaAdapter.enforce(req.cardId, req.resourceType, req.actionCode);
                        recorder.stop(start);
                    } catch (Exception e) {
                        recorder.recordError(System.nanoTime() - start);
                    }
                }
            }));
        }

        for (Future<?> f : futures) {
            try { f.get(); } catch (Exception e) { log.error("OPA concurrent benchmark thread error", e); }
        }
        shutdownExecutor(executor);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        log.info("  OPA concurrent: mean={}us, p95={}us, p99={}us, tps={}, errors={}",
            String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()),
            snapshot.errorOps());
        return snapshot;
    }

    private LatencyRecorder.LatencySnapshot benchmarkAstralColdStart(
            DataGenerator.GeneratedDataSet dataset, int iterations, int concurrency) {
        log.info("  AstralLight cold-start benchmark (cache flushed): {} iterations, {} threads", iterations, concurrency);

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        List<Future<?>> futures = new ArrayList<>();
        AtomicInteger reqIdx = new AtomicInteger(0);
        for (int t = 0; t < concurrency; t++) {
            futures.add(executor.submit(() -> {
                int perThread = iterations / concurrency;
                for (int i = 0; i < perThread; i++) {
                    DataGenerator.EvalRequest req = requests.get(reqIdx.getAndIncrement() % requests.size());
                    setupCardContext(req.cardId);
                    PolicyContext ctx = PolicyContext.builder()
                        .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                        .domainId(1L).templateId(1L)
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId).build();
                    long start = recorder.start();
                    policyEngine.evaluate(ctx);
                    recorder.stop(start);
                }
            }));
        }
        for (Future<?> f : futures) {
            try { f.get(); } catch (Exception e) { log.error("Benchmark thread error", e); }
        }
        shutdownExecutor(executor);

        LatencyRecorder.LatencySnapshot snapshot = recorder.snapshot();
        log.info("  AstralLight cache-miss: mean={}us, p95={}us, p99={}us, tps={}",
            String.format("%.1f", snapshot.meanUs()), String.format("%.1f", snapshot.p95Us()),
            String.format("%.1f", snapshot.p99Us()), String.format("%.0f", snapshot.tps()));
        return snapshot;
    }

    private List<ComplexityResult> benchmarkRuleComplexity(int iterationsPerPoint) {
        log.info("  Rule complexity sensitivity test");
        ScaleConfig[] complexityGradient = ScaleConfig.ruleComplexityGradient();
        List<ComplexityResult> results = new ArrayList<>();

        for (ScaleConfig scale : complexityGradient) {
            log.info("    Rules per card: {}", scale.getBaseRulesPerCard());

            cleanupBenchmarkData();
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            LatencyRecorder astralRecorder = new LatencyRecorder();
            List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                DataGenerator.EvalRequest req = requests.get(i % requests.size());
                setupCardContext(req.cardId);
                PolicyContext ctx = PolicyContext.builder()
                    .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                    .domainId(1L).templateId(1L)
                    .resource(req.resourceType).action(req.actionCode)
                    .targetId(req.resourceId).build();
                policyEngine.evaluate(ctx);
            }
            for (int i = 0; i < iterationsPerPoint; i++) {
                DataGenerator.EvalRequest req = requests.get(i % requests.size());
                setupCardContext(req.cardId);
                PolicyContext ctx = PolicyContext.builder()
                    .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                    .domainId(1L).templateId(1L)
                    .resource(req.resourceType).action(req.actionCode)
                    .targetId(req.resourceId).build();
                long start = astralRecorder.start();
                policyEngine.evaluate(ctx);
                astralRecorder.stop(start);
            }

            LatencyRecorder.LatencySnapshot casbinSnapshot;
            if (scale.getCardCount() >= 50000 || scale.totalNominalRules() > 500000) {
                log.info("    Skipping Casbin for cardCount={} rules/card={} totalRules={} (O(n) infeasible)",
                    scale.getCardCount(), scale.getBaseRulesPerCard(), scale.totalNominalRules());
                casbinSnapshot = casbinAdapter.benchmarkEval(dataset, 0); // skip
            } else {
                casbinAdapter.initialize(dataset);
                casbinSnapshot = casbinAdapter.benchmarkEval(dataset, iterationsPerPoint);
            }

            LatencyRecorder.LatencySnapshot opaSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
            if (opaAdapter.isAvailable()) {
                opaAdapter.initialize(dataset);
                opaSnapshot = opaAdapter.benchmarkComplexity(dataset, iterationsPerPoint);
            }

            ComplexityResult cr = new ComplexityResult();
            cr.rulesPerCard = scale.getBaseRulesPerCard();
            cr.astralSnapshot = astralRecorder.snapshot();
            cr.casbinSnapshot = casbinSnapshot;
            cr.opaSnapshot = opaSnapshot;
            results.add(cr);

            log.info("    AstralLight: mean={}us, Casbin: mean={}us, OPA: mean={}us",
                cr.astralSnapshot.meanUs(), cr.casbinSnapshot.meanUs(), cr.opaSnapshot.meanUs());
        }

        return results;
    }

    private void shutdownExecutor(ExecutorService executor) {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public static class DecisionPerformanceResult {
        public List<ScaleResult> scaleResults = new ArrayList<>();
        public List<ComplexityResult> complexityResults = new ArrayList<>();
    }

    public static class ScaleResult {
        public ScaleConfig scale;
        public LatencyRecorder.LatencySnapshot singleThreadAstral;
        public LatencyRecorder.LatencySnapshot singleThreadCasbin;
        public LatencyRecorder.LatencySnapshot singleThreadCasbinCached;
        public LatencyRecorder.LatencySnapshot singleThreadOpa;
        public LatencyRecorder.LatencySnapshot singleThreadOpaCached;
        public LatencyRecorder.LatencySnapshot concurrentAstral;
        public LatencyRecorder.LatencySnapshot concurrentCasbin;
        public LatencyRecorder.LatencySnapshot concurrentOpa;
        public LatencyRecorder.LatencySnapshot coldStartAstral;
    }

    public static class ComplexityResult {
        public int rulesPerCard;
        public LatencyRecorder.LatencySnapshot astralSnapshot;
        public LatencyRecorder.LatencySnapshot casbinSnapshot;
        public LatencyRecorder.LatencySnapshot opaSnapshot;
    }
}
