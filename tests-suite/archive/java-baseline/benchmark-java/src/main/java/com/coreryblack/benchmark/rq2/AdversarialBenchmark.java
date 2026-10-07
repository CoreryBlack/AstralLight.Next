package com.coreryblack.benchmark.rq2;

import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.coreryblack.benchmark.util.RedisMemoryMeasurer;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.CardRuleSetRef;
import com.coreryblack.permission.permission.RuleSetService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class AdversarialBenchmark {

    private static final int WARMUP = 1000;
    private static final int ITERATIONS = 5000;

    private final PolicyEngine policyEngine;
    private final RuleSetService ruleSetService;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;

    public AdversarialBenchmark(PolicyEngine policyEngine, RuleSetService ruleSetService,
                                DataGenerator dataGenerator, StringRedisTemplate redisTemplate,
                                JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.ruleSetService = ruleSetService;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
    }

    public AdversarialResultSet execute() {
        AdversarialResultSet resultSet = new AdversarialResultSet();

        log.info("========================================");
        log.info("=== ADVERSARIAL / WORST-CASE BENCHMARK ===");
        log.info("========================================");

        resultSet.skewResults = testExtremeSkew();
        resultSet.coldStartResults = testCacheColdStart();
        resultSet.evictionResults = testCacheEvictionStress();
        resultSet.writeHeavyResults = testWriteHeavyInterference();

        log.info("=== ADVERSARIAL BENCHMARK COMPLETE ===");
        return resultSet;
    }

    private List<SkewResult> testExtremeSkew() {
        log.info("--- ADVERSARIAL-1: Extreme Skew ---");
        List<SkewResult> results = new ArrayList<>();

        SkewConfig[] configs = {
                new SkewConfig("uniform_deny_20", 0.20, 1.0),
                new SkewConfig("extreme_deny_99.9", 0.999, 1.0),
                new SkewConfig("single_tenant_95%", 0.20, 0.05),
                new SkewConfig("worst_combo", 0.999, 0.05),
        };

        for (SkewConfig cfg : configs) {
            log.info("  Skew scenario: {} (denyRatio={}, tenantConcentration={})",
                    cfg.label, cfg.denyRatio, cfg.tenantConcentration);

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            ScaleConfig scaleConfig = ScaleConfig.builder()
                    .cardCount(10000)
                    .baseRulesPerCard(40)
                    .overlayRulesPerCard(5)
                    .resourceTypes(10)
                    .actionsPerResource(4)
                    .denyRatio(cfg.denyRatio)
                    .build();

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scaleConfig);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            List<DataGenerator.EvalRequest> skewedRequests =
                    generateSkewedRequests(dataset, cfg.tenantConcentration, ITERATIONS + WARMUP);

            policyEngine.resetCacheHitStats();

            for (int i = 0; i < WARMUP; i++) {
                DataGenerator.EvalRequest req = skewedRequests.get(i % skewedRequests.size());
                setupCardContext(req.cardId);
                PolicyContext ctx = PolicyContext.builder()
                        .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                        .domainId(1L).templateId(1L)
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId).build();
                policyEngine.evaluate(ctx);
            }

            LatencyRecorder recorder = new LatencyRecorder();
            AtomicInteger denyCount = new AtomicInteger(0);

            for (int i = 0; i < ITERATIONS; i++) {
                DataGenerator.EvalRequest req = skewedRequests.get(i % skewedRequests.size());
                setupCardContext(req.cardId);
                PolicyContext ctx = PolicyContext.builder()
                        .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                        .domainId(1L).templateId(1L)
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId).build();
                long start = recorder.start();
                var decision = policyEngine.evaluate(ctx);
                recorder.stop(start);
                if (!decision.isAllowed()) denyCount.incrementAndGet();
            }

            Map<String, Object> cacheStats = policyEngine.getCacheHitStats();
            policyEngine.resetCacheHitStats();

            SkewResult result = new SkewResult();
            result.label = cfg.label;
            result.denyRatio = cfg.denyRatio;
            result.tenantConcentration = cfg.tenantConcentration;
            result.latencySnapshot = recorder.snapshot();
            result.actualDenyRate = (double) denyCount.get() / ITERATIONS;
            result.l1HitRate = toDouble(cacheStats.getOrDefault("l1HitRate", 0.0));
            result.l2HitRate = toDouble(cacheStats.getOrDefault("l2HitRate", 0.0));
            result.l3HitRate = toDouble(cacheStats.getOrDefault("l3HitRate", 0.0));
            results.add(result);

            log.info("    {} => mean={}us, p99={}us, actualDeny={}%, L1={}%",
                    cfg.label,
                    String.format("%.1f", result.latencySnapshot.meanUs()),
                    String.format("%.1f", result.latencySnapshot.p99Us()),
                    String.format("%.1f", result.actualDenyRate * 100),
                    String.format("%.1f", result.l1HitRate * 100));
        }

        return results;
    }

    private List<ColdStartResult> testCacheColdStart() {
        log.info("--- ADVERSARIAL-2: Cache Cold Start / Eviction Stress ---");
        List<ColdStartResult> results = new ArrayList<>();

        log.info("  Phase 0: JVM warmup ({} iterations) to eliminate JIT bias...", WARMUP);
        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        ScaleConfig warmupScale = ScaleConfig.builder()
                .cardCount(1000).baseRulesPerCard(10).overlayRulesPerCard(2)
                .resourceTypes(5).actionsPerResource(2).denyRatio(0.2).build();
        DataGenerator.GeneratedDataSet warmupDs = dataGenerator.generate(warmupScale);
        dataGenerator.persistToDatabase(warmupDs);
        dataGenerator.populateRedisCache(warmupDs);
        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = warmupDs.evalRequests.get(i % warmupDs.evalRequests.size());
            setupCardContext(req.cardId);
            PolicyContext ctx = PolicyContext.builder()
                    .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                    .domainId(1L).templateId(1L)
                    .resource(req.resourceType).action(req.actionCode)
                    .targetId(req.resourceId).build();
            policyEngine.evaluate(ctx);
        }
        log.info("  JVM warmup complete.");

        ColdStartConfig[] configs = {
                new ColdStartConfig("warm_cache", false, false),
                new ColdStartConfig("cold_start", true, false),
                new ColdStartConfig("partial_eviction_50%", false, true),
        };

        for (ColdStartConfig cfg : configs) {
            log.info("  Cache scenario: {} (flushAll={}, evictHalf={})",
                    cfg.label, cfg.flushAll, cfg.evictHalf);

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            ScaleConfig scaleConfig = ScaleConfig.builder()
                    .cardCount(10000)
                    .baseRulesPerCard(40)
                    .overlayRulesPerCard(5)
                    .resourceTypes(10)
                    .actionsPerResource(4)
                    .denyRatio(0.2)
                    .build();

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scaleConfig);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            policyEngine.resetCacheHitStats();

            for (int i = 0; i < WARMUP; i++) {
                DataGenerator.EvalRequest req = dataset.evalRequests.get(i % dataset.evalRequests.size());
                setupCardContext(req.cardId);
                PolicyContext ctx = PolicyContext.builder()
                        .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                        .domainId(1L).templateId(1L)
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId).build();
                policyEngine.evaluate(ctx);
            }

            if (cfg.flushAll) {
                BenchmarkCleanupUtil.cleanupRedis(redisTemplate);
                log.info("    Flushed dedicated benchmark Redis DB (cold start) -- after warmup, before measurement");
            } else if (cfg.evictHalf) {
                evictHalfOfCardKeys();
                log.info("    Evicted 50% of per-card Redis keys -- after warmup, before measurement");
            }

            policyEngine.resetCacheHitStats();

            LatencyRecorder recorder = new LatencyRecorder();
            long totalEvalBefore = getTotalEvalCount();

            for (int i = 0; i < ITERATIONS; i++) {
                DataGenerator.EvalRequest req = dataset.evalRequests.get(i % dataset.evalRequests.size());
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

            long dbFallbackEstimate = getTotalEvalCount() - totalEvalBefore - ITERATIONS;

            Map<String, Object> cacheStats = policyEngine.getCacheHitStats();

            ColdStartResult result = new ColdStartResult();
            result.label = cfg.label;
            result.flushAll = cfg.flushAll;
            result.evictHalf = cfg.evictHalf;
            result.latencySnapshot = recorder.snapshot();
            result.l1HitRate = toDouble(cacheStats.getOrDefault("l1HitRate", 0.0));
            result.l2HitRate = toDouble(cacheStats.getOrDefault("l2HitRate", 0.0));
            result.l3HitRate = toDouble(cacheStats.getOrDefault("l3HitRate", 0.0));
            results.add(result);

            log.info("    {} => mean={}us, p99={}us, L1={}%, L2={}%",
                    cfg.label,
                    String.format("%.1f", result.latencySnapshot.meanUs()),
                    String.format("%.1f", result.latencySnapshot.p99Us()),
                    String.format("%.1f", result.l1HitRate * 100),
                    String.format("%.1f", result.l2HitRate * 100));
        }

        return results;
    }

    private List<EvictionResult> testCacheEvictionStress() {
        log.info("--- ADVERSARIAL-3: Cache Eviction at Scale ---");
        List<EvictionResult> results = new ArrayList<>();

        int[] cardCounts = {10000, 50000, 100000};

        for (int cardCount : cardCounts) {
            log.info("  Eviction stress: {} cards", cardCount);

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            ScaleConfig scaleConfig = ScaleConfig.builder()
                    .cardCount(cardCount)
                    .baseRulesPerCard(40)
                    .overlayRulesPerCard(5)
                    .resourceTypes(10)
                    .actionsPerResource(4)
                    .denyRatio(0.2)
                    .build();

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scaleConfig);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            RedisMemoryMeasurer.MemorySnapshot memBefore = new RedisMemoryMeasurer(redisTemplate).measure();

            policyEngine.resetCacheHitStats();

            for (int i = 0; i < WARMUP; i++) {
                DataGenerator.EvalRequest req = dataset.evalRequests.get(i % dataset.evalRequests.size());
                setupCardContext(req.cardId);
                PolicyContext ctx = PolicyContext.builder()
                        .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                        .domainId(1L).templateId(1L)
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId).build();
                policyEngine.evaluate(ctx);
            }

            LatencyRecorder recorder = new LatencyRecorder();
            for (int i = 0; i < ITERATIONS; i++) {
                DataGenerator.EvalRequest req = dataset.evalRequests.get(i % dataset.evalRequests.size());
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

            RedisMemoryMeasurer.MemorySnapshot memAfter = new RedisMemoryMeasurer(redisTemplate).measure();
            Map<String, Object> cacheStats = policyEngine.getCacheHitStats();

            EvictionResult result = new EvictionResult();
            result.cardCount = cardCount;
            result.redisUsedMemoryMb = memAfter.usedMemoryMb();
            result.redisKeyCount = memAfter.dbKeyCount;
            result.redisPeakMemoryMb = memAfter.peakMemoryBytes / (1024.0 * 1024.0);
            result.latencySnapshot = recorder.snapshot();
            result.l1HitRate = toDouble(cacheStats.getOrDefault("l1HitRate", 0.0));
            result.l2HitRate = toDouble(cacheStats.getOrDefault("l2HitRate", 0.0));
            result.l3HitRate = toDouble(cacheStats.getOrDefault("l3HitRate", 0.0));
            results.add(result);

            log.info("    {} cards => mean={}us, p99={}us, redisMem={}MB, keys={}, L1={}%",
                    cardCount,
                    String.format("%.1f", result.latencySnapshot.meanUs()),
                    String.format("%.1f", result.latencySnapshot.p99Us()),
                    String.format("%.2f", result.redisUsedMemoryMb),
                    result.redisKeyCount,
                    String.format("%.1f", result.l1HitRate * 100));
        }

        return results;
    }

    private List<WriteHeavyResult> testWriteHeavyInterference() {
        log.info("--- ADVERSARIAL-4: Write-Heavy Interference ---");
        List<WriteHeavyResult> results = new ArrayList<>();

        int[] writeTpsLevels = {0, 10, 50, 100};

        for (int writeTps : writeTpsLevels) {
            log.info("  Write-heavy: writeTps={}", writeTps);

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            ScaleConfig scaleConfig = ScaleConfig.builder()
                    .cardCount(1000)
                    .baseRulesPerCard(40)
                    .overlayRulesPerCard(5)
                    .resourceTypes(10)
                    .actionsPerResource(4)
                    .denyRatio(0.2)
                    .build();

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scaleConfig);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            Long ruleSetId = dataset.baseRuleSet.getRuleSetId();
            List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

            LatencyRecorder authRecorder = new LatencyRecorder();
            LatencyRecorder writeRecorder = new LatencyRecorder();
            AtomicLong authOps = new AtomicLong(0);
            AtomicLong writeOps = new AtomicLong(0);
            AtomicInteger authErrors = new AtomicInteger(0);

            int durationSeconds = 30;
            int authThreads = 8;
            int writeThreads = writeTps > 0 ? 2 : 0;

            ExecutorService executor = Executors.newFixedThreadPool(authThreads + Math.max(writeThreads, 1));
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(authThreads + writeThreads);
            AtomicLong reqIdx = new AtomicLong(0);
            AtomicLong ruleIdx = new AtomicLong(0);

            for (int t = 0; t < authThreads; t++) {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        long deadline = System.currentTimeMillis() + durationSeconds * 1000L;
                        while (System.currentTimeMillis() < deadline) {
                            DataGenerator.EvalRequest req = requests.get(
                                    (int) (reqIdx.getAndIncrement() % requests.size()));
                            setupCardContext(req.cardId);
                            PolicyContext ctx = PolicyContext.builder()
                                    .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                                    .domainId(1L).templateId(1L)
                                    .resource(req.resourceType).action(req.actionCode)
                                    .targetId(req.resourceId).build();
                            long start = authRecorder.start();
                            try {
                                policyEngine.evaluate(ctx);
                            } catch (Exception e) {
                                authErrors.incrementAndGet();
                            }
                            authRecorder.stop(start);
                            authOps.incrementAndGet();
                        }
                    } catch (InterruptedException ignored) {
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            if (writeTps > 0) {
                long sleepMs = Math.max(1, 1000L / writeTps);
                for (int t = 0; t < writeThreads; t++) {
                    executor.submit(() -> {
                        try {
                            startLatch.await();
                            long deadline = System.currentTimeMillis() + durationSeconds * 1000L;
                            while (System.currentTimeMillis() < deadline) {
                                int idx = (int) ruleIdx.getAndIncrement();
                                String resourceType = "learn_subject";
                                String actionCode = idx % 2 == 0 ? "read" : "create";
                                String resourceKey = resourceType + ":*";
                                long start = writeRecorder.start();
                                try {
                                    ruleSetService.rebuildSnapshot(ruleSetId,
                                            resourceKey, actionCode, null, true);
                                } catch (Exception ignored) {
                                }
                                writeRecorder.stop(start);
                                writeOps.incrementAndGet();
                                Thread.sleep(sleepMs);
                            }
                        } catch (InterruptedException ignored) {
                        } finally {
                            doneLatch.countDown();
                        }
                    });
                }
            } else {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        Thread.sleep(durationSeconds * 1000L);
                    } catch (InterruptedException ignored) {
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            try {
                startLatch.countDown();
                doneLatch.await(durationSeconds + 30, TimeUnit.SECONDS);
                executor.shutdownNow();
            } catch (InterruptedException ignored) {
            }

            WriteHeavyResult result = new WriteHeavyResult();
            result.writeTps = writeTps;
            result.authLatency = authRecorder.snapshot();
            result.writeLatency = writeRecorder.snapshot();
            result.authOps = authOps.get();
            result.writeOps = writeOps.get();
            result.authErrors = authErrors.get();
            result.effectiveAuthQps = authOps.get() / (double) durationSeconds;
            results.add(result);

            log.info("    writeTps={} => authMean={}us, authP99={}us, authQps={}, writeOps={}, errors={}",
                    writeTps,
                    String.format("%.1f", result.authLatency.meanUs()),
                    String.format("%.1f", result.authLatency.p99Us()),
                    String.format("%.0f", result.effectiveAuthQps),
                    result.writeOps,
                    result.authErrors);
        }

        return results;
    }

    private List<DataGenerator.EvalRequest> generateSkewedRequests(
            DataGenerator.GeneratedDataSet dataset, double tenantConcentration, int count) {
        List<DataGenerator.EvalRequest> requests = new ArrayList<>();
        Random rng = new Random(42);
        long hotCardId = 1;

        for (int i = 0; i < count; i++) {
            DataGenerator.EvalRequest req = new DataGenerator.EvalRequest();
            if (rng.nextDouble() < tenantConcentration) {
                req.cardId = hotCardId;
            } else {
                req.cardId = (long) (rng.nextInt(dataset.evalRequests.size()) + 1);
            }
            DataGenerator.EvalRequest template = dataset.evalRequests.get(
                    rng.nextInt(dataset.evalRequests.size()));
            req.resourceType = template.resourceType;
            req.actionCode = template.actionCode;
            req.resourceId = template.resourceId;
            requests.add(req);
        }
        return requests;
    }

    private void evictHalfOfCardKeys() {
        Set<String> allKeys = new HashSet<>();
        try (Cursor<String> cursor = redisTemplate.scan(
                ScanOptions.scanOptions().match("perm:refs:*").count(200).build())) {
            while (cursor.hasNext()) {
                allKeys.add(cursor.next());
            }
        }
        try (Cursor<String> cursor = redisTemplate.scan(
                ScanOptions.scanOptions().match("perm:card:status:*").count(200).build())) {
            while (cursor.hasNext()) {
                allKeys.add(cursor.next());
            }
        }
        List<String> keyList = new ArrayList<>(allKeys);
        Collections.shuffle(keyList, new Random(42));
        int evictCount = keyList.size() / 2;
        if (evictCount > 0) {
            redisTemplate.delete(keyList.subList(0, evictCount));
        }
    }

    private long getTotalEvalCount() {
        Map<String, Object> stats = policyEngine.getCacheHitStats();
        Object val = stats.getOrDefault("totalEvaluations", 0L);
        return val instanceof Number ? ((Number) val).longValue() : 0L;
    }

    private static final long BENCHMARK_TENANT_ID = 1L;

    private static double toDouble(Object val) {
        if (val instanceof Number) return ((Number) val).doubleValue();
        return 0.0;
    }

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

    private void clearCardContext() {
        CardContextHolder.clear();
    }

    @Data
    public static class AdversarialResultSet {
        public List<SkewResult> skewResults;
        public List<ColdStartResult> coldStartResults;
        public List<EvictionResult> evictionResults;
        public List<WriteHeavyResult> writeHeavyResults;
    }

    @Data
    public static class SkewResult {
        public String label;
        public double denyRatio;
        public double tenantConcentration;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public double actualDenyRate;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
    }

    @Data
    public static class ColdStartResult {
        public String label;
        public boolean flushAll;
        public boolean evictHalf;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
    }

    @Data
    public static class EvictionResult {
        public int cardCount;
        public double redisUsedMemoryMb;
        public long redisKeyCount;
        public double redisPeakMemoryMb;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public double l1HitRate;
        public double l2HitRate;
        public double l3HitRate;
    }

    @Data
    public static class WriteHeavyResult {
        public int writeTps;
        public LatencyRecorder.LatencySnapshot authLatency;
        public LatencyRecorder.LatencySnapshot writeLatency;
        public long authOps;
        public long writeOps;
        public int authErrors;
        public double effectiveAuthQps;
    }

    private static class SkewConfig {
        final String label;
        final double denyRatio;
        final double tenantConcentration;

        SkewConfig(String label, double denyRatio, double tenantConcentration) {
            this.label = label;
            this.denyRatio = denyRatio;
            this.tenantConcentration = tenantConcentration;
        }
    }

    private static class ColdStartConfig {
        final String label;
        final boolean flushAll;
        final boolean evictHalf;

        ColdStartConfig(String label, boolean flushAll, boolean evictHalf) {
            this.label = label;
            this.flushAll = flushAll;
            this.evictHalf = evictHalf;
        }
    }
}
