package com.coreryblack.benchmark.rq3;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.RuleSetEntryMapper;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.RuleSetSnapshotMapper;
import com.coreryblack.permission.permission.RuleSetService;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.coreryblack.benchmark.util.RedisMemoryMeasurer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.ScanOptions;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class IncrementalCompileBenchmark {

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

    private final RuleSetService ruleSetService;
    private final RuleSetEntryMapper entryMapper;
    private final RuleSetSnapshotMapper snapshotMapper;
    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final RedisMemoryMeasurer memoryMeasurer;
    private final JdbcTemplate jdbcTemplate;

    public IncrementalCompileBenchmark(RuleSetService ruleSetService,
                                        RuleSetEntryMapper entryMapper,
                                        RuleSetSnapshotMapper snapshotMapper,
                                        PolicyEngine policyEngine,
                                        DataGenerator dataGenerator,
                                        StringRedisTemplate redisTemplate,
                                        JdbcTemplate jdbcTemplate) {
        this.ruleSetService = ruleSetService;
        this.entryMapper = entryMapper;
        this.snapshotMapper = snapshotMapper;
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.memoryMeasurer = new RedisMemoryMeasurer(redisTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    public IncrementalCompileResult execute() {
        log.info("=== RQ3: Incremental Compile Benchmark ===");
        IncrementalCompileResult result = new IncrementalCompileResult();

        result.normalIncremental = benchmarkNormalIncremental();
        result.deleteWinnerDegradation = benchmarkDeleteWinner();
        result.highFrequencyWrite = benchmarkHighFrequencyWrite();
        result.scanVsHdel = benchmarkScanVsHdel();

        log.info("=== RQ3 Complete ===");
        return result;
    }

    private NormalIncrementalResult benchmarkNormalIncremental() {
        log.info("--- RQ3.1: Normal Incremental vs Full Rebuild ---");
        NormalIncrementalResult result = new NormalIncrementalResult();

        int[] ruleCounts = {10, 100, 500};
        for (int ruleCount : ruleCounts) {
            cleanupRq3Data();
            ScaleConfig config = ScaleConfig.builder()
                .cardCount(100).baseRulesPerCard(ruleCount).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).build();

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            long ruleSetId = dataset.baseRuleSet.getRuleSetId();

            LatencyRecorder incrementalAddRecorder = new LatencyRecorder();
            LatencyRecorder fullRebuildRecorder = new LatencyRecorder();

            int testIterations = 50;

            for (int i = 0; i < testIterations; i++) {
                setupCardContext(1L);
                RuleSetEntry newEntry = createTestEntry(ruleSetId, ruleCount + i + 1,
                    "learn_subject", "read", "ALLOW");
                entryMapper.insert(newEntry);
                long start = incrementalAddRecorder.start();
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", newEntry, false);
                incrementalAddRecorder.stop(start);
            }

            for (int i = 0; i < testIterations; i++) {
                setupCardContext(1L);
                long start = fullRebuildRecorder.start();
                ruleSetService.rebuildSnapshot(ruleSetId);
                fullRebuildRecorder.stop(start);
            }

            RuleCountResult rcr = new RuleCountResult();
            rcr.ruleCount = ruleCount;
            rcr.incrementalAddSnapshot = incrementalAddRecorder.snapshot();
            rcr.fullRebuildSnapshot = fullRebuildRecorder.snapshot();
            result.ruleCountResults.add(rcr);

            log.info("  rules={}: incremental_add mean={}us p99={}us | full_rebuild mean={}us p99={}us",
                ruleCount,
                String.format("%.1f", rcr.incrementalAddSnapshot.meanUs()), String.format("%.1f", rcr.incrementalAddSnapshot.p99Us()),
                String.format("%.1f", rcr.fullRebuildSnapshot.meanUs()), String.format("%.1f", rcr.fullRebuildSnapshot.p99Us()));
        }

        return result;
    }

    private DeleteWinnerResult benchmarkDeleteWinner() {
        log.info("--- RQ3.2: Delete Winner Degradation Test ---");
        DeleteWinnerResult result = new DeleteWinnerResult();

        int[] ruleCounts = {100, 500};
        for (int ruleCount : ruleCounts) {
            cleanupRq3Data();
            ScaleConfig config = ScaleConfig.builder()
                .cardCount(10).baseRulesPerCard(ruleCount).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).build();

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            long ruleSetId = dataset.baseRuleSet.getRuleSetId();

            LatencyRecorder deleteNonWinnerRecorder = new LatencyRecorder();
            LatencyRecorder deleteWinnerRecorder = new LatencyRecorder();

            for (int i = 0; i < 20; i++) {
                cleanupRq3Data();
                dataset = dataGenerator.generate(config);
                dataGenerator.persistToDatabase(dataset);
                dataGenerator.populateRedisCache(dataset);
                ruleSetId = dataset.baseRuleSet.getRuleSetId();

                List<RuleSetEntry> entries = dataset.baseEntries;

                RuleSetEntry nonWinner = entries.stream()
                    .filter(e -> "learn_level".equals(e.getResourceType()))
                    .findFirst().orElse(null);

                if (nonWinner != null) {
                    setupCardContext(1L);
                    entryMapper.deleteById(nonWinner.getEntryId());
                    long start = deleteNonWinnerRecorder.start();
                    ruleSetService.rebuildSnapshot(ruleSetId,
                        "learn_level:*", "read", nonWinner, true);
                    deleteNonWinnerRecorder.stop(start);
                }
            }

            for (int i = 0; i < 20; i++) {
                cleanupRq3Data();
                dataset = dataGenerator.generate(config);
                dataGenerator.persistToDatabase(dataset);
                dataGenerator.populateRedisCache(dataset);
                ruleSetId = dataset.baseRuleSet.getRuleSetId();

                List<RuleSetEntry> entries = dataset.baseEntries;

                RuleSetEntry winner = entries.stream()
                    .filter(e -> "learn_subject".equals(e.getResourceType()) && "read".equals(e.getActionCode()))
                    .findFirst().orElse(null);

                if (winner != null) {
                    setupCardContext(1L);
                    entryMapper.deleteById(winner.getEntryId());
                    long start = deleteWinnerRecorder.start();
                    ruleSetService.rebuildSnapshot(ruleSetId,
                        "learn_subject:*", "read", winner, true);
                    deleteWinnerRecorder.stop(start);
                }
            }

            DeleteWinnerPointResult dwp = new DeleteWinnerPointResult();
            dwp.ruleCount = ruleCount;
            dwp.deleteNonWinnerSnapshot = deleteNonWinnerRecorder.snapshot();
            dwp.deleteWinnerSnapshot = deleteWinnerRecorder.snapshot();
            result.points.add(dwp);

            log.info("  rules={}: delete_non_winner p99={}us | delete_winner p99={}us (degradation={}x)",
                ruleCount,
                dwp.deleteNonWinnerSnapshot.p99Us(),
                dwp.deleteWinnerSnapshot.p99Us(),
                dwp.deleteWinnerSnapshot.p99Us() / Math.max(1, dwp.deleteNonWinnerSnapshot.p99Us()));
        }

        return result;
    }

    private HighFrequencyWriteResult benchmarkHighFrequencyWrite() {
        log.info("--- RQ3.3: High-Frequency Write Impact (5000 QPS auth + 50 rule changes/sec) ---");
        HighFrequencyWriteResult result = new HighFrequencyWriteResult();

        cleanupRq3Data();
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(1000).baseRulesPerCard(40).overlayRulesPerCard(5)
            .resourceTypes(10).actionsPerResource(4).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        dataGenerator.persistToDatabase(dataset);
        dataGenerator.populateRedisCache(dataset);

        LatencyRecorder authLatencyRecorder = new LatencyRecorder();
        LatencyRecorder ruleChangeLatencyRecorder = new LatencyRecorder();
        AtomicLong authOps = new AtomicLong(0);
        AtomicLong ruleChangeOps = new AtomicLong(0);
        AtomicInteger authErrors = new AtomicInteger(0);

        int authThreads = 8;
        int ruleChangeThreads = 2;
        int durationSeconds = 30;

        ExecutorService executor = Executors.newFixedThreadPool(authThreads + ruleChangeThreads);
        List<Future<?>> futures = new ArrayList<>();
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(authThreads + ruleChangeThreads);

        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        AtomicInteger reqIdx = new AtomicInteger(0);

        for (int t = 0; t < authThreads; t++) {
            futures.add(executor.submit(() -> {
                try {
                    startLatch.await();
                    long deadline = System.currentTimeMillis() + durationSeconds * 1000L;
                    while (System.currentTimeMillis() < deadline) {
                        DataGenerator.EvalRequest req = requests.get(
                            reqIdx.getAndIncrement() % requests.size());
                        setupCardContext(req.cardId);
                        PolicyContext ctx = PolicyContext.builder()
                            .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                            .domainId(1L).templateId(1L)
                            .resource(req.resourceType).action(req.actionCode)
                            .targetId(req.resourceId).build();
                        long start = authLatencyRecorder.start();
                        try {
                            policyEngine.evaluate(ctx);
                        } catch (Exception e) {
                            authErrors.incrementAndGet();
                        }
                        authLatencyRecorder.stop(start);
                        authOps.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                } finally {
                    doneLatch.countDown();
                }
            }));
        }

        long ruleSetId = dataset.baseRuleSet.getRuleSetId();
        AtomicInteger ruleIdx = new AtomicInteger(0);

        for (int t = 0; t < ruleChangeThreads; t++) {
            futures.add(executor.submit(() -> {
                try {
                    startLatch.await();
                    long deadline = System.currentTimeMillis() + durationSeconds * 1000L;
                    while (System.currentTimeMillis() < deadline) {
                        int idx = ruleIdx.getAndIncrement();
                        String resourceType = "learn_subject";
                        String actionCode = idx % 2 == 0 ? "read" : "create";

                        setupCardContext(1L);
                        RuleSetEntry entry = createTestEntry(ruleSetId, 10000 + idx,
                            resourceType, actionCode, idx % 3 == 0 ? "DENY" : "ALLOW");
                        entryMapper.insert(entry);

                        long start = ruleChangeLatencyRecorder.start();
                        try {
                            ruleSetService.rebuildSnapshot(ruleSetId,
                            resourceType + ":*", actionCode, entry, false);
                        } catch (Exception ignored) {}
                        ruleChangeLatencyRecorder.stop(start);
                        ruleChangeOps.incrementAndGet();

                        try { Thread.sleep(20); } catch (InterruptedException ignored) {}
                    }
                } catch (InterruptedException ignored) {
                } finally {
                    doneLatch.countDown();
                }
            }));
        }

        try {
            startLatch.countDown();
            doneLatch.await(durationSeconds + 10, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {}

        shutdownExecutor(executor);

        result.authLatencySnapshot = authLatencyRecorder.snapshot();
        result.ruleChangeLatencySnapshot = ruleChangeLatencyRecorder.snapshot();
        result.totalAuthOps = authOps.get();
        result.totalRuleChanges = ruleChangeOps.get();
        result.authErrors = authErrors.get();
        result.effectiveAuthQps = (double) authOps.get() / durationSeconds;
        result.effectiveRuleChangeTps = (double) ruleChangeOps.get() / durationSeconds;

        log.info("  Auth: {} ops, QPS={}, mean={}us, p95={}us, p99={}us, errors={}",
            result.totalAuthOps, String.format("%.0f", result.effectiveAuthQps),
            String.format("%.1f", result.authLatencySnapshot.meanUs()),
            String.format("%.1f", result.authLatencySnapshot.p95Us()),
            String.format("%.1f", result.authLatencySnapshot.p99Us()),
            result.authErrors);
        log.info("  Rule changes: {} ops, TPS={}, mean={}us, p95={}us, p99={}us",
            result.totalRuleChanges, String.format("%.0f", result.effectiveRuleChangeTps),
            String.format("%.1f", result.ruleChangeLatencySnapshot.meanUs()),
            String.format("%.1f", result.ruleChangeLatencySnapshot.p95Us()),
            String.format("%.1f", result.ruleChangeLatencySnapshot.p99Us()));

        return result;
    }

    private ScanVsHdelResult benchmarkScanVsHdel() {
        log.info("--- RQ3.4: SCAN vs HDEL Cache Invalidation ---");
        ScanVsHdelResult result = new ScanVsHdelResult();

        long tenantId = 1L;
        long cardId = 1L;
        String hashKey = "perm:card:" + tenantId + ":" + cardId;

        int[] fieldCounts = {10, 50, 100, 500};
        int iterations = 50;

        for (int fieldCount : fieldCounts) {
            LatencyRecorder scanRecorder = new LatencyRecorder();
            LatencyRecorder hdelRecorder = new LatencyRecorder();

            for (int iter = 0; iter < iterations; iter++) {
                for (int f = 0; f < fieldCount; f++) {
                    String field = "snapshot:learn_subject_" + f + ":read";
                    redisTemplate.opsForHash().put(hashKey, field, "ALLOW");
                }

                long start = scanRecorder.start();
                Set<String> scannedKeys = new HashSet<>();
                try (Cursor<String> cursor = redisTemplate.scan(
                        ScanOptions.scanOptions().match("perm:card:" + tenantId + ":*").count(100).build())) {
                    while (cursor.hasNext()) {
                        scannedKeys.add(cursor.next());
                    }
                }
                if (!scannedKeys.isEmpty()) {
                    redisTemplate.delete(scannedKeys);
                }
                scanRecorder.stop(start);

                for (int f = 0; f < fieldCount; f++) {
                    String field = "snapshot:learn_subject_" + f + ":read";
                    redisTemplate.opsForHash().put(hashKey, field, "ALLOW");
                }

                start = hdelRecorder.start();
                Object[] fields = new Object[fieldCount];
                for (int f = 0; f < fieldCount; f++) {
                    fields[f] = "snapshot:learn_subject_" + f + ":read";
                }
                redisTemplate.opsForHash().delete(hashKey, fields);
                hdelRecorder.stop(start);
            }

            FieldCountResult fcr = new FieldCountResult();
            fcr.fieldCount = fieldCount;
            fcr.scanSnapshot = scanRecorder.snapshot();
            fcr.hdelSnapshot = hdelRecorder.snapshot();
            result.fieldCountResults.add(fcr);

            log.info("  fields={}: SCAN p99={}us | HDEL p99={}us (speedup={}x)",
                fieldCount,
                fcr.scanSnapshot.p99Us(), fcr.hdelSnapshot.p99Us(),
                fcr.scanSnapshot.p99Us() / Math.max(1, fcr.hdelSnapshot.p99Us()));
        }

        return result;
    }

    private void cleanupRq3Data() {
        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
    }

    private RuleSetEntry createTestEntry(Long ruleSetId, int priority,
                                          String resourceType, String actionCode, String effect) {
        RuleSetEntry entry = new RuleSetEntry();
        entry.setRuleSetId(ruleSetId);
        entry.setTenantId(1L);
        entry.setResourceType(resourceType);
        entry.setResourceId(null);
        entry.setActionCode(actionCode);
        entry.setEffect(effect);
        entry.setPriority(priority);
        entry.setEnabled(1);
        entry.setCreatedAt(LocalDateTime.now());
        return entry;
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

    public static class IncrementalCompileResult {
        public NormalIncrementalResult normalIncremental;
        public DeleteWinnerResult deleteWinnerDegradation;
        public HighFrequencyWriteResult highFrequencyWrite;
        public ScanVsHdelResult scanVsHdel;
    }

    public static class NormalIncrementalResult {
        public List<RuleCountResult> ruleCountResults = new ArrayList<>();
    }

    public static class RuleCountResult {
        public int ruleCount;
        public LatencyRecorder.LatencySnapshot incrementalAddSnapshot;
        public LatencyRecorder.LatencySnapshot fullRebuildSnapshot;
    }

    public static class DeleteWinnerResult {
        public List<DeleteWinnerPointResult> points = new ArrayList<>();
    }

    public static class DeleteWinnerPointResult {
        public int ruleCount;
        public LatencyRecorder.LatencySnapshot deleteNonWinnerSnapshot;
        public LatencyRecorder.LatencySnapshot deleteWinnerSnapshot;
    }

    public static class HighFrequencyWriteResult {
        public LatencyRecorder.LatencySnapshot authLatencySnapshot;
        public LatencyRecorder.LatencySnapshot ruleChangeLatencySnapshot;
        public long totalAuthOps;
        public long totalRuleChanges;
        public int authErrors;
        public double effectiveAuthQps;
        public double effectiveRuleChangeTps;
    }

    public static class ScanVsHdelResult {
        public List<FieldCountResult> fieldCountResults = new ArrayList<>();
    }

    public static class FieldCountResult {
        public int fieldCount;
        public LatencyRecorder.LatencySnapshot scanSnapshot;
        public LatencyRecorder.LatencySnapshot hdelSnapshot;
    }
}
