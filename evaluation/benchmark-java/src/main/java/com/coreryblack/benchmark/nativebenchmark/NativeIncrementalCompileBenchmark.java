package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.RuleSetEntryMapper;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.RuleSetSnapshotMapper;
import com.coreryblack.permission.permission.RuleSetService;
import com.coreryblack.benchmark.nativebenchmark.NativeScaleConfig;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.coreryblack.benchmark.util.RedisMemoryMeasurer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
public class NativeIncrementalCompileBenchmark extends AbstractNativeBenchmark {

    private final RuleSetService ruleSetService;
    private final RuleSetEntryMapper entryMapper;
    private final RuleSetSnapshotMapper snapshotMapper;
    private final RedisMemoryMeasurer memoryMeasurer;

    /** 当前基准测试的卡片绑定映射，供 setupCardContext 查找 templateId/cardType */
    private Map<Long, NativeDataGenerator.NativeCardBinding> currentBindingMap = Collections.emptyMap();

    public NativeIncrementalCompileBenchmark(RuleSetService ruleSetService,
                                               RuleSetEntryMapper entryMapper,
                                               RuleSetSnapshotMapper snapshotMapper,
                                               PolicyEngine policyEngine,
                                               NativeDataGenerator nativeDataGenerator,
                                               StringRedisTemplate redisTemplate,
                                               JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        this.ruleSetService = ruleSetService;
        this.entryMapper = entryMapper;
        this.snapshotMapper = snapshotMapper;
        this.memoryMeasurer = new RedisMemoryMeasurer(redisTemplate);
    }

    public NativeIncrementalCompileResult execute() {
        log.info("=== Native RQ3: Incremental Compile Benchmark (with ABAC Recompile) ===");
        NativeIncrementalCompileResult result = new NativeIncrementalCompileResult();

        result.normalIncremental = benchmarkNormalIncremental();
        result.deleteWinnerDegradation = benchmarkDeleteWinner();
        result.highFrequencyWrite = benchmarkHighFrequencyWrite();
        result.scanVsHdel = benchmarkScanVsHdel();
        result.abacRecompile = benchmarkAbacRecompile();
        result.permissionRuleRecompile = benchmarkPermissionRuleRecompile();

        log.info("=== Native RQ3 Complete ===");
        return result;
    }

    private NormalIncrementalResult benchmarkNormalIncremental() {
        log.info("--- Native RQ3.1: Normal Incremental vs Full Rebuild ---");
        NormalIncrementalResult result = new NormalIncrementalResult();

        int[] ruleCounts = {10, 100, 500};
        for (int ruleCount : ruleCounts) {
            cleanupRq3Data();
            NativeScaleConfig config = NativeScaleConfig.builder()
                .cardCount(100).baseRulesPerCard(ruleCount).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).build();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);
            currentBindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            long ruleSetId = dataset.ruleSets.get(0).getRuleSetId();

            LatencyRecorder incrementalAddRecorder = new LatencyRecorder();
            LatencyRecorder fullRebuildRecorder = new LatencyRecorder();

            int testIterations = 50;

            // B23 fix: warmup phase - 10 warmup iterations for incremental add
            for (int i = 0; i < 10; i++) {
                setupCardContext(1L, currentBindingMap);
                RuleSetEntry warmupEntry = createTestEntry(ruleSetId, -(i + 1),
                    "learn_subject", "read", "ALLOW");
                entryMapper.insert(warmupEntry);
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", warmupEntry, false);
            }

            for (int i = 0; i < testIterations; i++) {
                setupCardContext(1L, currentBindingMap);
                RuleSetEntry newEntry = createTestEntry(ruleSetId, ruleCount + i + 1,
                    "learn_subject", "read", "ALLOW");
                entryMapper.insert(newEntry);
                long start = incrementalAddRecorder.start();
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", newEntry, false);
                incrementalAddRecorder.stop(start);
            }

            // B23 fix: warmup phase - 10 warmup iterations for full rebuild
            for (int i = 0; i < 10; i++) {
                setupCardContext(1L, currentBindingMap);
                ruleSetService.rebuildSnapshot(ruleSetId);
            }

            for (int i = 0; i < testIterations; i++) {
                setupCardContext(1L, currentBindingMap);
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
                String.format("%.1f", rcr.incrementalAddSnapshot.meanUs()),
                String.format("%.1f", rcr.incrementalAddSnapshot.p99Us()),
                String.format("%.1f", rcr.fullRebuildSnapshot.meanUs()),
                String.format("%.1f", rcr.fullRebuildSnapshot.p99Us()));
        }

        return result;
    }

    private DeleteWinnerResult benchmarkDeleteWinner() {
        log.info("--- Native RQ3.2: Delete Winner Degradation Test ---");
        DeleteWinnerResult result = new DeleteWinnerResult();

        int[] ruleCounts = {100, 500};
        for (int ruleCount : ruleCounts) {
            cleanupRq3Data();
            NativeScaleConfig config = NativeScaleConfig.builder()
                .cardCount(10).baseRulesPerCard(ruleCount).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).build();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);
            currentBindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            long ruleSetId = dataset.ruleSets.get(0).getRuleSetId();

            LatencyRecorder deleteNonWinnerRecorder = new LatencyRecorder();
            LatencyRecorder deleteWinnerRecorder = new LatencyRecorder();

            // B23 fix: warmup phase - 5 warmup iterations for delete non-winner
            for (int w = 0; w < 5; w++) {
                cleanupRq3Data();
                NativeDataGenerator.NativeGeneratedDataSet warmupDataset = nativeDataGenerator.generate(config);
                nativeDataGenerator.persistToDatabase(warmupDataset);
                nativeDataGenerator.populateRedisCache(warmupDataset);
                currentBindingMap = warmupDataset.bindings.stream()
                    .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));
                long warmupRuleSetId = warmupDataset.ruleSets.get(0).getRuleSetId();
                List<RuleSetEntry> warmupEntries = warmupDataset.entries;
                RuleSetEntry warmupNonWinner = warmupEntries.stream()
                    .filter(e -> "learn_level".equals(e.getResourceType()))
                    .findFirst().orElse(null);
                if (warmupNonWinner != null) {
                    setupCardContext(1L, currentBindingMap);
                    entryMapper.deleteById(warmupNonWinner.getEntryId());
                    ruleSetService.rebuildSnapshot(warmupRuleSetId,
                        "learn_level:*", "read", warmupNonWinner, true);
                }
            }

            for (int i = 0; i < 20; i++) {
                cleanupRq3Data();
                dataset = nativeDataGenerator.generate(config);
                nativeDataGenerator.persistToDatabase(dataset);
                nativeDataGenerator.populateRedisCache(dataset);
                currentBindingMap = dataset.bindings.stream()
                    .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));
                ruleSetId = dataset.ruleSets.get(0).getRuleSetId();

                List<RuleSetEntry> entries = dataset.entries;

                RuleSetEntry nonWinner = entries.stream()
                    .filter(e -> "learn_level".equals(e.getResourceType()))
                    .findFirst().orElse(null);

                if (nonWinner != null) {
                    setupCardContext(1L, currentBindingMap);
                    entryMapper.deleteById(nonWinner.getEntryId());
                    long start = deleteNonWinnerRecorder.start();
                    ruleSetService.rebuildSnapshot(ruleSetId,
                        "learn_level:*", "read", nonWinner, true);
                    deleteNonWinnerRecorder.stop(start);
                }
            }

            // B23 fix: warmup phase - 5 warmup iterations for delete winner
            for (int w = 0; w < 5; w++) {
                cleanupRq3Data();
                NativeDataGenerator.NativeGeneratedDataSet warmupDataset = nativeDataGenerator.generate(config);
                nativeDataGenerator.persistToDatabase(warmupDataset);
                nativeDataGenerator.populateRedisCache(warmupDataset);
                currentBindingMap = warmupDataset.bindings.stream()
                    .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));
                long warmupRuleSetId = warmupDataset.ruleSets.get(0).getRuleSetId();
                List<RuleSetEntry> warmupEntries = warmupDataset.entries;
                RuleSetEntry warmupWinner = warmupEntries.stream()
                    .filter(e -> "learn_subject".equals(e.getResourceType()))
                    .findFirst().orElse(null);
                if (warmupWinner != null) {
                    setupCardContext(1L, currentBindingMap);
                    entryMapper.deleteById(warmupWinner.getEntryId());
                    ruleSetService.rebuildSnapshot(warmupRuleSetId,
                        "learn_subject:*", "read", warmupWinner, true);
                }
            }

            for (int i = 0; i < 20; i++) {
                cleanupRq3Data();
                dataset = nativeDataGenerator.generate(config);
                nativeDataGenerator.persistToDatabase(dataset);
                nativeDataGenerator.populateRedisCache(dataset);
                currentBindingMap = dataset.bindings.stream()
                    .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));
                ruleSetId = dataset.ruleSets.get(0).getRuleSetId();

                List<RuleSetEntry> entries = dataset.entries;

                RuleSetEntry winner = entries.stream()
                    .filter(e -> "learn_subject".equals(e.getResourceType()))
                    .findFirst().orElse(null);

                if (winner != null) {
                    setupCardContext(1L, currentBindingMap);
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
        log.info("--- Native RQ3.3: High-Frequency Write Impact (5000 QPS auth + 50 rule changes/sec) ---");
        HighFrequencyWriteResult result = new HighFrequencyWriteResult();

        cleanupRq3Data();
        NativeScaleConfig config = NativeScaleConfig.builder()
            .cardCount(1000).baseRulesPerCard(40).overlayRulesPerCard(5)
            .resourceTypes(10).actionsPerResource(4).build();

        NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
        nativeDataGenerator.persistToDatabase(dataset);
        nativeDataGenerator.populateRedisCache(dataset);
        currentBindingMap = dataset.bindings.stream()
            .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

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

        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;
        AtomicInteger reqIdx = new AtomicInteger(0);

        // B23 fix: warmup phase - 3 second warmup period
        log.info("  Warmup phase: 3 seconds...");
        long warmupDeadline = System.currentTimeMillis() + 3000L;
        AtomicInteger warmupIdx = new AtomicInteger(0);
        while (System.currentTimeMillis() < warmupDeadline) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(
                warmupIdx.getAndIncrement() % requests.size());
            setupCardContext(req, currentBindingMap);
            PolicyContext warmupCtx = buildPolicyContext(req);
            try {
                policyEngine.evaluate(warmupCtx);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }
        log.info("  Warmup complete");

        for (int t = 0; t < authThreads; t++) {
            futures.add(executor.submit(() -> {
                try {
                    startLatch.await();
                    long deadline = System.currentTimeMillis() + durationSeconds * 1000L;
                    while (System.currentTimeMillis() < deadline) {
                        NativeDataGenerator.NativeEvalRequest req = requests.get(
                            reqIdx.getAndIncrement() % requests.size());
                        setupCardContext(req, currentBindingMap);
                        PolicyContext ctx = buildPolicyContext(req);
                        long start = authLatencyRecorder.start();
                        try {
                            policyEngine.evaluate(ctx);
                            authLatencyRecorder.stop(start);
                        } catch (Exception e) {
                            authErrors.incrementAndGet();
                            // B27 fix: skip recorder.stop() for failed requests
                        }
                        authOps.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    log.debug("interrupted: {}", e.getMessage());
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            }));
        }

        long ruleSetId = dataset.ruleSets.get(0).getRuleSetId();
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

                        setupCardContext(1L, currentBindingMap);
                        RuleSetEntry entry = createTestEntry(ruleSetId, 10000 + idx,
                            resourceType, actionCode, idx % 3 == 0 ? "DENY" : "ALLOW");
                        entryMapper.insert(entry);

                        long start = ruleChangeLatencyRecorder.start();
                        try {
                            ruleSetService.rebuildSnapshot(ruleSetId,
                                resourceType + ":*", actionCode, entry, false);
                            ruleChangeLatencyRecorder.stop(start);
                        } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
                        ruleChangeOps.incrementAndGet();

                        try { Thread.sleep(20); } catch (InterruptedException e) { log.debug("interrupted: {}", e.getMessage()); Thread.currentThread().interrupt(); }
                    }
                } catch (InterruptedException e) {
                    log.debug("interrupted: {}", e.getMessage());
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            }));
        }

        try {
            startLatch.countDown();
            doneLatch.await(durationSeconds + 10, TimeUnit.SECONDS);
        } catch (InterruptedException e) { log.debug("interrupted: {}", e.getMessage()); Thread.currentThread().interrupt(); }

        shutdownExecutor(executor, 10);

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
        log.info("--- Native RQ3.4: SCAN vs HDEL Cache Invalidation ---");
        ScanVsHdelResult result = new ScanVsHdelResult();

        long tenantId = 1L;
        long cardId = 1L;
        String hashKey = "perm:card:" + tenantId + ":" + cardId;

        int[] fieldCounts = {10, 50, 100, 500};
        int iterations = 50;

        for (int fieldCount : fieldCounts) {
            LatencyRecorder scanRecorder = new LatencyRecorder();
            LatencyRecorder hdelRecorder = new LatencyRecorder();

            // B23 fix: warmup phase - 10 warmup iterations for SCAN vs HDEL
            for (int w = 0; w < 10; w++) {
                for (int f = 0; f < fieldCount; f++) {
                    String field = "snapshot:learn_subject_" + f + ":read";
                    redisTemplate.opsForHash().put(hashKey, field, "ALLOW");
                }
                Set<String> warmupKeys = new HashSet<>();
                try (var cursor = redisTemplate.scan(
                        org.springframework.data.redis.core.ScanOptions.scanOptions()
                            .match("perm:card:" + tenantId + ":*").count(100).build())) {
                    while (cursor.hasNext()) {
                        warmupKeys.add(cursor.next());
                    }
                }
                if (!warmupKeys.isEmpty()) {
                    redisTemplate.delete(warmupKeys);
                }
                for (int f = 0; f < fieldCount; f++) {
                    String field = "snapshot:learn_subject_" + f + ":read";
                    redisTemplate.opsForHash().put(hashKey, field, "ALLOW");
                }
                Object[] warmupFields = new Object[fieldCount];
                for (int f = 0; f < fieldCount; f++) {
                    warmupFields[f] = "snapshot:learn_subject_" + f + ":read";
                }
                redisTemplate.opsForHash().delete(hashKey, warmupFields);
            }

            for (int iter = 0; iter < iterations; iter++) {
                for (int f = 0; f < fieldCount; f++) {
                    String field = "snapshot:learn_subject_" + f + ":read";
                    redisTemplate.opsForHash().put(hashKey, field, "ALLOW");
                }

                long start = scanRecorder.start();
                Set<String> scannedKeys = new HashSet<>();
                try (var cursor = redisTemplate.scan(
                        org.springframework.data.redis.core.ScanOptions.scanOptions()
                            .match("perm:card:" + tenantId + ":*").count(100).build())) {
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

    private AbacRecompileResult benchmarkAbacRecompile() {
        log.info("--- Native RQ3.5: ABAC Condition Change Recompile ---");
        AbacRecompileResult result = new AbacRecompileResult();

        cleanupRq3Data();
        NativeScaleConfig config = NativeScaleConfig.builder()
            .cardCount(100).baseRulesPerCard(40).overlayRulesPerCard(5)
            .permissionRulesPerCard(5).abacConditionsPerRule(1)
            .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build();

        NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
        nativeDataGenerator.persistToDatabase(dataset);
        nativeDataGenerator.populateRedisCache(dataset);
        currentBindingMap = dataset.bindings.stream()
            .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

        long ruleSetId = dataset.ruleSets.get(0).getRuleSetId();

        LatencyRecorder abacRecompileRecorder = new LatencyRecorder();
        LatencyRecorder normalRecompileRecorder = new LatencyRecorder();

        int testIterations = 30;

        // B23 fix: warmup phase - 5 warmup iterations for ABAC recompile
        for (int i = 0; i < 5; i++) {
            setupCardContext(1L, currentBindingMap);
            RuleSetEntry warmupEntry = createTestEntry(ruleSetId, -(i + 1),
                "learn_subject", "read", "ALLOW");
            entryMapper.insert(warmupEntry);
            String warmupAbacKey = "perm:abac:" + BENCHMARK_TENANT_ID + ":" + (i % 100 + 1);
            redisTemplate.opsForHash().put(warmupAbacKey, "conditionJson",
                "{\"timeRange\":{\"start\":\"09:00\",\"end\":\"18:00\"}}");
            try {
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", warmupEntry, false);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < testIterations; i++) {
            setupCardContext(1L, currentBindingMap);
            RuleSetEntry abacEntry = createTestEntry(ruleSetId, 500 + i,
                "learn_subject", "read", i % 3 == 0 ? "DENY" : "ALLOW");
            entryMapper.insert(abacEntry);

            String abacKey = "perm:abac:" + BENCHMARK_TENANT_ID + ":" + (i % 100 + 1);
            redisTemplate.opsForHash().put(abacKey, "conditionJson",
                "{\"timeRange\":{\"start\":\"09:00\",\"end\":\"18:00\"}}");

            long start = abacRecompileRecorder.start();
            try {
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", abacEntry, false);
                abacRecompileRecorder.stop(start);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        // B23 fix: warmup phase - 5 warmup iterations for normal recompile
        for (int i = 0; i < 5; i++) {
            setupCardContext(1L, currentBindingMap);
            RuleSetEntry warmupEntry = createTestEntry(ruleSetId, -(i + 100),
                "learn_subject", "read", "ALLOW");
            entryMapper.insert(warmupEntry);
            try {
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", warmupEntry, false);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < testIterations; i++) {
            setupCardContext(1L, currentBindingMap);
            RuleSetEntry normalEntry = createTestEntry(ruleSetId, 1000 + i,
                "learn_subject", "read", "ALLOW");
            entryMapper.insert(normalEntry);

            long start = normalRecompileRecorder.start();
            try {
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", normalEntry, false);
                normalRecompileRecorder.stop(start);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        result.abacRecompileSnapshot = abacRecompileRecorder.snapshot();
        result.normalRecompileSnapshot = normalRecompileRecorder.snapshot();
        result.abacOverheadRatio = abacRecompileRecorder.snapshot().meanUs()
            / Math.max(1, normalRecompileRecorder.snapshot().meanUs());

        log.info("  ABAC recompile: mean={}us, p99={}us | Normal recompile: mean={}us, p99={}us | overhead={}x",
            String.format("%.1f", result.abacRecompileSnapshot.meanUs()),
            String.format("%.1f", result.abacRecompileSnapshot.p99Us()),
            String.format("%.1f", result.normalRecompileSnapshot.meanUs()),
            String.format("%.1f", result.normalRecompileSnapshot.p99Us()),
            String.format("%.2f", result.abacOverheadRatio));

        return result;
    }

    private PermissionRuleRecompileResult benchmarkPermissionRuleRecompile() {
        log.info("--- Native RQ3.6: PERMISSION_RULE Change Recompile ---");
        PermissionRuleRecompileResult result = new PermissionRuleRecompileResult();

        cleanupRq3Data();
        NativeScaleConfig config = NativeScaleConfig.builder()
            .cardCount(100).baseRulesPerCard(40).overlayRulesPerCard(5)
            .permissionRulesPerCard(10)
            .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build();

        NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
        nativeDataGenerator.persistToDatabase(dataset);
        nativeDataGenerator.populateRedisCache(dataset);
        currentBindingMap = dataset.bindings.stream()
            .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

        long ruleSetId = dataset.ruleSets.get(0).getRuleSetId();

        LatencyRecorder permRuleRecompileRecorder = new LatencyRecorder();
        LatencyRecorder ruleSetRecompileRecorder = new LatencyRecorder();

        int testIterations = 30;

        // B23 fix: warmup phase - 5 warmup iterations for permission rule recompile
        for (int i = 0; i < 5; i++) {
            setupCardContext(1L, currentBindingMap);
            try {
                jdbcTemplate.update(
                    "UPDATE permission_rule SET effect = ? WHERE card_id = ? AND resource_type = ? LIMIT 1",
                    "ALLOW", 1L, "learn_subject");
                ruleSetService.rebuildSnapshot(ruleSetId);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < testIterations; i++) {
            setupCardContext(1L, currentBindingMap);
            long start = permRuleRecompileRecorder.start();
            try {
                jdbcTemplate.update(
                    "UPDATE permission_rule SET effect = ? WHERE card_id = ? AND resource_type = ? LIMIT 1",
                    i % 2 == 0 ? "DENY" : "ALLOW", 1L, "learn_subject");
                ruleSetService.rebuildSnapshot(ruleSetId);
                permRuleRecompileRecorder.stop(start);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        // B23 fix: warmup phase - 5 warmup iterations for ruleset recompile
        for (int i = 0; i < 5; i++) {
            setupCardContext(1L, currentBindingMap);
            RuleSetEntry warmupEntry = createTestEntry(ruleSetId, -(i + 200),
                "learn_subject", "read", "ALLOW");
            entryMapper.insert(warmupEntry);
            try {
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", warmupEntry, false);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < testIterations; i++) {
            setupCardContext(1L, currentBindingMap);
            RuleSetEntry entry = createTestEntry(ruleSetId, 2000 + i,
                "learn_subject", "read", "ALLOW");
            entryMapper.insert(entry);

            long start = ruleSetRecompileRecorder.start();
            try {
                ruleSetService.rebuildSnapshot(ruleSetId,
                    "learn_subject:*", "read", entry, false);
                ruleSetRecompileRecorder.stop(start);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        result.permRuleRecompileSnapshot = permRuleRecompileRecorder.snapshot();
        result.ruleSetRecompileSnapshot = ruleSetRecompileRecorder.snapshot();
        result.permRuleOverheadRatio = permRuleRecompileRecorder.snapshot().meanUs()
            / Math.max(1, ruleSetRecompileRecorder.snapshot().meanUs());

        log.info("  PERMISSION_RULE recompile: mean={}us, p99={}us | RuleSet recompile: mean={}us, p99={}us | overhead={}x",
            String.format("%.1f", result.permRuleRecompileSnapshot.meanUs()),
            String.format("%.1f", result.permRuleRecompileSnapshot.p99Us()),
            String.format("%.1f", result.ruleSetRecompileSnapshot.meanUs()),
            String.format("%.1f", result.ruleSetRecompileSnapshot.p99Us()),
            String.format("%.2f", result.permRuleOverheadRatio));

        return result;
    }

    private void cleanupRq3Data() {
        cleanupBenchmarkData();
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

    public static class NativeIncrementalCompileResult {
        public NormalIncrementalResult normalIncremental;
        public DeleteWinnerResult deleteWinnerDegradation;
        public HighFrequencyWriteResult highFrequencyWrite;
        public ScanVsHdelResult scanVsHdel;
        public AbacRecompileResult abacRecompile;
        public PermissionRuleRecompileResult permissionRuleRecompile;
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

    public static class AbacRecompileResult {
        public LatencyRecorder.LatencySnapshot abacRecompileSnapshot;
        public LatencyRecorder.LatencySnapshot normalRecompileSnapshot;
        public double abacOverheadRatio;
    }

    public static class PermissionRuleRecompileResult {
        public LatencyRecorder.LatencySnapshot permRuleRecompileSnapshot;
        public LatencyRecorder.LatencySnapshot ruleSetRecompileSnapshot;
        public double permRuleOverheadRatio;
    }
}
