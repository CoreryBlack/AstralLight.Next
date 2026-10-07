package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.benchmark.nativebenchmark.NativeScaleConfig;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class NativeOptimisticLockBenchmark extends AbstractNativeBenchmark {

    public NativeOptimisticLockBenchmark(NativeDataGenerator nativeDataGenerator,
                                           StringRedisTemplate redisTemplate,
                                           JdbcTemplate jdbcTemplate) {
        super(null, nativeDataGenerator, redisTemplate, jdbcTemplate);
    }

    public List<NativeLockResult> execute(NativeScaleConfig config, int[] threadCounts, int iterationsPerThread) {
        List<NativeLockResult> results = new ArrayList<>();

        for (int threadCount : threadCounts) {
            log.info("Native optimistic lock benchmark: {} threads, {} iterations each", threadCount, iterationsPerThread);

            cleanupBenchmarkData();
            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            nativeDataGenerator.persistToDatabase(dataset);

            Long ruleSetId = dataset.ruleSets.get(0).getRuleSetId();

            Long snapshotId = jdbcTemplate.queryForObject(
                "SELECT snapshot_id FROM rule_set_snapshot WHERE rule_set_id = ? LIMIT 1",
                Long.class, ruleSetId);
            if (snapshotId == null) {
                log.warn("No snapshot row found for rule_set_id={}, skipping", ruleSetId);
                continue;
            }
            jdbcTemplate.update("UPDATE rule_set_snapshot SET version_no = 0 WHERE snapshot_id = ?", snapshotId);

            int versionChainDepth = measureVersionChainDepth(snapshotId);

            CyclicBarrier barrier = new CyclicBarrier(threadCount);
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            LatencyRecorder recorder = new LatencyRecorder();
            AtomicInteger retries = new AtomicInteger(0);
            AtomicInteger successes = new AtomicInteger(0);
            AtomicInteger failures = new AtomicInteger(0);
            final Long finalSnapshotId = snapshotId;

            List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < threadCount; t++) {
                futures.add(executor.submit(() -> {
                    try {
                        barrier.await(10, TimeUnit.SECONDS);
                    } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }

                    for (int i = 0; i < iterationsPerThread; i++) {
                        long start = recorder.start();
                        int localRetries = 0;
                        boolean success = false;
                        while (localRetries < 100 && !success) {
                            try {
                                Long currentVersion = jdbcTemplate.queryForObject(
                                    "SELECT version_no FROM rule_set_snapshot WHERE snapshot_id = ?",
                                    Long.class, finalSnapshotId);
                                if (currentVersion == null) {
                                    failures.incrementAndGet();
                                    break;
                                }
                                int updated = jdbcTemplate.update(
                                    "UPDATE rule_set_snapshot SET version_no = version_no + 1 " +
                                    "WHERE snapshot_id = ? AND version_no = ?",
                                    finalSnapshotId, currentVersion);
                                if (updated > 0) {
                                    success = true;
                                } else {
                                    localRetries++;
                                }
                            } catch (Exception e) {
                                failures.incrementAndGet();
                                break;
                            }
                        }
                        if (success) {
                            successes.incrementAndGet();
                        } else {
                            failures.incrementAndGet();
                        }
                        retries.addAndGet(localRetries);
                        recorder.stop(start);
                    }
                }));
            }

            for (Future<?> f : futures) {
                try { f.get(60, TimeUnit.SECONDS); } catch (Exception e) { log.trace("future get exception: {}", e.getMessage()); }
            }
            executor.shutdownNow();

            int finalVersionChainDepth = measureVersionChainDepth(snapshotId);

            NativeLockResult result = new NativeLockResult();
            result.threadCount = threadCount;
            result.totalOps = threadCount * iterationsPerThread;
            result.successCount = successes.get();
            result.retryCount = retries.get();
            result.failureCount = failures.get();
            result.p50Us = recorder.snapshot().p50Us();
            result.p99Us = recorder.snapshot().p99Us();
            result.meanUs = recorder.snapshot().meanUs();
            result.versionChainDepth = finalVersionChainDepth;
            result.initialVersionChainDepth = versionChainDepth;
            result.conflictRate = result.totalOps > 0
                ? (double) result.retryCount / result.totalOps : 0.0;
            results.add(result);

            log.info("  success={} retries={} failures={} p99={}us versionChainDepth={}->{} conflictRate={}",
                successes.get(), retries.get(), failures.get(),
                String.format("%.1f", result.p99Us),
                versionChainDepth, finalVersionChainDepth,
                String.format("%.4f", result.conflictRate));
        }

        runMultiTemplateVersionChainTest(config, results);

        return results;
    }

    private int measureVersionChainDepth(Long snapshotId) {
        try {
            Long version = jdbcTemplate.queryForObject(
                "SELECT version_no FROM rule_set_snapshot WHERE snapshot_id = ?",
                Long.class, snapshotId);
            return version != null ? version.intValue() : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    private void runMultiTemplateVersionChainTest(NativeScaleConfig config, List<NativeLockResult> results) {
        log.info("--- Native Optimistic Lock: Multi-Template Version Chain Test ---");

        int[] templateCounts = {1, 3, 5, 8};
        int threadsPerTemplate = 4;
        int iterations = 50;

        for (int templateCount : templateCounts) {
            cleanupBenchmarkData();

            NativeScaleConfig multiConfig = NativeScaleConfig.builder()
                .cardCount(templateCount * 100)
                .baseRulesPerCard(config.getBaseRulesPerCard())
                .overlayRulesPerCard(config.getOverlayRulesPerCard())
                .resourceTypes(config.getResourceTypes())
                .actionsPerResource(config.getActionsPerResource())
                .denyRatio(config.getDenyRatio())
                .build();

            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(multiConfig);
            nativeDataGenerator.persistToDatabase(dataset);

            List<Long> snapshotIds = jdbcTemplate.queryForList(
                "SELECT snapshot_id FROM rule_set_snapshot WHERE rule_set_id IN " +
                "(SELECT rule_set_id FROM rule_set WHERE source_type = 'TEMPLATE') LIMIT ?",
                Long.class, templateCount);

            if (snapshotIds.isEmpty()) {
                continue;
            }

            for (Long sid : snapshotIds) {
                jdbcTemplate.update("UPDATE rule_set_snapshot SET version_no = 0 WHERE snapshot_id = ?", sid);
            }

            int totalThreads = threadsPerTemplate * snapshotIds.size();
            CyclicBarrier barrier = new CyclicBarrier(totalThreads);
            ExecutorService executor = Executors.newFixedThreadPool(totalThreads);
            LatencyRecorder recorder = new LatencyRecorder();
            AtomicInteger retries = new AtomicInteger(0);
            AtomicInteger successes = new AtomicInteger(0);
            AtomicInteger failures = new AtomicInteger(0);

            List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < totalThreads; t++) {
                Long targetSnapshotId = snapshotIds.get(t % snapshotIds.size());
                futures.add(executor.submit(() -> {
                    try {
                        barrier.await(10, TimeUnit.SECONDS);
                    } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }

                    for (int i = 0; i < iterations; i++) {
                        long start = recorder.start();
                        int localRetries = 0;
                        boolean success = false;
                        while (localRetries < 100 && !success) {
                            try {
                                Long currentVersion = jdbcTemplate.queryForObject(
                                    "SELECT version_no FROM rule_set_snapshot WHERE snapshot_id = ?",
                                    Long.class, targetSnapshotId);
                                if (currentVersion == null) {
                                    failures.incrementAndGet();
                                    break;
                                }
                                int updated = jdbcTemplate.update(
                                    "UPDATE rule_set_snapshot SET version_no = version_no + 1 " +
                                    "WHERE snapshot_id = ? AND version_no = ?",
                                    targetSnapshotId, currentVersion);
                                if (updated > 0) {
                                    success = true;
                                } else {
                                    localRetries++;
                                }
                            } catch (Exception e) {
                                failures.incrementAndGet();
                                break;
                            }
                        }
                        if (success) {
                            successes.incrementAndGet();
                        } else {
                            failures.incrementAndGet();
                        }
                        retries.addAndGet(localRetries);
                        recorder.stop(start);
                    }
                }));
            }

            for (Future<?> f : futures) {
                try { f.get(60, TimeUnit.SECONDS); } catch (Exception e) { log.trace("future get exception: {}", e.getMessage()); }
            }
            executor.shutdownNow();

            int maxChainDepth = 0;
            for (Long sid : snapshotIds) {
                int depth = measureVersionChainDepth(sid);
                maxChainDepth = Math.max(maxChainDepth, depth);
            }

            NativeLockResult result = new NativeLockResult();
            result.threadCount = totalThreads;
            result.totalOps = totalThreads * iterations;
            result.successCount = successes.get();
            result.retryCount = retries.get();
            result.failureCount = failures.get();
            result.p50Us = recorder.snapshot().p50Us();
            result.p99Us = recorder.snapshot().p99Us();
            result.meanUs = recorder.snapshot().meanUs();
            result.versionChainDepth = maxChainDepth;
            result.initialVersionChainDepth = 0;
            result.conflictRate = result.totalOps > 0
                ? (double) result.retryCount / result.totalOps : 0.0;
            results.add(result);

            log.info("  templates={}: success={} retries={} failures={} p99={}us maxChainDepth={} conflictRate={}",
                templateCount, successes.get(), retries.get(), failures.get(),
                String.format("%.1f", result.p99Us),
                maxChainDepth,
                String.format("%.4f", result.conflictRate));
        }
    }

    @Data
    public static class NativeLockResult {
        public int threadCount;
        public int totalOps;
        public int successCount;
        public int retryCount;
        public int failureCount;
        public double p50Us;
        public double p99Us;
        public double meanUs;
        public int versionChainDepth;
        public int initialVersionChainDepth;
        public double conflictRate;
    }
}
