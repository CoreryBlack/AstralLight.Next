package com.coreryblack.benchmark.rq4;

import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import com.coreryblack.permission.permission.RuleSetService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class OptimisticLockBenchmark {

    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;
    private final RuleSetService ruleSetService;

    public OptimisticLockBenchmark(DataGenerator dataGenerator,
                                    StringRedisTemplate redisTemplate,
                                    JdbcTemplate jdbcTemplate,
                                    RuleSetService ruleSetService) {
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
        this.ruleSetService = ruleSetService;
    }

    public List<LockResult> execute(ScaleConfig config, int[] threadCounts, int iterationsPerThread) {
        List<LockResult> results = new ArrayList<>();

        for (int threadCount : threadCounts) {
            log.info("Optimistic lock benchmark: {} threads, {} iterations each", threadCount, iterationsPerThread);

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
            dataGenerator.persistToDatabase(dataset);

            Long ruleSetId = dataset.baseRuleSet.getRuleSetId();

            Long snapshotId = jdbcTemplate.queryForObject(
                "SELECT snapshot_id FROM rule_set_snapshot WHERE rule_set_id = ? LIMIT 1",
                Long.class, ruleSetId);
            if (snapshotId == null) {
                log.warn("No snapshot row found for rule_set_id={}, skipping", ruleSetId);
                continue;
            }
            jdbcTemplate.update("UPDATE rule_set_snapshot SET version_no = 0 WHERE snapshot_id = ?", snapshotId);

            CyclicBarrier barrier = new CyclicBarrier(threadCount);
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            LatencyRecorder recorder = new LatencyRecorder();
            AtomicInteger retries = new AtomicInteger(0);
            AtomicInteger successes = new AtomicInteger(0);
            AtomicInteger failures = new AtomicInteger(0);
            final Long finalRuleSetId = ruleSetId;

            List<Future<?>> futures = new ArrayList<>();
            for (int t = 0; t < threadCount; t++) {
                final int threadIdx = t;
                futures.add(executor.submit(() -> {
                    try {
                        barrier.await(10, TimeUnit.SECONDS);
                    } catch (Exception ignored) {}

                    for (int i = 0; i < iterationsPerThread; i++) {
                        long start = recorder.start();
                        int localRetries = 0;
                        boolean success = false;
                        // E5 fix: use RuleSetService.addEntry() which triggers
                        // optimistic lock check (version field) and retry logic,
                        // instead of raw JDBC SELECT+UPDATE
                        while (localRetries < 100 && !success) {
                            try {
                                RuleSetEntry entry = new RuleSetEntry();
                                entry.setRuleSetId(finalRuleSetId);
                                entry.setTenantId(1L);
                                entry.setResourceType("lock_res_" + threadIdx + "_" + i);
                                entry.setActionCode("read");
                                entry.setEffect(i % 2 == 0 ? "ALLOW" : "DENY");
                                entry.setPriority(100);
                                entry.setEnabled(1);
                                entry.setCreatedAt(java.time.LocalDateTime.now());
                                ruleSetService.addEntry(entry);
                                success = true;
                            } catch (OptimisticLockingFailureException e) {
                                localRetries++;
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
                try { f.get(60, TimeUnit.SECONDS); } catch (Exception ignored) {}
            }
            executor.shutdownNow();

            LockResult result = new LockResult();
            result.threadCount = threadCount;
            result.totalOps = threadCount * iterationsPerThread;
            result.successCount = successes.get();
            result.retryCount = retries.get();
            result.failureCount = failures.get();
            result.p50Us = recorder.snapshot().p50Us();
            result.p99Us = recorder.snapshot().p99Us();
            result.meanUs = recorder.snapshot().meanUs();
            results.add(result);

            log.info("  success={} retries={} failures={} p99={}us",
                successes.get(), retries.get(), failures.get(),
                String.format("%.1f", result.p99Us));
        }

        return results;
    }

    @Data
    public static class LockResult {
        public int threadCount;
        public int totalOps;
        public int successCount;
        public int retryCount;
        public int failureCount;
        public double p50Us;
        public double p99Us;
        public double meanUs;
    }
}
