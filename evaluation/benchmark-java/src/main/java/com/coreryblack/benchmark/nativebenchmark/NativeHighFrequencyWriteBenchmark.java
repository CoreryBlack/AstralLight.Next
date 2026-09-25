package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.permission.auth.SnapshotConsistencyChecker;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.benchmark.nativebenchmark.NativeScaleConfig;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
public class NativeHighFrequencyWriteBenchmark extends AbstractNativeBenchmark {

    private final SnapshotConsistencyChecker consistencyChecker;

    /** 当前基准测试的卡片绑定映射，供 setupCardContext 查找 templateId/cardType */
    private Map<Long, NativeDataGenerator.NativeCardBinding> currentBindingMap = java.util.Collections.emptyMap();

    public NativeHighFrequencyWriteBenchmark(PolicyEngine policyEngine,
                                               NativeDataGenerator nativeDataGenerator,
                                               StringRedisTemplate redisTemplate,
                                               JdbcTemplate jdbcTemplate,
                                               SnapshotConsistencyChecker consistencyChecker) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        this.consistencyChecker = consistencyChecker;
    }

    public List<NativeWriteResult> execute(NativeScaleConfig config, int[] writeTpsLevels, int durationSeconds) {
        List<NativeWriteResult> results = new ArrayList<>();

        for (int targetTps : writeTpsLevels) {
            log.info("Native high-frequency write benchmark: target={} TPS, duration={}s", targetTps, durationSeconds);

            cleanupBenchmarkData();
            NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
            nativeDataGenerator.persistToDatabase(dataset);
            nativeDataGenerator.populateRedisCache(dataset);
            currentBindingMap = dataset.bindings.stream()
                .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

            consistencyChecker.clearViolations();

            LatencyRecorder authRecorder = new LatencyRecorder();
            LatencyRecorder writeRecorder = new LatencyRecorder();
            LatencyRecorder consistencyCheckRecorder = new LatencyRecorder();
            AtomicInteger authErrors = new AtomicInteger(0);
            AtomicInteger writeErrors = new AtomicInteger(0);
            AtomicInteger writeConflicts = new AtomicInteger(0);
            AtomicLong authCount = new AtomicLong(0);
            AtomicLong writeCount = new AtomicLong(0);
            AtomicLong consistencyCheckCount = new AtomicLong(0);
            AtomicLong consistencyViolationCount = new AtomicLong(0);

            long endTime = System.currentTimeMillis() + durationSeconds * 1000L;

            ScheduledExecutorService writeExecutor = Executors.newSingleThreadScheduledExecutor();
            // Bounded queue prevents OOM from unbounded task submission
            ThreadPoolExecutor authExecutor = new ThreadPoolExecutor(
                    4, 4, 0L, TimeUnit.MILLISECONDS,
                    new LinkedBlockingQueue<>(10000),
                    new ThreadPoolExecutor.CallerRunsPolicy());

            // scheduleAtFixedRate requires period > 0; Math.max(1, ...) prevents
            // IllegalArgumentException when targetTps >= 1000 (e.g. 5000 → 1000/5000 = 0)
            long periodMs = Math.max(1, 1000 / Math.max(targetTps, 1));
            writeExecutor.scheduleAtFixedRate(() -> {
                if (System.currentTimeMillis() > endTime) return;
                long start = writeRecorder.start();
                try {
                    jdbcTemplate.update(
                        "UPDATE rule_set SET updated_at = NOW() WHERE rule_set_id = ?",
                        dataset.ruleSets.get(0).getRuleSetId());
                    writeCount.incrementAndGet();
                } catch (Exception e) {
                    writeErrors.incrementAndGet();
                    if (e.getMessage() != null && e.getMessage().contains("lock")) {
                        writeConflicts.incrementAndGet();
                    }
                }
                writeRecorder.stop(start);
            }, 0, periodMs, TimeUnit.MILLISECONDS);

            List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;
            long maxAuthRequests = (long) durationSeconds * 500;  // cap at 500 auth/sec to prevent OOM
            while (System.currentTimeMillis() < endTime && authCount.get() < maxAuthRequests) {
                authExecutor.submit(() -> {
                    if (System.currentTimeMillis() > endTime) return;
                    NativeDataGenerator.NativeEvalRequest req = requests.get(
                        (int) (authCount.incrementAndGet() % requests.size()));
                    setupCardContext(req, currentBindingMap);
                    PolicyContext ctx = buildPolicyContext(req);
                    long start = authRecorder.start();
                    try {
                        policyEngine.evaluate(ctx);
                    } catch (Exception e) {
                        authErrors.incrementAndGet();
                    }
                    authRecorder.stop(start);

                    long checkStart = consistencyCheckRecorder.start();
                    try {
                        SnapshotConsistencyChecker.ConsistencyResult cr =
                            consistencyChecker.checkConsistency(ctx,
                                com.coreryblack.astral_permission.contract.PolicyDecision.builder()
                                    .allowed(true).reason("BENCHMARK_CHECK").build());
                        consistencyCheckCount.incrementAndGet();
                        if (cr != null && !cr.isConsistent()) {
                            consistencyViolationCount.incrementAndGet();
                        }
                    } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
                    consistencyCheckRecorder.stop(checkStart);
                });
            }

            writeExecutor.shutdownNow();
            authExecutor.shutdownNow();
            try {
                writeExecutor.awaitTermination(5, TimeUnit.SECONDS);
                authExecutor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) { log.debug("interrupted: {}", e.getMessage()); Thread.currentThread().interrupt(); }

            long finalViolationCount = consistencyChecker.getViolationCount();
            long finalCheckCount = consistencyChecker.getCheckCount();
            boolean consistencyCheckPassed = finalViolationCount == 0;

            NativeWriteResult result = new NativeWriteResult();
            result.targetWriteTps = targetTps;
            result.actualAuthCount = authCount.get();
            result.actualWriteCount = writeCount.get();
            result.authP99Us = authRecorder.snapshot().p99Us();
            result.writeP99Us = writeRecorder.snapshot().p99Us();
            result.authErrorRate = authCount.get() > 0 ? (double) authErrors.get() / authCount.get() : 0;
            result.writeErrorRate = writeCount.get() > 0 ? (double) writeErrors.get() / writeCount.get() : 0;
            result.writeConflicts = writeConflicts.get();
            result.consistencyCheckPassed = consistencyCheckPassed;
            result.consistencyCheckCount = finalCheckCount;
            result.consistencyViolationCount = finalViolationCount;
            result.consistencyViolationRate = finalCheckCount > 0
                ? (double) finalViolationCount / finalCheckCount : 0.0;
            result.consistencyCheckLatencyP99Us = consistencyCheckRecorder.snapshot().p99Us();
            results.add(result);

            log.info("  auth={} writes={} authP99={}us writeP99={}us conflicts={} consistencyPassed={} violations={} ({})",
                authCount.get(), writeCount.get(),
                String.format("%.1f", result.authP99Us),
                String.format("%.1f", result.writeP99Us),
                writeConflicts.get(),
                consistencyCheckPassed,
                finalViolationCount,
                String.format("%.4f", result.consistencyViolationRate));
        }

        return results;
    }

    @Data
    public static class NativeWriteResult {
        public int targetWriteTps;
        public long actualAuthCount;
        public long actualWriteCount;
        public double authP99Us;
        public double writeP99Us;
        public double authErrorRate;
        public double writeErrorRate;
        public int writeConflicts;
        public boolean consistencyCheckPassed;
        public long consistencyCheckCount;
        public long consistencyViolationCount;
        public double consistencyViolationRate;
        public double consistencyCheckLatencyP99Us;
    }
}
