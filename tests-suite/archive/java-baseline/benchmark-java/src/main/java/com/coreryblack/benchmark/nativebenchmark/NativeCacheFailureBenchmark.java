package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.benchmark.nativebenchmark.NativeScaleConfig;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.DecisionOutcomeRecorder;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Slf4j
public class NativeCacheFailureBenchmark extends AbstractNativeBenchmark {

    private static final int WARMUP = 500;
    private static final int CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5;
    private static final long CIRCUIT_BREAKER_RESET_TIMEOUT_MS = 30000;
    private static final long CIRCUIT_BREAKER_RESET_TIMEOUT_NS = CIRCUIT_BREAKER_RESET_TIMEOUT_MS * 1_000_000L;
    /** How long the REDIS_DOWN / RECOVERY phases wait for the external fault script ack. */
    private static final long EXTERNAL_FAULT_TIMEOUT_MS = 180_000L;

    /** 当前基准测试的卡片绑定映射，供 setupCardContext 查找 templateId/cardType */
    private Map<Long, NativeDataGenerator.NativeCardBinding> currentBindingMap = Collections.emptyMap();

    /**
     * Directory for the external-fault marker protocol. When non-blank, the
     * REDIS_DOWN phase stops simulating a failure with FLUSHDB and instead
     * blocks until an external script stops the dedicated Redis container and
     * writes {@code fault-ack}; the RECOVERY phase blocks until the script has
     * restarted Redis before measuring recovery. When blank (default), the
     * benchmark keeps the legacy simulated behavior.
     */
    private final String externalFaultMarkerDir;
    /** Non-null for a three-node cluster run; the recorder annotates every
     * outcome with node identity/role/global-sequence in that case. */
    private final com.coreryblack.benchmark.util.ClusterRunContext clusterContext;

    private int consecutiveFailures = 0;
    private boolean circuitBreakerOpen = false;
    private long circuitBreakerOpenedAt = 0;

    public NativeCacheFailureBenchmark(PolicyEngine policyEngine,
                                         NativeDataGenerator nativeDataGenerator,
                                         StringRedisTemplate redisTemplate,
                                         JdbcTemplate jdbcTemplate) {
        this(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate, "",
                com.coreryblack.benchmark.util.ClusterRunContext.singleNode());
    }

    public NativeCacheFailureBenchmark(PolicyEngine policyEngine,
                                         NativeDataGenerator nativeDataGenerator,
                                         StringRedisTemplate redisTemplate,
                                         JdbcTemplate jdbcTemplate,
                                         String externalFaultMarkerDir) {
        this(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate, externalFaultMarkerDir,
                com.coreryblack.benchmark.util.ClusterRunContext.singleNode());
    }

    public NativeCacheFailureBenchmark(PolicyEngine policyEngine,
                                         NativeDataGenerator nativeDataGenerator,
                                         StringRedisTemplate redisTemplate,
                                         JdbcTemplate jdbcTemplate,
                                         String externalFaultMarkerDir,
                                         com.coreryblack.benchmark.util.ClusterRunContext clusterContext) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        this.externalFaultMarkerDir = externalFaultMarkerDir == null ? "" : externalFaultMarkerDir;
        this.clusterContext = clusterContext == null
                ? com.coreryblack.benchmark.util.ClusterRunContext.singleNode() : clusterContext;
    }

    private boolean externalFaultEnabled() {
        return !externalFaultMarkerDir.isBlank();
    }

    /** Records one decision; the cluster-aware overload annotates node/role/global-sequence. */
    private void recordDecision(DecisionOutcomeRecorder outcomeRecorder, String phase, int requestIndex,
                                NativeDataGenerator.NativeEvalRequest req,
                                com.coreryblack.astral_permission.contract.PolicyDecision decision,
                                long elapsed) {
        if (clusterContext.isClusterRun()) {
            outcomeRecorder.recordDecision(clusterContext,
                    clusterContext.globalSequence(requestIndex),
                    "rq4a-" + clusterContext.nodeId() + "-" + phase + "-" + requestIndex,
                    phase, requestIndex, req, decision, elapsed,
                    null, null, null, null, null);
        } else {
            outcomeRecorder.recordDecision(phase, requestIndex, req, decision, elapsed);
        }
    }

    /** Records one failure; cluster-aware overload annotates node/role/global-sequence. */
    private void recordFailure(DecisionOutcomeRecorder outcomeRecorder, String phase, int requestIndex,
                               NativeDataGenerator.NativeEvalRequest req, Throwable e, long elapsed) {
        if (clusterContext.isClusterRun()) {
            outcomeRecorder.recordFailure(clusterContext,
                    clusterContext.globalSequence(requestIndex),
                    "rq4a-" + clusterContext.nodeId() + "-" + phase + "-" + requestIndex,
                    phase, requestIndex, req, e, elapsed, null, null, null, null, null);
        } else {
            outcomeRecorder.recordFailure(phase, requestIndex, req, e, elapsed);
        }
    }

    /** Records one circuit-open decision; cluster-aware overload annotates node/role. */
    private void recordCircuitOpen(DecisionOutcomeRecorder outcomeRecorder, String phase, int requestIndex,
                                   NativeDataGenerator.NativeEvalRequest req, long elapsed) {
        if (clusterContext.isClusterRun()) {
            outcomeRecorder.recordCircuitOpen(clusterContext,
                    clusterContext.globalSequence(requestIndex),
                    "rq4a-" + clusterContext.nodeId() + "-" + phase + "-" + requestIndex,
                    phase, requestIndex, req, elapsed, null);
        } else {
            outcomeRecorder.recordCircuitOpen(phase, requestIndex, req, elapsed);
        }
    }

    public NativeCacheFailureResult execute(NativeScaleConfig config, int iterations) {
        log.info("=== Native Cache Failure Benchmark (with Circuit Breaker) ===");

        cleanupBenchmarkData();
        NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
        nativeDataGenerator.persistToDatabase(dataset);
        nativeDataGenerator.populateRedisCache(dataset);
        currentBindingMap = dataset.bindings.stream()
            .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

        resetCircuitBreaker();

        DecisionOutcomeRecorder outcomeRecorder = new DecisionOutcomeRecorder();
        LatencyRecorder.LatencySnapshot normalSnapshot = benchmarkPhase(
                dataset, iterations, "NORMAL", outcomeRecorder);
        double normalErrorRate = measureErrorRate(dataset, 1000);

        if (externalFaultEnabled()) {
            // External fault protocol: request the wrapper to stop Redis, then
            // wait for its ack before measuring the real failure path. The
            // Redis process is actually stopped, so policyEngine.evaluate
            // throws a real connection exception and the circuit breaker is
            // exercised by genuine failures.
            log.info("  External-fault mode: requesting REDIS_DOWN (docker stop astral_bench_redis)...");
            writeMarker("phase-REDIS_DOWN-requested");
            waitForAck("REDIS_DOWN");
            log.info("  External ack received; Redis is down. Measuring real fallback/circuit-breaker path.");
        } else {
            log.info("  Simulating Redis failure in the dedicated benchmark database (FLUSHDB)...");
            BenchmarkCleanupUtil.cleanupRedis(redisTemplate);
        }

        LatencyRecorder.LatencySnapshot downSnapshot = benchmarkPhaseWithCircuitBreaker(
                dataset, iterations, "REDIS_DOWN", outcomeRecorder);
        double downErrorRate = measureErrorRate(dataset, 1000);

        LatencyRecorder.LatencySnapshot cbOpenSnapshot = benchmarkPhaseCircuitBreakerOpen(
                dataset, iterations, "CB_OPEN", outcomeRecorder);

        if (externalFaultEnabled()) {
            // Recovery protocol: request the wrapper to start Redis, wait for
            // its ack, then rebuild the dataset and measure recovery against
            // the restarted Redis.
            log.info("  External-fault mode: requesting RECOVERY (docker start astral_bench_redis)...");
            writeMarker("phase-RECOVERY-requested");
            waitForAck("RECOVERY");
            // The Lettuce connection pool may still hold a broken connection
            // from the down period. Wait until a real ping succeeds before the
            // rebuild (whose first step FLUSHes Redis), instead of letting the
            // first command time out and fail the whole phase.
            waitForRedisConnection();
            log.info("  External ack received; Redis is back. Rebuilding snapshots for recovery measurement.");
        }

        log.info("  Restoring Redis (rebuilding snapshots)...");
        cleanupBenchmarkData();
        dataset = nativeDataGenerator.generate(config);
        nativeDataGenerator.persistToDatabase(dataset);
        nativeDataGenerator.populateRedisCache(dataset);
        currentBindingMap = dataset.bindings.stream()
            .collect(Collectors.toMap(b -> b.cardId, b -> b, (a, b2) -> a));

        resetCircuitBreaker();

        LatencyRecorder.LatencySnapshot recoverySnapshot = benchmarkPhase(
                dataset, iterations, "RECOVERY", outcomeRecorder);
        double recoveryErrorRate = measureErrorRate(dataset, 1000);

        NativeCacheFailureResult result = new NativeCacheFailureResult();
        result.normalSnapshot = normalSnapshot;
        result.normalErrorRate = normalErrorRate;
        result.downSnapshot = downSnapshot;
        result.downErrorRate = downErrorRate;
        result.recoverySnapshot = recoverySnapshot;
        result.recoveryErrorRate = recoveryErrorRate;
        result.circuitBreakerOpenSnapshot = cbOpenSnapshot;
        result.circuitBreakerTripped = circuitBreakerOpen;
        result.decisionOutcomes = outcomeRecorder.snapshot();
        result.allowedDecisionCount = outcomeRecorder.allowedCount();
        result.deniedDecisionCount = outcomeRecorder.deniedCount();
        result.failureDecisionCount = outcomeRecorder.failureCount();
        result.expectedAllowMismatchCount = outcomeRecorder.expectedAllowMismatchCount();
        result.expectedDenyMismatchCount = outcomeRecorder.expectedDenyMismatchCount();
        result.measuredRequestsPerPhase = iterations;

        log.info("  Normal: mean={}us, err={}%",
            String.format("%.1f", normalSnapshot.meanUs()),
            String.format("%.1f", normalErrorRate * 100));
        log.info("  Down:   mean={}us, err={}%",
            String.format("%.1f", downSnapshot.meanUs()),
            String.format("%.1f", downErrorRate * 100));
        log.info("  CB-Open: mean={}us, p99={}us (CIRCUIT_BREAKER_OPEN decisions)",
            String.format("%.1f", cbOpenSnapshot.meanUs()),
            String.format("%.1f", cbOpenSnapshot.p99Us()));
        log.info("  Recovery: mean={}us, err={}%",
            String.format("%.1f", recoverySnapshot.meanUs()),
            String.format("%.1f", recoveryErrorRate * 100));

        return result;
    }

    private LatencyRecorder.LatencySnapshot benchmarkPhase(NativeDataGenerator.NativeGeneratedDataSet dataset,
                                                             int iterations, String phase,
                                                             DecisionOutcomeRecorder outcomeRecorder) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            try {
                setupCardContext(req, currentBindingMap);
                PolicyContext ctx = buildPolicyContext(req);
                policyEngine.evaluate(ctx);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, currentBindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            long start = recorder.start();
            try {
                var decision = policyEngine.evaluate(ctx);
                long elapsed = recorder.stop(start);
                recordDecision(outcomeRecorder, phase, i, req, decision, elapsed);
            } catch (Exception e) {
                long elapsed = System.nanoTime() - start;
                recorder.recordError(elapsed);
                recordFailure(outcomeRecorder, phase, i, req, e, elapsed);
            }
        }

        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkPhaseWithCircuitBreaker(
            NativeDataGenerator.NativeGeneratedDataSet dataset, int iterations, String phase,
            DecisionOutcomeRecorder outcomeRecorder) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, currentBindingMap);

            if (isCircuitBreakerOpen()) {
                long start = recorder.start();
                long elapsed = recorder.stop(start);
                recordCircuitOpen(outcomeRecorder, phase, i, req, elapsed);
                continue;
            }

            PolicyContext ctx = buildPolicyContext(req);
            long start = recorder.start();
            try {
                var decision = policyEngine.evaluate(ctx);
                long elapsed = recorder.stop(start);
                recordDecision(outcomeRecorder, phase, i, req, decision, elapsed);
                consecutiveFailures = 0;
            } catch (Exception e) {
                long elapsed = System.nanoTime() - start;
                recorder.recordError(elapsed);
                recordFailure(outcomeRecorder, phase, i, req, e, elapsed);
                consecutiveFailures++;
                if (consecutiveFailures >= CIRCUIT_BREAKER_FAILURE_THRESHOLD) {
                    tripCircuitBreaker();
                }
            }
        }

        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkPhaseCircuitBreakerOpen(
            NativeDataGenerator.NativeGeneratedDataSet dataset, int iterations, String phase,
            DecisionOutcomeRecorder outcomeRecorder) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        if (!circuitBreakerOpen) {
            tripCircuitBreaker();
        }

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, currentBindingMap);

            long start = recorder.start();
            if (isCircuitBreakerOpen()) {
                long elapsed = recorder.stop(start);
                recordCircuitOpen(outcomeRecorder, phase, i, req, elapsed);
            } else {
                PolicyContext ctx = buildPolicyContext(req);
                try {
                    var decision = policyEngine.evaluate(ctx);
                    long elapsed = recorder.stop(start);
                    recordDecision(outcomeRecorder, phase, i, req, decision, elapsed);
                } catch (Exception e) {
                    long elapsed = System.nanoTime() - start;
                    recorder.recordError(elapsed);
                    recordFailure(outcomeRecorder, phase, i, req, e, elapsed);
                }
            }
        }

        return recorder.snapshot();
    }

    private double measureErrorRate(NativeDataGenerator.NativeGeneratedDataSet dataset, int sampleSize) {
        AtomicInteger errors = new AtomicInteger(0);
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;
        for (int i = 0; i < sampleSize; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            try {
                setupCardContext(req, currentBindingMap);
                PolicyContext ctx = buildPolicyContext(req);
                policyEngine.evaluate(ctx);
            } catch (Exception e) {
                errors.incrementAndGet();
            }
        }
        return (double) errors.get() / sampleSize;
    }

    private synchronized boolean isCircuitBreakerOpen() {
        if (circuitBreakerOpen) {
            if (System.nanoTime() - circuitBreakerOpenedAt > CIRCUIT_BREAKER_RESET_TIMEOUT_NS) {
                circuitBreakerOpen = false;
                consecutiveFailures = 0;
                return false;
            }
            return true;
        }
        return false;
    }

    private synchronized void tripCircuitBreaker() {
        circuitBreakerOpen = true;
        circuitBreakerOpenedAt = System.nanoTime();
        log.info("  Circuit breaker TRIPPED at {} ns", circuitBreakerOpenedAt);
    }

    private synchronized void resetCircuitBreaker() {
        circuitBreakerOpen = false;
        consecutiveFailures = 0;
        circuitBreakerOpenedAt = 0;
    }

    /**
     * Blocks until a Redis ping succeeds (up to 60s), so the recovery rebuild
     * runs against a live connection rather than a stale broken one.
     */
    private void waitForRedisConnection() {
        long deadline = System.currentTimeMillis() + 60_000L;
        while (System.currentTimeMillis() < deadline) {
            try {
                String pong = redisTemplate.getConnectionFactory().getConnection().ping();
                if (pong != null) {
                    log.info("  Redis connection recovered (ping={})", pong);
                    return;
                }
            } catch (Exception e) {
                log.debug("  Redis ping failed while waiting for recovery: {}", e.getMessage());
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for Redis recovery", ie);
            }
        }
        throw new IllegalStateException("Redis did not accept a ping within 60s after recovery ack");
    }

    /**
     * Writes a phase marker into the external fault directory. The wrapper
     * script watches for {@code phase-<NAME>-requested} files and performs the
     * container operation.
     */
    private void writeMarker(String name) {
        try {
            Path dir = Path.of(externalFaultMarkerDir);
            Files.createDirectories(dir);
            Files.writeString(dir.resolve(name),
                    LocalDateTime.now().toString() + "\n", StandardCharsets.UTF_8);
            log.info("  Marker written: {}", name);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to write fault marker " + name, e);
        }
    }

    /**
     * Blocks until the wrapper script writes {@code fault-ack} containing the
     * phase name, or the timeout expires. The ack file is consumed after a
     * successful read so a stale ack from a previous phase does not satisfy the
     * next wait.
     */
    private void waitForAck(String phase) {
        Path ack = Path.of(externalFaultMarkerDir, "fault-ack");
        long deadline = System.currentTimeMillis() + EXTERNAL_FAULT_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            try {
                if (Files.exists(ack)) {
                    String content = Files.readString(ack, StandardCharsets.UTF_8);
                    if (content.contains(phase)) {
                        Files.deleteIfExists(ack);
                        log.info("  Ack received for phase {}", phase);
                        return;
                    }
                }
            } catch (IOException e) {
                log.warn("  Failed to read fault ack for {}: {}", phase, e.getMessage());
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for fault ack for " + phase, ie);
            }
        }
        throw new IllegalStateException(
                "Timed out waiting for external fault ack for phase " + phase + " in " + externalFaultMarkerDir);
    }

    @Data
    public static class NativeCacheFailureResult {
        public LatencyRecorder.LatencySnapshot normalSnapshot;
        public double normalErrorRate;
        public LatencyRecorder.LatencySnapshot downSnapshot;
        public double downErrorRate;
        public LatencyRecorder.LatencySnapshot recoverySnapshot;
        public double recoveryErrorRate;
        public LatencyRecorder.LatencySnapshot circuitBreakerOpenSnapshot;
        public boolean circuitBreakerTripped;
        public List<DecisionOutcomeRecorder.DecisionOutcome> decisionOutcomes = List.of();
        public long allowedDecisionCount;
        public long deniedDecisionCount;
        public long failureDecisionCount;
        public long expectedAllowMismatchCount;
        public long expectedDenyMismatchCount;
        public int measuredRequestsPerPhase;
    }
}
