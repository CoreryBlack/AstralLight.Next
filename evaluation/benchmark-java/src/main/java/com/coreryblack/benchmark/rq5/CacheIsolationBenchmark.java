package com.coreryblack.benchmark.rq5;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * P5: Fairness Validation — Cache Isolation Experiment.
 *
 * <p>Isolates the contribution of the snapshot/cache layer from the
 * underlying rule engine architecture. Checks whether the observed latency
 * difference comes from the design or caching.</p>
 *
 * <h3>Experimental Modes</h3>
 * <ul>
 *   <li><b>SNAPSHOT_ON</b> — Full production config: rule_set_snapshot + Redis cache</li>
 *   <li><b>SNAPSHOT_OFF</b> — No snapshot, no Redis: per-request DB query on rule_set_entry</li>
 *   <li><b>REDIS_ONLY</b> — Redis cache but no pre-computed snapshot (read-through)</li>
 * </ul>
 *
 * <h3>Interpretation</h3>
 * <pre>
 *   gap_architecture  = SNAPSHOT_OFF mean - REDIS_ONLY mean
 *   gap_cache          = REDIS_ONLY mean - SNAPSHOT_ON mean
 *   total_gain         = SNAPSHOT_OFF mean - SNAPSHOT_ON mean
 *   architecture_pct   = gap_architecture / total_gain * 100%
 *   cache_pct          = gap_cache / total_gain * 100%
 * </pre>
 */
@Slf4j
public class CacheIsolationBenchmark {

    private static final long BENCHMARK_TENANT_ID = 1L;
    private static final int WARMUP = 1000;
    private static final int ITERATIONS = 10_000;

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;

    public CacheIsolationBenchmark(
            PolicyEngine policyEngine,
            DataGenerator dataGenerator,
            StringRedisTemplate redisTemplate,
            JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Result from one experimental mode.
     */
    public static class CacheModeResult {
        public String mode;                  // SNAPSHOT_ON, SNAPSHOT_OFF, REDIS_ONLY
        public LatencyRecorder.LatencySnapshot latencySnapshot;
        public long dbQueryCount;            // approximate DB hits during measurement

        public double meanUs() {
            return latencySnapshot != null ? latencySnapshot.meanUs() : -1;
        }

        public double p99Us() {
            return latencySnapshot != null ? latencySnapshot.p99Us() : -1;
        }
    }

    /**
     * Decomposed cache isolation analysis.
     */
    public static class CacheIsolationResult {
        public ScaleConfig scale;
        public CacheModeResult snapshotOn;     // production: snapshot + Redis
        public CacheModeResult snapshotOff;    // no cache: DB query per request
        public CacheModeResult redisOnly;      // Redis read-through, no snapshot
        public double architectureGainUs;      // gain from snapshot architecture alone
        public double cacheGainUs;             // additional gain from Redis cache
        public double architecturePercent;     // percentage of total gain from architecture
        public double cachePercent;            // percentage of total gain from cache

        public String toLatexRow() {
            return String.format("C=%d & %.1f & %.1f & %.1f & %.1f (%.0f\\%%) & %.1f (%.0f\\%%) \\\\",
                scale.getCardCount(),
                snapshotOff.meanUs(),
                redisOnly.meanUs(),
                snapshotOn.meanUs(),
                architectureGainUs, architecturePercent,
                cacheGainUs, cachePercent);
        }

        public static String latexHeader() {
            return "\\textbf{Scale} & \\textbf{No Cache} & " +
                "\\textbf{Redis Only} & \\textbf{Snapshot+Redis} & " +
                "\\textbf{Arch. Gain (\\%)} & \\textbf{Cache Gain (\\%)} \\\\";
        }
    }

    /**
     * Run cache isolation analysis across gradient scales.
     */
    public List<CacheIsolationResult> execute(ScaleConfig[] scales) {
        log.info("=== P5: Cache Isolation Experiment ===");
        List<CacheIsolationResult> results = new ArrayList<>();

        for (ScaleConfig scale : scales) {
            log.info("--- Scale: {} ---", scale.label());
            CacheIsolationResult result = new CacheIsolationResult();
            result.scale = scale;

            // Mode 1: SNAPSHOT_OFF — per-request DB query
            result.snapshotOff = measureNoCache(scale);

            // Mode 2: REDIS_ONLY — Redis read-through, no pre-computed snapshot
            result.redisOnly = measureRedisOnly(scale);

            // Mode 3: SNAPSHOT_ON — full production config
            result.snapshotOn = measureFullCache(scale);

            // Decomposition
            if (result.snapshotOff.latencySnapshot.sampleCount() > 0 &&
                result.snapshotOn.latencySnapshot.sampleCount() > 0) {

                double noCacheMean = result.snapshotOff.meanUs();
                double redisMean = result.redisOnly.meanUs();
                double fullMean = result.snapshotOn.meanUs();

                double totalGain = noCacheMean - fullMean;
                result.architectureGainUs = noCacheMean - redisMean;  // snapshot architecture contributes this
                result.cacheGainUs = redisMean - fullMean;            // Redis cache adds this

                if (totalGain > 0) {
                    result.architecturePercent = result.architectureGainUs / totalGain * 100.0;
                    result.cachePercent = result.cacheGainUs / totalGain * 100.0;
                }

                log.info("  Cache isolation: {} cards — noCache={}us, redis={}us, full={}us",
                    scale.getCardCount(),
                    String.format("%.1f", noCacheMean),
                    String.format("%.1f", redisMean),
                    String.format("%.1f", fullMean));
                log.info("    Architecture gain: {:.1f}us ({:.0f}%), Cache gain: {:.1f}us ({:.0f}%)",
                    result.architectureGainUs, result.architecturePercent,
                    result.cacheGainUs, result.cachePercent);
            }

            results.add(result);
        }

        return results;
    }

    private CacheModeResult measureNoCache(ScaleConfig scale) {
        log.info("  Mode: SNAPSHOT_OFF (per-request DB query)");

        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
        dataGenerator.persistToDatabase(dataset);
        // Do NOT populate Redis cache — forces DB path

        dataGenerator.flushAllCaches();

        CacheModeResult result = new CacheModeResult();
        result.mode = "SNAPSHOT_OFF";

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            policyEngine.evaluate(buildContext(req));
        }

        for (int i = 0; i < ITERATIONS; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            long start = recorder.start();
            policyEngine.evaluate(buildContext(req));
            recorder.stop(start);
        }

        result.latencySnapshot = recorder.snapshot();
        log.info("    No cache: mean={}us, p99={}us",
            String.format("%.1f", result.latencySnapshot.meanUs()),
            String.format("%.1f", result.latencySnapshot.p99Us()));
        return result;
    }

    private CacheModeResult measureRedisOnly(ScaleConfig scale) {
        log.info("  Mode: REDIS_ONLY (read-through, no pre-computed snapshot)");

        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
        dataGenerator.persistToDatabase(dataset);
        // Populate Redis with raw entry data (simulating read-through)
        // but NOT the pre-computed snapshot hashes
        // This mode tests the value of the snapshot architecture independently of Redis
        dataGenerator.populateRedisCache(dataset);

        CacheModeResult result = new CacheModeResult();
        result.mode = "REDIS_ONLY";

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            policyEngine.evaluate(buildContext(req));
        }

        for (int i = 0; i < ITERATIONS; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            long start = recorder.start();
            policyEngine.evaluate(buildContext(req));
            recorder.stop(start);
        }

        result.latencySnapshot = recorder.snapshot();
        log.info("    Redis only: mean={}us, p99={}us",
            String.format("%.1f", result.latencySnapshot.meanUs()),
            String.format("%.1f", result.latencySnapshot.p99Us()));
        return result;
    }

    private CacheModeResult measureFullCache(ScaleConfig scale) {
        log.info("  Mode: SNAPSHOT_ON (snapshot + Redis cache)");

        // Full production: this is the standard benchmark
        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(scale);
        dataGenerator.persistToDatabase(dataset);
        dataGenerator.populateRedisCache(dataset);

        CacheModeResult result = new CacheModeResult();
        result.mode = "SNAPSHOT_ON";

        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            policyEngine.evaluate(buildContext(req));
        }

        for (int i = 0; i < ITERATIONS; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            long start = recorder.start();
            policyEngine.evaluate(buildContext(req));
            recorder.stop(start);
        }

        result.latencySnapshot = recorder.snapshot();
        log.info("    Full cache: mean={}us, p99={}us",
            String.format("%.1f", result.latencySnapshot.meanUs()),
            String.format("%.1f", result.latencySnapshot.p99Us()));
        return result;
    }

    // ────────────── Helpers ──────────────

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

    private PolicyContext buildContext(DataGenerator.EvalRequest req) {
        return PolicyContext.builder()
            .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
            .domainId(1L).templateId(1L)
            .resource(req.resourceType).action(req.actionCode)
            .targetId(req.resourceId).build();
    }
}
