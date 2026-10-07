package com.coreryblack.benchmark.rq4;

import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class CacheFailureBenchmark {

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;

    public CacheFailureBenchmark(PolicyEngine policyEngine,
                                  DataGenerator dataGenerator,
                                  StringRedisTemplate redisTemplate,
                                  JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
    }

    public CacheFailureResult execute(ScaleConfig config, int iterations) {
        log.info("=== Cache Failure Benchmark ===");

        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        dataGenerator.persistToDatabase(dataset);
        dataGenerator.populateRedisCache(dataset);

        LatencyRecorder.LatencySnapshot normalSnapshot = benchmarkPhase(dataset, iterations, "NORMAL");
        double normalErrorRate = measureErrorRate(dataset, 1000);

        log.info("  Simulating Redis failure in the dedicated benchmark database...");
        BenchmarkCleanupUtil.cleanupRedis(redisTemplate);

        LatencyRecorder.LatencySnapshot downSnapshot = benchmarkPhase(dataset, iterations, "REDIS_DOWN");
        double downErrorRate = measureErrorRate(dataset, 1000);

        log.info("  Restoring Redis (rebuilding snapshots)...");
        BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
        dataset = dataGenerator.generate(config);
        dataGenerator.persistToDatabase(dataset);
        dataGenerator.populateRedisCache(dataset);

        LatencyRecorder.LatencySnapshot recoverySnapshot = benchmarkPhase(dataset, iterations, "RECOVERY");
        double recoveryErrorRate = measureErrorRate(dataset, 1000);

        CacheFailureResult result = new CacheFailureResult();
        result.normalSnapshot = normalSnapshot;
        result.normalErrorRate = normalErrorRate;
        result.downSnapshot = downSnapshot;
        result.downErrorRate = downErrorRate;
        result.recoverySnapshot = recoverySnapshot;
        result.recoveryErrorRate = recoveryErrorRate;

        log.info("  Normal: mean={}us, err={}%",
            String.format("%.1f", normalSnapshot.meanUs()),
            String.format("%.1f", normalErrorRate * 100));
        log.info("  Down:   mean={}us, err={}%",
            String.format("%.1f", downSnapshot.meanUs()),
            String.format("%.1f", downErrorRate * 100));
        log.info("  Recovery: mean={}us, err={}%",
            String.format("%.1f", recoverySnapshot.meanUs()),
            String.format("%.1f", recoveryErrorRate * 100));

        return result;
    }

    private static final int WARMUP = 500;
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

    private LatencyRecorder.LatencySnapshot benchmarkPhase(DataGenerator.GeneratedDataSet dataset, int iterations, String phase) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            try {
                setupCardContext(req.cardId);
                PolicyContext ctx = PolicyContext.builder()
                    .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                    .domainId(1L).templateId(1L)
                    .resource(req.resourceType).action(req.actionCode)
                    .targetId(req.resourceId).build();
                policyEngine.evaluate(ctx);
            } catch (Exception ignored) {}
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
            try {
                policyEngine.evaluate(ctx);
                recorder.stop(start);
            } catch (Exception e) {
                recorder.recordError(System.nanoTime() - start);
            }
        }

        return recorder.snapshot();
    }

    private double measureErrorRate(DataGenerator.GeneratedDataSet dataset, int sampleSize) {
        AtomicInteger errors = new AtomicInteger(0);
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        for (int i = 0; i < sampleSize; i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            try {
                setupCardContext(req.cardId);
                PolicyContext ctx = PolicyContext.builder()
                    .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                    .domainId(1L).templateId(1L)
                    .resource(req.resourceType).action(req.actionCode)
                    .targetId(req.resourceId).build();
                policyEngine.evaluate(ctx);
            } catch (Exception e) {
                errors.incrementAndGet();
            }
        }
        return (double) errors.get() / sampleSize;
    }

    @Data
    public static class CacheFailureResult {
        public LatencyRecorder.LatencySnapshot normalSnapshot;
        public double normalErrorRate;
        public LatencyRecorder.LatencySnapshot downSnapshot;
        public double downErrorRate;
        public LatencyRecorder.LatencySnapshot recoverySnapshot;
        public double recoveryErrorRate;
    }
}
