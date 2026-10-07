package com.coreryblack.benchmark.rq2;

import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.benchmark.baseline.CasbinAdapter;
import com.coreryblack.benchmark.baseline.OpaAdapter;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class ConflictDensityBenchmark {

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final CasbinAdapter casbinAdapter;
    private final OpaAdapter opaAdapter;
    private final OpaAdapter opaNoCacheAdapter;
    private final JdbcTemplate jdbcTemplate;

    public ConflictDensityBenchmark(PolicyEngine policyEngine,
                                     DataGenerator dataGenerator,
                                     StringRedisTemplate redisTemplate,
                                     CasbinAdapter casbinAdapter,
                                     OpaAdapter opaAdapter,
                                     OpaAdapter opaNoCacheAdapter,
                                     JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.casbinAdapter = casbinAdapter;
        this.opaAdapter = opaAdapter;
        this.opaNoCacheAdapter = opaNoCacheAdapter;
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<ConflictResult> execute(ScaleConfig[] configs, int iterations) {
        List<ConflictResult> results = new ArrayList<>();

        for (ScaleConfig config : configs) {
            log.info("Conflict density: deny={}%", (int)(config.getDenyRatio() * 100));

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            LatencyRecorder.LatencySnapshot astralSnapshot = benchmarkAstral(dataset, iterations);
            AtomicInteger astralDenyCount = countAstralDenies(dataset, iterations);

            LatencyRecorder.LatencySnapshot casbinSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
            log.info("  Skipping Casbin for ConflictDensity (O(n) infeasible at 450K policies)");

            LatencyRecorder.LatencySnapshot opaSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
            if (opaAdapter.isAvailable()) {
                try {
                    opaAdapter.initialize(dataset);
                    opaSnapshot = opaAdapter.benchmarkEval(dataset, iterations);
                } catch (Exception e) {
                    log.warn("OPA benchmark failed", e);
                }
            }

            LatencyRecorder.LatencySnapshot opaCachedSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
            if (opaNoCacheAdapter.isAvailable()) {
                try {
                    opaNoCacheAdapter.initialize(dataset);
                    opaCachedSnapshot = opaNoCacheAdapter.benchmarkEval(dataset, iterations);
                } catch (Exception e) {
                    log.warn("OPA Cached benchmark failed", e);
                }
            }

            ConflictResult result = new ConflictResult();
            result.denyRatio = config.getDenyRatio();
            result.astralSnapshot = astralSnapshot;
            result.casbinSnapshot = casbinSnapshot;
            result.opaSnapshot = opaSnapshot;
            result.opaCachedSnapshot = opaCachedSnapshot;
            result.actualDenyRate = (double) astralDenyCount.get() / iterations;
            results.add(result);

            log.info("  AstralLight: mean={}us, p99={}us, deny_rate={}%",
                String.format("%.1f", astralSnapshot.meanUs()),
                String.format("%.1f", astralSnapshot.p99Us()),
                String.format("%.1f", result.actualDenyRate * 100));
        }

        return results;
    }

    private static final int WARMUP = 1000;
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

    private LatencyRecorder.LatencySnapshot benchmarkAstral(DataGenerator.GeneratedDataSet dataset, int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP; i++) {
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

        return recorder.snapshot();
    }

    private AtomicInteger countAstralDenies(DataGenerator.GeneratedDataSet dataset, int iterations) {
        AtomicInteger denyCount = new AtomicInteger(0);
        List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
        for (int i = 0; i < Math.min(iterations, 1000); i++) {
            DataGenerator.EvalRequest req = requests.get(i % requests.size());
            setupCardContext(req.cardId);
            PolicyContext ctx = PolicyContext.builder()
                .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                .domainId(1L).templateId(1L)
                .resource(req.resourceType).action(req.actionCode)
                .targetId(req.resourceId).build();
            PolicyDecision decision = policyEngine.evaluate(ctx);
            if (decision != null && !decision.isAllowed()) {
                denyCount.incrementAndGet();
            }
        }
        return denyCount;
    }

    @Data
    public static class ConflictResult {
        public double denyRatio;
        public double actualDenyRate;
        public LatencyRecorder.LatencySnapshot astralSnapshot;
        public LatencyRecorder.LatencySnapshot casbinSnapshot;
        public LatencyRecorder.LatencySnapshot opaSnapshot;
        public LatencyRecorder.LatencySnapshot opaCachedSnapshot;
    }
}
