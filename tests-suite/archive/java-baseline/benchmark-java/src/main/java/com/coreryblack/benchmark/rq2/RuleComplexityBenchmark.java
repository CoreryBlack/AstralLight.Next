package com.coreryblack.benchmark.rq2;

import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.benchmark.baseline.CasbinAdapter;
import com.coreryblack.benchmark.baseline.CasbinCachedAdapter;
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

@Slf4j
public class RuleComplexityBenchmark {

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final CasbinAdapter casbinAdapter;
    private final CasbinCachedAdapter casbinCachedAdapter;
    private final OpaAdapter opaAdapter;
    private final OpaAdapter opaNoCacheAdapter;
    private final JdbcTemplate jdbcTemplate;

    public RuleComplexityBenchmark(PolicyEngine policyEngine,
                                    DataGenerator dataGenerator,
                                    StringRedisTemplate redisTemplate,
                                    CasbinAdapter casbinAdapter,
                                    CasbinCachedAdapter casbinCachedAdapter,
                                    OpaAdapter opaAdapter,
                                    OpaAdapter opaNoCacheAdapter,
                                    JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.casbinAdapter = casbinAdapter;
        this.casbinCachedAdapter = casbinCachedAdapter;
        this.opaAdapter = opaAdapter;
        this.opaNoCacheAdapter = opaNoCacheAdapter;
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<ComplexityResult> execute(ScaleConfig[] configs, int iterations) {
        List<ComplexityResult> results = new ArrayList<>();

        for (ScaleConfig config : configs) {
            log.info("RQ-A: rules_per_card={} (total={} rules)",
                config.getBaseRulesPerCard() + config.getOverlayRulesPerCard(),
                config.totalNominalRules());

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            LatencyRecorder.LatencySnapshot astralSnapshot = benchmarkAstral(dataset, iterations);

            LatencyRecorder.LatencySnapshot casbinSnapshot;
            LatencyRecorder.LatencySnapshot casbinCachedSnapshot;
            if (config.totalNominalRules() > 500000) {
                log.info("  Skipping Casbin/CasbinCached for totalRules={} (O(n) infeasible)", config.totalNominalRules());
                casbinSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.MICROSECONDS);
                casbinCachedSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.MICROSECONDS);
            } else {
                casbinSnapshot = benchmarkCasbin(dataset, iterations);
                casbinCachedSnapshot = benchmarkCasbinCached(dataset, iterations);
            }
            LatencyRecorder.LatencySnapshot opaSnapshot = benchmarkOpa(dataset, iterations);
            LatencyRecorder.LatencySnapshot opaCachedSnapshot = benchmarkOpaCached(dataset, iterations);

            ComplexityResult result = new ComplexityResult();
            result.rulesPerCard = config.getBaseRulesPerCard() + config.getOverlayRulesPerCard();
            result.totalRules = config.totalNominalRules();
            result.astralSnapshot = astralSnapshot;
            result.casbinSnapshot = casbinSnapshot;
            result.casbinCachedSnapshot = casbinCachedSnapshot;
            result.opaSnapshot = opaSnapshot;
            result.opaCachedSnapshot = opaCachedSnapshot;
            results.add(result);

            log.info("  AstralLight: mean={}us, p99={}us",
                String.format("%.1f", astralSnapshot.meanUs()),
                String.format("%.1f", astralSnapshot.p99Us()));
            log.info("  Casbin:      mean={}us, p99={}us",
                String.format("%.1f", casbinSnapshot.meanUs()),
                String.format("%.1f", casbinSnapshot.p99Us()));
            log.info("  CasbinCached: mean={}us, p99={}us",
                String.format("%.1f", casbinCachedSnapshot.meanUs()),
                String.format("%.1f", casbinCachedSnapshot.p99Us()));
            log.info("  OPA(no-cache): mean={}us, p99={}us",
                String.format("%.1f", opaSnapshot.meanUs()),
                String.format("%.1f", opaSnapshot.p99Us()));
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

    private LatencyRecorder.LatencySnapshot benchmarkCasbin(DataGenerator.GeneratedDataSet dataset, int iterations) {
        casbinAdapter.initialize(dataset);
        return casbinAdapter.benchmarkEval(dataset, iterations);
    }

    private LatencyRecorder.LatencySnapshot benchmarkCasbinCached(DataGenerator.GeneratedDataSet dataset, int iterations) {
        casbinCachedAdapter.initialize(dataset);
        return casbinCachedAdapter.benchmarkEval(dataset, iterations);
    }

    private LatencyRecorder.LatencySnapshot benchmarkOpa(DataGenerator.GeneratedDataSet dataset, int iterations) {
        if (!opaAdapter.isAvailable()) {
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }
        try {
            opaAdapter.initialize(dataset);
            return opaAdapter.benchmarkEval(dataset, iterations);
        } catch (Exception e) {
            log.warn("OPA benchmark failed", e);
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }
    }

    private LatencyRecorder.LatencySnapshot benchmarkOpaCached(DataGenerator.GeneratedDataSet dataset, int iterations) {
        if (!opaNoCacheAdapter.isAvailable()) {
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }
        try {
            opaNoCacheAdapter.initialize(dataset);
            return opaNoCacheAdapter.benchmarkEval(dataset, iterations);
        } catch (Exception e) {
            log.warn("OPA Cached benchmark failed", e);
            return LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
        }
    }

    @Data
    public static class ComplexityResult {
        public int rulesPerCard;
        public int totalRules;
        public LatencyRecorder.LatencySnapshot astralSnapshot;
        public LatencyRecorder.LatencySnapshot casbinSnapshot;
        public LatencyRecorder.LatencySnapshot casbinCachedSnapshot;
        public LatencyRecorder.LatencySnapshot opaSnapshot;
        public LatencyRecorder.LatencySnapshot opaCachedSnapshot;
    }
}
