package com.coreryblack.benchmark.rq2;

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

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class OverlayDepthBenchmark {

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;

    public OverlayDepthBenchmark(PolicyEngine policyEngine,
                                  DataGenerator dataGenerator,
                                  StringRedisTemplate redisTemplate,
                                  JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<OverlayDepthResult> execute(ScaleConfig[] configs, int iterations) {
        List<OverlayDepthResult> results = new ArrayList<>();

        for (ScaleConfig config : configs) {
            log.info("Overlay depth: overlay_rules={}, base_rules={}",
                config.getOverlayRulesPerCard(), config.getBaseRulesPerCard());

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            long compileStart = System.nanoTime();
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);
            long compileEnd = System.nanoTime();
            double compileMs = (compileEnd - compileStart) / 1_000_000.0;

            LatencyRecorder.LatencySnapshot latencySnapshot = benchmarkAstral(dataset, iterations);

            long snapshotBytes = measureSnapshotSize();

            OverlayDepthResult result = new OverlayDepthResult();
            result.overlayRules = config.getOverlayRulesPerCard();
            result.baseRules = config.getBaseRulesPerCard();
            result.totalRules = config.totalNominalRules();
            result.compileTimeMs = compileMs;
            result.snapshotSizeBytes = snapshotBytes;
            result.latencySnapshot = latencySnapshot;
            results.add(result);

            log.info("  compile={}ms, snapshot={}KB, mean={}us, p99={}us",
                String.format("%.1f", compileMs),
                String.format("%.1f", snapshotBytes / 1024.0),
                String.format("%.1f", latencySnapshot.meanUs()),
                String.format("%.1f", latencySnapshot.p99Us()));
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

    private long measureSnapshotSize() {
        try {
            Long snapshotCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM rule_set_snapshot", Long.class);
            Long ruleCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM rule_set_entry", Long.class);
            long snapshotRowBytes = snapshotCount != null ? snapshotCount * 200 : 0;
            long ruleRowBytes = ruleCount != null ? ruleCount * 150 : 0;
            return snapshotRowBytes + ruleRowBytes;
        } catch (Exception e) {
            return -1;
        }
    }

    @Data
    public static class OverlayDepthResult {
        public int overlayRules;
        public int baseRules;
        public int totalRules;
        public double compileTimeMs;
        public long snapshotSizeBytes;
        public LatencyRecorder.LatencySnapshot latencySnapshot;
    }
}
