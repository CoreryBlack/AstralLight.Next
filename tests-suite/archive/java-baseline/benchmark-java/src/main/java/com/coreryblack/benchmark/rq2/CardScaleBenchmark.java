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
import com.coreryblack.benchmark.util.RedisMemoryMeasurer;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
public class CardScaleBenchmark {

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final CasbinAdapter casbinAdapter;
    private final CasbinCachedAdapter casbinCachedAdapter;
    private final OpaAdapter opaAdapter;
    private final OpaAdapter opaNoCacheAdapter;
    private final JdbcTemplate jdbcTemplate;

    public CardScaleBenchmark(PolicyEngine policyEngine,
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

    public List<CardScaleResult> execute(ScaleConfig[] configs, int iterations) {
        List<CardScaleResult> results = new ArrayList<>();

        for (ScaleConfig config : configs) {
            log.info("RQ-B: cardCount={} (45 rules/card, total={} rules)",
                config.getCardCount(), config.totalNominalRules());

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);

            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            LatencyRecorder.LatencySnapshot astralSnapshot = benchmarkAstral(dataset, iterations);
            long storageBytes = measureStorageSize();
            double astralTps = astralSnapshot.tps();

            Map<String, Object> cacheHitStats = policyEngine.getCacheHitStats();
            policyEngine.resetCacheHitStats();

            Map<String, Object> breakdownStats = policyEngine.getBreakdownStats();
            policyEngine.resetBreakdownStats();

            RedisMemoryMeasurer.MemorySnapshot redisMemAfter = new RedisMemoryMeasurer(redisTemplate).measure();

            LatencyRecorder.LatencySnapshot casbinSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
            LatencyRecorder.LatencySnapshot casbinCachedSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
            LatencyRecorder.LatencySnapshot opaSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);
            LatencyRecorder.LatencySnapshot opaCachedSnapshot = LatencyRecorder.LatencySnapshot.empty(java.util.concurrent.TimeUnit.NANOSECONDS);

            boolean skipCasbin = true; // RQ-B focuses on AL scalability; Casbin data from RQ2
            if (skipCasbin) {
                log.info("  Skipping Casbin/CasbinCached for cardCount={} (O(n) infeasible)", config.getCardCount());
            } else {
            try {
                casbinAdapter.initialize(dataset);
                casbinSnapshot = casbinAdapter.benchmarkEval(dataset, iterations);
            } catch (Exception e) {
                log.warn("Casbin benchmark failed for cardCount={}", config.getCardCount(), e);
            }

            try {
                casbinCachedAdapter.initialize(dataset);
                casbinCachedSnapshot = casbinCachedAdapter.benchmarkEval(dataset, iterations);
            } catch (Exception e) {
                log.warn("CasbinCached benchmark failed for cardCount={}", config.getCardCount(), e);
            }
            } // end skipCasbin else

            if (opaAdapter.isAvailable()) {
                try {
                    opaAdapter.initialize(dataset);
                    opaSnapshot = opaAdapter.benchmarkEval(dataset, iterations);
                } catch (Exception e) {
                    log.warn("OPA benchmark failed for cardCount={}", config.getCardCount(), e);
                }
            }

            if (opaNoCacheAdapter.isAvailable()) {
                try {
                    opaNoCacheAdapter.initialize(dataset);
                    opaCachedSnapshot = opaNoCacheAdapter.benchmarkEval(dataset, iterations);
                } catch (Exception e) {
                    log.warn("OPA Cached benchmark failed for cardCount={}", config.getCardCount(), e);
                }
            }

            CardScaleResult result = new CardScaleResult();
            result.cardCount = config.getCardCount();
            result.totalRules = config.totalNominalRules();
            result.storageBytes = storageBytes;
            result.astralSnapshot = astralSnapshot;
            result.astralTps = astralTps;
            result.casbinSnapshot = casbinSnapshot;
            result.casbinCachedSnapshot = casbinCachedSnapshot;
            result.opaSnapshot = opaSnapshot;
            result.opaCachedSnapshot = opaCachedSnapshot;
            result.redisUsedMemoryMb = redisMemAfter.usedMemoryMb();
            result.redisKeyCount = redisMemAfter.dbKeyCount;
            result.redisFragmentationRatio = redisMemAfter.fragmentationRatio;
            result.l1HitRate = cacheHitStats.getOrDefault("l1HitRate", 0.0);
            result.l2HitRate = cacheHitStats.getOrDefault("l2HitRate", 0.0);
            result.l3HitRate = cacheHitStats.getOrDefault("l3HitRate", 0.0);
            result.totalEvaluations = cacheHitStats.getOrDefault("totalEvaluations", 0L);
            result.cardActiveAvgUs = breakdownStats.getOrDefault("cardActiveAvgUs", 0.0);
            result.refsLoadAvgUs = breakdownStats.getOrDefault("refsLoadAvgUs", 0.0);
            result.overlayEvalAvgUs = breakdownStats.getOrDefault("overlayEvalAvgUs", 0.0);
            result.baseEvalAvgUs = breakdownStats.getOrDefault("baseEvalAvgUs", 0.0);
            result.permRuleEvalAvgUs = breakdownStats.getOrDefault("permRuleEvalAvgUs", 0.0);
            results.add(result);

            log.info("  AstralLight: mean={}us, p99={}us, tps={}, storage={}KB",
                String.format("%.1f", astralSnapshot.meanUs()),
                String.format("%.1f", astralSnapshot.p99Us()),
                String.format("%.0f", astralTps),
                String.format("%.1f", storageBytes / 1024.0));
            log.info("  [DIAG] Redis: usedMem={}MB, keys={}, fragRatio={}",
                String.format("%.2f", redisMemAfter.usedMemoryMb()),
                redisMemAfter.dbKeyCount,
                String.format("%.2f", redisMemAfter.fragmentationRatio));
            log.info("  [DIAG] CacheHit: L1={}%, L2={}%, L3={}%, totalEval={}",
                String.format("%.1f", (double) result.l1HitRate * 100),
                String.format("%.1f", (double) result.l2HitRate * 100),
                String.format("%.1f", (double) result.l3HitRate * 100),
                result.totalEvaluations);
            log.info("  [DIAG] Breakdown: cardActive={}us, refsLoad={}us, overlay={}us, base={}us, permRule={}us",
                String.format("%.1f", (double) result.cardActiveAvgUs),
                String.format("%.1f", (double) result.refsLoadAvgUs),
                String.format("%.1f", (double) result.overlayEvalAvgUs),
                String.format("%.1f", (double) result.baseEvalAvgUs),
                String.format("%.1f", (double) result.permRuleEvalAvgUs));
            log.info("  Casbin:      mean={}us, p99={}us",
                String.format("%.1f", casbinSnapshot.meanUs()),
                String.format("%.1f", casbinSnapshot.p99Us()));
            log.info("  CasbinCached: mean={}us, p99={}us",
                String.format("%.1f", casbinCachedSnapshot.meanUs()),
                String.format("%.1f", casbinCachedSnapshot.p99Us()));
            log.info("  OPA(no-cache): mean={}us, p99={}us",
                String.format("%.1f", opaSnapshot.meanUs()),
                String.format("%.1f", opaSnapshot.p99Us()));
            log.info("  OPA(cached):  mean={}us, p99={}us",
                String.format("%.1f", opaCachedSnapshot.meanUs()),
                String.format("%.1f", opaCachedSnapshot.p99Us()));
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

        policyEngine.resetCacheHitStats();

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

    private long measureStorageSize() {
        try {
            Long snapshotCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM rule_set_snapshot", Long.class);
            Long entryCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM rule_set_entry", Long.class);
            Long refCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM card_rule_set_ref", Long.class);
            long snapshotBytes = snapshotCount != null ? snapshotCount * 200 : 0;
            long entryBytes = entryCount != null ? entryCount * 150 : 0;
            long refBytes = refCount != null ? refCount * 80 : 0;
            return snapshotBytes + entryBytes + refBytes;
        } catch (Exception e) {
            return -1;
        }
    }

    @Data
    public static class CardScaleResult {
        public int cardCount;
        public int totalRules;
        public long storageBytes;
        public double astralTps;
        public LatencyRecorder.LatencySnapshot astralSnapshot;
        public LatencyRecorder.LatencySnapshot casbinSnapshot;
        public LatencyRecorder.LatencySnapshot casbinCachedSnapshot;
        public LatencyRecorder.LatencySnapshot opaSnapshot;
        public LatencyRecorder.LatencySnapshot opaCachedSnapshot;
        public double redisUsedMemoryMb;
        public long redisKeyCount;
        public double redisFragmentationRatio;
        public Object l1HitRate;
        public Object l2HitRate;
        public Object l3HitRate;
        public Object totalEvaluations;
        public Object cardActiveAvgUs;
        public Object refsLoadAvgUs;
        public Object overlayEvalAvgUs;
        public Object baseEvalAvgUs;
        public Object permRuleEvalAvgUs;
    }
}
