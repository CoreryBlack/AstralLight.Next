package com.coreryblack.benchmark.rq4;

import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import com.coreryblack.permission.permission.RuleSetService;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class HighFrequencyWriteBenchmark {

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

    private final PolicyEngine policyEngine;
    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final JdbcTemplate jdbcTemplate;
    private final RuleSetService ruleSetService;

    public HighFrequencyWriteBenchmark(PolicyEngine policyEngine,
                                         DataGenerator dataGenerator,
                                         StringRedisTemplate redisTemplate,
                                         JdbcTemplate jdbcTemplate,
                                         RuleSetService ruleSetService) {
        this.policyEngine = policyEngine;
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
        this.ruleSetService = ruleSetService;
    }

    public List<WriteResult> execute(ScaleConfig config, int[] writeTpsLevels, int durationSeconds) {
        List<WriteResult> results = new java.util.ArrayList<>();

        for (int targetTps : writeTpsLevels) {
            log.info("High-frequency write benchmark: target={} TPS, duration={}s", targetTps, durationSeconds);

            BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate);
            DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
            dataGenerator.persistToDatabase(dataset);
            dataGenerator.populateRedisCache(dataset);

            LatencyRecorder authRecorder = new LatencyRecorder();
            LatencyRecorder writeRecorder = new LatencyRecorder();
            AtomicInteger authErrors = new AtomicInteger(0);
            AtomicInteger writeErrors = new AtomicInteger(0);
            AtomicInteger writeConflicts = new AtomicInteger(0);
            AtomicLong authCount = new AtomicLong(0);
            AtomicLong writeCount = new AtomicLong(0);

            long endTime = System.currentTimeMillis() + durationSeconds * 1000L;

            ScheduledExecutorService writeExecutor = Executors.newSingleThreadScheduledExecutor();
            ExecutorService authExecutor = Executors.newFixedThreadPool(4);

            writeExecutor.scheduleAtFixedRate(() -> {
                if (System.currentTimeMillis() > endTime) return;
                long start = writeRecorder.start();
                try {
                    // E6 fix: perform actual rule changes that trigger snapshot rebuild
                    // and cache invalidation, instead of just updating updated_at
                    int writeIdx = (int) writeCount.getAndIncrement();
                    String resourceType = "write_res_" + (writeIdx % 20);
                    String effect = writeIdx % 3 == 0 ? "DENY" : "ALLOW";
                    RuleSetEntry entry = new RuleSetEntry();
                    entry.setRuleSetId(dataset.baseRuleSet.getRuleSetId());
                    entry.setResourceType(resourceType);
                    entry.setActionCode("read");
                    entry.setEffect(effect);
                    entry.setPriority(50 + writeIdx % 100);
                    entry.setEnabled(1);
                    ruleSetService.addEntry(entry);
                } catch (Exception e) {
                    writeErrors.incrementAndGet();
                    if (e.getMessage() != null && e.getMessage().contains("lock")) {
                        writeConflicts.incrementAndGet();
                    }
                }
                writeRecorder.stop(start);
            }, 0, 1000 / Math.max(targetTps, 1), TimeUnit.MILLISECONDS);

            List<DataGenerator.EvalRequest> requests = dataset.evalRequests;
            while (System.currentTimeMillis() < endTime) {
                authExecutor.submit(() -> {
                    if (System.currentTimeMillis() > endTime) return;
                    DataGenerator.EvalRequest req = requests.get(
                        (int) (authCount.get() % requests.size()));
                    setupCardContext(req.cardId);
                    PolicyContext ctx = PolicyContext.builder()
                        .userId(1L).cardId(req.cardId).tenantId(BENCHMARK_TENANT_ID)
                        .domainId(1L).templateId(1L)
                        .resource(req.resourceType).action(req.actionCode)
                        .targetId(req.resourceId).build();
                    long start = authRecorder.start();
                    try {
                        policyEngine.evaluate(ctx);
                        authCount.incrementAndGet();
                    } catch (Exception e) {
                        authErrors.incrementAndGet();
                    }
                    authRecorder.stop(start);
                });
            }

            writeExecutor.shutdownNow();
            authExecutor.shutdownNow();
            try {
                writeExecutor.awaitTermination(5, TimeUnit.SECONDS);
                authExecutor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}

            WriteResult result = new WriteResult();
            result.targetWriteTps = targetTps;
            result.actualAuthCount = authCount.get();
            result.actualWriteCount = writeCount.get();
            result.authP99Us = authRecorder.snapshot().p99Us();
            result.writeP99Us = writeRecorder.snapshot().p99Us();
            result.authErrorRate = authCount.get() > 0 ? (double) authErrors.get() / authCount.get() : 0;
            result.writeErrorRate = writeCount.get() > 0 ? (double) writeErrors.get() / writeCount.get() : 0;
            result.writeConflicts = writeConflicts.get();
            results.add(result);

            log.info("  auth={} writes={} authP99={}us writeP99={}us conflicts={}",
                authCount.get(), writeCount.get(),
                String.format("%.1f", result.authP99Us),
                String.format("%.1f", result.writeP99Us),
                writeConflicts.get());
        }

        return results;
    }

    @Data
    public static class WriteResult {
        public int targetWriteTps;
        public long actualAuthCount;
        public long actualWriteCount;
        public double authP99Us;
        public double writeP99Us;
        public double authErrorRate;
        public double writeErrorRate;
        public int writeConflicts;
    }
}
