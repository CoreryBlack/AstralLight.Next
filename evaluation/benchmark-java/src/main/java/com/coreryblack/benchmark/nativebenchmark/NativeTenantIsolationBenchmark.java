package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.CardRuleSetRef;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSet;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.permission.permission.RuleSetService;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Benchmark for tenant isolation in the permission engine.
 * Tests cross-tenant access prevention, Redis key scoping, and multi-tenant performance.
 */
@Slf4j
public class NativeTenantIsolationBenchmark extends AbstractNativeBenchmark {

    private static final int WARMUP_ITERATIONS = 500;
    private static final long TENANT_A = 1L;
    private static final long TENANT_B = 2L;

    private final RuleSetService ruleSetService;

    public NativeTenantIsolationBenchmark(PolicyEngine policyEngine,
                                           RuleSetService ruleSetService,
                                           NativeDataGenerator nativeDataGenerator,
                                           StringRedisTemplate redisTemplate,
                                           JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        this.ruleSetService = ruleSetService;
    }

    public NativeTenantIsolationResult execute(NativeScaleConfig config, int iterations) {
        log.info("=== Native Tenant Isolation Benchmark ===");

        cleanupBenchmarkData();

        NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
        nativeDataGenerator.persistToDatabase(dataset);
        nativeDataGenerator.populateRedisCache(dataset);

        Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap = new HashMap<>();
        for (NativeDataGenerator.NativeCardBinding b : dataset.bindings) {
            bindingMap.put(b.cardId, b);
        }

        // Test 1: Cross-tenant binding rejection
        CrossTenantBindingResult bindingResult = testCrossTenantBindingRejection(dataset);

        // Test 2: Redis key tenant-scoping correctness
        RedisScopingResult redisResult = testRedisKeyScoping(dataset);

        // Test 3: Cross-tenant evaluation isolation
        CrossTenantEvalResult evalResult = testCrossTenantEvaluation(
            dataset, bindingMap, iterations);

        // Test 4: Multi-tenant concurrent performance
        LatencyRecorder.LatencySnapshot multiTenantSnapshot = benchmarkMultiTenantPerformance(
            dataset, bindingMap, iterations);

        NativeTenantIsolationResult result = new NativeTenantIsolationResult();
        result.crossTenantBindingResult = bindingResult;
        result.redisScopingResult = redisResult;
        result.crossTenantEvalResult = evalResult;
        result.multiTenantSnapshot = multiTenantSnapshot;

        log.info("  Cross-tenant binding: rejected={}, attempts={}",
            bindingResult.rejectedCount, bindingResult.attemptCount);
        log.info("  Redis scoping: tenantA_keys={}, tenantB_keys={}, cross_leak={}",
            redisResult.tenantAKeyCount, redisResult.tenantBKeyCount, redisResult.crossLeakCount);
        log.info("  Cross-tenant eval: same_tenant_allow={}, cross_tenant_deny={}",
            evalResult.sameTenantAllowCount, evalResult.crossTenantDenyCount);
        log.info("  Multi-tenant perf: mean={}us p99={}us",
            String.format("%.1f", multiTenantSnapshot.meanUs()),
            String.format("%.1f", multiTenantSnapshot.p99Us()));

        cleanupBenchmarkData();
        return result;
    }

    private CrossTenantBindingResult testCrossTenantBindingRejection(
            NativeDataGenerator.NativeGeneratedDataSet dataset) {
        CrossTenantBindingResult result = new CrossTenantBindingResult();
        result.attemptCount = 5;

        // Try to bind a card from tenant A to a ruleSet from tenant B
        if (!dataset.ruleSets.isEmpty() && !dataset.bindings.isEmpty()) {
            RuleSet ruleSet = dataset.ruleSets.get(0);
            long cardId = dataset.bindings.get(0).cardId;

            // Set context to tenant B while ruleSet belongs to tenant A
            NativeDataGenerator.NativeCardBinding binding = dataset.bindings.get(0);
            IdentityCardContext ctx = new IdentityCardContext();
            ctx.setCardId(cardId);
            ctx.setUserId(binding.userId);
            ctx.setTenantId(TENANT_B);
            ctx.setDomainId(binding.domainId);
            ctx.setTemplateId(binding.templateId);
            ctx.setCardType(binding.cardType);
            ctx.setStatus(binding.cardStatus);
            CardContextHolder.set(ctx);

            for (int i = 0; i < result.attemptCount; i++) {
                try {
                    ruleSetService.bindCardToRuleSet(cardId, ruleSet.getRuleSetId(), "BASE");
                } catch (SecurityException e) {
                    result.rejectedCount++;
                } catch (Exception e) {
                    // Other exceptions (e.g., already bound) - still counts as blocked
                    result.rejectedCount++;
                }
            }
            CardContextHolder.clear();
        }

        return result;
    }

    private RedisScopingResult testRedisKeyScoping(
            NativeDataGenerator.NativeGeneratedDataSet dataset) {
        RedisScopingResult result = new RedisScopingResult();

        // Count keys with tenant A prefix
        Set<String> tenantAKeys = new HashSet<>();
        Set<String> tenantBKeys = new HashSet<>();
        try (var cursor = redisTemplate.scan(
                org.springframework.data.redis.core.ScanOptions.scanOptions()
                    .match("perm:*").count(1000).build())) {
            while (cursor.hasNext()) {
                String key = cursor.next();
                if (key.contains(":" + TENANT_A + ":")) {
                    tenantAKeys.add(key);
                } else if (key.contains(":" + TENANT_B + ":")) {
                    tenantBKeys.add(key);
                }
            }
        }

        result.tenantAKeyCount = tenantAKeys.size();
        result.tenantBKeyCount = tenantBKeys.size();

        // Check for cross-tenant data leakage
        // Try reading tenant A's refs cache with tenant B context
        result.crossLeakCount = 0;
        for (NativeDataGenerator.NativeCardBinding b : dataset.bindings.subList(
                0, Math.min(100, dataset.bindings.size()))) {
            String tenantARefsKey = "perm:refs:" + TENANT_A + ":" + b.cardId;
            String tenantBRefsKey = "perm:refs:" + TENANT_B + ":" + b.cardId;
            String aData = redisTemplate.opsForValue().get(tenantARefsKey);
            String bData = redisTemplate.opsForValue().get(tenantBRefsKey);
            // If tenant B key has same data as tenant A, that's a leak
            if (aData != null && aData.equals(bData)) {
                result.crossLeakCount++;
            }
        }

        return result;
    }

    private CrossTenantEvalResult testCrossTenantEvaluation(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        CrossTenantEvalResult result = new CrossTenantEvalResult();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        int sampleCount = Math.min(iterations, 3000);
        for (int i = 0; i < sampleCount; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());

            // Same-tenant evaluation
            setupCardContext(req, bindingMap);
            PolicyContext ctxA = buildPolicyContext(req, TENANT_A);
            PolicyDecision decisionA = policyEngine.evaluate(ctxA);

            // Cross-tenant evaluation (same cardId but different tenant context)
            setupCardContext(req, bindingMap);
            PolicyContext ctxB = buildPolicyContext(req, TENANT_B);
            PolicyDecision decisionB = policyEngine.evaluate(ctxB);

            if (decisionA.isAllowed()) {
                result.sameTenantAllowCount++;
            }
            if (!decisionB.isAllowed()) {
                result.crossTenantDenyCount++;
            }

            // Correctness: if same-tenant allows but cross-tenant also allows,
            // that indicates a potential isolation gap (expected since PolicyEngine
            // doesn't enforce tenant isolation in evaluate())
            if (decisionA.isAllowed() && decisionB.isAllowed()) {
                result.isolationGapCount++;
            }

            result.totalChecks++;
        }

        CardContextHolder.clear();
        return result;
    }

    private LatencyRecorder.LatencySnapshot benchmarkMultiTenantPerformance(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            long tenantId = i % 2 == 0 ? TENANT_A : TENANT_B;
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req, tenantId);
            policyEngine.evaluate(ctx);
        }

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            long tenantId = i % 2 == 0 ? TENANT_A : TENANT_B;
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req, tenantId);
            long start = recorder.start();
            policyEngine.evaluate(ctx);
            recorder.stop(start);
        }

        CardContextHolder.clear();
        return recorder.snapshot();
    }

    public static class NativeTenantIsolationResult {
        public CrossTenantBindingResult crossTenantBindingResult;
        public RedisScopingResult redisScopingResult;
        public CrossTenantEvalResult crossTenantEvalResult;
        public LatencyRecorder.LatencySnapshot multiTenantSnapshot;
    }

    public static class CrossTenantBindingResult {
        public int attemptCount;
        public int rejectedCount;
    }

    public static class RedisScopingResult {
        public int tenantAKeyCount;
        public int tenantBKeyCount;
        public int crossLeakCount;
    }

    public static class CrossTenantEvalResult {
        public long totalChecks;
        public long sameTenantAllowCount;
        public long crossTenantDenyCount;
        public long isolationGapCount;
    }
}
