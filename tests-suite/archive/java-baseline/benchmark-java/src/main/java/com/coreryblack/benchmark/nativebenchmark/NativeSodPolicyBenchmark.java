package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.permission.auth.SodService;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.SodPolicy;
import com.coreryblack.benchmark.util.LatencyRecorder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;

/**
 * Benchmark for SOD (Separation of Duty) policy enforcement.
 * Tests both static SoD (grant-time validation) and dynamic SoD (runtime check) performance.
 */
@Slf4j
public class NativeSodPolicyBenchmark extends AbstractNativeBenchmark {

    private static final int WARMUP_ITERATIONS = 500;

    private final SodService sodService;

    public NativeSodPolicyBenchmark(PolicyEngine policyEngine,
                                     SodService sodService,
                                     NativeDataGenerator nativeDataGenerator,
                                     StringRedisTemplate redisTemplate,
                                     JdbcTemplate jdbcTemplate) {
        super(policyEngine, nativeDataGenerator, redisTemplate, jdbcTemplate);
        this.sodService = sodService;
    }

    public NativeSodResult execute(NativeScaleConfig config, int iterations) {
        log.info("=== Native SOD Policy Benchmark ===");

        cleanupBenchmarkData();

        NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
        nativeDataGenerator.persistToDatabase(dataset);
        nativeDataGenerator.populateRedisCache(dataset);

        // Create SOD policies for testing
        List<SodPolicy> testPolicies = createTestSodPolicies();
        for (SodPolicy policy : testPolicies) {
            sodService.createPolicy(policy);
        }
        log.info("  Created {} SOD policies", testPolicies.size());

        Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap = new HashMap<>();
        for (NativeDataGenerator.NativeCardBinding b : dataset.bindings) {
            bindingMap.put(b.cardId, b);
        }

        // Benchmark 1: Static SoD validation performance
        LatencyRecorder.LatencySnapshot staticSodSnapshot = benchmarkStaticSodValidation(
            dataset, bindingMap, iterations);

        // Benchmark 2: Dynamic SoD check performance (after policyEngine.evaluate)
        LatencyRecorder.LatencySnapshot dynamicSodSnapshot = benchmarkDynamicSodCheck(
            dataset, bindingMap, iterations);

        // Benchmark 3: Conflict detection performance
        LatencyRecorder.LatencySnapshot conflictDetectSnapshot = benchmarkConflictDetection(
            dataset, iterations);

        // Collect correctness statistics
        SodCorrectnessStats correctnessStats = collectCorrectnessStats(
            dataset, bindingMap, Math.min(iterations, 3000));

        NativeSodResult result = new NativeSodResult();
        result.staticSodSnapshot = staticSodSnapshot;
        result.dynamicSodSnapshot = dynamicSodSnapshot;
        result.conflictDetectSnapshot = conflictDetectSnapshot;
        result.correctnessStats = correctnessStats;
        result.policyCount = testPolicies.size();

        log.info("  Static SoD: mean={}us p99={}us, violations={}",
            String.format("%.1f", staticSodSnapshot.meanUs()),
            String.format("%.1f", staticSodSnapshot.p99Us()),
            correctnessStats.staticViolationCount);
        log.info("  Dynamic SoD: mean={}us p99={}us, violations={}",
            String.format("%.1f", dynamicSodSnapshot.meanUs()),
            String.format("%.1f", dynamicSodSnapshot.p99Us()),
            correctnessStats.dynamicViolationCount);
        log.info("  Conflict detect: mean={}us p99={}us",
            String.format("%.1f", conflictDetectSnapshot.meanUs()),
            String.format("%.1f", conflictDetectSnapshot.p99Us()));

        cleanupBenchmarkData();
        return result;
    }

    private List<SodPolicy> createTestSodPolicies() {
        List<SodPolicy> policies = new ArrayList<>();

        // Static: cannot create and delete same resource type
        SodPolicy staticPolicy = new SodPolicy();
        staticPolicy.setPolicyName("BENCH_NO_CREATE_DELETE");
        staticPolicy.setDescription("Cannot both create and delete the same resource type");
        staticPolicy.setConflictType("STATIC");
        staticPolicy.setResourceType("learn_subject");
        staticPolicy.setActionCode("create");
        staticPolicy.setPermissionA("learn_subject:create");
        staticPolicy.setPermissionB("learn_subject:delete");
        staticPolicy.setStatus("ACTIVE");
        staticPolicy.setCreatedAt(java.time.LocalDateTime.now());
        staticPolicy.setUpdatedAt(java.time.LocalDateTime.now());
        policies.add(staticPolicy);

        // Static: cannot approve and publish
        SodPolicy staticPolicy2 = new SodPolicy();
        staticPolicy2.setPolicyName("BENCH_NO_APPROVE_PUBLISH");
        staticPolicy2.setDescription("Cannot both approve and publish");
        staticPolicy2.setConflictType("STATIC");
        staticPolicy2.setResourceType("learn_exam");
        staticPolicy2.setActionCode("approve");
        staticPolicy2.setPermissionA("learn_exam:approve");
        staticPolicy2.setPermissionB("learn_exam:publish");
        staticPolicy2.setStatus("ACTIVE");
        staticPolicy2.setCreatedAt(java.time.LocalDateTime.now());
        staticPolicy2.setUpdatedAt(java.time.LocalDateTime.now());
        policies.add(staticPolicy2);

        // Dynamic: self-approval prevention
        SodPolicy dynamicPolicy = new SodPolicy();
        dynamicPolicy.setPolicyName("BENCH_NO_SELF_APPROVE");
        dynamicPolicy.setDescription("Cannot approve own resources");
        dynamicPolicy.setConflictType("DYNAMIC");
        dynamicPolicy.setResourceType("learn_question");
        dynamicPolicy.setActionCode("approve");
        dynamicPolicy.setPermissionA("learn_question:update");
        dynamicPolicy.setPermissionB("learn_question:approve");
        dynamicPolicy.setConditionScript("resourceOwnerId == currentUserId");
        dynamicPolicy.setLimitCount(1);
        dynamicPolicy.setLimitWindow("1h");
        dynamicPolicy.setStatus("ACTIVE");
        dynamicPolicy.setCreatedAt(java.time.LocalDateTime.now());
        dynamicPolicy.setUpdatedAt(java.time.LocalDateTime.now());
        policies.add(dynamicPolicy);

        // Dynamic: rate-limited export
        SodPolicy dynamicPolicy2 = new SodPolicy();
        dynamicPolicy2.setPolicyName("BENCH_RATE_LIMITED_EXPORT");
        dynamicPolicy2.setDescription("Export rate limited");
        dynamicPolicy2.setConflictType("DYNAMIC");
        dynamicPolicy2.setResourceType("learn_statistics");
        dynamicPolicy2.setActionCode("export");
        dynamicPolicy2.setPermissionA("learn_statistics:read");
        dynamicPolicy2.setPermissionB("learn_statistics:export");
        dynamicPolicy2.setConditionScript("resourceOwnerId == currentUserId");
        dynamicPolicy2.setLimitCount(5);
        dynamicPolicy2.setLimitWindow("1h");
        dynamicPolicy2.setStatus("ACTIVE");
        dynamicPolicy2.setCreatedAt(java.time.LocalDateTime.now());
        dynamicPolicy2.setUpdatedAt(java.time.LocalDateTime.now());
        policies.add(dynamicPolicy2);

        return policies;
    }

    private LatencyRecorder.LatencySnapshot benchmarkStaticSodValidation(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            try {
                sodService.validateGrant(req.cardId, req.resourceType, req.actionCode);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            long start = recorder.start();
            try {
                sodService.validateGrant(req.cardId, req.resourceType, req.actionCode);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
            recorder.stop(start);
        }

        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkDynamicSodCheck(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < WARMUP_ITERATIONS; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            policyEngine.evaluate(ctx);
            try {
                sodService.checkDynamicSoD(req.resourceType, req.actionCode, null, req.userId);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);
            PolicyContext ctx = buildPolicyContext(req);
            policyEngine.evaluate(ctx);
            long start = recorder.start();
            try {
                sodService.checkDynamicSoD(req.resourceType, req.actionCode, null, req.userId);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
            recorder.stop(start);
        }

        return recorder.snapshot();
    }

    private LatencyRecorder.LatencySnapshot benchmarkConflictDetection(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            int iterations) {
        LatencyRecorder recorder = new LatencyRecorder();
        int cardCount = dataset.bindings.size();
        int sampleCount = Math.min(iterations, cardCount);

        for (int i = 0; i < Math.min(100, sampleCount); i++) {
            long cardId = dataset.bindings.get(i % cardCount).cardId;
            try {
                sodService.detectConflicts(cardId);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
        }

        for (int i = 0; i < sampleCount; i++) {
            long cardId = dataset.bindings.get(i % cardCount).cardId;
            long start = recorder.start();
            try {
                sodService.detectConflicts(cardId);
            } catch (Exception e) { log.trace("benchmark exception: {}", e.getMessage()); }
            recorder.stop(start);
        }

        return recorder.snapshot();
    }

    private SodCorrectnessStats collectCorrectnessStats(
            NativeDataGenerator.NativeGeneratedDataSet dataset,
            Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap,
            int iterations) {
        SodCorrectnessStats stats = new SodCorrectnessStats();
        List<NativeDataGenerator.NativeEvalRequest> requests = dataset.evalRequests;

        for (int i = 0; i < iterations; i++) {
            NativeDataGenerator.NativeEvalRequest req = requests.get(i % requests.size());
            setupCardContext(req, bindingMap);

            // Static SoD check
            try {
                sodService.validateGrant(req.cardId, req.resourceType, req.actionCode);
            } catch (Exception e) {
                stats.staticViolationCount++;
            }

            // Dynamic SoD check
            try {
                sodService.checkDynamicSoD(req.resourceType, req.actionCode, null, req.userId);
            } catch (Exception e) {
                stats.dynamicViolationCount++;
            }

            stats.totalChecks++;
        }

        return stats;
    }

    public static class NativeSodResult {
        public LatencyRecorder.LatencySnapshot staticSodSnapshot;
        public LatencyRecorder.LatencySnapshot dynamicSodSnapshot;
        public LatencyRecorder.LatencySnapshot conflictDetectSnapshot;
        public SodCorrectnessStats correctnessStats;
        public int policyCount;
    }

    public static class SodCorrectnessStats {
        public long totalChecks;
        public long staticViolationCount;
        public long dynamicViolationCount;
    }
}
