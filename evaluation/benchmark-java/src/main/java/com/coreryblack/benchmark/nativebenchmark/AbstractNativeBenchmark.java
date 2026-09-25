package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.benchmark.util.BenchmarkCleanupUtil;
import com.coreryblack.benchmark.util.BenchmarkMockRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Abstract base class for all native benchmark classes.
 * Extracts common context setup, policy context building, and utility methods
 * to eliminate code duplication across benchmark implementations.
 */
@Slf4j
public abstract class AbstractNativeBenchmark {

    protected static final int WARMUP_ITERATIONS = 1000;
    protected static final long BENCHMARK_TENANT_ID = 1L;

    protected final PolicyEngine policyEngine;
    protected final NativeDataGenerator nativeDataGenerator;
    protected final StringRedisTemplate redisTemplate;
    protected final JdbcTemplate jdbcTemplate;

    protected AbstractNativeBenchmark(PolicyEngine policyEngine,
                                      NativeDataGenerator nativeDataGenerator,
                                      StringRedisTemplate redisTemplate,
                                      JdbcTemplate jdbcTemplate) {
        this.policyEngine = policyEngine;
        this.nativeDataGenerator = nativeDataGenerator;
        this.redisTemplate = redisTemplate;
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Setup CardContextHolder from a NativeEvalRequest, using bindingMap to look up cardType/cardStatus.
     */
    protected void setupCardContext(NativeDataGenerator.NativeEvalRequest req,
                                    Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap) {
        IdentityCardContext ctx = new IdentityCardContext();
        ctx.setCardId(req.cardId);
        ctx.setUserId(req.userId);
        ctx.setDomainId(req.domainId);
        ctx.setTemplateId(req.templateId);
        ctx.setTenantId(req.tenantId);

        NativeDataGenerator.NativeCardBinding binding = bindingMap.get(req.cardId);
        if (binding != null) {
            ctx.setCardType(binding.cardType);
            ctx.setStatus(binding.cardStatus);
        } else {
            ctx.setCardType("STUDENT");
            ctx.setStatus("ACTIVE");
        }

        CardContextHolder.set(ctx);
    }

    /**
     * Setup CardContextHolder from a NativeEvalRequest, using instance-level currentBindingMap.
     * Used by benchmarks that store binding map as instance variable (e.g. NativeCacheFailureBenchmark).
     */
    protected void setupCardContext(NativeDataGenerator.NativeEvalRequest req,
                                    Map<Long, NativeDataGenerator.NativeCardBinding> currentBindingMap,
                                    boolean useInstanceMap) {
        setupCardContext(req, currentBindingMap);
    }

    /**
     * Setup CardContextHolder from a cardId only, looking up details from bindingMap.
     * Used by non-evaluation operations like rebuildSnapshot.
     */
    protected void setupCardContext(Long cardId,
                                    Map<Long, NativeDataGenerator.NativeCardBinding> bindingMap) {
        IdentityCardContext ctx = new IdentityCardContext();
        ctx.setCardId(cardId);
        ctx.setTenantId(BENCHMARK_TENANT_ID);

        NativeDataGenerator.NativeCardBinding binding = bindingMap.get(cardId);
        if (binding != null) {
            ctx.setUserId(binding.userId);
            ctx.setDomainId(binding.domainId);
            ctx.setTemplateId(binding.templateId);
            ctx.setCardType(binding.cardType);
            ctx.setStatus(binding.cardStatus);
        } else {
            ctx.setUserId(1L);
            ctx.setDomainId(1L);
            ctx.setTemplateId(1L);
            ctx.setCardType("STUDENT");
            ctx.setStatus("ACTIVE");
        }

        CardContextHolder.set(ctx);
    }

    /**
     * Build a PolicyContext from a NativeEvalRequest for policy evaluation.
     */
    protected PolicyContext buildPolicyContext(NativeDataGenerator.NativeEvalRequest req) {
        return PolicyContext.builder()
            .userId(req.userId)
            .cardId(req.cardId)
            .tenantId(req.tenantId)
            .domainId(req.domainId)
            .templateId(req.templateId)
            .resource(req.resourceType)
            .action(req.actionCode)
            .targetId(req.resourceId)
            .request(BenchmarkMockRequest.fromAbacContext(req.abacContext))
            .build();
    }

    /**
     * Build a PolicyContext with a custom tenantId (for multi-tenant benchmarks).
     */
    protected PolicyContext buildPolicyContext(NativeDataGenerator.NativeEvalRequest req, long tenantId) {
        return PolicyContext.builder()
            .userId(req.userId)
            .cardId(req.cardId)
            .tenantId(tenantId)
            .domainId(req.domainId)
            .templateId(req.templateId)
            .resource(req.resourceType)
            .action(req.actionCode)
            .targetId(req.resourceId)
            .request(BenchmarkMockRequest.fromAbacContext(req.abacContext))
            .build();
    }

    /**
     * Safely extract a double value from a Map, returning 0.0 if absent or not a Number.
     */
    protected double getDouble(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val instanceof Number ? ((Number) val).doubleValue() : 0.0;
    }

    /**
     * Cleanup all benchmark data (database + Redis).
     */
    protected void cleanupBenchmarkData() {
        // A native measurement is invalid if stale state survives cleanup.
        BenchmarkCleanupUtil.cleanupAllStrict(jdbcTemplate, redisTemplate);
    }

    /**
     * Shutdown an ExecutorService with a default 30-second timeout.
     */
    protected void shutdownExecutor(ExecutorService executor) {
        shutdownExecutor(executor, 30);
    }

    /**
     * Shutdown an ExecutorService with a configurable timeout in seconds.
     */
    protected void shutdownExecutor(ExecutorService executor, long timeoutSeconds) {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(timeoutSeconds, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
