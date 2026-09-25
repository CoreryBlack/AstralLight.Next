package com.coreryblack.benchmark.util;

import com.coreryblack.permission.auth.PolicyEngine;
import com.coreryblack.astral_general.common.context.CardContextHolder;
import com.coreryblack.astral_general.common.entity.identity.IdentityCardContext;
import com.coreryblack.astral_permission.contract.PolicyContext;
import com.coreryblack.astral_permission.contract.PolicyDecision;
import com.coreryblack.permission.permission.RuleSetService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.Cursor;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.ScanOptions;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BenchmarkValidityAuditTest {

    @Mock
    private PolicyEngine policyEngine;
    @Mock
    private RuleSetService ruleSetService;
    @Mock
    private JdbcTemplate jdbcTemplate;
    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private HashOperations<String, Object, Object> hashOperations;
    @Mock
    private Cursor<String> emptyCursor;

    private BenchmarkValidityAudit audit;

    @BeforeEach
    void setUp() {
        CardContextHolder.clear();
        when(redisTemplate.opsForHash()).thenReturn(hashOperations);
        when(emptyCursor.hasNext()).thenReturn(false);
        when(redisTemplate.scan(any(ScanOptions.class))).thenReturn(emptyCursor);
        audit = new BenchmarkValidityAudit(policyEngine, ruleSetService, jdbcTemplate, redisTemplate);
    }

    @AfterEach
    void tearDown() {
        CardContextHolder.clear();
    }

    private void mockSnapshotTableHasData(int count) {
        when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM rule_set_snapshot"), eq(Integer.class)))
            .thenReturn(count);
        doAnswer(invocation -> {
            RowCallbackHandler handler = invocation.getArgument(1);
            return null;
        }).when(jdbcTemplate).query(eq("SELECT final_effect, COUNT(*) as cnt FROM rule_set_snapshot GROUP BY final_effect"), any(RowCallbackHandler.class));
    }

    private void mockCardRefs() {
        when(jdbcTemplate.queryForList(eq("SELECT DISTINCT card_id FROM card_rule_set_ref LIMIT 10"), eq(Long.class)))
            .thenReturn(Arrays.asList(1L, 2L, 3L));
    }

    private void mockPolicyEngineAllows() {
        PolicyDecision allowed = new PolicyDecision();
        allowed.setAllowed(true);
        allowed.setReason("L1_RULESET_ALLOW");
        when(policyEngine.evaluate(any(PolicyContext.class))).thenReturn(allowed);
    }

    private void mockCacheStatsL1Hit() {
        Map<String, Object> cacheStats = new HashMap<>();
        cacheStats.put("l1HitRate", 0.95);
        cacheStats.put("l2HitRate", 0.0);
        cacheStats.put("l3HitRate", 0.0);
        cacheStats.put("totalEvaluations", 100L);
        when(policyEngine.getCacheHitStats()).thenReturn(cacheStats);
    }

    private void mockCacheStatsZero() {
        Map<String, Object> cacheStats = new HashMap<>();
        cacheStats.put("l1HitRate", 0.0);
        cacheStats.put("l2HitRate", 0.0);
        cacheStats.put("l3HitRate", 0.0);
        cacheStats.put("totalEvaluations", 0L);
        when(policyEngine.getCacheHitStats()).thenReturn(cacheStats);
    }

    @SuppressWarnings("unchecked")
    private void mockRedisKeysWithEntries(Set<String> keys, Map<Object, Object> entries) {
        Cursor<String> mockCursor = mock(Cursor.class);
        Iterator<String> it = keys.iterator();
        when(mockCursor.hasNext()).thenAnswer(inv -> it.hasNext());
        when(mockCursor.next()).thenAnswer(inv -> it.next());
        when(redisTemplate.scan(any(ScanOptions.class))).thenReturn(mockCursor);
        for (String key : keys) {
            when(hashOperations.entries(eq(key))).thenReturn(entries);
        }
    }

    @Test
    void shouldFailL1WhenSnapshotTableIsEmpty() {
        when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM rule_set_snapshot"), eq(Integer.class)))
            .thenReturn(0);

        boolean result = audit.runFullAudit();

        assertFalse(result, "L1 should fail when snapshot table is empty");
    }

    @Test
    void shouldFailL1WhenSnapshotCountIsNull() {
        when(jdbcTemplate.queryForObject(eq("SELECT COUNT(*) FROM rule_set_snapshot"), eq(Integer.class)))
            .thenReturn(null);

        boolean result = audit.runFullAudit();

        assertFalse(result, "L1 should fail when snapshot count is null");
    }

    @Test
    void shouldPassL1WhenSnapshotTableHasData() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();
        mockCacheStatsL1Hit();

        boolean result = audit.runFullAudit();

        assertTrue(result, "L1 should pass when snapshot table has data");
    }

    @Test
    void shouldL3AutoFixMissingCardContext() {
        CardContextHolder.clear();

        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();
        mockCacheStatsL1Hit();

        boolean result = audit.runFullAudit();

        assertTrue(result, "Full audit should pass when L3 auto-fixes context");
    }

    @Test
    void shouldL3PassWhenCardContextAlreadySet() {
        IdentityCardContext ctx = new IdentityCardContext();
        ctx.setCardId(1L);
        ctx.setUserId(1L);
        ctx.setTenantId(1L);
        ctx.setDomainId(1L);
        ctx.setTemplateId(1L);
        ctx.setCardType("PLATFORM_CARD");
        ctx.setStatus("ACTIVE");
        CardContextHolder.set(ctx);

        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();
        mockCacheStatsL1Hit();

        boolean result = audit.runFullAudit();

        assertTrue(result, "L3 should pass when CardContextHolder is already set");
    }

    @Test
    void shouldFailL2WhenRedisValuesAreJson() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockCacheStatsZero();

        Set<String> keys = new HashSet<>();
        keys.add("perm:ruleset:1:1");
        Map<Object, Object> badEntries = new LinkedHashMap<>();
        badEntries.put("snapshot:learn_subject:*:read", "{\"effect\":\"ALLOW\",\"resourceType\":\"learn_subject\"}");
        mockRedisKeysWithEntries(keys, badEntries);

        boolean result = audit.runFullAudit();

        assertFalse(result, "L2 should fail when Redis values are JSON objects");
    }

    @Test
    void shouldPassL2WhenRedisValuesArePlainStrings() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();
        mockCacheStatsL1Hit();

        Set<String> keys = new HashSet<>();
        keys.add("perm:ruleset:1:1");
        Map<Object, Object> goodEntries = new LinkedHashMap<>();
        goodEntries.put("snapshot:learn_subject:*:read", "ALLOW");
        goodEntries.put("snapshot:learn_level:*:create", "DENY");
        mockRedisKeysWithEntries(keys, goodEntries);

        boolean result = audit.runFullAudit();

        assertTrue(result, "L2 should pass when Redis values are plain strings");
    }

    @Test
    void shouldFailL4WhenDefaultDenyRateTooHigh() {
        mockSnapshotTableHasData(100);
        mockCardRefs();

        PolicyDecision defaultDeny = new PolicyDecision();
        defaultDeny.setAllowed(false);
        defaultDeny.setReason("DEFAULT_DENY");
        when(policyEngine.evaluate(any(PolicyContext.class))).thenReturn(defaultDeny);

        Map<String, Object> cacheStats = new HashMap<>();
        cacheStats.put("l1HitRate", 0.5);
        cacheStats.put("l2HitRate", 0.0);
        cacheStats.put("l3HitRate", 0.5);
        cacheStats.put("totalEvaluations", 100L);
        when(policyEngine.getCacheHitStats()).thenReturn(cacheStats);

        boolean result = audit.runFullAudit();

        assertFalse(result, "L4 should fail when DEFAULT_DENY rate > 90% (L5 should pass)");
    }

    @Test
    void shouldFailL4WhenCardDisabledRateTooHigh() {
        mockSnapshotTableHasData(100);
        mockCardRefs();

        PolicyDecision cardDisabled = new PolicyDecision();
        cardDisabled.setAllowed(false);
        cardDisabled.setReason("CARD_DISABLED");
        when(policyEngine.evaluate(any(PolicyContext.class))).thenReturn(cardDisabled);

        mockCacheStatsZero();

        boolean result = audit.runFullAudit();

        assertFalse(result, "L4 should fail when CARD_DISABLED rate > 50%");
    }

    @Test
    void shouldPassL4WhenDecisionsAreNormal() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();
        mockCacheStatsL1Hit();

        boolean result = audit.runFullAudit();

        assertTrue(result, "L4 should pass when decisions are normal");
    }

    @Test
    void shouldFailL5WhenAllDecisionsDefaultDeny() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();

        Map<String, Object> cacheStats = new HashMap<>();
        cacheStats.put("l1HitRate", 0.0);
        cacheStats.put("l2HitRate", 0.0);
        cacheStats.put("l3HitRate", 1.0);
        cacheStats.put("totalEvaluations", 100L);
        when(policyEngine.getCacheHitStats()).thenReturn(cacheStats);

        boolean result = audit.runFullAudit();

        assertFalse(result, "L5 should fail when 100% L3 hit rate");
    }

    @Test
    void shouldPassL5WhenL1CacheHits() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();
        mockCacheStatsL1Hit();

        boolean result = audit.runFullAudit();

        assertTrue(result, "L5 should pass when L1 cache hits");
    }

    @Test
    void shouldSkipL2WhenNoRedisKeys() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();
        mockCacheStatsL1Hit();

        boolean result = audit.runFullAudit();

        assertTrue(result, "Should pass when no Redis keys (skip L2)");
    }

    @Test
    void shouldSkipL4WhenNoCardRefs() {
        mockSnapshotTableHasData(100);

        when(jdbcTemplate.queryForList(eq("SELECT DISTINCT card_id FROM card_rule_set_ref LIMIT 10"), eq(Long.class)))
            .thenReturn(Collections.emptyList());

        mockCacheStatsZero();

        boolean result = audit.runFullAudit();

        assertTrue(result, "Should pass when no card refs (skip L4, skip L5 with 0 evals)");
    }

    @Test
    void shouldFailL5WhenL1AndL2BothZero() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();

        Map<String, Object> cacheStats = new HashMap<>();
        cacheStats.put("l1HitRate", 0.0);
        cacheStats.put("l2HitRate", 0.0);
        cacheStats.put("l3HitRate", 0.5);
        cacheStats.put("totalEvaluations", 100L);
        when(policyEngine.getCacheHitStats()).thenReturn(cacheStats);

        boolean result = audit.runFullAudit();

        assertFalse(result, "L5 should fail when L1=0% and L2=0%");
    }

    @Test
    void shouldPassL5WhenL2CacheHits() {
        mockSnapshotTableHasData(100);
        mockCardRefs();
        mockPolicyEngineAllows();

        Map<String, Object> cacheStats = new HashMap<>();
        cacheStats.put("l1HitRate", 0.0);
        cacheStats.put("l2HitRate", 0.8);
        cacheStats.put("l3HitRate", 0.2);
        cacheStats.put("totalEvaluations", 100L);
        when(policyEngine.getCacheHitStats()).thenReturn(cacheStats);

        boolean result = audit.runFullAudit();

        assertTrue(result, "L5 should pass when L2 cache hits (even if L1 misses)");
    }
}