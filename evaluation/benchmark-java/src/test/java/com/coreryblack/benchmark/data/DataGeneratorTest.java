package com.coreryblack.benchmark.data;

import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.*;
import com.coreryblack.astral_platform.persistence.mapper.PlatformDomainMapper;
import com.coreryblack.astral_identity.persistence.mapper.PlatformUserMapper;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.*;
import com.coreryblack.astral_permission.infrastructure.persistence.mapper.*;
import com.coreryblack.benchmark.config.ScaleConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DataGeneratorTest {

    @Mock
    private RuleSetMapper ruleSetMapper;
    @Mock
    private RuleSetEntryMapper entryMapper;
    @Mock
    private RuleSetSnapshotMapper snapshotMapper;
    @Mock
    private CardRuleSetRefMapper cardRefMapper;
    @Mock
    private UserCardMapper userCardMapper;
    @Mock
    private PlatformDomainMapper domainMapper;
    @Mock
    private PlatformUserMapper platformUserMapper;
    @Mock
    private UserCardTemplateMapper templateMapper;
    @Mock
    private PermissionRuleMapper permissionRuleMapper;
    @Mock
    private PermissionRuleSnapshotMapper permSnapshotMapper;
    @Mock
    private StringRedisTemplate redisTemplate;

    private DataGenerator dataGenerator;

    @BeforeEach
    void setUp() {
        dataGenerator = new DataGenerator(
            ruleSetMapper, entryMapper, snapshotMapper, cardRefMapper,
            userCardMapper, domainMapper, platformUserMapper,
            templateMapper, permissionRuleMapper, permSnapshotMapper,
            redisTemplate);
    }

    @Test
    void shouldGenerateDataSetWithBaseRulesOnly() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(10).baseRulesPerCard(5).overlayRulesPerCard(0)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        assertEquals(10, dataset.bindings.size());
        assertEquals(5, dataset.baseEntries.size());
        assertTrue(dataset.overlayEntries.isEmpty());
        assertNull(dataset.overlayRuleSet);
        assertNotNull(dataset.baseRuleSet);
        assertNotNull(dataset.template);
    }

    @Test
    void shouldGenerateDataSetWithOverlayRules() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(10).baseRulesPerCard(5).overlayRulesPerCard(3)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.3).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        assertEquals(10, dataset.bindings.size());
        assertEquals(5, dataset.baseEntries.size());
        assertEquals(3, dataset.overlayEntries.size());
        assertNotNull(dataset.overlayRuleSet);
        assertNotNull(dataset.baseRuleSet);
    }

    @Test
    void shouldSetTenantIdOnAllBindings() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(5).baseRulesPerCard(3).overlayRulesPerCard(0)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        for (DataGenerator.CardBinding binding : dataset.bindings) {
            assertEquals(1L, (long) binding.baseRef.getTenantId());
            assertEquals("BASE", binding.baseRef.getRefType());
        }
    }

    @Test
    void shouldSetOverlayRefTypeCorrectly() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(5).baseRulesPerCard(3).overlayRulesPerCard(2)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.3).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        for (DataGenerator.CardBinding binding : dataset.bindings) {
            assertNotNull(binding.overlayRef);
            assertEquals("OVERLAY", binding.overlayRef.getRefType());
            assertEquals(1L, (long) binding.overlayRef.getTenantId());
        }
    }

    @Test
    void shouldGenerateEvalRequestsWithCorrectCount() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(10).baseRulesPerCard(5).overlayRulesPerCard(0)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        assertEquals(100, dataset.evalRequests.size());
    }

    @Test
    void shouldCapEvalRequestsAt100K() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(20000).baseRulesPerCard(5).overlayRulesPerCard(0)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        assertEquals(100_000, dataset.evalRequests.size());
    }

    @Test
    void shouldAllEvalRequestsHaveValidCardIds() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(10).baseRulesPerCard(5).overlayRulesPerCard(0)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        for (DataGenerator.EvalRequest req : dataset.evalRequests) {
            assertTrue(req.cardId >= 1 && req.cardId <= 10,
                "Card ID " + req.cardId + " out of range [1, 10]");
            assertNotNull(req.resourceType);
            assertNotNull(req.actionCode);
        }
    }

    @Test
    void shouldAllBaseEntriesHaveEffectALLOW() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(5).baseRulesPerCard(10).overlayRulesPerCard(0)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        // P10 fix: BASE entries now use denyRatio too; with denyRatio=0.0, all should be ALLOW
        for (var entry : dataset.baseEntries) {
            assertEquals("ALLOW", entry.getEffect(),
                "All base entries should be ALLOW when denyRatio=0.0");
        }
    }

    @Test
    void shouldBaseEntriesHaveMixedEffectWithDenyRatio() {
        // T23 fix: test BASE entries with denyRatio > 0
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(5).baseRulesPerCard(100).overlayRulesPerCard(0)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.3).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        long allowCount = dataset.baseEntries.stream()
            .filter(e -> "ALLOW".equals(e.getEffect())).count();
        long denyCount = dataset.baseEntries.stream()
            .filter(e -> "DENY".equals(e.getEffect())).count();

        assertTrue(allowCount > 0, "Should have some ALLOW base entries");
        assertTrue(denyCount > 0, "Should have some DENY base entries with denyRatio=0.3");
    }

    @Test
    void shouldOverlayEntriesHaveMixedEffectWithDenyRatio() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(5).baseRulesPerCard(5).overlayRulesPerCard(100)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.3).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        long allowCount = dataset.overlayEntries.stream()
            .filter(e -> "ALLOW".equals(e.getEffect())).count();
        long denyCount = dataset.overlayEntries.stream()
            .filter(e -> "DENY".equals(e.getEffect())).count();

        assertTrue(allowCount > 0, "Should have some ALLOW entries");
        assertTrue(denyCount > 0, "Should have some DENY entries with denyRatio=0.3");
    }

    @Test
    void shouldPopulateRedisCacheWithPipelineCalls() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(3).baseRulesPerCard(3).overlayRulesPerCard(0)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        dataset.baseRuleSet.setRuleSetId(1L);

        dataGenerator.populateRedisCache(dataset);

        // Verify executePipelined was called (at least once for ruleset hashes + once for card data)
        verify(redisTemplate, atLeast(2)).executePipelined(any(RedisCallback.class));
    }

    @Test
    void shouldPopulateRedisCacheWithOverlayData() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(3).baseRulesPerCard(2).overlayRulesPerCard(2)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.3).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        dataset.baseRuleSet.setRuleSetId(1L);
        dataset.overlayRuleSet.setRuleSetId(2L);

        dataGenerator.populateRedisCache(dataset);

        // With overlay, should have at least 2 pipeline calls (ruleset hashes + card data)
        verify(redisTemplate, atLeast(2)).executePipelined(any(RedisCallback.class));
    }

    @Test
    void shouldGenerateReproducibleDataWithSameSeed() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(10).baseRulesPerCard(5).overlayRulesPerCard(0)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.0).build();

        dataGenerator.setSeed(42L);
        DataGenerator.GeneratedDataSet dataset1 = dataGenerator.generate(config);

        dataGenerator.setSeed(42L);
        DataGenerator.GeneratedDataSet dataset2 = dataGenerator.generate(config);

        assertEquals(dataset1.baseEntries.size(), dataset2.baseEntries.size());
        assertEquals(dataset1.evalRequests.size(), dataset2.evalRequests.size());
        for (int i = 0; i < dataset1.evalRequests.size(); i++) {
            assertEquals(dataset1.evalRequests.get(i).resourceType,
                dataset2.evalRequests.get(i).resourceType);
        }
    }

    @Test
    void shouldTemplateHaveCorrectFields() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(5).baseRulesPerCard(3).overlayRulesPerCard(0)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        assertNotNull(dataset.template);
        assertTrue(dataset.template.getTemplateName().startsWith("BenchmarkTemplate"),
                "Template name should start with BenchmarkTemplate, got: " + dataset.template.getTemplateName());
        assertEquals("STUDENT", dataset.template.getCardType());
        assertEquals("ACTIVE", dataset.template.getStatus());
    }

    @Test
    void shouldRuleSetHaveCorrectFields() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(5).baseRulesPerCard(3).overlayRulesPerCard(0)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);

        assertNotNull(dataset.baseRuleSet);
        assertEquals("TEMPLATE", dataset.baseRuleSet.getSourceType());
        assertEquals(1L, (long) dataset.baseRuleSet.getTenantId());
        assertEquals(1, (int) dataset.baseRuleSet.getEnabled());
    }

    @Test
    void shouldPersistToDatabaseInsertAllRequiredTables() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(3).baseRulesPerCard(3).overlayRulesPerCard(0)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        // Set ruleSetId since batchInsert doesn't auto-fill IDs like single insert does
        dataset.baseRuleSet.setRuleSetId(1L);

        dataGenerator.persistToDatabase(dataset);

        // Batch insert: each mapper is called once with a list
        verify(templateMapper, times(1)).batchInsert(ArgumentMatchers.<List<UserCardTemplate>>any());
        verify(ruleSetMapper, times(1)).batchInsert(ArgumentMatchers.<List<RuleSet>>any());
        verify(entryMapper, times(1)).batchInsert(ArgumentMatchers.<List<RuleSetEntry>>any());
        verify(snapshotMapper, atLeast(1)).batchInsert(ArgumentMatchers.<List<RuleSetSnapshot>>any());
        verify(cardRefMapper, times(1)).batchInsert(ArgumentMatchers.<List<CardRuleSetRef>>any());
        verify(userCardMapper, times(1)).batchInsert(ArgumentMatchers.<List<UserCard>>any());
    }

    @Test
    void shouldPersistToDatabaseCallBatchInsertOnEntryMapper() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(2).baseRulesPerCard(3).overlayRulesPerCard(0)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        dataset.baseRuleSet.setRuleSetId(1L);

        dataGenerator.persistToDatabase(dataset);

        // Verify batchInsert was called on the entry mapper
        verify(entryMapper, times(1)).batchInsert(ArgumentMatchers.<List<RuleSetEntry>>any());
    }

    @Test
    void shouldPersistToDatabaseWithOverlayRules() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(2).baseRulesPerCard(2).overlayRulesPerCard(2)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.3).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        dataset.baseRuleSet.setRuleSetId(1L);
        dataset.overlayRuleSet.setRuleSetId(2L);

        dataGenerator.persistToDatabase(dataset);

        // With overlay: ruleSetMapper.batchInsert called once for all rule sets (1 BASE + 1 OVERLAY)
        verify(ruleSetMapper, times(1)).batchInsert(ArgumentMatchers.<List<RuleSet>>any());
        // Entries batch includes both base and overlay entries
        verify(entryMapper, times(1)).batchInsert(ArgumentMatchers.<List<RuleSetEntry>>any());
        // Card refs: 2 cards × (1 BASE + 1 OVERLAY) = 4 refs
        verify(cardRefMapper, times(1)).batchInsert(ArgumentMatchers.<List<CardRuleSetRef>>any());
        verify(userCardMapper, times(1)).batchInsert(ArgumentMatchers.<List<UserCard>>any());
    }

    @Test
    void shouldPersistSnapshotWithDeduplication() {
        ScaleConfig config = ScaleConfig.builder()
            .cardCount(2).baseRulesPerCard(5).overlayRulesPerCard(0)
            .resourceTypes(2).actionsPerResource(1).denyRatio(0.0).build();

        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        dataset.baseRuleSet.setRuleSetId(1L);

        dataGenerator.persistToDatabase(dataset);

        // Snapshot batchInsert should be called at least once
        verify(snapshotMapper, atLeast(1)).batchInsert(ArgumentMatchers.<List<RuleSetSnapshot>>any());
        // At most 1 batch call for the deduplicated snapshots
        verify(snapshotMapper, atMost(1)).batchInsert(ArgumentMatchers.<List<RuleSetSnapshot>>any());
    }
}
