package com.coreryblack.benchmark.util;

import com.coreryblack.benchmark.nativebenchmark.BenchmarkIdGenerator;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import com.coreryblack.benchmark.nativebenchmark.NativeScaleConfig;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BenchmarkDatasetValidatorTest {

    @Test
    void fixedSeedAndClockProduceTheSameNativeFingerprint() {
        NativeDataGenerator first = generator();
        first.setSeed(42L);
        first.setClock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        NativeDataGenerator.NativeGeneratedDataSet data1 = first.generate(config());

        NativeDataGenerator second = generator();
        second.setSeed(42L);
        second.setClock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        NativeDataGenerator.NativeGeneratedDataSet data2 = second.generate(config());

        assertEquals(BenchmarkDatasetValidator.nativeFingerprint(data1),
            BenchmarkDatasetValidator.nativeFingerprint(data2));
    }

    @Test
    void changingSeedChangesTheNativeFingerprint() {
        NativeDataGenerator first = generator();
        first.setSeed(42L);
        first.setClock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        NativeDataGenerator.NativeGeneratedDataSet data1 = first.generate(config());

        NativeDataGenerator second = generator();
        second.setSeed(43L);
        second.setClock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        NativeDataGenerator.NativeGeneratedDataSet data2 = second.generate(config());

        assertNotEquals(BenchmarkDatasetValidator.nativeFingerprint(data1),
            BenchmarkDatasetValidator.nativeFingerprint(data2));
    }

    @Test
    void generatedRequestsUseTheirCardBindingContext() {
        NativeDataGenerator generator = generator();
        generator.setSeed(42L);
        generator.setClock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        NativeDataGenerator.NativeGeneratedDataSet data = generator.generate(
            NativeScaleConfig.builder()
                .cardCount(20).templateCount(4).tenantCount(2)
                .baseRulesPerCard(5).overlayRulesPerCard(2)
                .resourceTypes(3).actionsPerResource(2).denyRatio(0.2)
                .build());

        BenchmarkDatasetValidator.requireNativeContextConsistency(data);
        assertEquals(2, data.bindings.stream().map(binding -> binding.tenantId).distinct().count());
    }

    @Test
    void cardOnlyRulesHaveDeterministicIdsReferencedBySnapshots() {
        NativeDataGenerator generator = generator();
        generator.setSeed(42L);
        generator.setClock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        NativeDataGenerator.NativeGeneratedDataSet data = generator.generate(
            NativeScaleConfig.builder()
                .cardCount(10).templateCount(2).permissionRulesPerCard(2)
                .baseRulesPerCard(2).overlayRulesPerCard(1)
                .resourceTypes(3).actionsPerResource(2).denyRatio(0.2)
                .build());

        var ruleIds = data.permissionRules.stream()
            .map(rule -> rule.getRuleId())
            .toList();
        assertEquals(data.permissionRules.size(), ruleIds.stream().distinct().count());
        assertTrue(ruleIds.stream().allMatch(java.util.Objects::nonNull));
        assertTrue(data.permSnapshots.stream()
            .allMatch(snapshot -> ruleIds.contains(snapshot.getRuleId())));
    }

    @Test
    void generatedTraceContainsAuditableCardOnlyHitRequests() {
        NativeDataGenerator generator = generator();
        generator.setSeed(42L);
        generator.setClock(Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC));
        NativeDataGenerator.NativeGeneratedDataSet data = generator.generate(
            NativeScaleConfig.builder()
                .cardCount(100).templateCount(2).permissionRulesPerCard(5)
                .baseRulesPerCard(2).overlayRulesPerCard(1)
                .resourceTypes(3).actionsPerResource(2).denyRatio(0.2)
                .build());

        var hitRequests = data.evalRequests.stream()
            .filter(request -> request.expectedCardOnlyHit)
            .toList();
        assertFalse(hitRequests.isEmpty());
        assertTrue(hitRequests.stream().allMatch(request ->
            request.expectedCardOnlyRuleId != null
                && request.expectedCardOnlyEffect != null
                && request.resourceId >= 1_000_000_000L));
        assertTrue(hitRequests.stream().allMatch(request -> data.bindings.stream()
            .filter(binding -> binding.cardId == request.cardId)
            .flatMap(binding -> binding.permissionRules.stream())
            .anyMatch(rule -> java.util.Objects.equals(rule.getRuleId(), request.expectedCardOnlyRuleId)
                && java.util.Objects.equals(rule.getResourceType(), request.resourceType)
                && java.util.Objects.equals(rule.getResourceId(), request.resourceId)
                && java.util.Objects.equals(rule.getActionCode(), request.actionCode)
                && java.util.Objects.equals(rule.getEffect(), request.expectedCardOnlyEffect))));
    }

    private static NativeDataGenerator generator() {
        return new NativeDataGenerator(
            new BenchmarkIdGenerator(),
            Mockito.mock(com.coreryblack.benchmark.nativebenchmark.DataPersistenceService.class),
            Mockito.mock(com.coreryblack.benchmark.nativebenchmark.RedisCacheService.class));
    }

    private static NativeScaleConfig config() {
        return NativeScaleConfig.builder()
            .cardCount(20).templateCount(4).tenantCount(2)
            .baseRulesPerCard(5).overlayRulesPerCard(2)
            .resourceTypes(3).actionsPerResource(2).denyRatio(0.2)
            .build();
    }
}
