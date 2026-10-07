package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.*;
import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Benchmark Redis 缓存服务。
 * 从 NativeDataGenerator 中提取，负责填充和清理基准测试的 Redis 缓存。
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisCacheService {

    private static final int PIPELINE_BATCH_SIZE = 5000;

    private final StringRedisTemplate redisTemplate;

    public void populateAll(NativeDataGenerator.NativeGeneratedDataSet dataset) {
        log.info("[Native] Populating Redis cache for {} cards (pipelined)...", dataset.bindings.size());

        Map<Long, List<RuleSet>> templateRuleSetMap = new LinkedHashMap<>();
        for (RuleSet rs : dataset.ruleSets) {
            templateRuleSetMap.computeIfAbsent(rs.getSourceId(), k -> new ArrayList<>()).add(rs);
        }

        Map<Long, List<RuleSetEntry>> ruleSetEntriesMap = dataset.entries.stream()
            .collect(java.util.stream.Collectors.groupingBy(RuleSetEntry::getRuleSetId));

        populateRuleSetSnapshots(dataset.ruleSets, ruleSetEntriesMap);
        populateCardBindings(dataset.bindings);
        populateAbacConditions(dataset.abacConditions);

        log.info("[Native] Redis cache populated: {} ruleSets, {} card statuses, {} card contexts, {} abac conditions",
            dataset.ruleSets.size(), dataset.bindings.size(), dataset.bindings.size(),
            dataset.abacConditions.size());
    }

    private void populateRuleSetSnapshots(List<RuleSet> ruleSets,
                                            Map<Long, List<RuleSetEntry>> ruleSetEntriesMap) {
        redisTemplate.executePipelined((org.springframework.data.redis.core.RedisCallback<Object>) connection -> {
            for (RuleSet rs : ruleSets) {
                String hashKey = "perm:ruleset:" + rs.getTenantId() + ":" + rs.getRuleSetId();
                List<RuleSetEntry> entries = ruleSetEntriesMap.getOrDefault(rs.getRuleSetId(), Collections.emptyList());
                Map<byte[], byte[]> fields = new HashMap<>();
                for (RuleSetEntry entry : BenchmarkWinnerSelector.select(entries).values()) {
                    String resourceKey = entry.getResourceType() + ":" +
                        (entry.getResourceId() != null ? entry.getResourceId() : "*");
                    String field = "snapshot:" + resourceKey + ":" + entry.getActionCode();
                    fields.put(field.getBytes(StandardCharsets.UTF_8),
                        entry.getEffect().getBytes(StandardCharsets.UTF_8));
                }
                if (!fields.isEmpty()) {
                    connection.hashCommands().hMSet(hashKey.getBytes(StandardCharsets.UTF_8), fields);
                }
            }
            return null;
        });
    }

    private void populateCardBindings(List<NativeDataGenerator.NativeCardBinding> bindings) {
        for (int offset = 0; offset < bindings.size(); offset += PIPELINE_BATCH_SIZE) {
            int end = Math.min(offset + PIPELINE_BATCH_SIZE, bindings.size());
            List<NativeDataGenerator.NativeCardBinding> chunk = bindings.subList(offset, end);

            redisTemplate.executePipelined((org.springframework.data.redis.core.RedisCallback<Object>) connection -> {
                for (NativeDataGenerator.NativeCardBinding binding : chunk) {
                    // Card refs
                    List<Map<String, Object>> refList = new ArrayList<>();
                    if (binding.baseRef != null) {
                        Map<String, Object> baseMap = new LinkedHashMap<>();
                        baseMap.put("cardId", binding.cardId);
                        baseMap.put("ruleSetId", binding.baseRef.getRuleSetId());
                        baseMap.put("tenantId", binding.tenantId);
                        baseMap.put("refType", "BASE");
                        refList.add(baseMap);
                    }
                    for (CardRuleSetRef overlayRef : binding.overlayRefs) {
                        Map<String, Object> overlayMap = new LinkedHashMap<>();
                        overlayMap.put("cardId", binding.cardId);
                        overlayMap.put("ruleSetId", overlayRef.getRuleSetId());
                        overlayMap.put("tenantId", binding.tenantId);
                        overlayMap.put("refType", "OVERLAY");
                        refList.add(overlayMap);
                    }
                    if (!refList.isEmpty()) {
                        String refsJson = toJsonArray(refList);
                        connection.stringCommands().set(
                            ("perm:refs:" + binding.tenantId + ":" + binding.cardId).getBytes(StandardCharsets.UTF_8),
                            refsJson.getBytes(StandardCharsets.UTF_8));
                    }

                    // Card status
                    connection.stringCommands().set(
                        ("perm:card:status:" + binding.cardId).getBytes(StandardCharsets.UTF_8),
                        binding.cardStatus.getBytes(StandardCharsets.UTF_8));

                    // Card context hash
                    Map<byte[], byte[]> ctxFields = new HashMap<>();
                    ctxFields.put("userId".getBytes(StandardCharsets.UTF_8), String.valueOf(binding.userId).getBytes(StandardCharsets.UTF_8));
                    ctxFields.put("domainId".getBytes(StandardCharsets.UTF_8), String.valueOf(binding.domainId).getBytes(StandardCharsets.UTF_8));
                    ctxFields.put("tenantId".getBytes(StandardCharsets.UTF_8), String.valueOf(binding.tenantId).getBytes(StandardCharsets.UTF_8));
                    ctxFields.put("templateId".getBytes(StandardCharsets.UTF_8), String.valueOf(binding.templateId).getBytes(StandardCharsets.UTF_8));
                    ctxFields.put("cardType".getBytes(StandardCharsets.UTF_8), binding.cardType.getBytes(StandardCharsets.UTF_8));
                    ctxFields.put("cardStatus".getBytes(StandardCharsets.UTF_8), binding.cardStatus.getBytes(StandardCharsets.UTF_8));
                    connection.hashCommands().hMSet(
                        ("perm:card:ctx:" + binding.cardId).getBytes(StandardCharsets.UTF_8),
                        ctxFields);
                }
                return null;
            });

            if (end % 50000 == 0 || end >= bindings.size()) {
                log.info("  Redis populated {}/{} cards", end, bindings.size());
            }
        }
    }

    private void populateAbacConditions(List<NativeDataGenerator.AbacCondition> abacConditions) {
        if (!abacConditions.isEmpty()) {
            redisTemplate.executePipelined((org.springframework.data.redis.core.RedisCallback<Object>) connection -> {
                for (NativeDataGenerator.AbacCondition abac : abacConditions) {
                    Map<byte[], byte[]> abacFields = new HashMap<>();
                    abacFields.put("conditionType".getBytes(StandardCharsets.UTF_8), abac.conditionType.getBytes(StandardCharsets.UTF_8));
                    abacFields.put("conditionJson".getBytes(StandardCharsets.UTF_8), abac.conditionJson.getBytes(StandardCharsets.UTF_8));
                    abacFields.put("cardId".getBytes(StandardCharsets.UTF_8), String.valueOf(abac.cardId).getBytes(StandardCharsets.UTF_8));
                    connection.hashCommands().hMSet(
                        ("perm:abac:" + abac.cardId).getBytes(StandardCharsets.UTF_8),
                        abacFields);
                }
                return null;
            });
        }
    }

    /**
     * Flush all Redis caches. Uses FLUSHDB instead of SCAN+DELETE because
     * the benchmark runs against an exclusive Redis instance — no other data
     * to preserve. FLUSHDB is a single-command O(1) operation vs SCAN which
     * requires multiple roundtrips.
     */
    public void flushAllCaches() {
        try (var conn = redisTemplate.getConnectionFactory().getConnection()) {
            conn.serverCommands().flushDb();
            log.debug("[Native] Redis FLUSHDB executed");
        } catch (Exception e) {
            log.warn("[Native] Redis FLUSHDB failed: {}", e.getMessage());
        }
    }

    private String toJsonArray(List<Map<String, Object>> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("{");
            Map<String, Object> map = list.get(i);
            int j = 0;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                if (j > 0) sb.append(",");
                sb.append("\"").append(entry.getKey()).append("\":");
                Object val = entry.getValue();
                if (val instanceof Number) {
                    sb.append(val);
                } else {
                    sb.append("\"").append(val).append("\"");
                }
                j++;
            }
            sb.append("}");
        }
        sb.append("]");
        return sb.toString();
    }
}
