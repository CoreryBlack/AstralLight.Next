package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.benchmark.nativebenchmark.NativeScaleConfig;
import com.coreryblack.benchmark.nativebenchmark.NativeDataGenerator;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.coreryblack.benchmark.util.RedisMemoryMeasurer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;

@Slf4j
public class NativeSpaceEfficiencyBenchmark {

    private static final long RULE_SET_ROW_SIZE = 460L;
    private static final long ENTRY_ROW_SIZE = 350L;
    private static final long REF_ROW_SIZE = 56L;
    private static final long SNAPSHOT_ROW_SIZE = 144L;
    private static final long PERMISSION_RULE_ROW_SIZE = 380L;
    private static final long PERMISSION_RULE_SNAPSHOT_ROW_SIZE = 200L;
    private static final long ABAC_CONDITION_ROW_SIZE = 512L;
    private static final long ABAC_REDIS_PER_CONDITION_BYTES = 256L;

    private final NativeDataGenerator nativeDataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final RedisMemoryMeasurer memoryMeasurer;

    public NativeSpaceEfficiencyBenchmark(NativeDataGenerator nativeDataGenerator,
                                            StringRedisTemplate redisTemplate) {
        this.nativeDataGenerator = nativeDataGenerator;
        this.redisTemplate = redisTemplate;
        this.memoryMeasurer = new RedisMemoryMeasurer(redisTemplate);
    }

    public NativeSpaceEfficiencyResult execute() {
        NativeScaleConfig config = NativeScaleConfig.nativeRq1Default();
        log.info("=== Native RQ1: Space Efficiency Benchmark (with ABAC + PERMISSION_RULE) ===");
        log.info("Scale: {} cards x {} base + {} overlay + {} cardOnly rules, abacRatio={}",
            config.getCardCount(), config.getBaseRulesPerCard(),
            config.getOverlayRulesPerCard(), config.getPermissionRulesPerCard(),
            config.getAbacConditionsPerRule() > 0 ? 1.0 : 0.0);

        NativeSpaceEfficiencyResult result = new NativeSpaceEfficiencyResult();
        result.config = config;

        result.astralStorageBytes = estimateAstralStorageBytes(config);
        result.astralSharedStorageMb = result.astralStorageBytes / (1024.0 * 1024.0);

        result.abacConditionBytes = estimateAbacStorageBytes(config);
        result.abacConditionMb = result.abacConditionBytes / (1024.0 * 1024.0);

        result.permissionRuleBytes = estimatePermissionRuleStorageBytes(config);
        result.permissionRuleMb = result.permissionRuleBytes / (1024.0 * 1024.0);

        result.multiTemplateOverheadBytes = estimateMultiTemplateOverhead(config);
        result.multiTemplateOverheadMb = result.multiTemplateOverheadBytes / (1024.0 * 1024.0);

        result.abacRedisOverheadBytes = estimateAbacRedisOverhead(config);
        result.abacRedisOverheadMb = result.abacRedisOverheadBytes / (1024.0 * 1024.0);

        RedisMemoryMeasurer.MemorySnapshot beforeRedis = memoryMeasurer.measure();
        LatencyRecorder storageLatency = new LatencyRecorder();

        long start = storageLatency.start();
        NativeDataGenerator.NativeGeneratedDataSet dataset = nativeDataGenerator.generate(config);
        nativeDataGenerator.persistToDatabase(dataset);
        nativeDataGenerator.populateRedisCache(dataset);
        storageLatency.stop(start);

        RedisMemoryMeasurer.MemorySnapshot afterRedis = memoryMeasurer.measure();

        // Use actual snapshot counts from generated dataset (accurate, accounts for dedup)
        result.snapshotCount = dataset.snapshots.size() + dataset.permSnapshots.size();

        result.astralRedisMemoryMb = afterRedis.usedMemoryMb() - beforeRedis.usedMemoryMb();
        result.astralRedisKeyCount = afterRedis.dbKeyCount - beforeRedis.dbKeyCount;

        result.astralSnapshot = storageLatency.snapshot();
        result.redisMemorySnapshot = afterRedis;

        result.totalStorageBytes = result.astralStorageBytes
            + result.abacConditionBytes
            + result.permissionRuleBytes;
        result.totalStorageMb = result.totalStorageBytes / (1024.0 * 1024.0);

        log.info("=== Native RQ1 Results ===");
        log.info("AstralLight Shared: storage={}MB, Redis={}MB",
            String.format("%.2f", result.astralSharedStorageMb),
            String.format("%.2f", result.astralRedisMemoryMb));
        log.info("ABAC conditions: {}MB (DB) + {}MB (Redis overhead)",
            String.format("%.2f", result.abacConditionMb),
            String.format("%.2f", result.abacRedisOverheadMb));
        log.info("PERMISSION_RULE snapshots: {}MB",
            String.format("%.2f", result.permissionRuleMb));
        log.info("Multi-template overhead: {}MB",
            String.format("%.2f", result.multiTemplateOverheadMb));
        log.info("Snapshot count: {}", result.snapshotCount);
        log.info("Total storage: {}MB ({} bytes)",
            String.format("%.2f", result.totalStorageMb), result.totalStorageBytes);

        return result;
    }

    private long estimateAstralStorageBytes(NativeScaleConfig config) {
        int tplCount = Math.max(1, config.getTemplateCount());
        long baseEntriesBytes = (long) tplCount * config.getBaseRulesPerCard() * ENTRY_ROW_SIZE;
        long overlayEntriesBytes = (long) tplCount * config.getOverlayRulesPerCard() * ENTRY_ROW_SIZE;
        long ruleSetBytes = (long) tplCount * 2L * RULE_SET_ROW_SIZE;
        long refBytes = (long) config.getCardCount() * REF_ROW_SIZE;
        long snapshotBytes = (long) tplCount * (config.getBaseRulesPerCard() + config.getOverlayRulesPerCard()) * SNAPSHOT_ROW_SIZE;
        return baseEntriesBytes + overlayEntriesBytes + ruleSetBytes + refBytes + snapshotBytes;
    }

    private long estimateAbacStorageBytes(NativeScaleConfig config) {
        long abacCardCount = (long) (config.getCardCount() * (config.getAbacConditionsPerRule() > 0 ? 1.0 : 0.0));
        return abacCardCount * ABAC_CONDITION_ROW_SIZE;
    }

    private long estimatePermissionRuleStorageBytes(NativeScaleConfig config) {
        long permRuleRows = (long) config.getCardCount() * config.getPermissionRulesPerCard();
        long permRuleBytes = permRuleRows * PERMISSION_RULE_ROW_SIZE;
        long permSnapshotBytes = permRuleRows * PERMISSION_RULE_SNAPSHOT_ROW_SIZE;
        return permRuleBytes + permSnapshotBytes;
    }

    private long estimateMultiTemplateOverhead(NativeScaleConfig config) {
        int templateCount = Math.max(1, config.getTemplateCount());
        long overhead = 0;
        for (int t = 0; t < templateCount; t++) {
            overhead += RULE_SET_ROW_SIZE;
            overhead += RULE_SET_ROW_SIZE;
            overhead += (long) config.getBaseRulesPerCard() * ENTRY_ROW_SIZE;
            if (config.getOverlayRulesPerCard() > 0) {
                overhead += (long) config.getOverlayRulesPerCard() * ENTRY_ROW_SIZE;
            }
            overhead += (long) (config.getBaseRulesPerCard() + config.getOverlayRulesPerCard()) * SNAPSHOT_ROW_SIZE;
        }
        return overhead;
    }

    private long estimateAbacRedisOverhead(NativeScaleConfig config) {
        long abacCardCount = (long) (config.getCardCount() * (config.getAbacConditionsPerRule() > 0 ? 1.0 : 0.0));
        return abacCardCount * ABAC_REDIS_PER_CONDITION_BYTES;
    }

    public String toLatexTable(NativeSpaceEfficiencyResult r) {
        return """
            \\begin{table}[htbp]
            \\centering
            \\caption{Native Storage Efficiency: Shared Model with ABAC and PERMISSION\\_RULE}
            \\label{tab:native-rq1-storage}
            \\begin{tabular}{lr}
            \\toprule
            \\textbf{Metric} & \\textbf{Value} \\\\
            \\midrule
            Shared Storage (MB) & %.2f \\\\
            ABAC Conditions (MB) & %.2f \\\\
            PERMISSION\\_RULE (MB) & %.2f \\\\
            Multi-Template Overhead (MB) & %.2f \\\\
            ABAC Redis Overhead (MB) & %.2f \\\\
            Total Storage (MB) & %.2f \\\\
            Snapshot Count & %d \\\\
            Redis Memory (MB) & %.2f \\\\
            Redis Key Count & %d \\\\
            \\bottomrule
            \\end{tabular}
            \\end{table}
            """.formatted(
                r.astralSharedStorageMb, r.abacConditionMb, r.permissionRuleMb,
                r.multiTemplateOverheadMb, r.abacRedisOverheadMb,
                r.totalStorageMb, r.snapshotCount,
                r.astralRedisMemoryMb, r.astralRedisKeyCount);
    }

    public static class NativeSpaceEfficiencyResult {
        public NativeScaleConfig config;
        public long astralStorageBytes;
        public double astralSharedStorageMb;
        public long snapshotCount;
        public long abacConditionBytes;
        public double abacConditionMb;
        public long permissionRuleBytes;
        public double permissionRuleMb;
        public long multiTemplateOverheadBytes;
        public double multiTemplateOverheadMb;
        public long abacRedisOverheadBytes;
        public double abacRedisOverheadMb;
        public double astralRedisMemoryMb;
        public long astralRedisKeyCount;
        public long totalStorageBytes;
        public double totalStorageMb;
        public LatencyRecorder.LatencySnapshot astralSnapshot;
        public RedisMemoryMeasurer.MemorySnapshot redisMemorySnapshot;
    }
}
