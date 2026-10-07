package com.coreryblack.benchmark.rq1;

import com.coreryblack.benchmark.baseline.NaiveFullCopyAdapter;
import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.data.DataGenerator;
import com.coreryblack.benchmark.util.RedisMemoryMeasurer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

@Slf4j
public class SpaceEfficiencyBenchmark {

    private final DataGenerator dataGenerator;
    private final StringRedisTemplate redisTemplate;
    private final RedisMemoryMeasurer memoryMeasurer;
    private final JdbcTemplate jdbcTemplate;

    public SpaceEfficiencyBenchmark(DataGenerator dataGenerator,
                                     StringRedisTemplate redisTemplate,
                                     JdbcTemplate jdbcTemplate) {
        this.dataGenerator = dataGenerator;
        this.redisTemplate = redisTemplate;
        this.memoryMeasurer = new RedisMemoryMeasurer(redisTemplate);
        this.jdbcTemplate = jdbcTemplate;
    }

    public SpaceEfficiencyResult execute() {
        ScaleConfig config = ScaleConfig.rq1Default();
        log.info("=== RQ1: Space Efficiency Benchmark ===");
        log.info("Scale: {} cards × {} base + {} overlay rules = {} nominal rules",
            config.getCardCount(), config.getBaseRulesPerCard(),
            config.getOverlayRulesPerCard(), config.totalNominalRules());

        SpaceEfficiencyResult result = new SpaceEfficiencyResult();
        result.config = config;

        NaiveFullCopyAdapter naive = new NaiveFullCopyAdapter();
        naive.initialize(config);

        result.naiveFullCopyStorageMb = naive.estimateStorageBytes() / (1024.0 * 1024.0);
        result.naiveFullCopyMemoryMb = naive.estimateMemoryBytes() / (1024.0 * 1024.0);

        // B8 fix: use actual ANALYZE TABLE + information_schema instead of hardcoded row sizes
        DataGenerator.GeneratedDataSet dataset = dataGenerator.generate(config);
        dataGenerator.persistToDatabase(dataset);

        // Fix: measure Redis memory BEFORE populateRedisCache to get accurate delta
        RedisMemoryMeasurer.MemorySnapshot beforeRedis = memoryMeasurer.measure();
        dataGenerator.populateRedisCache(dataset);
        RedisMemoryMeasurer.MemorySnapshot afterRedis = memoryMeasurer.measure();

        result.astralSharedStorageMb = measureActualStorageMb();
        result.storageReductionRatio = 1.0 - (result.astralSharedStorageMb / result.naiveFullCopyStorageMb);
        result.astralRedisMemoryMb = afterRedis.usedMemoryMb() - beforeRedis.usedMemoryMb();
        result.astralRedisKeyCount = afterRedis.dbKeyCount - beforeRedis.dbKeyCount;

        // Measure actual table breakdown
        result.astralSharedModelBreakdown = measureActualBreakdown();

        log.info("=== RQ1 Results ===");
        log.info("Naive Full-Copy: storage={}MB, memory={}MB",
            String.format("%.2f", result.naiveFullCopyStorageMb), String.format("%.2f", result.naiveFullCopyMemoryMb));
        log.info("AstralLight Shared: storage={}MB, Redis={}MB",
            String.format("%.2f", result.astralSharedStorageMb), String.format("%.2f", result.astralRedisMemoryMb));
        log.info("Storage reduction: {}%", String.format("%.1f", result.storageReductionRatio * 100));

        return result;
    }

    /** B8 fix: measure actual storage via ANALYZE TABLE + information_schema */
    private double measureActualStorageMb() {
        String[] tables = {"rule_set", "rule_set_entry", "card_rule_set_ref", "rule_set_snapshot"};
        long totalBytes = 0;
        for (String table : tables) {
            try {
                jdbcTemplate.execute("ANALYZE TABLE " + table);
            } catch (Exception e) {
                log.warn("ANALYZE TABLE {} failed: {}", table, e.getMessage());
            }
        }
        for (String table : tables) {
            try {
                List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                    "SELECT DATA_LENGTH + INDEX_LENGTH AS total_bytes FROM information_schema.TABLES " +
                    "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '" + table + "'");
                if (!rows.isEmpty()) {
                    Object val = rows.get(0).get("total_bytes");
                    if (val instanceof Number) {
                        totalBytes += ((Number) val).longValue();
                    }
                }
            } catch (Exception e) {
                log.warn("Failed to query storage for {}: {}", table, e.getMessage());
            }
        }
        return totalBytes / (1024.0 * 1024.0);
    }

    /** B8 fix: measure actual per-table breakdown */
    private AstralStorageBreakdown measureActualBreakdown() {
        AstralStorageBreakdown breakdown = new AstralStorageBreakdown();
        breakdown.baseRuleSetMb = measureTableMb("rule_set");
        breakdown.baseEntriesMb = measureTableMb("rule_set_entry");
        breakdown.overlayRuleSetMb = 0; // included in rule_set above
        breakdown.overlayEntriesMb = 0; // included in rule_set_entry above
        breakdown.cardRefsMb = measureTableMb("card_rule_set_ref");
        breakdown.snapshotsMb = measureTableMb("rule_set_snapshot");
        breakdown.totalMb = breakdown.baseRuleSetMb + breakdown.baseEntriesMb +
            breakdown.overlayRuleSetMb + breakdown.overlayEntriesMb +
            breakdown.cardRefsMb + breakdown.snapshotsMb;
        return breakdown;
    }

    private double measureTableMb(String table) {
        try {
            jdbcTemplate.execute("ANALYZE TABLE " + table);
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "SELECT DATA_LENGTH + INDEX_LENGTH AS total_bytes FROM information_schema.TABLES " +
                "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '" + table + "'");
            if (!rows.isEmpty()) {
                Object val = rows.get(0).get("total_bytes");
                if (val instanceof Number) {
                    return ((Number) val).longValue() / (1024.0 * 1024.0);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to measure table {}: {}", table, e.getMessage());
        }
        return 0.0;
    }

    public String toLatexTable(SpaceEfficiencyResult r) {
        return """
            \\begin{table}[htbp]
            \\centering
            \\caption{Storage Efficiency: Traditional Full-Copy vs AstralLight Shared Model}
            \\label{tab:rq1-storage}
            \\begin{tabular}{lrr}
            \\toprule
            \\textbf{Metric} & \\textbf{Full-Copy} & \\textbf{AstralLight} \\\\
            \\midrule
            Persistent Storage (MB) & %.2f & %.2f \\\\
            Redis Memory (MB) & N/A & %.2f \\\\
            Nominal Rules & %d & %d \\\\
            Actual Stored Rules & %d & %d \\\\
            Storage Reduction & — & %.1f\\%% \\\\
            \\bottomrule
            \\end{tabular}
            \\end{table}
            """.formatted(
                r.naiveFullCopyStorageMb, r.astralSharedStorageMb,
                r.astralRedisMemoryMb,
                r.config.totalNominalRules(), r.config.totalNominalRules(),
                r.config.totalNominalRules(), r.config.getBaseRulesPerCard() + r.config.getOverlayRulesPerCard(),
                r.storageReductionRatio * 100);
    }

    public static class SpaceEfficiencyResult {
        public ScaleConfig config;
        public double naiveFullCopyStorageMb;
        public double naiveFullCopyMemoryMb;
        public double astralSharedStorageMb;
        public double astralRedisMemoryMb;
        public long astralRedisKeyCount;
        public double storageReductionRatio;
        public AstralStorageBreakdown astralSharedModelBreakdown;
    }

    public static class AstralStorageBreakdown {
        public double baseRuleSetMb;
        public double baseEntriesMb;
        public double overlayRuleSetMb;
        public double overlayEntriesMb;
        public double cardRefsMb;
        public double snapshotsMb;
        public double totalMb;
    }
}
