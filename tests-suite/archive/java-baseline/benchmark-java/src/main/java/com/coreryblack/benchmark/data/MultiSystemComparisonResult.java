package com.coreryblack.benchmark.data;

import com.coreryblack.benchmark.config.ScaleConfig;
import com.coreryblack.benchmark.util.LatencyRecorder;
import com.coreryblack.benchmark.util.MemoryFootprintMeasurer;

import java.util.*;

/**
 * Data structures for multi-system comparative benchmark results.
 *
 * <h3>Comparison Layers</h3>
 * <ol>
 *   <li><b>Direct Authorization Engines</b>: Casbin, OPA, Cedar</li>
 *   <li><b>Literature Comparison</b>: RBAC96, ABAC, UCON, NGAC, Zanzibar (Related Work only)</li>
 * </ol>
 *
 * <h3>Fairness Validations</h3>
 * <ol>
 *   <li><b>P2</b>: Memory Footprint — heap usage per system at scale</li>
 *   <li><b>P3</b>: Cold/Hot Start Ratio — cold/hot latency ratio across systems</li>
 *   <li><b>P4</b>: Rule Change Cost — recovery time after single rule change</li>
 *   <li><b>P5</b>: Cache Isolation — snapshot vs Redis vs DB-only contribution</li>
 *   <li><b>P6</b>: Standard Deviation — mean ± stddev in all tables</li>
 * </ol>
 */
public class MultiSystemComparisonResult {

    /** Individual system result at a single scale point */
    public static class SystemResult {
        public String systemLabel;
        public LatencyRecorder.LatencySnapshot singleThreadSnapshot;
        public LatencyRecorder.LatencySnapshot concurrentSnapshot;
        public LatencyRecorder.LatencySnapshot coldStartSnapshot;
        public int totalPolicies;       // total policy/rules/tuples loaded
        public long initTimeMs;         // initialization time in ms
        public String optimizationLevel; // DEFAULT or OPTIMIZED
        /** P2: Memory footprint after full initialization */
        public MemoryFootprintMeasurer.FootprintResult memoryFootprint;
        /** P3: Cold/hot start ratio (cold mean / hot mean). >1 means cold is slower. */
        public double coldHotRatio;
        /** Error message when a system crashes (OOM, timeout, etc.) at this scale point */
        public String errorMessage;
    }

    /** All system results at a single scale point */
    public static class ScalePoint {
        public ScaleConfig scale;
        public List<SystemResult> systemResults = new ArrayList<>();
        /** Per-card mean latency (μs). Populated by single-thread comparison. */
        public List<CardLatencyPoint> cardLatencyUs = new ArrayList<>();

        public SystemResult getResult(String systemLabel) {
            return systemResults.stream()
                .filter(r -> r.systemLabel.equals(systemLabel))
                .findFirst().orElse(null);
        }

        public List<SystemResult> getOptimizedResults() {
            return systemResults.stream()
                .filter(r -> "OPTIMIZED".equals(r.optimizationLevel))
                .toList();
        }
    }

    /** Complete benchmark results across all scales */
    public static class BenchmarkResult {
        public List<ScalePoint> scalePoints = new ArrayList<>();
        public List<ComplexityPoint> complexityPoints = new ArrayList<>();
        public List<CardScalePoint> cardScalePoints = new ArrayList<>();
        /** RQ-Compare-3: Rule Update Overhead per system */
        public List<RuleChangeCostPoint> ruleChangeCosts = new ArrayList<>();
        public Map<String, String> metadata = new LinkedHashMap<>();
        /** P2: Memory footprint measurements across systems */
        public List<ColdHotRatioPoint> coldHotRatios = new ArrayList<>();
        public Map<String, String> fairnessMetadata = new LinkedHashMap<>();

        public void addMetadata(String key, String value) {
            metadata.put(key, value);
        }
    }

    /** P3: Cold/hot start latency ratio per system */
    public static class ColdHotRatioPoint {
        public String systemLabel;
        public double coldMeanUs;
        public double hotMeanUs;
        public double ratio;          // cold/hot (>1 = cold slower)
        public int scaleCards;
    }

    /** P5: Cache isolation decomposition point */
    public static class CacheDecompositionPoint {
        public int cardCount;
        public double noCacheMeanUs;
        public double redisOnlyMeanUs;
        public double snapshotRedisMeanUs;
        public double architectureGainPct;
        public double cacheGainPct;
    }

    /** Rule complexity sensitivity result */
    public static class ComplexityPoint {
        public int rulesPerCard;
        public Map<String, LatencyRecorder.LatencySnapshot> systemSnapshots = new LinkedHashMap<>();
    }

    /** Card count scalability result */
    public static class CardScalePoint {
        public int cardCount;
        public Map<String, LatencyRecorder.LatencySnapshot> systemSnapshots = new LinkedHashMap<>();
    }

    /** Per-card latency for distribution analysis. Populated in single-thread mode. */
    public static class CardLatencyPoint {
        public final long cardId;
        public final double meanLatencyUs;
        public CardLatencyPoint(long cardId, double meanLatencyUs) {
            this.cardId = cardId;
            this.meanLatencyUs = meanLatencyUs;
        }
    }

    /** RQ-Compare-3: Rule Update Overhead — incremental compile vs full reload */
    public static class RuleChangeCostPoint {
        public int cardCount;
        public int rulesPerCard;
        public String systemLabel;
        public String updateMethod;        // e.g. "Incremental Compile", "Policy Reload", "Bundle Reload", "Index Rebuild"
        public double updateMeanUs;
        public double updateP99Us;
        public double preUpdateLatencyUs;   // decision latency before change
        public double postUpdateLatencyUs;  // decision latency after change

        public static String latexHeader() {
            return "\\textbf{System} & \\textbf{Update Method} & \\textbf{Update (us)} & \\textbf{P99 (us)} & \\textbf{Pre-Update (us)} & \\textbf{Post-Update (us)} \\\\";
        }

        public String toLatexRow() {
            return String.format("%s & %s & %.1f & %.1f & %.1f & %.1f \\\\",
                systemLabel, updateMethod, updateMeanUs, updateP99Us,
                preUpdateLatencyUs, postUpdateLatencyUs);
        }
    }

    // ────────────── Pre-defined comparison matrices ──────────────

    /**
     * Returns the full system list for Layer 1 comparison
     * (Direct Authorization Engines: RBAC/ABAC/Policy evaluation).
     */
    public static String[] layer1Systems() {
        return new String[]{
            "AstralLight(Optimized)",
            "Casbin", "Casbin(Cached)",
            "OPA(REST)", "OPA(NoCache)",
            "Cedar(Optimized)"
        };
    }

    /**
     * Returns the best-practice system list (optimized only).
     * This is the primary comparison set for Layer 1 (Decision Latency).
     */
    public static String[] bestPracticeSystems() {
        return new String[]{
            "AstralLight",
            "Casbin(Cached)",
            "OPA(NoCache)",
            "Cedar(Optimized)"
        };
    }

    /**
     * Layer 2 relational authorization comparison has been removed.
     */
    public static String[] layer2Systems() {
        return new String[0];
    }

    /**
     * Returns the standard gradient scales for multi-system comparison.
     */
    /** Aligned with NativeScaleConfig.nativeGradientScale() — same card/rule/deny/templateCount. */
    public static ScaleConfig[] comparisonGradient() {
        return ScaleConfig.gradientScale();
    }

    /**
     * Generates the "Comparison Dimension" matrix for the benchmark report.
     * Maps each system to the capabilities being compared.
     *
     * <p>ABAC is marked with $\triangle$ (PARTIAL) for Casbin/OPA/Cedar because
     * the adapters receive no ABAC payload in the common-subset comparison; only
     * AstralLight evaluates ABAC conditions in the native suite. The same nuance
     * is captured in {@link com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix}.</p>
     */
    public static String generateComparisonDimensionTable() {
        StringBuilder sb = new StringBuilder();
        sb.append("\\begin{table}[htbp]\n");
        sb.append("\\centering\n");
        sb.append("\\caption{Comparison Dimensions Across Authorization Systems}\n");
        sb.append("\\label{tab:comparison-dimensions}\n");
        sb.append("\\begin{tabular}{lcccc}\n");
        sb.append("\\toprule\n");
        sb.append("\\textbf{Dimension} & \\textbf{Casbin} & \\textbf{OPA} & \\textbf{Cedar} & \\textbf{AstralLight} \\\\\n");
        sb.append("\\midrule\n");
        sb.append("Policy Evaluation & \\checkmark & \\checkmark & \\checkmark & \\checkmark \\\\\n");
        sb.append("RBAC Support & \\checkmark & \\checkmark & \\checkmark & \\checkmark \\\\\n");
        sb.append("ABAC Support & $\\triangle$ & $\\triangle$ & $\\triangle$ & \\checkmark \\\\\n");
        sb.append("Rule Set Reuse (Shared) & -- & -- & -- & \\checkmark \\\\\n");
        sb.append("Multi-Source Governance & -- & -- & -- & \\checkmark \\\\\n");
        sb.append("Incremental Compilation & -- & -- & -- & \\checkmark \\\\\n");
        sb.append("Snapshot Consistency & -- & -- & -- & \\checkmark \\\\\n");
        sb.append("Template-Level Sharing & -- & -- & -- & \\checkmark \\\\\n");
        sb.append("OVERLAY Priority Chain & -- & -- & -- & \\checkmark \\\\\n");
        sb.append("\\bottomrule\n");
        sb.append("\\end{tabular}\n");
        sb.append("\n% $\\triangle$ = PARTIAL: Casbin/OPA/Cedar adapters receive no ABAC payload in the\n");
        sb.append("% common-subset comparison; AstralLight evaluates ABAC in the native suite only.\n");
        sb.append("% Full capability detail: see BaselineCapabilityMatrix (capability_matrix.tex).\n");
        sb.append("\\end{table}\n");
        return sb.toString();
    }

    // ────────────── Fairness Validation Table Generators ──────────────

    /**
     * P3: Generates the Cold/Hot Start Ratio LaTeX table.
     */
    public static String generateColdHotRatioTable(List<ColdHotRatioPoint> points) {
        StringBuilder sb = new StringBuilder();
        sb.append("\\begin{table}[htbp]\n");
        sb.append("\\centering\n");
        sb.append("\\caption{Cold-Start vs Hot-Start Latency Ratio Across Systems}\n");
        sb.append("\\label{tab:cold-hot-ratio}\n");
        sb.append("\\begin{tabular}{lrrrr}\n");
        sb.append("\\toprule\n");
        sb.append("\\textbf{System} & \\textbf{Cold (us)} & \\textbf{Hot (us)} & " +
            "\\textbf{Ratio} & \\textbf{Cards} \\\\\n");
        sb.append("\\midrule\n");
        for (ColdHotRatioPoint p : points) {
            sb.append(String.format("%s & %.1f & %.1f & $%.2f\\times$ & %d \\\\\n",
                p.systemLabel, p.coldMeanUs, p.hotMeanUs, p.ratio, p.scaleCards));
        }
        sb.append("\\bottomrule\n");
        sb.append("\\end{tabular}\n");
        sb.append("\\end{table}\n");
        return sb.toString();
    }

    /**
     * P2: Generates the Memory Footprint comparison LaTeX table.
     */
    public static String generateMemoryFootprintTable(
            List<MemoryFootprintMeasurer.FootprintResult> footprints) {
        StringBuilder sb = new StringBuilder();
        sb.append("\\begin{table}[htbp]\n");
        sb.append("\\centering\n");
        sb.append("\\caption{Runtime Memory Footprint Comparison}\n");
        sb.append("\\label{tab:memory-footprint}\n");
        sb.append("\\begin{tabular}{lrrrrr}\n");
        sb.append("\\toprule\n");
        sb.append(MemoryFootprintMeasurer.FootprintResult.latexHeader()).append("\n");
        sb.append("\\midrule\n");
        for (MemoryFootprintMeasurer.FootprintResult f : footprints) {
            sb.append(f.toLatexRow()).append("\n");
        }
        sb.append("\\bottomrule\n");
        sb.append("\\end{tabular}\n");
        sb.append("\\end{table}\n");
        return sb.toString();
    }

    /**
     * P5: Generates the Cache Isolation Decomposition LaTeX table.
     */
    public static String generateCacheDecompositionTable(
            List<CacheDecompositionPoint> points) {
        StringBuilder sb = new StringBuilder();
        sb.append("\\begin{table}[htbp]\n");
        sb.append("\\centering\n");
        sb.append("\\caption{Cache Isolation: Architecture vs Cache Contribution}\n");
        sb.append("\\label{tab:cache-isolation}\n");
        sb.append("\\begin{tabular}{lrrrrr}\n");
        sb.append("\\toprule\n");
        sb.append("\\textbf{Cards} & \\textbf{No Cache} & \\textbf{Redis Only} & " +
            "\\textbf{Snapshot+Redis} & \\textbf{Arch. Gain} & \\textbf{Cache Gain} \\\\\n");
        sb.append("\\midrule\n");
        for (CacheDecompositionPoint p : points) {
            sb.append(String.format("%d & %.1f & %.1f & %.1f & %.0f\\%% & %.0f\\%% \\\\\n",
                p.cardCount, p.noCacheMeanUs, p.redisOnlyMeanUs,
                p.snapshotRedisMeanUs, p.architectureGainPct, p.cacheGainPct));
        }
        sb.append("\\bottomrule\n");
        sb.append("\\end{tabular}\n");
        sb.append("\\end{table}\n");
        return sb.toString();
    }
}
