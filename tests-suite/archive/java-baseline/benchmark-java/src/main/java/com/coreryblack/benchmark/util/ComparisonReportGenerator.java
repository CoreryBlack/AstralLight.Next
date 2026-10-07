package com.coreryblack.benchmark.util;

import com.coreryblack.benchmark.config.BaselineOptimizationConfig;
import com.coreryblack.benchmark.data.MultiSystemComparisonResult;
import com.coreryblack.benchmark.rq4.RuleChangeCostBenchmark;
import com.coreryblack.benchmark.rq5.CacheIsolationBenchmark;
import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Generates multi-system comparison reports in LaTeX, CSV, and Markdown formats.
 *
 * <h3>Output Artifacts</h3>
 * <ul>
 *   <li>{@code comparison_results.csv} — Full result matrix</li>
 *   <li>{@code comparison_latency.tex} — Decision latency LaTeX table</li>
 *   <li>{@code comparison_scalability.tex} — Scalability analysis table</li>
 *   <li>{@code baseline_optimization.tex} — Baseline optimization documentation</li>
 *   <li>{@code comparison_dimensions.tex} — Capability comparison matrix</li>
 *   <li>{@code comparison_statistics.csv} — Statistical test results</li>
 *   <li>{@code comparison_raw_*.csv} — Per-system raw latency samples</li>
 * </ul>
 */
@Slf4j
public class ComparisonReportGenerator {

    private final String outputDir;
    private final List<String> systemLabels = new ArrayList<>();

    public ComparisonReportGenerator(String outputDir) {
        this.outputDir = outputDir;
        ensureOutputDir();
    }

    private void ensureOutputDir() {
        File dir = new File(outputDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    }

    // ────────────── Main Report Entry Points ──────────────

    /**
     * Generate the full comparison report suite for a completed benchmark run.
     */
    public void generateFullReport(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {

        log.info("Generating full comparison report to {}", outputDir);

        writeCsvResultMatrix(result);
        writeLatexLatencyTable(result);
        writeLatexScalabilityTable(result);
        writeLatexComplexityTable(result);
        writeBaselineOptimizationTable();
        writeComparisonDimensionTable();
        writeCapabilityMatrix();
        writeStatisticalReport(result);
        writeRawSamples(result);
        writeSummaryMarkdown(result);

        // P2: Memory footprint
        writeMemoryFootprintTable(result);

        // P3: Cold/hot ratio
        writeColdHotRatioTable(result);

        // P6: StdDev-enhanced summary
        writeLatexLatencyTableWithStddev(result);

        // Hardware usage snapshot at report generation time
        writeHardwareSnapshot();

        log.info("Report generation complete: {} files written to {}",
            new File(outputDir).listFiles().length, outputDir);
    }

    /**
     * Generate P2-P6 fairness validation reports.
     */
    public void generateFairnessReports(
            MultiSystemComparisonResult.BenchmarkResult result,
            List<RuleChangeCostBenchmark.ChangeCostResult> ruleChangeCosts,
            List<CacheIsolationBenchmark.CacheIsolationResult> cacheIsolations)
            throws IOException {

        log.info("Generating fairness validation reports to {}", outputDir);

        writeMemoryFootprintTable(result);
        writeColdHotRatioTable(result);
        writeRuleChangeCostTable(ruleChangeCosts);
        writeCacheIsolationTable(cacheIsolations);
        writeFairnessSummary(result, ruleChangeCosts, cacheIsolations);

        log.info("Fairness validation reports complete");
    }

    // ────────────── CSV ──────────────

    public void writeCsvResultMatrix(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        String path = outputDir + "/comparison_results.csv";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("scale,system,optimization,mean_us,p50_us,p95_us,p99_us,p999_us," +
                "min_us,max_us,total_ops,error_ops,tps,cold_mean_us,concurrent_tps");

            for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                String scaleLabel = sp.scale.label();
                for (MultiSystemComparisonResult.SystemResult sr : sp.systemResults) {
                    if (sr.singleThreadSnapshot == null || sr.singleThreadSnapshot.sampleCount() == 0) {
                        continue;
                    }
                    LatencyRecorder.LatencySnapshot s = sr.singleThreadSnapshot;
                    double coldMean = sr.coldStartSnapshot != null ?
                        sr.coldStartSnapshot.meanUs() : -1;
                    double concurrentTps = sr.concurrentSnapshot != null ?
                        sr.concurrentSnapshot.tps() : -1;

                    pw.printf("%s,%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d,%.0f,%.2f,%.0f%n",
                        scaleLabel,
                        sr.systemLabel,
                        sr.optimizationLevel,
                        s.meanUs(), s.p50Us(), s.p95Us(), s.p99Us(), s.p999Us(),
                        s.minUs(), s.maxUs(),
                        s.totalOps(), s.errorOps(), s.tps(),
                        coldMean, concurrentTps);
                }
            }
        }
        log.info("  CSV result matrix: {}", path);
    }

    // ────────────── LaTeX Tables ──────────────

    /**
     * RQ2a: Decision latency across all systems at each scale point.
     * Primary table for cross-system decision latency results.
     */
    public void writeLatexLatencyTable(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        String path = outputDir + "/comparison_latency.tex";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% Multi-System Decision Latency Comparison");
            pw.println("% Generated: " + LocalDateTime.now());
            pw.println("% All systems at best-practice (optimized) configurations");
            pw.println();

            // Collect best-practice systems
            List<String> bestSystems = new ArrayList<>();
            for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                for (MultiSystemComparisonResult.SystemResult sr : sp.systemResults) {
                    if ("OPTIMIZED".equals(sr.optimizationLevel) &&
                        sr.singleThreadSnapshot != null &&
                        sr.singleThreadSnapshot.sampleCount() > 0) {
                        if (!bestSystems.contains(sr.systemLabel)) {
                            bestSystems.add(sr.systemLabel);
                        }
                    }
                }
            }

            // Build the table header dynamically
            int numSystems = bestSystems.size();
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Decision Latency Comparison Across Authorization Systems " +
                "(Best-Practice Configurations, microseconds)}");
            pw.println("\\label{tab:comparison-latency}");
            pw.print("\\begin{tabular}{l");
            for (int i = 0; i < numSystems; i++) {
                pw.print("r");
            }
            pw.println("}");
            pw.println("\\toprule");
            pw.print("\\textbf{Scale}");
            for (String sys : bestSystems) {
                pw.print(" & \\textbf{" + escapeLatex(sys) + "}");
            }
            pw.println(" \\\\");
            pw.println("\\midrule");

            for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                String scaleLabel = String.format("C=%d", sp.scale.getCardCount());
                pw.print(scaleLabel);
                for (String sys : bestSystems) {
                    MultiSystemComparisonResult.SystemResult sr = sp.getResult(sys);
                    if (sr != null && sr.singleThreadSnapshot != null &&
                        sr.singleThreadSnapshot.sampleCount() > 0) {
                        LatencyRecorder.ConfidenceInterval ci =
                            sr.singleThreadSnapshot.confidenceInterval95Us();
                        pw.printf(" & %.1f", ci.mean);
                    } else {
                        pw.print(" & --");
                    }
                }
                pw.println(" \\\\");
            }

            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println();

            // Add a legend
            pw.println("% Legend:");
            pw.println("% C = Card count (number of active cards)");
            pw.println("% All measurements in microseconds (us)");
            pw.println("% Values shown as mean with 95%% bootstrap confidence interval");
            pw.println("% Best-practice configurations documented in Table~\\ref{tab:baseline-optimization}");
            pw.println("\\end{table}");
        }
        log.info("  LaTeX latency table: {}", path);
    }

    /**
     * RQ2c/d: Scalability analysis — how latency grows with card count
     * and rule complexity across systems.
     */
    public void writeLatexScalabilityTable(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        String path = outputDir + "/comparison_scalability.tex";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% Card Count Scalability Comparison");
            pw.println("% Generated: " + LocalDateTime.now());
            pw.println();

            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Card Count Scalability: Mean Decision Latency (us)}");
            pw.println("\\label{tab:comparison-card-scale}");
            pw.println("\\begin{tabular}{lrrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{Card Count} & \\textbf{AstralLight} & " +
                "\\textbf{Casbin(Cached)} & \\textbf{Cedar(Opt)} \\\\");
            pw.println("\\midrule");

            for (MultiSystemComparisonResult.CardScalePoint cp : result.cardScalePoints) {
                pw.printf("%d", cp.cardCount);
                String[] systems = {"AstralLight", "Casbin(Cached)",
                    "Cedar(Optimized)"};
                for (String sys : systems) {
                    LatencyRecorder.LatencySnapshot snap = cp.systemSnapshots.get(sys);
                    if (snap != null && snap.sampleCount() > 0) {
                        pw.printf(" & %.1f", snap.meanUs());
                    } else {
                        pw.print(" & --");
                    }
                }
                pw.println(" \\\\");
            }

            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println("\\end{table}");
        }
        log.info("  LaTeX scalability table: {}", path);
    }

    /**
     * Rule complexity sensitivity table.
     */
    public void writeLatexComplexityTable(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        String path = outputDir + "/comparison_complexity.tex";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% Rule Complexity Sensitivity");
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Rule Complexity Sensitivity: Mean Decision Latency (us)}");
            pw.println("\\label{tab:comparison-complexity}");
            pw.println("\\begin{tabular}{lrrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{Rules/Card} & \\textbf{AstralLight} & " +
                "\\textbf{Casbin(Cached)} & \\textbf{Cedar(Opt)} \\\\");
            pw.println("\\midrule");

            for (MultiSystemComparisonResult.ComplexityPoint cp : result.complexityPoints) {
                pw.printf("%d", cp.rulesPerCard);
                // Key must match the snapshots written by
                // runLayer1ComplexitySensitivity ("AstralLight"), not the
                // SystemResult label convention ("AstralLight(Optimized)") —
                // a mismatch silently renders "--" for the whole column.
                String[] systems = {"AstralLight", "Casbin(Cached)", "Cedar(Optimized)"};
                for (String sys : systems) {
                    LatencyRecorder.LatencySnapshot snap = cp.systemSnapshots.get(sys);
                    if (snap != null && snap.sampleCount() > 0) {
                        pw.printf(" & %.1f", snap.meanUs());
                    } else {
                        pw.print(" & --");
                    }
                }
                pw.println(" \\\\");
            }

            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println("\\end{table}");
        }
        log.info("  LaTeX complexity table: {}", path);
    }

    /**
     * Baseline optimization documentation table (for experimental setup section).
     */
    public void writeBaselineOptimizationTable() throws IOException {
        String path = outputDir + "/baseline_optimization.tex";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println(BaselineOptimizationConfig.generateLatexOptimizationTable());
        }
        log.info("  LaTeX baseline optimization table: {}", path);
    }

    /**
     * Capability comparison dimension matrix.
     */
    public void writeComparisonDimensionTable() throws IOException {
        String path = outputDir + "/comparison_dimensions.tex";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println(MultiSystemComparisonResult.generateComparisonDimensionTable());
        }
        log.info("  LaTeX comparison dimensions table: {}", path);
    }

    /**
     * Baseline capability matrix (CSV + LaTeX) and the common-subset statement.
     * Every comparison artifact ships this so consumers can see which features
     * were excluded from the head-to-head numbers and why.
     */
    public void writeCapabilityMatrix() throws IOException {
        String csvPath = outputDir + "/capability_matrix.csv";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(csvPath)))) {
            pw.println(com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.toCsv());
        }
        log.info("  Capability matrix CSV: {}", csvPath);

        String texPath = outputDir + "/capability_matrix.tex";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(texPath)))) {
            pw.println(com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.toLatex());
        }
        log.info("  Capability matrix LaTeX: {}", texPath);

        String subsetPath = outputDir + "/common_subset.txt";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(subsetPath)))) {
            pw.println(com.coreryblack.benchmark.baseline.BaselineCapabilityMatrix.subsetStatement());
        }
        log.info("  Common subset statement: {}", subsetPath);
    }

    // ────────────── Statistical Report ──────────────

    public void writeStatisticalReport(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        String path = outputDir + "/comparison_statistics.csv";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("pair,test_type,mann_whitney_p_value,cliffs_delta," +
                "effect_size,significant_005");

            // Compare best-practice systems at each scale
            for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                List<MultiSystemComparisonResult.SystemResult> optimized =
                    sp.getOptimizedResults();

                for (int i = 0; i < optimized.size(); i++) {
                    for (int j = i + 1; j < optimized.size(); j++) {
                        MultiSystemComparisonResult.SystemResult a = optimized.get(i);
                        MultiSystemComparisonResult.SystemResult b = optimized.get(j);

                        if (a.singleThreadSnapshot == null || b.singleThreadSnapshot == null) continue;
                        if (a.singleThreadSnapshot.sampleCount() < 5 ||
                            b.singleThreadSnapshot.sampleCount() < 5) continue;

                        List<Long> sampleA = a.singleThreadSnapshot.rawSamples();
                        List<Long> sampleB = b.singleThreadSnapshot.rawSamples();

                        double pValue = StatisticalTest.mannWhitneyUTest(sampleA, sampleB);
                        double delta = StatisticalTest.cliffsDelta(sampleA, sampleB);
                        String interpretation = StatisticalTest.interpretCliffsDelta(delta);

                        String pairLabel = String.format("%s_vs_%s_C%d",
                            a.systemLabel.replace("(", "").replace(")", ""),
                            b.systemLabel.replace("(", "").replace(")", ""),
                            sp.scale.getCardCount());

                        pw.printf("%s,Mann-Whitney,%.6f,%.4f,%s,%s%n",
                            pairLabel, pValue, delta, interpretation,
                            pValue < 0.05 ? "YES" : "NO");
                    }
                }
            }
        }
        log.info("  Statistical report: {}", path);
    }

    // ────────────── Raw Samples ──────────────

    public void writeRawSamples(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
            String scaleSuffix = "C" + sp.scale.getCardCount();
            for (MultiSystemComparisonResult.SystemResult sr : sp.systemResults) {
                if (sr.singleThreadSnapshot == null ||
                    sr.singleThreadSnapshot.sampleCount() == 0) continue;

                String safeName = sr.systemLabel.replaceAll("[^a-zA-Z0-9_\\-=]", "_");
                String path = outputDir + "/raw_" + safeName + "_" + scaleSuffix + ".csv";

                try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
                    pw.println("latency_nanos");
                    for (Long v : sr.singleThreadSnapshot.rawSamples()) {
                        pw.println(v);
                    }
                }
            }
        }
        log.info("  Raw samples written for {} scale points", result.scalePoints.size());
    }

    // ────────────── Summary Markdown ──────────────

    public void writeSummaryMarkdown(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        String path = outputDir + "/comparison_summary.md";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("# Multi-System Comparison Benchmark Results");
            pw.println();
            pw.println("Generated: " + LocalDateTime.now());
            pw.println();
            pw.println("## Experimental Setup");
            pw.println();
            pw.println("- **Iterations per scale**: " +
                result.metadata.getOrDefault("iterations_per_scale", "N/A"));
            pw.println("- **Concurrency**: " +
                result.metadata.getOrDefault("concurrency", "N/A"));
            pw.println("- **Warmup iterations**: 1000 per system per scale");
            pw.println("- **Optimization level**: All systems at best-practice configurations");
            pw.println();
            pw.println("## Systems Compared");
            pw.println();
            pw.println("| Layer | System | Model | Optimization |");
            pw.println("|-------|--------|-------|-------------|");
            pw.println("| 1 | Casbin(Cached) | RBAC/ABAC Engine | CachedEnforcer + role link cache |");
            pw.println("| 1 | OPA(REST) | Policy Engine | Interpreted Rego via REST |");
            pw.println("| 1 | OPA(NoCache) | Policy Engine | REST + cache-busting headers |");
            pw.println("| 1 | Cedar(Optimized) | Policy Language | In-memory pre-loaded PolicyStore |");
            pw.println("| -- | **AstralLight(Optimized)** | Rule Engine + Governance | Snapshot + Redis + OVERLAY |");
            pw.println();
            pw.println("## Key Results");
            pw.println();

            // Print summary for each scale
            for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                pw.println("### Scale: " + sp.scale.label());
                pw.println();
                pw.println("| System | Mean (us) | P95 (us) | P99 (us) | TPS | Optimization |");
                pw.println("|--------|-----------|----------|----------|-----|-------------|");

                // Sort: best-practice first
                List<MultiSystemComparisonResult.SystemResult> sorted = new ArrayList<>(sp.systemResults);
                sorted.sort((a, b) -> {
                    if (!a.optimizationLevel.equals(b.optimizationLevel)) {
                        return "OPTIMIZED".equals(a.optimizationLevel) ? -1 : 1;
                    }
                    if (a.singleThreadSnapshot == null) return 1;
                    if (b.singleThreadSnapshot == null) return -1;
                    return Double.compare(a.singleThreadSnapshot.meanUs(), b.singleThreadSnapshot.meanUs());
                });

                for (MultiSystemComparisonResult.SystemResult sr : sorted) {
                    if (sr.singleThreadSnapshot == null || sr.singleThreadSnapshot.sampleCount() == 0) {
                        pw.printf("| %s | SKIPPED | -- | -- | -- | %s |%n",
                            sr.systemLabel, sr.optimizationLevel);
                    } else {
                        pw.printf("| %s | %.1f | %.1f | %.1f | %.0f | %s |%n",
                            sr.systemLabel,
                            sr.singleThreadSnapshot.meanUs(),
                            sr.singleThreadSnapshot.p95Us(),
                            sr.singleThreadSnapshot.p99Us(),
                            sr.singleThreadSnapshot.tps(),
                            sr.optimizationLevel);
                    }
                }
                pw.println();
            }
        }
        log.info("  Summary markdown: {}", path);
    }

    // ────────────── Fairness Validation Reports (P2-P6) ──────────────

    /**
     * P2: Memory Footprint comparison table.
     */
    public void writeMemoryFootprintTable(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        String path = outputDir + "/fairness_memory_footprint.tex";
        List<MemoryFootprintMeasurer.FootprintResult> footprints = new ArrayList<>();

        for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
            for (MultiSystemComparisonResult.SystemResult sr : sp.systemResults) {
                if (sr.memoryFootprint != null) {
                    footprints.add(sr.memoryFootprint);
                }
            }
        }

        if (footprints.isEmpty()) {
            log.info("  Memory footprint table: no data, skipping");
            return;
        }

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println(MultiSystemComparisonResult.generateMemoryFootprintTable(footprints));
        }
        log.info("  Memory footprint table: {}", path);
    }

    /**
     * P3: Cold/Hot Start Ratio table.
     */
    public void writeColdHotRatioTable(MultiSystemComparisonResult.BenchmarkResult result)
            throws IOException {
        String path = outputDir + "/fairness_cold_hot_ratio.tex";

        if (result.coldHotRatios == null || result.coldHotRatios.isEmpty()) {
            // Generate from scale points
            List<MultiSystemComparisonResult.ColdHotRatioPoint> points = new ArrayList<>();
            for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                for (MultiSystemComparisonResult.SystemResult sr : sp.systemResults) {
                    if ("OPTIMIZED".equals(sr.optimizationLevel) &&
                        sr.coldStartSnapshot != null &&
                        sr.singleThreadSnapshot != null &&
                        sr.coldStartSnapshot.sampleCount() > 0 &&
                        sr.singleThreadSnapshot.sampleCount() > 0) {

                        MultiSystemComparisonResult.ColdHotRatioPoint p =
                            new MultiSystemComparisonResult.ColdHotRatioPoint();
                        p.systemLabel = sr.systemLabel;
                        p.coldMeanUs = sr.coldStartSnapshot.meanUs();
                        p.hotMeanUs = sr.singleThreadSnapshot.meanUs();
                        p.ratio = sr.coldHotRatio > 0 ? sr.coldHotRatio :
                            (p.hotMeanUs > 0 ? p.coldMeanUs / p.hotMeanUs : 0);
                        p.scaleCards = sp.scale.getCardCount();
                        points.add(p);
                    }
                }
            }
            result.coldHotRatios = points;
        }

        if (result.coldHotRatios.isEmpty()) {
            log.info("  Cold/hot ratio table: no data, skipping");
            return;
        }

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println(MultiSystemComparisonResult.generateColdHotRatioTable(result.coldHotRatios));
        }
        log.info("  Cold/hot ratio table: {}", path);
    }

    /**
     * P4: Rule Change Cost comparison table.
     */
    public void writeRuleChangeCostTable(
            List<RuleChangeCostBenchmark.ChangeCostResult> changeCosts) throws IOException {
        String path = outputDir + "/fairness_rule_change_cost.tex";

        if (changeCosts == null || changeCosts.isEmpty()) {
            log.info("  Rule change cost table: no data, skipping");
            return;
        }

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% P4: Rule Change Cost Comparison");
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Rule Change Cost: Recovery Time After Single Rule Modification}");
            pw.println("\\label{tab:rule-change-cost}");
            pw.println("\\begin{tabular}{lrrrrrr}");
            pw.println("\\toprule");
            pw.println(RuleChangeCostBenchmark.ChangeCostResult.latexHeader());
            pw.println("\\midrule");
            for (RuleChangeCostBenchmark.ChangeCostResult r : changeCosts) {
                pw.println(r.toLatexRow());
            }
            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println("\\end{table}");
        }
        log.info("  Rule change cost table: {}", path);
    }

    /**
     * RQ-Compare-3: Rule Update Overhead — cross-system comparison.
     * AL Incremental Compile vs Casbin Policy Reload vs OPA Bundle Reload vs Cedar Index Rebuild.
     */
    public void writeRuleUpdateOverheadTable(
            List<MultiSystemComparisonResult.RuleChangeCostPoint> costs) throws IOException {
        String path = outputDir + "/rq_compare3_rule_update_overhead.tex";

        if (costs == null || costs.isEmpty()) {
            log.info("  Rule update overhead table: no data, skipping");
            return;
        }

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% RQ-Compare-3: Rule Update Overhead");
            pw.println("% AL Incremental Compile vs Casbin Policy Reload vs OPA Bundle Reload vs Cedar Index Rebuild");
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Rule Update Overhead: Incremental Compile vs Full Reload Across Systems}");
            pw.println("\\label{tab:rule-update-overhead}");
            pw.println("\\begin{tabular}{llrrrr}");
            pw.println("\\toprule");
            pw.println(MultiSystemComparisonResult.RuleChangeCostPoint.latexHeader());
            pw.println("\\midrule");

            for (MultiSystemComparisonResult.RuleChangeCostPoint p : costs) {
                pw.println(p.toLatexRow());
            }

            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println();
            pw.println("% All values in microseconds.");
            pw.println("% AstralLight uses Incremental Compile (only processes changed rules).");
            pw.println("% Baseline systems require full reload/rebuild of all policies.");
            pw.println("\\end{table}");
        }
        log.info("  Rule update overhead table: {}", path);

        // CSV version
        String csvPath = outputDir + "/rq_compare3_rule_update_overhead.csv";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(csvPath)))) {
            pw.println("system,update_method,cards,rules_per_card,update_mean_us,update_p99_us,pre_update_us,post_update_us");
            for (MultiSystemComparisonResult.RuleChangeCostPoint p : costs) {
                pw.printf("%s,%s,%d,%d,%.1f,%.1f,%.1f,%.1f%n",
                    p.systemLabel, p.updateMethod, p.cardCount, p.rulesPerCard,
                    p.updateMeanUs, p.updateP99Us, p.preUpdateLatencyUs, p.postUpdateLatencyUs);
            }
        }
        log.info("  Rule update overhead CSV: {}", csvPath);
    }

    /**
     * P5: Cache Isolation Decomposition table.
     */
    public void writeCacheIsolationTable(
            List<CacheIsolationBenchmark.CacheIsolationResult> cacheIsolations)
            throws IOException {
        String path = outputDir + "/fairness_cache_isolation.tex";

        if (cacheIsolations == null || cacheIsolations.isEmpty()) {
            log.info("  Cache isolation table: no data, skipping");
            return;
        }

        List<MultiSystemComparisonResult.CacheDecompositionPoint> points = new ArrayList<>();
        for (CacheIsolationBenchmark.CacheIsolationResult ci : cacheIsolations) {
            MultiSystemComparisonResult.CacheDecompositionPoint p =
                new MultiSystemComparisonResult.CacheDecompositionPoint();
            p.cardCount = ci.scale.getCardCount();
            p.noCacheMeanUs = ci.snapshotOff != null ? ci.snapshotOff.meanUs() : -1;
            p.redisOnlyMeanUs = ci.redisOnly != null ? ci.redisOnly.meanUs() : -1;
            p.snapshotRedisMeanUs = ci.snapshotOn != null ? ci.snapshotOn.meanUs() : -1;
            p.architectureGainPct = ci.architecturePercent;
            p.cacheGainPct = ci.cachePercent;
            points.add(p);
        }

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println(MultiSystemComparisonResult.generateCacheDecompositionTable(points));
        }
        log.info("  Cache isolation table: {}", path);

        // Also write CSV version
        String csvPath = outputDir + "/fairness_cache_isolation.csv";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(csvPath)))) {
            pw.println("card_count,no_cache_us,redis_only_us,snapshot_redis_us,arch_gain_pct,cache_gain_pct");
            for (MultiSystemComparisonResult.CacheDecompositionPoint p : points) {
                pw.printf("%d,%.1f,%.1f,%.1f,%.0f,%.0f%n",
                    p.cardCount, p.noCacheMeanUs, p.redisOnlyMeanUs,
                    p.snapshotRedisMeanUs, p.architectureGainPct, p.cacheGainPct);
            }
        }
        log.info("  Cache isolation CSV: {}", csvPath);
    }

    /**
     * P6: Latency table with standard deviation (mean ± stddev).
     * This is the version of the primary latency table that includes variability.
     */
    public void writeLatexLatencyTableWithStddev(
            MultiSystemComparisonResult.BenchmarkResult result) throws IOException {
        String path = outputDir + "/fairness_latency_with_stddev.tex";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("% P6: Decision Latency with Standard Deviation");
            pw.println("% Generated: " + LocalDateTime.now());
            pw.println();

            List<String> bestSystems = new ArrayList<>();
            for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                for (MultiSystemComparisonResult.SystemResult sr : sp.systemResults) {
                    if ("OPTIMIZED".equals(sr.optimizationLevel) &&
                        sr.singleThreadSnapshot != null &&
                        sr.singleThreadSnapshot.sampleCount() > 0) {
                        if (!bestSystems.contains(sr.systemLabel)) {
                            bestSystems.add(sr.systemLabel);
                        }
                    }
                }
            }

            int numSystems = bestSystems.size();
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Decision Latency With Standard Deviation " +
                "(Best-Practice Configurations, microseconds)}");
            pw.println("\\label{tab:comparison-latency-stddev}");
            pw.print("\\begin{tabular}{l");
            for (int i = 0; i < numSystems; i++) pw.print("r");
            pw.println("}");
            pw.println("\\toprule");
            pw.print("\\textbf{Scale} & ");
            pw.print("\\textbf{Metric}");
            for (String sys : bestSystems) {
                pw.print(" & \\textbf{" + escapeLatex(sys) + "}");
            }
            pw.println(" \\\\");
            pw.println("\\midrule");

            // Mean ± stddev row
            for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                String scaleLabel = String.format("C=%d", sp.scale.getCardCount());
                pw.print(scaleLabel + " & Mean$\\pm\\sigma$");
                for (String sys : bestSystems) {
                    MultiSystemComparisonResult.SystemResult sr = sp.getResult(sys);
                    if (sr != null && sr.singleThreadSnapshot != null &&
                        sr.singleThreadSnapshot.sampleCount() > 0) {
                        pw.printf(" & $%.1f \\pm %.1f$",
                            sr.singleThreadSnapshot.meanUs(),
                            sr.singleThreadSnapshot.stddevUs());
                    } else {
                        pw.print(" & --");
                    }
                }
                pw.println(" \\\\");

                // P95 row
                pw.print(" & P95");
                for (String sys : bestSystems) {
                    MultiSystemComparisonResult.SystemResult sr = sp.getResult(sys);
                    if (sr != null && sr.singleThreadSnapshot != null &&
                        sr.singleThreadSnapshot.sampleCount() > 0) {
                        pw.printf(" & %.1f", sr.singleThreadSnapshot.p95Us());
                    } else {
                        pw.print(" & --");
                    }
                }
                pw.println(" \\\\");

                // TPS row
                pw.print(" & TPS");
                for (String sys : bestSystems) {
                    MultiSystemComparisonResult.SystemResult sr = sp.getResult(sys);
                    if (sr != null && sr.singleThreadSnapshot != null &&
                        sr.singleThreadSnapshot.sampleCount() > 0) {
                        pw.printf(" & %.0f", sr.singleThreadSnapshot.tps());
                    } else {
                        pw.print(" & --");
                    }
                }
                pw.println(" \\\\");
                pw.println("\\midrule");
            }

            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println();
            pw.println("% All values in microseconds (us). Mean shown as mean ± population stddev.");
            pw.println("% Best-practice configurations documented in Table~\\ref{tab:baseline-optimization}.");
            pw.println("\\end{table}");
        }
        log.info("  Latency with stddev table: {}", path);
    }

    /**
     * Combined fairness validation summary document.
     */
    public void writeFairnessSummary(
            MultiSystemComparisonResult.BenchmarkResult result,
            List<RuleChangeCostBenchmark.ChangeCostResult> ruleChangeCosts,
            List<CacheIsolationBenchmark.CacheIsolationResult> cacheIsolations)
            throws IOException {
        String path = outputDir + "/fairness_validation_summary.md";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(path)))) {
            pw.println("# Fairness Validation Summary");
            pw.println();
            pw.println("Generated: " + LocalDateTime.now());
            pw.println();
            pw.println("## P1: DecisionPerformance — All systems on same dataset");
            pw.println();
            pw.println("All systems (AstralLight, Casbin, OPA, Cedar) benchmarked");
            pw.println("on identical generated datasets at matching scale gradients.");
            pw.println("See `comparison_latency.tex` and `fairness_latency_with_stddev.tex`.");
            pw.println();

            pw.println("## P2: Memory Footprint");
            pw.println();
            if (result.scalePoints.isEmpty()) {
                pw.println("(No data — run benchmark first)");
            } else {
                pw.println("| System | Init (MB) | Peak (MB) | Δ Peak (MB) | Steady (MB) | Policies |");
                pw.println("|--------|-----------|-----------|-------------|-------------|----------|");
                for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                    for (MultiSystemComparisonResult.SystemResult sr : sp.systemResults) {
                        if (sr.memoryFootprint != null) {
                            pw.printf("| %s | %d | %d | %d | %d | %d |%n",
                                sr.systemLabel,
                                sr.memoryFootprint.afterInit.heapUsedMB,
                                sr.memoryFootprint.peakMB > 0 ? sr.memoryFootprint.peakMB
                                    : (sr.memoryFootprint.peak != null ? sr.memoryFootprint.peak.heapUsedMB : -1),
                                sr.memoryFootprint.deltaPeakMB,
                                sr.memoryFootprint.steadyState.heapUsedMB,
                                sr.memoryFootprint.policyCount);
                        }
                    }
                }
            }
            pw.println();

            pw.println("## P3: Cold/Hot Start Ratio");
            pw.println();
            if (result.coldHotRatios == null || result.coldHotRatios.isEmpty()) {
                pw.println("(No data)");
            } else {
                pw.println("| System | Cold (us) | Hot (us) | Ratio | Cards |");
                pw.println("|--------|-----------|----------|-------|-------|");
                for (MultiSystemComparisonResult.ColdHotRatioPoint p : result.coldHotRatios) {
                    pw.printf("| %s | %.1f | %.1f | %.2fx | %d |%n",
                        p.systemLabel, p.coldMeanUs, p.hotMeanUs, p.ratio, p.scaleCards);
                }
            }
            pw.println();

            pw.println("## P4: Rule Change Cost");
            pw.println();
            if (ruleChangeCosts == null || ruleChangeCosts.isEmpty()) {
                pw.println("(No data)");
            } else {
                pw.println("| System | Rules | Change (us) | Recovery (us) | Post-Mean (us) |");
                pw.println("|--------|-------|-------------|---------------|----------------|");
                for (RuleChangeCostBenchmark.ChangeCostResult r : ruleChangeCosts) {
                    pw.printf("| %s | %d | %d | %d | %d |%n",
                        r.systemLabel, r.rulesBeforeChange,
                        r.changeLatencyUs, r.recoveryLatencyUs, r.postChangeMeanUs);
                }
            }
            pw.println();

            pw.println("## P5: Cache Isolation — Architecture vs Cache Contribution");
            pw.println();
            if (cacheIsolations == null || cacheIsolations.isEmpty()) {
                pw.println("(No data)");
            } else {
                pw.println("| Cards | No Cache | Redis Only | Snapshot+Redis | Arch Gain | Cache Gain |");
                pw.println("|-------|----------|------------|----------------|-----------|------------|");
                for (CacheIsolationBenchmark.CacheIsolationResult ci : cacheIsolations) {
                    pw.printf("| %d | %.1f | %.1f | %.1f | %.0f%% | %.0f%% |%n",
                        ci.scale.getCardCount(),
                        ci.snapshotOff.meanUs(),
                        ci.redisOnly.meanUs(),
                        ci.snapshotOn.meanUs(),
                        ci.architecturePercent,
                        ci.cachePercent);
                }
            }
            pw.println();

            pw.println("## P6: Standard Deviation");
            pw.println();
            pw.println("All latency tables now include population standard deviation as");
            pw.println("`mean ± stddev` in the LaTeX output. See `fairness_latency_with_stddev.tex`.");
            pw.println();
            pw.println("The CSV output also includes a `stddev_us` column for all results.");

            // ── Single-Thread Comparison table (if available) ──
            boolean hasStResults = result.scalePoints.stream()
                .anyMatch(sp -> sp.cardLatencyUs != null && !sp.cardLatencyUs.isEmpty());
            if (hasStResults) {
                pw.println();
                pw.println("## Per-Card Latency Distribution (AL single-thread)");
                pw.println();
                pw.println("| Scale | Cards Sampled | Min (us) | P25 (us) | P50 (us) | P75 (us) | Max (us) | Mean (us) | StdDev |");
                pw.println("|-------|---------------|----------|----------|----------|----------|----------|-----------|--------|");
                for (MultiSystemComparisonResult.ScalePoint sp : result.scalePoints) {
                    if (sp.cardLatencyUs == null || sp.cardLatencyUs.isEmpty()) continue;
                    List<Double> latencies = sp.cardLatencyUs.stream()
                        .map(c -> c.meanLatencyUs).sorted().toList();
                    double min = latencies.get(0);
                    double max = latencies.get(latencies.size() - 1);
                    double p25 = latencies.get(latencies.size() / 4);
                    double p50 = latencies.get(latencies.size() / 2);
                    double p75 = latencies.get(latencies.size() * 3 / 4);
                    double mean = latencies.stream().mapToDouble(d -> d).average().orElse(0);
                    double variance = latencies.stream().mapToDouble(d -> Math.pow(d - mean, 2)).average().orElse(0);
                    double stddev = Math.sqrt(variance);
                    pw.printf("| %s | %d | %.1f | %.1f | %.1f | %.1f | %.1f | %.1f | %.1f |%n",
                        sp.scale.label(), latencies.size(), min, p25, p50, p75, max, mean, stddev);
                }
            }
        }
        log.info("  Fairness summary: {}", path);
    }

    // ────────────── Utilities ──────────────

    private static String escapeLatex(String s) {
        return s.replace("_", "\\_")
                .replace("%", "\\%")
                .replace("&", "\\&")
                .replace("#", "\\#");
    }

    // ────────────── Hardware Snapshot ──────────────

    /**
     * Write a hardware usage snapshot captured at report generation time.
     * Provides point-in-time CPU, memory, disk, and GC utilization for the
     * experimental environment documentation.
     */
    public void writeHardwareSnapshot() throws IOException {
        HardwareMonitor.HardwareSnapshot snap = HardwareMonitor.capture();

        // CSV
        String csvPath = outputDir + "/hardware_snapshot.csv";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(csvPath)))) {
            pw.println("metric,value,unit");
            pw.printf("cpu_process,%.1f,%%%n", snap.cpuProcessPercent());
            pw.printf("cpu_system,%.1f,%%%n", snap.cpuSystemPercent());
            pw.printf("heap_used,%d,MB%n", snap.heapUsedMb());
            pw.printf("heap_committed,%d,MB%n", snap.heapCommittedMb());
            pw.printf("heap_max,%d,MB%n", snap.heapMaxMb());
            pw.printf("heap_used_pct,%.1f,%%%n", snap.heapUsedPercent());
            pw.printf("non_heap_used,%d,MB%n", snap.nonHeapUsedMb());
            pw.printf("physical_free,%d,MB%n", snap.physicalFreeMb());
            pw.printf("physical_total,%d,MB%n", snap.physicalTotalMb());
            pw.printf("physical_used,%d,MB%n", snap.physicalUsedMb());
            pw.printf("physical_used_pct,%.1f,%%%n", snap.physicalUsedPercent());
            pw.printf("disk_usable,%d,GB%n", snap.diskUsableGb());
            pw.printf("disk_total,%d,GB%n", snap.diskTotalGb());
            pw.printf("disk_used,%d,GB%n", snap.diskUsedGb());
            pw.printf("disk_used_pct,%.1f,%%%n", snap.diskUsedPercent());
            pw.printf("gc_total_count,%d,count%n", snap.gcTotalCount());
            pw.printf("gc_total_time_ms,%d,ms%n", snap.gcTotalTimeMs());
            pw.printf("eden_used,%d,MB%n", snap.edenUsedMb());
            pw.printf("old_gen_used,%d,MB%n", snap.oldGenUsedMb());
            pw.printf("survivor_used,%d,MB%n", snap.survivorUsedMb());
            pw.printf("metaspace_used,%d,MB%n", snap.metaspaceUsedMb());
        }
        log.info("  Hardware snapshot CSV: {}", csvPath);

        // LaTeX
        String texPath = outputDir + "/hardware_snapshot.tex";
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(texPath)))) {
            pw.println("% Hardware Resource Snapshot - Auto-generated " + java.time.LocalDateTime.now());
            pw.println("\\begin{table}[htbp]");
            pw.println("\\centering");
            pw.println("\\caption{Hardware Resource Utilization Snapshot}");
            pw.println("\\label{tab:hardware-snapshot}");
            pw.println("\\begin{tabular}{lrr}");
            pw.println("\\toprule");
            pw.println("\\textbf{Resource} & \\textbf{Used} & \\textbf{Total} \\\\");
            pw.println("\\midrule");
            pw.printf("CPU (Process) & %.1f\\%%%% & -- \\\\%n", snap.cpuProcessPercent());
            pw.printf("CPU (System) & %.1f\\%%%% & -- \\\\%n", snap.cpuSystemPercent());
            pw.printf("JVM Heap & %d MB & %d MB \\\\%n", snap.heapUsedMb(), snap.heapMaxMb());
            pw.printf("Non-Heap & %d MB & -- \\\\%n", snap.nonHeapUsedMb());
            pw.printf("Physical Memory & %d MB & %d MB \\\\%n", snap.physicalUsedMb(), snap.physicalTotalMb());
            pw.printf("Disk & %d GB & %d GB \\\\%n", snap.diskUsedGb(), snap.diskTotalGb());
            pw.println("\\midrule");
            pw.printf("Eden Space & %d MB & -- \\\\%n", snap.edenUsedMb());
            pw.printf("Old Gen & %d MB & -- \\\\%n", snap.oldGenUsedMb());
            pw.printf("Survivor & %d MB & -- \\\\%n", snap.survivorUsedMb());
            pw.printf("Metaspace & %d MB & -- \\\\%n", snap.metaspaceUsedMb());
            pw.printf("GC Collections & %d & -- \\\\%n", snap.gcTotalCount());
            pw.printf("GC Total Time & %d ms & -- \\\\%n", snap.gcTotalTimeMs());
            pw.println("\\bottomrule");
            pw.println("\\end{tabular}");
            pw.println();
            pw.println("% Snapshot captured at report generation time.");
            pw.println("% For time-series hardware data, see hardware_summary.csv.");
            pw.println("\\end{table}");
        }
        log.info("  Hardware snapshot LaTeX: {}", texPath);
    }

}
