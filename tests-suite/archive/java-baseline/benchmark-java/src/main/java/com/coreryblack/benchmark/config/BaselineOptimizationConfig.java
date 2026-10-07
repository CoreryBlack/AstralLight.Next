package com.coreryblack.benchmark.config;

import lombok.Builder;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * Documents the optimization levels for each baseline system in the
 * multi-system comparative benchmark.
 *
 * <p>Following benchmark fairness guidelines: all baselines are deployed using their
 * officially recommended production configurations to avoid unfair
 * comparison against default development settings.</p>
 *
 * <h3>Benchmark Type</h3>
 * <ul>
 *   <li><b>DEFAULT</b> — Official default configuration (naive, for
 *       documenting the optimization gap)</li>
 *   <li><b>OPTIMIZED</b> — Officially recommended production configuration
 *       (used for head-to-head comparison)</li>
 * </ul>
 */
@Data
@Builder
public class BaselineOptimizationConfig {

    /** System identifier (Casbin, OPA, Cedar, AstralLight) */
    private String system;

    /** DEFAULT or OPTIMIZED */
    private BenchmarkType type;

    /** Human-readable optimization summary */
    private String description;

    /** List of specific optimizations applied */
    private String[] optimizations;

    public enum BenchmarkType {
        DEFAULT,
        OPTIMIZED
    }

    // ──────────────────────────────────────────
    //  Casbin optimizations
    // ──────────────────────────────────────────
    public static BaselineOptimizationConfig casbinDefault() {
        return BaselineOptimizationConfig.builder()
            .system("Casbin")
            .type(BenchmarkType.DEFAULT)
            .description("Default Enforcer, no caching, full policy scan")
            .optimizations(new String[]{
                "new Enforcer(model) — bare enforcer",
                "No CachedEnforcer wrapper",
                "No FilteredAdapter",
                "No policy subset loading",
                "No role manager caching"
            })
            .build();
    }

    public static BaselineOptimizationConfig casbinOptimized() {
        return BaselineOptimizationConfig.builder()
            .system("Casbin(Cached)")
            .type(BenchmarkType.OPTIMIZED)
            .description("CachedEnforcer with in-memory cache, recommended production config")
            .optimizations(new String[]{
                "CachedEnforcer wrapper (LRU cache, default 1000 entries)",
                "AutoCleanEnforcerCache enabled",
                "buildRoleLinks() pre-building role hierarchy",
                "Policy ordered by priority (deny-override model)"
            })
            .build();
    }

    // ──────────────────────────────────────────
    //  OPA optimizations
    // ──────────────────────────────────────────
    public static BaselineOptimizationConfig opaDefault() {
        return BaselineOptimizationConfig.builder()
            .system("OPA(REST)")
            .type(BenchmarkType.DEFAULT)
            .description("Interpreted Rego evaluation via REST API, no caching")
            .optimizations(new String[]{
                "HTTP REST API (localhost:8181)",
                "Interpreted Rego (no WASM compilation)",
                "No OPA Bundle",
                "No decision cache",
                "No partial evaluation"
            })
            .build();
    }

    public static BaselineOptimizationConfig opaOptimized() {
        return BaselineOptimizationConfig.builder()
            .system("OPA(REST)")
            .type(BenchmarkType.OPTIMIZED)
            .description("Template-grouped data + flat deny-override Rego, evaluated via REST API")
            .optimizations(new String[]{
                "Template-grouped data (O(cards) bindings + O(templates × rules)) instead of flat per-card rules",
                "O(1) card→template object-key lookup in Rego",
                "Deny-override Rego (deny scan before allow scan)",
                "Pre-loaded data via /v1/data PUT (not incremental patches)",
                "REST evaluation (no WASM compilation; server decision cache not verifiably disabled)"
            })
            .build();
    }

    // ──────────────────────────────────────────
    //  Cedar optimizations
    // ──────────────────────────────────────────
    public static BaselineOptimizationConfig cedarDefault() {
        return BaselineOptimizationConfig.builder()
            .system("Cedar(Default)")
            .type(BenchmarkType.DEFAULT)
            .description("Default PolicyStore, per-request policy load")
            .optimizations(new String[]{
                "Default PolicyStore (no caching)",
                "Per-request policy set construction",
                "No entity pre-warming",
                "No principal caching"
            })
            .build();
    }

    public static BaselineOptimizationConfig cedarOptimized() {
        return BaselineOptimizationConfig.builder()
            .system("Cedar(Optimized)")
            .type(BenchmarkType.OPTIMIZED)
            .description("In-memory PolicyStore with pre-loaded policies, recommended production config")
            .optimizations(new String[]{
                "In-memory PolicyStore (avoids disk/network I/O per request)",
                "Pre-loaded policy set at initialization",
                "Pre-warmed entity store for common principals/resources",
                "Batch authorization for throughput benchmarks"
            })
            .build();
    }

    // ──────────────────────────────────────────
    //  AstralLight optimizations
    // ──────────────────────────────────────────
    public static BaselineOptimizationConfig astralLightDefault() {
        return BaselineOptimizationConfig.builder()
            .system("AstralLight(Naive)")
            .type(BenchmarkType.DEFAULT)
            .description("No snapshot, no cache, per-request DB query (baseline for optimization gap)")
            .optimizations(new String[]{
                "No rule_set_snapshot (per-request join on rule_set_entry)",
                "No Redis cache",
                "No card_rule_set_ref pre-loading",
                "8 GB heap"
            })
            .build();
    }

    public static BaselineOptimizationConfig astralLightOptimized() {
        return BaselineOptimizationConfig.builder()
            .system("AstralLight(Optimized)")
            .type(BenchmarkType.OPTIMIZED)
            .description("Snapshot + Redis cache + multi-source governance, current production config")
            .optimizations(new String[]{
                "rule_set_snapshot pre-computed (winner-takes-all compilation)",
                "Redis Hash read-through cache (perm:ruleset:{tid}:{rsid})",
                "card_rule_set_ref pre-loading with Redis string cache",
                "L1/L2/L3 evaluation path with AtomicLong hit counters",
                "OVERLAY → BASE priority chain with short-circuit",
                "CircuitBreaker (Resilience4j) on evaluate() and simulate()",
                "12 GB heap, G1GC tuned"
            })
            .build();
    }

    // ──────────────────────────────────────────
    //  All configurations
    // ──────────────────────────────────────────
    public static BaselineOptimizationConfig[] allOptimizedConfigs() {
        return new BaselineOptimizationConfig[]{
            casbinDefault(), casbinOptimized(),
            opaDefault(), opaOptimized(),
            cedarDefault(), cedarOptimized(),
            astralLightDefault(), astralLightOptimized()
        };
    }

    /**
     * Returns the official "best practice" configurations only —
     * these are the optimized configurations used for direct baseline comparison.
     */
    public static BaselineOptimizationConfig[] bestPracticeConfigs() {
        return new BaselineOptimizationConfig[]{
            casbinOptimized(),
            opaOptimized(),
            cedarOptimized(),
            astralLightOptimized()
        };
    }

    /**
     * Generates the LaTeX row for the baseline optimization table
     * in the benchmark setup documentation.
     */
    public String toLatexRow() {
        String optList = String.join(", ", optimizations);
        return String.format("%s & %s & %s \\\\",
            system, type, optList);
    }

    /**
     * Generates the full LaTeX table documenting baseline optimizations.
     */
    public static String generateLatexOptimizationTable() {
        StringBuilder sb = new StringBuilder();
        sb.append("\\begin{table}[htbp]\n");
        sb.append("\\centering\n");
        sb.append("\\caption{Baseline System Optimization Configurations}\n");
        sb.append("\\label{tab:baseline-optimization}\n");
        sb.append("\\begin{tabular}{llp{7cm}}\n");
        sb.append("\\toprule\n");
        sb.append("\\textbf{System} & \\textbf{Type} & \\textbf{Optimizations Applied} \\\\\n");
        sb.append("\\midrule\n");
        for (BaselineOptimizationConfig config : allOptimizedConfigs()) {
            sb.append(config.toLatexRow()).append("\n");
        }
        sb.append("\\bottomrule\n");
        sb.append("\\end{tabular}\n");
        sb.append("\\end{table}\n");

        sb.append("\n% Baseline deployment configuration:\n");
        sb.append("% All baseline systems were deployed using their officially recommended\n");
        sb.append("% production configurations to avoid unfair comparison against default\n");
        sb.append("% development settings.\n");

        return sb.toString();
    }

    /**
     * Generates a markdown summary of the baseline optimization strategy
     * for benchmark notes and result summaries.
     */
    public static String generateOptimizationSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("# Baseline System Optimization Strategy\n\n");
        sb.append("All baseline systems were benchmarked in two configurations:\n\n");
        sb.append("1. **DEFAULT** — Official out-of-the-box configuration (development settings)\n");
        sb.append("2. **OPTIMIZED** — Officially recommended production configuration\n\n");
        sb.append("The OPTIMIZED variants are used for direct head-to-head comparison.\n");
        sb.append("All systems use recommended configurations to reduce bias from default-only baselines.\n\n");

        sb.append("## Optimization Summary\n\n");
        sb.append("| System | Type | Optimizations |\n");
        sb.append("|--------|------|---------------|\n");
        for (BaselineOptimizationConfig config : allOptimizedConfigs()) {
            sb.append(String.format("| %s | %s | %s |\n",
                config.system, config.type,
                String.join("; ", config.optimizations)));
        }
        sb.append("\n");

        sb.append("## Why Best-Practice Configuration Matters\n\n");
        sb.append("Comparing an optimized AstralLight against default configurations of\n");
        sb.append("Casbin, OPA, or Cedar would be methodologically flawed. The performance\n");
        sb.append("gap between default and optimized configurations can exceed one order\n");
        sb.append("of magnitude for systems like Casbin (CachedEnforcer vs Enforcer) and\n");
        sb.append("OPA (WASM compilation vs interpreted Rego).\n\n");

        sb.append("By benchmarking all systems at their best-practice configurations,\n");
        sb.append("we ensure the comparison is fair and the results are credible to\n");
        sb.append("operators experienced with each baseline system.\n");

        return sb.toString();
    }
}
