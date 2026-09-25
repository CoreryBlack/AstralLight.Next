package com.coreryblack.benchmark.baseline;

import com.coreryblack.benchmark.config.ScaleConfig;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Declarative capability matrix for the cross-system comparison.
 *
 * <p>The comparison is only meaningful inside the <em>common expressible
 * subset</em>: the intersection of features every participating system can
 * actually evaluate. Features outside that subset are reported in the matrix
 * (for Casbin, OPA and Cedar they are NONE or PARTIAL) and are <b>excluded</b>
 * from the blocking correctness gate — they are never treated as adapter
 * "mismatches" because they are language-semantics differences, not bugs.</p>
 *
 * <h3>Common expressible subset (used by the gate and the benchmark)</h3>
 * <ul>
 *   <li>resource type × action × effect (ALLOW/DENY)</li>
 *   <li>deny-override conflict resolution (no priority conflicts in the subset)</li>
 *   <li>template-grouped policy sharing (flat BASE + OVERLAY merged per template)</li>
 * </ul>
 *
 * <h3>Excluded from the subset (declared, not compared)</h3>
 * <ul>
 *   <li>targetId / resource-ID-scoped rules — baselines ignore resource ID</li>
 *   <li>priority-based conflict resolution — baselines use deny-override</li>
 *   <li>CARD_ONLY per-card rules — baselines only express template grouping</li>
 *   <li>BASE/OVERLAY layered precedence — baselines flatten overlays</li>
 *   <li>ABAC conditions — baselines receive no attribute payload</li>
 *   <li>tenant scoping — the comparison is single-tenant (tenant 1)</li>
 *   <li>durable projection / revoke fence — AstralLight-only runtime safety</li>
 * </ul>
 */
public final class BaselineCapabilityMatrix {

    /** Capability axis identifiers — keep in sync with the table row order. */
    public static final String[] CAPABILITIES = {
            "targetId (resource-ID rules)",
            "priority (conflict resolution)",
            "card_only (per-card rules)",
            "base_overlay (layered precedence)",
            "abac (attribute conditions)",
            "tenant (context scoping)",
            "projection (durable projection / revoke fence)"
    };

    /** Support levels used by the matrix. */
    public enum Support { FULL, NONE, PARTIAL }

    /** Systems participating in the comparison. */
    public static final String[] SYSTEMS = {"AstralLight", "Casbin", "OPA(REST)", "Cedar"};

    private BaselineCapabilityMatrix() {
    }

    /**
     * Capability of each system on each axis.
     *
     * <p>AstralLight is FULL on every axis (it is the reference runtime).
     * Casbin/OPA/Cedar are limited to the flat template-grouped subset used by
     * their adapters: resource-type × action × deny-override. All other axes
     * are NONE — the adapters intentionally do not receive targetId, priority,
     * per-card rules, ABAC payloads or tenant context.</p>
     */
    public static Map<String, Map<String, Support>> matrix() {
        Map<String, Map<String, Support>> m = new LinkedHashMap<>();
        for (String system : SYSTEMS) {
            m.put(system, new LinkedHashMap<>());
        }
        for (String cap : CAPABILITIES) {
            m.get("AstralLight").put(cap, Support.FULL);
            m.get("Casbin").put(cap, Support.NONE);
            m.get("OPA(REST)").put(cap, Support.NONE);
            m.get("Cedar").put(cap, Support.NONE);
        }
        return m;
    }

    /**
     * The features every system shares. A request falls inside the subset iff
     * it only uses these features.
     */
    public static Set<String> commonSubsetFeatures() {
        return new LinkedHashSet<>(Set.of(
                "resource_type", "action", "effect_allow_deny",
                "deny_override", "template_grouped_policy"));
    }

    /**
     * Validates that a benchmark/gate scale stays inside the common subset.
     * Throws {@link IllegalArgumentException} otherwise, so a misconfigured
     * scale cannot silently produce incomparable numbers.
     *
     * @param scale           the scale configuration
     * @param expectedDenyRatio if {@code >= 0}, the scale's denyRatio must equal it
     *                          (used by the gate's allow-only/deny-only cases)
     */
    public static void requireCommonSubset(ScaleConfig scale, double expectedDenyRatio) {
        if (scale.getOverlayRulesPerCard() > 0) {
            throw new IllegalArgumentException(
                    "Scale outside common subset: overlayRulesPerCard="
                            + scale.getOverlayRulesPerCard()
                            + " — overlays are AstralLight-only (baselines flatten them); "
                            + "the cross-system comparison must use overlayRulesPerCard=0.");
        }
        if (scale.getDomainCount() > 1) {
            throw new IllegalArgumentException(
                    "Scale outside common subset: domainCount=" + scale.getDomainCount()
                            + " — tenant/domain scoping is AstralLight-only; "
                            + "the cross-system comparison must be single-tenant.");
        }
        if (expectedDenyRatio >= 0
                && Math.abs(scale.getDenyRatio() - expectedDenyRatio) > 1e-9) {
            throw new IllegalArgumentException(
                    "Scale denyRatio=" + scale.getDenyRatio()
                            + " does not match gate expectation " + expectedDenyRatio
                            + " — gate cases must be pure ALLOW / pure DENY / empty.");
        }
        // targetId-specific rules, CARD_ONLY rules and priority conflicts are
        // not configured through ScaleConfig (they would require explicit
        // per-card rule injection), so a ScaleConfig that passes the checks
        // above stays inside the flat subset by construction.
    }

    /**
     * Short human-readable statement of the subset restriction, embedded in
     * the artifact manifest so no downstream consumer can over-interpret the
     * comparison numbers.
     */
    public static String subsetStatement() {
        return "Cross-system comparison restricted to the common expressible subset: "
                + "resource-type × action × ALLOW/DENY with deny-override conflict "
                + "resolution and template-grouped policy sharing (overlayRulesPerCard=0, "
                + "single tenant, no targetId-scoped rules, no CARD_ONLY rules, no ABAC "
                + "payloads). Features outside this subset are AstralLight-only and are "
                + "reported in the capability matrix, not in the comparison.";
    }

    // ──────────────────────────────────────────
    //  Serialization
    // ──────────────────────────────────────────

    public static String toCsv() {
        StringBuilder sb = new StringBuilder();
        sb.append("system,").append(String.join(",", CAPABILITIES)).append('\n');
        Map<String, Map<String, Support>> m = matrix();
        for (String system : SYSTEMS) {
            sb.append(system);
            for (String cap : CAPABILITIES) {
                sb.append(',').append(m.get(system).get(cap));
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    public static String toLatex() {
        StringBuilder sb = new StringBuilder();
        sb.append("% Capability matrix — features excluded from the cross-system comparison\n");
        sb.append("% are NONE/PARTIAL for baselines and must not be read as adapter defects.\n");
        sb.append("\\begin{table}[htbp]\n");
        sb.append("\\centering\n");
        sb.append("\\caption{Authorization Capability Matrix (common expressible subset)}\n");
        sb.append("\\label{tab:capability-matrix}\n");
        sb.append("\\begin{tabular}{lp{2.6cm}p{2.6cm}p{2.6cm}p{2.6cm}}\n");
        sb.append("\\toprule\n");
        sb.append("\\textbf{Capability} & \\textbf{AstralLight} & \\textbf{Casbin} & \\textbf{OPA} & \\textbf{Cedar} \\\\\n");
        sb.append("\\midrule\n");
        Map<String, Map<String, Support>> m = matrix();
        for (String cap : CAPABILITIES) {
            sb.append(cap).append(" & ");
            for (int i = 0; i < SYSTEMS.length; i++) {
                Support s = m.get(SYSTEMS[i]).get(cap);
                sb.append(s == Support.FULL ? "\\checkmark" : "--");
                if (i < SYSTEMS.length - 1) {
                    sb.append(" & ");
                }
            }
            sb.append(" \\\\\n");
        }
        sb.append("\\bottomrule\n");
        sb.append("\\end{tabular}\n");
        sb.append("\\end{table}\n");
        sb.append("\n% ").append(subsetStatement()).append('\n');
        return sb.toString();
    }
}
