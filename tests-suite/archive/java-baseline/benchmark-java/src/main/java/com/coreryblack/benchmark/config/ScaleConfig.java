package com.coreryblack.benchmark.config;

import lombok.Builder;
import lombok.Data;

/**
 * Scale configuration for multi-system comparison benchmarks.
 *
 * <p>All gradients are aligned with {@code NativeScaleConfig} parameters
 * (minus Native-only fields like ABAC, PERM_RULE, multi-overlay).
 * Control variable method is used where applicable.
 */
@Data
@Builder
public class ScaleConfig {

    private int cardCount;
    private int baseRulesPerCard;
    private int overlayRulesPerCard;
    private int resourceTypes;
    private int actionsPerResource;
    private double denyRatio;

    /** Number of templates to distribute cards across. 0 or 1 means single template. */
    @Builder.Default
    private int templateCount = 1;

    /** Number of domains for multi-domain testing. 0 or 1 means single domain. */
    @Builder.Default
    private int domainCount = 1;

    public int totalNominalRules() {
        return cardCount * (baseRulesPerCard + overlayRulesPerCard);
    }

    public String label() {
        return "cards=" + cardCount
            + "|tpl=" + Math.max(1, templateCount)
            + "|base=" + baseRulesPerCard
            + "|overlay=" + overlayRulesPerCard
            + "|res=" + resourceTypes
            + "|act=" + actionsPerResource
            + "|deny=" + String.format("%.0f%%", denyRatio * 100);
    }

    // ═══════════════════════════════════════════════════════════════
    // RQ-Compare-1 Decision Latency — only cardCount varies, all else fixed
    // ═══════════════════════════════════════════════════════════════
    public static ScaleConfig[] decisionLatencyGradient() {
        return new ScaleConfig[]{
            // Small scale — baseline latency
            ScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            // Mid scale
            ScaleConfig.builder()
                .cardCount(1000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            // Large scale
            ScaleConfig.builder()
                .cardCount(10000).templateCount(2).baseRulesPerCard(40).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            // Max scale — all systems must participate (no skipping)
            ScaleConfig.builder()
                .cardCount(50000).templateCount(3).baseRulesPerCard(40).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // RQ2 Main gradient — aligned with NativeScaleConfig.nativeGradientScale()
    // Capped at 50K cards: Cedar entity hierarchy O(n) makes larger scales impractical
    // ═══════════════════════════════════════════════════════════════
    public static ScaleConfig[] gradientScale() {
        return new ScaleConfig[]{
            ScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(10).overlayRulesPerCard(2)
                .resourceTypes(5).actionsPerResource(2).denyRatio(0.2).build(),
            ScaleConfig.builder()
                .cardCount(1000).templateCount(1).baseRulesPerCard(10).overlayRulesPerCard(3)
                .resourceTypes(5).actionsPerResource(2).denyRatio(0.2).build(),
            ScaleConfig.builder()
                .cardCount(10000).templateCount(2).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(50000).templateCount(3).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(15).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // Rule Complexity — aligned with Native (control variable method)
    // Only baseRulesPerCard varies; overlay/res/act/deny held constant.
    // Capped at 1000 rules/card: Cedar policy count grows linearly with rules
    // ═══════════════════════════════════════════════════════════════
    public static ScaleConfig[] ruleComplexityGradient() {
        // Cross-system rule-growth comparison stays inside the common
        // expressible subset (overlayRulesPerCard=0, single tenant) so the
        // measured numbers are comparable across AstralLight, Casbin(Cached)
        // and Cedar. Only baseRulesPerCard varies; res/act/deny held constant.
        return new ScaleConfig[]{
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(10).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(50).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(100).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(500).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(1000).overlayRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // Card Scale — aligned with Native (100:1 tpl:card ratio)
    // Capped at 50K cards: Cedar entity hierarchy O(n) makes larger scales impractical
    // ═══════════════════════════════════════════════════════════════
    public static ScaleConfig[] cardScaleGradient() {
        // Card-count sensitivity comparison stays inside the common expressible
        // subset (overlayRulesPerCard=0, single tenant). Previously this gradient
        // used overlay=5 and domainCount=2 at 10k/50k cards, which violated the
        // subset and produced invalid AstralLight latencies: data-scope filters
        // on domain=2 cards evaluated under a fixed domain=1 context took the
        // slow path (~15ms vs ~2.5ms at the same card count in Layer A).
        return new ScaleConfig[]{
            ScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(0)
                .domainCount(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(1000).templateCount(10).baseRulesPerCard(40).overlayRulesPerCard(0)
                .domainCount(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).templateCount(100).baseRulesPerCard(40).overlayRulesPerCard(0)
                .domainCount(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(50000).templateCount(500).baseRulesPerCard(40).overlayRulesPerCard(0)
                .domainCount(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // Overlay Depth — already aligned with Native
    // ═══════════════════════════════════════════════════════════════
    public static ScaleConfig[] overlayDepthGradient() {
        return new ScaleConfig[]{
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(10)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(20)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(50)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    // ═══════════════════════════════════════════════════════════════
    // Conflict Density — aligned with Native (B18: 1.0→0.8)
    // ═══════════════════════════════════════════════════════════════
    public static ScaleConfig[] conflictDensityGradient() {
        return new ScaleConfig[]{
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.0).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.1).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.5).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.7).build(),
            ScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.8).build(),
        };
    }

    public static ScaleConfig rq1Default() {
        return ScaleConfig.builder()
            .cardCount(5000).templateCount(2).baseRulesPerCard(40).overlayRulesPerCard(5)
            .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build();
    }
}
