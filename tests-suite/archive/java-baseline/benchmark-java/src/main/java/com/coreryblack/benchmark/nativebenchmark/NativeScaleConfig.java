package com.coreryblack.benchmark.nativebenchmark;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class NativeScaleConfig {

    private int cardCount;
    @Builder.Default
    private int templateCount = 1;
    private int baseRulesPerCard;
    private int overlayRulesPerCard;
    @Builder.Default
    private int permissionRulesPerCard = 0;
    @Builder.Default
    private int abacConditionsPerRule = 0;
    private int resourceTypes;
    private int actionsPerResource;
    private double denyRatio;
    /** ABAC-specific deny ratio (reserved for future use; currently NOT consumed by NativeDataGenerator). */
    @Builder.Default
    private double abacDenyRatio = 0.0;
    @Builder.Default
    private boolean multiDomain = false;
    @Builder.Default
    private int domainCount = 1;
    @Builder.Default
    private int tenantCount = 1;
    @Builder.Default
    private boolean multiOverlayEnabled = false;
    /** Number of additional OVERLAY refs per card when multiOverlayEnabled=true. Default=1 (backward compatible). */
    @Builder.Default
    private int multiOverlayCount = 1;
    /**
     * Ablation switch: when true, every card receives its own dedicated BASE
     * (and OVERLAY) rule set instead of sharing the template-level rule sets.
     * Used only by the ablation campaign to measure the cost of the shared
     * rule-set representation. Default=false (production-style shared).
     */
    @Builder.Default
    private boolean perCardRuleSets = false;

    public int totalNominalRules() {
        return cardCount * (baseRulesPerCard + overlayRulesPerCard + permissionRulesPerCard);
    }

    public String label() {
        StringBuilder sb = new StringBuilder();
        sb.append("cards=").append(cardCount);
        // B19 fix: 使用 Math.max(1, templateCount) 与 NativeDataGenerator 保持一致，
        // 确保标签输出的是实际生效的模板数量
        sb.append("|tpl=").append(Math.max(1, templateCount));
        sb.append("|base=").append(baseRulesPerCard);
        sb.append("|overlay=").append(overlayRulesPerCard);
        if (permissionRulesPerCard > 0) {
            sb.append("|perm=").append(permissionRulesPerCard);
        }
        if (abacConditionsPerRule > 0) {
            sb.append("|abac=").append(abacConditionsPerRule);
        }
        sb.append("|res=").append(resourceTypes);
        sb.append("|act=").append(actionsPerResource);
        sb.append("|deny=").append(String.format("%.0f%%", denyRatio * 100));
        if (perCardRuleSets) {
            sb.append("|perCardRuleSets=true");
        }
        // abacDenyRatio currently not consumed by data generator; omit from label to avoid misleading
        if (multiDomain) {
            sb.append("|domains=").append(domainCount);
        }
        return sb.toString();
    }

    public static NativeScaleConfig[] nativeGradientScale() {
        return new NativeScaleConfig[]{
            // B14 fix: all gradients now include OVERLAY and DENY for consistency
            NativeScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(10).overlayRulesPerCard(2)
                .resourceTypes(5).actionsPerResource(2).denyRatio(0.2).build(),
            NativeScaleConfig.builder()
                .cardCount(1000).templateCount(1).baseRulesPerCard(10).overlayRulesPerCard(3)
                .resourceTypes(5).actionsPerResource(2).denyRatio(0.2).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(2).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(50000).templateCount(3).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(2)
                .resourceTypes(15).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(100000).templateCount(5).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(3)
                .resourceTypes(20).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    public static NativeScaleConfig[] nativeRuleComplexityGradient() {
        // B15 fix: control variable method — only baseRulesPerCard varies,
        // all other parameters are held constant to isolate rule count effect
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(10).overlayRulesPerCard(5)
                .abacConditionsPerRule(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(50).overlayRulesPerCard(5)
                .abacConditionsPerRule(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(100).overlayRulesPerCard(5)
                .abacConditionsPerRule(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(500).overlayRulesPerCard(5)
                .abacConditionsPerRule(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(1000).overlayRulesPerCard(5)
                .abacConditionsPerRule(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(5000).overlayRulesPerCard(5)
                .abacConditionsPerRule(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    public static NativeScaleConfig[] nativeCardScaleGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(100).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .domainCount(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(1000).templateCount(10).baseRulesPerCard(40).overlayRulesPerCard(5)
                .domainCount(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(100).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiDomain(true).domainCount(2)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(50000).templateCount(500).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiDomain(true).domainCount(2)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(100000).templateCount(1000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiDomain(true).domainCount(3)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(400000).templateCount(4000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiDomain(true).domainCount(3)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(500000).templateCount(5000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiDomain(true).domainCount(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(1000000).templateCount(5000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiDomain(true).domainCount(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    public static NativeScaleConfig[] nativeOverlayDepthGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(10)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(20)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(50)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    public static NativeScaleConfig[] nativeConflictDensityGradient() {
        // B18 fix: denyRatio=1.0 is all-DENY (no conflict), replaced with 0.8 as max
        // Key sampling points: 0.0 (no deny), 0.3 (moderate), 0.5 (max conflict), 0.7 (deny-dominant)
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .denyRatio(0.0).abacDenyRatio(0.0)
                .resourceTypes(10).actionsPerResource(4).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .denyRatio(0.1).abacDenyRatio(0.05)
                .resourceTypes(10).actionsPerResource(4).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .denyRatio(0.3).abacDenyRatio(0.1)
                .resourceTypes(10).actionsPerResource(4).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .denyRatio(0.5).abacDenyRatio(0.2)
                .resourceTypes(10).actionsPerResource(4).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .denyRatio(0.7).abacDenyRatio(0.3)
                .resourceTypes(10).actionsPerResource(4).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .denyRatio(0.8).abacDenyRatio(0.4)
                .resourceTypes(10).actionsPerResource(4).build(),
        };
    }

    public static NativeScaleConfig[] nativeAbacComplexityGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(0).abacDenyRatio(0.0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(1).abacDenyRatio(0.1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(3).abacDenyRatio(0.15)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(5).abacDenyRatio(0.2)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(8).abacDenyRatio(0.25)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    public static NativeScaleConfig[] nativePipelineStageGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(0)
                .permissionRulesPerCard(0).abacConditionsPerRule(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(0).abacConditionsPerRule(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(0).abacConditionsPerRule(3)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(5).abacConditionsPerRule(3)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(5).abacConditionsPerRule(3)
                .multiDomain(true).domainCount(3)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    public static NativeScaleConfig nativeRq1Default() {
        return NativeScaleConfig.builder()
            .cardCount(5000).templateCount(2).baseRulesPerCard(40).overlayRulesPerCard(5)
            .abacConditionsPerRule(2).abacDenyRatio(0.1)
            .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build();
    }

    /**
     * RQ2-G: Template isolation gradient — verify O(1) w.r.t. T.
     * Fixed N=10000, M=40, vary T=1/5/10/20/50/100.
     */
    public static NativeScaleConfig[] nativeTemplateIsolationGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(5).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(10).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(20).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(50).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(100).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    /**
     * RQ2-H: Card isolation gradient — verify O(1) w.r.t. N.
     * Fixed T=1, M=40, vary N=1K/5K/10K/50K/100K/500K.
     */
    public static NativeScaleConfig[] nativeCardIsolationGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(1000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(5000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(50000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(100000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(500000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    /**
     * RQ2-I: Overlay ref count gradient — verify O(K) for OVERLAY refs.
     * Fixed N=10000, M=40. Vary multiOverlayCount to produce
     * 2/4/8/16 total refs per card (1 BASE + 1 primary + 0/2/6/14 extra).
     */
    public static NativeScaleConfig[] nativeOverlayRefGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiOverlayEnabled(false).multiOverlayCount(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiOverlayEnabled(true).multiOverlayCount(2)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiOverlayEnabled(true).multiOverlayCount(6)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).templateCount(1).baseRulesPerCard(40).overlayRulesPerCard(5)
                .multiOverlayEnabled(true).multiOverlayCount(14)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    /**
     * RQ2-J: ABAC complexity gradient — verify O(C) for ABAC condition evaluation.
     * Fixed N=10000, M=40, vary abacConditionsPerRule=0/1/2/4/8.
     */
    public static NativeScaleConfig[] nativeAbacComplexityIsolationGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(0).abacDenyRatio(0.0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(1).abacDenyRatio(0.1)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(2).abacDenyRatio(0.15)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(4).abacDenyRatio(0.2)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .abacConditionsPerRule(8).abacDenyRatio(0.25)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    /**
     * RQ2-K: Permission rule gradient — verify L2 path performance.
     * Fixed N=10000, M=40, vary permissionRulesPerCard=0/5/10/20/50.
     */
    public static NativeScaleConfig[] nativePermRuleGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(0)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(5)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(10)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(20)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(10000).baseRulesPerCard(40).overlayRulesPerCard(5)
                .permissionRulesPerCard(50)
                .resourceTypes(10).actionsPerResource(4).denyRatio(0.3).build(),
        };
    }

    /**
     * Small local/remote smoke gradient. It exercises the same L1/L2/L3 trace
     * contract without presenting it as a full-scale measurement.
     */
    public static NativeScaleConfig[] nativePermRuleSmokeGradient() {
        return new NativeScaleConfig[]{
            NativeScaleConfig.builder()
                .cardCount(100).templateCount(2).baseRulesPerCard(4).overlayRulesPerCard(1)
                .permissionRulesPerCard(0)
                .resourceTypes(3).actionsPerResource(2).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(100).templateCount(2).baseRulesPerCard(4).overlayRulesPerCard(1)
                .permissionRulesPerCard(2)
                .resourceTypes(3).actionsPerResource(2).denyRatio(0.3).build(),
            NativeScaleConfig.builder()
                .cardCount(100).templateCount(2).baseRulesPerCard(4).overlayRulesPerCard(1)
                .permissionRulesPerCard(5)
                .resourceTypes(3).actionsPerResource(2).denyRatio(0.3).build(),
        };
    }
}
