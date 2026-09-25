package com.coreryblack.benchmark.nativebenchmark;

/**
 * Shared configuration for RQ5 additional benchmark scenarios.
 *
 * <p>Centralizes the scale and concurrency parameters so that
 * {@link SupplementaryExperimentRunner} and
 * {@link NativeAstralBenchmark#runRq5(String)} use identical configurations,
 * eliminating the dual-maintenance drift of the previous design.
 */
final class RQ5Configs {

    private RQ5Configs() {}

    /** Configuration for the direct-PDP card-selection benchmark. */
    static final NativeScaleConfig SAT_CONFIG = NativeScaleConfig.builder()
        .cardCount(1000).templateCount(2).baseRulesPerCard(40)
        .overlayRulesPerCard(5).resourceTypes(10).actionsPerResource(5)
        .denyRatio(0.4).build();

    /** Scale sweep for the throughput benchmark. */
    static final NativeScaleConfig[] SCALES = {
        NativeScaleConfig.builder().cardCount(100).templateCount(1)
            .baseRulesPerCard(40).overlayRulesPerCard(5)
            .resourceTypes(10).actionsPerResource(5).denyRatio(0.3).build(),
        NativeScaleConfig.builder().cardCount(1000).templateCount(2)
            .baseRulesPerCard(40).overlayRulesPerCard(5)
            .resourceTypes(10).actionsPerResource(5).denyRatio(0.3).build(),
        NativeScaleConfig.builder().cardCount(5000).templateCount(2)
            .baseRulesPerCard(40).overlayRulesPerCard(5)
            .resourceTypes(10).actionsPerResource(5).denyRatio(0.3).build(),
        NativeScaleConfig.builder().cardCount(10000).templateCount(3)
            .baseRulesPerCard(40).overlayRulesPerCard(5)
            .resourceTypes(10).actionsPerResource(5).denyRatio(0.3).build(),
    };

    /** Concurrency sweep for the throughput benchmark. */
    static final int[] CONCURRENCIES = {1, 4, 8, 16, 32};

    /** Measurement duration per (scale, concurrency) configuration. */
    static final int MEASURE_SEC = 15;
}
