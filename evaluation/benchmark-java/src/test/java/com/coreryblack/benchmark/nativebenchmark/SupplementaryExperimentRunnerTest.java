package com.coreryblack.benchmark.nativebenchmark;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SupplementaryExperimentRunnerTest {

    private static final String DESTRUCTIVE_CLEANUP_PROPERTY = "benchmark.allow-destructive-cleanup";

    @AfterEach
    void clearDestructiveCleanupProperty() {
        System.clearProperty(DESTRUCTIVE_CLEANUP_PROPERTY);
    }

    @Test
    void rejectsMissingExplicitDestructiveCleanupApproval() {
        assertThrows(IllegalStateException.class, SupplementaryExperimentRunner::requireDestructiveCleanupApproval);
    }

    @Test
    void acceptsExplicitDestructiveCleanupApproval() {
        System.setProperty(DESTRUCTIVE_CLEANUP_PROPERTY, "true");

        assertDoesNotThrow(SupplementaryExperimentRunner::requireDestructiveCleanupApproval);
    }
}
