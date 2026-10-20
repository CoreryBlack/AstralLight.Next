package com.coreryblack.astrlIdentity.service;

/**
 * Test-only coordination hook for controlled lease experiments. No bean is
 * registered outside the explicitly enabled TDSC fault profile.
 */
public interface SessionProjectionPostClaimGate {

    /**
     * Acknowledges a completed atomic claim and waits for a bounded test release.
     *
     * @return true only when this invocation passed through the armed test gate
     */
    boolean awaitAfterClaim();

    /** Records that the gated claimant lost its lease after another worker completed the row. */
    void acknowledgeLeaseLost();
}
