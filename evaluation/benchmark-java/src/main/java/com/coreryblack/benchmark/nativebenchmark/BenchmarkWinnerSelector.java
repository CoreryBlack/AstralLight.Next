package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Selects the deterministic winner for one rule-set key.
 *
 * <p>All projections used by the Java benchmark must use the same winner
 * function. A larger priority wins; entry id is the deterministic tie-breaker.
 * This prevents the database snapshot (first-write) and Redis hash (last-write)
 * paths from silently producing different effects.</p>
 */
public final class BenchmarkWinnerSelector {

    private BenchmarkWinnerSelector() {
    }

    public static Map<String, RuleSetEntry> select(Collection<RuleSetEntry> entries) {
        Map<String, RuleSetEntry> winners = new LinkedHashMap<>();
        for (RuleSetEntry candidate : entries) {
            String key = key(candidate);
            RuleSetEntry current = winners.get(key);
            if (current == null || outranks(candidate, current)) {
                winners.put(key, candidate);
            }
        }
        return winners;
    }

    public static String key(RuleSetEntry entry) {
        return entry.getResourceType() + ":"
            + (entry.getResourceId() != null ? entry.getResourceId() : "*")
            + ":" + entry.getActionCode();
    }

    private static boolean outranks(RuleSetEntry candidate, RuleSetEntry current) {
        int candidatePriority = candidate.getPriority() == null
            ? Integer.MIN_VALUE : candidate.getPriority();
        int currentPriority = current.getPriority() == null
            ? Integer.MIN_VALUE : current.getPriority();
        if (candidatePriority != currentPriority) {
            return candidatePriority > currentPriority;
        }
        long candidateId = candidate.getEntryId() == null ? Long.MIN_VALUE : candidate.getEntryId();
        long currentId = current.getEntryId() == null ? Long.MIN_VALUE : current.getEntryId();
        return candidateId > currentId;
    }
}
