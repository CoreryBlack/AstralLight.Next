package com.coreryblack.benchmark.nativebenchmark;

import com.coreryblack.astral_permission.infrastructure.persistence.entity.permission.RuleSetEntry;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BenchmarkWinnerSelectorTest {

    @Test
    void selectsHighestPriorityAndUsesEntryIdAsTieBreaker() {
        RuleSetEntry low = entry(10L, 10, "ALLOW");
        RuleSetEntry high = entry(11L, 20, "DENY");
        RuleSetEntry samePriorityLater = entry(12L, 20, "ALLOW");

        var winners = BenchmarkWinnerSelector.select(List.of(low, high, samePriorityLater));

        assertEquals(1, winners.size());
        assertEquals("ALLOW", winners.values().iterator().next().getEffect());
        assertEquals(12L, winners.values().iterator().next().getEntryId());
    }

    @Test
    void keepsIndependentResourceAndActionKeysSeparate() {
        RuleSetEntry read = entry(1L, 1, "ALLOW");
        read.setActionCode("read");
        RuleSetEntry write = entry(2L, 1, "DENY");
        write.setActionCode("write");

        var winners = BenchmarkWinnerSelector.select(List.of(read, write));

        assertEquals(2, winners.size());
        assertEquals("ALLOW", winners.get(BenchmarkWinnerSelector.key(read)).getEffect());
        assertEquals("DENY", winners.get(BenchmarkWinnerSelector.key(write)).getEffect());
    }

    private static RuleSetEntry entry(long id, int priority, String effect) {
        RuleSetEntry entry = new RuleSetEntry();
        entry.setEntryId(id);
        entry.setResourceType("learn_subject");
        entry.setResourceId(100L);
        entry.setActionCode("read");
        entry.setPriority(priority);
        entry.setEffect(effect);
        return entry;
    }
}
