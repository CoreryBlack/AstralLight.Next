package com.coreryblack.benchmark.nativebenchmark;

import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Benchmark 专用确定性 ID 生成器。
 * 从 NativeDataGenerator 中提取，负责为 RuleSet、Entry、Snapshot、Policy 生成可复现的递增 ID，
 * 避免依赖数据库自增，保证多次运行的数据一致性。
 */
@Component
public class BenchmarkIdGenerator {

    private final AtomicLong ruleSetIdSeq = new AtomicLong(0);
    private final AtomicLong entryIdSeq = new AtomicLong(0);
    private final AtomicLong snapshotIdSeq = new AtomicLong(0);
    private final AtomicLong permissionRuleIdSeq = new AtomicLong(0);
    private final AtomicLong policyIdSeq = new AtomicLong(0);

    public long nextRuleSetId() {
        return ruleSetIdSeq.incrementAndGet();
    }

    public long nextEntryId() {
        return entryIdSeq.incrementAndGet();
    }

    public long nextSnapshotId() {
        return snapshotIdSeq.incrementAndGet();
    }

    /**
     * Generates deterministic permission-rule IDs so card-only snapshots can
     * refer to the exact persisted rule without relying on JDBC key backfill.
     */
    public long nextPermissionRuleId() {
        return permissionRuleIdSeq.incrementAndGet();
    }

    public long nextPolicyId() {
        return policyIdSeq.incrementAndGet();
    }

    public void reset() {
        ruleSetIdSeq.set(0);
        entryIdSeq.set(0);
        snapshotIdSeq.set(0);
        permissionRuleIdSeq.set(0);
        policyIdSeq.set(0);
    }
}
