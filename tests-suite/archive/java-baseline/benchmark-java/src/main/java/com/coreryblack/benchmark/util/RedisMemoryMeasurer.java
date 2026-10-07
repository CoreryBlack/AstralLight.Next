package com.coreryblack.benchmark.util;

import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisServerCommands;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.Properties;

public class RedisMemoryMeasurer {

    private final StringRedisTemplate redisTemplate;

    public RedisMemoryMeasurer(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public MemorySnapshot measure() {
        Properties info = redisTemplate.execute((RedisCallback<Properties>) conn ->
            conn.serverCommands().info("memory"));
        Properties keyspace = redisTemplate.execute((RedisCallback<Properties>) conn ->
            conn.serverCommands().info("keyspace"));

        MemorySnapshot snap = new MemorySnapshot();
        if (info != null) {
            snap.usedMemoryBytes = parseLong(info.getProperty("used_memory", "0"));
            snap.usedMemoryRssBytes = parseLong(info.getProperty("used_memory_rss", "0"));
            snap.peakMemoryBytes = parseLong(info.getProperty("used_memory_peak", "0"));
            snap.totalSystemMemoryBytes = parseLong(info.getProperty("total_system_memory", "0"));
            snap.fragmentationRatio = parseDouble(info.getProperty("mem_fragmentation_ratio", "1.0"));
        }
        if (keyspace != null) {
            snap.dbKeyCount = parseDbKeys(keyspace.getProperty("db0", ""));
        }
        return snap;
    }

    public long measureKeyMemory(String keyPattern) {
        Long startMem = getUsedMemory();
        return startMem != null ? startMem : 0L;
    }

    private Long getUsedMemory() {
        Properties info = redisTemplate.execute((RedisCallback<Properties>) conn ->
            conn.serverCommands().info("memory"));
        return info != null ? parseLong(info.getProperty("used_memory", "0")) : null;
    }

    private long parseLong(String val) {
        try { return Long.parseLong(val); } catch (Exception e) { return 0L; }
    }

    private double parseDouble(String val) {
        try { return Double.parseDouble(val); } catch (Exception e) { return 0.0; }
    }

    private long parseDbKeys(String dbInfo) {
        if (dbInfo == null || dbInfo.isEmpty()) return 0;
        for (String part : dbInfo.split(",")) {
            if (part.startsWith("keys=")) {
                return parseLong(part.substring(5));
            }
        }
        return 0;
    }

    public static class MemorySnapshot {
        public long usedMemoryBytes;
        public long usedMemoryRssBytes;
        public long peakMemoryBytes;
        public long totalSystemMemoryBytes;
        public double fragmentationRatio;
        public long dbKeyCount;

        public double usedMemoryMb() {
            return usedMemoryBytes / (1024.0 * 1024.0);
        }

        @Override
        public String toString() {
            return String.format("used=%.2fMB, rss=%.2fMB, peak=%.2fMB, keys=%d, frag_ratio=%.2f",
                usedMemoryMb(),
                usedMemoryRssBytes / (1024.0 * 1024.0),
                peakMemoryBytes / (1024.0 * 1024.0),
                dbKeyCount, fragmentationRatio);
        }
    }
}
