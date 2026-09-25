package com.coreryblack.benchmark.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
public class BenchmarkCleanupUtil {

    private static final int DB_RETRY_ATTEMPTS = 5;
    private static final long DB_RETRY_DELAY_MS = 2000L;
    private static final String DESTRUCTIVE_CLEANUP_PROPERTY = "benchmark.allow-destructive-cleanup";

    private static final String[] TABLES_TO_CLEAN = {
        "authorization_projection_outbox",
        "authorization_projection_head",
        "card_rule_set_ref",
        "rule_set_snapshot",
        "rule_set_entry",
        "rule_set",
        "permission_rule_snapshot",
        "permission_rule",
        "sod_policy",
        "user_card",
        "user_card_template"
    };

    private BenchmarkCleanupUtil() {}

    /**
     * Best-effort cleanup — failures are logged but not propagated.
     * Suitable for non-critical cleanup between non-comparison benchmarks.
     */
    public static void cleanupAll(JdbcTemplate jdbcTemplate, StringRedisTemplate redisTemplate) {
        cleanupAll(jdbcTemplate, redisTemplate, false);
    }

    /**
     * Strict cleanup — Redis failures throw to prevent cache contamination.
     * Use in comparison benchmarks where data integrity is critical.
     */
    public static void cleanupAllStrict(JdbcTemplate jdbcTemplate, StringRedisTemplate redisTemplate) {
        cleanupAll(jdbcTemplate, redisTemplate, true);
    }

    private static void cleanupAll(JdbcTemplate jdbcTemplate, StringRedisTemplate redisTemplate, boolean strict) {
        requireDestructiveCleanupApproval();
        cleanupRedis(redisTemplate, strict);
        cleanupDatabase(jdbcTemplate, strict);
    }

    private static void requireDestructiveCleanupApproval() {
        if (!Boolean.getBoolean(DESTRUCTIVE_CLEANUP_PROPERTY)) {
            throw new IllegalStateException("Refusing destructive benchmark cleanup. "
                    + "Run only against dedicated MySQL and Redis, then set -D"
                    + DESTRUCTIVE_CLEANUP_PROPERTY + "=true.");
        }
    }

    public static void cleanupRedis(StringRedisTemplate redisTemplate) {
        requireDestructiveCleanupApproval();
        cleanupRedis(redisTemplate, false);
    }

    private static void cleanupRedis(StringRedisTemplate redisTemplate, boolean strict) {
        try (var conn = redisTemplate.getConnectionFactory().getConnection()) {
            conn.serverCommands().flushDb();
            log.debug("Redis flushed");
        } catch (Exception e) {
            if (strict) {
                throw new RuntimeException("Redis flush failed — refusing to proceed with stale cache", e);
            }
            log.warn("Redis flush failed (may not be available): {}", e.getMessage());
        }
    }

    public static void cleanupDatabase(JdbcTemplate jdbcTemplate) {
        requireDestructiveCleanupApproval();
        cleanupDatabase(jdbcTemplate, false);
    }

    private static void cleanupDatabase(JdbcTemplate jdbcTemplate, boolean strict) {
        List<String> failedTables = new ArrayList<>();

        RuntimeException lastError = null;
        for (int attempt = 1; attempt <= DB_RETRY_ATTEMPTS; attempt++) {
            failedTables.clear();
            try {
                jdbcTemplate.execute("SET FOREIGN_KEY_CHECKS = 0");
                for (String table : TABLES_TO_CLEAN) {
                    try {
                        jdbcTemplate.execute("TRUNCATE TABLE " + table);
                        log.debug("Truncated table: {}", table);
                    } catch (Exception e) {
                        failedTables.add(table);
                        log.warn("Failed to truncate table {}: {}", table, e.getMessage());
                    }
                }
                jdbcTemplate.execute("SET FOREIGN_KEY_CHECKS = 1");
                lastError = null;
                break;
            } catch (Exception e) {
                lastError = new RuntimeException("Database cleanup attempt " + attempt + " failed", e);
                log.warn("Database cleanup attempt {}/{} failed: {}", attempt, DB_RETRY_ATTEMPTS, e.getMessage());
                if (attempt < DB_RETRY_ATTEMPTS) {
                    sleepQuietly(DB_RETRY_DELAY_MS);
                }
            }
        }

        if (lastError != null) {
            if (strict) {
                throw new RuntimeException("Database cleanup failed after retries — refusing to proceed with stale data", lastError);
            }
            log.warn("Database cleanup failed after retries, continuing: {}", lastError.getMessage());
            return;
        }

        if (strict && !failedTables.isEmpty()) {
            throw new RuntimeException("TRUNCATE failed for tables: " + failedTables
                + " — refusing to proceed with stale data");
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            TimeUnit.MILLISECONDS.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
