package com.coreryblack.benchmark.util;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class BenchmarkCleanupUtilTest {

    private static final String DESTRUCTIVE_CLEANUP_PROPERTY = "benchmark.allow-destructive-cleanup";

    @AfterEach
    void clearDestructiveCleanupProperty() {
        System.clearProperty(DESTRUCTIVE_CLEANUP_PROPERTY);
    }

    @Test
    void cleanupAllRejectsMissingExplicitApproval() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);

        assertThrows(IllegalStateException.class,
                () -> BenchmarkCleanupUtil.cleanupAll(jdbcTemplate, redisTemplate));

        verifyNoInteractions(jdbcTemplate, redisTemplate);
    }

    @Test
    void cleanupRedisRejectsMissingExplicitApproval() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);

        assertThrows(IllegalStateException.class,
                () -> BenchmarkCleanupUtil.cleanupRedis(redisTemplate));

        verifyNoInteractions(redisTemplate);
    }

    @Test
    void cleanupDatabaseRejectsMissingExplicitApproval() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);

        assertThrows(IllegalStateException.class,
                () -> BenchmarkCleanupUtil.cleanupDatabase(jdbcTemplate));

        verifyNoInteractions(jdbcTemplate);
    }
}
