package com.nguyenhan.authbasedproject.service.auth;

import com.nguyenhan.authbasedproject.config.auth.BruteForceProperties;
import com.nguyenhan.authbasedproject.entity.auth.LoginStatus;
import jakarta.annotation.PostConstruct;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

@Service
public class LoginAttemptService {

    private static final Logger logger = LoggerFactory.getLogger(LoginAttemptService.class);

    @Autowired
    @Qualifier("loginStatusRedisTemplate")
    private RedisTemplate<String, LoginStatus> redisTemplate;

    @Autowired
    private BruteForceProperties bruteForceProperties;

    @PostConstruct
    public void testRedis() {
        try {
            LoginStatus status = new LoginStatus(1, Instant.now(), Instant.now().plusSeconds(60));
            String testKey = "debug:test";

            // Store the test object
            redisTemplate.opsForValue().set(testKey, status);
            logger.info("✅ Successfully stored test LoginStatus in Redis");

            // Retrieve and verify
            LoginStatus result = redisTemplate.opsForValue().get(testKey);
            if (result != null) {
                logger.info("✅ Redis connection successful. Retrieved: failedAttempts={}, lastFailed={}",
                        result.getFailedAttempts(), result.getLastFailed());
            } else {
                logger.warn("⚠️ Retrieved null from Redis");
            }

            // Clean up test data
            redisTemplate.delete(testKey);

        } catch (ClassCastException e) {
            logger.error("❌ Redis deserialization error - check Redis configuration: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("❌ Redis connection failed during startup: {}", e.getMessage());
        }
    }

    private String key(String username) {
        return "login:attempts:" + username;
    }

    public void loginSucceeded(String username) {
        try {
            redisTemplate.delete(key(username));
            logger.debug("Cleared login attempts for user: {}", username);
        } catch (Exception e) {
            logger.error("Failed to clear login attempts for user: {}, Error: {}", username, e.getMessage());
        }
    }

    public void loginFailed(String username) {
        try {
            String redisKey = key(username);
            LoginStatus status = redisTemplate.opsForValue().get(redisKey);

            if (status == null) {
                status = new LoginStatus(1, Instant.now(), null);
                logger.debug("Created new login status for user: {}", username);
            } else {
                status.setFailedAttempts(status.getFailedAttempts() + 1);
                status.setLastFailed(Instant.now());

                if (status.getFailedAttempts() >= bruteForceProperties.getMaxAttempts()) {
                    status.setLockUntil(Instant.now().plus(bruteForceProperties.getLockoutDuration()));
                    logger.warn("User {} has been locked after {} failed attempts", username, status.getFailedAttempts());
                }
            }

            redisTemplate.opsForValue().set(redisKey, status, bruteForceProperties.getResetDuration());
            logger.debug("Updated login failure count for user: {} (attempts: {})", username, status.getFailedAttempts());

        } catch (ClassCastException e) {
            logger.error("Redis deserialization error for user {}: {}", username, e.getMessage());
        } catch (Exception e) {
            logger.error("Failed to record login failure for user: {}, Error: {}", username, e.getMessage());
        }
    }

    public boolean isLocked(String username) {
        try {
            LoginStatus status = redisTemplate.opsForValue().get(key(username));
            boolean locked = status != null && status.getLockUntil() != null && status.getLockUntil().isAfter(Instant.now());

            if (locked) {
                logger.debug("User {} is locked until {}", username, status.getLockUntil());
            }

            return locked;
        } catch (ClassCastException e) {
            logger.error("Redis deserialization error checking lock status for user {}: {}", username, e.getMessage());
            return false; // Fail safe - don't lock user if we can't deserialize
        } catch (Exception e) {
            logger.error("Failed to check lock status for user: {}, Error: {}", username, e.getMessage());
            return false; // Fail safe - don't lock user if Redis is down
        }
    }

    public Duration getProgressiveDelay(String username) {
        try {
            if (!bruteForceProperties.getProgressiveDelay().isEnabled()) {
                return Duration.ZERO;
            }

            LoginStatus status = redisTemplate.opsForValue().get(key(username));
            if (status == null) {
                return Duration.ZERO;
            }

            int overAttempts = Math.max(0, status.getFailedAttempts() - bruteForceProperties.getMaxAttempts());
            double delay = bruteForceProperties.getProgressiveDelay().getBaseDelay().toMillis() *
                    Math.pow(bruteForceProperties.getProgressiveDelay().getMultiplier(), overAttempts);

            Duration calculatedDelay = Duration.ofMillis((long) Math.min(delay, bruteForceProperties.getProgressiveDelay().getMaxDelay().toMillis()));

            if (!calculatedDelay.isZero()) {
                logger.debug("Progressive delay for user {}: {}ms", username, calculatedDelay.toMillis());
            }

            return calculatedDelay;
        } catch (ClassCastException e) {
            logger.error("Redis deserialization error calculating delay for user {}: {}", username, e.getMessage());
            return Duration.ZERO; // Fail safe - no delay if we can't deserialize
        } catch (Exception e) {
            logger.error("Failed to calculate progressive delay for user: {}, Error: {}", username, e.getMessage());
            return Duration.ZERO; // Fail safe - no delay if Redis is down
        }
    }
}