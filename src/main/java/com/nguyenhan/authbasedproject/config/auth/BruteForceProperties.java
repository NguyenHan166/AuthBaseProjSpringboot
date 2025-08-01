package com.nguyenhan.authbasedproject.config.auth;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@ConfigurationProperties(prefix = "security.brute-force")
@Data
public class BruteForceProperties {
    private int maxAttempts;
    private Duration lockoutDuration;
    private Duration resetDuration;
    private ProgressiveDelay progressiveDelay;

    @Data
    public static class ProgressiveDelay {
        private boolean enabled;
        private Duration baseDelay;
        private Duration maxDelay;
        private double multiplier;
    }
}
