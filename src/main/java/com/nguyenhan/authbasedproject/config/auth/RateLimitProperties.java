package com.nguyenhan.authbasedproject.config.auth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "security.rate-limit")
@Getter
@Setter
public class RateLimitProperties {

    private RateLimitConfig login;
    private RateLimitConfig api;
    private RateLimitConfig global;

    @Setter
    @Getter
    public static class RateLimitConfig {
        private int requests;
        private Duration window;
    }

}
