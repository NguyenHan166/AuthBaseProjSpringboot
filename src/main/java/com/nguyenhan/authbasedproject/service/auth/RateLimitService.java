package com.nguyenhan.authbasedproject.service.auth;

import com.nguyenhan.authbasedproject.config.auth.RateLimitProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class RateLimitService {

    @Autowired
    @Qualifier("stringRedisTemplate")
    private RedisTemplate<String, String> redisTemplate;

    @Autowired
    private RateLimitProperties rateLimitProperties;

    @Autowired
    private IPBlockService ipBlockService;
    private final Logger logger = LoggerFactory.getLogger(RateLimitService.class);

    public boolean isAllowed(String ip, String type) {

        if (ipBlockService.isBlocked(ip)) return false;
        RateLimitProperties.RateLimitConfig config = getConfig(type);
        String key = "rate_limit:" + type + ":" + ip;

        Long current = redisTemplate.opsForValue().increment(key);

        if (current == 1) {
            redisTemplate.expire(key, config.getWindow());
            logger.info("Rate limit for type: {} has been initialized for IP: {}", type, ip);
        }

        if (current > config.getRequests()) {
            ipBlockService.blockIP(ip);
            logger.warn("IP {} has been blocked due to exceeding rate limit for type: {}", ip, type);
            return false;
        }

        return true;
    }

    public long getRemainingTTL(String ip, String type) {
        String key = "rate_limit:" + type + ":" + ip;
        return redisTemplate.getExpire(key , TimeUnit.SECONDS);
    }

    private RateLimitProperties.RateLimitConfig getConfig(String type) {
        switch (type) {
            case "login":
                return rateLimitProperties.getLogin();
            case "api":
                return rateLimitProperties.getApi();
            case "global":
                return rateLimitProperties.getGlobal();
            default:
                return rateLimitProperties.getGlobal();
        }
    }
}
