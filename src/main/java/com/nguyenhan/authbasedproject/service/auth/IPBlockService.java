package com.nguyenhan.authbasedproject.service.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class IPBlockService {

    @Autowired
    @Qualifier("stringRedisTemplate")
    private RedisTemplate<String, String> redisTemplate;

    private final Duration BLOCK_DURATION = Duration.ofHours(1); // Duration for which the IP is blocked

//    public IPBlockService(RedisTemplate<String, String> redisTemplate) {
//        this.redisTemplate = redisTemplate;
//    }

    public void blockIP(String ip) {
        // Set the IP in Redis with a block duration
        redisTemplate.opsForValue().set("blocked_ip:" + ip, "true", BLOCK_DURATION);
    }

    public boolean isBlocked(String ip) {
        return Boolean.TRUE.equals(redisTemplate.hasKey("blocked_ip:" + ip));
    }

}
