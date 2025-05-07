package com.idea.authservice.infraestructure.config;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class RateLimiterConfig {

    @Bean
    public LoadingCache<String, Integer> requestCountsPerIp() {
        return CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.MINUTES)
                .build(new CacheLoader<String, Integer>() {
                    @Override
                    public Integer load(String key) {
                        return 0;
                    }
                });
    }

    public boolean isRateLimitExceeded(String ip) {
        int requests = 0;
        try {
            requests = requestCountsPerIp().get(ip);
            if (requests > 100) { // 100 requests per minute
                return true;
            }
            requests++;
            requestCountsPerIp().put(ip, requests);
        } catch (Exception e) {
            return true;
        }
        return false;
    }
} 