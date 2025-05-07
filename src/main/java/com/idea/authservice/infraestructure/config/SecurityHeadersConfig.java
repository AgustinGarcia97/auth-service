package com.idea.authservice.infraestructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.DelegatingRequestMatcherHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SecurityHeadersConfig {

    @Bean
    public HeaderWriterFilter headerWriterFilter() {
        List<HeaderWriter> headers = new ArrayList<>();
        
        // Add security headers
        headers.add(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"));
        headers.add(new StaticHeadersWriter("X-Frame-Options", "DENY"));
        headers.add(new StaticHeadersWriter("X-XSS-Protection", "1; mode=block"));
        headers.add(new StaticHeadersWriter("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'"));
        
        // Add headers for API endpoints
        headers.add(new DelegatingRequestMatcherHeaderWriter(
            new AntPathRequestMatcher("/api/**"),
            new StaticHeadersWriter("Cache-Control", "no-store, no-cache, must-revalidate")
        ));

        return new HeaderWriterFilter(headers);
    }
} 