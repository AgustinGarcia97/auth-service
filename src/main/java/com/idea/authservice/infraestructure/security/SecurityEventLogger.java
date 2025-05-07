package com.idea.authservice.infraestructure.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class SecurityEventLogger {
    private static final Logger logger = LoggerFactory.getLogger(SecurityEventLogger.class);
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void logSecurityEvent(String event, String username, String ip) {
        String timestamp = LocalDateTime.now().format(formatter);
        String logMessage = String.format("[%s] Security Event: %s | User: %s | IP: %s",
                timestamp, event, username, ip);
        logger.info(logMessage);
    }

    public void logFailedLoginAttempt(String username, String ip) {
        logSecurityEvent("Failed Login Attempt", username, ip);
    }

    public void logSuccessfulLogin(String username, String ip) {
        logSecurityEvent("Successful Login", username, ip);
    }

    public void logTokenGeneration(String username, String ip) {
        logSecurityEvent("Token Generated", username, ip);
    }

    public void logTokenValidation(String username, String ip) {
        logSecurityEvent("Token Validated", username, ip);
    }
} 