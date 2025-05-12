package com.idea.authservice.infraestructure.security;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

@Service
public class MFAService {
    private final GoogleAuthenticator gAuth;
    private final SecurityEventLogger securityEventLogger;

    public MFAService(SecurityEventLogger securityEventLogger) {
        this.gAuth = new GoogleAuthenticator();
        this.securityEventLogger = securityEventLogger;
    }

    public String generateSecretKey() {
        final GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    public String generateQRCode(String secretKey, String email) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("AuthService", email, 
            new GoogleAuthenticatorKey.Builder(secretKey).build());
    }

    public boolean verifyCode(String secretKey, int code) {
        return gAuth.authorize(secretKey, code);
    }

    public boolean verifyCode(String secretKey, int code, String username, String ip) {
        boolean isValid = gAuth.authorize(secretKey, code);
        if (isValid) {
            securityEventLogger.logSecurityEvent("MFA Success", username, ip);
        } else {
            securityEventLogger.logSecurityEvent("MFA Failed", username, ip);
        }
        return isValid;
    }
} 