package com.idea.authservice.infraestructure.controller;

import com.idea.authservice.infraestructure.security.MFAService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/mfa")
@RequiredArgsConstructor
public class MFAController {

    private final MFAService mfaService;

    @PostMapping("/setup")
    public ResponseEntity<?> setupMFA(Authentication authentication) {
        String secretKey = mfaService.generateSecretKey();
        String qrCode = mfaService.generateQRCode(secretKey, authentication.getName());
        
        Map<String, String> response = new HashMap<>();
        response.put("secretKey", secretKey);
        response.put("qrCode", qrCode);
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyMFA(
            @RequestParam int code,
            @RequestParam String secretKey,
            Authentication authentication) {
        
        boolean isValid = mfaService.verifyCode(secretKey, code, 
            authentication.getName(), "IP_ADDRESS"); // You should get the actual IP
        
        if (isValid) {
            return ResponseEntity.ok().body("MFA verification successful");
        } else {
            return ResponseEntity.badRequest().body("Invalid MFA code");
        }
    }

    @PostMapping("/enable")
    public ResponseEntity<?> enableMFA(
            @RequestParam String secretKey,
            @RequestParam int code,
            Authentication authentication) {
        
        if (mfaService.verifyCode(secretKey, code, authentication.getName(), "IP_ADDRESS")) {
            // Here you would typically save the MFA status and secret key to your user database
            return ResponseEntity.ok().body("MFA enabled successfully");
        } else {
            return ResponseEntity.badRequest().body("Invalid MFA code");
        }
    }
} 