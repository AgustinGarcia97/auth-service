package com.idea.authservice.infraestructure.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    
    private final SecurityEventLogger securityEventLogger;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        // Log the OAuth2 login attempt
        securityEventLogger.logSecurityEvent(
            "OAuth2 Login Attempt",
            oauth2User.getAttribute("email"),
            "OAuth2 Provider: " + userRequest.getClientRegistration().getRegistrationId()
        );
        
        return oauth2User;
    }
} 