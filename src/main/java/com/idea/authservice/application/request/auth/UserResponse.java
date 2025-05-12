package com.idea.authservice.application.request.auth;

import com.idea.authservice.domain.model.enums.Role;
import lombok.Data;

import java.util.Collection;

@Data
public class UserResponse {
    private String username;
    private String password;
    private String role;
}
