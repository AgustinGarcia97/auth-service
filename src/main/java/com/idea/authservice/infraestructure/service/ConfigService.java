package com.idea.authservice.infraestructure.service;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.stereotype.Service;

@Service
public class ConfigService {
    private final Dotenv dotenv;

    public ConfigService(Dotenv dotenv) {
        this.dotenv = dotenv;
    }

    public String getJWTSecretKey() {
        return dotenv.get("JWT_SECRET_KEY");
    }

    public String getJWTExpiration() {
        return dotenv.get("JWT_EXPIRATION");
    }

    public String getDBUser(){
        return dotenv.get("DB_USER");
    }

    public String getDBPassword(){
        return dotenv.get("DB_PASSWORD");
    }
}
