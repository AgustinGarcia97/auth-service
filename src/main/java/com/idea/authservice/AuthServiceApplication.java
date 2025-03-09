package com.idea.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {

    public static void main(String[] args) {
        System.getenv().forEach((key, value) -> System.out.println(key + ": " + value));

        SpringApplication.run(AuthServiceApplication.class, args);
    }

}
