package com.idea.authservice.infraestructure.config;

import com.idea.authservice.infraestructure.security.JwtAuthenticationFilter;
import com.idea.authservice.infraestructure.security.SecurityEventLogger;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.HeaderWriterFilter;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/*
Esta clase configura cual sera la seguridad HTTP. Es una cadena de responsabilidad de seguridad

Se podra configurar una cadena de responsabilidades sobre seguridad. Gracias a esto se puede hacer
de configuraciones.

*/

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Data
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final SecurityEventLogger securityEventLogger;
    private final RateLimiterConfig rateLimiterConfig;
    private final HeaderWriterFilter headerWriterFilter;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req -> req
                        .requestMatchers("/api/v1/auth/**", "/oauth2/**").permitAll()
                        .anyRequest()
                        .authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(headerWriterFilter, HeaderWriterFilter.class)
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(oauth2UserService))
                        .successHandler((request, response, authentication) -> {
                            // Handle successful OAuth2 login
                            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
                            // Generate JWT token for OAuth2 user
                            // Store user in your database if needed
                        }));

        return http.build();
    }
/*
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }**/
}

//aca se verifica, que endpoints de la app, tendrian que pedir autorizacion, y cuales no. Y ademas que endpoints voy a querer que solo accedan aquellos request que pertenezcan a usuario
//y rol en particular

//Todos los put y post de producto tendrian que tener un rol de ADMIN

//para ver a nivel codigo que el token no fue manipulado ver clase JwtAuthenticationFilter