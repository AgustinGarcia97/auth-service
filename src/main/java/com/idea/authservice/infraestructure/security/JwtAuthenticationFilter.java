package com.idea.authservice.infraestructure.security;

import com.idea.authservice.infraestructure.config.RateLimiterConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.hibernate.annotations.Array;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;



//cuando se hace una request previo a llegar al endpoint del controller, se ejecuta el metodo doFilterInternal. Creo que se activa al usar el metodo .authenticated() de SecurityConfig

@Component
@Data
//Se ejecuta por cada request
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final SecurityEventLogger securityEventLogger;
    private final RateLimiterConfig rateLimiterConfig;
    private final MFAService mfaService;

    @Autowired
    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService, SecurityEventLogger securityEventLogger, RateLimiterConfig rateLimiterConfig, MFAService mfaService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.securityEventLogger = securityEventLogger;
        this.rateLimiterConfig = rateLimiterConfig;
        this.mfaService = mfaService;
    }




    @Override
    //aca se valida el token.
    //recibe tres parametros, la request, la response, y la cadena. Si no hago nada, dejo que siga la cadena
    //dentro del request se puede obtener muchos datos, como el header
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        
        // Check rate limiting
        String clientIp = getClientIP(request);
        if (rateLimiterConfig.isRateLimitExceeded(clientIp)) {
            response.setStatus(429); // 429 Too Many Requests
            response.getWriter().write("Rate limit exceeded");
            return;
        }

        final String authHeader = request.getHeader("Authorization"); //header
        final String jwt;
        final String userEmail;
        //aca valida si el header es nulo
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        //convierte el jwt a string
        jwt = authHeader.substring(7);
        //obtiene el email de la request mediante la clase jwtService implementada que servira para obtener el usuario en la DB
        userEmail = jwtService.extractUsername(jwt);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //userdetail permite rellenar la informacion del usuario, y almacenarlo en el securityContextHolder
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); //va a la db a buscar los datos
            if (jwtService.isTokenValid(jwt, userDetails)) { //aca valida el token -ver JwtService para entender
                // Check if MFA is required
                String mfaCode = request.getHeader("X-MFA-Code");
                if (mfaCode != null && !mfaCode.isEmpty()) {
                    // Verify MFA code
                    if (!mfaService.verifyCode(userDetails.getUsername(), Integer.parseInt(mfaCode), userEmail, clientIp)) {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.getWriter().write("Invalid MFA code");
                        return;
                    }
                }

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
                
                // Log successful token validation
                securityEventLogger.logTokenValidation(userEmail, clientIp);
            } else {
                // Log failed token validation
                securityEventLogger.logSecurityEvent("Invalid Token", userEmail, clientIp);
            }
        }

        filterChain.doFilter(request, response);

    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
