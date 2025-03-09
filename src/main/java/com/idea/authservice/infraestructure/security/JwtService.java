package com.idea.authservice.infraestructure.security;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${application.security.jwt.secretKey}")
    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    public String generateToken(
            UserDetails userDetails) {
        return buildToken(userDetails, jwtExpiration);
    }
    //usa la libreria jsonwt y genera el builder que genera el token, que tenga con sub del payload , el mail, iat (new date), exp: fecha actual mas expiracion
    private String buildToken(
            UserDetails userDetails,
            long expiration) {
        System.out.println("Hola");
        return Jwts
                .builder()
                .subject(userDetails.getUsername()) // prueba@hotmail.com
                .issuedAt(new Date(System.currentTimeMillis()))
                .claim("role", userDetails.getAuthorities().iterator().next().getAuthority())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSecretKey())
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractClaim(token, Claims::getSubject);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date()); //verifica si la fecha del token es antes de la fecha de hoy. si es asi, esta todo ok, sino expiro y hay que volver a autenticar
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { // extractClaim obtiene toda la informacion del payload
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) { //este metodo es clave para mantener la integridad
        //libreria de java, que valida  si el token recibido con respecto a la firma
        return Jwts
                .parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        //cuando paso este bloque de codigo, y no hubo excepcion, garantizo que el token recibido fue firmado por el autor correspondiente.

    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }
}
