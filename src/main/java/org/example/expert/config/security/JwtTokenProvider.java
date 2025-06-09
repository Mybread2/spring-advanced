package org.example.expert.config.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final JwtProperties jwtProperties;

    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(jwtProperties.getSecretKey());
        key = Keys.hmacShaKeyFor(bytes);
    }

    public String createToken(Long userId, String email, UserRole userRole) {
        Date date = new Date();
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setId(jti)
                .setSubject(String.valueOf(userId))
                .claim("email", email)
                .claim("userRole", userRole.name())
                .setIssuer(jwtProperties.getIssuer())
                .setExpiration(new Date(date.getTime() + jwtProperties.getExpirationTime()))
                .setIssuedAt(date)
                .signWith(key, signatureAlgorithm)
                .compact();
    }

    public Claims parseToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            if (!jwtProperties.getIssuer().equals(claims.getIssuer())) {
                throw new SecurityException("유효하지 않은 JWT 발급자입니다.");
            }

            return claims;
        } catch (ExpiredJwtException e) {
            throw new CredentialsExpiredException("JWT 토큰이 만료되었습니다.");
        } catch (JwtException | SecurityException e) {
            throw new BadCredentialsException("유효하지 않은 JWT 토큰입니다.");
        }
    }

    public LocalDateTime getExpirationTime(Claims claims) {
        Date expiration = claims.getExpiration();
        return expiration.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }
}