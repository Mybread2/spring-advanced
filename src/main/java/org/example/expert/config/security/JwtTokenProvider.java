package org.example.expert.config.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;

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

    // JWT 토큰 생성 (Bearer 접두사 포함)
    public String createToken(Long userId, String email, UserRole userRole) {
        Date date = new Date();

        return Jwts.builder()
                .setSubject(String.valueOf(userId))
                .claim("email", email)
                .claim("userRole", userRole.name())
                .setIssuer(jwtProperties.getIssuer())
                .setExpiration(new Date(date.getTime() + jwtProperties.getExpirationTime()))
                .setIssuedAt(date)
                .signWith(key, signatureAlgorithm)
                .compact();
    }

    // JWT 토큰 파싱 및 검증
    public Claims parseToken(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // 발급자 검증
        if (!jwtProperties.getIssuer().equals(claims.getIssuer())) {
            throw new SecurityException("유효하지 않은 JWT 발급자입니다.");
        }

        return claims;
    }

    // 토큰의 만료 시간을 LocalDateTime으로 반환
    public LocalDateTime getExpirationTime(Claims claims) {
        Date expiration = claims.getExpiration();
        return expiration.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }
}