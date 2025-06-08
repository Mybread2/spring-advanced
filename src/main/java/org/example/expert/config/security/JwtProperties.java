package org.example.expert.config.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    // JWT 서명에 사용할 비밀키 (Base64 인코딩)
    private String secretKey;

    // Access Token 만료 시간 (밀리초)
    private Long expirationTime = 3_600_000L;

    // JWT 발급자 정보
    private String issuer = "expert-app";

    // Bearer 토큰 접두사
    private String bearerPrefix = "Bearer ";
}