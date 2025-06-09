package org.example.expert.config.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    private String secretKey;

    private Long expirationTime = 900_000L;

    private String issuer = "expert-app";

    private String bearerPrefix = "Bearer ";
}