package org.example.expert.domain.auth.service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.example.expert.config.security.JwtTokenProvider;
import org.example.expert.domain.auth.entity.TokenBlacklist;
import org.example.expert.domain.auth.repository.TokenBlacklistRepository;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, Object> redisTemplate;

    private static final String BLACKLIST_KEY_PREFIX = "blacklist:";

    @Transactional
    public void addTokenToBlacklist(String accessToken, Long userId) {
        Claims claims = jwtTokenProvider.parseToken(accessToken);
        String jti = claims.getId();

        if (StringUtils.hasText(jti)) {
            LocalDateTime expiresAt = jwtTokenProvider.getExpirationTime(claims);

            if (expiresAt.isAfter(LocalDateTime.now())) {
                // Redis에 저장
                String redisKey = BLACKLIST_KEY_PREFIX + jti;
                long ttlSeconds = java.time.Duration.between(LocalDateTime.now(), expiresAt).getSeconds();
                redisTemplate.opsForValue().set(redisKey, "blocked", ttlSeconds, TimeUnit.SECONDS);

                // DB에 저장 (중복 방지)
                if (!tokenBlacklistRepository.existsById(jti)) {
                    TokenBlacklist blacklistToken = new TokenBlacklist(jti, userId, expiresAt);
                    tokenBlacklistRepository.save(blacklistToken);
                }
            }
        }
    }

    public boolean isBlacklisted(String jti) {

        String redisKey = BLACKLIST_KEY_PREFIX + jti;
        Boolean existsInRedis = redisTemplate.hasKey(redisKey);

        if (existsInRedis) {
            return true;
        }

        // DB 확인
        boolean existsInDB = tokenBlacklistRepository.existsByJtiAndExpiresAtAfter(jti, LocalDateTime.now());

        if (existsInDB) {
            // Redis에 재캐싱
            redisTemplate.opsForValue().set(redisKey, "blocked", 3600, TimeUnit.SECONDS);
        }

        return existsInDB;
    }

    @Scheduled(fixedRate = 300000)
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        tokenBlacklistRepository.deleteExpiredTokens(now);
    }
}