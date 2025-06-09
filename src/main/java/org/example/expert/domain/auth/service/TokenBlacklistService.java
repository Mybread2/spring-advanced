package org.example.expert.domain.auth.service;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.config.security.JwtTokenProvider;
import org.example.expert.domain.auth.entity.TokenBlacklist;
import org.example.expert.domain.auth.repository.TokenBlacklistRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final JwtTokenProvider jwtTokenProvider;

    // Access Token을 블랙리스트에 추가
    @Transactional
    public void addTokenToBlacklist(String accessToken, Long userId) {
        try {
            Claims claims = jwtTokenProvider.parseToken(accessToken);
            String jti = claims.getId();

            if (StringUtils.hasText(jti)) {
                LocalDateTime expiresAt = jwtTokenProvider.getExpirationTime(claims);

                // 아직 만료되지 않은 토큰만 블랙리스트에 추가
                if (expiresAt.isAfter(LocalDateTime.now())) {
                    // 이미 존재하면 무시 (중복 방지)
                    if (!tokenBlacklistRepository.existsById(jti)) {
                        TokenBlacklist blacklistToken = new TokenBlacklist(jti, userId, expiresAt);
                        tokenBlacklistRepository.save(blacklistToken);
                    }
                }
            }

        } catch (Exception e) {
            log.debug("토큰 블랙리스트 추가 실패: userId={}, error={}", userId, e.getMessage());
        }
    }

    // 토큰이 블랙리스트에 있는지 확인
    @Transactional(readOnly = true)
    public boolean isBlacklisted(String jti) {
        return tokenBlacklistRepository.existsByJtiAndExpiresAtAfter(jti, LocalDateTime.now());
    }

    // 만료된 토큰들을 정리 (스케줄러)
    @Scheduled(fixedRate = 300000)
    @Transactional
    public void cleanupExpiredTokens() {
        try {
            LocalDateTime now = LocalDateTime.now();
            tokenBlacklistRepository.deleteExpiredTokens(now);
        } catch (Exception e) {
            log.error("블랙리스트 토큰 정리 중 오류 발생", e);
        }
    }
}