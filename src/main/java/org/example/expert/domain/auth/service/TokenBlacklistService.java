package org.example.expert.domain.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.auth.entity.TokenBlacklist;
import org.example.expert.domain.auth.repository.TokenBlacklistRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final TokenBlacklistRepository tokenBlacklistRepository;

    // 토큰을 블랙리스트에 추가
    @Transactional
    public void addToBlacklist(String jti, Long userId, LocalDateTime expiresAt) {
        try {
            // 이미 존재하는지 확인 (중복 방지)
            if (tokenBlacklistRepository.existsById(jti)) {
                log.debug("이미 블랙리스트된 토큰: jti={}", jti);
                return;
            }

            TokenBlacklist blacklistToken = new TokenBlacklist(jti, userId, expiresAt);
            tokenBlacklistRepository.save(blacklistToken);

            log.info("토큰 블랙리스트 추가 완료: userId={}, jti={}, expiresAt={}",
                    userId, jti, expiresAt);

        } catch (Exception e) {
            log.error("토큰 블랙리스트 추가 실패: jti={}, userId={}", jti, userId, e);
            throw new RuntimeException("토큰 블랙리스트 추가 중 오류가 발생했습니다.", e);
        }
    }

    // 토큰이 블랙리스트에 있는지 확인
    @Transactional(readOnly = true)
    public boolean isBlacklisted(String jti) {
        try {
            boolean blacklisted = tokenBlacklistRepository.existsByJtiAndNotExpired(jti, LocalDateTime.now());

            if (blacklisted) {
                log.debug("블랙리스트된 토큰 감지: jti={}", jti);
            }

            return blacklisted;

        } catch (Exception e) {
            log.error("블랙리스트 확인 중 오류 발생: jti={}", jti, e);
            // 안전을 위해 true 반환 (의심스러운 경우 차단)
            return true;
        }
    }

    // 사용자의 활성 블랙리스트 토큰 목록 조회
    @Transactional(readOnly = true)
    public List<TokenBlacklist> getActiveBlacklistedTokens(Long userId) {
        return tokenBlacklistRepository.findActiveTokensByUserId(userId, LocalDateTime.now());
    }

    // 만료된 토큰들을 정리 (스케줄러)
    @Scheduled(fixedRate = 300000) // 5분 = 300,000ms
    @Transactional
    public void cleanupExpiredTokens() {
        try {
            LocalDateTime now = LocalDateTime.now();
            int deletedCount = tokenBlacklistRepository.deleteExpiredTokens(now);

            if (deletedCount > 0) {
                log.info("만료된 블랙리스트 토큰 정리 완료: {} 개 삭제", deletedCount);
            }

            // 현재 활성 토큰 수 로깅
            long activeCount = tokenBlacklistRepository.countActiveTokens(now);
            log.debug("현재 활성 블랙리스트 토큰 수: {}", activeCount);

        } catch (Exception e) {
            log.error("블랙리스트 토큰 정리 중 오류 발생", e);
        }
    }

    // 사용자별 블랙리스트 토큰 통계
    @Transactional(readOnly = true)
    public long getActiveTokenCount(Long userId) {
        return tokenBlacklistRepository.countActiveTokensByUserId(userId, LocalDateTime.now());
    }

    // 전체 활성 블랙리스트 토큰 개수 (모니터링용)
    @Transactional(readOnly = true)
    public long getTotalActiveTokenCount() {
        return tokenBlacklistRepository.countActiveTokens(LocalDateTime.now());
    }
}