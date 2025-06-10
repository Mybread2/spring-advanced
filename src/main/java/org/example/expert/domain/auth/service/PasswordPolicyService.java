package org.example.expert.domain.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.auth.entity.PasswordHistory;
import org.example.expert.domain.auth.repository.PasswordHistoryRepository;
import org.example.expert.domain.common.exception.InvalidRequestException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordPolicyService {

    private final PasswordHistoryRepository passwordHistoryRepository;
    private final PasswordEncoder passwordEncoder;

    private static final int PASSWORD_HISTORY_COUNT = 5;
    private static final int PASSWORD_EXPIRY_DAYS = 90;

    public void validatePasswordReuse(String newPassword, Long userId) {
        log.debug("비밀번호 재사용 검증 시작 - 사용자: {}", userId);

        List<PasswordHistory> recentPasswords = passwordHistoryRepository
                .findRecentPasswordsByUserId(userId, PASSWORD_HISTORY_COUNT);

        boolean isReused = recentPasswords.stream()
                .anyMatch(history -> passwordEncoder.matches(newPassword, history.getPasswordHash()));

        if (isReused) {
            throw new InvalidRequestException(
                    String.format("최근 %d개의 비밀번호는 재사용할 수 없습니다.", PASSWORD_HISTORY_COUNT)
            );
        }

        log.debug("비밀번호 재사용 검증 완료 - 사용자: {}", userId);
    }

    @Transactional
    public void savePasswordHistory(Long userId, String passwordHash) {
        log.debug("비밀번호 히스토리 저장 시작 - 사용자: {}", userId);

        PasswordHistory newHistory = new PasswordHistory(userId, passwordHash);
        passwordHistoryRepository.save(newHistory);

        passwordHistoryRepository.deleteOldPasswords(userId, PASSWORD_HISTORY_COUNT);

        log.debug("비밀번호 히스토리 저장 완료 - 사용자: {}", userId);
    }

    public boolean isPasswordExpired(LocalDateTime lastPasswordChange) {
        if (lastPasswordChange == null) return true;

        return lastPasswordChange.isBefore(
                LocalDateTime.now().minusDays(PASSWORD_EXPIRY_DAYS)
        );
    }

    public long getDaysUntilPasswordExpiry(LocalDateTime lastPasswordChange) {
        if (lastPasswordChange == null) return 0;

        LocalDateTime expiryDate = lastPasswordChange.plusDays(PASSWORD_EXPIRY_DAYS);
        long daysLeft = java.time.Duration.between(LocalDateTime.now(), expiryDate).toDays();

        return Math.max(0, daysLeft);
    }

    public boolean isSuspiciousPasswordChangePattern(Long userId) {
        LocalDateTime oneHour = LocalDateTime.now().minusHours(1);
        long recentChanges = passwordHistoryRepository.countPasswordChangesSince(userId, oneHour);

        if (recentChanges >= 3) {
            log.warn("의심스러운 비밀번호 변경 패턴 감지 - 사용자: {}, 1시간내 {}번 변경", userId, recentChanges);
            return true;
        }

        return false;
    }
}
