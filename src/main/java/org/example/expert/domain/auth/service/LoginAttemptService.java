package org.example.expert.domain.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class LoginAttemptService {

    private static final int MAX_ATTEMPTS = 5;
    private static final int BLOCK_DURATION_MINUTES = 15;

    private final ConcurrentHashMap<String, AttemptInfo> loginAttempts = new ConcurrentHashMap<>();

    public void recordFailedAttempt(String email) {
        String key = email.toLowerCase();

        loginAttempts.compute(key, (k, attemptInfo) -> {
            if (attemptInfo == null) {
                // 첫 번째 실패
                return new AttemptInfo(1, LocalDateTime.now());
            } else {
                // 기존 실패 횟수 증가
                return new AttemptInfo(
                        attemptInfo.attemptCount() + 1,
                        LocalDateTime.now()
                );
            }
        });

        AttemptInfo info = loginAttempts.get(key);

        if (info.attemptCount() >= MAX_ATTEMPTS) {
            log.warn("로그인 차단됨: 계정 {}분간 차단", BLOCK_DURATION_MINUTES);
        }
    }

    public void recordSuccessfulLogin(String email) {
        String key = email.toLowerCase();
        loginAttempts.remove(key);
    }

    public boolean isBlocked(String email) {
        String key = email.toLowerCase();
        AttemptInfo attemptInfo = loginAttempts.get(key);

        if (attemptInfo == null) {
            return false;
        }

        if (attemptInfo.attemptCount() < MAX_ATTEMPTS) {
            return false;
        }

        LocalDateTime blockUntil = attemptInfo.lastAttemptTime().plusMinutes(BLOCK_DURATION_MINUTES);
        boolean stillBlocked = LocalDateTime.now().isBefore(blockUntil);

        if (!stillBlocked) {
            loginAttempts.remove(key);
        }

        return stillBlocked;
    }

    public long getRemainingBlockTimeMinutes(String email) {
        String key = email.toLowerCase();
        AttemptInfo attemptInfo = loginAttempts.get(key);

        if (attemptInfo == null || attemptInfo.attemptCount() < MAX_ATTEMPTS) {
            return 0;
        }

        LocalDateTime blockUntil = attemptInfo.lastAttemptTime().plusMinutes(BLOCK_DURATION_MINUTES);
        LocalDateTime now = LocalDateTime.now();

        if (now.isAfter(blockUntil)) {
            return 0;
        }

        return java.time.Duration.between(now, blockUntil).toMinutes();
    }

    // 로그인 시도 정보를 담는 내부 클래스
    private record AttemptInfo(int attemptCount, LocalDateTime lastAttemptTime) {
    }
}